"""
PhantomScan — Smart Fuzzer
Fuzzing adaptatif : ajuste les payloads selon la baseline et le WAF détecté.
"""

from __future__ import annotations

import asyncio
import re
from typing import AsyncIterator
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester, ProbeRequest
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity

WORDLIST_CHUNK = 5000

# ─────────────────────────── Wordlists intégrées ────────────────────────────

COMMON_PATHS: list[str] = [
    # Admin / config
    "admin", "administrator", "admin.php", "admin/login", "wp-admin",
    "manager", "management", "dashboard", "panel", "cpanel", "control",
    "backend", "backoffice", "cms", "portal",
    # API
    "api", "api/v1", "api/v2", "api/v3", "graphql", "graphiql",
    "api/docs", "api/swagger", "swagger", "swagger.json", "openapi.json",
    "api/health", "health", "status", "ping", "metrics",
    # Debug / dev
    "debug", "test", "dev", "staging", "phpinfo.php", "info.php",
    "server-status", "server-info", "elmah.axd",
    # Fichiers sensibles
    ".env", ".git/HEAD", ".git/config", "config.php", "config.yml",
    "configuration.php", "database.yml", "settings.py", "local.py",
    "wp-config.php", "web.config", "app.config", "appsettings.json",
    ".htaccess", ".htpasswd", "robots.txt", "sitemap.xml",
    # Backups
    "backup", "backup.zip", "backup.tar.gz", "db.sql", "dump.sql",
    "old", "bak", "copy", "_old", "_bak",
    # Logs
    "log", "logs", "error.log", "access.log", "debug.log",
    # Auth
    "login", "logout", "register", "signup", "signin", "auth",
    "oauth", "oauth2", "sso", "forgot-password", "reset-password",
    # Upload
    "upload", "uploads", "files", "media", "static", "assets",
    # Cloud / infra
    ".aws/credentials", ".ssh/id_rsa", "metadata/v1", "latest/meta-data",
    # Spring Boot Actuator
    "actuator", "actuator/env", "actuator/beans", "actuator/mappings",
    "actuator/httptrace", "actuator/logfile", "actuator/heapdump",
    # Rails / Django
    "rails/info/properties", "rails/mailers", "__debug__", "django-admin",
    # Generic API versioning
    "v1", "v2", "v3", "api/v1/docs", "api/v2/docs",
    # GraphQL
    "graphiql", "__graphql", "api/graphql", "graphql/console",
    # Misc
    "console", "telescope", "horizon", "jobs", "queues",
    "phpmyadmin", "adminer", "pma", "myadmin",
    ".DS_Store", "Thumbs.db", "web.config.bak", ".env.bak", ".env.prod",
]

PARAM_FUZZ_PAYLOADS: list[str] = [
    "'", "\"", "' OR '1'='1", "1 OR 1=1", "'; DROP TABLE--",
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
    "../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
    "....//....//....//etc/passwd",
    "{{7*7}}", "${7*7}", "<%= 7*7 %>",
    ";id", "|id", "`id`", "$(id)",
    "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>",
    "%0d%0aX-Injected:true",
    "%00", "\x00",
    "ＳＥＬＥＣＴ",
]

_SSTI_RESULT = "49"


class SmartFuzzer:
    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req = req
        self._heuristic = heuristic
        self._cfg = cfg

    async def run(self, target: str) -> AsyncIterator[Finding]:
        async for f in self._fuzz_paths(target):
            yield f

        parsed = urlparse(target)
        if parsed.query:
            async for f in self._fuzz_params(target):
                yield f

        if self._cfg.wordlist_path:
            async for f in self._fuzz_wordlist(target, self._cfg.wordlist_path):
                yield f

    # ── Directory fuzzing ─────────────────────────────────────────────────────

    async def _fuzz_paths(self, target: str) -> AsyncIterator[Finding]:
        base = target.rstrip("/")
        waf = self._heuristic.fingerprint and self._heuristic.fingerprint.waf

        concurrency = 5 if waf else 15
        sem = asyncio.Semaphore(concurrency)

        async def probe(path: str):
            async with sem:
                url = f"{base}/{path}"
                return path, await self._req.get(url)

        tasks = [asyncio.create_task(probe(p)) for p in COMMON_PATHS]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        baseline_status = self._heuristic.baseline.status_mode if self._heuristic.baseline else 404

        for item in results:
            if isinstance(item, Exception):
                continue
            path, resp = item
            if resp.error:
                continue
            if resp.status == baseline_status:
                continue

            self._heuristic.analyze(resp, context=f"path_fuzz:{path}")

            if resp.status in (200, 201, 204, 301, 302, 307):
                sev = Severity.MEDIUM if resp.status == 200 else Severity.LOW
                yield Finding(
                    title=f"Path discovered: /{path}",
                    severity=sev,
                    url=resp.url,
                    module="fuzz/smart_fuzzer",
                    description=f"HTTP {resp.status} — Ressource accessible",
                    evidence=f"Size: {resp.content_length}B | Time: {resp.elapsed_ms:.0f}ms",
                )
            elif resp.status == 403:
                yield Finding(
                    title=f"Forbidden resource: /{path}",
                    severity=Severity.LOW,
                    url=resp.url,
                    module="fuzz/smart_fuzzer",
                    description="HTTP 403 — Ressource existe mais accès refusé (potentiel bypass)",
                    evidence=f"Size: {resp.content_length}B",
                )
            elif resp.status == 500:
                yield Finding(
                    title=f"Server error on path: /{path}",
                    severity=Severity.MEDIUM,
                    url=resp.url,
                    module="fuzz/smart_fuzzer",
                    description="HTTP 500 — Erreur serveur, potentielle vulnérabilité",
                    evidence=resp.body[:200],
                )

    # ── Param fuzzing — parallèle ─────────────────────────────────────────────

    async def _fuzz_params(self, target: str) -> AsyncIterator[Finding]:
        parsed = urlparse(target)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return

        waf = self._heuristic.fingerprint and self._heuristic.fingerprint.waf
        # Concurrence réduite si WAF détecté pour éviter le ban
        sem = asyncio.Semaphore(5 if waf else 20)

        async def probe_one(param_name: str, payload: str) -> Finding | None:
            async with sem:
                fuzzed = dict(params)
                fuzzed[param_name] = [payload]
                new_query = urlencode(fuzzed, doseq=True)
                fuzz_url = urlunparse(parsed._replace(query=new_query))

                resp = await self._req.get(fuzz_url)
                if resp.error:
                    return None

                hr = self._heuristic.analyze(resp, context=f"param_fuzz:{param_name}={payload[:30]}")
                if not hr.interesting:
                    return None

                vuln_type, sev, cwe = self._classify_param_response(payload, resp.body, resp.status)
                if not vuln_type:
                    return None

                return Finding(
                    title=f"Potential {vuln_type} — param `{param_name}`",
                    severity=sev,
                    url=fuzz_url,
                    module="fuzz/smart_fuzzer",
                    description=f"Payload déclenche une réponse anormale sur param `{param_name}`",
                    evidence=f"Payload: {payload[:60]} | Status: {resp.status} | Size: {resp.content_length}B",
                    cwe=cwe,
                )

        # Toutes les combinaisons (param × payload) lancées en parallèle
        combos = [
            (param_name, payload)
            for param_name in params
            for payload in PARAM_FUZZ_PAYLOADS
        ]
        tasks = [asyncio.create_task(probe_one(p, v)) for p, v in combos]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Déduplique par (param, vuln_type) pour pas spammer le même finding
        seen: set[tuple[str, str]] = set()
        for item in results:
            if isinstance(item, Exception) or item is None:
                continue
            key = (item.url.split("=")[0], item.title)
            if key not in seen:
                seen.add(key)
                yield item

    def _classify_param_response(
        self,
        payload: str,
        body: str,
        status: int,
    ) -> tuple[str | None, Severity, str]:
        body_low = body.lower()

        # SQL injection — error patterns
        sqli_errors = [
            "sql syntax", "mysql_fetch", "ora-0", "postgresql", "sqlite3",
            "unclosed quotation", "unterminated string", "division by zero",
            "sqlstate[", "pg_query()", "java.sql.sqlexception",
            "com.mysql.jdbc", "org.postgresql", "microsoft ole db",
        ]
        if any(e in body_low for e in sqli_errors):
            return "SQL Injection", Severity.CRITICAL, "CWE-89"

        # XSS — reflected payloads
        if "<script>alert(1)</script>" in body or "onerror=alert(1)" in body:
            return "Reflected XSS", Severity.HIGH, "CWE-79"

        # SSTI — template evaluation
        if "{{7*7}}" in payload or "${7*7}" in payload or "<%= 7*7 %>" in payload:
            if re.search(r"(?<!\d)49(?!\d)", body):
                return "SSTI", Severity.CRITICAL, "CWE-94"

        # LFI / Path traversal
        if "root:x:0:0" in body or "[boot loader]" in body_low:
            return "Path Traversal / LFI", Severity.CRITICAL, "CWE-22"

        # CRLF injection
        if "%0d%0a" in payload.lower() and "x-injected" in body_low:
            return "CRLF Injection", Severity.HIGH, "CWE-93"

        # Command injection — output dans la réponse
        if any(p in payload for p in (";id", "|id", "`id`", "$(id)")):
            if re.search(r"uid=\d+\(\w+\)", body):
                return "Command Injection", Severity.CRITICAL, "CWE-78"

        # XXE
        if "xxe" in payload.lower() and ("root:x:0:0" in body or "file:///" in body_low):
            return "XXE", Severity.CRITICAL, "CWE-611"

        # Server error — peut indiquer une injection
        if status == 500:
            return "Unhandled exception (possible injection)", Severity.MEDIUM, "CWE-20"

        # 403 sur un paramètre → WAF trigger possible, intéressant
        if status == 403:
            return "WAF/ACL trigger on payload", Severity.LOW, "CWE-20"

        return None, Severity.INFO, ""

    # ── Wordlist externe — chunked streaming ──────────────────────────────────

    async def _fuzz_wordlist(self, target: str, path: str) -> AsyncIterator[Finding]:
        base = target.rstrip("/")
        waf = self._heuristic.fingerprint and self._heuristic.fingerprint.waf
        sem = asyncio.Semaphore(5 if waf else 15)
        baseline_status = self._heuristic.baseline.status_mode if self._heuristic.baseline else 404

        async def probe(word: str):
            async with sem:
                return word, await self._req.get(f"{base}/{word}")

        try:
            fh = open(path, "r", encoding="utf-8", errors="ignore")
        except OSError:
            return

        chunk: list[str] = []

        with fh:
            for line in fh:
                word = line.strip()
                if not word or word.startswith("#"):
                    continue
                chunk.append(word)

                # Process par batch de WORDLIST_CHUNK — libère la mémoire entre chaque
                if len(chunk) >= WORDLIST_CHUNK:
                    async for finding in self._run_wordlist_batch(chunk, probe, baseline_status):
                        yield finding
                    chunk = []

            # Dernier batch résiduel
            if chunk:
                async for finding in self._run_wordlist_batch(chunk, probe, baseline_status):
                    yield finding

    async def _run_wordlist_batch(
        self,
        words: list[str],
        probe,
        baseline_status: int,
    ) -> AsyncIterator[Finding]:
        tasks = [asyncio.create_task(probe(w)) for w in words]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for item in results:
            if isinstance(item, Exception):
                continue
            word, resp = item
            if resp.error or resp.status == baseline_status:
                continue
            if resp.status in (200, 201, 403, 500):
                yield Finding(
                    title=f"Wordlist hit: /{word}",
                    severity=Severity.LOW if resp.status == 403 else Severity.MEDIUM,
                    url=resp.url,
                    module="fuzz/smart_fuzzer",
                    description=f"HTTP {resp.status} via wordlist custom",
                    evidence=f"Word: {word} | Size: {resp.content_length}B",
                )
