"""
PhantomScan — Wayback Scraper  v1.0
Découverte d'anciens endpoints via Wayback Machine CDX API.

Fonctionnalités :
  - Requête CDX API pour récupérer toutes les URLs archivées d'un domaine
  - Filtrage des URLs intéressantes (params exposés, endpoints oubliés)
  - Détection de patterns sensibles : .env, config, backup, admin, api, credentials
  - Extraction de paramètres GET uniques pour fuzzing ultérieur
  - Findings INFO/MEDIUM selon la nature de l'URL
"""

from __future__ import annotations

import re
from typing import AsyncGenerator
from urllib.parse import urlparse, parse_qs, urlencode

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester, ProbeRequest
from phantomscan.output.reporter import Finding, Severity


# ─────────────────────── Patterns URLs sensibles ─────────────────────────────

_SENSITIVE_PATH_PATTERNS: list[tuple[str, str, Severity]] = [
    # Fichiers de config / secrets
    (r'\.env(\.|$)',                    "Fichier .env exposé",              Severity.CRITICAL),
    (r'\.git/',                         "Répertoire .git exposé",           Severity.CRITICAL),
    (r'config\.(js|json|php|yml|yaml)', "Fichier de configuration exposé",  Severity.HIGH),
    (r'secrets?\.(js|json|env|yml)',    "Fichier secrets exposé",           Severity.CRITICAL),
    (r'credentials?\.(json|xml|yml)',   "Fichier credentials exposé",       Severity.CRITICAL),
    (r'\.(bak|backup|old|orig|save)$',  "Fichier backup exposé",            Severity.HIGH),
    (r'wp-config\.php',                 "wp-config.php exposé",             Severity.CRITICAL),
    (r'database\.(yml|json|php)',       "Config database exposée",          Severity.HIGH),
    # Endpoints admin / oubliés
    (r'/admin/?$',                      "Endpoint admin (archivé)",         Severity.MEDIUM),
    (r'/phpmyadmin',                    "phpMyAdmin (archivé)",             Severity.HIGH),
    (r'/swagger',                       "Swagger UI (archivé)",             Severity.MEDIUM),
    (r'/api-docs',                      "API docs (archivé)",               Severity.MEDIUM),
    (r'/graphql',                       "GraphQL endpoint (archivé)",       Severity.MEDIUM),
    (r'/debug',                         "Endpoint debug (archivé)",         Severity.MEDIUM),
    (r'/console',                       "Console (archivé)",                Severity.HIGH),
    (r'/actuator',                      "Spring Actuator (archivé)",        Severity.HIGH),
    (r'/_profiler',                     "Symfony Profiler (archivé)",       Severity.HIGH),
    # Dumps / exports
    (r'\.(sql|dump|tar\.gz|zip)(\?|$)', "Dump/archive exposé",             Severity.CRITICAL),
    (r'/backup',                        "Répertoire backup (archivé)",      Severity.HIGH),
    # Logs
    (r'\.(log|logs?)(\?|$)',            "Fichier log exposé",               Severity.MEDIUM),
    (r'/logs?/',                        "Répertoire logs (archivé)",        Severity.MEDIUM),
]

# Paramètres GET souvent sensibles (IDOR, injection, etc.)
_INTERESTING_PARAMS: set[str] = {
    "id", "user", "uid", "userid", "account", "token", "key", "api_key",
    "secret", "password", "pass", "pwd", "auth", "session", "sessid",
    "redirect", "url", "next", "return", "callback", "file", "path",
    "page", "include", "doc", "document", "folder", "root", "cmd",
    "exec", "shell", "query", "search", "q", "debug", "test",
}

_CDX_API = "http://web.archive.org/cdx/search/cdx"


class WaybackScraper:
    """Récupère les URLs archivées d'un domaine via la CDX API Wayback Machine."""

    def __init__(self, req: Requester, cfg: PhantomConfig) -> None:
        self._req = req
        self._cfg = cfg

    async def run(self, target: str) -> AsyncGenerator[Finding, None]:
        domain = self._extract_domain(target)

        async for finding in self._fetch_and_analyze(target, domain):
            yield finding

    async def _fetch_and_analyze(self, target: str, domain: str) -> AsyncGenerator[Finding, None]:
        urls = await self._fetch_cdx_urls(domain)

        if not urls:
            return

        # Finding INFO — résumé global
        yield Finding(
            title="Wayback Machine — URLs archivées trouvées",
            url=target,
            severity=Severity.INFO,
            description=(
                f"{len(urls)} URLs archivées trouvées pour {domain} via Wayback Machine CDX API.\n"
                "Ces URLs peuvent révéler d'anciens endpoints, paramètres et fichiers oubliés."
            ),
            evidence=f"CDX query: {_CDX_API}?url={domain}/*&output=json&fl=original&collapse=urlkey",
        )

        seen_findings: set[str] = set()
        interesting_params: dict[str, set[str]] = {}  # param -> set of URLs

        for url in urls:
            parsed = urlparse(url)
            path = parsed.path.lower()

            # ── Analyse du path ──────────────────────────────────────────
            for pattern, label, severity in _SENSITIVE_PATH_PATTERNS:
                if re.search(pattern, path, re.IGNORECASE):
                    key = f"{label}:{path}"
                    if key not in seen_findings:
                        seen_findings.add(key)
                        yield Finding(
                            title=f"Wayback — {label}",
                            url=url,
                            severity=severity,
                            description=(
                                f"URL archivée détectée : {url}\n"
                                f"Pattern : {pattern}\n"
                                "Cette ressource était accessible publiquement dans le passé."
                            ),
                            evidence=f"Source: web.archive.org — pattern: {pattern}",
                        )
                    break  # un seul finding par URL

            # ── Analyse des paramètres GET ───────────────────────────────
            params = parse_qs(parsed.query, keep_blank_values=False)
            for param in params:
                if param.lower() in _INTERESTING_PARAMS:
                    interesting_params.setdefault(param.lower(), set()).add(url)

        # Findings agrégés par param intéressant
        for param, param_urls in interesting_params.items():
            sample = sorted(param_urls)[:5]
            yield Finding(
                title=f"Wayback — Paramètre sensible exposé : ?{param}=",
                url=next(iter(param_urls)),
                severity=Severity.MEDIUM,
                param=param,
                description=(
                    f"Le paramètre `{param}` apparaît dans {len(param_urls)} URL(s) archivée(s).\n"
                    "Ce paramètre est souvent associé à des vulnérabilités IDOR, injection ou open redirect."
                ),
                evidence="Exemples:\n" + "\n".join(sample),
            )

    async def _fetch_cdx_urls(self, domain: str) -> list[str]:
        """Interroge la CDX API et retourne la liste des URLs uniques."""
        params = {
            "url": f"{domain}/*",
            "output": "json",
            "fl": "original",
            "collapse": "urlkey",
            "limit": "5000",
            "filter": "statuscode:200",
        }
        query = urlencode(params)
        cdx_url = f"{_CDX_API}?{query}"

        try:
            probe = ProbeRequest(url=cdx_url, method="GET", timeout=30)
            resp = await self._req.probe(probe)
            if not resp or resp.status_code != 200 or not resp.body:
                return []

            # CDX retourne JSON array of arrays, première ligne = headers
            import json
            data = json.loads(resp.body)
            if not data or len(data) < 2:
                return []

            # data[0] = ["original"], data[1:] = [["https://..."]]
            urls = [row[0] for row in data[1:] if row]
            return urls

        except Exception:
            return []

    @staticmethod
    def _extract_domain(target: str) -> str:
        parsed = urlparse(target)
        host = parsed.netloc or parsed.path
        return host.split(":")[0].lower()
