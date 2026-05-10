"""
PhantomScan — Google Dorker  v1.0
Génération et exécution de Google Dorks ciblés sur un domaine.

Fonctionnalités :
  - Génération de dorks thématiques (fichiers exposés, endpoints sensibles,
    erreurs, CMS, logins, credentials, configs, backups)
  - Requêtes via SearXNG public (fallback : DuckDuckGo HTML scraping)
  - Parsing des résultats et extraction des URLs pertinentes
  - Findings classés par catégorie avec description actionnable
  - Rate limiting intégré pour ne pas se faire bloquer

Note : Google bloque les requêtes automatiques directes (CAPTCHAs).
Ce module utilise des moteurs de recherche alternatifs accessibles
sans JavaScript (SearXNG, DuckDuckGo HTML).
"""

from __future__ import annotations

import asyncio
import re
from typing import AsyncGenerator
from urllib.parse import urlparse, quote_plus

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester, ProbeRequest
from phantomscan.output.reporter import Finding, Severity


# ─────────────────────── Dorks par catégorie ─────────────────────────────────

_DORK_CATEGORIES: list[tuple[str, str, Severity, list[str]]] = [
    (
        "Fichiers de configuration exposés",
        "config_files",
        Severity.CRITICAL,
        [
            'site:{domain} ext:env',
            'site:{domain} ext:env.backup',
            'site:{domain} "DB_PASSWORD" OR "DB_USER" OR "SECRET_KEY"',
            'site:{domain} ext:xml OR ext:conf OR ext:cnf inurl:config',
        ],
    ),
    (
        "Fichiers sensibles exposés",
        "sensitive_files",
        Severity.HIGH,
        [
            'site:{domain} ext:sql',
            'site:{domain} ext:bak OR ext:backup OR ext:old',
            'site:{domain} ext:log',
            'site:{domain} inurl:.git/config',
            'site:{domain} ext:yaml OR ext:yml inurl:secret',
        ],
    ),
    (
        "Pages d'erreur et stack traces",
        "error_pages",
        Severity.MEDIUM,
        [
            'site:{domain} "Fatal error" OR "Warning:" OR "Stack trace"',
            'site:{domain} "SQL syntax" OR "mysql_fetch" OR "ORA-0"',
            'site:{domain} "Traceback (most recent call last)"',
            'site:{domain} inurl:error OR inurl:debug intitle:"Error"',
        ],
    ),
    (
        "Interfaces d'administration exposées",
        "admin_panels",
        Severity.HIGH,
        [
            'site:{domain} inurl:admin OR inurl:administrator OR inurl:wp-admin',
            'site:{domain} inurl:phpmyadmin OR inurl:pma',
            'site:{domain} intitle:"Dashboard" inurl:admin',
            'site:{domain} inurl:login intitle:"Admin"',
        ],
    ),
    (
        "Endpoints API exposés",
        "api_endpoints",
        Severity.MEDIUM,
        [
            'site:{domain} inurl:api/v1 OR inurl:api/v2 OR inurl:graphql',
            'site:{domain} inurl:swagger OR inurl:api-docs OR inurl:openapi',
            'site:{domain} filetype:json inurl:api',
            'site:{domain} "apikey" OR "api_key" OR "access_token" ext:json',
        ],
    ),
    (
        "Credentials et tokens exposés",
        "credentials",
        Severity.CRITICAL,
        [
            'site:{domain} "password" OR "passwd" filetype:txt OR filetype:log',
            'site:{domain} "access_key" OR "secret_key" OR "client_secret"',
            'site:{domain} inurl:credentials OR inurl:passwd',
        ],
    ),
    (
        "Répertoires listés",
        "directory_listing",
        Severity.MEDIUM,
        [
            'site:{domain} intitle:"Index of /" OR intitle:"Directory Listing"',
            'site:{domain} intitle:"Index of" inurl:backup OR inurl:upload',
        ],
    ),
    (
        "Endpoints de test / staging",
        "staging_endpoints",
        Severity.LOW,
        [
            'site:{domain} inurl:test OR inurl:staging OR inurl:dev OR inurl:sandbox',
            'site:{domain} inurl:debug OR inurl:beta OR inurl:demo',
        ],
    ),
]

# Moteurs de recherche à essayer dans l'ordre
_SEARXNG_INSTANCES = [
    "https://searx.be",
    "https://search.bus-hit.me",
    "https://searxng.world",
    "https://paulgo.io",
]

_DDG_SEARCH_URL = "https://html.duckduckgo.com/html/"


class GoogleDorker:
    """Génère et exécute des Google Dorks ciblés via SearXNG / DuckDuckGo."""

    def __init__(self, req: Requester, cfg: PhantomConfig) -> None:
        self._req = req
        self._cfg = cfg
        self._delay = 2.5  # secondes entre requêtes pour éviter le rate-limit

    async def run(self, target: str) -> AsyncGenerator[Finding, None]:
        domain = self._extract_domain(target)

        yield Finding(
            title="Google Dorking — Démarrage",
            url=target,
            severity=Severity.INFO,
            description=(
                f"Exécution de {sum(len(d) for _, _, _, d in _DORK_CATEGORIES)} dorks "
                f"sur le domaine {domain} via SearXNG/DuckDuckGo.\n"
                "Les résultats peuvent révéler des ressources indexées sensibles."
            ),
            evidence=f"Domaine ciblé : {domain}",
        )

        seen_urls: set[str] = set()

        for category_name, category_id, severity, dorks in _DORK_CATEGORIES:
            cat_results: list[str] = []

            for dork_template in dorks:
                dork = dork_template.format(domain=domain)
                urls = await self._search(dork)
                # Filtrer pour ne garder que les URLs du domaine cible
                filtered = [u for u in urls if domain in u and u not in seen_urls]
                seen_urls.update(filtered)
                cat_results.extend(filtered)
                await asyncio.sleep(self._delay)

            if cat_results:
                yield Finding(
                    title=f"Google Dork — {category_name}",
                    url=target,
                    severity=severity,
                    description=(
                        f"Dork catégorie `{category_id}` : {len(cat_results)} URL(s) indexée(s) trouvées.\n"
                        f"Ces URLs ont été indexées par les moteurs de recherche et sont potentiellement sensibles."
                    ),
                    evidence=(
                        f"Dorks exécutés : {len(dorks)}\n"
                        "URLs trouvées :\n" + "\n".join(cat_results[:20])
                    ),
                )

    async def _search(self, query: str) -> list[str]:
        """Tente SearXNG en premier, puis DuckDuckGo HTML."""
        results = await self._search_searxng(query)
        if not results:
            results = await self._search_ddg(query)
        return results

    async def _search_searxng(self, query: str) -> list[str]:
        """Interroge une instance SearXNG publique (JSON API)."""
        for instance in _SEARXNG_INSTANCES:
            try:
                url = f"{instance}/search?q={quote_plus(query)}&format=json&categories=general"
                probe = ProbeRequest(url=url, method="GET", timeout=15, headers={
                    "Accept": "application/json",
                    "User-Agent": "Mozilla/5.0 (compatible; PhantomScan/5.2)",
                })
                resp = await self._req.probe(probe)
                if not resp or resp.status_code != 200 or not resp.body:
                    continue

                import json
                data = json.loads(resp.body)
                results = data.get("results", [])
                return [r.get("url", "") for r in results if r.get("url")]

            except Exception:
                continue

        return []

    async def _search_ddg(self, query: str) -> list[str]:
        """Scrape DuckDuckGo HTML (fallback sans JS)."""
        try:
            probe = ProbeRequest(
                url=_DDG_SEARCH_URL,
                method="POST",
                body=f"q={quote_plus(query)}&b=",
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
                },
                timeout=15,
            )
            resp = await self._req.probe(probe)
            if not resp or resp.status_code != 200 or not resp.body:
                return []

            # Extraction des URLs depuis le HTML DDG
            urls = re.findall(r'href="(https?://[^"&]+)"', resp.body)
            # Filtrer les URLs internes DDG
            return [u for u in urls if "duckduckgo.com" not in u]

        except Exception:
            return []

    @staticmethod
    def _extract_domain(target: str) -> str:
        parsed = urlparse(target)
        host = parsed.netloc or parsed.path
        return host.split(":")[0].lower()
