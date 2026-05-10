"""
PhantomScan — Sitemap & Robots.txt Recon
==========================================
Parse sitemap.xml, robots.txt et les sitemaps imbriqués pour découvrir
des endpoints cachés, des sections interdites et des patterns d'URL.

Valeur : sitemap.xml révèle souvent des URLs non liées dans la navigation
principale (pages admin, exports, endpoints API, fichiers de debug).
robots.txt révèle volontairement les chemins à "ne pas indexer" —
exactement là où les vulnérabilités les plus intéressantes se trouvent.

Fonctionnalités :
  1. Parse sitemap.xml + sitemapindex.xml (sitemaps imbriqués)
  2. Parse robots.txt (Disallow, Allow, Sitemap directives)
  3. Extraction et scoring des endpoints découverts
  4. Détection des sections sensibles (admin, backup, export, api, debug)
  5. Publication sur l'EndpointBus pour les modules vulns
"""

from __future__ import annotations

import asyncio
import re
import xml.etree.ElementTree as ET
from typing import AsyncIterator
from urllib.parse import urlparse, urljoin

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity
from phantomscan.core.scanner_mixin import ScannerMixin


# ── Patterns d'endpoints sensibles ───────────────────────────────────────────
_SENSITIVE_PATH_RE = re.compile(
    r"/(?:admin|administrator|backup|backups|export|exports|debug|"
    r"api|internal|private|secret|hidden|staging|dev|test|qa|"
    r"management|dashboard|panel|control|config|configuration|"
    r"log|logs|temp|tmp|upload|uploads|old|archive|archives|"
    r"swagger|openapi|graphql|graphiql|playground|"
    r"phpinfo|info\.php|test\.php|debug\.php|"
    r"\.env|\.git|\.svn|web\.config|wp-config)",
    re.I,
)

# ── Patterns d'URLs à fort potentiel ─────────────────────────────────────────
_HIGH_VALUE_RE = re.compile(
    r"(?:[?&](?:id|user|account|file|path|url|redirect|token|key|"
    r"name|search|query|cmd|exec|action|page)=)",
    re.I,
)


class SitemapReconScanner(ScannerMixin):
    """
    Recon via sitemap.xml et robots.txt.
    Publie les endpoints découverts sur l'EndpointBus.
    """

    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req = req
        self._heur = heuristic
        self._cfg = cfg
        self._discovered: set[str] = set()
        self._sensitive_found: set[str] = set()

    async def run(self, target: str) -> AsyncIterator[Finding]:
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # 1. robots.txt
        robots_urls, disallowed = await self._parse_robots(base)

        # 2. Signaler les paths Disallow intéressants
        for path in disallowed:
            if _SENSITIVE_PATH_RE.search(path):
                key = f"robots_sensitive:{path}"
                if key not in self._sensitive_found:
                    self._sensitive_found.add(key)
                    yield Finding(
                        title=f"robots.txt Disallow — Sensitive Path: {path}",
                        severity=Severity.INFO,
                        url=base + path,
                        module="recon/sitemap_recon",
                        description=(
                            f"Le fichier robots.txt interdit l'indexation de `{path}`. "
                            "Les chemins Disallow révèlent souvent des fonctionnalités "
                            "sensibles : admin, backups, export, debug, etc."
                        ),
                        evidence=f"Disallow: {path}",
                        cwe="CWE-200",
                        remediation=(
                            "Ne pas considérer robots.txt comme un mécanisme de sécurité. "
                            "Protéger les sections sensibles par authentification et autorisation."
                        ),
                    )

        # 3. Récupérer et parser les sitemaps (depuis robots.txt + chemins standards)
        sitemap_urls = robots_urls or []
        for standard_path in ["/sitemap.xml", "/sitemap_index.xml", "/sitemaps.xml",
                               "/sitemap/sitemap.xml", "/wp-sitemap.xml"]:
            sitemap_urls.append(base + standard_path)

        all_page_urls: list[str] = []
        for sm_url in sitemap_urls[:5]:
            urls = await self._parse_sitemap(sm_url, base, depth=0)
            all_page_urls.extend(urls)

        # 4. Dédupliquer et scorer les URLs
        unique_urls = list(dict.fromkeys(all_page_urls))[:500]
        sensitive_urls = [u for u in unique_urls if _SENSITIVE_PATH_RE.search(u)]
        high_value_urls = [u for u in unique_urls if _HIGH_VALUE_RE.search(u)]

        # 5. Publier sur le bus d'endpoints
        if self.bus:
            for url in unique_urls[:300]:
                from phantomscan.core.intelligence import DiscoveredEndpoint
                from urllib.parse import parse_qs
                p = urlparse(url)
                params = list(parse_qs(p.query).keys())
                score = 0.3
                if _SENSITIVE_PATH_RE.search(url):
                    score = 0.9
                elif _HIGH_VALUE_RE.search(url):
                    score = 0.8
                elif params:
                    score = 0.6
                self.bus.publish(DiscoveredEndpoint(
                    url=url, method="GET", params=params,
                    source="recon/sitemap", score=score,
                ))

        # 6. Rapport de découverte
        if unique_urls:
            yield Finding(
                title=f"Sitemap Discovery — {len(unique_urls)} URLs found",
                severity=Severity.INFO,
                url=base + "/sitemap.xml",
                module="recon/sitemap_recon",
                description=(
                    f"Sitemap.xml/robots.txt ont révélé {len(unique_urls)} URLs. "
                    f"{len(sensitive_urls)} URLs sensibles, "
                    f"{len(high_value_urls)} URLs avec paramètres à fort potentiel."
                ),
                evidence=(
                    f"Total URLs: {len(unique_urls)} | "
                    f"Sensitive: {len(sensitive_urls)} | "
                    f"High-value params: {len(high_value_urls)} | "
                    f"Examples: {sensitive_urls[:3]}"
                ),
                cwe="CWE-200",
                remediation="Revoir le contenu du sitemap — ne pas exposer les URLs d'admin.",
            )

        # 7. Signaler les URLs sensibles trouvées dans le sitemap
        for url in sensitive_urls[:10]:
            key = f"sitemap_sensitive:{url}"
            if key not in self._sensitive_found:
                self._sensitive_found.add(key)
                yield Finding(
                    title=f"Sensitive URL in Sitemap: {urlparse(url).path}",
                    severity=Severity.LOW,
                    url=url,
                    module="recon/sitemap_recon",
                    description=(
                        f"URL sensible exposée dans sitemap.xml : `{url}`. "
                        "Les moteurs de recherche peuvent indexer ces pages."
                    ),
                    evidence=f"Found in sitemap: {url}",
                    cwe="CWE-200",
                    remediation="Exclure les URLs sensibles du sitemap et les protéger.",
                )

    # ── Parsers ───────────────────────────────────────────────────────────────

    async def _parse_robots(self, base: str) -> tuple[list[str], list[str]]:
        """Parse robots.txt et retourne (sitemap_urls, disallowed_paths)."""
        resp = await self._req.get(base + "/robots.txt")
        if resp.error or resp.status != 200:
            return [], []

        body = resp.body or ""
        sitemap_urls = re.findall(r'^Sitemap:\s*(https?://\S+)', body, re.I | re.M)
        disallowed = re.findall(r'^Disallow:\s*(/\S*)', body, re.I | re.M)
        return sitemap_urls, disallowed

    async def _parse_sitemap(self, url: str, base: str, depth: int) -> list[str]:
        """Parse récursivement un sitemap XML. Max depth=2."""
        if depth > 2 or url in self._discovered:
            return []
        self._discovered.add(url)

        resp = await self._req.get(url)
        if resp.error or resp.status != 200:
            return []

        body = resp.body or ""
        urls: list[str] = []

        try:
            # Nettoyer le namespace XML
            body_clean = re.sub(r' xmlns[^"]*"[^"]*"', '', body)
            root = ET.fromstring(body_clean)
            tag = root.tag.lower()

            if "sitemapindex" in tag:
                # Sitemap index → récursion sur les sous-sitemaps
                sitemap_locs = [e.text for e in root.iter() if e.tag.lower() == "loc" and e.text]
                sub_tasks = [
                    self._parse_sitemap(loc, base, depth + 1)
                    for loc in sitemap_locs[:10]
                ]
                results = await asyncio.gather(*sub_tasks, return_exceptions=True)
                for r in results:
                    if isinstance(r, list):
                        urls.extend(r)
            else:
                # Sitemap classique → extraire les <loc>
                locs = [e.text for e in root.iter() if e.tag.lower() == "loc" and e.text]
                urls.extend(locs[:1000])
        except ET.ParseError:
            # Fallback : extraction par regex
            locs = re.findall(r'<loc>\s*(https?://[^<]+)\s*</loc>', body, re.I)
            urls.extend(locs[:500])

        return urls
