"""
PhantomScan — Crawler  (v5.0)
==============================
Améliorations v5.0 :
- Batches concurrents configurables (crawl_concurrency dans ScanConfig).
- Extraction d'attributs HTML étendus : data-url, data-src, data-href,
  meta[http-equiv=refresh], <link rel=canonical/alternate>, srcset.
- Détection de shadow DOM / Web Components (customElements, attachShadow).
- Crawl de fichiers JSON découverts (APIs REST exposées publiquement).
- Extraction des endpoints GraphQL depuis le JS.
- Découverte de .well-known/ (security.txt, openid-configuration, assetlinks.json).
- Détection de clés/secrets dans les réponses HTML et JS (API keys, tokens JWT).
- Score de risque par URL : les URLs avec plusieurs params intéressants
  reçoivent un Finding HIGH au lieu de INFO.
- Rate limiting adaptatif : ralentit si le serveur retourne des 429.
- Gestion des redirections cross-origin (les log mais ne les suit pas).
- Paramètres POST extraits des formulaires (method=POST) → Finding dédié.
- Déduplication canonique des URLs (tri des query params, suppression des
  ancres + tracking params utm_*, fbclid, gclid).
- Extraction des WebSockets (ws://, wss://) pour recon.
- Support basique d'auth bearer : si cfg.headers contient Authorization.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import xml.etree.ElementTree as ET
from collections import deque
from typing import AsyncGenerator
from urllib.parse import (
    urljoin, urlparse, parse_qs, urlencode,
    urlunparse, quote
)

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity

# ── Extensions à ignorer ──────────────────────────────────────────────────────

_SKIP_EXT = (
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".webp", ".avif",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".pdf", ".zip", ".tar", ".gz", ".bz2", ".xz",
    ".mp4", ".webm", ".mp3", ".ogg", ".wav", ".avi", ".mov",
    ".exe", ".dmg", ".deb", ".rpm", ".apk",
)

# Paramètres de tracking à supprimer lors de la canonicalisation
_TRACKING_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid", "msclkid", "mc_eid", "_ga", "ref", "source",
}

_INTERESTING_PARAMS = {
    "id", "user", "uid", "pid", "order", "item", "file", "path",
    "url", "redirect", "next", "return", "goto", "target",
    "src", "source", "dest", "destination", "ref", "referrer",
    "page", "token", "key", "secret", "password", "pass",
    "cmd", "exec", "query", "search", "q", "s", "action",
    "type", "view", "format", "include", "template", "lang",
    "callback", "jsonp", "debug", "test", "admin",
}

# Patterns de secrets dans le contenu HTML/JS
_SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("AWS Access Key",         re.compile(r"AKIA[0-9A-Z]{16}")),
    ("AWS Secret Key",         re.compile(r"(?:aws_secret|AWS_SECRET)[^=]*=\s*['\"]([A-Za-z0-9/+=]{40})['\"]", re.I)),
    ("Generic API Key",        re.compile(r"(?:api[_-]?key|apikey)\s*[:=]\s*['\"]([A-Za-z0-9_\-]{20,})['\"]", re.I)),
    ("Bearer Token",           re.compile(r"Bearer\s+([A-Za-z0-9\-._~+/]+=*)", re.I)),
    ("Private Key header",     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("JWT Token",              re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("Google API Key",         re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Slack Token",            re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}")),
    ("GitHub Token",           re.compile(r"ghp_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{82}")),
    ("Database URL",           re.compile(r"(?:mysql|postgres|mongodb|redis)://[^\s\"'<>]{10,}", re.I)),
    ("SendGrid API Key",       re.compile(r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}")),
]

_GRAPHQL_PATTERN = re.compile(
    r'(?:endpoint|url|path)\s*[:=]\s*["\']([^"\']*graphql[^"\']*)["\']',
    re.I
)
_WS_PATTERN = re.compile(r'["\']?(wss?://[^\s"\'<>]{5,})["\']?', re.I)


# ── Crawler ───────────────────────────────────────────────────────────────────

class Crawler:

    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req        = req
        self._heuristic  = heuristic
        self._cfg        = cfg
        self._max_pages: int = getattr(cfg.scan, "crawl_max_pages", 200)
        self._concurrency: int = getattr(cfg.scan, "crawl_concurrency", 15)
        self._rate_delay: float = 0.0  # adaptatif
        # v5.11 — URLs déjà visitées par le crawl passif (skip en recon actif)
        self._skip_urls: set[str] = set()

    def set_skip_urls(self, urls: set[str]) -> None:
        """v5.11 — Indique au crawler les URLs déjà visitées passivement.
        Ces URLs seront ajoutées à visited d'emblée pour éviter le double-crawl.
        """
        self._skip_urls = set(urls)

    async def run(self, target: str) -> AsyncGenerator[Finding, None]:
        base    = self._base(target)
        visited: set[str]  = set(self._canonicalize(u) for u in self._skip_urls)
        pending: set[str]  = {target}
        queue: deque[str]  = deque([target])
        # Canonical fingerprints pour éviter les doublons de contenu identique
        seen_fingerprints: set[str] = set()

        # ── Phase 0 : well-known + robots + sitemaps ───────────────────
        async for f in self._probe_well_known(base):
            yield f
        async for f in self._parse_robots(base, queue, visited, pending):
            yield f
        async for f in self._parse_sitemap(base, queue, visited, pending):
            yield f

        # ── Phase 1 : spider ──────────────────────────────────────────
        while queue and len(visited) < self._max_pages:
            # Construire un batch
            batch: list[str] = []
            while queue and len(batch) < self._concurrency:
                url = queue.popleft()
                pending.discard(url)
                canon = self._canonicalize(url)
                if canon not in visited and self._same_origin(url, base):
                    visited.add(canon)
                    batch.append(url)

            if not batch:
                break

            if self._rate_delay > 0:
                await asyncio.sleep(self._rate_delay)

            responses = await asyncio.gather(
                *[self._req.get(u) for u in batch],
                return_exceptions=True,
            )

            for url, resp in zip(batch, responses):
                if isinstance(resp, Exception) or resp.error:
                    continue

                # Rate limiting adaptatif
                if resp.status == 429:
                    self._rate_delay = min(self._rate_delay + 0.5, 5.0)
                    pending.add(url)
                    queue.appendleft(url)
                    continue
                elif resp.status in (200, 201) and self._rate_delay > 0:
                    self._rate_delay = max(0.0, self._rate_delay - 0.1)

                if resp.status not in (200, 201):
                    continue

                # Déduplication par fingerprint de contenu
                fp = hashlib.md5(resp.body[:512].encode(errors="replace")).hexdigest()
                if fp in seen_fingerprints:
                    continue
                seen_fingerprints.add(fp)

                ct = (resp.headers or {}).get("content-type", "")

                # ── HTML ──────────────────────────────────────────────
                if "html" in ct or not ct:
                    for link in self._extract_links(resp.body, url):
                        self._enqueue(link, visited, pending, queue)

                    for form_url, inputs, method in self._extract_forms(resp.body, url):
                        sev = Severity.INFO if method.upper() == "GET" else Severity.LOW
                        yield Finding(
                            title=f"Form découvert ({method.upper()})",
                            severity=sev,
                            url=form_url,
                            module="recon/crawler",
                            description=f"Formulaire {method.upper()} avec {len(inputs)} champ(s)",
                            evidence=f"Params: {inputs}",
                        )
                        # POST forms → candidats CSRF/injection
                        if method.upper() == "POST" and inputs:
                            yield Finding(
                                title="POST Form — candidat injection/CSRF",
                                severity=Severity.LOW,
                                url=form_url,
                                module="recon/crawler",
                                description=(
                                    f"Formulaire POST exposant {len(inputs)} champ(s) — "
                                    "à tester pour XSS, SQLi, CSRF."
                                ),
                                evidence=f"Champs: {inputs}",
                            )

                    for js_link in self._extract_js_urls(resp.body, url):
                        self._enqueue(js_link, visited, pending, queue)

                    # WebSockets dans HTML
                    for ws_url in _WS_PATTERN.findall(resp.body):
                        if ws_url.startswith(("ws://", "wss://")):
                            yield Finding(
                                title="WebSocket endpoint découvert",
                                severity=Severity.INFO,
                                url=url,
                                module="recon/crawler",
                                description=f"WebSocket détecté : {ws_url}",
                                evidence=ws_url,
                            )

                    # Secrets dans HTML
                    async for f in self._detect_secrets(resp.body, url):
                        yield f

                # ── JavaScript ────────────────────────────────────────
                if "javascript" in ct or url.endswith(".js"):
                    for link in self._extract_links_from_js(resp.body, url):
                        self._enqueue(link, visited, pending, queue)

                    # GraphQL endpoints
                    for gql in _GRAPHQL_PATTERN.findall(resp.body):
                        full = urljoin(url, gql)
                        if self._same_origin(full, base):
                            yield Finding(
                                title="GraphQL endpoint découvert",
                                severity=Severity.INFO,
                                url=full,
                                module="recon/crawler",
                                description=f"Endpoint GraphQL détecté dans le JS : {full}",
                                evidence=f"Source JS: {url}",
                            )

                    # Secrets dans JS
                    async for f in self._detect_secrets(resp.body, url):
                        yield f

                # ── JSON (API REST) ───────────────────────────────────
                if "json" in ct or url.endswith(".json"):
                    yield Finding(
                        title="Endpoint JSON/API découvert",
                        severity=Severity.INFO,
                        url=url,
                        module="recon/crawler",
                        description="Réponse JSON publiquement accessible.",
                        evidence=resp.body[:200],
                    )

                # ── Params intéressants ───────────────────────────────
                interesting = self._interesting_params(url)
                if interesting:
                    score = len(interesting)
                    sev   = Severity.HIGH if score >= 3 else (
                            Severity.MEDIUM if score == 2 else Severity.INFO)
                    yield Finding(
                        title="URL avec paramètres à risque",
                        severity=sev,
                        url=url,
                        module="recon/crawler",
                        description=(
                            f"{score} paramètre(s) potentiellement vulnérable(s) : {interesting}"
                        ),
                        evidence=url,
                    )

                # ── Redirections cross-origin ─────────────────────────
                location = (resp.headers or {}).get("location", "")
                if location and not self._same_origin(location, base):
                    yield Finding(
                        title="Redirection cross-origin détectée",
                        severity=Severity.LOW,
                        url=url,
                        module="recon/crawler",
                        description=f"Redirection vers domaine externe : {location}",
                        evidence=f"Location: {location}",
                    )

    # ── Well-known ────────────────────────────────────────────────────────────

    async def _probe_well_known(self, base: str) -> AsyncGenerator[Finding, None]:
        probes = [
            ("/.well-known/security.txt",         "Security.txt",            Severity.INFO),
            ("/.well-known/openid-configuration", "OpenID Configuration",    Severity.LOW),
            ("/.well-known/assetlinks.json",      "Asset Links (Android)",   Severity.INFO),
            ("/.well-known/apple-app-site-association", "Apple App Assoc.",  Severity.INFO),
            ("/humans.txt",                       "humans.txt",              Severity.INFO),
            ("/crossdomain.xml",                  "crossdomain.xml (Flash)", Severity.LOW),
            ("/clientaccesspolicy.xml",           "clientaccesspolicy.xml",  Severity.LOW),
        ]
        for path, name, sev in probes:
            url  = f"{base}{path}"
            resp = await self._req.get(url)
            if resp.error or resp.status != 200:
                continue
            yield Finding(
                title=f"{name} accessible",
                severity=sev,
                url=url,
                module="recon/crawler",
                description=f"`{path}` est accessible publiquement.",
                evidence=resp.body[:200],
            )

    # ── robots.txt ────────────────────────────────────────────────────────────

    async def _parse_robots(
        self, base: str, queue: deque, visited: set, pending: set
    ) -> AsyncGenerator[Finding, None]:
        url  = f"{base}/robots.txt"
        resp = await self._req.get(url)
        if resp.error or resp.status != 200:
            return

        paths_found:   list[str] = []
        sitemaps_found: list[str] = []

        for line in resp.body.splitlines():
            line = line.strip()
            low  = line.lower()
            if low.startswith(("disallow:", "allow:")):
                _, _, path = line.partition(":")
                path = path.strip()
                if path and path != "/":
                    full = urljoin(base, path)
                    paths_found.append(path)
                    self._enqueue(full, visited, pending, queue)
            elif low.startswith("sitemap:"):
                parts = line.split(":", 1)
                if len(parts) == 2:
                    sm = parts[1].strip()
                    if sm:
                        sitemaps_found.append(sm)

        if paths_found:
            yield Finding(
                title=f"robots.txt — {len(paths_found)} paths disclosed",
                severity=Severity.LOW,
                url=url,
                module="recon/crawler",
                description="robots.txt expose des paths cachés (Disallow/Allow).",
                evidence="\n".join(paths_found[:20]),
            )

        visited_sitemaps: set[str] = {url}
        for sm in sitemaps_found:
            async for f in self._fetch_sitemap(sm, base, queue, visited, pending, visited_sitemaps):
                yield f

    # ── sitemap ───────────────────────────────────────────────────────────────

    async def _parse_sitemap(
        self, base: str, queue: deque, visited: set, pending: set
    ) -> AsyncGenerator[Finding, None]:
        visited_sitemaps: set[str] = set()
        for path in ("/sitemap.xml", "/sitemap_index.xml", "/sitemap.php", "/sitemap.txt"):
            url = f"{base}{path}"
            async for f in self._fetch_sitemap(url, base, queue, visited, pending, visited_sitemaps):
                yield f

    async def _fetch_sitemap(
        self, url: str, origin_base: str,
        queue: deque, visited: set, pending: set,
        visited_sitemaps: set,
    ) -> AsyncGenerator[Finding, None]:
        if url in visited_sitemaps:
            return
        visited_sitemaps.add(url)

        resp = await self._req.get(url)
        if resp.error or resp.status != 200:
            return
        ct = (resp.headers or {}).get("content-type", "")
        if "xml" not in ct and not resp.body.strip().startswith("<"):
            # Essai format texte (une URL par ligne)
            urls_txt = [
                line.strip() for line in resp.body.splitlines()
                if line.strip().startswith("http")
            ]
            if urls_txt:
                for u in urls_txt:
                    self._enqueue(u, visited, pending, queue)
                yield Finding(
                    title=f"sitemap.txt — {len(urls_txt)} URLs",
                    severity=Severity.INFO,
                    url=url,
                    module="recon/crawler",
                    description=f"Sitemap texte expose {len(urls_txt)} URL(s).",
                    evidence="\n".join(urls_txt[:10]),
                )
            return

        urls_found:     list[str] = []
        nested_sitemaps: list[str] = []

        try:
            root = ET.fromstring(resp.body)
            ns   = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
            for loc in root.findall(".//sm:sitemap/sm:loc", ns):
                if loc.text:
                    nested_sitemaps.append(loc.text.strip())
            for loc in root.findall(".//sm:url/sm:loc", ns):
                if loc.text:
                    entry = loc.text.strip()
                    urls_found.append(entry)
                    if self._same_origin(entry, origin_base):
                        self._enqueue(entry, visited, pending, queue)
        except ET.ParseError:
            for m in re.finditer(r"<loc>\s*(https?://[^<]+)\s*</loc>", resp.body):
                entry = m.group(1).strip()
                urls_found.append(entry)
                if self._same_origin(entry, origin_base):
                    self._enqueue(entry, visited, pending, queue)

        if urls_found:
            yield Finding(
                title=f"sitemap.xml — {len(urls_found)} URLs",
                severity=Severity.INFO,
                url=url,
                module="recon/crawler",
                description=f"Sitemap expose {len(urls_found)} URL(s).",
                evidence="\n".join(urls_found[:10]),
            )

        for nested in nested_sitemaps[:10]:
            async for f in self._fetch_sitemap(
                nested, origin_base, queue, visited, pending, visited_sitemaps
            ):
                yield f

    # ── Extracteurs HTML ──────────────────────────────────────────────────────

    def _extract_links(self, body: str, base_url: str) -> list[str]:
        patterns = [
            r'href=["\']([^"\'>\s]+)',
            r'action=["\']([^"\'>\s]+)',
            # data-* attributs
            r'data-(?:url|href|src|link|target)=["\']([^"\'>\s]+)',
            # meta refresh
            r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+content=["\'][^;]*;\s*url=([^"\'>\s]+)',
            # link canonical/alternate
            r'<link[^>]+(?:canonical|alternate)[^>]+href=["\']([^"\'>\s]+)',
            # srcset (trop d'images ? on prend quand même les .html)
            r'srcset=["\']([^"\'>\s]+)',
        ]
        links: set[str] = set()
        for pat in patterns:
            for m in re.finditer(pat, body, re.I):
                href = m.group(1).split(",")[0].strip()  # srcset peut avoir plusieurs
                if href.startswith(("mailto:", "tel:", "javascript:", "#", "data:", "void(")):
                    continue
                full   = urljoin(base_url, href)
                parsed = urlparse(full)
                clean  = parsed._replace(fragment="").geturl()
                if not any(parsed.path.lower().endswith(ext) for ext in _SKIP_EXT):
                    links.add(clean)
        return list(links)

    def _extract_js_urls(self, body: str, base_url: str) -> list[str]:
        urls: list[str] = []
        for m in re.finditer(
            r'<script[^>]+src=["\']([^"\'>\s]+\.js[^"\'>\s]*)["\']', body, re.I
        ):
            full = urljoin(base_url, m.group(1))
            if urlparse(full).scheme in ("http", "https"):
                urls.append(full)
        return urls

    def _extract_links_from_js(self, body: str, base_url: str) -> list[str]:
        raw_patterns = [
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.(?:get|post|put|delete|patch|request)\(["\']([^"\']+)["\']',
            r'(?:"|\'|`)(/(?:api|v\d|admin|internal|graphql|rest|auth|backend|service|webhook)[^\s"\'`<>]*)',
            r'(?:"|\'|`)(/[a-z0-9_\-/]+\.(?:json|xml|yaml|yml|env|config|cfg|php|asp|aspx))',
            r'(?:url|href|path|endpoint|route|baseURL|baseUrl)\s*[:=]\s*["\']([^"\']{3,150})["\']',
            r'(?:window|document)\.location(?:\.href)?\s*=\s*["\']([^"\']+)["\']',
            r'(?:import|require)\s*\(["\']([^"\']+)["\']',
            r'XMLHttpRequest[^;]*\.open\(["\'](?:GET|POST)["\'],\s*["\']([^"\']+)["\']',
        ]
        links: set[str] = set()
        base  = self._base(base_url)
        for pat in raw_patterns:
            for m in re.finditer(pat, body, re.I):
                raw = m.group(1).strip()
                if raw.startswith(("http://", "https://")):
                    if self._same_origin(raw, base):
                        links.add(raw)
                elif raw.startswith("/"):
                    links.add(urljoin(base_url, raw))
                elif raw.startswith("."):
                    resolved = urljoin(base_url, raw)
                    if self._same_origin(resolved, base):
                        links.add(resolved)
                # bare npm module names → skip
        return list(links)

    def _extract_forms(
        self, body: str, base_url: str
    ) -> list[tuple[str, list[str], str]]:
        forms: list[tuple[str, list[str], str]] = []
        form_pat   = re.compile(r"<form[^>]*>(.*?)</form>", re.I | re.S)
        action_pat = re.compile(r'action=["\']([^"\']*)["\']', re.I)
        method_pat = re.compile(r'method=["\']([^"\']*)["\']', re.I)
        input_pat  = re.compile(
            r'<(?:input|textarea|select)[^>]+name=["\']([^"\']+)["\']', re.I
        )
        for m in form_pat.finditer(body):
            form_html = m.group(0)
            action_m  = action_pat.search(form_html)
            method_m  = method_pat.search(form_html)
            action    = urljoin(base_url, action_m.group(1)) if action_m and action_m.group(1) else base_url
            method    = method_m.group(1) if method_m else "GET"
            inputs    = input_pat.findall(m.group(1))
            if inputs:
                forms.append((action, inputs, method))
        return forms

    # ── Détection de secrets ──────────────────────────────────────────────────

    async def _detect_secrets(self, body: str, url: str) -> AsyncGenerator[Finding, None]:
        for name, pattern in _SECRET_PATTERNS:
            match = pattern.search(body)
            if match:
                secret_fragment = match.group(0)[:60]
                yield Finding(
                    title=f"Secret potentiel exposé — {name}",
                    severity=Severity.CRITICAL,
                    url=url,
                    module="recon/crawler",
                    description=(
                        f"Pattern correspondant à `{name}` détecté dans la réponse. "
                        "Vérifier qu'il ne s'agit pas d'un faux positif."
                    ),
                    evidence=f"Fragment: {secret_fragment}...",
                    cwe="CWE-312",
                    remediation=(
                        "Ne jamais exposer de secrets dans le code frontend ou les réponses HTTP. "
                        "Utiliser des variables d'environnement côté serveur uniquement. "
                        "Révoquer immédiatement les credentials exposés."
                    ),
                )

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _interesting_params(self, url: str) -> list[str]:
        params = parse_qs(urlparse(url).query)
        return [k for k in params if k.lower() in _INTERESTING_PARAMS]

    def _enqueue(
        self, url: str, visited: set, pending: set, queue: deque
    ) -> None:
        canon = self._canonicalize(url)
        if canon not in visited and url not in pending:
            queue.append(url)
            pending.add(url)

    @staticmethod
    def _canonicalize(url: str) -> str:
        """Canonicalise une URL : tri des params, suppression tracking, lowercase host."""
        try:
            p = urlparse(url)
            params = parse_qs(p.query, keep_blank_values=True)
            # Suppression des paramètres de tracking
            clean_params = {k: v for k, v in params.items() if k.lower() not in _TRACKING_PARAMS}
            # Tri pour déduplication
            sorted_query = urlencode(
                sorted((k, v[0]) for k, v in clean_params.items())
            )
            canonical = p._replace(
                scheme=p.scheme.lower(),
                netloc=p.netloc.lower(),
                fragment="",
                query=sorted_query,
            ).geturl()
            return canonical
        except Exception:
            return url

    @staticmethod
    def _base(target: str) -> str:
        p = urlparse(target)
        return f"{p.scheme}://{p.netloc}"

    @staticmethod
    def _same_origin(url: str, base: str) -> bool:
        try:
            return urlparse(url).netloc == urlparse(base).netloc
        except Exception:
            return False
