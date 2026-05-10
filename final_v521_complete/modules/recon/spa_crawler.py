"""
PhantomScan — SPA Crawler
===========================
Extrait les endpoints et routes depuis les Single Page Applications
(React, Vue, Angular, Svelte, Next.js, Nuxt.js).

Les SPA chargent leur code en JavaScript — le crawler HTML classique
manque tous les endpoints définis dans le JS bundle.

Techniques :
  1. Extraction de routes depuis les bundles JS (regex sur les path strings)
  2. Détection de frameworks JS et extraction spécifique
  3. Source maps (.map) pour avoir le code source lisible
  4. API endpoints dans le JS (fetch/axios/XMLHttpRequest patterns)
  5. Constantes d'URL dans les builds webpack/vite

Sources analysées :
  - Scripts inline dans le HTML
  - Fichiers JS référencés
  - Source maps si disponibles
  - window.__INITIAL_STATE__ / __NEXT_DATA__ / __NUXT__
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import AsyncIterator
from urllib.parse import urlparse, urljoin

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity
from phantomscan.core.scanner_mixin import ScannerMixin


# ── Patterns d'extraction d'endpoints ─────────────────────────────────────────
_API_FETCH_RE = re.compile(
    r"""(?:fetch|axios\.(?:get|post|put|delete|patch)|http\.(?:get|post))\s*\(\s*[`'"]((/[a-zA-Z0-9_/\-\.{}:?=&%]+)[`'"]|(`[^`]+`))""",
    re.I,
)

_API_URL_CONST_RE = re.compile(
    r"""(?:url|URL|endpoint|path|route|api)\s*[:=]\s*[`'"]((/[a-zA-Z0-9_/\-\.{}:?=&%]{3,})[`'"])""",
    re.I,
)

_REACT_ROUTE_RE = re.compile(
    r"""(?:path|to|href)\s*[:=]\s*[`'"]([/][a-zA-Z0-9_/\-:*?=&%\.]{2,})[`'"]""",
    re.I,
)

_TEMPLATE_URL_RE = re.compile(
    r"""["'`](/(?:api|v\d|service|rest|graphql|admin|auth|user|account)[a-zA-Z0-9_/\-\.{}:?=&%]*)[`'"]""",
    re.I,
)

# ── Patterns de détection de framework ────────────────────────────────────────
_FRAMEWORK_SIGS = {
    "React":   [r"react\.development\.js|react-dom|__reactFiber", r"createElement\("],
    "Vue":     [r"vue\.runtime|__vue_app__|createApp\(", r"Vue\.component"],
    "Angular": [r"angular\.min\.js|ng-app|platform-browser", r"NgModule"],
    "Next.js": [r"__NEXT_DATA__|_next/static|next/dist"],
    "Nuxt":    [r"__NUXT__|_nuxt/|nuxt\.js"],
    "Svelte":  [r"svelte/internal|__svelte|SvelteComponent"],
}

# ── Patterns d'état initial (SSR) ─────────────────────────────────────────────
_SSR_STATE_RE = re.compile(
    r'(?:window\.__(?:NEXT_DATA|NUXT|INITIAL_STATE|APP_STATE|REDUX_STATE|PRELOADED_STATE|'
    r'APP_CONFIG|INIT_DATA)__\s*=\s*|<script[^>]+id="__NEXT_DATA__"[^>]*>)\s*(\{.{10,}?\})\s*(?:</script>|;)',
    re.S,
)

# ── Source map ─────────────────────────────────────────────────────────────────
_SOURCEMAP_RE = re.compile(r'//# sourceMappingURL=(.+\.map)')


class SPACrawler(ScannerMixin):
    """Crawl orienté SPA — extraction d'endpoints depuis les JS bundles."""

    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req = req
        self._heur = heuristic
        self._cfg = cfg
        self._visited_js: set[str] = set()
        self._found_endpoints: set[str] = set()

    async def run(self, target: str) -> AsyncIterator[Finding]:
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # 1. Charger la page principale
        resp = await self._req.get(target)
        if resp.error:
            return
        html = resp.body or ""

        # 2. Détecter le framework
        framework = self._detect_framework(html)

        # 3. Extraire les scripts JS référencés
        js_urls = self._extract_js_urls(html, base, target)

        # 4. Analyser l'état SSR (Next.js, Nuxt)
        ssr_endpoints = self._extract_ssr_state(html, base)

        # 5. Analyser chaque bundle JS
        all_endpoints: list[str] = list(ssr_endpoints)
        js_tasks = [self._analyze_js(url, base) for url in js_urls[:12]]
        js_results = await asyncio.gather(*js_tasks, return_exceptions=True)
        for result in js_results:
            if isinstance(result, list):
                all_endpoints.extend(result)

        # 6. Analyser les scripts inline
        inline_endpoints = self._extract_inline_scripts(html, base)
        all_endpoints.extend(inline_endpoints)

        # 7. Dédupliquer et scorer
        unique = list(dict.fromkeys(all_endpoints))
        api_endpoints = [u for u in unique if re.search(r'/api/|/v\d+/|/rest/', u, re.I)]
        auth_endpoints = [u for u in unique if re.search(r'/auth|/login|/token|/oauth', u, re.I)]

        # 8. Publier sur le bus
        if self.bus and unique:
            from phantomscan.core.intelligence import DiscoveredEndpoint
            for ep_path in unique[:200]:
                ep_url = urljoin(base, ep_path) if ep_path.startswith("/") else ep_path
                params_re = re.findall(r'[?&]([^=&]+)=', ep_url)
                path_params = re.findall(r':([a-zA-Z_]+)|{([a-zA-Z_]+)}', ep_path)
                all_params = params_re + [p[0] or p[1] for p in path_params]

                score = 0.4
                if re.search(r'/api/|/v\d+/', ep_url, re.I):
                    score = 0.8
                if re.search(r'/auth|/admin|/token|/user', ep_url, re.I):
                    score = 0.9
                if all_params:
                    score = min(1.0, score + 0.1)

                self.bus.publish(DiscoveredEndpoint(
                    url=ep_url, method="GET",
                    params=all_params, source="recon/spa_crawler",
                    score=score,
                ))

        # 9. Findings
        if unique:
            yield Finding(
                title=f"SPA Crawler — {len(unique)} endpoints extracted"
                      + (f" [{framework}]" if framework else ""),
                severity=Severity.INFO,
                url=target,
                module="recon/spa_crawler",
                description=(
                    f"Analyse des bundles JS{'  [' + framework + ']' if framework else ''} : "
                    f"{len(unique)} endpoints/routes extraits.\n"
                    f"  API endpoints : {len(api_endpoints)}\n"
                    f"  Auth endpoints: {len(auth_endpoints)}\n"
                    f"  JS files analysed: {len(js_urls)}"
                ),
                evidence=(
                    f"Framework: {framework or 'unknown'} | "
                    f"JS bundles: {len(js_urls)} | "
                    f"Endpoints: {len(unique)} | "
                    f"API: {api_endpoints[:3]}"
                ),
                cwe="CWE-200",
                remediation=(
                    "Vérifier que les endpoints découverts dans les JS bundles "
                    "sont bien protégés par authentification et autorisation."
                ),
            )

        # 10. Endpoints auth/admin trouvés dans le JS
        for ep in auth_endpoints[:5]:
            full_url = urljoin(base, ep) if ep.startswith("/") else ep
            yield Finding(
                title=f"Auth/Admin Endpoint in JS Bundle — {ep}",
                severity=Severity.LOW,
                url=full_url,
                module="recon/spa_crawler",
                description=(
                    f"Endpoint sensible extrait du bundle JS : `{ep}`. "
                    "Vérifier qu'il nécessite une authentification forte."
                ),
                evidence=f"Found in JS bundle | path={ep}",
                cwe="CWE-200",
                remediation="Sécuriser tous les endpoints exposés dans le code JS frontend.",
            )

    # ── Détection framework ───────────────────────────────────────────────────

    def _detect_framework(self, html: str) -> str | None:
        for name, patterns in _FRAMEWORK_SIGS.items():
            if any(re.search(p, html, re.I) for p in patterns):
                return name
        return None

    # ── Extraction URLs JS ────────────────────────────────────────────────────

    def _extract_js_urls(self, html: str, base: str, page_url: str) -> list[str]:
        """Extrait les URLs de scripts JS depuis le HTML."""
        urls = []
        script_src_re = re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.I)
        for m in script_src_re.finditer(html):
            src = m.group(1)
            if src.startswith("//"):
                src = urlparse(page_url).scheme + ":" + src
            elif src.startswith("/"):
                src = base + src
            elif not src.startswith("http"):
                src = urljoin(page_url, src)
            if src not in self._visited_js:
                urls.append(src)
        return urls

    # ── Analyse JS bundle ─────────────────────────────────────────────────────

    async def _analyze_js(self, js_url: str, base: str) -> list[str]:
        """Analyse un fichier JS et extrait les endpoints."""
        if js_url in self._visited_js:
            return []
        self._visited_js.add(js_url)

        resp = await self._req.get(js_url)
        if resp.error or resp.status != 200:
            return []

        content = resp.body or ""
        endpoints = set()

        # Extraire depuis fetch/axios/http
        for m in _API_FETCH_RE.finditer(content):
            ep = m.group(2) or m.group(1)
            if ep and 3 < len(ep) < 200:
                endpoints.add(ep.strip("`'\""))

        # Extraire depuis les constantes URL
        for m in _API_URL_CONST_RE.finditer(content):
            ep = m.group(2)
            if ep and 3 < len(ep) < 200:
                endpoints.add(ep.strip("`'\""))

        # Extraire les routes React/Vue
        for m in _REACT_ROUTE_RE.finditer(content):
            ep = m.group(1)
            if ep and ep != "/" and 3 < len(ep) < 100:
                endpoints.add(ep)

        # Extraire les URL templates
        for m in _TEMPLATE_URL_RE.finditer(content):
            ep = m.group(1)
            if ep and 3 < len(ep) < 150:
                endpoints.add(ep.strip("`'\""))

        # Source map : analyser si disponible
        sm_match = _SOURCEMAP_RE.search(content)
        if sm_match:
            sm_path = sm_match.group(1)
            if not sm_path.startswith("http"):
                sm_url = urljoin(js_url, sm_path)
            else:
                sm_url = sm_path
            sm_eps = await self._analyze_sourcemap(sm_url)
            endpoints.update(sm_eps)

        return list(endpoints)

    # ── Analyse source map ────────────────────────────────────────────────────

    async def _analyze_sourcemap(self, sm_url: str) -> list[str]:
        """Extrait les paths depuis un source map (révèle la structure src)."""
        if sm_url in self._visited_js:
            return []
        self._visited_js.add(sm_url)

        resp = await self._req.get(sm_url)
        if resp.error or resp.status != 200:
            return []

        try:
            data = json.loads(resp.body or "{}")
            sources = data.get("sources", [])
            # Les sources révèlent la structure du projet
            # Chercher les fichiers de routes/API
            route_files = [
                s for s in sources
                if re.search(r"route|router|api|endpoint|service|store", s, re.I)
            ]
            return route_files[:20]
        except (json.JSONDecodeError, TypeError):
            return []

    # ── État SSR ──────────────────────────────────────────────────────────────

    def _extract_ssr_state(self, html: str, base: str) -> list[str]:
        """Extrait les endpoints depuis l'état SSR (Next.js, Nuxt, Redux)."""
        endpoints = []
        for m in _SSR_STATE_RE.finditer(html):
            raw = m.group(1)
            try:
                data = json.loads(raw)
                # Chercher des URLs dans les données SSR
                self._extract_urls_from_json(data, endpoints)
            except (json.JSONDecodeError, TypeError):
                # Extraction regex de fallback
                for url_m in re.finditer(r'"((?:/[a-zA-Z0-9_/\-\.{}: ]+){2,})"', raw):
                    ep = url_m.group(1)
                    if len(ep) > 5:
                        endpoints.append(ep)
        return endpoints[:50]

    def _extract_urls_from_json(self, obj, result: list, depth: int = 0) -> None:
        """Récursivement extrait les URLs depuis un objet JSON."""
        if depth > 5:
            return
        if isinstance(obj, str):
            if obj.startswith("/") and len(obj) > 3:
                result.append(obj)
        elif isinstance(obj, dict):
            for v in obj.values():
                self._extract_urls_from_json(v, result, depth + 1)
        elif isinstance(obj, list):
            for item in obj[:20]:
                self._extract_urls_from_json(item, result, depth + 1)

    # ── Scripts inline ────────────────────────────────────────────────────────

    def _extract_inline_scripts(self, html: str, base: str) -> list[str]:
        """Extrait les endpoints depuis les scripts inline du HTML."""
        endpoints = []
        inline_re = re.compile(r'<script(?:[^>]*)>(.*?)</script>', re.S | re.I)
        for m in inline_re.finditer(html):
            script_content = m.group(1)
            if len(script_content) < 50:
                continue
            for url_m in _TEMPLATE_URL_RE.finditer(script_content):
                ep = url_m.group(1)
                if ep and 3 < len(ep) < 150:
                    endpoints.append(ep)
        return endpoints[:30]
