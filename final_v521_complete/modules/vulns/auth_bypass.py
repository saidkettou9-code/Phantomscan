"""
PhantomScan — Auth Bypass
Techniques de contournement 401/403.
"""

from __future__ import annotations

import re
from typing import AsyncIterator
from urllib.parse import urlparse, urljoin

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester, ProbeRequest
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity


# ── Patterns WAF/reverse-proxy qui retournent 200 mais bloquent réellement ──
_WAF_REJECTION_PATTERNS = [
    re.compile(r"Request Rejected", re.I),
    re.compile(r"Your support ID is", re.I),
    re.compile(r"Access Denied", re.I),
    re.compile(r"Forbidden by policy", re.I),
    re.compile(r"<title>.*?(403|forbidden|rejected|blocked|error).*?</title>", re.I),
    re.compile(r"(mod_security|cloudflare.*blocked|blocked by)", re.I),
    re.compile(r"This page isn.t working|The page you.re looking for", re.I),
]

# Signatures de contenu sensible attendu selon le path demandé
_SENSITIVE_CONTENT_SIGNATURES: dict[str, re.Pattern] = {
    ".env":    re.compile(r"[A-Z_]{2,}\s*=\s*.+", re.M),       # KEY=value
    "admin":   re.compile(r"(admin|dashboard|logout|panel)", re.I),
    "config":  re.compile(r"(config|setting|database|secret)", re.I),
    "api":     re.compile(r"(\{|\[|\"[a-zA-Z]+\"\s*:)", re.M),  # JSON body
}


def _is_waf_block(body: str) -> bool:
    """Retourne True si la réponse est un blocage WAF déguisé en 200."""
    return any(p.search(body) for p in _WAF_REJECTION_PATTERNS)


def _body_looks_real(path: str, body: str, min_length: int = 100) -> bool:
    """
    Vérifie que le body de la réponse bypass contient du contenu réel,
    pas une page d'erreur générique.
    """
    if _is_waf_block(body):
        return False
    if len(body.strip()) < min_length:
        return False
    # Pour les paths sensibles, vérifier la présence d'une signature de contenu
    for key, sig in _SENSITIVE_CONTENT_SIGNATURES.items():
        if key in path:
            return bool(sig.search(body))
    # Rejeter les pages HTML 100% génériques (404/error pages déguisées)
    if body.strip().startswith("<!DOCTYPE") or body.strip().startswith("<html"):
        generic_indicators = [
            re.compile(r"(not found|page not found|404)", re.I),
            re.compile(r"(error|sorry|oops|something went wrong)", re.I),
        ]
        matches = sum(1 for p in generic_indicators if p.search(body[:500]))
        if matches >= 2:
            return False
    return True


# Headers de bypass courants
BYPASS_HEADERS: list[dict[str, str]] = [
    {"X-Original-URL": "/"},
    {"X-Rewrite-URL": "/"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-Host": "localhost"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"Forwarded": "for=127.0.0.1;host=localhost;proto=https"},
    {"CF-Connecting-IP": "127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
    {"Cluster-Client-IP": "127.0.0.1"},
    {"X-ProxyUser-Ip": "127.0.0.1"},
    {"X-Original-Remote-Addr": "127.0.0.1"},
]

# Variantes de chemins (case, encodage, slash)
PATH_VARIANTS: list[str] = [
    "/{path}/",
    "/{path}//",
    "/{path}%20",
    "/{path}%09",
    "/{path}?",
    "/{path}?debug=true",
    "/{path}#",
    "/{path}.json",
    "/{path}.html",
    "/{path}%2f",
    "/{path}%2F/",
    "/;/{path}",
    "///{path}",
    "/{path}..;/",
    "/{path}?id=1",
    # v5.10 — Unicode normalization bypasses
    "/{path_upper}",         # uppercase
    "/{path_unicode}",       # unicode lookalike chars
    "/\u0041dmin",           # Α (Latin capital A) → admin
    "/%ef%bc%8f{path}",      # ／ FULLWIDTH SOLIDUS
    "/{path}\u200b",         # Zero-width space
    "/{path};/",             # Semicolon bypass (Spring, Node)
    "/v1/{path}",            # Version prefix bypass
    "/api/{path}",           # API prefix bypass
]

# HTTP method bypass
METHODS: list[str] = ["GET", "POST", "HEAD", "OPTIONS", "TRACE", "PUT", "PATCH", "DELETE", "CONNECT"]


from phantomscan.core.scanner_mixin import ScannerMixin


class AuthBypassScanner(ScannerMixin):
    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req = req
        self._heuristic = heuristic
        self._cfg = cfg

    async def run(self, target: str) -> AsyncIterator[Finding]:
        # 1. Trouver les pages 401/403
        forbidden_urls = await self._find_forbidden(target)

        for url in forbidden_urls:
            async for f in self._try_bypass(url):
                yield f

    async def _find_forbidden(self, target: str) -> list[str]:
        """Récupère les URLs qui retournent 401 ou 403."""
        # On teste quelques paths sensibles connus
        sensitive = [
            "admin", "dashboard", "api/admin", "admin/users", "config",
            "management", "internal", "private", "secret", ".env",
        ]
        forbidden: list[str] = []
        base = target.rstrip("/")
        for path in sensitive:
            resp = await self._req.get(f"{base}/{path}")
            if not resp.error and resp.status in (401, 403):
                forbidden.append(resp.url)
        return forbidden

    async def _try_bypass(self, url: str) -> AsyncIterator[Finding]:
        parsed = urlparse(url)
        path = parsed.path.lstrip("/")
        base = f"{parsed.scheme}://{parsed.netloc}"

        original_resp = await self._req.get(url)
        if original_resp.error:
            return
        original_status = original_resp.status

        # ── Technique 1 : Header bypass ───────────────────────────────────
        for header_set in BYPASS_HEADERS:
            resp = await self._req.send(ProbeRequest(
                method="GET",
                url=url,
                headers=header_set,
            ))
            if resp.error:
                continue
            # FIX: skip 404/erreurs HTTP explicites
            if resp.status in (404, 410, 400):
                continue
            if resp.status == 200 and original_status in (401, 403):
                # FP-FIX: vérifier que le body est du contenu réel
                if not _body_looks_real(path, resp.body):
                    continue
                # fix v5.18-fp: body quasi-identique à l'original → WAF custom qui retourne
                # 200 avec une page d'erreur non listée dans _WAF_REJECTION_PATTERNS
                if self._heuristic.body_similarity(original_resp.body, resp.body) > 0.85:
                    continue
                header_name = list(header_set.keys())[0]
                yield Finding(
                    title=f"Auth Bypass via header: {header_name}",
                    severity=Severity.HIGH,
                    url=url,
                    module="vulns/auth_bypass",
                    description=f"Contournement {original_status} → 200 via header {header_name}: {list(header_set.values())[0]}",
                    evidence=f"Header: {header_set}",
                    cwe="CWE-284",
                    remediation="Valider l'accès côté serveur, pas via headers client.",
                )

        # ── Technique 2 : Path variant bypass ────────────────────────────
        seen_urls: set[str] = {url}  # FP-FIX: éviter de reporter l'URL originale comme bypass
        for template in PATH_VARIANTS:
            # Générer les variantes unicode si présentes dans le template
            if "{path_upper}" in template:
                variant_path = f"/{path.upper()}"
            elif "{path_unicode}" in template:
                # Remplacer 'a' par 'ａ' (FULLWIDTH LATIN SMALL LETTER A) dans le path
                variant_path = "/" + path.replace("a", "\uff41").replace("e", "\uff45")
            elif "{path}" in template:
                variant_path = template.format(path=path)
            else:
                variant_path = template

            variant_url = f"{base}{variant_path}"

            # FP-FIX: ne pas tester deux fois la même URL résolue
            if variant_url in seen_urls:
                continue
            seen_urls.add(variant_url)

            resp = await self._req.get(variant_url)
            if resp.error:
                continue
            # FIX: skip 404/erreurs HTTP explicites
            if resp.status in (404, 410, 400):
                continue
            if resp.status == 200 and original_status in (401, 403):
                # FP-FIX: vérifier que le body est du contenu réel, pas un blocage WAF
                if not _body_looks_real(path, resp.body):
                    continue
                # fix v5.18-fp: body quasi-identique → pas un vrai bypass
                if self._heuristic.body_similarity(original_resp.body, resp.body) > 0.85:
                    continue
                yield Finding(
                    title=f"Auth Bypass via path variant",
                    severity=Severity.HIGH,
                    url=variant_url,
                    module="vulns/auth_bypass",
                    description=f"Contournement {original_status} → 200 via variante de chemin",
                    evidence=f"Original: {url} | Bypass: {variant_url}",
                    cwe="CWE-284",
                    remediation="Normaliser les chemins avant validation des ACL. Appliquer la normalisation Unicode (NFC/NFKC) avant le contrôle d'accès.",
                )

        # ── Technique 3 : Method bypass ───────────────────────────────────
        # FP-FIX: HEAD/OPTIONS retournent 200 par défaut — seuls GET/POST/PUT/DELETE
        # peuvent révéler un vrai bypass. HEAD ne retourne pas de body → non vérifiable.
        _MEANINGFUL_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
        for method in METHODS:
            if method == "GET":
                continue
            resp = await self._req.send(ProbeRequest(method=method, url=url))
            if resp.error:
                continue
            # FIX: skip 404/erreurs HTTP explicites
            if resp.status in (404, 410, 400):
                continue
            if resp.status == 200 and original_status in (401, 403):
                # FP-FIX: HEAD/OPTIONS/TRACE retournent 200 normalement sans contenu
                # → non signifiants comme bypass sans vérification du body
                if method not in _MEANINGFUL_METHODS:
                    continue
                # FP-FIX: vérifier que le body est réel
                if not _body_looks_real(path, resp.body, min_length=50):
                    continue
                # fix v5.18-fp: body quasi-identique → pas un vrai bypass
                if self._heuristic.body_similarity(original_resp.body, resp.body) > 0.85:
                    continue
                yield Finding(
                    title=f"Auth Bypass via HTTP method: {method}",
                    severity=Severity.MEDIUM,
                    url=url,
                    module="vulns/auth_bypass",
                    description=f"Contournement {original_status} → 200 via méthode HTTP {method}",
                    evidence=f"Method: {method}",
                    cwe="CWE-284",
                    remediation="Restreindre les méthodes HTTP autorisées pour les ressources protégées.",
                )
