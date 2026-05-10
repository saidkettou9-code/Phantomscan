"""
PhantomScan — 403/401 Forbidden Bypass Scanner
Techniques de bypass d'accès refusé :
  - Path normalization tricks (%2f, ../, ./, etc.)
  - Header-based bypass (X-Forwarded-For, X-Original-URL, X-Rewrite-URL)
  - HTTP method override (X-HTTP-Method-Override)
  - Case variation et double encoding
  - Trailing chars (/., /#, /;, /..;/)
"""

from __future__ import annotations

import asyncio
import uuid
from typing import AsyncGenerator
from urllib.parse import urlparse, quote

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester, ProbeRequest
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity
from phantomscan.core.scanner_mixin import ScannerMixin

# Endpoints classiques qui retournent souvent 403
PROTECTED_PATHS = [
    "/admin", "/admin/", "/administrator", "/dashboard", "/panel",
    "/api/admin", "/api/internal", "/api/v1/admin", "/api/v2/admin",
    "/config", "/backup", "/debug", "/console", "/actuator",
    "/actuator/env", "/actuator/health", "/actuator/mappings",
    "/.env", "/.git/HEAD", "/wp-admin", "/phpinfo.php",
    "/server-status", "/server-info", "/metrics",
]

# Path tricks
PATH_TRICKS = [
    "{path}/.",
    "{path}//",
    "{path}%20",
    "{path}%09",
    "{path}?",
    "{path}?debug=true",
    "{path}#",
    "{path}/*",
    "{path}.json",
    "{path}.html",
    "{path};/",
    "{path}/..;/",
    "/%2e{path}",
    "{path}%2f",
    "//{netloc}{path}",
    "{path}/..",
    # Double encoding
    "%252f{path_enc}",
    # Unicode normalization
    "{path_unicode}",
]

# Header overrides
HEADER_BYPASS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-ProxyUser-Ip": "127.0.0.1"},
    {"X-Original-URL": "{path}"},
    {"X-Rewrite-URL": "{path}"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Host": "localhost"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"Content-Length": "0"},
    {"Referer": "{base}/admin/"},
]

METHOD_OVERRIDES = [
    {"X-HTTP-Method-Override": "GET"},
    {"X-Method-Override": "GET"},
    {"_method": "GET"},
]


class ForbiddenBypassScanner(ScannerMixin):

    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req = req
        self._heuristic = heuristic
        self._cfg = cfg

    async def run(self, target: str) -> AsyncGenerator[Finding, None]:
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # D'abord identifier les 403/401 existants
        forbidden_paths = await self._find_forbidden(base)

        if not forbidden_paths:
            return

        # Pour chaque path interdit, tenter les bypasses
        for path, original_resp in forbidden_paths:
            async for f in self._try_all_bypasses(base, path, original_resp.status):
                yield f

    async def _get_baseline_403(self, base: str) -> int | None:
        """
        Fetch un path aléatoire pour obtenir la taille d'un 403 générique nginx.
        Si le serveur retourne 404 (ou autre) sur un path inexistant, baseline = None.
        """
        random_path = f"/{uuid.uuid4().hex}/nonexistent"
        resp = await self._req.get(f"{base}{random_path}")
        if not resp.error and resp.status == 403:
            return resp.content_length
        return None

    @staticmethod
    def _is_generic_403(resp, baseline_len: int | None) -> bool:
        """
        Vrai si la réponse 403 ressemble à un 403 nginx par défaut.
        Compare la taille avec la baseline (tolérance ±64 bytes).
        """
        if baseline_len is None:
            return False
        return abs(resp.content_length - baseline_len) <= 64

    async def _find_forbidden(self, base: str) -> list[tuple[str, object]]:
        """Cherche les endpoints qui retournent 401/403, en excluant les 403 nginx génériques."""
        # Baseline : taille d'un 403 sur un path qui n'existe certainement pas
        baseline_len = await self._get_baseline_403(base)

        sem = asyncio.Semaphore(10)

        async def probe(path: str):
            async with sem:
                resp = await self._req.get(f"{base}{path}")
                return path, resp

        tasks = [asyncio.create_task(probe(p)) for p in PROTECTED_PATHS]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        forbidden = []
        for item in results:
            if isinstance(item, Exception):
                continue
            path, resp = item
            if not resp.error and resp.status in (401, 403):
                # Filtre : ignorer les 403 de même taille que la baseline nginx
                if resp.status == 403 and self._is_generic_403(resp, baseline_len):
                    continue
                forbidden.append((path, resp))

        return forbidden

    async def _try_all_bypasses(
        self, base: str, path: str, original_status: int
    ) -> AsyncGenerator[Finding, None]:
        parsed = urlparse(base)
        netloc = parsed.netloc
        path_enc = quote(path, safe="")
        # Unicode substitution simple (/ → %c0%af)
        path_unicode = path.replace("/", "%c0%af")

        found_bypass = False

        # 1. Path tricks
        for trick_tpl in PATH_TRICKS:
            trick = (
                trick_tpl
                .replace("{path}", path)
                .replace("{netloc}", netloc)
                .replace("{path_enc}", path_enc)
                .replace("{path_unicode}", path_unicode)
            )
            url = f"{base}{trick}" if trick.startswith("/") else f"{base}/{trick}"
            resp = await self._req.get(url)
            if resp.error:
                continue
            if resp.status == 200 and self._heuristic.is_real_hit(resp, min_confidence=40):
                found_bypass = True
                yield Finding(
                    title=f"403 Bypass via path trick: {trick_tpl}",
                    severity=Severity.HIGH,
                    url=url,
                    module="vulns/forbidden_bypass",
                    description=(
                        f"L'accès à '{path}' (HTTP {original_status}) est bypassé via "
                        f"manipulation du path: '{trick}'."
                    ),
                    evidence=f"Original: {base}{path} → {original_status}\nBypass: {url} → {resp.status} ({resp.content_length}B)",
                    cwe="CWE-284",
                    remediation=(
                        "Normaliser les URLs côté serveur avant les vérifications d'accès. "
                        "Ne pas faire confiance au path brut pour les ACL."
                    ),
                )
                break  # Un seul bypass par path trick type

        # 2. Header bypass
        for headers_tpl in HEADER_BYPASS:
            headers = {}
            for k, v in headers_tpl.items():
                headers[k] = v.replace("{path}", path).replace("{base}", base)

            resp = await self._req.send(ProbeRequest(
                method="GET",
                url=f"{base}{path}",
                headers=headers,
            ))
            if resp.error:
                continue
            if resp.status == 200 and self._heuristic.is_real_hit(resp, min_confidence=40):
                found_bypass = True
                yield Finding(
                    title=f"403 Bypass via header: {list(headers.keys())[0]}",
                    severity=Severity.HIGH,
                    url=f"{base}{path}",
                    module="vulns/forbidden_bypass",
                    description=(
                        f"L'accès à '{path}' (HTTP {original_status}) est bypassé via "
                        f"le header {list(headers.keys())[0]}: {list(headers.values())[0]}."
                    ),
                    evidence=f"Header: {headers}\nStatus: {original_status} → {resp.status}",
                    cwe="CWE-290",
                    remediation=(
                        "Ne pas utiliser des headers proxy pour les décisions d'accès. "
                        "L'autorisation doit être basée sur l'authentification, pas l'IP source."
                    ),
                )

        # 3. HTTP method smuggling vers GET
        for method in ("POST", "PUT", "PATCH", "OPTIONS", "TRACE", "HEAD"):
            resp = await self._req.send(ProbeRequest(
                method=method,
                url=f"{base}{path}",
            ))
            if resp.error:
                continue
            if method == "HEAD" and resp.status == 200 and resp.content_length > 0:
                # HEAD bypass est rarement exploitable sans body — ne signaler que si
                # la taille suggère du vrai contenu (pas juste des headers vides)
                if not self._heuristic.is_real_hit(resp):
                    continue
                yield Finding(
                    title=f"403 Bypass via HEAD method on {path}",
                    severity=Severity.LOW,
                    url=f"{base}{path}",
                    module="vulns/forbidden_bypass",
                    description=(
                        f"HEAD sur '{path}' retourne 200 (content-length={resp.content_length}) "
                        f"alors que GET retourne {original_status}. "
                        "Les headers de réponse peuvent exposer des informations sensibles."
                    ),
                    evidence=f"GET → {original_status}, HEAD → {resp.status} ({resp.content_length}B)",
                    cwe="CWE-284",
                )
            elif method not in ("HEAD", "OPTIONS") and resp.status == 200 and self._heuristic.is_real_hit(resp, min_confidence=40):
                found_bypass = True
                yield Finding(
                    title=f"403 Bypass via HTTP method: {method}",
                    severity=Severity.HIGH,
                    url=f"{base}{path}",
                    module="vulns/forbidden_bypass",
                    description=(
                        f"La méthode {method} sur '{path}' retourne 200 alors que GET retourne {original_status}."
                    ),
                    evidence=f"GET → {original_status}, {method} → {resp.status} ({resp.content_length}B)",
                    cwe="CWE-284",
                    remediation="Appliquer les ACL sur toutes les méthodes HTTP, pas uniquement GET.",
                )

        # 4. Method override headers
        for override_hdr in METHOD_OVERRIDES:
            for http_method in ("POST", "PUT"):
                resp = await self._req.send(ProbeRequest(
                    method=http_method,
                    url=f"{base}{path}",
                    headers=override_hdr,
                ))
                if resp.error:
                    continue
                if resp.status == 200 and self._heuristic.is_real_hit(resp, min_confidence=40):
                    yield Finding(
                        title=f"403 Bypass via method override: {list(override_hdr.keys())[0]}",
                        severity=Severity.MEDIUM,
                        url=f"{base}{path}",
                        module="vulns/forbidden_bypass",
                        description=(
                            f"Method override via {override_hdr} bypass le contrôle d'accès sur '{path}'."
                        ),
                        evidence=f"{http_method} + {override_hdr} → {resp.status}",
                        cwe="CWE-284",
                    )
