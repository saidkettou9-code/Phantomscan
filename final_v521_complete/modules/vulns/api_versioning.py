"""
PhantomScan — API Versioning Scanner
======================================
Détecte les anciennes versions d'API encore actives et potentiellement vulnérables.

Les équipes patchent souvent la dernière version de leur API mais oublient
d'appliquer les fixes sur les versions précédentes encore actives.
Cette technique est très fréquente dans les programmes BB (souvent P2/HIGH).

Techniques :
  1. Enumération des versions connues (/v1, /v2, /api/v1, etc.)
  2. Comparaison fonctionnelle : version ancienne = features/params différents
  3. Détection de versions sans auth via les anciennes routes
  4. Test des endpoints deprecated qui bypassent les contrôles modernes
  5. Header versioning (Accept: application/vnd.api+json;version=1)
"""

from __future__ import annotations

import asyncio
import re
from typing import AsyncIterator
from urllib.parse import urlparse

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester, ProbeRequest
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity
from phantomscan.core.scanner_mixin import ScannerMixin


# ── Schémas de versioning à tester ───────────────────────────────────────────
_VERSION_PREFIXES = [
    # Path versioning
    "/api/v1", "/api/v2", "/api/v3",
    "/api/v0", "/api/v1.0", "/api/v2.0",
    "/v1", "/v2", "/v3", "/v0",
    # Legacy paths
    "/api/beta", "/api/alpha", "/api/dev", "/api/test",
    "/api/internal", "/api/private", "/api/legacy",
    "/api/old", "/api/deprecated",
    # Numeric only
    "/1", "/2", "/rest/v1", "/rest/v2",
    "/service/v1", "/service/v2",
    "/api/1.0", "/api/2.0",
    # Mobile APIs (souvent moins strictes)
    "/api/mobile/v1", "/api/mobile/v2",
    "/mobile/api/v1", "/app/api/v1",
]

# ── Headers de versioning ─────────────────────────────────────────────────────
_VERSION_HEADERS = [
    {"API-Version": "1"},
    {"API-Version": "1.0"},
    {"Accept": "application/vnd.api+json;version=1"},
    {"Accept": "application/json; version=1.0"},
    {"X-API-Version": "1"},
    {"X-API-Version": "v1"},
]

# ── Endpoints sensibles à tester sur chaque version ──────────────────────────
_SENSITIVE_PATHS = [
    "/users", "/user", "/accounts", "/account",
    "/admin", "/admins",
    "/tokens", "/token", "/auth",
    "/profile", "/me",
    "/settings", "/config",
    "/export", "/dump",
    "/debug", "/health", "/status",
]

# ── Indicateurs d'API active ──────────────────────────────────────────────────
_API_ACTIVE_RE = re.compile(
    r'"(?:data|results?|users?|items?|records?|objects?|message|status)"',
    re.I,
)


class APIVersioningScanner(ScannerMixin):
    """Scanner de versioning API — détecte les versions obsolètes actives."""

    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req = req
        self._heur = heuristic
        self._cfg = cfg
        self._found: set[str] = set()

    async def run(self, target: str) -> AsyncIterator[Finding]:
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # 1. Détecter la version actuelle de l'API
        current_version = await self._detect_current_version(base, parsed.path)

        # 2. Enumérer les autres versions
        async for f in self._enumerate_versions(base, current_version):
            yield f

        # 3. Tester les headers de versioning
        async for f in self._test_version_headers(target):
            yield f

    # ── Détection version actuelle ────────────────────────────────────────────

    async def _detect_current_version(self, base: str, path: str) -> str | None:
        """Détecter la version courante depuis le chemin ou les réponses."""
        m = re.search(r'/v(\d+(?:\.\d+)?)', path)
        if m:
            return m.group(1)

        # Chercher dans les réponses
        resp = await self._req.get(base + "/api")
        if not resp.error:
            body = resp.body or ""
            m2 = re.search(r'"version"\s*:\s*"?v?(\d+(?:\.\d+)?)"?', body, re.I)
            if m2:
                return m2.group(1)
        return None

    # ── Enumération versions ──────────────────────────────────────────────────

    async def _enumerate_versions(
        self, base: str, current_version: str | None
    ) -> AsyncIterator[Finding]:
        """Tester toutes les variantes de versioning."""
        current_ver_num = None
        if current_version:
            m = re.match(r'(\d+)', current_version)
            if m:
                current_ver_num = int(m.group(1))

        active_versions: list[tuple[str, str]] = []  # (version_str, base_url)

        # Tester chaque préfixe
        tasks = []
        for prefix in _VERSION_PREFIXES:
            url = base + prefix
            tasks.append(self._probe_version(url, prefix))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for prefix, result in zip(_VERSION_PREFIXES, results):
            if isinstance(result, Exception) or not result:
                continue
            version_str, resp = result

            # Extraire le numéro de version
            vm = re.search(r'v?(\d+)', prefix)
            if not vm:
                continue
            ver_num = int(vm.group(1))

            # Cette version est "vieille" si < version courante
            is_old = current_ver_num is not None and ver_num < current_ver_num
            active_versions.append((prefix, base + prefix))

            # Tester les endpoints sensibles sur cette version
            async for f in self._test_sensitive_on_version(
                base + prefix, prefix, is_old
            ):
                yield f

        # Si plusieurs versions actives → signaler
        if len(active_versions) > 1:
            key = f"multi_version:{base}"
            if key not in self._found:
                self._found.add(key)
                yield Finding(
                    title=f"Multiple API Versions Active ({len(active_versions)} versions)",
                    severity=Severity.INFO,
                    url=base,
                    module="vulns/api_versioning",
                    description=(
                        f"{len(active_versions)} versions d'API actives détectées : "
                        f"{', '.join(v[0] for v in active_versions[:5])}. "
                        "Les anciennes versions peuvent ne pas avoir reçu les mêmes "
                        "patches de sécurité que la version courante."
                    ),
                    evidence=f"Active: {[v[0] for v in active_versions[:5]]}",
                    cwe="CWE-1104",
                    remediation=(
                        "Désactiver les versions obsolètes. Définir une politique de "
                        "dépréciation avec sunset headers. Appliquer les patches de "
                        "sécurité à toutes les versions actives."
                    ),
                )

    async def _probe_version(self, url: str, prefix: str):
        """Probe une URL de version et retourne (version_str, resp) si active."""
        resp = await self._req.get(url)
        if resp.error or resp.status in (404, 410):
            return None
        if resp.status in (200, 401, 403, 405, 301, 302):
            body = resp.body or ""
            # Vérifier que c'est une vraie API (JSON response)
            if (_API_ACTIVE_RE.search(body) or
                    resp.headers.get("Content-Type", "").startswith("application/json") or
                    resp.status in (401, 403)):
                return (prefix, resp)
        return None

    async def _test_sensitive_on_version(
        self, base_version: str, version_label: str, is_old: bool
    ) -> AsyncIterator[Finding]:
        """Teste les endpoints sensibles sur une version spécifique."""
        for path in _SENSITIVE_PATHS:
            url = base_version + path
            resp = await self._req.get(url)
            if resp.error:
                continue

            body = resp.body or ""

            # Endpoint accessible sans auth sur une vieille version
            if resp.status == 200 and is_old:
                if _API_ACTIVE_RE.search(body):
                    key = f"old_version_endpoint:{url}"
                    if key not in self._found:
                        self._found.add(key)
                        yield Finding(
                            title=f"Old API Version Exposes Endpoint — {version_label}{path}",
                            severity=Severity.HIGH,
                            url=url,
                            module="vulns/api_versioning",
                            description=(
                                f"L'ancienne version d'API `{version_label}` expose "
                                f"`{path}` sans authentification ou avec moins de contrôles "
                                "que la version courante. "
                                "Les correctifs de sécurité peuvent ne pas avoir été portés."
                            ),
                            evidence=(
                                f"HTTP 200 | Old version: {version_label} | "
                                f"Data in response: {body[:100]}"
                            ),
                            cwe="CWE-1104",
                            remediation=(
                                "Appliquer les mêmes contrôles d'accès sur toutes les versions. "
                                "Désactiver les versions non maintenues. "
                                "Utiliser un API gateway pour centraliser l'authentification."
                            ),
                        )
                        break  # Un finding par version

    # ── Header versioning ─────────────────────────────────────────────────────

    async def _test_version_headers(self, target: str) -> AsyncIterator[Finding]:
        """Teste les headers de versioning pour accéder à des versions anciennes."""
        # Baseline sans header de version
        baseline = await self._req.get(target)
        if baseline.error:
            return
        baseline_body = baseline.body or ""

        for hdrs in _VERSION_HEADERS[:3]:
            resp = await self._req.send(ProbeRequest(
                method="GET",
                url=target,
                headers=hdrs,
            ))
            if resp.error:
                continue

            # Si la réponse diffère significativement, un autre versioning est actif
            diff = self.stable_diff(resp.body or "", baseline_body)
            if diff > 0.30:
                hdr_name = list(hdrs.keys())[0]
                hdr_val = list(hdrs.values())[0]
                key = f"hdr_version:{target}:{hdr_name}"
                if key not in self._found:
                    self._found.add(key)
                    yield Finding(
                        title=f"API Version via Header Accepted — {hdr_name}: {hdr_val}",
                        severity=Severity.LOW,
                        url=target,
                        module="vulns/api_versioning",
                        description=(
                            f"L'API répond différemment quand le header `{hdr_name}: {hdr_val}` "
                            "est envoyé (diff={:.0%}). Une version alternative est accessible "
                            "via ce header de versioning."
                        ).format(diff),
                        evidence=f"Header: {hdr_name}={hdr_val} | body_diff={diff:.2f}",
                        cwe="CWE-1104",
                        remediation="Tester les endpoints critiques avec tous les headers de versioning.",
                    )
                    return
