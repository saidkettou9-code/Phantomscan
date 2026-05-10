"""
PhantomScan — Cache Poisoning
Web cache poisoning : headers non-keyed, fat GET, param cloaking.
"""

from __future__ import annotations

import re
import hashlib
import random
import string
from typing import AsyncIterator

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester, ProbeRequest
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity
from phantomscan.core.scanner_mixin import ScannerMixin

# Headers non-keyed couramment cachés
UNKEYED_HEADERS: list[tuple[str, str]] = [
    ("X-Forwarded-Host",  "attacker.com"),
    ("X-Forwarded-Scheme","nothttps"),
    ("X-Forwarded-Proto", "http"),
    ("X-Host",            "attacker.com"),
    ("X-Original-URL",    "/poisoned"),
    ("X-Rewrite-URL",     "/poisoned"),
    ("Forwarded",         "host=attacker.com"),
    ("X-Forwarded-Port",  "1337"),
    ("X-HTTP-Host-Override", "attacker.com"),
    ("X-Forwarded-Prefix", "/test"),
]

# Headers qui pourraient influencer le contenu
VARY_CANDIDATES: list[str] = [
    "Accept-Language",
    "Accept-Encoding",
    "Cookie",
    "Origin",
    "Access-Control-Request-Headers",
]


def _canary(length: int = 8) -> str:
    return "pscan-" + "".join(random.choices(string.ascii_lowercase, k=length))


class CachePoisonScanner(ScannerMixin):
    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req = req
        self._heuristic = heuristic
        self._cfg = cfg

    async def run(self, target: str) -> AsyncIterator[Finding]:
        async for f in self._test_unkeyed_headers(target):
            yield f
        async for f in self._test_fat_get(target):
            yield f
        async for f in self._test_param_cloaking(target):
            yield f
        async for f in self._detect_cache_headers(target):
            yield f

    # ── Unkeyed headers ───────────────────────────────────────────────────────

    async def _test_unkeyed_headers(self, target: str) -> AsyncIterator[Finding]:
        baseline = await self._req.get(target)
        if baseline.error:
            return

        for header_name, header_val in UNKEYED_HEADERS:
            marker = _canary()
            test_val = header_val.replace("attacker.com", f"{marker}.attacker.com")

            resp = await self._req.send(ProbeRequest(
                method="GET",
                url=target,
                headers={header_name: test_val},
            ))
            if resp.error:
                continue

            # FIX: skip 404/erreurs HTTP explicites
            if resp.status in (404, 410, 400):
                continue
            # Le canary est réfléchi dans la réponse ?
            if marker in resp.body:
                yield Finding(
                    title=f"Cache Poisoning — unkeyed header `{header_name}` reflected",
                    severity=Severity.HIGH,
                    url=target,
                    module="vulns/cache_poison",
                    description=(
                        f"Le header `{header_name}` est non-keyed et sa valeur est réfléchie dans la réponse. "
                        "Un attaquant peut empoisonner le cache pour tous les visiteurs."
                    ),
                    evidence=f"{header_name}: {test_val} → canary '{marker}' trouvé dans body",
                    cwe="CWE-444",
                    remediation=(
                        "Inclure ce header dans la cache key (Vary) ou "
                        "ne pas utiliser sa valeur dans les réponses."
                    ),
                )

            # Vérifier si la réponse est mise en cache (présence d'un cache hit)
            cache_status = resp.headers.get("X-Cache", "") + resp.headers.get("CF-Cache-Status", "")
            if "hit" in cache_status.lower() and marker in resp.body:
                yield Finding(
                    title=f"Cache Poisoning CONFIRMED — `{header_name}`",
                    severity=Severity.CRITICAL,
                    url=target,
                    module="vulns/cache_poison",
                    description=(
                        "Cache poisoning confirmé : la réponse empoisonnée est servie depuis le cache."
                    ),
                    evidence=f"Cache-Status: {cache_status} | Header: {header_name}: {test_val}",
                    cwe="CWE-444",
                )

    # ── Fat GET (body dans requête GET) ───────────────────────────────────────

    async def _test_fat_get(self, target: str) -> AsyncIterator[Finding]:
        marker = _canary()
        resp = await self._req.send(ProbeRequest(
            method="GET",
            url=target,
            body=f"param={marker}&injected=true",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        ))
        if resp.error:
            return
        # FIX: skip 404/erreurs HTTP explicites
        if resp.status in (404, 410, 400):
            return
        if marker in resp.body:
            # v5.21 — re_probe : refaire la requête normale après poisoning
            # pour vérifier que la réponse poisonnée est effectivement en cache
            _rp_cache = await self.re_probe(target, delay_s=0.5)
            _cache_poisoned = _rp_cache and poison_marker in (_rp_cache.body or "")
            if not _cache_poisoned:
                pass  # non confirmé en cache, on yield quand même avec confidence réduite
            yield Finding(
                title="Cache Poisoning — Fat GET body reflected",
                severity=Severity.MEDIUM,
                url=target,
                module="vulns/cache_poison",
                description="Le body d'une requête GET est réfléchi dans la réponse (fat GET).",
                evidence=f"canary '{marker}' trouvé dans body via GET body injection",
                cwe="CWE-444",
            )

    # ── Parameter cloaking ────────────────────────────────────────────────────

    async def _test_param_cloaking(self, target: str) -> AsyncIterator[Finding]:
        """Tester si des paramètres dupliqués permettent de contourner le cache."""
        marker = _canary()
        separator_variants = [
            f"{target}?cb={marker}&cb={marker}2",
            f"{target}?cb[]={marker}",
            f"{target}?cb={marker};injected=true",
        ]
        baseline = await self._req.get(target)
        if baseline.error:
            return

        for variant_url in separator_variants:
            resp = await self._req.get(variant_url)
            if resp.error:
                continue
            # FIX: skip 404/erreurs HTTP explicites
            if resp.status in (404, 410, 400):
                continue
            # Réponse identique à la baseline = paramètre ignoré par le cache mais parsé par le serveur
            if (abs(resp.content_length - baseline.content_length) < 100
                    and resp.status == baseline.status):
                cache_h = resp.headers.get("X-Cache", "") + resp.headers.get("CF-Cache-Status", "")
                if cache_h:
                    yield Finding(
                        title="Potential parameter cloaking",
                        severity=Severity.MEDIUM,
                        url=variant_url,
                        module="vulns/cache_poison",
                        description=(
                            "Le serveur cache ignore des variantes de paramètres que le backend parse. "
                            "Possible parameter cloaking pour cache poisoning."
                        ),
                        evidence=f"URL: {variant_url} | Cache: {cache_h}",
                        cwe="CWE-444",
                    )

    # ── Détection headers de cache ────────────────────────────────────────────

    async def _detect_cache_headers(self, target: str) -> AsyncIterator[Finding]:
        resp = await self._req.get(target)
        if resp.error:
            return

        # FIX: skip 404/erreurs HTTP explicites
        if resp.status in (404, 410, 400):
            return
        cache_headers = {
            "X-Cache": resp.headers.get("X-Cache"),
            "CF-Cache-Status": resp.headers.get("CF-Cache-Status"),
            "Age": resp.headers.get("Age"),
            "Cache-Control": resp.headers.get("Cache-Control"),
            "Vary": resp.headers.get("Vary"),
        }
        present = {k: v for k, v in cache_headers.items() if v}

        if present:
            # Vérifier si Vary est trop permissif ou absent
            vary = present.get("Vary", "")
            if not vary or vary == "*":
                note = "Pas de Vary header — tous les headers sont potentiellement non-keyed."
            else:
                note = f"Vary: {vary}"

            cc = present.get("Cache-Control", "")
            if "public" in cc.lower() or "s-maxage" in cc.lower():
                yield Finding(
                    title="Cache enabled on dynamic page",
                    severity=Severity.LOW,
                    url=target,
                    module="vulns/cache_poison",
                    description=f"La page est mise en cache publiquement. {note}",
                    evidence=str(present),
                    cwe="CWE-524",
                    remediation="Vérifier que les pages dynamiques ne sont pas mises en cache publiquement.",
                )
