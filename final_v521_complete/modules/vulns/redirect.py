"""
PhantomScan — Open Redirect
Détection de redirections ouvertes.
"""

from __future__ import annotations

import re
from typing import AsyncIterator
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity
from phantomscan.core.scanner_mixin import ScannerMixin

REDIRECT_PARAMS = {
    "url", "redirect", "redirect_url", "redirect_uri", "return",
    "return_url", "returnUrl", "next", "goto", "dest", "destination",
    "target", "link", "ref", "referrer", "continue", "forward",
    "location", "out", "view", "logoutUrl", "image_url", "go",
    "success", "data", "reference", "site", "uri", "to",
}

REDIRECT_PAYLOADS: list[tuple[str, str]] = [
    ("https://attacker.com",             "Direct external domain"),
    ("//attacker.com",                   "Protocol-relative"),
    ("/\\attacker.com",                  "Backslash bypass"),
    ("https:attacker.com",              "No-slash bypass"),
    ("\\/attacker.com",                  "Double backslash"),
    ("///attacker.com",                  "Triple slash"),
    ("////attacker.com",                 "Quad slash"),
    ("https://attacker%2Ecom",          "Encoded dot"),
    ("https://attacker.com%23.target",  "Fragment bypass"),
    ("https://attacker.com@target.com", "At-sign bypass"),
    ("https://target.com.attacker.com", "Subdomain bypass"),
    ("javascript:alert(1)",             "JS proto"),
    ("data:text/html,<script>alert(1)</script>", "Data URI"),
]

ATTACKER_DOMAIN = "attacker.com"


class RedirectScanner(ScannerMixin):
    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req = req
        self._heuristic = heuristic
        self._cfg = cfg

    async def run(self, target: str) -> AsyncIterator[Finding]:
        parsed = urlparse(target)
        params = parse_qs(parsed.query, keep_blank_values=True)

        # ── Test via query params ─────────────────────────────────────────────
        for param in list(params.keys()):
            if param.lower() not in REDIRECT_PARAMS:
                continue
            async for f in self._test_param(target, parsed, params, param):
                yield f

        # ── Test endpoints courants avec param redirect ────────────────────────
        async for f in self._test_common_endpoints(target):
            yield f

    async def _test_param(
        self,
        target: str,
        parsed,
        params: dict,
        param: str,
    ) -> AsyncIterator[Finding]:
        for payload, desc in REDIRECT_PAYLOADS:
            fuzzed = dict(params)
            fuzzed[param] = [payload]
            fuzz_url = urlunparse(parsed._replace(query=urlencode(fuzzed, doseq=True)))

            # On coupe les redirections pour intercepter le Location
            resp = await self._req.get(fuzz_url)
            if resp.error:
                continue

            # FIX: skip 404/erreurs HTTP explicites
            if resp.status in (404, 410, 400):
                continue
            # FIX fp: filtrage heuristique — élimine les soft-404 qui retournent 302
            if not self._heuristic.is_real_hit(resp, min_confidence=40):
                continue
            redirect_target = self._check_redirect(resp, payload)
            if redirect_target:
                sev = Severity.HIGH if "javascript:" not in payload and "data:" not in payload else Severity.CRITICAL
                # v5.20 — re-probe : confirmer que la redirection est reproductible
                _rp = await self.re_probe(fuzz_url, delay_s=0.3)
                if _rp is None:
                    continue
                _loc2 = (_rp.headers or {}).get("Location", "")
                if redirect_target not in _loc2 and redirect_target not in (_rp.body or ""):
                    continue  # non reproductible → FP
                yield Finding(
                    title=f"Open Redirect — param `{param}`",
                    severity=sev,
                    url=fuzz_url,
                    module="vulns/redirect",
                    description=f"Redirection ouverte confirmée via param `{param}`. Technique: {desc}",
                    evidence=f"Payload: {payload} → Location: {redirect_target}",
                    cwe="CWE-601",
                    remediation=(
                        "Utiliser une whitelist de domaines autorisés pour les redirections. "
                        "Éviter d'utiliser des paramètres contrôlés par l'utilisateur pour les redirections."
                    ),
                )
                return  # Un seul finding par param

    async def _test_common_endpoints(self, target: str) -> AsyncIterator[Finding]:
        base = target.rstrip("/")
        endpoints_templates = [
            "{base}/logout?next={payload}",
            "{base}/redirect?url={payload}",
            "{base}/login?return={payload}",
            "{base}/auth/callback?redirect_uri={payload}",
            "{base}/go?url={payload}",
            "{base}/out?url={payload}",
        ]

        for template in endpoints_templates:
            # Baseline: récupérer l'endpoint sans payload pour vérifier s'il redirige déjà
            # vers l'extérieur par défaut (ex: /logout redirige toujours → FP si on ne baseline pas)
            baseline_url = template.format(base=base, payload="__baseline_phantomscan__")
            baseline_resp = await self._req.get(baseline_url)
            baseline_redirects_externally = False
            if not baseline_resp.error and baseline_resp.status in (301, 302, 303, 307, 308):
                loc = baseline_resp.headers.get("Location", "") or baseline_resp.headers.get("location", "")
                # Si l'endpoint redirige déjà vers un domaine externe (non-relatif), skip
                if loc and (loc.startswith("http://") or loc.startswith("https://") or loc.startswith("//")):
                    try:
                        from urllib.parse import urlparse as _up
                        loc_host = _up(loc).netloc
                        base_host = _up(base).netloc
                        if loc_host and loc_host != base_host:
                            baseline_redirects_externally = True
                    except Exception:
                        pass

            if baseline_redirects_externally:
                continue  # Endpoint redirige déjà vers l'extérieur → skip pour éviter les FP

            for payload, desc in REDIRECT_PAYLOADS[:4]:
                url = template.format(base=base, payload=payload)
                resp = await self._req.get(url)
                if resp.error:
                    continue
                # FIX: skip 404/erreurs HTTP explicites
                if resp.status in (404, 410, 400):
                    continue
                # FIX fp: filtrage heuristique
                if not self._heuristic.is_real_hit(resp, min_confidence=40):
                    continue
                redirect_target = self._check_redirect(resp, payload)
                if redirect_target:
                    yield Finding(
                        title=f"Open Redirect — common endpoint",
                        severity=Severity.HIGH,
                        url=url,
                        module="vulns/redirect",
                        description=f"Redirection ouverte via endpoint commun. Technique: {desc}",
                        evidence=f"URL: {url} → Location: {redirect_target}",
                        cwe="CWE-601",
                        remediation="Valider les cibles de redirection côté serveur.",
                    )
                    break

    @staticmethod
    def _check_redirect(resp, payload: str) -> str | None:
        """Vérifie si la réponse redirige vers notre payload."""
        if resp.status not in (301, 302, 303, 307, 308):
            return None
        location = resp.headers.get("Location", "") or resp.headers.get("location", "")
        if not location:
            return None

        # Vérifie si ATTACKER_DOMAIN est dans la location ET que l'URL pointe vraiment
        # vers ce domaine (pas juste un path ou query param qui contient le mot)
        if ATTACKER_DOMAIN in location.lower():
            # S'assurer que c'est bien le host, pas juste un paramètre dans l'URL
            try:
                loc_parsed = urlparse(location)
                if loc_parsed.netloc and ATTACKER_DOMAIN in loc_parsed.netloc.lower():
                    return location
                # Protocol-relative //attacker.com
                if location.startswith("//") and ATTACKER_DOMAIN in location[2:].split("/")[0].lower():
                    return location
            except Exception:
                pass
            return None  # ATTACKER_DOMAIN présent mais pas dans le host → FP

        if location.startswith("javascript:") or location.startswith("data:"):
            return location
        # Redirections relatives vers payloads tricky (backslash)
        if location.startswith("/\\") or location.startswith("\\/"):
            return location
        return None
