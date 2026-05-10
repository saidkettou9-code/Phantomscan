"""
PhantomScan — CRLF Injection
Injection CRLF dans headers, body splitting, log injection.
"""

from __future__ import annotations

import re
from typing import AsyncIterator
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester, ProbeRequest
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity
from phantomscan.core.scanner_mixin import ScannerMixin

CRLF_PAYLOADS: list[str] = [
    "%0d%0aX-Injected: crlf-test",
    "%0aX-Injected: crlf-test",
    "%0dX-Injected: crlf-test",
    "\r\nX-Injected: crlf-test",
    "\nX-Injected: crlf-test",
    "%E5%98%8A%E5%98%8DX-Injected: crlf-test",   # Unicode CRLF
    "%E5%98%8AX-Injected: crlf-test",
    "%0d%0a%0d%0a<script>alert(1)</script>",       # CRLF + XSS
    "%0d%0aSet-Cookie: crlf=injected",
    "%0d%0aContent-Type: text/html%0d%0a%0d%0a<svg/onload=alert(1)>",
    "a%0d%0aX-Injected: crlf-test",
    "%23%0d%0aX-Injected: crlf-test",
    "/%0d%0aX-Injected: crlf-test",
]

INJECT_MARKER = "X-Injected"
COOKIE_MARKER = "crlf=injected"


class CRLFScanner(ScannerMixin):
    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req = req
        self._heuristic = heuristic
        self._cfg = cfg

    async def run(self, target: str) -> AsyncIterator[Finding]:
        parsed = urlparse(target)
        params = parse_qs(parsed.query, keep_blank_values=True)

        # ── CRLF via query params ─────────────────────────────────────────────
        for param, values in params.items():
            async for f in self._test_param(target, parsed, params, param):
                yield f

        # ── CRLF via path ─────────────────────────────────────────────────────
        async for f in self._test_path(target, parsed):
            yield f

        # ── CRLF via custom headers ───────────────────────────────────────────
        async for f in self._test_headers(target):
            yield f

    async def _test_param(
        self,
        target: str,
        parsed,
        params: dict,
        param: str,
    ) -> AsyncIterator[Finding]:
        for payload in CRLF_PAYLOADS:
            fuzzed = dict(params)
            fuzzed[param] = [payload]
            fuzz_url = urlunparse(parsed._replace(query=urlencode(fuzzed, doseq=True)))

            resp = await self._req.get(fuzz_url)
            if resp.error:
                continue

            # FIX: skip 404/erreurs HTTP explicites
            if resp.status in (404, 410, 400):
                continue
            # FIX fp: filtrage heuristique pour éliminer les soft-404 et pages génériques
            if not self._heuristic.is_real_hit(resp, min_confidence=55):
                continue
            sev, finding_type = self._check_response(resp)
            if sev:
                # v5.20 — re-probe avant yield (CRLF FP fréquent sur caches)
                _rp = await self.re_probe(resp.url or target, delay_s=0.3)
                if _rp is None:
                    continue
                sev2, _ = self._check_response(_rp)
                if not sev2:
                    continue  # non reproductible
                yield Finding(
                    title=f"CRLF Injection — {finding_type} (param `{param}`)",
                    severity=sev,
                    url=fuzz_url,
                    module="vulns/crlf",
                    description=f"CRLF injecté via param `{param}`. Type: {finding_type}",
                    evidence=f"Payload: {payload[:60]} | Réponse: {resp.status}",
                    cwe="CWE-113",
                    remediation="Encoder les CR/LF dans toutes les sorties vers les headers HTTP.",
                )
                break

    async def _test_path(self, target: str, parsed) -> AsyncIterator[Finding]:
        base = f"{parsed.scheme}://{parsed.netloc}"
        for payload in CRLF_PAYLOADS[:6]:
            test_url = f"{base}/{payload}"
            resp = await self._req.get(test_url)
            if resp.error:
                continue
            # FIX: skip 404/erreurs HTTP explicites
            if resp.status in (404, 410, 400):
                continue
            # FIX fp: filtrage heuristique
            if not self._heuristic.is_real_hit(resp, min_confidence=55):
                continue
            sev, finding_type = self._check_response(resp)
            if sev:
                # v5.20 — re-probe avant yield (CRLF FP fréquent sur caches)
                _rp = await self.re_probe(resp.url or target, delay_s=0.3)
                if _rp is None:
                    continue
                sev2, _ = self._check_response(_rp)
                if not sev2:
                    continue  # non reproductible
                yield Finding(
                    title=f"CRLF Injection — {finding_type} (path)",
                    severity=sev,
                    url=test_url,
                    module="vulns/crlf",
                    description=f"CRLF injecté via le chemin URL. Type: {finding_type}",
                    evidence=f"Payload: {payload[:60]}",
                    cwe="CWE-113",
                    remediation="Valider et encoder les inputs dans les redirections et logs.",
                )
                break

    async def _test_headers(self, target: str) -> AsyncIterator[Finding]:
        """CRLF dans des headers qui sont souvent loggés ou réfléchis."""
        injectable_headers = {
            "Referer": f"https://example.com/\r\nX-Injected: crlf-test",
            "User-Agent": f"Mozilla/5.0\r\nX-Injected: crlf-test",
            "X-Forwarded-For": f"1.2.3.4\r\nX-Injected: crlf-test",
        }
        for header_name, header_val in injectable_headers.items():
            resp = await self._req.send(ProbeRequest(
                method="GET",
                url=target,
                headers={header_name: header_val},
            ))
            if resp.error:
                continue
            # FIX: skip 404/erreurs HTTP explicites
            if resp.status in (404, 410, 400):
                continue
            # FIX fp: filtrage heuristique
            if not self._heuristic.is_real_hit(resp, min_confidence=55):
                continue
            sev, finding_type = self._check_response(resp)
            if sev:
                # v5.20 — re-probe avant yield (CRLF FP fréquent sur caches)
                _rp = await self.re_probe(resp.url or target, delay_s=0.3)
                if _rp is None:
                    continue
                sev2, _ = self._check_response(_rp)
                if not sev2:
                    continue  # non reproductible
                yield Finding(
                    title=f"CRLF Injection — {finding_type} (header `{header_name}`)",
                    severity=sev,
                    url=target,
                    module="vulns/crlf",
                    description=f"CRLF injecté via header `{header_name}`",
                    evidence=f"Header: {header_name}: {header_val[:60]}",
                    cwe="CWE-113",
                )

    @staticmethod
    def _check_response(resp) -> tuple[Severity | None, str]:
        # Header injecté présent dans la réponse
        if INJECT_MARKER.lower() in (k.lower() for k in resp.headers):
            return Severity.HIGH, "Header injection"
        # Cookie injecté
        set_cookie = resp.headers.get("Set-Cookie", "")
        if COOKIE_MARKER in set_cookie:
            return Severity.HIGH, "Cookie injection"
        # XSS via CRLF dans body
        if "<script>alert(1)</script>" in resp.body or "<svg/onload=alert(1)>" in resp.body:
            return Severity.HIGH, "CRLF → XSS"
        return None, ""
