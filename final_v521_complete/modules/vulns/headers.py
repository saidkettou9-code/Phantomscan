"""
PhantomScan — Headers Injection
Host injection, X-Forwarded-Host, X-Forwarded-For, etc.
"""

from __future__ import annotations

import re
from typing import AsyncIterator
from urllib.parse import urlparse

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester, ProbeRequest
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity
from phantomscan.core.scanner_mixin import ScannerMixin

CANARY = "phantomscan-injection-test.invalid"
CANARY_IP = "169.254.169.254"


class HeadersScanner(ScannerMixin):
    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req = req
        self._heuristic = heuristic
        self._cfg = cfg

    async def run(self, target: str) -> AsyncIterator[Finding]:
        async for f in self._host_header_injection(target):
            yield f
        async for f in self._forwarded_header_abuse(target):
            yield f
        async for f in self._xfwd_for_spoofing(target):
            yield f
        async for f in self._xfwd_host_cache_poisoning(target):
            yield f

    # ── X-Forwarded-Host → Cache Poisoning (cross-module) ────────────────────

    async def _xfwd_host_cache_poisoning(self, target: str) -> AsyncIterator[Finding]:
        """
        Teste l'injection X-Forwarded-Host spécifiquement pour le cache poisoning.
        Contrairement à cache_poison.py (qui teste la réflexion générique),
        ce test vérifie :
          1. que la valeur injectée apparaît dans des champs utilisés pour construire
             des URLs dans la réponse (href, src, action, Location, canonical),
          2. que la réponse est potentiellement cacheable (Cache-Control, Vary absent
             sur X-Forwarded-Host, Age/X-Cache présents),
        ce qui constitue la condition nécessaire à un cache poisoning exploitable.
        """
        poison_host = CANARY
        cache_indicators = re.compile(
            r"age|x-cache|cf-cache-status|x-varnish|x-drupal-cache|surrogate-key",
            re.I,
        )
        url_reflect_re = re.compile(
            re.escape(poison_host),
            re.I,
        )

        resp = await self._req.send(ProbeRequest(
            method="GET",
            url=target,
            headers={"X-Forwarded-Host": poison_host},
        ))
        if resp.error:
            return

        body = resp.body or ""
        resp_headers = resp.headers or {}

        host_reflected_in_body = bool(url_reflect_re.search(body))
        vary_header = resp_headers.get("Vary", "")
        # Si Vary ne couvre pas X-Forwarded-Host, la réponse peut être cachée avec le host injecté
        xfh_not_in_vary = "x-forwarded-host" not in vary_header.lower()
        cache_present = any(cache_indicators.search(k) for k in resp_headers)
        cache_control = resp_headers.get("Cache-Control", "")
        is_cacheable = (
            "no-store" not in cache_control.lower()
            and "private" not in cache_control.lower()
        )

        if host_reflected_in_body and xfh_not_in_vary and (cache_present or is_cacheable):
            yield Finding(
                title="X-Forwarded-Host injection — Cache Poisoning potentiel",
                severity=Severity.HIGH,
                url=target,
                module="vulns/headers",
                description=(
                    f"La valeur de X-Forwarded-Host (`{poison_host}`) est réfléchie dans le body "
                    "(liens, URLs) ET la réponse semble cacheable (Vary n'inclut pas "
                    "X-Forwarded-Host, pas de Cache-Control: no-store/private). "
                    "Un attaquant peut empoisonner le cache avec un host arbitraire et rediriger "
                    "les victimes vers une infrastructure malveillante."
                ),
                evidence=(
                    f"X-Forwarded-Host: {poison_host} → réfléchi dans body | "
                    f"Vary: {vary_header or '(absent)'} | "
                    f"Cache-Control: {cache_control or '(absent)'} | "
                    f"Cache headers: {[k for k in resp_headers if cache_indicators.search(k)]}"
                ),
                cwe="CWE-444",
                remediation=(
                    "Ajouter X-Forwarded-Host à la clé de cache ou le supprimer du pipeline. "
                    "Ne pas construire d'URLs depuis ce header sans validation. "
                    "Définir Cache-Control: no-store sur les réponses contenant des URLs dynamiques, "
                    "ou inclure X-Forwarded-Host dans Vary si le comportement est intentionnel."
                ),
            )
        elif host_reflected_in_body and not (cache_present or is_cacheable):
            # Réfléchi mais pas cacheable → signaler uniquement comme injection (moins grave)
            yield Finding(
                title="X-Forwarded-Host injection — URL reflection (non cacheable)",
                severity=Severity.MEDIUM,
                url=target,
                module="vulns/headers",
                description=(
                    f"La valeur de X-Forwarded-Host (`{poison_host}`) est réfléchie dans le body "
                    "mais la réponse ne semble pas cacheable. "
                    "Exploitable pour du phishing ou SSO hijacking si un redirect est déclenché."
                ),
                evidence=f"X-Forwarded-Host: {poison_host} → réfléchi | Cache-Control: {cache_control or '(absent)'}",
                cwe="CWE-644",
                remediation=(
                    "Valider et ignorer X-Forwarded-Host si l'application ne se trouve pas derrière "
                    "un proxy de confiance qui positionne ce header."
                ),
            )

    # ── Host Header Injection ─────────────────────────────────────────────────

    async def _host_header_injection(self, target: str) -> AsyncIterator[Finding]:
        payloads = [
            CANARY,
            f"attacker.com",
            f"localhost",
            f"169.254.169.254",
            f"{urlparse(target).netloc}:{CANARY}",
            f"{CANARY}:{urlparse(target).netloc}",
        ]
        original = await self._req.get(target)

        for host_val in payloads:
            resp = await self._req.send(ProbeRequest(
                method="GET",
                url=target,
                headers={
                    "Host": host_val,
                    "X-Forwarded-Host": host_val,
                },
            ))
            if resp.error:
                continue

            # FIX fp: filtrage heuristique — évite les soft-404 qui réfléchissent n'importe quoi
            if not self._heuristic.is_real_hit(resp, min_confidence=35):
                continue

            # Check si le canary est réfléchi dans la réponse (cache poisoning / SSRF)
            if CANARY in resp.body:
                yield Finding(
                    title="Host Header Injection — value reflected",
                    severity=Severity.HIGH,
                    url=target,
                    module="vulns/headers",
                    description=(
                        f"La valeur du header Host ({host_val}) est réfléchie dans la réponse. "
                        "Potentiel password reset poisoning ou cache poisoning."
                    ),
                    evidence=f"Host: {host_val} → trouvé dans body",
                    cwe="CWE-644",
                    remediation="Valider le header Host côté serveur et utiliser une whitelist.",
                )

            # Check redirection vers host injecté
            for redir in resp.redirects:
                if host_val in redir and CANARY not in urlparse(target).netloc:
                    yield Finding(
                        title="Host Header Injection — redirect hijacking",
                        severity=Severity.HIGH,
                        url=target,
                        module="vulns/headers",
                        description=f"Redirection vers host injecté: {redir}",
                        evidence=f"Host: {host_val} → Location: {redir}",
                        cwe="CWE-601",
                        remediation="Construire les redirections depuis la configuration serveur, pas depuis le header Host.",
                    )

    # ── X-Forwarded-Host abuse ─────────────────────────────────────────────────

    async def _forwarded_header_abuse(self, target: str) -> AsyncIterator[Finding]:
        # Note: X-Forwarded-Host is already fully covered by _xfwd_host_cache_poisoning
        # (which checks reflection + cacheability). Only test the other headers here.
        headers_to_test = {
            "X-HTTP-Host-Override": CANARY,
            "Forwarded": f"host={CANARY}",
        }
        for header, value in headers_to_test.items():
            resp = await self._req.send(ProbeRequest(
                method="GET",
                url=target,
                headers={header: value},
            ))
            if resp.error:
                continue
            # FIX fp: filtrage heuristique
            if not self._heuristic.is_real_hit(resp, min_confidence=35):
                continue
            if CANARY in resp.body:
                yield Finding(
                    title=f"Header injection reflected: {header}",
                    severity=Severity.MEDIUM,
                    url=target,
                    module="vulns/headers",
                    description=f"Valeur du header {header} réfléchie dans la réponse.",
                    evidence=f"{header}: {value}",
                    cwe="CWE-644",
                )

    # ── X-Forwarded-For IP spoofing ───────────────────────────────────────────

    async def _xfwd_for_spoofing(self, target: str) -> AsyncIterator[Finding]:
        """Vérifie si X-Forwarded-For est utilisé pour bypasser des restrictions IP."""
        original = await self._req.get(target)
        if original.error:
            return

        spoof_headers: list[dict[str, str]] = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Forwarded-For": "::1"},
            {"X-Forwarded-For": CANARY_IP},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Real-IP": CANARY_IP},
        ]

        for hdr in spoof_headers:
            resp = await self._req.send(ProbeRequest(
                method="GET",
                url=target,
                headers=hdr,
            ))
            if resp.error:
                continue

            # Si le status change (ex: 403 → 200), c'est un bypass
            if original.status in (401, 403) and resp.status == 200:
                header_name = list(hdr.keys())[0]
                yield Finding(
                    title=f"IP restriction bypass via {header_name}",
                    severity=Severity.HIGH,
                    url=target,
                    module="vulns/headers",
                    description=f"Status change {original.status} → {resp.status} en spoofant l'IP via {header_name}",
                    evidence=str(hdr),
                    cwe="CWE-290",
                    remediation="Ne pas faire confiance aux headers X-Forwarded-For pour les contrôles d'accès.",
                )

            # Vérifier si l'IP cloud metadata est accessible
            if CANARY_IP in hdr.get("X-Forwarded-For", "") or CANARY_IP in hdr.get("X-Real-IP", ""):
                orig_len = original.content_length or len(original.body or "")
                resp_len = resp.content_length or len(resp.body or "")
                # Seuil 50% (vs 20%) + cherche des patterns cloud metadata dans le body
                # pour éviter les FP sur CDN/proxy qui ajoutent du contenu de debug
                _METADATA_RE = re.compile(
                    r'ami-id|instance-id|placement|security-group|iam/security-credentials',
                    re.I
                )
                if resp.status == 200 and orig_len > 0 and (
                    resp_len > orig_len * 1.5 or _METADATA_RE.search(resp.body or "")
                ):
                    yield Finding(
                        title="Potential SSRF via metadata IP in X-Forwarded-For",
                        severity=Severity.HIGH,
                        url=target,
                        module="vulns/headers",
                        description=f"L'IP cloud metadata {CANARY_IP} dans X-Forwarded-For produit une réponse différente.",
                        evidence=str(hdr),
                        cwe="CWE-918",
                    )
