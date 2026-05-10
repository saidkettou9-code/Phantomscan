"""
PhantomScan — Host Header Injection Scanner  v1.0
==================================================
Spécialisé sur l'injection du header Host, distinct du scanner générique
headers.py qui couvre X-Forwarded-For/Host, etc.

Vecteurs couverts :
  1. Password-Reset Poisoning
       - Injecte un domaine attaquant via Host / X-Forwarded-Host / X-Original-Host
       - Détecte la réflexion dans la réponse (link de reset, email preview, debug)
       - HIGH si le domaine attaquant apparaît dans un contexte reset-password
  2. Host Header → Cache Poisoning
       - Dual Host header (Host: target\nHost: evil)
       - Host avec port arbitraire réfléchi dans les liens
       - X-Forwarded-Host réfléchi sans validation
  3. Routing bypass / Internal host access
       - Host: localhost, Host: 127.0.0.1 → bypass d'un reverse proxy
       - Host: internal-admin.local → accès à vhosts internes
  4. Open-redirect via Host
       - Location header qui inclut le Host injecté sans validation
  5. Absolute-URI smuggling
       - Requête avec URI absolue GET http://evil.com/ HTTP/1.1 + Host: target
         (serveurs qui utilisent la Request-URI au lieu du Host pour les redirections)

Findings émis :
  HIGH    — réflexion Host evil dans reset-password ou Location redirect
  HIGH    — dual Host accepté, evil host réfléchi dans response body/headers
  MEDIUM  — X-Forwarded-Host réfléchi (non cache-poisoning, juste réflexion)
  MEDIUM  — Host: localhost accepté, réponse différente (possible internal bypass)
  LOW     — port arbitraire réfléchi dans les liens
  INFO    — endpoint password-reset détecté (pour faciliter test manuel)
"""

from __future__ import annotations

import re
from typing import AsyncIterator
from urllib.parse import urlparse, urljoin

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester, ProbeRequest
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity
from phantomscan.core.scanner_mixin import ScannerMixin

CANARY_DOMAIN = "evil-phantomscan.invalid"
CANARY_DOMAIN_2 = "phantomscan-probe.evil"

# Chemins typiques de reset de mot de passe
RESET_PATHS: list[str] = [
    "/forgot-password",
    "/forgot_password",
    "/reset-password",
    "/reset_password",
    "/password/reset",
    "/password/forgot",
    "/auth/forgot",
    "/account/forgot-password",
    "/users/password/new",
    "/api/v1/auth/forgot-password",
    "/api/v1/password/reset",
    "/api/auth/forgot",
    "/identity/api/auth/forget-password",
]

# Regex pour détecter la réflexion du canary dans la réponse
_CANARY_RE = re.compile(re.escape(CANARY_DOMAIN), re.I)
_CANARY2_RE = re.compile(re.escape(CANARY_DOMAIN_2), re.I)

# Contextes indiquant un lien de reset dans le body HTML/JSON
_RESET_CONTEXT_RE = re.compile(
    r"(reset|forgot|password|verify|confirm|token|link|url|href)[^\n]{0,80}",
    re.I,
)


class HostHeaderInjectionScanner(ScannerMixin):

    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req = req
        self._heuristic = heuristic
        self._cfg = cfg

    async def run(self, target: str) -> AsyncIterator[Finding]:
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        real_host = parsed.netloc

        async for f in self._password_reset_poisoning(base, real_host):
            yield f
        async for f in self._host_reflection(target, real_host):
            yield f
        async for f in self._localhost_bypass(target, real_host):
            yield f
        async for f in self._port_reflection(target, real_host):
            yield f
        async for f in self._absolute_uri_smuggling(target, real_host):
            yield f

    # ── 1. Password Reset Poisoning ───────────────────────────────────────────

    async def _password_reset_poisoning(
        self, base: str, real_host: str
    ) -> AsyncIterator[Finding]:
        """
        Injecte CANARY_DOMAIN dans Host / X-Forwarded-Host / X-Original-Host
        sur les endpoints password-reset et cherche la réflexion.
        """
        poison_headers_variants = [
            {"Host": CANARY_DOMAIN},
            {"X-Forwarded-Host": CANARY_DOMAIN},
            {"X-Original-Host": CANARY_DOMAIN},
            # Double Host header — certains frameworks lisent le second
            {"Host": real_host, "X-Forwarded-Host": CANARY_DOMAIN},
        ]

        for path in RESET_PATHS:
            url = base + path

            # Probe GET pour confirmer que l'endpoint existe
            resp_check = await self._req.send(ProbeRequest(method="GET", url=url))
            if resp_check is None:
                continue
            if resp_check.status_code not in (200, 302, 400, 405, 422):
                continue

            # Tentatives d'injection sur POST (reset) et GET (form)
            for method in ("POST", "GET"):
                for extra_hdrs in poison_headers_variants:
                    resp = await self._req.send(ProbeRequest(
                        method=method,
                        url=url,
                        headers={**extra_hdrs, "Content-Type": "application/json"},
                        body=b'{"email":"pentest@phantomscan.invalid"}',
                    ))
                    if resp is None:
                        continue

                    body = resp.body or b""
                    body_str = body.decode("utf-8", errors="replace")

                    if _CANARY_RE.search(body_str) or _CANARY_RE.search(
                        str(resp.headers)
                    ):
                        # Cherche si c'est dans un contexte de lien de reset
                        ctx_match = _RESET_CONTEXT_RE.search(body_str)
                        context_snippet = ctx_match.group(0)[:120] if ctx_match else body_str[:120]

                        injected_header = list(extra_hdrs.keys())[-1]
                        # v5.20 — re-probe avec le même header pour confirmer
                        _reprobe = await self.re_probe(url,
                            headers={**extra_hdrs, "Host": real_host},
                            delay_s=0.4)
                        if _reprobe is None:
                            continue
                        if evil_domain not in (_reprobe.body or ""):
                            continue  # non reproductible → FP
                        yield Finding(
                            title="Host Header Injection → Password Reset Poisoning",
                            url=url,
                            severity=Severity.HIGH,
                            description=(
                                f"L'endpoint {url} reflète le header `{injected_header}: {CANARY_DOMAIN}` "
                                f"dans la réponse ({method}). "
                                "Si l'application génère un lien de réinitialisation à partir du Host, "
                                "un attaquant peut remplacer le domaine dans le lien envoyé à la victime "
                                "et voler le token de reset.\n\n"
                                f"Extrait réponse : {context_snippet!r}"
                            ),
                            param=injected_header,
                            evidence=context_snippet,
                            remediation=(
                                "Ne jamais construire des URLs à partir du header Host. "
                                "Utiliser une base URL configurée statiquement côté serveur. "
                                "Valider le header Host contre une whitelist de domaines autorisés."
                            ),
                        )
                        break  # Un finding par endpoint suffit
                else:
                    continue
                break

    # ── 2. Host Header Reflection (hors reset) ────────────────────────────────

    async def _host_reflection(
        self, target: str, real_host: str
    ) -> AsyncIterator[Finding]:
        """
        Teste la réflexion du Host injecté dans le body ou les headers de réponse.
        Technique générale (pas spécifique au reset).
        """
        variants = [
            # Header + label
            ({"Host": CANARY_DOMAIN}, "Host override"),
            ({"X-Forwarded-Host": CANARY_DOMAIN}, "X-Forwarded-Host"),
            ({"X-Host": CANARY_DOMAIN}, "X-Host"),
            ({"X-Original-Host": CANARY_DOMAIN}, "X-Original-Host"),
            ({"X-Rewrite-URL": f"https://{CANARY_DOMAIN}/"}, "X-Rewrite-URL"),
        ]

        for extra_hdrs, label in variants:
            resp = await self._req.send(ProbeRequest(
                method="GET",
                url=target,
                headers=extra_hdrs,
            ))
            if resp is None:
                continue

            body_str = (resp.body or b"").decode("utf-8", errors="replace")
            headers_str = str(resp.headers)

            reflected_in_body = _CANARY_RE.search(body_str)
            reflected_in_headers = _CANARY_RE.search(headers_str)

            if reflected_in_body or reflected_in_headers:
                location = resp.headers.get("location", "")
                if _CANARY_RE.search(location):
                    sev = Severity.HIGH
                    vuln_type = "Open Redirect via Host Header"
                else:
                    sev = Severity.MEDIUM
                    vuln_type = "Host Header Reflection"

                snippet = body_str[:200] if reflected_in_body else headers_str[:200]
                yield Finding(
                    title=f"{vuln_type} ({label})",
                    url=target,
                    severity=sev,
                    description=(
                        f"Le serveur reflète `{label}: {CANARY_DOMAIN}` dans la réponse. "
                        "Cela peut mener à du cache poisoning, du password reset poisoning "
                        "ou un open redirect selon le contexte.\n\n"
                        f"Réfléchi dans : {'body' if reflected_in_body else 'headers'}\n"
                        f"Extrait : {snippet[:150]!r}"
                    ),
                    param=label,
                    evidence=snippet[:150],
                    remediation=(
                        "Valider et filtrer les headers Host, X-Forwarded-Host avant usage. "
                        "Ne pas construire d'URLs depuis ces headers sans whitelist stricte."
                    ),
                )
                break  # Un finding par target pour cette catégorie

    # ── 3. Localhost bypass ───────────────────────────────────────────────────

    async def _localhost_bypass(
        self, target: str, real_host: str
    ) -> AsyncIterator[Finding]:
        """
        Teste si Host: localhost ou Host: 127.0.0.1 modifie la réponse
        de façon significative (bypass reverse-proxy, accès vhost interne).
        """
        resp_normal = await self._req.send(ProbeRequest(method="GET", url=target))
        if resp_normal is None:
            return

        for fake_host in ("localhost", "127.0.0.1", "internal", "admin.internal"):
            resp = await self._req.send(ProbeRequest(
                method="GET",
                url=target,
                headers={"Host": fake_host},
            ))
            if resp is None:
                continue

            # Réponse significativement différente → possible internal vhost bypass
            body_normal = resp_normal.body or b""
            body_test = resp.body or b""

            status_changed = resp.status_code != resp_normal.status_code
            size_ratio = abs(len(body_test) - len(body_normal)) / max(len(body_normal), 1)

            if status_changed or size_ratio > 0.3:
                yield Finding(
                    title=f"Host Header → Internal Vhost Bypass (Host: {fake_host})",
                    url=target,
                    severity=Severity.MEDIUM,
                    description=(
                        f"Remplacer le header Host par `{fake_host}` produit une réponse différente : "
                        f"status {resp_normal.status_code} → {resp.status_code}, "
                        f"taille body {len(body_normal)} → {len(body_test)} octets. "
                        "Le serveur peut être vulnérable à un accès de vhost interne via "
                        "manipulation du header Host."
                    ),
                    param="Host",
                    evidence=f"Status: {resp_normal.status_code}→{resp.status_code}, size diff: {size_ratio:.0%}",
                    remediation=(
                        "Configurer le reverse proxy pour rejeter les requêtes dont le Host "
                        "ne correspond pas aux domaines autorisés. "
                        "Ne pas router vers des vhosts internes basé sur le Host non validé."
                    ),
                )
                break

    # ── 4. Port Reflection ────────────────────────────────────────────────────

    async def _port_reflection(
        self, target: str, real_host: str
    ) -> AsyncIterator[Finding]:
        """
        Injecte un port arbitraire dans le header Host et cherche sa réflexion
        dans les liens (href, action, src) de la réponse.
        """
        hostname = real_host.split(":")[0]
        injected_host = f"{hostname}:9999"

        resp = await self._req.send(ProbeRequest(
            method="GET",
            url=target,
            headers={"Host": injected_host},
        ))
        if resp is None:
            return

        body_str = (resp.body or b"").decode("utf-8", errors="replace")
        port_re = re.compile(r":9999", re.I)

        if port_re.search(body_str):
            # Cherche dans quel contexte
            ctx = re.search(r"(href|src|action|url)[^\n]{0,100}:9999[^\n]{0,100}", body_str, re.I)
            snippet = ctx.group(0)[:150] if ctx else ":9999 trouvé dans body"

            yield Finding(
                title="Host Header Port Reflection → Potential Cache Poisoning",
                url=target,
                severity=Severity.LOW,
                description=(
                    f"Le port `9999` injecté via `Host: {injected_host}` apparaît dans la réponse. "
                    "Si la réponse est mise en cache, des liens pointant vers un port attaquant "
                    "pourraient être servis à d'autres utilisateurs.\n\n"
                    f"Contexte : {snippet!r}"
                ),
                param="Host (port)",
                evidence=snippet,
                remediation=(
                    "Utiliser une URL de base configurée statiquement pour construire les liens. "
                    "Ajouter le header Vary: Host ou exclure les variations de Host du cache."
                ),
            )

    # ── 5. Absolute-URI Smuggling ─────────────────────────────────────────────

    async def _absolute_uri_smuggling(
        self, target: str, real_host: str
    ) -> AsyncIterator[Finding]:
        """
        Envoie une requête avec URI absolue pointant vers un domaine attaquant
        pour voir si le serveur suit l'URI absolue plutôt que le Host header
        dans ses redirections.
        """
        parsed = urlparse(target)
        # URI absolue vers le canary, Host reste le vrai serveur
        evil_url = f"{parsed.scheme}://{CANARY_DOMAIN}{parsed.path or '/'}"

        resp = await self._req.send(ProbeRequest(
            method="GET",
            url=evil_url,
            headers={"Host": real_host},
        ))
        if resp is None:
            return

        location = resp.headers.get("location", "")
        body_str = (resp.body or b"").decode("utf-8", errors="replace")

        if _CANARY_RE.search(location) or _CANARY_RE.search(body_str):
            yield Finding(
                title="Absolute-URI Smuggling → Host Header Bypass",
                url=target,
                severity=Severity.MEDIUM,
                description=(
                    f"Le serveur a répondu à une requête avec URI absolue `{evil_url}` "
                    f"en reflétant `{CANARY_DOMAIN}` dans la réponse "
                    f"({'Location: ' + location if location else 'body'}). "
                    "Cela indique que le serveur utilise l'URI absolue de la Request-Line "
                    "plutôt que le header Host pour construire ses URLs, permettant "
                    "un bypass de vhost ou un open redirect."
                ),
                param="Request-URI (absolute)",
                evidence=location or body_str[:120],
                remediation=(
                    "Configurer le serveur/proxy pour ignorer l'URI absolue dans la Request-Line "
                    "et toujours se baser sur le header Host validé."
                ),
            )
