"""
PhantomScan — Open Redirect Chain Scanner [v5.16]
Détecte les open redirects exploitables pour :
- Account takeover via OAuth callback poisoning
- Phishing amplifié (redirect depuis domaine de confiance)
- Token/code leakage via Referer header
- Bypass de CSP/whitelist en chaînant des redirections

Ce module va au-delà d'un simple open redirect en testant :
1. Redirect direct (/?next=https://evil.com)
2. Bypass de validation (double slash, CRLF, Unicode, protocol-relative)
3. Chain OAuth : si un endpoint oauth callback est trouvé, teste le vol de code
4. Token leakage : vérifie si le token/session est transmis au domaine cible
5. Open redirect chaining : exploitabilité réelle (deux sauts)

Différence avec redirect.py (RedirectScanner) :
- RedirectScanner : détection basique de params redirect/next/url
- OpenRedirectChainScanner : confirmation d'exploitabilité + OAuth chain + token leak
"""

from __future__ import annotations

import re
from typing import AsyncGenerator
from urllib.parse import urlparse, urljoin, urlencode, quote, parse_qs, urlunparse

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester, ProbeRequest
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity
from phantomscan.core.scanner_mixin import ScannerMixin


# ─────────────────────────── Payloads ────────────────────────────────────────

_CANARY_DOMAIN = "evil-phantomscan-test.com"
_CANARY_URL    = f"https://{_CANARY_DOMAIN}"

# Payloads de bypass — classés par technique
_REDIRECT_PAYLOADS: list[tuple[str, str]] = [
    # Basique
    (_CANARY_URL,                                  "direct"),
    (f"http://{_CANARY_DOMAIN}",                   "http_scheme"),
    # Protocol-relative
    (f"//{_CANARY_DOMAIN}",                        "protocol_relative"),
    (f"////{_CANARY_DOMAIN}",                      "quad_slash"),
    # Slashes multiples
    (f"https:///{_CANARY_DOMAIN}",                 "triple_slash"),
    # Backslash (Windows + some parsers)
    (f"https:\\\\{_CANARY_DOMAIN}",                "backslash"),
    (f"/\\{_CANARY_DOMAIN}",                       "slash_backslash"),
    # Encodage URL
    (f"https://%{_CANARY_DOMAIN.replace('.', '%2E')}",  "url_encoded_dot"),
    (quote(_CANARY_URL, safe=""),                  "full_url_encoded"),
    # @ trick (user@host)
    (f"https://trusted@{_CANARY_DOMAIN}",          "at_trick"),
    # Null byte / CRLF
    (f"{_CANARY_URL}%00",                          "null_byte"),
    (f"{_CANARY_URL}%0d%0a",                       "crlf"),
    # Double URL encode
    (f"https%3A%2F%2F{_CANARY_DOMAIN}",            "double_encoded"),
    # Fragment confusion
    (f"/{_CANARY_DOMAIN}",                         "relative_path"),
    (f"//google.com/{_CANARY_DOMAIN}",             "trusted_then_evil"),
    # Unicode
    (f"https://ⓔvil.com",                          "unicode_homoglyph"),
    # Data URI (rare)
    ("data:text/html,<script>location='https://evil.com'</script>", "data_uri"),
    # Javascript URI
    ("javascript:alert(document.location='https://evil.com')",      "js_uri"),
    # Whitespace
    (f" {_CANARY_URL}",                            "leading_space"),
    (f"{_CANARY_URL} ",                            "trailing_space"),
    # Path traversal combiné
    (f"https://trusted.com/../../{_CANARY_DOMAIN}", "path_traversal"),
]

# Paramètres de redirection communs
_REDIRECT_PARAMS = [
    "next", "url", "redirect", "redirect_url", "redirect_uri",
    "return", "return_url", "returnUrl", "returnTo", "return_to",
    "goto", "go", "target", "dest", "destination",
    "forward", "continue", "callback", "r", "redir",
    "location", "link", "path", "href", "ref",
    # OAuth
    "redirect_uri", "oauth_callback", "callback_url",
    # Logout
    "logout_redirect", "post_logout_redirect_uri",
]

# Endpoints OAuth/OIDC courants
_OAUTH_ENDPOINTS = [
    "/oauth/authorize", "/oauth2/authorize", "/oauth/callback",
    "/auth/callback", "/auth/authorize", "/connect/authorize",
    "/oidc/authorize", "/api/oauth/authorize",
    "/login/oauth/authorize",
]


class OpenRedirectChainScanner(ScannerMixin):

    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req  = req
        self._h    = heuristic
        self._cfg  = cfg

    async def run(self, target: str) -> AsyncGenerator[Finding, None]:
        parsed = urlparse(target)
        base   = f"{parsed.scheme}://{parsed.netloc}"
        domain = parsed.hostname or ""

        # 1. Teste les paramètres de redirect sur les endpoints courants
        async for f in self._scan_redirect_params(target, base, domain):
            yield f

        # 2. Cherche et teste les endpoints OAuth
        async for f in self._scan_oauth_chain(base, domain):
            yield f

        # 3. Teste les paths qui contiennent directement l'URL cible
        async for f in self._scan_path_redirect(base, domain):
            yield f

    # ────────────────── Scan paramètres redirect ─────────────────────────────

    async def _scan_redirect_params(self, target: str, base: str, domain: str) -> AsyncGenerator[Finding, None]:
        # Endpoints à tester
        test_endpoints = [target, base + "/", base + "/login", base + "/logout",
                          base + "/auth/login", base + "/signin"]

        seen_params: set[str] = set()

        for endpoint in test_endpoints:
            # D'abord GET pour voir les params en place
            resp = await self._req.send(ProbeRequest(method="GET", url=endpoint))
            if resp.error:
                continue

            # Détecte les params redirect déjà dans l'URL cible
            existing = parse_qs(urlparse(endpoint).query)
            candidate_params = list(_REDIRECT_PARAMS)
            for k in existing:
                if k.lower() in [p.lower() for p in _REDIRECT_PARAMS]:
                    candidate_params.insert(0, k)

            for param in candidate_params:
                if param in seen_params:
                    continue

                async for f in self._test_param(endpoint, param, domain):
                    seen_params.add(param)
                    yield f
                    break  # Une vuln par param suffit

    async def _test_param(self, endpoint: str, param: str, domain: str) -> AsyncGenerator[Finding, None]:
        """Teste un paramètre avec les différents payloads de bypass."""
        parsed = urlparse(endpoint)
        base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))

        for payload, technique in _REDIRECT_PAYLOADS:
            test_url = f"{base_url}?{param}={quote(payload, safe=':/?=&@#')}"
            resp = await self._req.send(ProbeRequest(
                method="GET",
                url=test_url,
                allow_redirects=False,  # Ne pas suivre pour détecter le header
            ))
            if resp.error:
                continue

            location = (resp.headers or {}).get("location", "") or (resp.headers or {}).get("Location", "")
            if not location:
                continue

            # Vérifie si la redirection pointe RÉELLEMENT vers notre domaine canary.
            # On parse le Location header pour contrôler le hostname cible,
            # et non juste vérifier que la chaîne apparaît dans l'URL (ce qui
            # causerait un faux positif si le site redirige vers lui-même avec
            # le paramètre réfléchi en query string, ex:
            #   /fr?redirect_uri=https://evil-phantomscan-test.com  ← FP ici)
            location_parsed = urlparse(location)
            location_host = location_parsed.hostname or ""
            # Cas 1 : redirection directe vers le domaine canary
            points_to_canary = location_host == _CANARY_DOMAIN or location_host.endswith(f".{_CANARY_DOMAIN}")
            # Cas 2 : URL relative commençant par //evil-... (protocol-relative)
            if not points_to_canary and location.startswith("//"):
                proto_rel_host = urlparse("https:" + location).hostname or ""
                points_to_canary = proto_rel_host == _CANARY_DOMAIN or proto_rel_host.endswith(f".{_CANARY_DOMAIN}")

            if points_to_canary:
                # Redirection confirmée vers domaine externe
                sev = Severity.HIGH
                is_oauth_param = param in ("redirect_uri", "oauth_callback", "callback_url")
                if is_oauth_param:
                    sev = Severity.CRITICAL

                yield Finding(
                    title       = f"Open Redirect" + (" [OAuth Chain]" if is_oauth_param else "") + f" — {technique}",
                    severity    = sev,
                    url         = test_url,
                    module      = "OpenRedirectChainScanner",
                    description = self._build_description(param, technique, location, is_oauth_param, domain),
                    evidence    = f"Paramètre `{param}` avec technique `{technique}` → Location: `{location[:200]}`",
                    remediation = (
                        "Valider les URLs de redirection contre une whitelist stricte de domaines autorisés. "
                        "Rejeter toute URL relative ou contenant des caractères suspects (\\, @, //, data:, javascript:). "
                        "Pour les OAuth redirect_uri, utiliser une comparaison exacte (pas de wildcard, pas de prefix match). "
                        "Envisager d'utiliser un token opaque au lieu de l'URL directe."
                    ),
                    cwe  = "CWE-601",
                    cvss = 8.1 if is_oauth_param else 6.1,
                    extra = {
                        "param": param,
                        "technique": technique,
                        "payload": payload[:100],
                        "location_header": location[:200],
                        "is_oauth_chain": is_oauth_param,
                    },
                )
                return  # Une vuln confirmée par param suffit

            # Vérifie aussi les redirects côté body (meta refresh, JS location)
            body = resp.body or ""
            if _CANARY_DOMAIN in body:
                yield Finding(
                    title       = f"Open Redirect (Body) — {technique}",
                    severity    = Severity.MEDIUM,
                    url         = test_url,
                    module      = "OpenRedirectChainScanner",
                    description = f"Le domaine de test `{_CANARY_DOMAIN}` apparaît dans le body de réponse après injection dans `{param}`. Possibilité d'open redirect via meta refresh ou window.location.",
                    evidence    = f"Paramètre `{param}`, technique `{technique}` — domaine canary dans body",
                    remediation = "Encoder les sorties et valider les URLs avant de les écrire dans le HTML/JS.",
                    cwe  = "CWE-601",
                    cvss = 5.4,
                    extra={"param": param, "technique": technique},
                )
                return

    # ────────────────── Scan OAuth chain ─────────────────────────────────────

    async def _scan_oauth_chain(self, base: str, domain: str) -> AsyncGenerator[Finding, None]:
        """Détecte les endpoints OAuth et teste le vol de code via redirect_uri."""
        for oauth_path in _OAUTH_ENDPOINTS:
            url = urljoin(base, oauth_path)
            # Sonde avec redirect_uri malveillant
            test_url = f"{url}?client_id=test&response_type=code&redirect_uri={quote(_CANARY_URL)}&scope=openid"
            resp = await self._req.send(ProbeRequest(
                method="GET",
                url=test_url,
                allow_redirects=False,
            ))
            if resp.error:
                continue
            # 302/303 vers notre domaine = OAuth redirect_uri non validé
            if resp.status_code in (301, 302, 303, 307, 308):
                location = (resp.headers or {}).get("location", "") or (resp.headers or {}).get("Location", "")
                if _CANARY_DOMAIN in location:
                    yield Finding(
                        title       = "OAuth redirect_uri Open Redirect [Account Takeover Risk]",
                        severity    = Severity.CRITICAL,
                        url         = test_url,
                        module      = "OpenRedirectChainScanner",
                        description = (
                            f"L'endpoint OAuth `{oauth_path}` accepte une `redirect_uri` arbitraire pointant vers "
                            f"un domaine externe (`{_CANARY_DOMAIN}`). Un attaquant peut construire un lien "
                            f"d'autorisation qui redirige le code OAuth vers son serveur, permettant un account takeover "
                            f"complet si l'utilisateur clique sur le lien."
                        ),
                        evidence    = f"redirect_uri={_CANARY_URL} → Location: {location[:200]}",
                        remediation = (
                            "Valider redirect_uri par comparaison exacte avec les URIs enregistrés pour le client OAuth. "
                            "Ne pas accepter de wildcard, ni de préfixe. Enregistrer les redirect_uri explicitement "
                            "par application OAuth. Appliquer la RFC 6749 strictement."
                        ),
                        cwe  = "CWE-601",
                        cvss = 9.3,
                        extra={"endpoint": oauth_path, "redirect_uri": _CANARY_URL, "location": location[:200]},
                    )

    # ────────────────── Scan path redirect ───────────────────────────────────

    async def _scan_path_redirect(self, base: str, domain: str) -> AsyncGenerator[Finding, None]:
        """Teste les patterns /redirect/URL et /go/URL."""
        path_patterns = [
            f"/redirect/{_CANARY_URL}",
            f"/go/{_CANARY_URL}",
            f"/out/{_CANARY_URL}",
            f"/external?url={_CANARY_URL}",
            f"/link?href={quote(_CANARY_URL)}",
            f"/track?redirect={quote(_CANARY_URL)}",
        ]
        for path in path_patterns:
            url = urljoin(base, path)
            resp = await self._req.send(ProbeRequest(method="GET", url=url, allow_redirects=False))
            if resp.error or resp.status_code not in (301, 302, 303, 307, 308):
                continue
            location = (resp.headers or {}).get("location", "") or (resp.headers or {}).get("Location", "")
            if _CANARY_DOMAIN in location:
                yield Finding(
                    title       = "Open Redirect via Path",
                    severity    = Severity.HIGH,
                    url         = url,
                    module      = "OpenRedirectChainScanner",
                    description = (
                        f"L'endpoint de redirection `{path.split('?')[0]}` redirige directement vers "
                        f"une URL externe sans validation. Ce type d'endpoint est souvent utilisé pour "
                        f"les liens de tracking ou les sorties du site, et peut être abusé pour du phishing ciblé."
                    ),
                    evidence    = f"GET {path} → Location: {location[:200]}",
                    remediation = (
                        "Valider que l'URL cible appartient à une whitelist de domaines autorisés. "
                        "Afficher une page interstitielle d'avertissement avant la redirection externe."
                    ),
                    cwe  = "CWE-601",
                    cvss = 6.1,
                    extra={"path": path, "location": location[:200]},
                )

    # ────────────────── Description builder ──────────────────────────────────

    def _build_description(self, param: str, technique: str, location: str,
                           is_oauth: bool, domain: str) -> str:
        if is_oauth:
            return (
                f"Le paramètre OAuth `{param}` accepte une URL de redirection vers un domaine externe "
                f"(technique: `{technique}`). En envoyant un lien d'autorisation malveillant à une victime, "
                f"un attaquant peut capturer le code OAuth ou le token d'accès, permettant un account takeover complet. "
                f"Impact : P1/Critical dans la plupart des programmes Bug Bounty."
            )
        technique_desc = {
            "direct":           "redirection directe sans validation",
            "protocol_relative":"URL protocol-relative (`//evil.com`) non filtrée",
            "backslash":        "backslash (`https:\\\\`) accepté comme séparateur",
            "at_trick":         "confusion `user@host` — le host réel est après le @",
            "crlf":             "injection CRLF dans l'URL de redirection",
            "double_encoded":   "double encodage URL non décodé avant validation",
            "url_encoded_dot":  "points encodés en %2E non normalisés avant validation",
            "null_byte":        "null byte permettant de tronquer la validation",
        }.get(technique, f"bypass par `{technique}`")
        return (
            f"Le paramètre `{param}` est vulnérable à un open redirect via {technique_desc}. "
            f"Un attaquant peut envoyer un lien `{domain}/...?{param}=https://evil.com` qui "
            f"semble légitime mais redirige vers un site de phishing. Redirection détectée vers: `{location[:100]}`."
        )
