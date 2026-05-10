"""
PhantomScan — OAuth2 Misconfiguration Scanner (v5.5)
=====================================================
Détection des misconfigurations OAuth2 / OpenID Connect :

  1. Open Redirect sur redirect_uri
       - redirect_uri non validé → redirection vers domaine attaquant
       - Bypass via encodage, fragments, sous-domaines ouverts

  2. Token Leakage
       - access_token/id_token dans l'URL (Referer leakage)
       - Tokens dans les logs d'erreur ou corps HTML
       - Authorization code visible dans l'URL après échange

  3. PKCE Bypass / absent
       - Flux authorization_code sans PKCE (code_challenge manquant)
       - Downgrade PKCE vers plain
       - code_verifier faible (< 43 chars)

  4. State parameter absent / fixable
       - CSRF sur le flow OAuth si state absent ou prévisible

  5. Scope over-permission
       - Scope non restreint (wildcard, offline_access excessif)

  6. Implicit flow encore actif (deprecated)

  7. Discovery endpoint exposé (.well-known/openid-configuration)

Findings émis :
  CRITICAL  — token leakage direct, open redirect confirmé
  HIGH      — PKCE absent, state absent
  MEDIUM    — implicit flow actif, scope large, PKCE plain
  LOW       — discovery exposé, implicit flow possible
  INFO      — endpoints OAuth détectés
"""

from __future__ import annotations

import asyncio
import re
import urllib.parse
from typing import AsyncIterator

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester, ProbeRequest
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity
from phantomscan.core.scanner_mixin import ScannerMixin


# ── Endpoints OAuth courants ──────────────────────────────────────────────────

OAUTH_ENDPOINT_PATHS: list[str] = [
    "/oauth/authorize",
    "/oauth2/authorize",
    "/oauth/token",
    "/oauth2/token",
    "/connect/authorize",
    "/connect/token",
    "/auth/oauth2/authorize",
    "/api/oauth/authorize",
    "/sso/oauth2/authorize",
    "/openid-connect/auth",
    "/protocol/openid-connect/auth",     # Keycloak
    "/as/authorization.oauth2",          # PingFederate
    "/oxauth/restv1/authorize",          # Gluu
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
]

# ── Regex pour détecter les tokens dans les réponses ─────────────────────────

TOKEN_PATTERNS: list[tuple[str, str]] = [
    ("access_token in URL",    r"[?&]access_token=([A-Za-z0-9\-_\.]+)"),
    ("id_token in URL",        r"[?&]id_token=([A-Za-z0-9\-_\.]+)"),
    ("Bearer in body",         r"[\"']?access_token[\"']?\s*[=:]\s*[\"']?([A-Za-z0-9\-_\.]{20,})"),
    ("JWT in body",            r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
    ("Authorization code URL", r"[?&]code=([A-Za-z0-9\-_\.]+)"),
]

# ── Payloads open redirect pour redirect_uri ─────────────────────────────────

REDIRECT_URI_BYPASSES: list[tuple[str, str]] = [
    ("direct",           "https://evil.com"),
    ("encoded_slash",    "https://evil.com%2F@legitimate.com"),
    ("at_sign",          "https://legitimate.com@evil.com"),
    ("fragment",         "https://legitimate.com#https://evil.com"),
    ("double_encoded",   "https:%2f%2fevil.com"),
    ("subdomain",        "https://legitimate.com.evil.com"),
    ("path_bypass",      "https://legitimate.com/../../evil.com"),
    ("null_byte",        "https://legitimate.com%00evil.com"),
    ("backslash",        "https://legitimate.com\\evil.com"),
    ("param_pollution",  "https://legitimate.com&redirect=https://evil.com"),
]


class OAuth2MisconfigScanner(ScannerMixin):

    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req = req
        self._heuristic = heuristic
        self._cfg = cfg

    async def run(self, target: str) -> AsyncIterator[Finding]:
        """Point d'entrée principal."""
        base = target.rstrip("/")

        # 1. Découverte des endpoints OAuth
        oauth_endpoints = await self._discover_endpoints(base)
        if not oauth_endpoints:
            return

        yield Finding(
            title="Endpoints OAuth2/OIDC découverts",
            severity=Severity.INFO,
            url=base,
            module="OAuth2MisconfigScanner",
            description=f"{len(oauth_endpoints)} endpoint(s) OAuth2/OIDC trouvés.",
            evidence="\n".join(oauth_endpoints[:10]),
            remediation="Vérifier que seuls les endpoints nécessaires sont exposés.",
            cwe="CWE-200",
        )

        # 2. Discovery endpoint → extraire les paramètres réels
        discovery_data = await self._fetch_discovery(base)
        if discovery_data:
            async for f in self._check_discovery(base, discovery_data):
                yield f

        # 3. Identifier l'authorize endpoint
        authorize_url = self._pick_authorize(oauth_endpoints, discovery_data)
        if not authorize_url:
            return

        # 4. Checks sur l'authorize endpoint
        async for f in self._check_state_param(authorize_url):
            yield f

        async for f in self._check_pkce(authorize_url):
            yield f

        async for f in self._check_open_redirect(authorize_url, base):
            yield f

        async for f in self._check_implicit_flow(authorize_url):
            yield f

        # 5. Token leakage dans les réponses
        async for f in self._check_token_leakage(base):
            yield f

    # ── Découverte ───────────────────────────────────────────────────────────

    async def _discover_endpoints(self, base: str) -> list[str]:
        found: list[str] = []
        tasks = [self._probe_path(base, path) for path in OAUTH_ENDPOINT_PATHS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for path, result in zip(OAUTH_ENDPOINT_PATHS, results):
            if isinstance(result, int) and result in (200, 302, 400, 401):
                found.append(f"{base}{path}")
        return found

    async def _probe_path(self, base: str, path: str) -> int:
        try:
            resp = await self._req.get(ProbeRequest(url=f"{base}{path}"))
            return resp.status_code
        except Exception:
            return 0

    async def _fetch_discovery(self, base: str) -> dict | None:
        for path in ("/.well-known/openid-configuration",
                     "/.well-known/oauth-authorization-server"):
            try:
                resp = await self._req.get(ProbeRequest(url=f"{base}{path}"))
                if resp.status_code == 200 and resp.text:
                    import json
                    try:
                        return json.loads(resp.text)
                    except Exception:
                        pass
            except Exception:
                continue
        return None

    def _pick_authorize(
        self, endpoints: list[str], discovery: dict | None
    ) -> str | None:
        if discovery and "authorization_endpoint" in discovery:
            return discovery["authorization_endpoint"]
        for ep in endpoints:
            if "authorize" in ep or "auth" in ep:
                return ep
        return None

    # ── Checks ───────────────────────────────────────────────────────────────

    async def _check_discovery(
        self, base: str, data: dict
    ) -> AsyncIterator[Finding]:
        """Analyse le contenu du discovery endpoint."""
        issues: list[str] = []

        # Implicit flow déclaré comme supporté
        response_types = data.get("response_types_supported", [])
        if any("token" in rt for rt in response_types):
            yield Finding(
                title="OAuth2 — Implicit flow actif (déprécié)",
                severity=Severity.MEDIUM,
                url=f"{base}/.well-known/openid-configuration",
                module="OAuth2MisconfigScanner",
                description=(
                    "Le serveur déclare supporter l'implicit flow (response_type=token), "
                    "déprécié par RFC 9700. Les access_tokens apparaissent dans le fragment "
                    "d'URL, exposés au Referer et à l'historique du navigateur."
                ),
                evidence=f"response_types_supported: {response_types}",
                remediation=(
                    "Désactiver l'implicit flow. Utiliser authorization_code + PKCE "
                    "pour les clients publics (RFC 7636)."
                ),
                cwe="CWE-319",
                cvss=6.1,
            )

        # PKCE non listé
        pkce_methods = data.get("code_challenge_methods_supported", [])
        if not pkce_methods:
            issues.append("PKCE (code_challenge_methods_supported) absent du discovery")

        # Scopes larges
        scopes = data.get("scopes_supported", [])
        risky_scopes = [s for s in scopes if s in ("*", "all", "admin", "write")]
        if risky_scopes:
            yield Finding(
                title="OAuth2 — Scopes à haut privilège exposés",
                severity=Severity.MEDIUM,
                url=f"{base}/.well-known/openid-configuration",
                module="OAuth2MisconfigScanner",
                description=f"Scopes à risque déclarés : {risky_scopes}",
                evidence=f"scopes_supported: {scopes}",
                remediation=(
                    "Appliquer le principe du moindre privilège sur les scopes. "
                    "Ne pas exposer de scopes admin/write dans le discovery public."
                ),
                cwe="CWE-272",
                cvss=5.0,
            )

    async def _check_state_param(self, authorize_url: str) -> AsyncIterator[Finding]:
        """Teste si le state est requis (protection CSRF)."""
        params = {
            "response_type": "code",
            "client_id":     "test",
            "redirect_uri":  "https://example.com/callback",
            # pas de state → devrait être rejeté
        }
        url = f"{authorize_url}?{urllib.parse.urlencode(params)}"
        try:
            resp = await self._req.get(ProbeRequest(url=url))
            # Si le serveur redirige sans erreur et sans state → CSRF possible
            if resp.status_code in (302, 303, 200):
                loc = resp.headers.get("location", "") if resp.headers else ""
                if "error" not in loc and "error" not in (resp.text or "")[:500]:
                    yield Finding(
                        title="OAuth2 — Paramètre state absent (CSRF possible)",
                        severity=Severity.HIGH,
                        url=authorize_url,
                        module="OAuth2MisconfigScanner",
                        description=(
                            "Le serveur accepte une requête d'autorisation sans "
                            "paramètre state, exposant le flow à une attaque CSRF/fixation "
                            "selon RFC 6749 §10.12."
                        ),
                        evidence=f"GET {url} → {resp.status_code}",
                        remediation=(
                            "Exiger un paramètre state cryptographiquement aléatoire. "
                            "Valider sa correspondance lors du callback."
                        ),
                        cwe="CWE-352",
                        cvss=7.4,
                    )
        except Exception:
            pass

    async def _check_pkce(self, authorize_url: str) -> AsyncIterator[Finding]:
        """Teste si PKCE est requis."""
        # Requête sans code_challenge
        params = {
            "response_type": "code",
            "client_id":     "test",
            "redirect_uri":  "https://example.com/callback",
            "state":         "random_state_xyz",
        }
        url_no_pkce = f"{authorize_url}?{urllib.parse.urlencode(params)}"
        try:
            resp = await self._req.get(ProbeRequest(url=url_no_pkce))
            body = (resp.text or "")[:1000]
            loc  = (resp.headers.get("location", "") if resp.headers else "")

            # Si pas d'erreur relative à PKCE → PKCE non requis
            pkce_error = bool(
                re.search(r"code_challenge|pkce|invalid_request", body + loc, re.I)
            )
            if not pkce_error and resp.status_code in (302, 303, 200):
                yield Finding(
                    title="OAuth2 — PKCE non requis (authorization code interception)",
                    severity=Severity.HIGH,
                    url=authorize_url,
                    module="OAuth2MisconfigScanner",
                    description=(
                        "Le serveur n'exige pas PKCE (code_challenge) pour le flux "
                        "authorization_code. Un attaquant interceptant le code peut "
                        "l'échanger contre un token (RFC 7636)."
                    ),
                    evidence=f"Requête sans code_challenge acceptée → HTTP {resp.status_code}",
                    remediation=(
                        "Rendre PKCE obligatoire pour tous les clients publics. "
                        "Utiliser code_challenge_method=S256 (ne pas accepter plain)."
                    ),
                    cwe="CWE-303",
                    cvss=7.5,
                )
        except Exception:
            pass

        # Requête avec PKCE plain (downgrade)
        params_plain = {**params, "code_challenge": "test", "code_challenge_method": "plain"}
        url_plain = f"{authorize_url}?{urllib.parse.urlencode(params_plain)}"
        try:
            resp2 = await self._req.get(ProbeRequest(url=url_plain))
            body2 = (resp2.text or "")[:1000]
            loc2  = (resp2.headers.get("location", "") if resp2.headers else "")
            if resp2.status_code in (302, 303, 200) and "error" not in (body2 + loc2).lower():
                yield Finding(
                    title="OAuth2 — PKCE plain accepté (downgrade S256→plain)",
                    severity=Severity.MEDIUM,
                    url=authorize_url,
                    module="OAuth2MisconfigScanner",
                    description=(
                        "Le serveur accepte code_challenge_method=plain. "
                        "La méthode plain n'offre aucune protection cryptographique réelle "
                        "contre l'interception du code_verifier."
                    ),
                    evidence=f"Requête PKCE plain acceptée → HTTP {resp2.status_code}",
                    remediation="N'accepter que code_challenge_method=S256.",
                    cwe="CWE-327",
                    cvss=5.3,
                )
        except Exception:
            pass

    async def _check_open_redirect(
        self, authorize_url: str, base: str
    ) -> AsyncIterator[Finding]:
        """Teste les bypasses open redirect sur redirect_uri."""
        parsed = urllib.parse.urlparse(base)
        legitimate = f"{parsed.scheme}://{parsed.netloc}/callback"

        for bypass_name, evil_uri in REDIRECT_URI_BYPASSES:
            # Remplace la partie "legitimate.com" par le vrai domaine
            actual_evil = evil_uri.replace("legitimate.com", parsed.netloc)

            params = {
                "response_type": "code",
                "client_id":     "test",
                "redirect_uri":  actual_evil,
                "state":         "test_state",
            }
            url = f"{authorize_url}?{urllib.parse.urlencode(params)}"
            try:
                resp = await self._req.get(ProbeRequest(url=url))
                loc  = resp.headers.get("location", "") if resp.headers else ""

                # Vérifier si la redirection part vers evil.com
                if "evil.com" in loc or (
                    resp.status_code in (302, 303)
                    and "error" not in loc.lower()
                    and legitimate not in loc
                ):
                    yield Finding(
                        title=f"OAuth2 — Open Redirect redirect_uri ({bypass_name})",
                        severity=Severity.CRITICAL,
                        url=authorize_url,
                        module="OAuth2MisconfigScanner",
                        description=(
                            f"La validation du redirect_uri est bypassable via '{bypass_name}'. "
                            "Un attaquant peut voler le code d'autorisation en redirigeant "
                            "la victime vers un domaine contrôlé."
                        ),
                        evidence=(
                            f"redirect_uri={actual_evil} → "
                            f"HTTP {resp.status_code} Location: {loc[:200]}"
                        ),
                        remediation=(
                            "Implémenter une whitelist exacte des redirect_uri autorisés. "
                            "Rejeter tout URI contenant des caractères d'encodage ou "
                            "des fragments (#). Pas de correspondance par préfixe."
                        ),
                        cwe="CWE-601",
                        cvss=9.1,
                    )
                    break  # Un seul finding par type pour éviter le flood
            except Exception:
                pass
            await asyncio.sleep(0.2)

    async def _check_implicit_flow(self, authorize_url: str) -> AsyncIterator[Finding]:
        """Teste si response_type=token (implicit) est accepté."""
        params = {
            "response_type": "token",
            "client_id":     "test",
            "redirect_uri":  "https://example.com/callback",
            "state":         "test_state",
        }
        url = f"{authorize_url}?{urllib.parse.urlencode(params)}"
        try:
            resp = await self._req.get(ProbeRequest(url=url))
            body = (resp.text or "")[:1000]
            loc  = (resp.headers.get("location", "") if resp.headers else "")

            if resp.status_code in (302, 303, 200):
                if not re.search(r"unsupported_response_type|error", body + loc, re.I):
                    yield Finding(
                        title="OAuth2 — Implicit flow accepté (response_type=token)",
                        severity=Severity.MEDIUM,
                        url=authorize_url,
                        module="OAuth2MisconfigScanner",
                        description=(
                            "Le serveur accepte response_type=token (implicit flow). "
                            "Ce flow expose les access_tokens dans le fragment d'URL, "
                            "les logs serveur, et le header Referer."
                        ),
                        evidence=f"response_type=token → HTTP {resp.status_code}",
                        remediation=(
                            "Désactiver l'implicit flow. Migrer vers "
                            "authorization_code + PKCE (RFC 9700)."
                        ),
                        cwe="CWE-319",
                        cvss=6.1,
                    )
        except Exception:
            pass

    async def _check_token_leakage(self, base: str) -> AsyncIterator[Finding]:
        """Cherche des tokens dans les pages publiques du site."""
        pages_to_check = ["/", "/callback", "/auth/callback", "/oauth/callback"]
        for path in pages_to_check:
            url = f"{base}{path}"
            try:
                resp = await self._req.get(ProbeRequest(url=url))
                if resp.status_code != 200 or not resp.text:
                    continue
                body = resp.text[:8000]
                full = url + body

                for pattern_name, pattern in TOKEN_PATTERNS:
                    m = re.search(pattern, full, re.I)
                    if m:
                        token_preview = m.group(0)[:80]
                        yield Finding(
                            title=f"OAuth2 — Token leakage : {pattern_name}",
                            severity=Severity.CRITICAL,
                            url=url,
                            module="OAuth2MisconfigScanner",
                            description=(
                                f"Token OAuth2/OIDC détecté dans la réponse HTTP "
                                f"({pattern_name}). Exposition dans l'URL ou le body."
                            ),
                            evidence=f"Pattern '{pattern_name}' matché : {token_preview}",
                            remediation=(
                                "Ne jamais transmettre les tokens dans les paramètres GET. "
                                "Utiliser uniquement POST/body ou les fragments (#) non "
                                "transmis au serveur. Implémenter PKCE."
                            ),
                            cwe="CWE-200",
                            cvss=9.3,
                        )
                        break
            except Exception:
                continue
            await asyncio.sleep(0.1)
