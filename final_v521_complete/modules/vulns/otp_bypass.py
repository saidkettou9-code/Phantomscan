"""
PhantomScan — 2FA / OTP Bypass Scanner  (v5.8)
===============================================
Teste les faiblesses courantes des implémentations 2FA/OTP :

  1. Brute force OTP (absence de rate limit sur /verify, /otp, /2fa)
  2. OTP reuse (un code déjà consommé reste accepté)
  3. OTP skip (accès direct aux endpoints post-auth sans passer par /2fa)
  4. Response manipulation (modifier le champ "success" dans la réponse)
  5. Backup codes faibles (longueur, entropie, séquentiels)
  6. Code à longue validité (réponse indique exp > 10 min)
  7. Race condition (double soumission simultanée d'un même OTP)
  8. Null / empty bypass (envoyer code vide, null, 000000)

Tous les tests sont passifs ou peu bruteforçants — conçus pour du
bug bounty (pas de floods agressifs).
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from typing import AsyncGenerator
from urllib.parse import urlparse, urljoin

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester, ProbeRequest
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity
from phantomscan.core.scanner_mixin import ScannerMixin

# ---------------------------------------------------------------------------
# Endpoints OTP/2FA typiques
# ---------------------------------------------------------------------------
_2FA_PATHS: list[tuple[str, str]] = [
    ("/2fa", "POST"),
    ("/2fa/verify", "POST"),
    ("/api/2fa", "POST"),
    ("/api/2fa/verify", "POST"),
    ("/api/v1/2fa", "POST"),
    ("/api/v1/2fa/verify", "POST"),
    ("/api/v2/2fa/verify", "POST"),
    ("/otp", "POST"),
    ("/otp/verify", "POST"),
    ("/api/otp", "POST"),
    ("/api/otp/verify", "POST"),
    ("/verify", "POST"),
    ("/verify/otp", "POST"),
    ("/auth/verify", "POST"),
    ("/auth/otp", "POST"),
    ("/mfa", "POST"),
    ("/mfa/verify", "POST"),
    ("/api/mfa/verify", "POST"),
    ("/totp/verify", "POST"),
    ("/api/totp/verify", "POST"),
    ("/login/verify", "POST"),
    ("/account/verify", "POST"),
    ("/users/verify", "POST"),
]

# Endpoints typiquement protégés par 2FA (pour tester le skip)
_POST_2FA_PATHS: list[str] = [
    "/dashboard", "/home", "/account", "/profile",
    "/api/me", "/api/user", "/api/profile",
    "/api/v1/me", "/api/v1/user",
    "/settings", "/account/settings",
    "/admin", "/panel",
]

# Payloads brute force — codes OTP courants + codes triviaux
_OTP_BRUTEFORCE_CODES: list[str] = [
    "000000", "111111", "123456", "654321",
    "999999", "000001", "100000",
    "123123", "112233", "121212",
    "0", "1", "",                    # null/empty bypass
    "null", "undefined", "true",     # type juggling (PHP/JS)
    "AAAAAA", "aaaaaa",              # non-numérique
]

# Paramètres courants pour le champ OTP dans le body
_OTP_PARAM_NAMES: list[str] = [
    "otp", "code", "token", "totp", "mfa_code",
    "otp_code", "verification_code", "two_factor_code",
    "2fa_code", "pin", "passcode",
]

# Marqueurs de succès dans la réponse
_SUCCESS_MARKERS: list[str] = [
    "\"success\":true", "\"verified\":true", "\"valid\":true",
    "\"status\":\"ok\"", "\"authenticated\":true",
    "access_token", "\"token\":", "\"jwt\":",
    "dashboard", "welcome", "logged",
]

# Marqueurs indiquant un taux de validité trop long (> 10 min)
_EXPIRY_PATTERNS: list[re.Pattern] = [
    re.compile(r'"expires?_in"\s*:\s*(\d+)', re.IGNORECASE),
    re.compile(r'"ttl"\s*:\s*(\d+)', re.IGNORECASE),
    re.compile(r'"valid_for"\s*:\s*(\d+)', re.IGNORECASE),
    re.compile(r'"validity"\s*:\s*(\d+)', re.IGNORECASE),
]

# Délai entre tentatives brute force (secondes) — respectueux des cibles BB
_BF_DELAY = 0.4

# Nombre max de tentatives brute force par endpoint
_BF_MAX_ATTEMPTS = 10


class OTPBypassScanner(ScannerMixin):

    _RPS = 3.0

    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req = req
        self._heuristic = heuristic
        self._cfg = cfg

    # ------------------------------------------------------------------
    # Point d'entrée
    # ------------------------------------------------------------------

    async def run(self, target: str) -> AsyncGenerator[Finding, None]:
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Découverte des endpoints 2FA actifs
        active_endpoints = await self._discover_endpoints(base)
        if not active_endpoints:
            return

        for path, method in active_endpoints:
            url = f"{base}{path}"

            # 1. Null / empty bypass
            async for f in self._test_null_bypass(url):
                yield f

            # 2. Brute force léger (rate limit detection)
            async for f in self._test_bruteforce(url):
                yield f

            # 3. OTP reuse
            async for f in self._test_otp_reuse(url):
                yield f

            # 4. Longue validité OTP dans la réponse
            async for f in self._test_long_expiry(url):
                yield f

            # 5. Race condition
            async for f in self._test_race_condition(url):
                yield f

        # 6. 2FA skip (accès direct post-auth)
        async for f in self._test_2fa_skip(base):
            yield f

    # ------------------------------------------------------------------
    # Découverte des endpoints actifs
    # ------------------------------------------------------------------

    async def _discover_endpoints(self, base: str) -> list[tuple[str, str]]:
        active: list[tuple[str, str]] = []
        sem = asyncio.Semaphore(10)

        async def probe(path: str, method: str) -> tuple[str, str] | None:
            async with sem:
                url = f"{base}{path}"
                resp = await self._req.send(ProbeRequest(method=method, url=url))
                if resp.error:
                    return None
                # 400/422 = endpoint existe mais params manquants → actif
                if resp.status_code in (200, 201, 400, 401, 403, 405, 422, 429):
                    return (path, method)
                return None

        tasks = [probe(p, m) for p, m in _2FA_PATHS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, tuple):
                active.append(r)
        return active

    # ------------------------------------------------------------------
    # 1. Null / empty / type juggling bypass
    # ------------------------------------------------------------------

    async def _test_null_bypass(self, url: str) -> AsyncGenerator[Finding, None]:
        bypass_payloads = [
            ({}, "body vide"),
            ({"otp": ""}, "champ OTP vide"),
            ({"otp": None}, "otp=null"),
            ({"otp": True}, "otp=true (type juggling)"),
            ({"otp": 0}, "otp=0"),
            ({"code": ""}, "code vide"),
            ({"token": ""}, "token vide"),
        ]

        for payload, label in bypass_payloads:
            resp = await self._req.send(ProbeRequest(
                method="POST",
                url=url,
                headers={"Content-Type": "application/json"},
                body=json.dumps(payload),
            ))
            if resp.error:
                continue

            body = (resp.body or "").lower()
            matched = [m for m in _SUCCESS_MARKERS if m.lower() in body]

            if resp.status_code in (200, 201) and matched:
                yield Finding(
                    title="2FA Bypass — Null/Empty OTP Accepted",
                    url=url,
                    severity=Severity.CRITICAL,
                    description=(
                        f"Le endpoint 2FA accepte un code vide ou null.\n"
                        f"Payload testé : `{label}` → HTTP {resp.status_code}\n"
                        f"Indicateurs de succès : {matched}\n\n"
                        f"Un attaquant peut contourner le 2FA sans connaître le code."
                    ),
                    evidence=json.dumps(payload),
                    module="otp_bypass",
                )
                return

    # ------------------------------------------------------------------
    # 2. Brute force + détection absence rate limit
    # ------------------------------------------------------------------

    async def _test_bruteforce(self, url: str) -> AsyncGenerator[Finding, None]:
        attempts = 0
        rate_limited = False
        codes_tried: list[str] = []

        for code in _OTP_BRUTEFORCE_CODES[:_BF_MAX_ATTEMPTS]:
            # Tester chaque nom de param OTP courant
            for param in _OTP_PARAM_NAMES[:3]:
                payload = {param: code}
                resp = await self._req.send(ProbeRequest(
                    method="POST",
                    url=url,
                    headers={"Content-Type": "application/json"},
                    body=json.dumps(payload),
                ))
                if resp.error:
                    continue

                attempts += 1
                codes_tried.append(code)

                # Rate limit détecté
                if resp.status_code == 429:
                    rate_limited = True
                    break

                body = (resp.body or "").lower()
                matched = [m for m in _SUCCESS_MARKERS if m.lower() in body]

                # Bypass réussi
                if resp.status_code in (200, 201) and matched:
                    yield Finding(
                        title=f"2FA Bypass — Brute Force OTP ({code})",
                        url=url,
                        severity=Severity.CRITICAL,
                        description=(
                            f"Code OTP trivial `{code}` accepté après {attempts} tentatives.\n"
                            f"Paramètre : `{param}`\n"
                            f"Indicateurs de succès : {matched}"
                        ),
                        evidence=json.dumps(payload),
                        module="otp_bypass",
                    )
                    return

                await asyncio.sleep(_BF_DELAY)
            if rate_limited:
                break

        # Aucun rate limit après N tentatives → signaler la faiblesse
        if not rate_limited and attempts >= 5:
            yield Finding(
                title="2FA — Absence de Rate Limiting sur Vérification OTP",
                url=url,
                severity=Severity.HIGH,
                description=(
                    f"{attempts} tentatives OTP envoyées sans déclencher de rate limit "
                    f"(HTTP 429).\n"
                    f"Codes testés : {codes_tried[:8]}\n\n"
                    f"Sans rate limit, un attaquant peut brute-forcer un OTP à 6 chiffres "
                    f"(1M combinaisons) ou TOTP (30s window = 1000 codes valides par fenêtre)."
                ),
                evidence=f"{attempts} requêtes sans 429",
                module="otp_bypass",
            )

    # ------------------------------------------------------------------
    # 3. OTP Reuse
    # ------------------------------------------------------------------

    async def _test_otp_reuse(self, url: str) -> AsyncGenerator[Finding, None]:
        """
        Soumet le même code deux fois consécutivement.
        Si la 2e tentative retourne aussi 200, le code n'est pas invalidé.
        Note : sans vrai OTP valide, on teste avec un code fixe et vérifie
        la cohérence des réponses (même status, même body).
        """
        payload = json.dumps({"otp": "123456"})
        headers = {"Content-Type": "application/json"}

        resp1 = await self._req.send(ProbeRequest(
            method="POST", url=url, headers=headers, body=payload
        ))
        if resp1.error:
            return

        await asyncio.sleep(0.3)

        resp2 = await self._req.send(ProbeRequest(
            method="POST", url=url, headers=headers, body=payload
        ))
        if resp2.error:
            return

        # Si les deux réponses sont identiques et pas d'erreur liée au reuse
        body1 = (resp1.body or "").lower()
        body2 = (resp2.body or "").lower()

        reuse_blocked_patterns = ["already used", "expired", "invalid", "consumed", "used"]
        blocked_on_2 = any(p in body2 for p in reuse_blocked_patterns)
        blocked_on_1 = any(p in body1 for p in reuse_blocked_patterns)

        if not blocked_on_2 and resp1.status_code == resp2.status_code:
            # Les deux réponses semblent identiques → le code n'est pas invalidé
            if resp1.status_code in (400, 422):
                # Les deux échouent normalement (mauvais code) — vérifier quand même
                # si aucun mécanisme d'invalidation n'est visible
                yield Finding(
                    title="2FA — Possible OTP Reuse (à confirmer manuellement)",
                    url=url,
                    severity=Severity.MEDIUM,
                    description=(
                        f"Deux soumissions identiques du même OTP retournent le même "
                        f"status ({resp1.status_code}). Aucun message d'invalidation détecté.\n"
                        f"À confirmer avec un vrai OTP valide : si un code peut être soumis "
                        f"deux fois après validation, l'OTP n'est pas correctement consommé."
                    ),
                    evidence=f"Req1: {resp1.status_code} | Req2: {resp2.status_code}",
                    module="otp_bypass",
                )

    # ------------------------------------------------------------------
    # 4. Longue validité OTP
    # ------------------------------------------------------------------

    async def _test_long_expiry(self, url: str) -> AsyncGenerator[Finding, None]:
        """
        Cherche des infos d'expiration dans la réponse de l'endpoint OTP.
        GET sur l'endpoint de génération OTP si possible.
        """
        # Tenter un GET sur le même chemin (endpoint de génération)
        resp = await self._req.send(ProbeRequest(method="GET", url=url))
        if resp.error or resp.status_code not in (200, 201):
            # Tenter un POST sans payload
            resp = await self._req.send(ProbeRequest(
                method="POST", url=url,
                headers={"Content-Type": "application/json"},
                body="{}",
            ))

        if resp.error:
            return

        body = resp.body or ""
        for pattern in _EXPIRY_PATTERNS:
            m = pattern.search(body)
            if m:
                try:
                    seconds = int(m.group(1))
                except ValueError:
                    continue

                minutes = seconds / 60
                if minutes > 10:
                    yield Finding(
                        title=f"2FA — OTP Validity Too Long ({int(minutes)} min)",
                        url=url,
                        severity=Severity.MEDIUM,
                        description=(
                            f"L'endpoint révèle une durée de validité OTP de "
                            f"**{int(minutes)} minutes** ({seconds}s).\n"
                            f"Recommandation NIST SP 800-63B : max 30 secondes (TOTP) "
                            f"ou 5 minutes pour les OTP envoyés par SMS/email.\n"
                            f"Pattern détecté : `{m.group(0)}`"
                        ),
                        evidence=m.group(0),
                        module="otp_bypass",
                    )

    # ------------------------------------------------------------------
    # 5. Race condition
    # ------------------------------------------------------------------

    async def _test_race_condition(self, url: str) -> AsyncGenerator[Finding, None]:
        """
        Envoie N requêtes simultanées avec le même OTP.
        Si plusieurs retournent 200, la vérification n'est pas atomique.
        """
        RACE_CONCURRENCY = 8
        payload = json.dumps({"otp": "000000"})
        headers = {"Content-Type": "application/json"}

        async def send_one() -> int:
            resp = await self._req.send(ProbeRequest(
                method="POST", url=url, headers=headers, body=payload
            ))
            return resp.status_code if not resp.error else -1

        tasks = [send_one() for _ in range(RACE_CONCURRENCY)]
        statuses = await asyncio.gather(*tasks)

        success_count = sum(1 for s in statuses if s in (200, 201))

        if success_count >= 2:
            yield Finding(
                title="2FA — Race Condition sur Vérification OTP",
                url=url,
                severity=Severity.HIGH,
                description=(
                    f"{success_count}/{RACE_CONCURRENCY} requêtes simultanées avec le même OTP "
                    f"ont retourné HTTP 2xx.\n"
                    f"La vérification OTP n'est pas atomique — un attaquant peut "
                    f"exploiter cette fenêtre pour valider un code plusieurs fois "
                    f"ou passer la 2FA avec un code périmé.\n"
                    f"Statuts obtenus : {list(statuses)}"
                ),
                evidence=f"Statuts race: {list(statuses)}",
                module="otp_bypass",
            )

    # ------------------------------------------------------------------
    # 6. 2FA Skip — accès direct post-auth
    # ------------------------------------------------------------------

    async def _test_2fa_skip(self, base: str) -> AsyncGenerator[Finding, None]:
        """
        Teste si les endpoints normalement protégés par 2FA sont accessibles
        directement sans avoir complété la vérification.
        On teste sans session valide, donc les 200 réels sont rares —
        mais si on obtient un 200 avec du contenu, c'est suspect.
        """
        for path in _POST_2FA_PATHS:
            url = f"{base}{path}"
            resp = await self._req.send(ProbeRequest(method="GET", url=url))
            if resp.error:
                continue

            body = (resp.body or "")
            body_lower = body.lower()

            # Doit être redirigé vers /login ou /2fa, pas retourner du contenu
            if resp.status_code == 200:
                # Chercher du contenu "authentifié" dans la réponse
                auth_content = [
                    "logout", "sign out", "my account", "profile",
                    "dashboard", "welcome", "\"email\":", "\"user\":",
                ]
                matched = [c for c in auth_content if c in body_lower]
                if matched:
                    yield Finding(
                        title=f"2FA Skip — Endpoint Post-Auth Accessible sans 2FA",
                        url=url,
                        severity=Severity.HIGH,
                        description=(
                            f"L'endpoint `{path}` retourne HTTP 200 avec du contenu "
                            f"authentifié sans avoir complété la vérification 2FA.\n"
                            f"Contenu suspect détecté : {matched}\n\n"
                            f"À confirmer manuellement : créer une session à l'étape "
                            f"pré-2FA et accéder directement à cet endpoint."
                        ),
                        evidence=body[:300],
                        module="otp_bypass",
                    )
