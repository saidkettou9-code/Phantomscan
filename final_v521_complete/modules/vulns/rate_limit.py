"""
PhantomScan — Rate Limit & Business Logic Scanner
Teste :
  - Absence de rate limiting sur endpoints sensibles (login, reset, OTP)
  - Race condition sur endpoints transactionnels
  - Mass assignment via params non documentés
  - Account enumeration via timing/message différentiel
"""

from __future__ import annotations

import asyncio
import statistics
import time
from typing import AsyncGenerator
from urllib.parse import urlparse, urljoin

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester, ProbeRequest
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity
from phantomscan.core.scanner_mixin import ScannerMixin

# Endpoints sensibles à tester pour rate limit
SENSITIVE_PATHS = [
    ("/login", "POST"),
    ("/signin", "POST"),
    ("/api/login", "POST"),
    ("/api/auth/login", "POST"),
    ("/api/v1/login", "POST"),
    ("/forgot-password", "POST"),
    ("/reset-password", "POST"),
    ("/api/reset-password", "POST"),
    ("/api/otp", "POST"),
    ("/api/verify", "POST"),
    ("/api/2fa", "POST"),
    ("/register", "POST"),
    ("/api/register", "POST"),
    ("/api/v1/register", "POST"),
    ("/search", "GET"),
    ("/api/search", "GET"),
]

# Nombre de requêtes pour déclencher un rate limit
RATE_LIMIT_PROBE_COUNT = 20
# Délai max acceptable entre requêtes (en ms) pour confirmer race condition
RACE_WINDOW_MS = 50


class RateLimitScanner(ScannerMixin):

    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req = req
        self._heuristic = heuristic
        self._cfg = cfg

    async def run(self, target: str) -> AsyncGenerator[Finding, None]:
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Phase 1: découverte des endpoints sensibles qui existent
        live_endpoints = await self._discover_endpoints(base)

        for path, method in live_endpoints:
            url = f"{base}{path}"

            # Rate limit test
            async for f in self._test_rate_limit(url, method, path):
                yield f

            # Account enumeration test (login seulement)
            if "login" in path or "signin" in path:
                async for f in self._test_account_enum(url, method):
                    yield f

        # Phase 2: race condition sur endpoints transactionnels
        async for f in self._test_race_condition(base):
            yield f

        # Phase 3: mass assignment
        async for f in self._test_mass_assignment(target):
            yield f

    async def _discover_endpoints(self, base: str) -> list[tuple[str, str]]:
        """Retourne les (path, method) qui existent (pas 404)."""
        sem = asyncio.Semaphore(8)

        async def probe(path: str, method: str):
            async with sem:
                resp = await self._req.send(ProbeRequest(
                    method=method,
                    url=f"{base}{path}",
                    body="{}" if method == "POST" else None,
                    headers={"Content-Type": "application/json"} if method == "POST" else {},
                ))
                return path, method, resp

        tasks = [asyncio.create_task(probe(p, m)) for p, m in SENSITIVE_PATHS]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        live = []
        for item in results:
            if isinstance(item, Exception):
                continue
            path, method, resp = item
            # On exclut les 404 et les 403/400 permanents — ils ne sont pas testables
            # et génèrent des faux positifs (rate limit sur des endpoints qui bloquent tout)
            if not resp.error and resp.status in (200, 201, 401, 405, 422):
                live.append((path, method))

        return live

    async def _test_rate_limit(
        self, url: str, method: str, path: str
    ) -> AsyncGenerator[Finding, None]:
        """
        Envoie RATE_LIMIT_PROBE_COUNT requêtes rapides et vérifie si l'app rate-limite.
        Indicateurs de rate limit : 429, Retry-After header, ou message spécifique.
        """
        body = '{"username":"test@test.com","password":"test1234"}' if method == "POST" else None
        headers = {"Content-Type": "application/json"} if method == "POST" else {}

        statuses: list[int] = []
        got_rate_limited = False

        for i in range(RATE_LIMIT_PROBE_COUNT):
            resp = await self._req.send(ProbeRequest(
                method=method,
                url=url,
                body=body,
                headers=headers,
                timeout=8,
            ))
            if resp.error:
                continue
            statuses.append(resp.status)

            # Rate limit détecté
            if resp.status == 429 or "retry-after" in {k.lower() for k in resp.headers}:
                got_rate_limited = True
                break

            # Message de rate limit dans le body
            if any(
                kw in resp.body.lower()
                for kw in ("rate limit", "too many", "slow down", "throttl", "try again later")
            ):
                got_rate_limited = True
                break

        if not got_rate_limited and len(statuses) >= RATE_LIMIT_PROBE_COUNT // 2:
            # Vérifie que les réponses sont cohérentes (pas juste des errors réseau)
            non_error = [s for s in statuses if s > 0]
            if len(non_error) >= 10 and self._heur.is_real_hit(resp, min_confidence=45):
                yield Finding(
                    title=f"No Rate Limiting on {method} {path}",
                    severity=Severity.MEDIUM,
                    url=url,
                    module="vulns/rate_limit",
                    description=(
                        f"{RATE_LIMIT_PROBE_COUNT} requêtes {method} envoyées sans déclenchement "
                        f"de rate limit. L'endpoint '{path}' est vulnérable au brute force / flooding."
                    ),
                    evidence=(
                        f"Statuses observés: {set(non_error)}\n"
                        f"Aucun 429 ni header Retry-After reçu."
                    ),
                    cwe="CWE-307",
                    remediation=(
                        "Implémenter un rate limiting par IP et par compte. "
                        "Ajouter un CAPTCHA sur les endpoints d'authentification. "
                        "Retourner HTTP 429 avec header Retry-After."
                    ),
                )

    async def _test_account_enum(
        self, url: str, method: str
    ) -> AsyncGenerator[Finding, None]:
        """
        Teste si l'app permet l'énumération de comptes via des réponses différenciées
        entre un utilisateur existant et un utilisateur inexistant.
        Méthodes : timing différentiel + message différentiel.
        """
        # Deux usernames : un plausible, un clairement inexistant
        existing_candidates = [
            "admin@example.com", "admin", "test@test.com", "user@example.com",
        ]
        nonexistent = "zz_nonexistent_phantomscan_probe_9x@nowhere.invalid"

        timings_exist: list[float] = []
        timings_noexist: list[float] = []
        bodies_exist: list[str] = []
        bodies_noexist: list[str] = []

        for username in existing_candidates[:2]:
            t0 = time.monotonic()
            resp = await self._req.send(ProbeRequest(
                method=method,
                url=url,
                body=f'{{"username":"{username}","password":"wrongpassword_x9z"}}',
                headers={"Content-Type": "application/json"},
                timeout=10,
            ))
            elapsed = (time.monotonic() - t0) * 1000
            if not resp.error:
                timings_exist.append(elapsed)
                bodies_exist.append(resp.body[:500].lower())

        for _ in range(2):
            t0 = time.monotonic()
            resp = await self._req.send(ProbeRequest(
                method=method,
                url=url,
                body=f'{{"username":"{nonexistent}","password":"wrongpassword_x9z"}}',
                headers={"Content-Type": "application/json"},
                timeout=10,
            ))
            elapsed = (time.monotonic() - t0) * 1000
            if not resp.error:
                timings_noexist.append(elapsed)
                bodies_noexist.append(resp.body[:500].lower())

        if not timings_exist or not timings_noexist:
            return

        # Timing différentiel > 150ms → suspect
        avg_exist = statistics.mean(timings_exist)
        avg_noexist = statistics.mean(timings_noexist)
        timing_diff = abs(avg_exist - avg_noexist)

        if timing_diff > 150:
            yield Finding(
                title="Account Enumeration via Timing Differential",
                severity=Severity.MEDIUM,
                url=url,
                module="vulns/rate_limit",
                description=(
                    f"Différence de timing significative entre utilisateur existant "
                    f"({avg_exist:.0f}ms) et inexistant ({avg_noexist:.0f}ms): {timing_diff:.0f}ms. "
                    "Indique un traitement différent (ex: hash comparaison vs early return)."
                ),
                evidence=f"Exist avg: {avg_exist:.0f}ms | Noexist avg: {avg_noexist:.0f}ms | Diff: {timing_diff:.0f}ms",
                cwe="CWE-204",
                remediation=(
                    "Utiliser un hash constant-time même pour les utilisateurs inexistants. "
                    "Retourner des messages d'erreur génériques ('identifiants incorrects')."
                ),
            )

        # Message différentiel
        if bodies_exist and bodies_noexist:
            msg_exist = bodies_exist[0]
            msg_noexist = bodies_noexist[0]
            if msg_exist != msg_noexist:
                # Cherche des indicateurs clairs
                exist_indicators = ["invalid password", "wrong password", "incorrect password", "bad credentials"]
                noexist_indicators = ["user not found", "account not found", "no account", "doesn't exist", "not registered"]

                exist_leaks = any(i in msg_exist for i in exist_indicators)
                noexist_leaks = any(i in msg_noexist for i in noexist_indicators)

                if exist_leaks or noexist_leaks:
                    yield Finding(
                        title="Account Enumeration via Error Message",
                        severity=Severity.MEDIUM,
                        url=url,
                        module="vulns/rate_limit",
                        description=(
                            "Messages d'erreur différenciés entre utilisateur existant et inexistant. "
                            "Permet à un attaquant de valider des comptes."
                        ),
                        evidence=(
                            f"Existing user message: '{msg_exist[:150]}'\n"
                            f"Nonexistent user message: '{msg_noexist[:150]}'"
                        ),
                        cwe="CWE-204",
                        remediation="Retourner un message générique identique quelle que soit la cause de l'échec.",
                    )

    async def _test_race_condition(self, base: str) -> AsyncGenerator[Finding, None]:
        """
        Teste la race condition sur les endpoints de type "limité à 1 utilisation" :
        - Code promo / coupon
        - Withdraw / transfer
        - Vote / reaction
        Lance N requêtes simultanées et vérifie si plusieurs réussissent.
        """
        race_candidates = [
            ("/api/redeem", "POST", '{"code":"PROMO10"}'),
            ("/api/coupon/apply", "POST", '{"coupon":"TEST10"}'),
            ("/api/transfer", "POST", '{"amount":1,"to":"attacker"}'),
            ("/api/vote", "POST", '{"item_id":1}'),
            ("/api/like", "POST", '{"post_id":1}'),
            ("/api/claim", "POST", '{"reward_id":1}'),
        ]

        RACE_COUNT = 10

        for path, method, body in race_candidates:
            url = f"{base}{path}"

            # Check si l'endpoint existe
            check = await self._req.send(ProbeRequest(
                method=method, url=url,
                body=body,
                headers={"Content-Type": "application/json"},
                timeout=5,
            ))
            if check.error or check.status == 404:
                continue

            # Lance RACE_COUNT requêtes simultanées
            tasks = [
                asyncio.create_task(self._req.send(ProbeRequest(
                    method=method, url=url,
                    body=body,
                    headers={"Content-Type": "application/json"},
                    timeout=8,
                )))
                for _ in range(RACE_COUNT)
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            success_count = sum(
                1 for r in results
                if not isinstance(r, Exception) and not r.error and r.status in (200, 201)
            )

            if success_count > 1:
                yield Finding(
                    title=f"Race Condition on {path}",
                    severity=Severity.HIGH,
                    url=url,
                    module="vulns/rate_limit",
                    description=(
                        f"{success_count}/{RACE_COUNT} requêtes simultanées ont réussi sur '{path}'. "
                        "L'endpoint n'est pas protégé contre les accès concurrents. "
                        "Exploitable pour doubler des transactions, utiliser un coupon plusieurs fois, etc."
                    ),
                    evidence=f"Requêtes simultanées: {RACE_COUNT} | Succès: {success_count}",
                    cwe="CWE-362",
                    remediation=(
                        "Utiliser des transactions atomiques (verrous DB, SELECT FOR UPDATE). "
                        "Implémenter un idempotency key côté serveur. "
                        "Utiliser des queues pour les opérations sensibles."
                    ),
                )

    async def _test_mass_assignment(self, target: str) -> AsyncGenerator[Finding, None]:
        """
        Teste le mass assignment : envoie des champs non attendus sur des endpoints
        d'inscription/mise à jour et vérifie s'ils sont acceptés dans la réponse.
        """
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        mass_assign_paths = [
            ("/api/register", '{"username":"pstest_x9","email":"ps@test.com","password":"Test1234!","role":"admin","is_admin":true,"admin":true,"privilege":9,"credits":9999}'),
            ("/api/user/update", '{"name":"test","role":"admin","is_admin":true,"admin":1}'),
            ("/api/profile", '{"bio":"test","role":"admin","balance":99999}'),
            ("/register", '{"username":"pstest_x9","password":"Test1234!","role":"admin","is_admin":true}'),
        ]

        sensitive_fields = ["role", "is_admin", "admin", "privilege", "credits", "balance", "verified"]

        for path, body in mass_assign_paths:
            url = f"{base}{path}"
            resp = await self._req.send(ProbeRequest(
                method="POST",
                url=url,
                body=body,
                headers={"Content-Type": "application/json"},
                timeout=8,
            ))

            if resp.error or resp.status == 404:
                continue

            # Si l'endpoint existe et retourne 200/201, vérifie si les champs sensibles sont dans la réponse
            if resp.status in (200, 201) and resp.body:
                body_low = resp.body.lower()
                found_fields = [f for f in sensitive_fields if f'"' + f + '"' in resp.body or f"'{f}'" in resp.body]
                if found_fields:
                    yield Finding(
                        title=f"Mass Assignment — sensitive fields accepted on {path}",
                        severity=Severity.HIGH,
                        url=url,
                        module="vulns/rate_limit",
                        description=(
                            f"L'endpoint {path} accepte des champs sensibles non prévus: {found_fields}. "
                            "Un attaquant peut s'attribuer des rôles élevés ou manipuler son compte."
                        ),
                        evidence=f"Fields sent: {found_fields}\nResponse: {resp.body[:300]}",
                        cwe="CWE-915",
                        remediation=(
                            "Utiliser un whitelist explicite des champs acceptés (DTOs). "
                            "Ne jamais bind directement le body JSON vers un objet modèle. "
                            "Filtrer les champs sensibles avant tout traitement."
                        ),
                    )
