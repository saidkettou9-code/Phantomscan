"""
PhantomScan — OpenAPI / Swagger Recon & Security Scanner

Découverte et analyse des specs OpenAPI/Swagger exposées :
  - Détection automatique des chemins de spec communs
  - Extraction de tous les endpoints, méthodes, paramètres
  - Détection d'endpoints non authentifiés (pas de securityScheme)
  - Repérage d'informations sensibles dans les descriptions / examples
  - Détection de schémas dangereux (file upload, eval, exec)
  - Test d'accès non authentifié aux endpoints documentés

Compatible : OpenAPI 2.0 (Swagger), OpenAPI 3.0, OpenAPI 3.1
"""

from __future__ import annotations

import json
import re
from typing import AsyncGenerator
from urllib.parse import urlparse, urljoin

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester, ProbeRequest
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity
from phantomscan.core.scanner_mixin import ScannerMixin

# ------------------------------------------------------------------
# Chemins communs où les specs sont exposées
# ------------------------------------------------------------------

SPEC_PATHS = [
    "/swagger.json",
    "/swagger.yaml",
    "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json",
    "/openapi.json",
    "/openapi.yaml",
    "/api/swagger.json",
    "/api/openapi.json",
    "/api/v1/swagger.json",
    "/api/v1/openapi.json",
    "/api/v2/swagger.json",
    "/api/v2/openapi.json",
    "/api/v3/openapi.json",
    "/api-docs",
    "/api-docs/swagger.json",
    "/api-docs/v1",
    "/api-docs/v2",
    "/v1/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/docs/swagger.json",
    "/docs/openapi.json",
    "/spec/openapi.json",
    "/.well-known/openapi",
    "/redoc",
    "/swagger-ui/swagger.json",
    "/swagger-ui.html",
    "/api/spec",
    "/api/schema",
]

# Patterns sensibles dans les specs (descriptions, examples, default values)
SENSITIVE_PATTERNS = [
    (r'password.*?:.*?"[^"]{4,}"',     "Mot de passe en clair dans la spec"),
    (r'secret.*?:.*?"[^"]{4,}"',       "Secret exposé dans la spec"),
    (r'api[-_]?key.*?:.*?"[^"]{8,}"',  "Clé API exposée dans la spec"),
    (r'token.*?:.*?"[^"]{10,}"',       "Token exposé dans la spec"),
    (r'private[-_]key',                "Clé privée mentionnée dans la spec"),
    (r'BEGIN\s+(RSA|EC|PRIVATE)',       "Clé PEM dans la spec"),
    (r'AKIA[0-9A-Z]{16}',              "AWS Access Key ID dans la spec"),
    (r'127\.0\.0\.1|localhost|internal\.', "Adresse interne dans la spec"),
    (r'\.internal\.|\.local\b',         "Domaine interne dans la spec"),
    (r'admin|root|superuser',           "Compte privilégié dans les exemples"),
]

# Scopes / permissions qui indiquent un endpoint sensible
SENSITIVE_SCOPES = {"admin", "write", "delete", "internal", "manage", "root", "superuser"}

# Méthodes HTTP dangereuses
DANGEROUS_METHODS = {"DELETE", "PUT", "PATCH"}

# Paramètre types dangereux
DANGEROUS_PARAM_NAMES = {
    "exec", "eval", "cmd", "command", "shell", "script",
    "file", "filename", "upload", "path", "filepath",
    "url", "redirect", "callback", "webhook",
    "sql", "query", "filter", "template",
}


class OpenAPIReconScanner(ScannerMixin):

    _RPS = 10.0

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

        spec_url, spec_data = await self._discover_spec(base)
        if not spec_data:
            return

        yield Finding(
            title="OpenAPI/Swagger Spec Exposed",
            url=spec_url,
            severity=Severity.INFO,
            description=(
                f"Spécification OpenAPI accessible publiquement à `{spec_url}`.\n"
                f"Cela expose la surface d'attaque complète de l'API."
            ),
            evidence=spec_url,
            module="open_api_recon",
        )

        # Analyser la spec
        async for f in self._analyze_spec(base, spec_url, spec_data):
            yield f

    # ------------------------------------------------------------------
    # Découverte de la spec
    # ------------------------------------------------------------------

    async def _discover_spec(self, base: str) -> tuple[str, dict | None]:
        for path in SPEC_PATHS:
            url = f"{base}{path}"
            resp = await self._req.send(ProbeRequest(method="GET", url=url))
            if resp.error or resp.status_code != 200:
                continue

            body = resp.body or ""

            # Essayer JSON
            try:
                data = json.loads(body)
                if self._is_openapi_spec(data):
                    return url, data
            except json.JSONDecodeError:
                pass

            # Essayer de détecter un JSON imbriqué dans du HTML (Swagger UI)
            json_match = re.search(r'url:\s*["\']([^"\']+\.json)["\']', body)
            if json_match:
                sub_url = urljoin(base, json_match.group(1))
                sub_resp = await self._req.send(ProbeRequest(method="GET", url=sub_url))
                if not sub_resp.error and sub_resp.status_code == 200:
                    try:
                        data = json.loads(sub_resp.body or "")
                        if self._is_openapi_spec(data):
                            return sub_url, data
                    except json.JSONDecodeError:
                        pass

        return "", None

    def _is_openapi_spec(self, data: dict) -> bool:
        return (
            isinstance(data, dict) and (
                "swagger" in data or
                "openapi" in data or
                "paths" in data
            )
        )

    # ------------------------------------------------------------------
    # Analyse de la spec
    # ------------------------------------------------------------------

    async def _analyze_spec(
        self, base: str, spec_url: str, spec: dict
    ) -> AsyncGenerator[Finding, None]:

        version = spec.get("openapi", spec.get("swagger", "?"))
        paths = spec.get("paths", {})
        components = spec.get("components", spec.get("definitions", {}))
        security_schemes = (
            components.get("securitySchemes", {}) or
            spec.get("securityDefinitions", {})
        )

        # 1. Pas de schéma d'auth global
        global_security = spec.get("security", [])
        if not global_security and not security_schemes:
            yield Finding(
                title="OpenAPI — No Global Security Scheme Defined",
                url=spec_url,
                severity=Severity.MEDIUM,
                description=(
                    "La spec OpenAPI ne définit aucun schéma d'authentification global.\n"
                    "Tous les endpoints peuvent être accessibles sans credentials."
                ),
                evidence=f"OpenAPI {version} — security: []",
                module="open_api_recon",
            )

        # 2. Secrets / données sensibles dans la spec
        spec_text = json.dumps(spec)
        for pattern, description in SENSITIVE_PATTERNS:
            if re.search(pattern, spec_text, re.IGNORECASE):
                yield Finding(
                    title=f"OpenAPI — Sensitive Data in Spec: {description}",
                    url=spec_url,
                    severity=Severity.HIGH,
                    description=(
                        f"Données sensibles détectées dans la spécification OpenAPI.\n"
                        f"Pattern: `{pattern}`\n"
                        f"Description: {description}"
                    ),
                    evidence=pattern,
                    module="open_api_recon",
                )

        # 3. Analyse par endpoint
        unauthenticated_endpoints: list[str] = []
        dangerous_params_found: list[tuple] = []

        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            for method, operation in path_item.items():
                if method.upper() not in ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"):
                    continue
                if not isinstance(operation, dict):
                    continue

                full_url = f"{base}{path}"
                op_security = operation.get("security")

                # Endpoint sans sécurité explicite
                if op_security == [] or (op_security is None and not global_security):
                    unauthenticated_endpoints.append(f"{method.upper()} {path}")

                # Méthodes dangereuses non protégées
                if method.upper() in DANGEROUS_METHODS and (op_security == [] or not global_security):
                    yield Finding(
                        title=f"OpenAPI — Unprotected {method.upper()} Endpoint",
                        url=full_url,
                        severity=Severity.HIGH,
                        description=(
                            f"Endpoint `{method.upper()} {path}` sans authentification requise.\n"
                            f"Les méthodes destructives (PUT/PATCH/DELETE) sans auth "
                            f"représentent un risque critique."
                        ),
                        evidence=f"{method.upper()} {path} — security: none",
                        module="open_api_recon",
                    )

                # Paramètres dangereux
                params = operation.get("parameters", [])
                # OpenAPI 3.x : requestBody
                req_body = operation.get("requestBody", {})
                if req_body:
                    content = req_body.get("content", {})
                    for ct, ct_data in content.items():
                        schema = ct_data.get("schema", {})
                        props = schema.get("properties", {})
                        params += [{"name": k, "in": "body"} for k in props]

                for param in params:
                    pname = (param.get("name") or "").lower()
                    if pname in DANGEROUS_PARAM_NAMES:
                        dangerous_params_found.append((method.upper(), path, pname))

                # Test accès non authentifié sur endpoints GET sans security
                if (method.upper() == "GET" and
                        (op_security == [] or (op_security is None and not global_security))):
                    # Construire l'URL avec des valeurs factices pour les path params
                    test_url = re.sub(r"\{[^}]+\}", "1", path)
                    test_full = f"{base}{test_url}"
                    resp = await self._req.send(ProbeRequest(method="GET", url=test_full))
                    if not resp.error and resp.status_code == 200:
                        body_snippet = (resp.body or "")[:200]
                        yield Finding(
                            title="OpenAPI — Unauthenticated Endpoint Accessible",
                            url=test_full,
                            severity=Severity.MEDIUM,
                            description=(
                                f"Endpoint `GET {path}` documenté comme public — accessible sans token.\n"
                                f"Vérifier si des données sensibles sont retournées."
                            ),
                            evidence=body_snippet,
                            module="open_api_recon",
                        )

        # 4. Rapport sur les params dangereux
        if dangerous_params_found:
            names = list({p for _, _, p in dangerous_params_found})
            endpoints_list = [f"{m} {p}" for m, p, _ in dangerous_params_found[:10]]
            yield Finding(
                title="OpenAPI — Dangerous Parameter Names Detected",
                url=spec_url,
                severity=Severity.MEDIUM,
                description=(
                    f"Paramètres à haut risque d'injection détectés dans la spec.\n"
                    f"Noms suspects: {names}\n"
                    f"Endpoints concernés: {endpoints_list}"
                ),
                evidence=str(dangerous_params_found[:5]),
                module="open_api_recon",
            )

        # 5. Beaucoup d'endpoints non authentifiés
        if len(unauthenticated_endpoints) > 5:
            yield Finding(
                title="OpenAPI — Large Unauthenticated Attack Surface",
                url=spec_url,
                severity=Severity.HIGH,
                description=(
                    f"{len(unauthenticated_endpoints)} endpoints sans authentification.\n"
                    f"Exemples: {unauthenticated_endpoints[:8]}"
                ),
                evidence=str(unauthenticated_endpoints[:10]),
                module="open_api_recon",
            )
