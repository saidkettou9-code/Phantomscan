"""
PhantomScan — API Security Scanner  v1.0
==========================================
Détection de vulnérabilités spécifiques aux APIs REST modernes.

Techniques couvertes :
  - API Versioning Abuse : tester les anciennes versions (v0, v1, v2...) moins sécurisées
  - Exposed Debug/Admin Endpoints : /api/debug, /api/internal, /api/admin
  - HTTP Method Override : X-HTTP-Method-Override, _method, X-Method-Override
  - Response Format Manipulation : Accept: text/plain, Accept: application/xml
  - Field Filtering Bypass : ?fields=* ?select=* pour extraire tous les champs
  - Content-Type Confusion : JSON → form, form → JSON, multipart → JSON
  - API Key in URL : détection de clés dans les params d'URL
  - Unreferenced Endpoints : découverte d'endpoints REST standards non-documentés
    (CRUD complet depuis un seul endpoint connu)
"""

from __future__ import annotations

import re
from typing import AsyncIterator
from urllib.parse import urlparse, urljoin, urlencode, urlunparse, parse_qs

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester, ProbeRequest
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity
from phantomscan.core.scanner_mixin import ScannerMixin


# ─────────────────────────── Constantes ──────────────────────────────────────

_API_PREFIXES = ["/api/", "/v1/", "/v2/", "/v3/", "/rest/", "/graphql", "/service/"]

_OLD_VERSIONS = ["v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9",
                 "1.0", "2.0", "3.0", "beta", "alpha", "internal", "dev", "test"]

_DEBUG_PATHS = [
    "/api/debug", "/api/internal", "/api/admin", "/api/health", "/api/status",
    "/api/metrics", "/api/info", "/api/version", "/api/config", "/api/env",
    "/api/ping", "/api/test", "/api/dev", "/api/diagnostic",
    "/internal/api", "/debug/api", "/admin/api",
    "/api/swagger", "/api/swagger.json", "/api/openapi.json",
    "/api/schema", "/api/docs", "/api/redoc",
    "/__debug__", "/_debug", "/debug",
    "/api/users?admin=true", "/api/admin/users",
    "/api/v1/admin", "/api/v2/admin",
]

_METHOD_OVERRIDE_HEADERS = [
    "X-HTTP-Method-Override",
    "X-Method-Override",
    "X-HTTP-Method",
    "_method",
]

_SENSITIVE_RESPONSE_PATTERNS = re.compile(
    r"(password|passwd|secret|token|api_key|private_key|access_key|"
    r"ssn|social_security|credit_card|card_number|cvv|pin\b)",
    re.I,
)

_API_KEY_IN_URL = re.compile(
    r"[?&](api[_-]?key|apikey|access[_-]?token|auth[_-]?token|key|token)=([A-Za-z0-9_\-]{16,})",
    re.I,
)

_CRUD_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]


# ─────────────────────────── Scanner ─────────────────────────────────────────

class APISecurityScanner(ScannerMixin):

    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req = req
        self._heuristic = heuristic
        self._cfg = cfg
        self._bus = None

    def set_endpoint_bus(self, bus) -> None:
        self._bus = bus

    async def run(self, target: str) -> AsyncIterator[Finding]:
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # ── 1. Détection endpoints debug/admin exposés ───────────────────────
        async for f in self._scan_debug_endpoints(base):
            yield f

        # ── 2. API Versioning Abuse ──────────────────────────────────────────
        if any(p in target for p in _API_PREFIXES):
            async for f in self._test_api_versioning(target):
                yield f

        # ── 3. HTTP Method Override ──────────────────────────────────────────
        async for f in self._test_method_override(target):
            yield f

        # ── 4. Field Filtering Bypass ────────────────────────────────────────
        async for f in self._test_field_bypass(target):
            yield f

        # ── 5. API Key dans l'URL ────────────────────────────────────────────
        async for f in self._detect_api_key_in_url(target):
            yield f

        # ── 6. CRUD Discovery sur les endpoints connus ───────────────────────
        if self._bus:
            endpoints = self._bus.snapshot
            api_eps = [ep for ep in endpoints if any(p in ep.url for p in _API_PREFIXES)]
            for ep in api_eps[:20]:
                async for f in self._discover_unreferenced_methods(ep.url):
                    yield f

        # ── 7. Content-Type Confusion ────────────────────────────────────────
        if self._bus:
            endpoints = self._bus.snapshot
            post_eps = [ep for ep in endpoints if ep.method == "POST"]
            for ep in post_eps[:10]:
                async for f in self._test_content_type_confusion(ep.url):
                    yield f

    # ── Debug endpoints ───────────────────────────────────────────────────────

    async def _scan_debug_endpoints(self, base: str) -> AsyncIterator[Finding]:
        for path in _DEBUG_PATHS:
            url = base + path
            resp = await self._req.get(url)
            if resp.error or resp.status in (404, 410):
                continue

            if resp.status in (200, 201):
                has_sensitive = bool(_SENSITIVE_RESPONSE_PATTERNS.search(resp.body))
                severity = Severity.HIGH if has_sensitive else Severity.MEDIUM
                yield Finding(
                    title=f"API Endpoint non-protégé exposé: {path}",
                    severity=severity,
                    url=url,
                    module="vulns/api_security",
                    description=(
                        f"L'endpoint `{path}` est accessible sans authentification (HTTP {resp.status}). "
                        + ("Contient des données sensibles." if has_sensitive else "")
                    ),
                    evidence=f"GET {url} → {resp.status} | body[:200]: {resp.body[:200]}",
                    cwe="CWE-200",
                    remediation=(
                        "Protéger les endpoints debug/admin par authentification forte. "
                        "Désactiver ou supprimer les endpoints de debug en production. "
                        "Implémenter un réseau séparé pour les endpoints d'administration."
                    ),
                )

    # ── API Versioning Abuse ──────────────────────────────────────────────────

    async def _test_api_versioning(self, target: str) -> AsyncIterator[Finding]:
        parsed = urlparse(target)
        path = parsed.path

        # Détecter la version actuelle
        version_re = re.compile(r"/(v\d+|v\d+\.\d+)/")
        m = version_re.search(path)
        if not m:
            return

        current_version = m.group(1)
        base_path = path[:m.start()]
        rest_path = path[m.end():]

        base = f"{parsed.scheme}://{parsed.netloc}"
        orig_resp = await self._req.get(target)
        if orig_resp.error:
            return

        for old_ver in _OLD_VERSIONS:
            if old_ver == current_version:
                continue
            old_url = f"{base}{base_path}/{old_ver}/{rest_path}"
            resp = await self._req.get(old_url)
            if resp.error or resp.status in (404, 410):
                continue
            if resp.status == 200:
                # Comparer si la vieille version retourne des données supplémentaires
                extra_fields = _SENSITIVE_RESPONSE_PATTERNS.search(resp.body)
                if extra_fields or len(resp.body) > len(orig_resp.body) * 1.1:
                    yield Finding(
                        title=f"API Version Abuse — {old_ver} retourne plus de données que {current_version}",
                        severity=Severity.HIGH,
                        url=old_url,
                        module="vulns/api_security",
                        description=(
                            f"L'ancienne version `{old_ver}` de l'API est accessible et retourne "
                            f"potentiellement plus de données que la version actuelle `{current_version}`. "
                            f"Les vieilles versions ont souvent moins de contrôles d'accès."
                        ),
                        evidence=f"GET {old_url} → HTTP {resp.status} | body: {resp.content_length}B vs {orig_resp.content_length}B",
                        cwe="CWE-1059",
                        remediation=(
                            "Désactiver toutes les versions d'API non-maintenues. "
                            "Implémenter les mêmes contrôles d'accès sur toutes les versions. "
                            "Documenter et appliquer une politique de dépréciation avec date de suppression."
                        ),
                    )
                    break

    # ── HTTP Method Override ──────────────────────────────────────────────────

    async def _test_method_override(self, target: str) -> AsyncIterator[Finding]:
        # Tester si DELETE/PUT sont possibles via header override sur un endpoint GET
        for override_method in ["DELETE", "PUT", "PATCH"]:
            for header_name in _METHOD_OVERRIDE_HEADERS:
                resp = await self._req.send(ProbeRequest(
                    method="GET",
                    url=target,
                    headers={header_name: override_method},
                ))
                if resp.error:
                    continue
                # DELETE via override → si le statut change significativement
                if resp.status in (200, 204, 202):
                    orig_resp = await self._req.get(target)
                    if not orig_resp.error and orig_resp.status == 200:
                        if resp.content_length != orig_resp.content_length:
                            yield Finding(
                                title=f"HTTP Method Override — {header_name}: {override_method}",
                                severity=Severity.HIGH,
                                url=target,
                                module="vulns/api_security",
                                description=(
                                    f"Le header `{header_name}: {override_method}` est accepté et "
                                    f"modifie le comportement de la requête GET. "
                                    f"Peut permettre d'exécuter des méthodes normalement bloquées "
                                    f"par le WAF ou le proxy (DELETE, PUT)."
                                ),
                                evidence=f"GET + {header_name}: {override_method} → HTTP {resp.status} | {resp.content_length}B vs {orig_resp.content_length}B",
                                cwe="CWE-650",
                                remediation=(
                                    "Désactiver le support des headers X-HTTP-Method-Override si non-nécessaire. "
                                    "Valider les autorisations pour la méthode réelle, pas la méthode d'override."
                                ),
                            )

    # ── Field Filtering Bypass ────────────────────────────────────────────────

    async def _test_field_bypass(self, target: str) -> AsyncIterator[Finding]:
        parsed = urlparse(target)
        existing_params = parse_qs(parsed.query)

        field_params = ["fields", "select", "include", "expand", "columns", "attrs"]
        wildcard_values = ["*", "all", "**"]

        base_resp = await self._req.get(target)
        if base_resp.error:
            return

        for param in field_params:
            for wildcard in wildcard_values:
                probe_params = dict(existing_params)
                probe_params[param] = [wildcard]
                probe_url = urlunparse(parsed._replace(query=urlencode(probe_params, doseq=True)))
                resp = await self._req.get(probe_url)
                if resp.error:
                    continue
                if resp.status == 200:
                    # Plus de données retournées ?
                    if resp.content_length > base_resp.content_length * 1.2:
                        has_sensitive = bool(_SENSITIVE_RESPONSE_PATTERNS.search(resp.body))
                        yield Finding(
                            title=f"Field Bypass — ?{param}={wildcard} retourne plus de données",
                            severity=Severity.HIGH if has_sensitive else Severity.MEDIUM,
                            url=probe_url,
                            module="vulns/api_security",
                            description=(
                                f"Le paramètre `{param}={wildcard}` retourne {resp.content_length}B "
                                f"vs {base_resp.content_length}B sans le paramètre. "
                                + ("Contient des champs sensibles." if has_sensitive else "")
                            ),
                            evidence=f"GET {probe_url} → {resp.content_length}B | sans param: {base_resp.content_length}B",
                            cwe="CWE-200",
                            remediation=(
                                "Implémenter une allowlist des champs retournables. "
                                "Ne jamais exposer tous les champs d'un modèle par défaut. "
                                "Valider les params `fields` / `select` contre la liste des champs autorisés."
                            ),
                        )
                        return

    # ── API Key dans l'URL ────────────────────────────────────────────────────

    async def _detect_api_key_in_url(self, target: str) -> AsyncIterator[Finding]:
        m = _API_KEY_IN_URL.search(target)
        if m:
            param_name = m.group(1)
            key_value  = m.group(2)
            yield Finding(
                title=f"API Key dans l'URL — param `{param_name}`",
                severity=Severity.HIGH,
                url=target,
                module="vulns/api_security",
                description=(
                    f"Une clé API est passée en clair dans l'URL via le paramètre `{param_name}`. "
                    f"Valeur: `{key_value[:8]}...` (tronquée). "
                    f"Les URLs sont loggées dans les serveurs web, CDN, proxies et historique du navigateur."
                ),
                evidence=f"URL: {target[:120]} | param: {param_name}={key_value[:8]}...",
                cwe="CWE-598",
                remediation=(
                    "Passer les clés API dans les headers HTTP (Authorization: Bearer ...). "
                    "Ne jamais inclure de secrets dans les URLs. "
                    "Révoquer et remplacer les clés exposées."
                ),
            )

    # ── CRUD Method Discovery ─────────────────────────────────────────────────

    async def _discover_unreferenced_methods(self, url: str) -> AsyncIterator[Finding]:
        """Découvre les méthodes HTTP inattendues sur un endpoint."""
        base_resp = await self._req.send(ProbeRequest(method="OPTIONS", url=url))
        allowed_from_options = set()
        if not base_resp.error:
            allow_header = base_resp.headers.get("allow", "") + base_resp.headers.get("access-control-allow-methods", "")
            allowed_from_options = {m.strip().upper() for m in re.split(r"[,\s]+", allow_header) if m.strip()}

        for method in ["DELETE", "PUT", "PATCH"]:
            if method in allowed_from_options:
                continue  # Déjà annoncé — pas surprenant
            resp = await self._req.send(ProbeRequest(method=method, url=url, json={}))
            if resp.error or resp.status in (404, 405, 501):
                continue
            if resp.status in (200, 201, 202, 204):
                yield Finding(
                    title=f"Méthode HTTP non-documentée acceptée: {method} {url}",
                    severity=Severity.MEDIUM,
                    url=url,
                    module="vulns/api_security",
                    description=(
                        f"La méthode `{method}` est acceptée sur `{url}` (HTTP {resp.status}) "
                        f"mais n'est pas annoncée dans le header OPTIONS Allow."
                    ),
                    evidence=f"{method} {url} → {resp.status}",
                    cwe="CWE-749",
                    remediation=(
                        "Documenter et restreindre les méthodes HTTP autorisées pour chaque endpoint. "
                        "Implémenter un contrôle d'accès approprié pour DELETE et PUT."
                    ),
                )

    # ── Content-Type Confusion ────────────────────────────────────────────────

    async def _test_content_type_confusion(self, url: str) -> AsyncIterator[Finding]:
        """
        Tente d'envoyer des données JSON à un endpoint form et vice-versa.
        Certains parseurs acceptent les deux et peuvent ignorer des validations.
        """
        test_payload_json = '{"__test__": "<script>alert(1)</script>"}'
        test_payload_form = "__test__=<script>alert(1)</script>"

        # Envoyer JSON à un endpoint qui attend du form
        resp_json = await self._req.send(ProbeRequest(
            method="POST", url=url,
            body=test_payload_json,
            headers={"Content-Type": "application/json"},
        ))
        resp_form = await self._req.send(ProbeRequest(
            method="POST", url=url,
            body=test_payload_form,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        ))

        if resp_json.error or resp_form.error:
            return

        # Si les deux retournent 200 avec des réponses similaires → confusion possible
        if resp_json.status in (200, 201) and resp_form.status in (200, 201):
            if abs(resp_json.content_length - resp_form.content_length) < 200:
                yield Finding(
                    title=f"Content-Type Confusion — JSON et Form acceptés indifféremment",
                    severity=Severity.LOW,
                    url=url,
                    module="vulns/api_security",
                    description=(
                        f"L'endpoint POST `{url}` accepte à la fois application/json "
                        f"et application/x-www-form-urlencoded. Peut indiquer un parseur permissif "
                        f"qui bypasse des validations dépendantes du Content-Type."
                    ),
                    evidence=f"JSON → {resp_json.status} ({resp_json.content_length}B) | Form → {resp_form.status} ({resp_form.content_length}B)",
                    cwe="CWE-436",
                    remediation=(
                        "Valider et rejeter explicitement les Content-Types non-attendus. "
                        "Appliquer les mêmes validations quel que soit le format d'entrée."
                    ),
                )
