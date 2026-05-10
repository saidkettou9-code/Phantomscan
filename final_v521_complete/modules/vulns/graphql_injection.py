"""
PhantomScan — GraphQL Injection Scanner
Détection des vulnérabilités GraphQL :
  - Introspection non protégée (information disclosure)
  - Injection dans les arguments de requête (SQLi/CMDi via GraphQL)
  - Batching abuse (DoS / auth bypass)
  - Field suggestion disclosure
  - Denial of Service via deep nesting
"""

from __future__ import annotations

import json
import re
from typing import AsyncIterator
from urllib.parse import urlparse

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester, ProbeRequest
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity
from phantomscan.core.scanner_mixin import ScannerMixin


# ── Endpoints GraphQL communs ─────────────────────────────────────────────────

_GQL_ENDPOINTS: list[str] = [
    "/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql",
    "/gql", "/query", "/api/query", "/graphiql", "/playground",
    "/api", "/api/v1", "/api/v2",
]

# ── Introspection query ───────────────────────────────────────────────────────

_INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields { name }
    }
  }
}
""".strip()

_INTROSPECTION_RE = re.compile(r'"__schema"\s*:\s*\{', re.I)
_TYPENAME_RE      = re.compile(r'"__typename"\s*:', re.I)
_SUGGESTION_RE    = re.compile(r'Did you mean|suggestions?.*"[a-zA-Z]', re.I)
_GQL_ERROR_RE     = re.compile(r'"errors"\s*:\s*\[', re.I)

# ── Payloads d'injection dans arguments ───────────────────────────────────────

_INJECTION_PAYLOADS: list[tuple[str, str, re.Pattern]] = [
    # SQLi
    ("' OR '1'='1",         "SQLi single quote",   re.compile(r"syntax error|sql|mysql|sqlite|postgres|ora-\d+", re.I)),
    ("1; DROP TABLE",       "SQLi DROP TABLE",      re.compile(r"syntax error|sql|table.*drop", re.I)),
    ("\"; DROP TABLE--",    "SQLi double quote",    re.compile(r"syntax error|sql", re.I)),
    # CMDi
    (";id",                 "CMDi semicolon id",    re.compile(r"uid=\d+\(")),
    ("`id`",                "CMDi backtick id",     re.compile(r"uid=\d+\(")),
    # XSS dans réponse JSON
    ("<script>alert(1)</script>", "XSS in GQL arg", re.compile(r"<script>alert", re.I)),
    # SSTI
    ("{{7*7}}",             "SSTI {{7*7}}",         re.compile(r"\b49\b")),
    ("${7*7}",              "SSTI ${7*7}",           re.compile(r"\b49\b")),
]

# ── Requêtes de fuzzing argument ──────────────────────────────────────────────

_COMMON_QUERIES_TEMPLATE = [
    'query {{ node(id: "{payload}") {{ id }} }}',
    'query {{ user(id: "{payload}") {{ id name email }} }}',
    'query {{ search(query: "{payload}") {{ id }} }}',
    '{{ users(filter: "{payload}") {{ id }} }}',
    '{{ login(username: "{payload}", password: "pass") {{ token }} }}',
]

# ── DoS via nesting profond ───────────────────────────────────────────────────

def _make_deep_query(depth: int = 15) -> str:
    """Génère une requête imbriquée récursivement pour tester les limites de profondeur."""
    inner = "{ __typename }"
    for _ in range(depth):
        inner = f"friends {inner}"
    return f"query {{ user(id: \"1\") {{ {inner} }} }}"

# ── Batch abuse ───────────────────────────────────────────────────────────────

_BATCH_QUERY = json.dumps([
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": '{ user(id: "1") { id } }'},
    {"query": '{ users { id email } }'},
])


class GraphQLInjectionScanner(ScannerMixin):
    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req   = req
        self._heur  = heuristic
        self._cfg   = cfg
        self._found: set[str] = set()
        self._gql_endpoints: list[str] = []

    async def run(self, target: str) -> AsyncIterator[Finding]:
        parsed = urlparse(target)
        base   = f"{parsed.scheme}://{parsed.netloc}"

        # Phase 1 : découverte des endpoints GraphQL
        await self._discover_endpoints(base)

        if not self._gql_endpoints:
            return

        for endpoint in self._gql_endpoints:
            # Phase 2 : introspection
            async for f in self._check_introspection(endpoint):
                yield f

            # Phase 3 : field suggestion disclosure
            async for f in self._check_field_suggestions(endpoint):
                yield f

            # Phase 4 : injection dans arguments
            async for f in self._check_injection(endpoint):
                yield f

            # Phase 5 : batch abuse
            async for f in self._check_batch(endpoint):
                yield f

            # Phase 6 : DoS depth
            async for f in self._check_depth_dos(endpoint):
                yield f

            # Phase 7 : v5.20 — BOLA / IDOR via ID enumeration
            async for f in self._check_bola(endpoint):
                yield f

    # ── Découverte d'endpoint ─────────────────────────────────────────────────

    async def _discover_endpoints(self, base: str) -> None:
        probe = json.dumps({"query": "{ __typename }"})
        for path in _GQL_ENDPOINTS:
            url = base + path
            resp = await self._req.send(ProbeRequest(
                method="POST", url=url,
                headers={"Content-Type": "application/json"},
                body=probe,
            ))
            if resp.error:
                continue
            body = resp.body or ""
            # Un endpoint GQL répond avec {"data":...} ou {"errors":...}
            if ('"data"' in body or _GQL_ERROR_RE.search(body)) and resp.status != 404:
                self._gql_endpoints.append(url)

    # ── Introspection ─────────────────────────────────────────────────────────

    async def _check_introspection(self, endpoint: str) -> AsyncIterator[Finding]:
        resp = await self._req.send(ProbeRequest(
            method="POST", url=endpoint,
            headers={"Content-Type": "application/json"},
            body=json.dumps({"query": _INTROSPECTION_QUERY}),
        ))
        if resp.error or not resp.body:
            return

        if _INTROSPECTION_RE.search(resp.body):
            key = f"gql_intro:{endpoint}"
            if key not in self._found:
                self._found.add(key)
                # Tenter d'extraire les types exposés
                try:
                    data  = json.loads(resp.body)
                    types = [t["name"] for t in data.get("data", {}).get("__schema", {}).get("types", [])
                             if not t["name"].startswith("__")][:10]
                    evidence_extra = f" Types exposés: {', '.join(types)}"
                except Exception:
                    evidence_extra = ""
                yield self._make_finding(
                    title="GraphQL — Introspection activée (information disclosure)",
                    severity=Severity.MEDIUM,
                    url=endpoint,
                    payload=_INTROSPECTION_QUERY[:80],
                    technique="Introspection query",
                    desc="Schéma GraphQL complet accessible sans authentification." + evidence_extra,
                    status=resp.status,
                )

    # ── Field suggestion disclosure ───────────────────────────────────────────

    async def _check_field_suggestions(self, endpoint: str) -> AsyncIterator[Finding]:
        probe = json.dumps({"query": "{ usre { id } }"})  # typo volontaire
        resp = await self._req.send(ProbeRequest(
            method="POST", url=endpoint,
            headers={"Content-Type": "application/json"},
            body=probe,
        ))
        if resp.error or not resp.body:
            return

        if _SUGGESTION_RE.search(resp.body):
            key = f"gql_suggest:{endpoint}"
            if key not in self._found:
                self._found.add(key)
                yield self._make_finding(
                    title="GraphQL — Field suggestion disclosure",
                    severity=Severity.LOW,
                    url=endpoint,
                    payload='{ usre { id } }',
                    technique="Typo → suggestion",
                    desc="Le serveur révèle les noms de champs via les messages de suggestion d'erreur.",
                    status=resp.status,
                )

    # ── Injection dans arguments ──────────────────────────────────────────────

    async def _check_injection(self, endpoint: str) -> AsyncIterator[Finding]:
        # v5.20 — Baseline : requête neutre pour éviter les FP sur messages d'erreur
        # déjà présents dans les réponses GraphQL normales
        baseline_body = ""
        base_resp = await self._req.send(ProbeRequest(
            method="POST", url=endpoint,
            headers={"Content-Type": "application/json"},
            body=json.dumps({"query": "{ __typename }"}),
        ))
        if not base_resp.error:
            baseline_body = base_resp.body or ""

        for query_tpl in _COMMON_QUERIES_TEMPLATE:
            for inj_payload, inj_desc, sig_re in _INJECTION_PAYLOADS:
                query = query_tpl.format(payload=inj_payload)
                resp = await self._req.send(ProbeRequest(
                    method="POST", url=endpoint,
                    headers={"Content-Type": "application/json"},
                    body=json.dumps({"query": query}),
                ))
                if resp.error or not resp.body:
                    continue

                body = resp.body
                # v5.20 — FP guard : signature déjà dans baseline → skip
                if sig_re.search(baseline_body):
                    continue
                # v5.20 — FP guard : entropie de la signature
                match = sig_re.search(body)
                if not match:
                    continue
                if not self.sig_entropy_ok(match.group(0), body, min_entropy=1.8):
                    continue

                if True:  # toujours entrer (remplace le if sig_re.search(body))
                    key = f"gql_inj:{endpoint}:{inj_desc}"
                    if key not in self._found:
                        self._found.add(key)
                        yield self._make_finding(
                            title=f"GraphQL — Injection · {inj_desc}",
                            severity=Severity.CRITICAL,
                            url=endpoint,
                            payload=query[:120],
                            technique=f"Argument injection ({inj_desc})",
                            desc=f"Injection détectée dans un argument GraphQL: {inj_desc}",
                            status=resp.status,
                        )
                    break

    # ── Batch abuse ───────────────────────────────────────────────────────────

    async def _check_batch(self, endpoint: str) -> AsyncIterator[Finding]:
        resp = await self._req.send(ProbeRequest(
            method="POST", url=endpoint,
            headers={"Content-Type": "application/json"},
            body=_BATCH_QUERY,
        ))
        if resp.error or not resp.body:
            return

        # Si le serveur répond à un tableau de queries → batching activé
        body = resp.body.strip()
        if body.startswith("[") and '"data"' in body:
            key = f"gql_batch:{endpoint}"
            if key not in self._found:
                self._found.add(key)
                yield self._make_finding(
                    title="GraphQL — Batching activé (abus possible)",
                    severity=Severity.MEDIUM,
                    url=endpoint,
                    payload="[...] (5 queries batchées)",
                    technique="Query batching",
                    desc="Le batching GraphQL permet de contourner le rate-limiting et amplifier les attaques bruteforce.",
                    status=resp.status,
                )

    # ── Depth DoS ─────────────────────────────────────────────────────────────

    async def _check_depth_dos(self, endpoint: str) -> AsyncIterator[Finding]:
        query = _make_deep_query(depth=15)
        resp = await self._req.send(ProbeRequest(
            method="POST", url=endpoint,
            headers={"Content-Type": "application/json"},
            body=json.dumps({"query": query}),
        ))
        if resp.error:
            return

        # Serveur vulnérable = répond 200 à une requête de profondeur 15
        # sans message d'erreur de limite de profondeur
        if resp.status == 200 and not re.search(r"depth|complexity|limit|max", resp.body or "", re.I):
            key = f"gql_depth:{endpoint}"
            if key not in self._found:
                self._found.add(key)
                yield self._make_finding(
                    title="GraphQL — Pas de limite de profondeur (DoS possible)",
                    severity=Severity.MEDIUM,
                    url=endpoint,
                    payload=query[:80] + "...",
                    technique="Deep nesting query (depth=15)",
                    desc="Aucune limite de profondeur de requête n'est appliquée. Un attaquant peut déclencher un DoS par requêtes imbriquées.",
                    status=resp.status,
                )

    # ── Factory ───────────────────────────────────────────────────────────────

    @staticmethod

    # ── BOLA / IDOR via énumération d'IDs ────────────────────────────────────

    async def _check_bola(self, endpoint: str) -> AsyncIterator[Finding]:
        """
        v5.20 — Teste le BOLA (IDOR) via énumération d'IDs dans les requêtes GraphQL.
        Envoie user(id:1), user(id:2), user(id:3) et vérifie si des données
        d'autres utilisateurs sont accessibles sans restriction d'accès.
        """
        id_queries = [
            ('{ user(id: "1") { id email name role } }', "user_1"),
            ('{ user(id: "2") { id email name role } }', "user_2"),
            ('{ users(limit: 100) { id email name } }',  "users_list"),
            ('{ me { id } }',                            "me_baseline"),
        ]
        responses: dict[str, str] = {}
        for query, label in id_queries:
            resp = await self._req.send(ProbeRequest(
                method="POST", url=endpoint,
                headers={"Content-Type": "application/json"},
                body=json.dumps({"query": query}),
            ))
            if not resp.error and resp.body:
                responses[label] = resp.body

        # Si users_list retourne plusieurs emails → data leak
        if "users_list" in responses:
            try:
                data = json.loads(responses["users_list"])
                users = (data.get("data") or {}).get("users", []) or []
                if len(users) >= 2:
                    emails = [u.get("email", "") for u in users[:3] if u.get("email")]
                    key = f"gql_bola:{endpoint}"
                    if key not in self._found:
                        self._found.add(key)
                        yield self._make_finding(
                            title="GraphQL — BOLA: users list accessible sans restriction",
                            severity=Severity.HIGH,
                            url=endpoint,
                            payload='{ users(limit: 100) { id email name } }',
                            technique="Users enumeration via GraphQL",
                            desc=(
                                f"{len(users)} utilisateurs retournés sans contrôle d'accès. "
                                f"Emails exposés : {', '.join(emails[:3])}"
                            ),
                            status=200,
                        )
            except Exception:
                pass

        # Si user(id:1) et user(id:2) retournent des données différentes → potentiel IDOR
        if "user_1" in responses and "user_2" in responses:
            diff = self.stable_diff(responses["user_1"], responses["user_2"])
            if 0.10 < diff < 0.90:  # Différents mais pas des erreurs
                try:
                    d1 = json.loads(responses["user_1"])
                    d2 = json.loads(responses["user_2"])
                    u1 = (d1.get("data") or {}).get("user")
                    u2 = (d2.get("data") or {}).get("user")
                    if u1 and u2:
                        key = f"gql_idor:{endpoint}"
                        if key not in self._found:
                            self._found.add(key)
                            yield self._make_finding(
                                title="GraphQL — IDOR: ressources d'autres utilisateurs accessibles",
                                severity=Severity.HIGH,
                                url=endpoint,
                                payload='{ user(id: "N") { id email name role } }',
                                technique="ID enumeration via GraphQL args",
                                desc=(
                                    "Les ressources de différents utilisateurs sont accessibles "
                                    "en changeant le paramètre id. Aucun contrôle d'autorisation détecté."
                                ),
                                status=200,
                            )
                except Exception:
                    pass

    def _make_finding(title, severity, url, payload, technique, desc, status) -> Finding:
        return Finding(
            title=title,
            severity=severity,
            url=url,
            module="vulns/graphql_injection",
            description=desc,
            evidence=f"Payload: {payload[:120]} | Technique: {technique} | HTTP {status}",
            cwe="CWE-89" if "SQL" in technique else "CWE-200",
            remediation=(
                "Désactiver l'introspection en production. "
                "Implémenter une limite de profondeur et de complexité de requête. "
                "Désactiver ou limiter strictement le batching. "
                "Utiliser des requêtes préparées ou des resolvers paramétrés. "
                "Valider et sanitiser tous les arguments. "
                "Appliquer une authentification sur tous les resolvers sensibles."
            ),
        )
