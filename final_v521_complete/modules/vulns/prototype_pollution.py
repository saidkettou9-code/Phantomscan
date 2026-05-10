"""
PhantomScan — Prototype Pollution Scanner
Détecte les vulnérabilités de pollution de prototype JavaScript côté serveur.

Techniques couvertes :
  - JSON body pollution via __proto__ / constructor.prototype
  - Query string pollution (?__proto__[x]=y)
  - Nested object pollution
  - Gadget-based detection (response différentielle sur propriétés ajoutées)
"""

from __future__ import annotations

import json
import re
from typing import AsyncIterator
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester, ProbeRequest
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity
from phantomscan.core.scanner_mixin import ScannerMixin


# ── Marqueur unique par run ───────────────────────────────────────────────────

import uuid as _uuid
_PP_MARKER = "ps" + _uuid.uuid4().hex[:8] + "pp"
_PP_VALUE  = f"polluted_{_PP_MARKER}"

# ── Vecteurs JSON body ────────────────────────────────────────────────────────

_JSON_PAYLOADS: list[tuple[dict, str]] = [
    # (__proto__ direct)
    ({"__proto__": {_PP_MARKER: _PP_VALUE}},                           "__proto__ direct"),
    ({"__proto__": {"constructor": {"prototype": {_PP_MARKER: _PP_VALUE}}}}, "__proto__.constructor.prototype"),
    # constructor.prototype
    ({"constructor": {"prototype": {_PP_MARKER: _PP_VALUE}}},          "constructor.prototype"),
    # Deep merge via Object.assign pattern
    ({"a": {"__proto__": {_PP_MARKER: _PP_VALUE}}},                    "nested __proto__"),
    # toString override (gadget populaire)
    ({"__proto__": {"toString": f"function(){{return '{_PP_VALUE}'}}"}},"__proto__.toString override"),
]

# ── Vecteurs Query String ─────────────────────────────────────────────────────

_QS_PAYLOADS: list[tuple[str, str]] = [
    (f"__proto__[{_PP_MARKER}]={_PP_VALUE}",        "QS __proto__[key]"),
    (f"constructor[prototype][{_PP_MARKER}]={_PP_VALUE}", "QS constructor.prototype[key]"),
    (f"__proto__.{_PP_MARKER}={_PP_VALUE}",          "QS __proto__.key dot notation"),
]

# ── Patterns de détection dans la réponse ────────────────────────────────────

_REFLECT_RE   = re.compile(re.escape(_PP_VALUE))
_GADGET_RES   = [
    # Express.js / Node.js gadgets courants
    re.compile(r"res\.json\(.*polluted|Object\.keys.*polluted", re.I),
    # Erreurs de sérialisation révélatrices
    re.compile(r"Cannot read propert.*__proto__|prototype.*polluted", re.I),
    # Réflexion directe de la valeur injectée dans JSON
    re.compile(re.escape(_PP_VALUE)),
]

# ── Endpoints JSON typiques ───────────────────────────────────────────────────

_JSON_ENDPOINTS: list[str] = [
    "/api", "/api/v1", "/api/v2", "/graphql", "/rest",
    "/user", "/users", "/profile", "/settings", "/config",
    "/login", "/auth", "/register", "/update", "/merge",
    "/data", "/submit", "/upload", "/search",
]


class PrototypePollutionScanner(ScannerMixin):
    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req   = req
        self._heur  = heuristic
        self._cfg   = cfg
        self._found: set[str] = set()

    async def run(self, target: str) -> AsyncIterator[Finding]:
        parsed = urlparse(target)
        base   = f"{parsed.scheme}://{parsed.netloc}"

        # 1. JSON body pollution sur l'URL cible + endpoints connus
        targets = [target] + [base + ep for ep in _JSON_ENDPOINTS]
        for url in targets:
            async for f in self._json_pollution(url):
                yield f

        # 2. Query string pollution sur l'URL cible
        async for f in self._qs_pollution(target, parsed):
            yield f

    # ── JSON body ─────────────────────────────────────────────────────────────

    async def _json_pollution(self, url: str) -> AsyncIterator[Finding]:
        # Baseline GET pour comparer
        base_resp = await self._req.get(url)
        base_body = base_resp.body or ""

        for payload_dict, desc in _JSON_PAYLOADS:
            # POST avec JSON pollué
            resp = await self._req.send(ProbeRequest(
                method="POST",
                url=url,
                headers={"Content-Type": "application/json"},
                json=payload_dict,
            ))
            if resp.error or not resp.body:
                continue

            # Ne reporter que sur des réponses JSON/API — pas du HTML
            resp_ct = resp.headers.get("Content-Type", "") if resp.headers else ""
            if "text/html" in resp_ct:
                continue

            body = resp.body

            # v5.21 — Vérification de réflexion directe : si _PP_VALUE apparaît
            # dans la réponse, le serveur a renvoyé la valeur polluée
            if _PP_VALUE in body and _PP_VALUE not in base_body:
                # re-probe pour confirmer
                resp2 = await self.re_probe(url, method="POST",
                    headers={"Content-Type": "application/json"},
                    body=None, delay_s=0.3)
                if resp2 and _PP_VALUE in (resp2.body or ""):
                    key = f"pp_reflect:{url}:{desc}"
                    if key not in self._found:
                        self._found.add(key)
                        yield self._make_finding(
                            title=f"Prototype Pollution — Value Reflected · {desc}",
                            severity=Severity.HIGH,
                            url=url,
                            payload=json.dumps(payload_dict),
                            technique="JSON body — value reflection (confirmed 2x)",
                            desc=f"Pollution value '{_PP_VALUE}' found in response",
                            status=resp.status,
                        )
                        break

            for sig_re in _GADGET_RES:
                if sig_re.search(body) and not sig_re.search(base_body):
                    key = f"pp_json:{url}:{desc}"
                    if key not in self._found:
                        self._found.add(key)
                        yield self._make_finding(
                            title=f"Prototype Pollution — JSON body · {desc}",
                            severity=Severity.HIGH,
                            url=url,
                            payload=json.dumps(payload_dict),
                            technique="JSON body pollution",
                            desc=desc,
                            status=resp.status,
                        )
                    break

            # MERGE via PATCH (pattern courant dans les APIs REST)
            resp_patch = await self._req.send(ProbeRequest(
                method="PATCH",
                url=url,
                headers={"Content-Type": "application/merge-patch+json"},
                json=payload_dict,
            ))
            if not resp_patch.error and resp_patch.body:
                patch_ct = resp_patch.headers.get("Content-Type", "") if resp_patch.headers else ""
                if "text/html" not in patch_ct:
                    for sig_re in _GADGET_RES:
                        if sig_re.search(resp_patch.body) and not sig_re.search(base_body):
                            key = f"pp_patch:{url}:{desc}"
                            if key not in self._found:
                                self._found.add(key)
                                yield self._make_finding(
                                    title=f"Prototype Pollution — PATCH merge · {desc}",
                                    severity=Severity.HIGH,
                                    url=url,
                                    payload=json.dumps(payload_dict),
                                    technique="PATCH merge-patch pollution",
                                    desc=desc,
                                    status=resp_patch.status,
                                )
                            break

    # ── Query String ─────────────────────────────────────────────────────────

    async def _qs_pollution(self, target: str, parsed) -> AsyncIterator[Finding]:
        base_resp = await self._req.get(target)
        base_body = base_resp.body or ""

        for qs_payload, desc in _QS_PAYLOADS:
            # Append le payload aux QS existants
            sep = "&" if parsed.query else "?"
            fuzz_url = target + sep + qs_payload

            resp = await self._req.get(fuzz_url)
            if resp.error or not resp.body:
                continue

            # FIX: vérifier Content-Type spécifiquement, pas toutes les valeurs de headers concaténées
            # L'ancienne version concaténait TOUTES les valeurs de headers, ce qui rendait
            # le check "text/html" pratiquement toujours vrai (Set-Cookie, Server, etc.)
            content_type = resp.headers.get("Content-Type", "") if resp.headers else ""
            if "text/html" in content_type:
                continue
            if _REFLECT_RE.search(resp.body) and not _REFLECT_RE.search(base_body):
                key = f"pp_qs:{target}:{desc}"
                if key not in self._found:
                    self._found.add(key)
                    yield self._make_finding(
                        title=f"Prototype Pollution — Query String · {desc}",
                        severity=Severity.HIGH,
                        url=fuzz_url,
                        payload=qs_payload,
                        technique="Query string pollution",
                        desc=desc,
                        status=resp.status,
                    )

    # ── Factory ───────────────────────────────────────────────────────────────

    @staticmethod
    def _make_finding(title, severity, url, payload, technique, desc, status) -> Finding:
        return Finding(
            title=title,
            severity=severity,
            url=url,
            module="vulns/prototype_pollution",
            description=(
                f"Pollution de prototype JavaScript détectée ({technique}). "
                f"Variante: {desc}. "
                "Un attaquant peut modifier Object.prototype et injecter des propriétés "
                "arbitraires héritées par tous les objets de l'application, pouvant "
                "mener à un bypass d'autorisation, RCE (via gadgets), ou DoS."
            ),
            evidence=f"Payload: {payload[:120]} | Technique: {technique} | HTTP {status}",
            cwe="CWE-1321",
            remediation=(
                "Utiliser Object.create(null) pour les objets de configuration. "
                "Valider et sanitiser les clés avant tout merge récursif. "
                "Utiliser des parsers JSON avec protection __proto__ (qs avec allowPrototypes=false). "
                "Appliquer Object.freeze(Object.prototype) en entrée d'application. "
                "Mettre à jour les librairies de merge (lodash >= 4.17.21, etc.)."
            ),
        )
