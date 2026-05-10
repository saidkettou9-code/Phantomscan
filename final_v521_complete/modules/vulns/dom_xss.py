"""
PhantomScan — DOM XSS Analyzer  (v5.7)
=======================================
Détection du XSS basé sur le DOM — invisible aux scanners classiques qui ne
testent que le XSS réfléchi côté serveur.

Approche : analyse statique des fichiers JS crawlés pour tracer les flux
source → sink potentiellement exploitables, sans envoyer de payload.

Sources DOM connues (points d'entrée contrôlables par l'attaquant) :
  document.URL, document.location, location.href/search/hash/pathname,
  document.referrer, window.name, document.cookie, postMessage data,
  URLSearchParams, location.ancestorOrigins

Sinks dangereux (exécution de code ou injection HTML) :
  innerHTML, outerHTML, insertAdjacentHTML, document.write/writeln,
  eval(), Function(), setTimeout(str), setInterval(str),
  location.href = ..., location.replace(), location.assign(),
  src = ..., href = ..., action = ...,
  $.html(), $.append(), React.dangerouslySetInnerHTML

Scoring :
  - Source + Sink dans la même fonction/bloc → HIGH
  - Source + Sink avec passage par une variable intermédiaire → MEDIUM
  - Sink sans source traçable mais avec input non sanitisé → LOW

Limitations connues :
  - Analyse statique uniquement, pas d'exécution JS
  - Pas de taint-tracking inter-fichiers (limité au scope d'un fichier)
  - Obfuscation avancée (eval(atob(...))) → non détectée
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import AsyncIterator
from urllib.parse import urljoin, urlparse

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity
from phantomscan.core.scanner_mixin import ScannerMixin


# ─────────────────────────── Définitions source/sink ────────────────────────

# Sources : patterns qui capturent une valeur contrôlable par l'utilisateur
_SOURCES: list[tuple[str, re.Pattern, str]] = [
    ("location.href",       re.compile(r'\blocation\.href\b'),                      "URL complète"),
    ("location.search",     re.compile(r'\blocation\.search\b'),                    "query string"),
    ("location.hash",       re.compile(r'\blocation\.hash\b'),                      "fragment URL"),
    ("location.pathname",   re.compile(r'\blocation\.pathname\b'),                  "chemin URL"),
    ("document.URL",        re.compile(r'\bdocument\.URL\b'),                       "URL document"),
    ("document.location",   re.compile(r'\bdocument\.location\b'),                  "location document"),
    ("document.referrer",   re.compile(r'\bdocument\.referrer\b'),                  "Referrer header"),
    ("window.name",         re.compile(r'\bwindow\.name\b'),                        "window.name"),
    ("document.cookie",     re.compile(r'\bdocument\.cookie\b'),                    "cookies"),
    ("URLSearchParams",     re.compile(r'\bnew URLSearchParams\b'),                 "URLSearchParams"),
    ("postMessage",         re.compile(r'\bmessage\b.*\bdata\b|\bevent\.data\b'),   "postMessage data"),
    ("localStorage",        re.compile(r'\blocalStorage\.getItem\b'),               "localStorage"),
    ("sessionStorage",      re.compile(r'\bsessionStorage\.getItem\b'),             "sessionStorage"),
    ("getParameter",        re.compile(r'\.get\(["\'][^"\']+["\']\)'),              "URL param .get()"),
]

# Sinks dangereux : exécution ou injection de code/HTML
_SINKS: list[tuple[str, re.Pattern, str, Severity]] = [
    ("innerHTML",             re.compile(r'\.innerHTML\s*='),                Severity.HIGH,     "injection HTML directe"),
    ("outerHTML",             re.compile(r'\.outerHTML\s*='),                Severity.HIGH,     "remplacement nœud DOM"),
    ("insertAdjacentHTML",    re.compile(r'\.insertAdjacentHTML\s*\('),      Severity.HIGH,     "insertion HTML adjacente"),
    ("document.write",        re.compile(r'document\.write\s*\('),           Severity.HIGH,     "écriture dans le document"),
    ("document.writeln",      re.compile(r'document\.writeln\s*\('),         Severity.HIGH,     "écriture dans le document"),
    ("eval",                  re.compile(r'\beval\s*\('),                    Severity.CRITICAL, "exécution de code JS"),
    ("Function constructor",  re.compile(r'\bnew Function\s*\('),            Severity.CRITICAL, "construction de fonction"),
    ("setTimeout (string)",   re.compile(r'\bsetTimeout\s*\(\s*["\']'),      Severity.HIGH,     "exécution différée (string)"),
    ("setInterval (string)",  re.compile(r'\bsetInterval\s*\(\s*["\']'),     Severity.HIGH,     "exécution répétée (string)"),
    ("location.href =",       re.compile(r'\blocation\.href\s*=\s*(?!["\']/(?!/))'), Severity.MEDIUM, "redirection ouverte"),
    ("location.replace",      re.compile(r'\blocation\.replace\s*\('),       Severity.MEDIUM,   "redirection replace"),
    ("location.assign",       re.compile(r'\blocation\.assign\s*\('),        Severity.MEDIUM,   "redirection assign"),
    ("src =",                 re.compile(r'\.\bsrc\s*=\s*(?!["\']/|["\']https?://)'), Severity.MEDIUM, "attribut src dynamique"),
    ("jQuery html()",         re.compile(r'\$\([^)]+\)\.html\s*\('),        Severity.HIGH,     "jQuery .html() injection"),
    ("jQuery append()",       re.compile(r'\$\([^)]+\)\.append\s*\('),      Severity.MEDIUM,   "jQuery .append()"),
    ("dangerouslySetInnerHTML", re.compile(r'dangerouslySetInnerHTML'),      Severity.HIGH,     "React innerHTML bypass"),
    ("execScript",            re.compile(r'\bexecScript\s*\('),              Severity.CRITICAL, "IE execScript"),
    ("importScripts",         re.compile(r'\bimportScripts\s*\('),           Severity.HIGH,     "importScripts Worker"),
]

# Fonctions de sanitisation qui cassent le flux source→sink
_SANITIZERS = re.compile(
    r'\b(?:encodeURIComponent|encodeURI|escape|DOMPurify\.sanitize|'
    r'sanitize|htmlspecialchars|htmlentities|textContent\s*=|'
    r'createTextNode|innerText\s*=)\b',
    re.I,
)

# Extensions JS à analyser
_JS_EXTENSIONS = (".js", ".mjs", ".jsx", ".ts", ".tsx", ".vue")


# ─────────────────────────── Data structures ────────────────────────────────

@dataclass
class DomFlow:
    """Représente un flux source → sink détecté dans un fichier JS."""
    source_name: str
    source_desc: str
    sink_name: str
    sink_desc: str
    sink_severity: Severity
    line_source: int
    line_sink: int
    snippet_source: str
    snippet_sink: str
    sanitized: bool = False
    confidence: float = 0.0   # 0.0–1.0


# ─────────────────────────── Analyzer ───────────────────────────────────────

class DOMXSSAnalyzer(ScannerMixin):
    """
    Analyse statique source→sink sur les fichiers JS crawlés.

    Usage :
        scanner = DOMXSSAnalyzer(req, heuristic, cfg)
        async for finding in scanner.run(target):
            yield finding
    """

    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req = req
        self._heur = heuristic
        self._cfg = cfg
        self._bus = None  # EndpointBus injecté par l'engine si disponible

    def set_endpoint_bus(self, bus) -> None:
        self._bus = bus

    async def run(self, target: str) -> AsyncIterator[Finding]:
        """Collecte les URLs JS depuis le crawler/bus, analyse chacune."""
        js_urls = await self._discover_js_urls(target)
        seen_js: set[str] = set()

        for js_url in js_urls:
            if js_url in seen_js:
                continue
            seen_js.add(js_url)

            resp = await self._req.get(js_url)
            if resp.error or resp.status not in (200,):
                continue

            js_source = resp.body
            if not js_source.strip():
                continue

            flows = self._trace_flows(js_source)
            for flow in flows:
                if flow.sanitized:
                    continue
                async for f in self._flow_to_finding(flow, js_url):
                    yield f

    async def _discover_js_urls(self, target: str) -> list[str]:
        """
        Collecte toutes les URLs JS à analyser depuis :
        1. Le bus d'endpoints (findings du crawler/js_analyzer)
        2. La page cible elle-même (balises <script src=...>)
        """
        js_urls: list[str] = []
        seen: set[str] = set()

        def _add(url: str) -> None:
            canon = url.split("?")[0].split("#")[0]
            if canon not in seen and any(canon.endswith(ext) for ext in _JS_EXTENSIONS):
                seen.add(canon)
                js_urls.append(url)

        # Depuis le bus (findings js_analyzer et crawler qui logguent les <script src>)
        if self._bus is not None:
            for ep in self._bus.snapshot:
                if ep.source in ("crawler/api", "js_analyzer") or any(
                    ep.url.endswith(ext) for ext in _JS_EXTENSIONS
                ):
                    _add(ep.url)

        # Scraping direct de la page cible pour <script src>
        try:
            resp = await self._req.get(target)
            if not resp.error:
                for m in re.finditer(
                    r'<script[^>]+\bsrc=["\']([^"\']+)["\']', resp.body, re.I
                ):
                    raw = m.group(1)
                    full = urljoin(target, raw)
                    # Limiter au même origin
                    if urlparse(full).netloc == urlparse(target).netloc:
                        _add(full)
        except Exception:
            pass

        return js_urls

    def _trace_flows(self, js: str) -> list[DomFlow]:
        """
        Découpe le JS en blocs logiques (fonctions/closures) et recherche
        des co-occurrences source+sink dans chaque bloc.

        Stratégie :
          1. Chercher toutes les occurrences de sources avec leur numéro de ligne
          2. Chercher tous les sinks
          3. Pour chaque paire (source, sink) dans une fenêtre de 30 lignes,
             vérifier s'il y a un sanitiseur entre les deux
        """
        lines = js.splitlines()
        flows: list[DomFlow] = []

        # Index source occurrences : {(source_name, line_no) → snippet}
        source_hits: list[tuple[str, str, int, str]] = []  # (name, desc, lineno, snippet)
        for name, pat, desc in _SOURCES:
            for i, line in enumerate(lines):
                if pat.search(line):
                    source_hits.append((name, desc, i + 1, line.strip()[:120]))

        if not source_hits:
            return flows

        # Index sink occurrences
        sink_hits: list[tuple[str, str, Severity, int, str]] = []
        for name, pat, severity, desc in _SINKS:
            for i, line in enumerate(lines):
                if pat.search(line):
                    sink_hits.append((name, desc, severity, i + 1, line.strip()[:120]))

        if not sink_hits:
            return flows

        # Fenêtre de 30 lignes pour corréler source→sink
        WINDOW = 30

        seen_pairs: set[tuple[str, str, int, int]] = set()

        for s_name, s_desc, s_line, s_snip in source_hits:
            for k_name, k_desc, k_sev, k_line, k_snip in sink_hits:
                distance = abs(k_line - s_line)
                if distance > WINDOW:
                    continue

                pair_key = (s_name, k_name, s_line, k_line)
                if pair_key in seen_pairs:
                    continue
                seen_pairs.add(pair_key)

                # Vérifier présence d'un sanitiseur entre source et sink
                start = min(s_line, k_line) - 1
                end = max(s_line, k_line)
                region = "\n".join(lines[start:end])
                sanitized = bool(_SANITIZERS.search(region))

                # Confiance : plus la distance est faible, plus c'est probable
                confidence = max(0.3, 1.0 - distance / WINDOW)
                if sanitized:
                    confidence *= 0.2  # forte pénalité si sanitiseur présent

                flows.append(DomFlow(
                    source_name=s_name,
                    source_desc=s_desc,
                    sink_name=k_name,
                    sink_desc=k_desc,
                    sink_severity=k_sev,
                    line_source=s_line,
                    line_sink=k_line,
                    snippet_source=s_snip,
                    snippet_sink=k_snip,
                    sanitized=sanitized,
                    confidence=confidence,
                ))

        # Dédoublonner : garder un seul flow par (source_name, sink_name) par fichier
        best: dict[tuple[str, str], DomFlow] = {}
        for f in flows:
            key = (f.source_name, f.sink_name)
            if key not in best or f.confidence > best[key].confidence:
                best[key] = f

        return list(best.values())

    async def _flow_to_finding(
        self, flow: DomFlow, js_url: str
    ) -> AsyncIterator[Finding]:
        """Convertit un DomFlow en Finding PhantomScan."""
        if flow.confidence < 0.25:
            return

        # Ajuster la sévérité selon la confiance
        severity = flow.sink_severity
        if flow.confidence < 0.5 and severity == Severity.HIGH:
            severity = Severity.MEDIUM
        elif flow.confidence < 0.4 and severity == Severity.CRITICAL:
            severity = Severity.HIGH

        title = f"DOM XSS — {flow.source_name} → {flow.sink_name}"
        if flow.sanitized:
            title += " (sanitiseur présent, à vérifier)"

        yield Finding(
            title=title,
            severity=severity,
            url=js_url,
            module="vulns/dom_xss",
            description=(
                f"Flux source→sink potentiellement exploitable détecté par analyse statique JS.\n\n"
                f"Source (ligne {flow.line_source}): `{flow.source_name}` — {flow.source_desc}\n"
                f"Sink   (ligne {flow.line_sink}): `{flow.sink_name}` — {flow.sink_desc}\n"
                f"Confiance: {flow.confidence:.0%}"
                + (f"\nSanitiseur détecté entre les deux — vérifier s'il est suffisant." if flow.sanitized else "")
            ),
            evidence=(
                f"Source  L{flow.line_source}: {flow.snippet_source}\n"
                f"Sink    L{flow.line_sink}:   {flow.snippet_sink}"
            ),
            cwe="CWE-79",
            remediation=(
                "Éviter d'assigner des valeurs issues de l'URL/DOM directement à innerHTML, eval(), etc. "
                "Utiliser textContent au lieu d'innerHTML. "
                "Appliquer DOMPurify.sanitize() avant toute injection HTML. "
                "Mettre en place une CSP stricte (script-src 'self' sans 'unsafe-eval')."
            ),
        )
