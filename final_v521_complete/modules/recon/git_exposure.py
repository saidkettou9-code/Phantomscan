"""
PhantomScan — Git Exposure Recon  v1.0
Détection et exploitation avancée de dépôts Git exposés.

Techniques couvertes :
  - Détection de /.git/ accessible (HEAD, config, COMMIT_EDITMSG)
  - Reconstruction partielle du repo via objets loose et pack files
  - Extraction des remotes (URLs SSH/HTTPS avec potentiels credentials)
  - Extraction des branches, tags et historique de commits
  - Détection de secrets dans les blobs reconstruits (clés, tokens, passwords)
  - Détection SVN, HG (Mercurial), Bazaar exposés

Limitations :
  - La reconstruction complète nécessite gitpython ou dulwich (optionnels).
    Si absents, on reste sur l'extraction HTTP des fichiers critiques.
  - Respecte le rate-limit du Requester (pas de flood sur les objets SHA).

Références :
  - https://www.bughunting.guide/a-guide-to-finding-hidden-objects-in-git/
  - https://github.com/internetwache/GitTools
"""

from __future__ import annotations

import hashlib
import re
from typing import AsyncIterator
from urllib.parse import urlparse, urljoin

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester, ProbeRequest
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity


# ──────────────────────── Fichiers Git critiques ──────────────────────────

_GIT_CRITICAL_FILES: list[tuple[str, str, Severity]] = [
    # (chemin, description, sévérité)
    ("/.git/HEAD",                  "Pointeur HEAD",                     Severity.HIGH),
    ("/.git/config",                "Configuration repo (remotes, user)", Severity.CRITICAL),
    ("/.git/COMMIT_EDITMSG",        "Dernier message de commit",          Severity.MEDIUM),
    ("/.git/description",           "Description du repo",                Severity.LOW),
    ("/.git/info/exclude",          "Patterns exclus locaux",             Severity.LOW),
    ("/.git/logs/HEAD",             "Journal des références HEAD",        Severity.HIGH),
    ("/.git/logs/refs/heads/main",  "Journal branche main",               Severity.HIGH),
    ("/.git/logs/refs/heads/master","Journal branche master",             Severity.HIGH),
    ("/.git/refs/heads/main",       "SHA branche main",                   Severity.HIGH),
    ("/.git/refs/heads/master",     "SHA branche master",                 Severity.HIGH),
    ("/.git/FETCH_HEAD",            "Dernier fetch",                      Severity.MEDIUM),
    ("/.git/index",                 "Index Git (binaire — staging area)", Severity.CRITICAL),
    ("/.git/packed-refs",           "Références packées",                 Severity.HIGH),
]

# VCS alternatifs
_OTHER_VCS_FILES: list[tuple[str, str, Severity]] = [
    ("/.svn/entries",               "SVN entries exposé",                 Severity.HIGH),
    ("/.svn/wc.db",                 "SVN sqlite exposé",                  Severity.CRITICAL),
    ("/.hg/",                       "Mercurial repo exposé",              Severity.HIGH),
    ("/.hg/store/00manifest.i",     "Mercurial manifest",                 Severity.HIGH),
    ("/.bzr/README",                "Bazaar repo exposé",                 Severity.MEDIUM),
]

# Patterns secrets dans les blobs reconstruits
_SECRET_PATTERNS: list[tuple[str, str, Severity]] = [
    (r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]?(\S{6,})",        "Password hardcodé",       Severity.CRITICAL),
    (r"(?i)(secret[_-]?key|secret)\s*[=:]\s*['\"]?([A-Za-z0-9/+]{16,})", "Secret key",      Severity.CRITICAL),
    (r"AKIA[0-9A-Z]{16}",                                           "AWS Access Key ID",       Severity.CRITICAL),
    (r"(?i)aws.{0,20}secret.{0,20}['\"]([A-Za-z0-9/+]{40})",       "AWS Secret Access Key",   Severity.CRITICAL),
    (r"ghp_[A-Za-z0-9]{36}",                                        "GitHub Personal Token",   Severity.CRITICAL),
    (r"xox[baprs]-[0-9A-Za-z\-]{10,48}",                           "Slack Token",             Severity.CRITICAL),
    (r"sk-[A-Za-z0-9]{32,}",                                        "OpenAI API Key",          Severity.CRITICAL),
    (r"-----BEGIN (RSA|EC|OPENSSH|DSA) PRIVATE KEY-----",           "Clé privée PEM",          Severity.CRITICAL),
    (r"(?i)database.{0,10}(url|host|password)\s*[=:]\s*\S+",        "DB credentials",          Severity.HIGH),
    (r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"]?([A-Za-z0-9\-_]{16,})", "API Key générique",  Severity.HIGH),
]

# Regex SHA-1 (40 hex chars)
_SHA_RE = re.compile(r"\b([0-9a-f]{40})\b")


class GitExposureScanner:
    """Détecte et exploite les dépôts Git/VCS exposés."""

    RPS = 5.0

    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req = req
        self._heuristic = heuristic
        self._cfg = cfg
        self._base: str = ""

    async def run(self, target: str) -> AsyncIterator[Finding]:
        parsed = urlparse(target)
        self._base = f"{parsed.scheme}://{parsed.netloc}"

        # Phase 1 : vérifier que /.git/ est accessible
        git_accessible = await self._check_git_root()
        if not git_accessible:
            # Tenter quand même les autres VCS
            async for f in self._check_other_vcs():
                yield f
            return

        # Phase 2 : finding principal
        yield Finding(
            title="Dépôt Git exposé publiquement",
            severity=Severity.CRITICAL,
            url=f"{self._base}/.git/",
            module="recon/git_exposure",
            description=(
                "Le répertoire `.git/` est accessible publiquement. "
                "Un attaquant peut reconstruire le code source complet, "
                "l'historique des commits et potentiellement extraire des secrets."
            ),
            evidence=f"GET {self._base}/.git/ → HTTP 200/403 avec listage ou fichiers accessibles",
            cwe="CWE-538",
            remediation=(
                "Bloquer l'accès à `/.git/` via la configuration du serveur web :\n"
                "  Nginx : `location ~ /\\.git { deny all; }`\n"
                "  Apache : `<DirectoryMatch \\.git> Deny from all </DirectoryMatch>`\n"
                "  Supprimer le répertoire .git des déploiements de production."
            ),
        )

        # Phase 3 : fichiers critiques
        async for f in self._fetch_critical_files():
            yield f

        # Phase 4 : extraction des SHAs depuis les refs et reconstruction partielle
        shas = await self._extract_shas_from_refs()
        async for f in self._probe_objects(shas[:10]):  # Limité à 10 objets
            yield f

        # Phase 5 : pack files
        async for f in self._check_pack_files():
            yield f

        # Phase 6 : autres VCS
        async for f in self._check_other_vcs():
            yield f

    # ──────────────────────── Phase 1 : détection ────────────────────────────

    async def _check_git_root(self) -> bool:
        """Vérifie que le dépôt Git est accessible."""
        head_url = f"{self._base}/.git/HEAD"
        resp = await self._req.get(head_url)
        if resp.error or resp.status != 200:
            return False
        # Le HEAD doit commencer par "ref:" ou être un SHA
        body = resp.body.strip()
        return body.startswith("ref:") or bool(re.match(r"[0-9a-f]{40}", body))

    # ──────────────────────── Phase 2 : fichiers critiques ───────────────────

    async def _fetch_critical_files(self) -> AsyncIterator[Finding]:
        for path, desc, severity in _GIT_CRITICAL_FILES:
            url = f"{self._base}{path}"
            resp = await self._req.get(url)
            if resp.error or resp.status != 200 or len(resp.body) < 5:
                continue

            body = resp.body[:2000]

            # Chercher des secrets dans config et logs
            secrets_found = []
            for pattern, label, sec_sev in _SECRET_PATTERNS:
                m = re.search(pattern, body)
                if m:
                    secrets_found.append((label, m.group(0)[:100], sec_sev))

            # Extraire les URLs de remote depuis config
            remote_urls = []
            if "config" in path:
                remote_urls = re.findall(r"url\s*=\s*(\S+)", body)
                for rurl in remote_urls:
                    # Remote avec credentials intégrés (http://user:pass@host)
                    if re.search(r"://[^@]+:[^@]+@", rurl):
                        yield Finding(
                            title="Credentials dans l'URL de remote Git",
                            severity=Severity.CRITICAL,
                            url=url,
                            module="recon/git_exposure",
                            description=f"L'URL de remote Git contient des credentials : `{rurl[:80]}`",
                            evidence=f"Remote URL: {rurl[:120]}",
                            cwe="CWE-312",
                            remediation="Utiliser SSH keys ou des credential helpers au lieu d'encoder les credentials dans l'URL.",
                        )

            if secrets_found:
                for sec_label, snippet, sec_sev in secrets_found:
                    yield Finding(
                        title=f"Secret dans Git — {sec_label} (`{path}`)",
                        severity=sec_sev,
                        url=url,
                        module="recon/git_exposure",
                        description=f"Pattern `{sec_label}` détecté dans `{path}` du dépôt Git exposé.",
                        evidence=f"Extrait (tronqué) : {snippet[:100]}",
                        cwe="CWE-312",
                        remediation="Révoquer immédiatement le secret détecté. Utiliser git-filter-repo pour le purger de l'historique.",
                    )
            else:
                yield Finding(
                    title=f"Fichier Git exposé — {desc}",
                    severity=severity,
                    url=url,
                    module="recon/git_exposure",
                    description=f"`{path}` est accessible publiquement ({desc}).",
                    evidence=f"Contenu (extrait) : {body[:300]}",
                    cwe="CWE-538",
                    remediation="Restreindre l'accès au répertoire `.git/` au niveau du serveur web.",
                )

    # ──────────────────────── Phase 3 : extraction SHAs ─────────────────────

    async def _extract_shas_from_refs(self) -> list[str]:
        """Collecte les SHAs depuis refs/heads/* et packed-refs."""
        shas: set[str] = set()

        for path in [
            "/.git/refs/heads/main",
            "/.git/refs/heads/master",
            "/.git/refs/heads/develop",
            "/.git/packed-refs",
            "/.git/logs/HEAD",
        ]:
            resp = await self._req.get(f"{self._base}{path}")
            if not resp.error and resp.status == 200:
                for sha in _SHA_RE.findall(resp.body):
                    shas.add(sha)

        return list(shas)

    # ──────────────────────── Phase 4 : objets loose ─────────────────────────

    async def _probe_objects(self, shas: list[str]) -> AsyncIterator[Finding]:
        """
        Tente de récupérer des objets Git loose (/.git/objects/XX/YYYYYY…).
        Décompression zlib nécessite Python stdlib — OK.
        """
        import zlib

        for sha in shas:
            obj_path = f"/.git/objects/{sha[:2]}/{sha[2:]}"
            url = f"{self._base}{obj_path}"
            resp = await self._req.send(ProbeRequest(
                method="GET", url=url,
                headers={"Accept": "application/octet-stream"},
            ))
            if resp.error or resp.status != 200:
                continue

            # Tenter la décompression zlib
            try:
                raw = resp.body.encode("latin-1")  # préserve les bytes bruts
                decompressed = zlib.decompress(raw).decode("utf-8", errors="replace")
            except Exception:
                decompressed = ""

            # Chercher des secrets dans le blob
            for pattern, label, severity in _SECRET_PATTERNS:
                m = re.search(pattern, decompressed)
                if m:
                    yield Finding(
                        title=f"Secret dans objet Git — {label} (SHA {sha[:8]}…)",
                        severity=severity,
                        url=url,
                        module="recon/git_exposure",
                        description=(
                            f"L'objet Git `{sha[:8]}` contient un secret de type `{label}`.\n"
                            "Le code source (potentiellement historique) contient des credentials."
                        ),
                        evidence=f"Match : {m.group(0)[:100]}",
                        cwe="CWE-312",
                        remediation="Révoquer le secret et supprimer l'objet de l'historique avec git-filter-repo.",
                    )
                    break

    # ──────────────────────── Phase 5 : pack files ───────────────────────────

    async def _check_pack_files(self) -> AsyncIterator[Finding]:
        """Détecte les pack files accessibles (/.git/objects/pack/)."""
        pack_idx_url = f"{self._base}/.git/objects/info/packs"
        resp = await self._req.get(pack_idx_url)
        if resp.error or resp.status != 200:
            return

        # Parser la liste des packs
        pack_names = re.findall(r"P\s+(pack-[0-9a-f]+\.pack)", resp.body)
        for pack_name in pack_names[:3]:  # Limite à 3 pack files
            pack_url = f"{self._base}/.git/objects/pack/{pack_name}"
            # Vérifier que le pack est téléchargeable
            head_resp = await self._req.send(ProbeRequest(method="HEAD", url=pack_url))
            if not head_resp.error and head_resp.status == 200:
                size = head_resp.headers.get("content-length", "?")
                yield Finding(
                    title=f"Pack file Git accessible — {pack_name}",
                    severity=Severity.CRITICAL,
                    url=pack_url,
                    module="recon/git_exposure",
                    description=(
                        f"Le pack file `{pack_name}` ({size} bytes) est téléchargeable.\n"
                        "Il contient l'ensemble des objets Git compressés — "
                        "un attaquant peut reconstruire l'intégralité du code source et de l'historique."
                    ),
                    evidence=f"HEAD {pack_url} → 200 OK, Content-Length: {size}",
                    cwe="CWE-538",
                    remediation="Bloquer l'accès au répertoire `.git/` sur le serveur web.",
                )

    # ──────────────────────── Phase 6 : autres VCS ───────────────────────────

    # Patterns de pages d'erreur WAF/reverse-proxy — indiquent un blocage déguisé en 200
    _WAF_REJECTION_PATTERNS = [
        re.compile(r"Request Rejected", re.I),
        re.compile(r"Your support ID is", re.I),
        re.compile(r"Access Denied", re.I),
        re.compile(r"Forbidden by policy", re.I),
        re.compile(r"<title>.*?(403|forbidden|rejected|blocked).*?</title>", re.I),
        re.compile(r"mod_security|nginx.*403|cloudflare.*blocked", re.I),
    ]

    # Signatures de contenu attendu pour chaque type de fichier VCS
    _VCS_CONTENT_SIGNATURES: dict[str, re.Pattern] = {
        "/.svn/entries":            re.compile(r"^(10\r?\n|<wc-entries)", re.M),
        "/.svn/wc.db":              re.compile(r"^SQLite format 3", re.M),
        "/.hg/":                    re.compile(r"(\.hg|mercurial|manifest|dirstate)", re.I),
        "/.hg/store/00manifest.i":  re.compile(r"\x00\x00"),          # fichier binaire HG
        "/.bzr/README":             re.compile(r"Bazaar", re.I),
    }

    def _is_waf_block(self, body: str) -> bool:
        """Retourne True si la réponse est une page de rejet WAF/proxy déguisée en 200."""
        return any(p.search(body) for p in self._WAF_REJECTION_PATTERNS)

    def _has_vcs_content(self, path: str, body: str) -> bool:
        """Vérifie que le body contient bien une signature de contenu VCS attendue."""
        sig = self._VCS_CONTENT_SIGNATURES.get(path)
        if sig is None:
            # Path inconnu : accepter si non-WAF et non-HTML générique
            return not self._is_waf_block(body) and not body.strip().startswith("<!DOCTYPE")
        return bool(sig.search(body))

    async def _check_other_vcs(self) -> AsyncIterator[Finding]:
        for path, desc, severity in _OTHER_VCS_FILES:
            url = f"{self._base}{path}"
            resp = await self._req.get(url)
            if resp.error or resp.status != 200 or len(resp.body) < 10:
                continue

            # FP-FIX: rejeter les pages WAF déguisées en 200
            if self._is_waf_block(resp.body):
                continue

            # FP-FIX: vérifier que le contenu ressemble vraiment à un fichier VCS
            if not self._has_vcs_content(path, resp.body):
                continue

            yield Finding(
                title=f"VCS exposé — {desc}",
                severity=severity,
                url=url,
                module="recon/git_exposure",
                description=f"`{path}` est accessible publiquement ({desc}).",
                evidence=f"Contenu (extrait) : {resp.body[:200]}",
                cwe="CWE-538",
                remediation=f"Bloquer l'accès au répertoire `{path.split('/')[1]}/` sur le serveur web.",
            )
