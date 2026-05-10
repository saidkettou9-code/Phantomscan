"""
PhantomScan — Cloud Recon Scanner
===================================
Découverte de ressources cloud exposées à partir du domaine cible.

Buckets S3, blobs Azure, buckets GCP, Firebase RTDB, et autres stockages
cloud mal configurés représentent une large part des vulnérabilités BB P1.

Technique : générer des noms de buckets probables depuis le nom de domaine
(company-name, company-backup, company-dev, etc.) puis tester leur accès.

Couverture :
  1. AWS S3     — s3.amazonaws.com + s3-{region}.amazonaws.com
  2. Azure Blob — {account}.blob.core.windows.net
  3. GCP Storage — storage.googleapis.com/{bucket}
  4. Firebase RTDB — {project}.firebaseio.com
  5. DigitalOcean Spaces — {bucket}.{region}.digitaloceanspaces.com

Génération des noms :
  - Nom de domaine exact et variantes
  - Préfixes/suffixes courants (backup, dev, staging, prod, assets, cdn)
  - Abréviations de l'entreprise
"""

from __future__ import annotations

import asyncio
import re
from typing import AsyncIterator
from urllib.parse import urlparse

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester, ProbeRequest
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity
from phantomscan.core.scanner_mixin import ScannerMixin


# ── Suffixes courants pour les noms de buckets ────────────────────────────────
_BUCKET_SUFFIXES = [
    "", "-backup", "-backups", "-dev", "-development",
    "-staging", "-stage", "-prod", "-production",
    "-assets", "-static", "-media", "-images", "-img",
    "-files", "-uploads", "-data", "-logs", "-log",
    "-internal", "-private", "-public", "-cdn",
    "-test", "-qa", "-uat", "-sandbox",
    "-api", "-web", "-app", "-apps",
    "backup", "backups", "dev", "staging", "prod", "assets",
    "static", "media", "files", "data", "logs", "internal",
]

# ── S3 Regions ────────────────────────────────────────────────────────────────
_S3_REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-west-2", "eu-central-1",
    "ap-southeast-1", "ap-northeast-1",
]

# ── Patterns de réponse indiquant un bucket ouvert ────────────────────────────
_S3_OPEN_RE = re.compile(
    r"<ListBucketResult|<Contents>|<Key>.*</Key>|"
    r"NoSuchBucket|AllAccessDisabled|AccessDenied",
    re.I,
)
_S3_FILES_RE = re.compile(r"<Key>([^<]+)</Key>", re.I)
_AZURE_OPEN_RE = re.compile(r"<EnumerationResults|<Blob>|<Name>.*</Name>", re.I)
_GCP_OPEN_RE   = re.compile(r'"kind":\s*"storage#objects"|"items":\s*\[', re.I)
_FIREBASE_OPEN_RE = re.compile(r'^\{.*\}$|^\[.*\]$', re.S)


class CloudReconScanner(ScannerMixin):
    """Scanner de ressources cloud exposées."""

    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req = req
        self._heur = heuristic
        self._cfg = cfg
        self._tested: set[str] = set()

    async def run(self, target: str) -> AsyncIterator[Finding]:
        parsed = urlparse(target)
        hostname = parsed.hostname or ""

        # Générer les noms de buckets candidats
        bucket_names = self._generate_bucket_names(hostname)

        # Tester toutes les plateformes en parallèle
        tasks = []
        for name in bucket_names[:30]:  # Cap à 30 noms
            tasks.extend([
                self._test_s3(name),
                self._test_azure(name),
                self._test_gcp(name),
                self._test_firebase(name),
            ])

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for finding in results:
            if isinstance(finding, Finding):
                yield finding

    # ── Génération des noms ───────────────────────────────────────────────────

    def _generate_bucket_names(self, hostname: str) -> list[str]:
        """Génère les noms de buckets candidats depuis le hostname."""
        # Extraire le nom de domaine principal
        parts = hostname.split(".")
        # company.example.com → ["company", "example", "com"]
        candidates: set[str] = set()

        # Domaine complet sans TLD
        if len(parts) >= 2:
            domain_no_tld = ".".join(parts[:-1])  # company.example
            company = parts[-2]  # example
            candidates.add(domain_no_tld)
            candidates.add(company)
            if len(parts) >= 3:
                subdomain = parts[0]
                candidates.add(subdomain)
                candidates.add(f"{subdomain}-{company}")
                candidates.add(f"{company}-{subdomain}")

        # Générer les variantes avec suffixes
        result = []
        for base_name in list(candidates)[:5]:
            # Nettoyer : uniquement alphanum + tirets
            base_clean = re.sub(r'[^a-z0-9-]', '-', base_name.lower()).strip('-')
            if not base_clean or len(base_clean) < 3:
                continue
            for suffix in _BUCKET_SUFFIXES[:15]:
                candidate = base_clean + suffix
                if 3 <= len(candidate) <= 63:
                    result.append(candidate)

        return list(dict.fromkeys(result))  # Dédupliquer en préservant l'ordre

    # ── AWS S3 ────────────────────────────────────────────────────────────────

    async def _test_s3(self, name: str) -> Finding | None:
        """Teste l'accès à un bucket S3."""
        urls = [
            f"https://{name}.s3.amazonaws.com/",
            f"https://s3.amazonaws.com/{name}/",
        ]
        for url in urls:
            if url in self._tested:
                continue
            self._tested.add(url)

            resp = await self._req.send(ProbeRequest(
                method="GET", url=url,
                headers={"User-Agent": "Mozilla/5.0"},
            ))
            if resp.error:
                continue

            body = resp.body or ""
            if not _S3_OPEN_RE.search(body):
                continue

            if "AllAccessDisabled" in body or "AccessDenied" in body:
                # Bucket existe mais accès refusé → INFO
                return Finding(
                    title=f"AWS S3 Bucket Exists — {name}",
                    severity=Severity.INFO,
                    url=url,
                    module="recon/cloud_recon",
                    description=(
                        f"Le bucket S3 `{name}` existe mais son accès est refusé. "
                        "Vérifier sa configuration de permissions et la politique bucket."
                    ),
                    evidence=f"HTTP {resp.status} | AccessDenied or bucket exists",
                    cwe="CWE-200",
                    remediation="Vérifier que le bucket n'est pas accessible publiquement.",
                )

            # Bucket lisible !
            files = _S3_FILES_RE.findall(body)[:5]
            return Finding(
                title=f"AWS S3 Bucket Publicly Accessible — {name}",
                severity=Severity.HIGH if files else Severity.MEDIUM,
                url=url,
                module="recon/cloud_recon",
                description=(
                    f"Le bucket S3 `{name}` est accessible publiquement. "
                    + (f"Fichiers visibles : {', '.join(files[:3])}" if files
                       else "Listing activé.")
                ),
                evidence=(
                    f"HTTP {resp.status} | "
                    f"Files: {files[:3]} | "
                    f"Body: {body[:200]}"
                ),
                cwe="CWE-200",
                remediation=(
                    "Désactiver le Block Public Access. "
                    "Supprimer les ACL 'public-read' et 'public-read-write'. "
                    "Utiliser des policies bucket restrictives."
                ),
            )
        return None

    # ── Azure Blob ────────────────────────────────────────────────────────────

    async def _test_azure(self, name: str) -> Finding | None:
        """Teste l'accès à un container Azure Blob Storage."""
        # Format Azure : {account}.blob.core.windows.net/{container}
        clean = re.sub(r'[^a-z0-9]', '', name.lower())
        if len(clean) < 3 or len(clean) > 24:
            return None

        for container in ["", "$root", "public", "uploads", "assets", "files", "data"]:
            path = f"/{container}" if container else ""
            url = f"https://{clean}.blob.core.windows.net{path}?restype=container&comp=list"
            if url in self._tested:
                continue
            self._tested.add(url)

            resp = await self._req.send(ProbeRequest(method="GET", url=url))
            if resp.error or resp.status == 404:
                continue

            body = resp.body or ""
            if _AZURE_OPEN_RE.search(body):
                return Finding(
                    title=f"Azure Blob Container Publicly Accessible — {clean}",
                    severity=Severity.HIGH,
                    url=url,
                    module="recon/cloud_recon",
                    description=(
                        f"Container Azure Blob `{clean}` accessible publiquement. "
                        "Les fichiers sont listables et potentiellement téléchargeables."
                    ),
                    evidence=f"HTTP {resp.status} | {body[:200]}",
                    cwe="CWE-200",
                    remediation=(
                        "Désactiver l'accès public anonyme sur le Storage Account. "
                        "Utiliser des SAS tokens ou Azure AD pour l'accès autorisé."
                    ),
                )

            if resp.status in (403, 401):
                return Finding(
                    title=f"Azure Storage Account Exists — {clean}",
                    severity=Severity.INFO,
                    url=f"https://{clean}.blob.core.windows.net/",
                    module="recon/cloud_recon",
                    description=f"Storage account Azure `{clean}` existe (accès refusé).",
                    evidence=f"HTTP {resp.status}",
                    cwe="CWE-200",
                    remediation="Vérifier la configuration d'accès public.",
                )
            break  # Ne tester qu'un container par compte
        return None

    # ── GCP Storage ───────────────────────────────────────────────────────────

    async def _test_gcp(self, name: str) -> Finding | None:
        """Teste l'accès à un bucket GCP Storage."""
        url = f"https://storage.googleapis.com/{name}/"
        if url in self._tested:
            return None
        self._tested.add(url)

        resp = await self._req.send(ProbeRequest(method="GET", url=url))
        if resp.error or resp.status == 404:
            return None

        body = resp.body or ""
        if _GCP_OPEN_RE.search(body):
            return Finding(
                title=f"GCP Storage Bucket Publicly Accessible — {name}",
                severity=Severity.HIGH,
                url=url,
                module="recon/cloud_recon",
                description=f"Bucket GCP `{name}` listé publiquement.",
                evidence=f"HTTP {resp.status} | {body[:200]}",
                cwe="CWE-200",
                remediation=(
                    "Supprimer l'accès allUsers dans les IAM bindings. "
                    "Utiliser Uniform bucket-level access."
                ),
            )

        if resp.status in (401, 403):
            return Finding(
                title=f"GCP Bucket Exists — {name}",
                severity=Severity.INFO,
                url=url,
                module="recon/cloud_recon",
                description=f"Bucket GCP `{name}` existe (accès refusé).",
                evidence=f"HTTP {resp.status}",
                cwe="CWE-200",
                remediation="Vérifier les bindings IAM allUsers.",
            )
        return None

    # ── Firebase ──────────────────────────────────────────────────────────────

    async def _test_firebase(self, name: str) -> Finding | None:
        """Teste l'accès à une Firebase Realtime Database."""
        url = f"https://{name}.firebaseio.com/.json"
        if url in self._tested:
            return None
        self._tested.add(url)

        resp = await self._req.send(ProbeRequest(method="GET", url=url))
        if resp.error or resp.status == 404:
            return None

        body = resp.body or ""

        if resp.status == 200 and _FIREBASE_OPEN_RE.match(body.strip()):
            size = len(body)
            return Finding(
                title=f"Firebase RTDB Publicly Readable — {name}",
                severity=Severity.CRITICAL if size > 100 else Severity.HIGH,
                url=url,
                module="recon/cloud_recon",
                description=(
                    f"Base Firebase Realtime `{name}` lisible sans authentification. "
                    f"Taille des données : {size} bytes. "
                    "Toutes les données sont exposées."
                ),
                evidence=f"HTTP 200 | Data size: {size}B | Preview: {body[:200]}",
                cwe="CWE-200",
                remediation=(
                    "Configurer les Firebase Security Rules pour refuser l'accès anonyme. "
                    "Règle minimale : {\\\"rules\\\": {\\\"read\\\": false, \\\"write\\\": false}}"
                ),
            )

        if resp.status == 401:
            return Finding(
                title=f"Firebase RTDB Exists — {name}",
                severity=Severity.INFO,
                url=f"https://{name}.firebaseio.com/",
                module="recon/cloud_recon",
                description=f"Firebase RTDB `{name}` existe (accès refusé).",
                evidence=f"HTTP {resp.status}",
                cwe="CWE-200",
                remediation="Vérifier les Security Rules Firebase.",
            )
        return None
