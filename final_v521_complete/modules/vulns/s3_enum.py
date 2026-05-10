"""
PhantomScan — Cloud Storage Enumeration (S3 / GCS / Azure Blob)
Détecte les buckets/containers mal configurés liés au domaine cible.

Stratégies :
  - Permutations du nom de domaine → noms de buckets probables
  - Vérification accès public en lecture (ListBucket/ListObjects)
  - Vérification accès public en écriture (PUT object)
  - Détection ACL misconfiguration (AllUsers/AuthenticatedUsers)
  - Support : AWS S3, Google Cloud Storage, Azure Blob Storage

CWE-732 : Incorrect Permission Assignment for Critical Resource
"""

from __future__ import annotations

import asyncio
import re
from typing import AsyncIterator
from urllib.parse import urlparse

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity
from phantomscan.core.scanner_mixin import ScannerMixin


# ─────────────────────────────────────────────────────────────────────────────
# URL templates par provider
# ─────────────────────────────────────────────────────────────────────────────

_S3_URL       = "https://{bucket}.s3.amazonaws.com/"
_S3_PATH_URL  = "https://s3.amazonaws.com/{bucket}/"
_GCS_URL      = "https://storage.googleapis.com/{bucket}/"
_AZURE_URL    = "https://{account}.blob.core.windows.net/{container}/?comp=list"

# Indicateurs d'accès public en lecture
_READ_INDICATORS = [
    r"<ListBucketResult",       # S3 / GCS
    r"<Contents>",              # S3 contents
    r"<EnumerationResults",     # Azure
    r"<Blobs>",                 # Azure blobs
    r"\"kind\": \"storage#objects\"",  # GCS JSON API
    r"<Key>",                   # S3 key list
    r"<Name>",                  # bucket name in XML
]

# Indicateurs de bucket existant (mais potentiellement protégé)
_EXISTS_INDICATORS = [
    r"AccessDenied",
    r"NoSuchBucketPolicy",
    r"AllAccessDisabled",
    r"InvalidBucketAclWithObjectOwnership",
    r"<Code>403</Code>",
    r"AuthorizationRequired",
    r"StorageErrorCode",
]

# Indicateurs d'erreur "bucket inexistant"
_NOTFOUND_INDICATORS = [
    r"NoSuchBucket",
    r"The specified bucket does not exist",
    r"BucketNotFound",
    r"ContainerNotFound",
    r"ResourceNotFound",
]

# Test PUT pour vérifier l'écriture publique
_PUT_TEST_KEY  = "phantomscan_write_test.txt"
_PUT_TEST_BODY = b"phantomscan-write-check"


# ─────────────────────────────────────────────────────────────────────────────
# Génération des permutations de noms de buckets
# ─────────────────────────────────────────────────────────────────────────────

def _generate_bucket_names(domain: str) -> list[str]:
    """
    Génère des noms de buckets probables à partir du domaine.
    Ex: 'api.example.com' → ['example', 'api-example', 'example-api',
                              'example-static', 'example-assets', ...]
    """
    # Extraire les parties significatives du domaine
    parts = domain.lower().replace("-", ".").split(".")
    # Filtrer les TLD et sous-domaines génériques
    filtered = [p for p in parts if p not in ("www", "api", "com", "net", "org",
                                               "io", "fr", "co", "uk", "app",
                                               "dev", "staging", "prod")]
    core = filtered[0] if filtered else parts[0]

    suffixes = [
        "", "-static", "-assets", "-media", "-files", "-uploads",
        "-backup", "-data", "-storage", "-cdn", "-images", "-logs",
        "-public", "-private", "-dev", "-prod", "-staging",
        ".static", ".assets", ".media",
    ]
    prefixes = [
        "", "static-", "assets-", "media-", "files-", "uploads-",
        "backup-", "data-", "storage-", "cdn-", "images-",
    ]

    names: set[str] = set()

    # Variations sur le core
    for suffix in suffixes:
        names.add(f"{core}{suffix}")
    for prefix in prefixes:
        names.add(f"{prefix}{core}")

    # Si sous-domaine présent, combiner
    if len(filtered) >= 2:
        combined = "-".join(filtered[:2])
        for suffix in suffixes[:6]:
            names.add(f"{combined}{suffix}")

    # Domaine complet sans TLD
    domain_no_tld = ".".join(parts[:-1]) if len(parts) > 2 else parts[0]
    safe_domain = re.sub(r"[^a-z0-9\-]", "-", domain_no_tld)
    names.add(safe_domain)

    # Filtrer les noms invalides (trop courts, caractères interdits)
    valid = []
    for n in names:
        n = n.strip("-").strip(".")
        if len(n) >= 3 and re.match(r"^[a-z0-9][a-z0-9\-\.]*[a-z0-9]$", n):
            valid.append(n)

    return list(set(valid))[:40]  # Limiter à 40 permutations


# ─────────────────────────────────────────────────────────────────────────────
# Scanner principal
# ─────────────────────────────────────────────────────────────────────────────

class S3EnumScanner(ScannerMixin):
    """
    Énumère les buckets cloud (S3, GCS, Azure) liés au domaine cible.
    Vérifie : existence, lecture publique (ListBucket), écriture publique (PUT).
    """

    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req = req
        self._heuristic = heuristic
        self._cfg = cfg

    async def run(self, target: str) -> AsyncIterator[Finding]:
        parsed = urlparse(target)
        domain = parsed.hostname or target.split("/")[2]
        bucket_names = _generate_bucket_names(domain)

        # Limite la concurrence pour éviter le rate-limiting AWS/GCS
        sem = asyncio.Semaphore(8)

        async def _check(bucket: str):
            results = []
            async with sem:
                async for f in self._check_bucket(bucket, domain):
                    results.append(f)
            return results

        tasks = [asyncio.create_task(_check(name)) for name in bucket_names]
        for coro in asyncio.as_completed(tasks):
            try:
                findings = await coro
                for f in findings:
                    yield f
            except Exception:
                continue

    async def _check_bucket(self, bucket: str, domain: str) -> AsyncIterator[Finding]:
        """Vérifie un nom de bucket sur les trois providers."""
        # AWS S3
        async for f in self._check_s3(bucket, domain):
            yield f
        # Google Cloud Storage
        async for f in self._check_gcs(bucket, domain):
            yield f
        # Azure Blob (utilise le core domain comme account name)
        account = re.sub(r"[^a-z0-9]", "", bucket)[:24]
        if len(account) >= 3:
            async for f in self._check_azure(account, bucket, domain):
                yield f

    # ── AWS S3 ───────────────────────────────────────────────────────────────

    async def _check_s3(self, bucket: str, domain: str) -> AsyncIterator[Finding]:
        url = _S3_URL.format(bucket=bucket)
        resp = await self._req.get(url)
        if resp.error or resp.status == 0:
            return

        # Bucket inexistant
        if resp.status == 404 or self._matches(resp.body, _NOTFOUND_INDICATORS):
            return

        # Lecture publique confirmée
        if resp.status == 200 and self._matches(resp.body, _READ_INDICATORS):
            # Compter les objects listés
            file_count = len(re.findall(r"<Key>", resp.body))
            yield Finding(
                title=f"S3 Bucket public en lecture — {bucket}",
                severity=Severity.HIGH,
                url=url,
                module="recon/s3_enum",
                description=(
                    f"Le bucket S3 `{bucket}` est accessible publiquement en lecture. "
                    f"ListBucket retourne {file_count} objet(s). "
                    f"Lié au domaine cible : {domain}"
                ),
                evidence=f"HTTP 200 sur {url} | {file_count} clés S3 listées",
                cwe="CWE-732",
                remediation=(
                    "Désactiver 'Block Public Access' settings au niveau bucket ET account. "
                    "Auditer la bucket policy et les ACL. "
                    "Utiliser des presigned URLs pour les accès légitimes."
                ),
            )
            # Vérifier aussi l'écriture
            async for f in self._check_s3_write(bucket, url):
                yield f

        # Bucket existe mais accès refusé (peut quand même être intéressant pour recon)
        elif resp.status == 403 and self._matches(resp.body, _EXISTS_INDICATORS):
            yield Finding(
                title=f"S3 Bucket existant (accès refusé) — {bucket}",
                severity=Severity.INFO,
                url=url,
                module="recon/s3_enum",
                description=(
                    f"Le bucket S3 `{bucket}` existe (HTTP 403) mais l'accès public est restreint. "
                    f"Bucket lié au domaine `{domain}` — peut être utile pour recon."
                ),
                evidence=f"HTTP 403 | Body: {resp.body[:200]}",
                cwe="CWE-732",
                remediation="Vérifier que le bucket ne contient pas de données sensibles accessibles via signed URLs exposées.",
            )

    async def _check_s3_write(self, bucket: str, list_url: str) -> AsyncIterator[Finding]:
        """Tente un PUT pour détecter l'écriture publique."""
        put_url = f"https://{bucket}.s3.amazonaws.com/{_PUT_TEST_KEY}"
        try:
            resp = await self._req.put(put_url, data=_PUT_TEST_BODY, headers={
                "Content-Type": "text/plain",
            })
            if resp and resp.status in (200, 204):
                yield Finding(
                    title=f"S3 Bucket public en ÉCRITURE — {bucket}",
                    severity=Severity.CRITICAL,
                    url=put_url,
                    module="recon/s3_enum",
                    description=(
                        f"Le bucket S3 `{bucket}` accepte les PUT non authentifiés ! "
                        f"Un attaquant peut uploader des fichiers arbitraires (malware, phishing, "
                        f"XSS via Content-Type, etc.)"
                    ),
                    evidence=f"PUT {put_url} → HTTP {resp.status}",
                    cwe="CWE-732",
                    remediation=(
                        "CRITIQUE — Activer 'Block Public Access' immédiatement. "
                        "Révoquer toutes les bucket policies AllUsers avec s3:PutObject."
                    ),
                )
        except Exception:
            pass

    # ── Google Cloud Storage ─────────────────────────────────────────────────

    async def _check_gcs(self, bucket: str, domain: str) -> AsyncIterator[Finding]:
        url = _GCS_URL.format(bucket=bucket)
        resp = await self._req.get(url)
        if resp.error or resp.status == 0:
            return

        if resp.status == 404 or self._matches(resp.body, _NOTFOUND_INDICATORS):
            return

        if resp.status == 200 and self._matches(resp.body, _READ_INDICATORS):
            file_count = len(re.findall(r'"name":', resp.body))
            yield Finding(
                title=f"GCS Bucket public en lecture — {bucket}",
                severity=Severity.HIGH,
                url=url,
                module="recon/s3_enum",
                description=(
                    f"Le bucket GCS `{bucket}` est accessible publiquement. "
                    f"{file_count} objet(s) listés. Lié au domaine : {domain}"
                ),
                evidence=f"HTTP 200 | {file_count} objets | {url}",
                cwe="CWE-732",
                remediation=(
                    "Supprimer les bindings IAM `allUsers` / `allAuthenticatedUsers`. "
                    "Utiliser Uniform Bucket-Level Access. "
                    "Auditer avec `gsutil iam get gs://{bucket}`."
                ),
            )

        elif resp.status == 403 and self._matches(resp.body, _EXISTS_INDICATORS):
            yield Finding(
                title=f"GCS Bucket existant (accès refusé) — {bucket}",
                severity=Severity.INFO,
                url=url,
                module="recon/s3_enum",
                description=f"Bucket GCS `{bucket}` détecté (403) — lié au domaine {domain}",
                evidence=f"HTTP 403 | {url}",
                cwe="CWE-732",
                remediation="Auditer les IAM bindings du bucket.",
            )

    # ── Azure Blob Storage ───────────────────────────────────────────────────

    async def _check_azure(self, account: str, container: str, domain: str) -> AsyncIterator[Finding]:
        url = _AZURE_URL.format(account=account, container=container)
        resp = await self._req.get(url)
        if resp.error or resp.status == 0:
            return

        if resp.status == 404 or self._matches(resp.body, _NOTFOUND_INDICATORS):
            return

        if resp.status == 200 and self._matches(resp.body, _READ_INDICATORS):
            blob_count = len(re.findall(r"<Name>", resp.body))
            yield Finding(
                title=f"Azure Blob Container public — {account}/{container}",
                severity=Severity.HIGH,
                url=url,
                module="recon/s3_enum",
                description=(
                    f"Le container Azure Blob `{container}` sur le compte `{account}` "
                    f"est accessible publiquement. {blob_count} blob(s) listés. "
                    f"Domaine lié : {domain}"
                ),
                evidence=f"HTTP 200 | {blob_count} blobs | {url}",
                cwe="CWE-732",
                remediation=(
                    "Définir le niveau d'accès public du container sur 'Private'. "
                    "Utiliser des SAS tokens pour les accès légitimes. "
                    "Activer Azure Defender for Storage."
                ),
            )

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _matches(body: str, patterns: list[str]) -> bool:
        for pattern in patterns:
            if re.search(pattern, body, re.I):
                return True
        return False
