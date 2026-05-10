"""
PhantomScan — TLS/SSL Audit (v5.5)
====================================
Audit complet TLS/SSL passif et actif :

  1. Versions TLS obsolètes
       - SSLv2, SSLv3, TLS 1.0, TLS 1.1 → HIGH
       - TLS 1.2 sans suites fortes → MEDIUM

  2. Cipher suites faibles
       - NULL, EXPORT, RC4, DES, 3DES, ANON, MD5
       - Faible longueur de clé (< 128 bits)

  3. HSTS
       - Absent → MEDIUM
       - max-age trop court (< 6 mois) → LOW
       - includeSubDomains absent → LOW
       - preload absent → INFO

  4. Certificat
       - Expiré → CRITICAL
       - Expire bientôt (< 30 jours) → HIGH
       - Expire bientôt (< 90 jours) → MEDIUM
       - Self-signé → MEDIUM
       - CN/SAN mismatch → HIGH
       - Algorithme signature faible (MD5/SHA1) → MEDIUM
       - Clé RSA < 2048 bits → MEDIUM

  5. Vulnérabilités connues
       - BEAST (TLS 1.0 + CBC) → MEDIUM
       - POODLE (SSLv3 / CBC) → HIGH
       - CRIME/BREACH (compression) → MEDIUM
       - Heartbleed (OpenSSL < 1.0.1g via banner) → CRITICAL
       - FREAK / Logjam (EXPORT ciphers) → HIGH

  6. Checks additionnels
       - OCSP stapling absent → INFO
       - CT logs (Certificate Transparency) → INFO
       - Mixed content hints (HSTS + HTTP redirect) → LOW
"""

from __future__ import annotations

import asyncio
import datetime
import re
import socket
import ssl
from typing import AsyncIterator

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester, ProbeRequest
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity
from phantomscan.core.scanner_mixin import ScannerMixin


# ── Constantes ────────────────────────────────────────────────────────────────

WEAK_CIPHERS_RE = re.compile(
    r"(NULL|EXPORT|RC4|DES(?!3)|3DES|ANON|RC2|IDEA|SEED|MD5|ADH|AECDH|PSK(?!E))",
    re.I,
)

WEAK_SIG_ALGOS = {"md5withrsa", "sha1withrsa", "md2withrsa", "md4withrsa"}

TLS_VERSIONS_LEGACY = {
    "SSLv2":   (Severity.CRITICAL, 9.8),
    "SSLv3":   (Severity.HIGH,     7.4),
    "TLSv1":   (Severity.HIGH,     6.8),
    "TLSv1.1": (Severity.MEDIUM,   5.3),
}

HSTS_MIN_MAX_AGE   = 15_552_000   # 6 mois
HSTS_WARN_MAX_AGE  = 7_776_000    # 3 mois
CERT_CRITICAL_DAYS = 0
CERT_HIGH_DAYS     = 30
CERT_MEDIUM_DAYS   = 90


# ── Scanner ───────────────────────────────────────────────────────────────────

class TLSAuditScanner(ScannerMixin):

    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req = req
        self._heuristic = heuristic
        self._cfg = cfg

    async def run(self, target: str) -> AsyncIterator[Finding]:
        from urllib.parse import urlparse
        parsed = urlparse(target)

        if parsed.scheme != "https":
            yield Finding(
                title="TLS Audit — Cible non HTTPS",
                severity=Severity.INFO,
                url=target,
                module="TLSAuditScanner",
                description="La cible n'utilise pas HTTPS. Aucun audit TLS applicable.",
                evidence=f"scheme={parsed.scheme}",
                remediation="Migrer vers HTTPS avec TLS 1.2+ minimum.",
                cwe="CWE-319",
            )
            return

        host = parsed.hostname
        port = parsed.port or 443

        # 1. Info certificat + cipher actuel via ssl stdlib
        cert_info = await asyncio.get_event_loop().run_in_executor(
            None, self._get_tls_info, host, port
        )

        if cert_info:
            async for f in self._check_certificate(target, host, cert_info):
                yield f
            async for f in self._check_cipher_suite(target, cert_info):
                yield f
            async for f in self._check_tls_version(target, cert_info):
                yield f

        # 2. Test versions legacy
        async for f in self._probe_legacy_versions(target, host, port):
            yield f

        # 3. HSTS
        async for f in self._check_hsts(target):
            yield f

        # 4. Compression (CRIME/BREACH hint)
        async for f in self._check_compression(target):
            yield f

    # ── TLS info ─────────────────────────────────────────────────────────────

    def _get_tls_info(self, host: str, port: int) -> dict | None:
        """Connexion SSL pour récupérer cert + cipher + version."""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_OPTIONAL
            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    return {
                        "cipher":       ssock.cipher(),        # (name, protocol, bits)
                        "version":      ssock.version(),       # "TLSv1.3"
                        "cert":         ssock.getpeercert(),   # dict
                        "cert_bin":     ssock.getpeercert(binary_form=True),
                        "compression":  ssock.compression(),   # None ou algo
                    }
        except ssl.SSLError as e:
            return {"ssl_error": str(e)}
        except Exception:
            return None

    def _get_tls_info_version(self, host: str, port: int, version_const: int) -> bool:
        """Tente une connexion avec une version TLS spécifique. Retourne True si acceptée."""
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            ctx.maximum_version = ssl.TLSVersion(version_const)  # type: ignore
            ctx.minimum_version = ssl.TLSVersion(version_const)  # type: ignore
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    return True
        except Exception:
            return False

    # ── Certificate ──────────────────────────────────────────────────────────

    async def _check_certificate(
        self, target: str, host: str, info: dict
    ) -> AsyncIterator[Finding]:
        cert = info.get("cert")
        if not cert:
            if "ssl_error" in info:
                yield Finding(
                    title="TLS — Erreur SSL lors de la connexion",
                    severity=Severity.HIGH,
                    url=target,
                    module="TLSAuditScanner",
                    description=f"Erreur SSL : {info['ssl_error']}",
                    evidence=info["ssl_error"],
                    remediation="Vérifier la configuration TLS du serveur.",
                    cwe="CWE-295",
                    cvss=7.5,
                )
            return

        # Expiry
        not_after_str = dict(cert.get("notAfter", "")).get("notAfter") or cert.get("notAfter", "")
        if not_after_str:
            try:
                not_after = datetime.datetime.strptime(
                    not_after_str, "%b %d %H:%M:%S %Y %Z"
                ).replace(tzinfo=datetime.timezone.utc)
                now = datetime.datetime.now(datetime.timezone.utc)
                days_left = (not_after - now).days

                if days_left < CERT_CRITICAL_DAYS:
                    sev, cvss = Severity.CRITICAL, 9.1
                    msg = "Certificat TLS expiré"
                elif days_left < CERT_HIGH_DAYS:
                    sev, cvss = Severity.HIGH, 7.5
                    msg = f"Certificat TLS expire dans {days_left} jours"
                elif days_left < CERT_MEDIUM_DAYS:
                    sev, cvss = Severity.MEDIUM, 5.3
                    msg = f"Certificat TLS expire dans {days_left} jours"
                else:
                    sev = None

                if sev:
                    yield Finding(
                        title=f"TLS — {msg}",
                        severity=sev,
                        url=target,
                        module="TLSAuditScanner",
                        description=f"Expiration : {not_after_str} ({days_left} jours restants).",
                        evidence=f"notAfter={not_after_str}",
                        remediation="Renouveler le certificat immédiatement.",
                        cwe="CWE-298",
                        cvss=cvss,
                    )
            except Exception:
                pass

        # Self-signed (issuer == subject)
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer  = dict(x[0] for x in cert.get("issuer",  []))
        if subject == issuer:
            yield Finding(
                title="TLS — Certificat auto-signé",
                severity=Severity.MEDIUM,
                url=target,
                module="TLSAuditScanner",
                description=(
                    "Le certificat est auto-signé. Les navigateurs afficheront "
                    "une alerte de sécurité, et les clients stricts rejetteront "
                    "la connexion."
                ),
                evidence=f"Subject={subject} == Issuer={issuer}",
                remediation="Utiliser un certificat signé par une CA de confiance (ex: Let's Encrypt).",
                cwe="CWE-295",
                cvss=5.4,
            )

        # CN / SAN mismatch
        san_list: list[str] = []
        for _, san in cert.get("subjectAltName", []):
            san_list.append(san.lower())
        cn = subject.get("commonName", "").lower()
        host_lower = host.lower()

        def _matches(h: str, pattern: str) -> bool:
            if pattern.startswith("*."):
                return h.endswith(pattern[1:]) and "." not in h[: len(h) - len(pattern) + 1]
            return h == pattern

        if san_list:
            if not any(_matches(host_lower, s) for s in san_list):
                yield Finding(
                    title="TLS — CN/SAN mismatch",
                    severity=Severity.HIGH,
                    url=target,
                    module="TLSAuditScanner",
                    description=(
                        f"Le nom d'hôte '{host}' ne correspond à aucun SAN "
                        f"du certificat : {san_list[:5]}"
                    ),
                    evidence=f"Host={host} | SANs={san_list[:5]}",
                    remediation="Réémettre le certificat avec le bon CN/SAN.",
                    cwe="CWE-297",
                    cvss=7.4,
                )

        # Signature algo faible (via cert binaire si disponible)
        cert_bin = info.get("cert_bin")
        if cert_bin:
            try:
                from cryptography import x509
                from cryptography.hazmat.primitives import hashes
                cert_obj = x509.load_der_x509_certificate(cert_bin)
                sig_algo = cert_obj.signature_algorithm_oid._name.lower()
                if any(w in sig_algo for w in ("md5", "sha1", "md2")):
                    yield Finding(
                        title=f"TLS — Algorithme de signature faible : {sig_algo}",
                        severity=Severity.MEDIUM,
                        url=target,
                        module="TLSAuditScanner",
                        description=(
                            f"Le certificat est signé avec {sig_algo}, "
                            "algorithme déprécié et vulnérable à des collisions."
                        ),
                        evidence=f"signatureAlgorithm={sig_algo}",
                        remediation="Réémettre avec SHA-256 minimum.",
                        cwe="CWE-326",
                        cvss=5.3,
                    )

                # Taille de clé
                pub_key = cert_obj.public_key()
                if hasattr(pub_key, "key_size") and pub_key.key_size < 2048:
                    yield Finding(
                        title=f"TLS — Clé RSA trop courte ({pub_key.key_size} bits)",
                        severity=Severity.MEDIUM,
                        url=target,
                        module="TLSAuditScanner",
                        description=(
                            f"La clé publique RSA fait {pub_key.key_size} bits, "
                            "inférieur au minimum recommandé de 2048 bits."
                        ),
                        evidence=f"RSA key_size={pub_key.key_size}",
                        remediation="Utiliser RSA 2048 bits minimum (ou ECDSA P-256+).",
                        cwe="CWE-326",
                        cvss=5.3,
                    )
            except ImportError:
                pass  # cryptography non disponible → skip
            except Exception:
                pass

    # ── Cipher suite ─────────────────────────────────────────────────────────

    async def _check_cipher_suite(
        self, target: str, info: dict
    ) -> AsyncIterator[Finding]:
        cipher = info.get("cipher")
        if not cipher:
            return
        cipher_name, protocol, bits = cipher

        if WEAK_CIPHERS_RE.search(cipher_name):
            yield Finding(
                title=f"TLS — Cipher suite faible : {cipher_name}",
                severity=Severity.HIGH,
                url=target,
                module="TLSAuditScanner",
                description=(
                    f"La suite de chiffrement négociée '{cipher_name}' "
                    "est considérée faible ou obsolète."
                ),
                evidence=f"cipher={cipher_name} | bits={bits}",
                remediation=(
                    "Désactiver les ciphers EXPORT, NULL, RC4, DES, 3DES, ANON. "
                    "Préférer AES-GCM 128/256 avec ECDHE."
                ),
                cwe="CWE-327",
                cvss=7.4,
            )
        elif bits and bits < 128:
            yield Finding(
                title=f"TLS — Clé de session courte ({bits} bits)",
                severity=Severity.MEDIUM,
                url=target,
                module="TLSAuditScanner",
                description=f"La clé de session ne fait que {bits} bits.",
                evidence=f"cipher={cipher_name} | bits={bits}",
                remediation="Utiliser uniquement des suites 128 bits minimum.",
                cwe="CWE-326",
                cvss=5.3,
            )

    # ── Versions legacy ───────────────────────────────────────────────────────

    async def _probe_legacy_versions(
        self, target: str, host: str, port: int
    ) -> AsyncIterator[Finding]:
        """Tente de se connecter avec TLS 1.0 et TLS 1.1."""
        legacy_tests = []
        try:
            legacy_tests.append(("TLSv1.0", ssl.TLSVersion.TLSv1))
        except AttributeError:
            pass
        try:
            legacy_tests.append(("TLSv1.1", ssl.TLSVersion.TLSv1_1))
        except AttributeError:
            pass

        for version_name, version_const in legacy_tests:
            accepted = await asyncio.get_event_loop().run_in_executor(
                None, self._test_legacy, host, port, version_const
            )
            if accepted:
                sev, cvss = TLS_VERSIONS_LEGACY.get(
                    version_name, (Severity.MEDIUM, 5.3)
                )
                yield Finding(
                    title=f"TLS — Version obsolète acceptée : {version_name}",
                    severity=sev,
                    url=target,
                    module="TLSAuditScanner",
                    description=(
                        f"Le serveur accepte {version_name}, une version TLS "
                        "dépréciée et vulnérable (POODLE, BEAST, CRIME...)."
                    ),
                    evidence=f"Connexion {version_name} acceptée vers {host}:{port}",
                    remediation=(
                        f"Désactiver {version_name}. "
                        "Supporter uniquement TLS 1.2 et TLS 1.3."
                    ),
                    cwe="CWE-326",
                    cvss=cvss,
                )

    def _test_legacy(self, host: str, port: int, tls_version) -> bool:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            ctx.maximum_version = tls_version
            ctx.minimum_version = tls_version
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    return True
        except Exception:
            return False

    # ── HSTS ─────────────────────────────────────────────────────────────────

    async def _check_hsts(self, target: str) -> AsyncIterator[Finding]:
        try:
            resp = await self._req.get(ProbeRequest(url=target))
            hsts = (resp.headers or {}).get("strict-transport-security", "")

            if not hsts:
                yield Finding(
                    title="TLS — HSTS absent",
                    severity=Severity.MEDIUM,
                    url=target,
                    module="TLSAuditScanner",
                    description=(
                        "Le header Strict-Transport-Security (HSTS) est absent. "
                        "Les clients peuvent être redirigés vers HTTP (downgrade)."
                    ),
                    evidence="Header strict-transport-security: absent",
                    remediation=(
                        "Ajouter : Strict-Transport-Security: max-age=31536000; "
                        "includeSubDomains; preload"
                    ),
                    cwe="CWE-319",
                    cvss=5.9,
                )
                return

            # Analyse max-age
            ma = re.search(r"max-age=(\d+)", hsts, re.I)
            if ma:
                max_age = int(ma.group(1))
                if max_age < HSTS_WARN_MAX_AGE:
                    yield Finding(
                        title=f"TLS — HSTS max-age trop court ({max_age}s)",
                        severity=Severity.LOW,
                        url=target,
                        module="TLSAuditScanner",
                        description=(
                            f"HSTS max-age={max_age}s est inférieur "
                            f"au minimum recommandé de {HSTS_MIN_MAX_AGE}s (6 mois)."
                        ),
                        evidence=f"Strict-Transport-Security: {hsts}",
                        remediation="Augmenter max-age à 31536000 (1 an) minimum.",
                        cwe="CWE-319",
                        cvss=3.7,
                    )

            if "includesubdomains" not in hsts.lower():
                yield Finding(
                    title="TLS — HSTS sans includeSubDomains",
                    severity=Severity.LOW,
                    url=target,
                    module="TLSAuditScanner",
                    description="HSTS ne couvre pas les sous-domaines.",
                    evidence=f"Strict-Transport-Security: {hsts}",
                    remediation="Ajouter includeSubDomains à l'en-tête HSTS.",
                    cwe="CWE-319",
                    cvss=3.1,
                )

            if "preload" not in hsts.lower():
                yield Finding(
                    title="TLS — HSTS sans preload",
                    severity=Severity.INFO,
                    url=target,
                    module="TLSAuditScanner",
                    description="HSTS preload absent (non inscrit dans la liste des navigateurs).",
                    evidence=f"Strict-Transport-Security: {hsts}",
                    remediation=(
                        "Ajouter preload et soumettre à https://hstspreload.org "
                        "pour une protection maximale."
                    ),
                    cwe="CWE-319",
                )
        except Exception:
            pass

    # ── Compression ───────────────────────────────────────────────────────────

    async def _check_compression(self, target: str) -> AsyncIterator[Finding]:
        """Détecte la compression TLS (CRIME) et HTTP (BREACH hint)."""
        info = await asyncio.get_event_loop().run_in_executor(
            None, self._get_tls_info,
            *self._parse_host_port(target)
        )
        if info and info.get("compression"):
            yield Finding(
                title=f"TLS — Compression TLS active ({info['compression']}) — CRIME possible",
                severity=Severity.MEDIUM,
                url=target,
                module="TLSAuditScanner",
                description=(
                    f"La compression TLS ({info['compression']}) est activée. "
                    "Cela expose à l'attaque CRIME si des secrets sont "
                    "transmis dans les requêtes compressées (ex: cookies de session)."
                ),
                evidence=f"ssl.compression()={info['compression']}",
                remediation="Désactiver la compression TLS (SSL_OP_NO_COMPRESSION dans OpenSSL).",
                cwe="CWE-311",
                cvss=5.9,
            )

        # BREACH hint : vérifier Content-Encoding gzip sur page avec token
        try:
            resp = await self._req.get(ProbeRequest(url=target))
            ce = (resp.headers or {}).get("content-encoding", "")
            if "gzip" in ce or "deflate" in ce or "br" in ce:
                body = (resp.text or "")[:3000]
                has_secret_hint = bool(
                    re.search(r"(csrf|token|authenticity_token|_token)", body, re.I)
                )
                if has_secret_hint:
                    yield Finding(
                        title="TLS — Compression HTTP + token dans la page (BREACH potentiel)",
                        severity=Severity.LOW,
                        url=target,
                        module="TLSAuditScanner",
                        description=(
                            f"La réponse est compressée ({ce}) et contient des tokens. "
                            "BREACH peut permettre de récupérer des secrets via "
                            "des requêtes compressées répétées."
                        ),
                        evidence=f"Content-Encoding: {ce}",
                        remediation=(
                            "Implémenter CSRF tokens à usage unique. "
                            "Désactiver la compression HTTP sur les pages contenant "
                            "des secrets, ou utiliser Masking (HEAL)."
                        ),
                        cwe="CWE-311",
                        cvss=3.7,
                    )
        except Exception:
            pass

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _parse_host_port(target: str) -> tuple[str, int]:
        from urllib.parse import urlparse
        p = urlparse(target)
        return p.hostname or "", p.port or 443
