"""
PhantomScan — Port Scanner
TCP connect scan asynchrone avec banner grabbing.
Identifie les services exposés et détecte les versions
pour alimenter les modules vulns suivants.
"""

from __future__ import annotations

import asyncio
import socket
import time
from dataclasses import dataclass, field
from typing import AsyncIterator

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity


# ─────────────────────────── Ports & services ───────────────────────────────

# (port, service_name, severity_si_ouvert, banner_probe)
PORT_DEFINITIONS: list[tuple[int, str, str, bytes | None]] = [
    (21,    "FTP",           "high",   b""),
    (22,    "SSH",           "info",   b""),
    (23,    "Telnet",        "critical", b"\n"),
    (25,    "SMTP",          "medium", b"EHLO phantomscan\r\n"),
    (53,    "DNS",           "info",   None),
    (80,    "HTTP",          "info",   b"HEAD / HTTP/1.0\r\n\r\n"),
    (110,   "POP3",         "medium", b""),
    (111,   "RPC",          "high",   None),
    (135,   "MSRPC",        "high",   None),
    (139,   "NetBIOS",      "high",   None),
    (143,   "IMAP",         "medium", b""),
    (161,   "SNMP",         "high",   None),
    (389,   "LDAP",         "high",   None),
    (443,   "HTTPS",        "info",   b"HEAD / HTTP/1.0\r\n\r\n"),
    (445,   "SMB",          "critical", None),
    (465,   "SMTPS",        "medium", b""),
    (512,   "rexec",        "critical", None),
    (513,   "rlogin",       "critical", None),
    (514,   "rsh",          "critical", None),
    (587,   "SMTP Submit",  "medium", b"EHLO phantomscan\r\n"),
    (631,   "IPP",          "medium", None),
    (873,   "rsync",        "high",   b""),
    (993,   "IMAPS",        "medium", b""),
    (995,   "POP3S",        "medium", b""),
    (1080,  "SOCKS",        "high",   None),
    (1433,  "MSSQL",        "critical", None),
    (1521,  "Oracle DB",    "critical", None),
    (2049,  "NFS",          "high",   None),
    (2375,  "Docker API",   "critical", b"GET /version HTTP/1.0\r\n\r\n"),
    (2376,  "Docker TLS",   "high",   None),
    (3000,  "Dev HTTP",     "medium", b"GET / HTTP/1.0\r\n\r\n"),
    (3306,  "MySQL",        "critical", None),
    (3389,  "RDP",          "high",   None),
    (4444,  "Metasploit?",  "critical", None),
    (5000,  "Dev/Flask",    "medium", b"GET / HTTP/1.0\r\n\r\n"),
    (5432,  "PostgreSQL",   "critical", None),
    (5900,  "VNC",          "critical", b""),
    (5984,  "CouchDB",      "critical", b"GET / HTTP/1.0\r\n\r\n"),
    (6379,  "Redis",        "critical", b"PING\r\n"),
    (6443,  "K8s API",      "critical", None),
    (8080,  "HTTP Alt",     "medium", b"GET / HTTP/1.0\r\n\r\n"),
    (8443,  "HTTPS Alt",    "medium", b"GET / HTTP/1.0\r\n\r\n"),
    (8888,  "Jupyter?",     "high",   b"GET / HTTP/1.0\r\n\r\n"),
    (9000,  "PHP-FPM/Dev",  "high",   None),
    (9090,  "Prometheus",   "high",   b"GET / HTTP/1.0\r\n\r\n"),
    (9200,  "Elasticsearch","critical", b"GET / HTTP/1.0\r\n\r\n"),
    (9300,  "ES Transport", "critical", None),
    (11211, "Memcached",    "critical", b"stats\r\n"),
    (27017, "MongoDB",      "critical", None),
    (27018, "MongoDB",      "critical", None),
    (50000, "Jenkins?",     "high",   b"GET / HTTP/1.0\r\n\r\n"),
]

# Mapping severity string → Severity enum
_SEV_MAP = {
    "info":     Severity.INFO,
    "medium":   Severity.MEDIUM,
    "high":     Severity.HIGH,
    "critical": Severity.CRITICAL,
}

# Services critiques exposés sans auth connue
_CRITICAL_SERVICES = {
    6379, 9200, 27017, 27018, 11211, 5984, 2375, 5432, 3306, 1433,
}


# ─────────────────────────── Dataclass résultat ─────────────────────────────

@dataclass
class PortResult:
    port: int
    service: str
    banner: str = ""
    elapsed_ms: float = 0.0
    severity_hint: str = "info"


# ─────────────────────────── Scanner ────────────────────────────────────────

class PortScanner:
    """
    TCP Connect Scanner asynchrone avec banner grabbing.

    Stratégie :
    1. Tente une connexion TCP sur chaque port de la liste.
    2. Si ouvert → envoie une sonde et lit le banner (max 1024 bytes).
    3. Génère un Finding par port ouvert, avec sévérité adaptée au service.
    4. Finding CRITICAL supplémentaire si le service est dans la liste
       des services critiques exposés sans auth (Redis, ES, MongoDB…).
    """

    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req = req
        self._heuristic = heuristic
        self._cfg = cfg
        self._timeout: float = getattr(cfg, "port_scan_timeout", 3.0)
        self._concurrency: int = getattr(cfg, "port_scan_concurrency", 100)
        self._custom_ports: list[int] = getattr(cfg, "port_scan_extra_ports", [])

    # ── Point d'entrée ───────────────────────────────────────────────────────

    async def run(self, target: str) -> AsyncIterator[Finding]:
        from urllib.parse import urlparse
        parsed = urlparse(target)
        host = parsed.hostname or target.split("/")[0]

        # Résolution DNS une seule fois
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror:
            return

        port_defs = list(PORT_DEFINITIONS)
        # Ajouter les ports custom (sans service name connu)
        known_ports = {p for p, *_ in PORT_DEFINITIONS}
        for p in self._custom_ports:
            if p not in known_ports:
                port_defs.append((p, f"Custom({p})", "medium", None))

        sem = asyncio.Semaphore(self._concurrency)
        tasks = [
            self._scan_port(ip, host, port, service, sev, probe, sem)
            for port, service, sev, probe in port_defs
        ]

        for coro in asyncio.as_completed(tasks):
            findings = await coro
            for f in findings:
                yield f

    # ── Scan d'un port ───────────────────────────────────────────────────────

    async def _scan_port(
        self,
        ip: str,
        host: str,
        port: int,
        service: str,
        severity_hint: str,
        probe: bytes | None,
        sem: asyncio.Semaphore,
    ) -> list[Finding]:
        async with sem:
            result = await self._tcp_connect_banner(ip, port, probe)

        if result is None:
            return []

        result.service = service
        result.severity_hint = severity_hint

        findings = []

        # ── FP-FIX: ports 80/443 sont ouverts par définition sur tout site web public ──
        # Ne pas émettre de finding INFO pour ces ports — c'est du bruit inutile en BB.
        _STANDARD_PUBLIC_PORTS = {80, 443}
        if port in _STANDARD_PUBLIC_PORTS and severity_hint == "info":
            # Tenter quand même le finding critique si no-auth détecté (rare mais possible)
            if port in _CRITICAL_SERVICES:
                no_auth = self._detect_no_auth(service, result.banner)
                if no_auth:
                    findings.append(Finding(
                        title=f"CRITIQUE — {service} exposé sans authentification ({host}:{port})",
                        severity=Severity.CRITICAL,
                        url=f"{host}:{port}",
                        module="network/port_scan",
                        description=(
                            f"{service} sur {host}:{port} semble accessible sans authentification. "
                            f"Ce type de service exposé directement sur Internet est fréquemment "
                            f"exploité pour de l'exfiltration de données ou du pivot réseau."
                        ),
                        evidence=f"Banner: {result.banner[:200] or 'connexion acceptée sans challenge auth'}",
                        cwe="CWE-306",
                    ))
            return findings

        # ── Finding principal : port ouvert ──────────────────────────────────
        banner_info = f" | Banner: {result.banner[:120]}" if result.banner else ""
        findings.append(Finding(
            title=f"Port ouvert : {port}/{service} sur {host}",
            severity=_SEV_MAP.get(severity_hint, Severity.INFO),
            url=f"{host}:{port}",
            module="network/port_scan",
            description=(
                f"Le port TCP {port} ({service}) est ouvert sur {host} ({ip}). "
                f"Temps de réponse : {result.elapsed_ms:.0f} ms."
                f"{banner_info}"
            ),
            evidence=f"TCP CONNECT OK | Port={port} | Service={service} | IP={ip}{banner_info}",
            cwe="CWE-200",
            remediation=(
                f"Vérifier si le service {service} sur le port {port} doit être "
                "exposé publiquement. Restreindre via firewall si non nécessaire."
            ),
        ))

        # ── Finding critique : service exposé sans auth ──────────────────────
        if port in _CRITICAL_SERVICES:
            no_auth = self._detect_no_auth(service, result.banner)
            if no_auth:
                findings.append(Finding(
                    title=f"CRITIQUE — {service} exposé sans authentification ({host}:{port})",
                    severity=Severity.CRITICAL,
                    url=f"{host}:{port}",
                    module="network/port_scan",
                    description=(
                        f"{service} sur {host}:{port} semble accessible sans authentification. "
                        f"Ce type de service exposé directement sur Internet est fréquemment "
                        f"exploité pour de l'exfiltration de données ou du pivot réseau."
                    ),
                    evidence=f"Banner: {result.banner[:200] or 'connexion acceptée sans challenge auth'}",
                    cwe="CWE-306",
                    remediation=(
                        f"Bloquer immédiatement l'accès public au port {port}. "
                        f"Activer l'authentification sur {service}. "
                        "Ne jamais exposer des bases de données ou caches sur Internet."
                    ),
                    cvss=9.8,
                ))

        return findings

    # ── TCP Connect + Banner Grab ─────────────────────────────────────────────

    async def _tcp_connect_banner(
        self,
        ip: str,
        port: int,
        probe: bytes | None,
    ) -> PortResult | None:
        t0 = time.monotonic()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self._timeout,
            )
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None

        elapsed = (time.monotonic() - t0) * 1000
        banner = ""

        try:
            # Lire le banner passif (ex: SSH, FTP, SMTP envoient d'abord)
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                banner = data.decode("utf-8", errors="replace").strip()
            except asyncio.TimeoutError:
                pass

            # Envoyer une sonde si définie et banner vide
            if probe and not banner:
                writer.write(probe)
                await writer.drain()
                try:
                    data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                    banner = data.decode("utf-8", errors="replace").strip()
                except asyncio.TimeoutError:
                    pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

        return PortResult(port=port, service="", banner=banner, elapsed_ms=elapsed)

    # ── Détection no-auth ────────────────────────────────────────────────────

    @staticmethod
    def _detect_no_auth(service: str, banner: str) -> bool:
        """
        Retourne True si le banner indique une réponse sans challenge d'auth.
        """
        banner_low = banner.lower()
        no_auth_indicators = {
            "Redis":         ["+pong", "redis_version"],
            "Elasticsearch": ['"cluster_name"', '"version"', '"lucene_version"'],
            "MongoDB":       ["ismaster", "mongodb"],
            "Memcached":     ["stat ", "version "],
            "CouchDB":       ['"couchdb"', '"version"'],
            "Docker API":    ['"apiversion"', '"version"'],
        }
        indicators = no_auth_indicators.get(service, [])
        return any(ind.lower() in banner_low for ind in indicators) or (
            not indicators and len(banner) > 0 and "auth" not in banner_low
            and "password" not in banner_low and "login" not in banner_low
        )
