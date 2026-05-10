"""
PhantomScan — Subdomain Enumerator  v2.0
Énumération passive multi-source + DNS brute-force + résolution de confirmation.

Sources passives:
  - crt.sh          (Certificate Transparency logs)
  - AlienVault OTX  (Threat intelligence, sans clé API)
  - ThreatMiner     (Passive DNS, sans clé API)
  - AnubisDB        (jldc.me, JSON list)
  - Wayback CDX     (URLs indexées par archive.org)
  - HackerTarget    (hostsearch API)

Active:
  - DNS brute-force avec wordlist intégrée (si cfg.scan.subdomain_bruteforce)
  - Résolution DNS asynchrone pour filtrer les sous-domaines alive

Takeover detection (v2.0):
  - CNAME fingerprinting via _TAKEOVER_FINGERPRINTS
  - Vérification de dangling CNAME (CNAME résout mais hôte cible absent)
  - Findings CRITICAL pour chaque service vulnérable identifié
"""

from __future__ import annotations

import asyncio
import json
import random
import re
from typing import AsyncGenerator
from urllib.parse import urlparse

try:
    import aiodns
    _AIODNS_AVAILABLE = True
except ImportError:
    import socket
    _AIODNS_AVAILABLE = False

_DNS_RESOLVERS: list[str] = [
    "1.1.1.1", "1.0.0.1",
    "8.8.8.8", "8.8.4.4",
    "9.9.9.9", "149.112.112.112",
    "208.67.222.222", "208.67.220.220",
]

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester, ProbeRequest
from phantomscan.output.reporter import Finding, Severity


# ---------------------------------------------------------------------------
# Wordlist intégrée pour le brute-force (top 200 communs)
# ---------------------------------------------------------------------------
_BRUTE_WORDLIST: list[str] = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "mx", "ns1", "ns2",
    "dns", "dns1", "dns2", "vpn", "remote", "api", "dev", "staging", "stage",
    "test", "qa", "uat", "sandbox", "beta", "alpha", "demo", "preview",
    "admin", "portal", "dashboard", "panel", "cp", "cpanel", "whm",
    "blog", "shop", "store", "pay", "payment", "checkout", "cdn", "static",
    "assets", "img", "images", "media", "upload", "uploads", "files", "docs",
    "help", "support", "status", "monitor", "metrics", "grafana", "kibana",
    "jenkins", "ci", "git", "gitlab", "github", "jira", "confluence",
    "app", "apps", "mobile", "m", "wap", "secure", "ssl", "login", "auth",
    "sso", "oauth", "id", "account", "accounts", "my", "user", "users",
    "intranet", "internal", "corp", "corporate", "office",
    "db", "database", "mysql", "postgres", "redis", "mongo", "elastic",
    "s3", "backup", "bak", "old", "new", "v1", "v2", "v3",
    "forum", "community", "wiki", "kb", "knowledge",
    "api2", "api3", "rest", "graphql", "ws", "websocket", "socket",
    "smtp1", "smtp2", "mail2", "mx1", "mx2", "ns3", "ns4",
    "vpn1", "vpn2", "gw", "gateway", "proxy", "lb", "load",
    "web", "web1", "web2", "srv", "server", "server1", "server2",
    "cloud", "aws", "azure", "gcp",
    "crm", "erp", "hr", "finance", "legal", "marketing",
    "download", "mirror", "repo", "registry",
]

# ---------------------------------------------------------------------------
# CNAME Fingerprints pour Subdomain Takeover
# Format: (cname_pattern, body_fingerprint, service_name, remediation)
# ---------------------------------------------------------------------------
_TAKEOVER_FINGERPRINTS: list[dict] = [
    {
        "cname_pattern": r"\.github\.io$",
        "body_markers": ["There isn't a GitHub Pages site here.", "404"],
        "service": "GitHub Pages",
        "remediation": "Créer un repo GitHub avec ce nom ou supprimer l'enregistrement CNAME.",
    },
    {
        "cname_pattern": r"\.s3(?:[\.-][a-z0-9-]+)?\.amazonaws\.com$",
        "body_markers": ["NoSuchBucket", "The specified bucket does not exist"],
        "service": "Amazon S3",
        "remediation": "Supprimer l'enregistrement CNAME ou créer le bucket S3 correspondant.",
    },
    {
        "cname_pattern": r"\.azurewebsites\.net$",
        "body_markers": ["404 Web Site not found", "Microsoft Azure"],
        "service": "Azure Web Apps",
        "remediation": "Supprimer l'enregistrement CNAME ou recréer l'App Service Azure.",
    },
    {
        "cname_pattern": r"\.azureedge\.net$",
        "body_markers": ["404", "The resource you are looking for has been removed"],
        "service": "Azure CDN",
        "remediation": "Supprimer le CNAME ou reconfigurer le profil Azure CDN.",
    },
    {
        "cname_pattern": r"\.herokuapp\.com$",
        "body_markers": ["No such app", "herokucdn.com/error-pages"],
        "service": "Heroku",
        "remediation": "Supprimer le CNAME ou recréer l'app Heroku.",
    },
    {
        "cname_pattern": r"\.netlify\.(?:app|com)$",
        "body_markers": ["Not Found - Request ID", "netlify"],
        "service": "Netlify",
        "remediation": "Supprimer le CNAME ou revendiquer le site sur Netlify.",
    },
    {
        "cname_pattern": r"\.vercel\.app$",
        "body_markers": ["The deployment could not be found", "DEPLOYMENT_NOT_FOUND"],
        "service": "Vercel",
        "remediation": "Supprimer le CNAME ou redéployer sur Vercel.",
    },
    {
        "cname_pattern": r"\.surge\.sh$",
        "body_markers": ["project not found", "surge.sh"],
        "service": "Surge.sh",
        "remediation": "Revendiquer le domaine avec `surge` CLI ou supprimer le CNAME.",
    },
    {
        "cname_pattern": r"\.firebaseapp\.com$",
        "body_markers": ["Site Not Found", "firebase"],
        "service": "Firebase Hosting",
        "remediation": "Recréer le projet Firebase ou supprimer l'enregistrement CNAME.",
    },
    {
        "cname_pattern": r"\.pantheonsite\.io$",
        "body_markers": ["404 error unknown site!", "Pantheon"],
        "service": "Pantheon",
        "remediation": "Supprimer le CNAME ou reconfigurer l'environnement Pantheon.",
    },
    {
        "cname_pattern": r"\.ghost\.io$",
        "body_markers": ["404", "Ghost"],
        "service": "Ghost.io",
        "remediation": "Supprimer le CNAME ou recréer le blog Ghost.",
    },
    {
        "cname_pattern": r"\.helpscoutdocs\.com$",
        "body_markers": ["No settings were found for this company:"],
        "service": "HelpScout Docs",
        "remediation": "Supprimer le CNAME ou reconfigurer HelpScout.",
    },
    {
        "cname_pattern": r"cargocollective\.com$",
        "body_markers": ["404 Not Found"],
        "service": "Cargo Collective",
        "remediation": "Supprimer le CNAME ou recréer le site Cargo.",
    },
    {
        "cname_pattern": r"\.myshopify\.com$",
        "body_markers": ["Sorry, this shop is currently unavailable."],
        "service": "Shopify",
        "remediation": "Supprimer le CNAME ou réactiver la boutique Shopify.",
    },
    {
        "cname_pattern": r"\.wordpress\.com$",
        "body_markers": ["Do you want to register"],
        "service": "WordPress.com",
        "remediation": "Supprimer le CNAME ou revendiquer le blog WordPress.",
    },
    {
        "cname_pattern": r"freshdesk\.com$",
        "body_markers": ["There is no helpdesk here"],
        "service": "Freshdesk",
        "remediation": "Supprimer le CNAME ou recréer le portail Freshdesk.",
    },
    {
        "cname_pattern": r"\.zendesk\.com$",
        "body_markers": ["Help Center Closed"],
        "service": "Zendesk",
        "remediation": "Supprimer le CNAME ou reconfigurer Zendesk.",
    },
    {
        "cname_pattern": r"\.readme\.io$",
        "body_markers": ["Project doesnt exist", "readme.io"],
        "service": "ReadMe.io",
        "remediation": "Supprimer le CNAME ou recréer le projet ReadMe.",
    },
]


class SubdomainEnumerator:
    def __init__(self, req: Requester, cfg: PhantomConfig) -> None:
        self._req = req
        self._cfg = cfg

    async def run(self, target: str) -> AsyncGenerator[Finding, None]:
        domain = self._extract_domain(target)
        found: dict[str, set[str]] = {}

        wildcard_ips = await self._detect_wildcard(domain)

        # ── Sources passives ────────────────────────────────────────────────
        tasks = {
            "crt.sh":       self._crtsh(domain),
            "alienvault":   self._alienvault(domain),
            "threatminer":  self._threatminer(domain),
            "anubisdb":     self._anubisdb(domain),
            "wayback":      self._wayback(domain),
            "hackertarget": self._hackertarget(domain),
        }
        results = await asyncio.gather(*tasks.values(), return_exceptions=True)
        for source, result in zip(tasks.keys(), results):
            if isinstance(result, list):
                for sub in result:
                    sub = sub.strip().lower()
                    if not sub or not sub.endswith(domain):
                        continue
                    found.setdefault(sub, set()).add(source)

        # ── Brute-force DNS (optionnel) ─────────────────────────────────────
        bruteforce_enabled = getattr(self._cfg.scan, "subdomain_bruteforce", False)
        if bruteforce_enabled:
            for sub in await self._bruteforce(domain):
                found.setdefault(sub, set()).add("bruteforce")

        # ── Résolution DNS ──────────────────────────────────────────────────
        resolve_enabled = getattr(self._cfg.scan, "subdomain_resolve", True)
        if resolve_enabled:
            alive = await self._resolve_all(list(found.keys()), wildcard_ips)
        else:
            alive = set(found.keys())

        # ── Yield findings découverte ───────────────────────────────────────
        for sub in sorted(alive):
            sources = ", ".join(sorted(found.get(sub, {"bruteforce"})))
            yield Finding(
                title=f"Subdomain discovered: {sub}",
                severity=Severity.INFO,
                url=f"https://{sub}",
                module="recon/subdomain",
                description=f"Sous-domaine actif découvert via: {sources}",
                evidence=sub,
            )

        # ── Takeover detection ──────────────────────────────────────────────
        takeover_enabled = getattr(self._cfg.scan, "subdomain_takeover", True)
        if takeover_enabled:
            async for f in self._check_takeovers(list(found.keys())):
                yield f

    # ── Sources passives ────────────────────────────────────────────────────

    async def _crtsh(self, domain: str) -> list[str]:
        resp = await self._req.send(ProbeRequest(
            method="GET",
            url=f"https://crt.sh/?q=%25.{domain}&output=json",
            headers={"Accept": "application/json"},
        ))
        if resp.error or resp.status != 200:
            return []
        try:
            data = json.loads(resp.body)
            subs: set[str] = set()
            for entry in data:
                for name in entry.get("name_value", "").splitlines():
                    name = name.strip().lstrip("*.")
                    if name.endswith(domain):
                        subs.add(name)
            return list(subs)
        except Exception:
            return []

    async def _alienvault(self, domain: str) -> list[str]:
        resp = await self._req.send(ProbeRequest(
            method="GET",
            url=f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            headers={"Accept": "application/json"},
        ))
        if resp.error or resp.status != 200:
            return []
        try:
            data = json.loads(resp.body)
            subs: set[str] = set()
            for record in data.get("passive_dns", []):
                hostname = record.get("hostname", "")
                if hostname.endswith(domain):
                    subs.add(hostname.strip().lower())
            return list(subs)
        except Exception:
            return []

    async def _threatminer(self, domain: str) -> list[str]:
        resp = await self._req.send(ProbeRequest(
            method="GET",
            url=f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5",
            headers={"Accept": "application/json"},
        ))
        if resp.error or resp.status != 200:
            return []
        try:
            data = json.loads(resp.body)
            results = data.get("results", [])
            return [r for r in results if isinstance(r, str) and r.endswith(domain)]
        except Exception:
            return []

    async def _anubisdb(self, domain: str) -> list[str]:
        resp = await self._req.send(ProbeRequest(
            method="GET",
            url=f"https://jldc.me/anubis/subdomains/{domain}",
            headers={"Accept": "application/json"},
        ))
        if resp.error or resp.status != 200:
            return []
        try:
            data = json.loads(resp.body)
            if isinstance(data, list):
                return [s for s in data if isinstance(s, str) and s.endswith(domain)]
            return []
        except Exception:
            return []

    async def _wayback(self, domain: str) -> list[str]:
        resp = await self._req.send(ProbeRequest(
            method="GET",
            url=(
                f"https://web.archive.org/cdx/search/cdx"
                f"?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=5000"
            ),
            headers={"Accept": "application/json"},
        ))
        if resp.error or resp.status != 200:
            return []
        try:
            entries = json.loads(resp.body)
            subs: set[str] = set()
            pattern = re.compile(rf"https?://([a-zA-Z0-9\-\.]+\.{re.escape(domain)})")
            for entry in entries[1:]:
                url_str = entry[0] if isinstance(entry, list) else ""
                m = pattern.match(url_str)
                if m:
                    subs.add(m.group(1).lower())
            return list(subs)
        except Exception:
            return []

    async def _hackertarget(self, domain: str) -> list[str]:
        resp = await self._req.send(ProbeRequest(
            method="GET",
            url=f"https://api.hackertarget.com/hostsearch/?q={domain}",
        ))
        if resp.error or resp.status != 200:
            return []
        subs: list[str] = []
        for line in resp.body.splitlines():
            parts = line.split(",")
            if parts and parts[0].strip().endswith(domain):
                subs.append(parts[0].strip().lower())
        return subs

    # ── Takeover detection ──────────────────────────────────────────────────

    async def _check_takeovers(self, subdomains: list[str]) -> AsyncGenerator[Finding, None]:
        """
        Pour chaque sous-domaine :
        1. Résout les enregistrements CNAME
        2. Matche contre _TAKEOVER_FINGERPRINTS
        3. Fetche le HTTP body et vérifie les body_markers
        4. Yield un finding CRITICAL si vulnérable
        """
        sem = asyncio.Semaphore(20)

        async def check_one(sub: str) -> Finding | None:
            async with sem:
                cnames = await self._resolve_cname(sub)
                if not cnames:
                    return None

                for cname in cnames:
                    for fp in _TAKEOVER_FINGERPRINTS:
                        if not re.search(fp["cname_pattern"], cname, re.I):
                            continue

                        # CNAME pattern match — vérifier le body HTTP
                        resp = await self._req.send(ProbeRequest(
                            method="GET",
                            url=f"https://{sub}",
                            headers={"User-Agent": "PhantomScan/takeover-check"},
                            timeout=10,
                            allow_redirects=True,
                        ))
                        if resp.error:
                            # Connexion refusée / timeout → dangling CNAME sans hôte
                            return Finding(
                                title=f"[TAKEOVER] Dangling CNAME → {fp['service']}",
                                severity=Severity.CRITICAL,
                                url=f"https://{sub}",
                                module="recon/subdomain",
                                description=(
                                    f"Le sous-domaine `{sub}` pointe via CNAME vers `{cname}` "
                                    f"({fp['service']}) mais la cible ne répond pas. "
                                    f"Prise de contrôle potentielle."
                                ),
                                evidence=f"CNAME: {sub} → {cname} | Connexion: {resp.error}",
                                cwe="CWE-350",
                                remediation=fp["remediation"],
                            )

                        body = resp.body
                        for marker in fp["body_markers"]:
                            if marker.lower() in body.lower():
                                return Finding(
                                    title=f"[TAKEOVER CONFIRMED] {fp['service']} — {sub}",
                                    severity=Severity.CRITICAL,
                                    url=f"https://{sub}",
                                    module="recon/subdomain",
                                    description=(
                                        f"Subdomain takeover confirmé sur `{sub}`. "
                                        f"CNAME pointe vers `{cname}` ({fp['service']}) "
                                        f"et le body contient le marqueur de service non revendiqué."
                                    ),
                                    evidence=f"CNAME: {sub} → {cname} | Marker: '{marker}'",
                                    cwe="CWE-350",
                                    remediation=fp["remediation"],
                                )
                return None

        tasks = [check_one(sub) for sub in subdomains]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Finding):
                yield r

    async def _resolve_cname(self, hostname: str) -> list[str]:
        """Retourne la chaîne CNAME complète pour un hostname. Liste vide si pas de CNAME."""
        if not _AIODNS_AVAILABLE:
            return []
        try:
            resolver = aiodns.DNSResolver(
                nameservers=[random.choice(_DNS_RESOLVERS)],
                timeout=3,
            )
            result = await resolver.query(hostname, "CNAME")
            # aiodns retourne une liste de CnameRecord(cname=...)
            return [r.cname.rstrip(".").lower() for r in result]
        except aiodns.error.DNSError:
            return []
        except Exception:
            return []

    # ── Brute-force DNS ─────────────────────────────────────────────────────

    async def _bruteforce(self, domain: str) -> list[str]:
        wordlist = list(_BRUTE_WORDLIST)
        wl_path: str | None = getattr(self._cfg, "wordlist_path", None)
        if wl_path:
            try:
                with open(wl_path) as f:
                    wordlist = [line.strip() for line in f if line.strip()]
            except OSError:
                pass
        candidates = [f"{word}.{domain}" for word in wordlist]
        wildcard_ips = await self._detect_wildcard(domain)
        alive = await self._resolve_all(candidates, wildcard_ips)
        return list(alive)

    # ── Wildcard detection ───────────────────────────────────────────────────

    async def _detect_wildcard(self, domain: str) -> set[str]:
        probe = f"phantomscan-nowildcard-{random.randint(100000, 999999)}.{domain}"
        ips = await self._resolve_one_raw(probe)
        return ips if ips else set()

    # ── Résolution DNS ──────────────────────────────────────────────────────

    async def _resolve_all(self, subdomains: list[str], wildcard_ips: set[str]) -> set[str]:
        sem = asyncio.Semaphore(100)

        async def check(sub: str) -> str | None:
            async with sem:
                ips = await self._resolve_one_raw(sub)
                if not ips:
                    return None
                if wildcard_ips and ips.issubset(wildcard_ips):
                    return None
                return sub

        results = await asyncio.gather(*[check(s) for s in subdomains])
        return {r for r in results if r is not None}

    async def _resolve_one_raw(self, hostname: str) -> set[str]:
        if _AIODNS_AVAILABLE:
            return await self._resolve_aiodns(hostname)
        return await self._resolve_socket(hostname)

    async def _resolve_aiodns(self, hostname: str) -> set[str]:
        resolver = aiodns.DNSResolver(
            nameservers=[random.choice(_DNS_RESOLVERS)],
            timeout=3,
        )
        try:
            result = await resolver.query(hostname, "A")
            return {r.host for r in result}
        except aiodns.error.DNSError:
            return set()
        except Exception:
            return set()

    async def _resolve_socket(self, hostname: str) -> set[str]:
        loop = asyncio.get_event_loop()
        try:
            infos = await loop.run_in_executor(
                None, lambda: socket.getaddrinfo(hostname, None)
            )
            return {info[4][0] for info in infos}
        except (socket.gaierror, OSError):
            return set()

    # ── Utilitaire ──────────────────────────────────────────────────────────

    @staticmethod
    def _extract_domain(target: str) -> str:
        parsed = urlparse(target)
        host = parsed.netloc or parsed.path
        return host.split(":")[0].lower()
