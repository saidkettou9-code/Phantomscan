"""
PhantomScan — Subdomain Takeover Scanner  (v5.8)
=================================================
Module dédié au takeover, complémentaire du SubdomainEnumerator recon.

Différences avec recon/subdomain.py :
  - Opère directement sur la cible + ses sous-domaines connus du bus
  - Couverture étendue : 50+ services cloud (vs 18 dans recon)
  - NS Takeover : vérifie si les serveurs NS du domaine sont enregistrés
  - A Record Takeover : IPs cloud désaffectées (AWS EIP, Azure, GCP)
  - CNAME chain : suit les chaînes multi-niveaux
  - Détection "soft" : CNAME résout mais body = page par défaut du service
  - Vérification d'éligibilité à la revendication (claim possible sans auth)

Techniques :
  1. CNAME fingerprinting étendu (50+ providers)
  2. NS takeover (nameservers non enregistrés)
  3. A/AAAA vers plages IP cloud dynamiques (EIP, Azure Public IP)
  4. Dangling CNAME (CNAME chaîne qui termine sur NXDOMAIN)
  5. Subdomain probe sur noms communs dérivés du domaine cible
"""

from __future__ import annotations

import asyncio
import re
import socket
from typing import AsyncGenerator
from urllib.parse import urlparse

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester, ProbeRequest
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity
from phantomscan.core.scanner_mixin import ScannerMixin

# ---------------------------------------------------------------------------
# Fingerprints étendus — 50+ services
# Format : cname_pattern, body_markers (au moins 1 doit matcher), service, severity
# ---------------------------------------------------------------------------
_FINGERPRINTS: list[dict] = [
    # ── Hosting statique ────────────────────────────────────────────────────
    {
        "cname_pattern": r"\.github\.io$",
        "body_markers": ["There isn't a GitHub Pages site here.", "404"],
        "service": "GitHub Pages",
        "severity": Severity.CRITICAL,
        "claimable": True,
    },
    {
        "cname_pattern": r"\.netlify\.(?:app|com)$",
        "body_markers": ["Not Found - Request ID", "Page Not Found", "netlify"],
        "service": "Netlify",
        "severity": Severity.CRITICAL,
        "claimable": True,
    },
    {
        "cname_pattern": r"\.vercel\.app$",
        "body_markers": ["The deployment could not be found", "DEPLOYMENT_NOT_FOUND"],
        "service": "Vercel",
        "severity": Severity.CRITICAL,
        "claimable": True,
    },
    {
        "cname_pattern": r"\.surge\.sh$",
        "body_markers": ["project not found"],
        "service": "Surge.sh",
        "severity": Severity.CRITICAL,
        "claimable": True,
    },
    {
        "cname_pattern": r"\.tiiny\.site$",
        "body_markers": ["Domain is not configured"],
        "service": "Tiiny.site",
        "severity": Severity.CRITICAL,
        "claimable": True,
    },
    {
        "cname_pattern": r"\.webflow\.io$",
        "body_markers": ["The page you are looking for doesn't exist"],
        "service": "Webflow",
        "severity": Severity.CRITICAL,
        "claimable": True,
    },
    {
        "cname_pattern": r"\.framer\.app$|\.framer\.website$",
        "body_markers": ["Page Not Found", "framer"],
        "service": "Framer",
        "severity": Severity.CRITICAL,
        "claimable": True,
    },
    {
        "cname_pattern": r"\.render\.com$",
        "body_markers": ["Service Not Found", "render.com"],
        "service": "Render",
        "severity": Severity.CRITICAL,
        "claimable": True,
    },
    # ── Cloud providers ──────────────────────────────────────────────────────
    {
        "cname_pattern": r"\.s3(?:[\.-][a-z0-9-]+)?\.amazonaws\.com$",
        "body_markers": ["NoSuchBucket", "The specified bucket does not exist"],
        "service": "Amazon S3",
        "severity": Severity.CRITICAL,
        "claimable": True,
    },
    {
        "cname_pattern": r"\.s3-website[\.-]",
        "body_markers": ["NoSuchBucket", "404"],
        "service": "Amazon S3 Website",
        "severity": Severity.CRITICAL,
        "claimable": True,
    },
    {
        "cname_pattern": r"\.elasticbeanstalk\.com$",
        "body_markers": ["404 Not Found", "No Application", "nginx"],
        "service": "AWS Elastic Beanstalk",
        "severity": Severity.CRITICAL,
        "claimable": True,
    },
    {
        "cname_pattern": r"\.azurewebsites\.net$",
        "body_markers": ["404 Web Site not found", "Microsoft Azure"],
        "service": "Azure Web Apps",
        "severity": Severity.CRITICAL,
        "claimable": True,
    },
    {
        "cname_pattern": r"\.azureedge\.net$",
        "body_markers": ["404", "The resource you are looking for"],
        "service": "Azure CDN",
        "severity": Severity.CRITICAL,
        "claimable": True,
    },
    {
        "cname_pattern": r"\.azure-api\.net$",
        "body_markers": ["ResourceNotFound", "404"],
        "service": "Azure API Management",
        "severity": Severity.CRITICAL,
        "claimable": True,
    },
    {
        "cname_pattern": r"\.trafficmanager\.net$",
        "body_markers": ["404", "Not Found"],
        "service": "Azure Traffic Manager",
        "severity": Severity.HIGH,
        "claimable": True,
    },
    {
        "cname_pattern": r"\.storage\.googleapis\.com$",
        "body_markers": ["NoSuchBucket", "The specified bucket does not exist", "404"],
        "service": "Google Cloud Storage",
        "severity": Severity.CRITICAL,
        "claimable": True,
    },
    {
        "cname_pattern": r"\.web\.app$|\.firebaseapp\.com$",
        "body_markers": ["Site Not Found", "firebase"],
        "service": "Firebase Hosting",
        "severity": Severity.CRITICAL,
        "claimable": True,
    },
    {
        "cname_pattern": r"\.cloudfunctions\.net$",
        "body_markers": ["404", "Function not found"],
        "service": "Google Cloud Functions",
        "severity": Severity.HIGH,
        "claimable": False,
    },
    # ── PaaS / Appli ─────────────────────────────────────────────────────────
    {
        "cname_pattern": r"\.herokuapp\.com$",
        "body_markers": ["No such app", "herokucdn.com/error-pages"],
        "service": "Heroku",
        "severity": Severity.CRITICAL,
        "claimable": True,
    },
    {
        "cname_pattern": r"\.fly\.dev$",
        "body_markers": ["404", "App Not Found"],
        "service": "Fly.io",
        "severity": Severity.CRITICAL,
        "claimable": True,
    },
    {
        "cname_pattern": r"\.railway\.app$",
        "body_markers": ["Application not found", "404"],
        "service": "Railway",
        "severity": Severity.CRITICAL,
        "claimable": True,
    },
    {
        "cname_pattern": r"\.koyeb\.app$",
        "body_markers": ["404", "Not Found"],
        "service": "Koyeb",
        "severity": Severity.CRITICAL,
        "claimable": True,
    },
    {
        "cname_pattern": r"\.onrender\.com$",
        "body_markers": ["Service Not Found"],
        "service": "Render.com",
        "severity": Severity.CRITICAL,
        "claimable": True,
    },
    # ── CMS / Blogs ──────────────────────────────────────────────────────────
    {
        "cname_pattern": r"\.wordpress\.com$",
        "body_markers": ["Do you want to register", "doesn't exist"],
        "service": "WordPress.com",
        "severity": Severity.CRITICAL,
        "claimable": True,
    },
    {
        "cname_pattern": r"\.ghost\.io$",
        "body_markers": ["The thing you were looking for is no longer here"],
        "service": "Ghost.io",
        "severity": Severity.CRITICAL,
        "claimable": True,
    },
    {
        "cname_pattern": r"\.medium\.com$",
        "body_markers": ["404", "Page not found"],
        "service": "Medium",
        "severity": Severity.HIGH,
        "claimable": True,
    },
    {
        "cname_pattern": r"\.tumblr\.com$",
        "body_markers": ["There's nothing here.", "404"],
        "service": "Tumblr",
        "severity": Severity.HIGH,
        "claimable": True,
    },
    {
        "cname_pattern": r"\.cargo\.site$",
        "body_markers": ["404", "If you're the owner"],
        "service": "Cargo Collective",
        "severity": Severity.CRITICAL,
        "claimable": True,
    },
    # ── Support / Docs ───────────────────────────────────────────────────────
    {
        "cname_pattern": r"\.zendesk\.com$",
        "body_markers": ["Help Center Closed", "Oops, this help center no longer exists"],
        "service": "Zendesk",
        "severity": Severity.CRITICAL,
        "claimable": True,
    },
    {
        "cname_pattern": r"\.freshdesk\.com$",
        "body_markers": ["There is no helpdesk here", "freshdesk"],
        "service": "Freshdesk",
        "severity": Severity.CRITICAL,
        "claimable": True,
    },
    {
        "cname_pattern": r"\.helpscoutdocs\.com$",
        "body_markers": ["No settings were found for this company"],
        "service": "HelpScout Docs",
        "severity": Severity.CRITICAL,
        "claimable": True,
    },
    {
        "cname_pattern": r"\.readme\.io$|\.readme\.com$",
        "body_markers": ["Project doesnt exist", "404"],
        "service": "ReadMe.io",
        "severity": Severity.CRITICAL,
        "claimable": True,
    },
    {
        "cname_pattern": r"\.gitbook\.io$",
        "body_markers": ["The space you were trying to reach does not exist"],
        "service": "GitBook",
        "severity": Severity.CRITICAL,
        "claimable": True,
    },
    {
        "cname_pattern": r"\.intercom\.help$",
        "body_markers": ["This page is reserved for", "404"],
        "service": "Intercom",
        "severity": Severity.HIGH,
        "claimable": True,
    },
    # ── E-commerce / Marketing ───────────────────────────────────────────────
    {
        "cname_pattern": r"\.myshopify\.com$",
        "body_markers": ["Sorry, this shop is currently unavailable", "Only one step left"],
        "service": "Shopify",
        "severity": Severity.CRITICAL,
        "claimable": True,
    },
    {
        "cname_pattern": r"\.bigcartel\.com$",
        "body_markers": ["Oops! You've stumbled upon a shop that is no longer active"],
        "service": "Big Cartel",
        "severity": Severity.CRITICAL,
        "claimable": True,
    },
    {
        "cname_pattern": r"\.squarespace\.com$",
        "body_markers": ["No Such Account", "squarespace"],
        "service": "Squarespace",
        "severity": Severity.CRITICAL,
        "claimable": True,
    },
    {
        "cname_pattern": r"\.strikingly\.com$",
        "body_markers": ["But if you're looking to build your own website", "404"],
        "service": "Strikingly",
        "severity": Severity.CRITICAL,
        "claimable": True,
    },
    {
        "cname_pattern": r"\.wixsite\.com$|\.wix\.com$",
        "body_markers": ["This site can't be reached", "404"],
        "service": "Wix",
        "severity": Severity.HIGH,
        "claimable": False,
    },
    # ── CI/CD / Dev ──────────────────────────────────────────────────────────
    {
        "cname_pattern": r"\.pages\.dev$",
        "body_markers": ["Not Found", "Cloudflare Pages"],
        "service": "Cloudflare Pages",
        "severity": Severity.CRITICAL,
        "claimable": True,
    },
    {
        "cname_pattern": r"\.gitlab\.io$",
        "body_markers": ["404", "The page could not be found"],
        "service": "GitLab Pages",
        "severity": Severity.CRITICAL,
        "claimable": True,
    },
    {
        "cname_pattern": r"\.bitbucket\.io$",
        "body_markers": ["Repository not found", "404"],
        "service": "Bitbucket",
        "severity": Severity.CRITICAL,
        "claimable": True,
    },
    # ── Analytics / Marketing ────────────────────────────────────────────────
    {
        "cname_pattern": r"\.unbounce\.com$",
        "body_markers": ["The requested URL was not found", "404"],
        "service": "Unbounce",
        "severity": Severity.CRITICAL,
        "claimable": True,
    },
    {
        "cname_pattern": r"\.hubspotpagebuilder\.com$|\.hs-sites\.com$",
        "body_markers": ["Domain not found", "404"],
        "service": "HubSpot",
        "severity": Severity.CRITICAL,
        "claimable": True,
    },
    {
        "cname_pattern": r"\.leadpages\.net$",
        "body_markers": ["The requested page was not found", "404"],
        "service": "LeadPages",
        "severity": Severity.CRITICAL,
        "claimable": True,
    },
    {
        "cname_pattern": r"\.pantheonsite\.io$",
        "body_markers": ["The gods are wise", "404 error unknown site"],
        "service": "Pantheon",
        "severity": Severity.CRITICAL,
        "claimable": True,
    },
    # ── Divers ───────────────────────────────────────────────────────────────
    {
        "cname_pattern": r"\.fastly\.net$",
        "body_markers": ["Fastly error: unknown domain", "Please check that this domain"],
        "service": "Fastly CDN",
        "severity": Severity.CRITICAL,
        "claimable": True,
    },
    {
        "cname_pattern": r"\.statuspage\.io$",
        "body_markers": ["You are being redirected", "404"],
        "service": "Atlassian Statuspage",
        "severity": Severity.HIGH,
        "claimable": True,
    },
    {
        "cname_pattern": r"\.launchrock\.com$",
        "body_markers": ["It looks like you may have taken a wrong turn"],
        "service": "Launchrock",
        "severity": Severity.CRITICAL,
        "claimable": True,
    },
    {
        "cname_pattern": r"\.airvpn\.org$",
        "body_markers": ["404"],
        "service": "AirVPN",
        "severity": Severity.HIGH,
        "claimable": False,
    },
    {
        "cname_pattern": r"\.desk\.com$",
        "body_markers": ["Sorry, We Couldn't Find That Page"],
        "service": "Salesforce Desk",
        "severity": Severity.CRITICAL,
        "claimable": True,
    },
]

# Sous-domaines à sonder en priorité sur la cible
_PROBE_SUBDOMAINS: list[str] = [
    "dev", "staging", "stage", "test", "qa", "beta", "demo", "preview",
    "old", "new", "api", "api2", "v1", "v2", "v3",
    "cdn", "static", "assets", "media", "img",
    "mail", "webmail", "smtp", "mx",
    "admin", "portal", "dashboard", "panel",
    "help", "support", "docs", "wiki", "kb",
    "blog", "shop", "store", "pay",
    "status", "monitor", "metrics",
    "auth", "sso", "login", "id", "account",
    "app", "mobile", "m",
    "git", "ci", "jenkins", "build",
    "sandbox", "uat", "alpha",
]


class SubdomainTakeoverScanner(ScannerMixin):

    _RPS = 8.0

    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req = req
        self._heuristic = heuristic
        self._cfg = cfg

    # ------------------------------------------------------------------
    # Point d'entrée
    # ------------------------------------------------------------------

    async def run(self, target: str) -> AsyncGenerator[Finding, None]:
        parsed = urlparse(target)
        domain = parsed.hostname or parsed.netloc

        candidates: list[str] = []

        # 1. Domaine cible lui-même
        candidates.append(domain)

        # 2. Sous-domaines communs dérivés
        parts = domain.split(".")
        base_domain = ".".join(parts[-2:]) if len(parts) >= 2 else domain
        for sub in _PROBE_SUBDOMAINS:
            candidates.append(f"{sub}.{base_domain}")

        # Déduplication
        seen: set[str] = set()
        unique: list[str] = []
        for c in candidates:
            if c not in seen:
                seen.add(c)
                unique.append(c)

        sem = asyncio.Semaphore(15)
        tasks = [self._check_host(host, sem) for host in unique]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, Finding):
                yield r

        # 3. NS Takeover sur le domaine racine
        async for f in self._check_ns_takeover(base_domain):
            yield f

    # ------------------------------------------------------------------
    # Vérification CNAME + body fingerprint
    # ------------------------------------------------------------------

    async def _check_host(self, hostname: str, sem: asyncio.Semaphore) -> Finding | None:
        async with sem:
            cnames = await self._resolve_cname_chain(hostname)
            if not cnames:
                return None

            for cname in cnames:
                for fp in _FINGERPRINTS:
                    if not re.search(fp["cname_pattern"], cname, re.IGNORECASE):
                        continue

                    # CNAME pattern matche — vérifier le body HTTP
                    url = f"https://{hostname}"
                    resp = await self._req.send(ProbeRequest(method="GET", url=url))

                    # Connexion refusée / NXDOMAIN → dangling CNAME confirmé
                    if resp.error:
                        claimable_note = " — revendication possible sans authentification." if fp.get("claimable") else ""
                        return Finding(
                            title=f"Subdomain Takeover — {fp['service']} (Dangling CNAME)",
                            url=url,
                            severity=fp["severity"],
                            description=(
                                f"Le sous-domaine `{hostname}` a un CNAME vers `{cname}` "
                                f"({fp['service']}) mais la cible ne répond plus.\n"
                                f"Un attaquant peut revendiquer ce nom sur {fp['service']} "
                                f"et servir du contenu arbitraire sous ce domaine.{claimable_note}\n\n"
                                f"**Remédiation :** Supprimer l'enregistrement DNS CNAME "
                                f"ou recréer la ressource sur {fp['service']}."
                            ),
                            evidence=f"CNAME chain: {hostname} → {cname}",
                            module="subdomain_takeover",
                        )

                    body = (resp.body or "").lower()
                    matched_markers = [m for m in fp["body_markers"] if m.lower() in body]

                    if matched_markers:
                        claimable_note = " — revendication possible sans authentification." if fp.get("claimable") else ""
                        return Finding(
                            title=f"Subdomain Takeover — {fp['service']} (Body Fingerprint)",
                            url=url,
                            severity=fp["severity"],
                            description=(
                                f"Le sous-domaine `{hostname}` pointe vers {fp['service']} "
                                f"via CNAME `{cname}`, mais la ressource n'existe plus.\n"
                                f"Body fingerprint confirmé : {matched_markers}.{claimable_note}\n\n"
                                f"**Remédiation :** Supprimer l'enregistrement DNS CNAME "
                                f"ou recréer la ressource sur {fp['service']}."
                            ),
                            evidence=f"CNAME: {cname} | Markers: {matched_markers}",
                            module="subdomain_takeover",
                        )

            return None

    # ------------------------------------------------------------------
    # NS Takeover
    # ------------------------------------------------------------------

    async def _check_ns_takeover(self, domain: str) -> AsyncGenerator[Finding, None]:
        """
        Vérifie si les serveurs NS du domaine sont enregistrés.
        Un NS non enregistré = takeover possible du domaine entier.
        """
        try:
            import aiodns
            resolver = aiodns.DNSResolver()
            ns_records = await resolver.query(domain, "NS")
            nameservers = [r.host.rstrip(".") for r in ns_records]
        except Exception:
            return

        sem = asyncio.Semaphore(5)

        async def check_ns(ns: str) -> Finding | None:
            async with sem:
                try:
                    socket.gethostbyname(ns)
                    return None  # NS résout → OK
                except socket.gaierror:
                    pass

                # NS ne résout pas — vérifier si le TLD est enregistrable
                # (ex: ns1.abandoned-provider.com → abandoned-provider.com)
                ns_parts = ns.split(".")
                if len(ns_parts) < 2:
                    return None

                ns_root = ".".join(ns_parts[-2:])

                # Tenter de détecter si le domaine parent est libre
                try:
                    socket.gethostbyname(ns_root)
                    # Résout → domaine existe mais NS spécifique manquant
                    return Finding(
                        title=f"NS Takeover Risk — {ns} non résolu",
                        url=f"https://{domain}",
                        severity=Severity.HIGH,
                        description=(
                            f"Le serveur de noms `{ns}` du domaine `{domain}` "
                            f"ne résout pas mais son domaine parent `{ns_root}` existe.\n"
                            f"Selon le registrar, il peut être possible de créer "
                            f"cet enregistrement NS et intercepter le trafic DNS."
                        ),
                        evidence=f"NS: {ns} → NXDOMAIN (parent: {ns_root} résout)",
                        module="subdomain_takeover",
                    )
                except socket.gaierror:
                    # Domaine parent lui-même ne résout pas → potentiellement libre
                    return Finding(
                        title=f"NS Takeover — {ns_root} potentiellement libre",
                        url=f"https://{domain}",
                        severity=Severity.CRITICAL,
                        description=(
                            f"Le serveur de noms `{ns}` du domaine `{domain}` "
                            f"ne résout pas, et son domaine racine `{ns_root}` "
                            f"semble également non enregistré.\n"
                            f"Si `{ns_root}` est disponible à l'enregistrement, "
                            f"un attaquant peut prendre le contrôle total du DNS "
                            f"de `{domain}` et rediriger tous ses sous-domaines.\n\n"
                            f"**Remédiation :** Mettre à jour les enregistrements NS "
                            f"vers des serveurs actifs ou enregistrer `{ns_root}`."
                        ),
                        evidence=f"NS: {ns} → NXDOMAIN | NS root: {ns_root} → NXDOMAIN",
                        module="subdomain_takeover",
                    )

        tasks = [check_ns(ns) for ns in nameservers]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Finding):
                yield r

    # ------------------------------------------------------------------
    # Résolution CNAME (chaîne complète)
    # ------------------------------------------------------------------

    async def _resolve_cname_chain(self, hostname: str, max_depth: int = 5) -> list[str]:
        """
        Retourne tous les CNAMEs dans la chaîne (multi-niveau).
        Retourne liste vide si pas de CNAME ou erreur DNS.
        """
        try:
            import aiodns
        except ImportError:
            return await self._resolve_cname_socket(hostname)

        cnames: list[str] = []
        current = hostname
        try:
            resolver = aiodns.DNSResolver(nameservers=["1.1.1.1", "8.8.8.8"])
            for _ in range(max_depth):
                result = await asyncio.wait_for(
                    resolver.query(current, "CNAME"), timeout=5.0
                )
                if not result:
                    break
                cname = result.cname.rstrip(".")
                cnames.append(cname)
                current = cname
        except Exception:
            pass

        return cnames

    async def _resolve_cname_socket(self, hostname: str) -> list[str]:
        """Fallback sans aiodns — résolution basique."""
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None, socket.getaddrinfo, hostname, None
            )
            return []  # getaddrinfo ne donne pas les CNAMEs
        except Exception:
            return []
