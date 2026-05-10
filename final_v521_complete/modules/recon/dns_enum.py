"""
PhantomScan — DNS Enumerator  v1.0
Énumération DNS complète : zone transfer, MX, TXT, SPF, DKIM, DMARC, NS, CAA.

Fonctionnalités :
  - Tentative de zone transfer (AXFR) sur chaque serveur NS
  - Récupération et analyse des enregistrements : A, AAAA, MX, NS, TXT, CAA, SOA
  - Parsing SPF (include, redirect, mécanismes permissifs)
  - Analyse DMARC (policy, reporting, alignement)
  - Détection DKIM (sélecteurs communs)
  - Détection de misconfiguration : SPF +all, DMARC manquant, zone transfer ouverte
  - Findings classés CRITICAL/HIGH/MEDIUM/INFO selon la sévérité
"""

from __future__ import annotations

import asyncio
import re
import socket
from typing import AsyncGenerator

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester
from phantomscan.output.reporter import Finding, Severity

# Sélecteurs DKIM courants à tester
_DKIM_SELECTORS = [
    "default", "google", "mail", "email", "dkim", "k1", "k2",
    "selector1", "selector2", "s1", "s2", "smtp", "key1", "key2",
    "mailjet", "sendgrid", "ses", "zoho", "protonmail",
]

_DNS_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]


class DNSEnumerator:
    """Énumération DNS complète pour un domaine cible."""

    def __init__(self, req: Requester, cfg: PhantomConfig) -> None:
        self._req = req
        self._cfg = cfg

    async def run(self, target: str) -> AsyncGenerator[Finding, None]:
        from urllib.parse import urlparse
        parsed = urlparse(target)
        domain = (parsed.netloc or parsed.path).split(":")[0].lower()

        # NS records + zone transfer
        async for f in self._check_zone_transfer(domain):
            yield f

        # Enregistrements standards
        async for f in self._enumerate_records(domain):
            yield f

        # SPF / DMARC / DKIM
        async for f in self._check_email_security(domain):
            yield f

    # ──────────────────────────────────────────────────────────────────────────
    # Zone Transfer (AXFR)
    # ──────────────────────────────────────────────────────────────────────────

    async def _check_zone_transfer(self, domain: str) -> AsyncGenerator[Finding, None]:
        ns_servers = await self._query_dns(domain, "NS")
        if not ns_servers:
            return

        yield Finding(
            title="DNS — Serveurs NS trouvés",
            url=f"dns://{domain}",
            severity=Severity.INFO,
            description=f"Serveurs NS pour {domain} : {', '.join(ns_servers)}",
            evidence="\n".join(ns_servers),
        )

        for ns in ns_servers:
            ns_clean = ns.rstrip(".")
            try:
                records = await asyncio.get_event_loop().run_in_executor(
                    None, self._axfr_attempt, domain, ns_clean
                )
                if records:
                    yield Finding(
                        title="DNS Zone Transfer (AXFR) — OUVERT",
                        url=f"dns://{domain}",
                        severity=Severity.CRITICAL,
                        description=(
                            f"Le serveur NS `{ns_clean}` autorise le zone transfer AXFR pour `{domain}`.\n"
                            "Cela expose l'intégralité des enregistrements DNS du domaine.\n"
                            "Un attaquant peut cartographier toute l'infrastructure DNS."
                        ),
                        evidence=f"Zone transfer réussi sur {ns_clean} :\n" + "\n".join(records[:50]),
                    )
            except Exception:
                pass

    @staticmethod
    def _axfr_attempt(domain: str, ns_host: str) -> list[str]:
        """Tentative AXFR synchrone via dnspython si disponible, sinon skip."""
        try:
            import dns.zone
            import dns.query
            import dns.resolver
            z = dns.zone.from_xfr(dns.query.xfr(ns_host, domain, timeout=10))
            return [str(r) for r in z.nodes.keys()]
        except ImportError:
            # dnspython non dispo — on skip silencieusement
            return []
        except Exception:
            return []

    # ──────────────────────────────────────────────────────────────────────────
    # Enregistrements standards
    # ──────────────────────────────────────────────────────────────────────────

    async def _enumerate_records(self, domain: str) -> AsyncGenerator[Finding, None]:
        record_types = ["A", "AAAA", "MX", "SOA", "CAA"]

        results: dict[str, list[str]] = {}
        tasks = {rtype: self._query_dns(domain, rtype) for rtype in record_types}

        for rtype, coro in tasks.items():
            records = await coro
            if records:
                results[rtype] = records

        if results:
            evidence_lines = []
            for rtype, recs in results.items():
                for r in recs:
                    evidence_lines.append(f"{rtype:8s}  {r}")

            yield Finding(
                title="DNS — Enregistrements énumérés",
                url=f"dns://{domain}",
                severity=Severity.INFO,
                description=f"Enregistrements DNS récupérés pour `{domain}`.",
                evidence="\n".join(evidence_lines),
            )

        # CAA manquant
        if "CAA" not in results:
            yield Finding(
                title="DNS — Enregistrement CAA absent",
                url=f"dns://{domain}",
                severity=Severity.LOW,
                description=(
                    f"Aucun enregistrement CAA trouvé pour `{domain}`.\n"
                    "Sans CAA, n'importe quelle autorité de certification peut émettre "
                    "un certificat TLS pour ce domaine."
                ),
                evidence=f"dig CAA {domain} — aucun résultat",
            )

        # MX — affichage
        if "MX" in results:
            yield Finding(
                title="DNS — Serveurs MX",
                url=f"dns://{domain}",
                severity=Severity.INFO,
                description=f"Serveurs mail pour {domain} : {', '.join(results['MX'])}",
                evidence="\n".join(results["MX"]),
            )

    # ──────────────────────────────────────────────────────────────────────────
    # Email security : SPF, DMARC, DKIM
    # ──────────────────────────────────────────────────────────────────────────

    async def _check_email_security(self, domain: str) -> AsyncGenerator[Finding, None]:
        txt_records = await self._query_dns(domain, "TXT")
        dmarc_records = await self._query_dns(f"_dmarc.{domain}", "TXT")

        # ── SPF ──────────────────────────────────────────────────────────────
        spf_records = [r for r in txt_records if r.startswith("v=spf1")]

        if not spf_records:
            yield Finding(
                title="DNS — SPF manquant",
                url=f"dns://{domain}",
                severity=Severity.MEDIUM,
                description=(
                    f"Aucun enregistrement SPF trouvé pour `{domain}`.\n"
                    "Sans SPF, le domaine peut être utilisé pour du spoofing d'email."
                ),
                evidence=f"dig TXT {domain} — aucun enregistrement v=spf1 trouvé",
            )
        else:
            spf = spf_records[0]
            yield Finding(
                title="DNS — SPF trouvé",
                url=f"dns://{domain}",
                severity=Severity.INFO,
                description=f"Enregistrement SPF : {spf}",
                evidence=spf,
            )

            # SPF +all = n'importe qui peut envoyer (misconfiguration critique)
            if "+all" in spf:
                yield Finding(
                    title="DNS — SPF permissif (+all)",
                    url=f"dns://{domain}",
                    severity=Severity.CRITICAL,
                    description=(
                        f"L'enregistrement SPF de `{domain}` contient `+all`.\n"
                        "Cela autorise n'importe quel serveur à envoyer des emails au nom du domaine.\n"
                        "Recommandation : remplacer `+all` par `~all` ou `-all`."
                    ),
                    evidence=f"SPF: {spf}",
                )
            elif "?all" in spf:
                yield Finding(
                    title="DNS — SPF neutre (?all)",
                    url=f"dns://{domain}",
                    severity=Severity.MEDIUM,
                    description=(
                        f"L'enregistrement SPF de `{domain}` utilise `?all` (neutre).\n"
                        "Cela ne protège pas contre le spoofing. Préférer `-all` ou `~all`."
                    ),
                    evidence=f"SPF: {spf}",
                )

            # SPF include excessifs (lookup limit = 10)
            includes = re.findall(r'include:\S+', spf)
            if len(includes) > 8:
                yield Finding(
                    title="DNS — SPF trop de lookups DNS",
                    url=f"dns://{domain}",
                    severity=Severity.LOW,
                    description=(
                        f"L'enregistrement SPF contient {len(includes)} directives `include:`.\n"
                        "La limite DNS est de 10 lookups — au-delà, les vérifications SPF échouent (PermError)."
                    ),
                    evidence=f"SPF includes: {', '.join(includes)}",
                )

        # ── DMARC ────────────────────────────────────────────────────────────
        dmarc = next((r for r in dmarc_records if r.startswith("v=DMARC1")), None)

        if not dmarc:
            yield Finding(
                title="DNS — DMARC manquant",
                url=f"dns://{domain}",
                severity=Severity.HIGH,
                description=(
                    f"Aucun enregistrement DMARC trouvé pour `_dmarc.{domain}`.\n"
                    "Sans DMARC, les fournisseurs email ne savent pas comment traiter "
                    "les emails qui échouent SPF/DKIM → risque de spoofing."
                ),
                evidence=f"dig TXT _dmarc.{domain} — aucun résultat",
            )
        else:
            yield Finding(
                title="DNS — DMARC trouvé",
                url=f"dns://{domain}",
                severity=Severity.INFO,
                description=f"Enregistrement DMARC pour {domain}.",
                evidence=dmarc,
            )

            # Policy none = monitoring only, pas de protection réelle
            policy_match = re.search(r'p=(none|quarantine|reject)', dmarc)
            if policy_match:
                policy = policy_match.group(1)
                if policy == "none":
                    yield Finding(
                        title="DNS — DMARC policy=none (pas de protection)",
                        url=f"dns://{domain}",
                        severity=Severity.MEDIUM,
                        description=(
                            f"La politique DMARC est `p=none` — mode monitoring uniquement.\n"
                            "Les emails qui échouent SPF/DKIM sont quand même délivrés.\n"
                            "Recommandation : passer à `p=quarantine` ou `p=reject`."
                        ),
                        evidence=f"DMARC: {dmarc}",
                    )

        # ── DKIM ─────────────────────────────────────────────────────────────
        dkim_found: list[str] = []
        tasks = {
            sel: self._query_dns(f"{sel}._domainkey.{domain}", "TXT")
            for sel in _DKIM_SELECTORS
        }
        for selector, coro in tasks.items():
            records = await coro
            for r in records:
                if "p=" in r or "k=rsa" in r.lower():
                    dkim_found.append(f"{selector}: {r[:120]}")

        if dkim_found:
            yield Finding(
                title="DNS — Enregistrements DKIM trouvés",
                url=f"dns://{domain}",
                severity=Severity.INFO,
                description=f"{len(dkim_found)} sélecteur(s) DKIM trouvé(s) pour {domain}.",
                evidence="\n".join(dkim_found),
            )
        else:
            yield Finding(
                title="DNS — DKIM non détecté",
                url=f"dns://{domain}",
                severity=Severity.MEDIUM,
                description=(
                    f"Aucun enregistrement DKIM trouvé parmi les sélecteurs communs testés.\n"
                    "Sans DKIM, les emails ne sont pas signés cryptographiquement → spoofing facilité."
                ),
                evidence=f"Sélecteurs testés : {', '.join(_DKIM_SELECTORS)}",
            )

    # ──────────────────────────────────────────────────────────────────────────
    # Résolution DNS générique
    # ──────────────────────────────────────────────────────────────────────────

    async def _query_dns(self, name: str, rtype: str) -> list[str]:
        """Résolution DNS via dnspython si dispo, sinon socket (A uniquement)."""
        loop = asyncio.get_event_loop()
        try:
            return await loop.run_in_executor(None, self._dns_lookup_sync, name, rtype)
        except Exception:
            return []

    @staticmethod
    def _dns_lookup_sync(name: str, rtype: str) -> list[str]:
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.nameservers = _DNS_RESOLVERS
            resolver.timeout = 5
            resolver.lifetime = 10
            answers = resolver.resolve(name, rtype)
            return [r.to_text() for r in answers]
        except ImportError:
            pass
        except Exception:
            return []

        # Fallback socket pour A records
        if rtype == "A":
            try:
                infos = socket.getaddrinfo(name, None, socket.AF_INET)
                return list({info[4][0] for info in infos})
            except Exception:
                return []

        return []
