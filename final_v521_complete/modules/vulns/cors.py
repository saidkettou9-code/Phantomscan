"""
PhantomScan — CORS Misconfiguration Scanner
Teste les politiques CORS laxistes : reflection d'origine, wildcard credentials,
null origin, sous-domaines arbitraires, origins tricky.
"""

from __future__ import annotations

import re
from typing import AsyncGenerator
from urllib.parse import urlparse

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester, ProbeRequest
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity
from phantomscan.core.scanner_mixin import ScannerMixin


class CORSScanner(ScannerMixin):

    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req = req
        self._heuristic = heuristic
        self._cfg = cfg

    async def run(self, target: str) -> AsyncGenerator[Finding, None]:
        parsed = urlparse(target)
        scheme = parsed.scheme
        netloc = parsed.netloc
        domain = parsed.hostname or netloc

        # Construit les origines à tester
        origins = self._build_test_origins(scheme, domain)

        # Endpoints à tester (root + API communs)
        endpoints = [target]
        for path in ("/api", "/api/v1", "/api/v2", "/graphql", "/data"):
            endpoints.append(f"{scheme}://{netloc}{path}")

        for endpoint in endpoints:
            async for f in self._probe_cors(endpoint, origins, domain):
                yield f

    def _build_test_origins(self, scheme: str, domain: str) -> list[tuple[str, str]]:
        """
        Retourne une liste (origin, label) à tester.
        Chaque technique cible un type de misconfiguration différent.
        """
        origins = [
            # 1. Reflection basique — l'app reflète n'importe quelle origine
            (f"{scheme}://evil.com", "arbitrary_origin"),
            # 2. Prefix match — l'app vérifie juste que l'origin commence par le bon domaine
            (f"{scheme}://{domain}.evil.com", "prefix_bypass"),
            # 3. Suffix match — l'app vérifie juste la fin de l'origin
            (f"{scheme}://evil{domain}", "suffix_bypass"),
            # 4. Subdomain wildcard — sous-domaine arbitraire accepté
            (f"{scheme}://attacker.{domain}", "subdomain_wildcard"),
            # 5. null origin — whitelist null (iframe sandbox, file://)
            ("null", "null_origin"),
            # 6. HTTP → HTTPS downgrade
            ("http://" + domain if scheme == "https" else "https://" + domain, "scheme_downgrade"),
            # 7. Unicode trick — homoglyphe dans le domaine
            (f"{scheme}://{domain.replace('o', 'ο') if 'o' in domain else domain + 'ο'}.evil.com", "unicode_trick"),
        ]
        return origins

    async def _probe_cors(
        self,
        url: str,
        origins: list[tuple[str, str]],
        target_domain: str,
    ) -> AsyncGenerator[Finding, None]:

        for origin, label in origins:
            resp = await self._req.send(ProbeRequest(
                method="GET",
                url=url,
                headers={"Origin": origin},
            ))
            if resp.error:
                continue

            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
            acam = resp.headers.get("Access-Control-Allow-Methods", "")

            if not acao:
                continue

            # Wildcard avec credentials → impossible selon spec, mais certaines libs le font
            if acao == "*" and acac == "true":
                yield Finding(
                    title="CORS: Wildcard + credentials (spec violation — likely broken middleware)",
                    severity=Severity.HIGH,
                    url=url,
                    module="vulns/cors",
                    description=(
                        "Access-Control-Allow-Origin: * combiné avec "
                        "Access-Control-Allow-Credentials: true viole la spec CORS. "
                        "Certains frameworks malconfigurés acceptent quand même les requests."
                    ),
                    evidence=f"ACAO: {acao} | ACAC: {acac}",
                    cwe="CWE-942",
                    remediation="Ne jamais utiliser * avec credentials. Utiliser une whitelist d'origines explicites.",
                )
                continue

            # Origin reflétée avec credentials — critique
            if acao == origin and acac == "true":
                # v5.20 — re-probe pour confirmer (évite FP sur flap headers)
                resp2 = await self.re_probe(url, headers={"Origin": origin}, delay_s=0.3)
                if resp2 is None or resp2.headers.get("Access-Control-Allow-Origin","") != origin:
                    continue  # non reproductible → FP
                sev, desc = self._classify_reflection(label, origin, target_domain)
                # Anti-FP pour subdomain_wildcard : ce vecteur nécessite un XSS ou compromission
                # d'un sous-domaine — ne pas le remonter en CRITICAL, HIGH suffit
                if label == "subdomain_wildcard" and sev == Severity.CRITICAL:
                    sev = Severity.HIGH
                yield Finding(
                    title=f"CORS Misconfiguration: {label} — credentials exposed",
                    severity=sev,
                    url=url,
                    module="vulns/cors",
                    description=desc,
                    evidence=f"Origin: {origin}\nAccess-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: true\nMethods: {acam}",
                    cwe="CWE-942",
                    remediation=(
                        "Valider l'origine via une whitelist stricte côté serveur. "
                        "Ne pas utiliser de regex ou de comparaison par prefix/suffix. "
                        "Ne pas autoriser 'null' comme origine valide."
                    ),
                )

            # Origin reflétée sans credentials — signaler seulement si la réponse
            # contient un Set-Cookie de session (sinon souvent intentionnel/inoffensif)
            elif acao == origin and acac != "true":
                if label in ("arbitrary_origin", "null_origin", "scheme_downgrade"):  # v5.9-fp: +scheme_downgrade
                    has_session_cookie = any(
                        "session" in v.lower() or "auth" in v.lower() or "token" in v.lower()
                        for v in resp.headers.get("Set-Cookie", "").split(";")
                    )
                    if has_session_cookie:
                        yield Finding(
                            title=f"CORS: Origin reflected without credentials ({label}) — session cookie present",
                            severity=Severity.MEDIUM,
                            url=url,
                            module="vulns/cors",
                            description=(
                                f"L'origine '{origin}' est réfléchie dans ACAO sans credentials, "
                                "mais la réponse contient un cookie de session. "
                                "Exploitable pour lire des données via cross-origin requests."
                            ),
                            evidence=f"Origin: {origin} → ACAO: {acao} | Set-Cookie présent",
                            cwe="CWE-942",
                            remediation="Restreindre ACAO aux origines légitimes.",
                        )

            # null + credentials : combinaison spécifique à tester explicitement
            # même si l'origin n'est pas "reflétée" au sens strict (ACAO = "null")
            # Guard: ne fire que si le bloc credentials ci-dessus ne l'a pas déjà reporté
            elif label == "null_origin" and acao == "null" and acac == "true":
                yield Finding(
                    title="CORS: Origin null acceptée avec credentials — sandbox/iframe exploit",
                    severity=Severity.HIGH,
                    url=url,
                    module="vulns/cors",
                    description=(
                        "Le serveur accepte explicitement l'origine 'null' avec "
                        "Access-Control-Allow-Credentials: true. "
                        "Exploitable depuis un iframe sandboxé (<iframe sandbox>) ou via file:// "
                        "pour effectuer des requêtes authentifiées cross-origin et lire la réponse. "
                        "L'origine 'null' ne représente aucun contexte de confiance."
                    ),
                    evidence=f"Origin: null → ACAO: null | ACAC: true | Methods: {acam}",
                    cwe="CWE-942",
                    remediation=(
                        "Ne jamais autoriser 'null' comme origine valide. "
                        "Retirer 'null' de toute whitelist CORS. "
                        "Utiliser des origines HTTPS explicites uniquement."
                    ),
                )

            # Preflight OPTIONS — tester si des méthodes dangereuses sont autorisées
            # Seulement si pas déjà signalé via credentials (pour éviter le bruit)
            # FIX fp: acao == "*" sans credentials n'est pas exploitable selon la spec CORS
            # (les navigateurs refusent d'envoyer les cookies/auth sur les requêtes wildcard).
            # On exige une origin explicitement réfléchie ET non-wildcard.
            if (
                acao == origin
                and acao != "*"
                and acac != "true"
                and any(m in acam.upper() for m in ("PUT", "DELETE", "PATCH"))
            ):
                yield Finding(
                    title="CORS: Dangerous methods allowed cross-origin",
                    severity=Severity.HIGH,
                    url=url,
                    module="vulns/cors",
                    description=(
                        f"Les méthodes {acam} sont autorisées depuis l'origine '{origin}'. "
                        "Un attaquant peut effectuer des mutations depuis un domaine tiers."
                    ),
                    evidence=f"ACAO: {acao} | Methods: {acam}",
                    cwe="CWE-942",
                    remediation="Limiter les méthodes CORS aux seules méthodes nécessaires (GET si read-only).",
                )

        # OPTIONS preflight global
        async for f in self._probe_preflight(url):
            yield f

    async def _probe_preflight(self, url: str) -> AsyncGenerator[Finding, None]:
        """Probe OPTIONS pour détecter Access-Control-Allow-Methods trop permissif."""
        resp = await self._req.send(ProbeRequest(
            method="OPTIONS",
            url=url,
            headers={
                "Origin": "https://evil.com",
                "Access-Control-Request-Method": "DELETE",
                "Access-Control-Request-Headers": "Authorization",
            },
        ))
        if resp.error:
            return

        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acam = resp.headers.get("Access-Control-Allow-Methods", "")
        acah = resp.headers.get("Access-Control-Allow-Headers", "")

        # acao == "*" ne permet pas de transmettre les credentials selon la spec CORS
        # (le browser refuse) → ne signaler que si l'origin est explicitement reflétée
        if acao and acao != "*" and "authorization" in acah.lower() and any(
            m in acam.upper() for m in ("DELETE", "PUT", "PATCH")
        ):
            yield Finding(
                title="CORS Preflight: Authorization header + dangerous methods allowed",
                severity=Severity.HIGH,
                url=url,
                module="vulns/cors",
                description=(
                    "Le preflight CORS autorise le header Authorization avec des méthodes "
                    f"dangereuses ({acam}). Exploitable pour des requêtes authentifiées cross-origin."
                ),
                evidence=f"ACAO: {acao}\nMethods: {acam}\nHeaders: {acah}",
                cwe="CWE-942",
            )

    def _classify_reflection(
        self, label: str, origin: str, target_domain: str
    ) -> tuple[Severity, str]:
        if label == "arbitrary_origin":
            return Severity.CRITICAL, (
                "N'importe quelle origine est acceptée et les credentials sont transmis. "
                "Un attaquant peut faire des requêtes authentifiées depuis evil.com et lire la réponse."
            )
        if label == "null_origin":
            return Severity.HIGH, (
                "L'origine 'null' est acceptée avec credentials. Exploitable depuis un iframe sandboxé "
                "ou via file:// (phishing local, electron apps)."
            )
        if label in ("prefix_bypass", "suffix_bypass"):
            return Severity.CRITICAL, (
                f"Validation CORS par {label} ({origin}). "
                "L'attaquant enregistre un domaine qui passe la vérification côté serveur."
            )
        if label == "subdomain_wildcard":
            return Severity.HIGH, (
                f"Tout sous-domaine de {target_domain} est accepté. "
                "Un XSS sur un sous-domaine ou un sous-domaine compromis permet un CORS exploit."
            )
        if label == "scheme_downgrade":
            return Severity.LOW, (  # v5.9-fp: MEDIUM → LOW, nécessite MitM réseau local
                "L'origine HTTP est acceptée pour un site HTTPS. "
                "Exploitable uniquement via une attaque man-in-the-middle sur le réseau local. "
                "Impact limité en contexte bug bounty standard."
            )
        return Severity.MEDIUM, f"Origin {origin} reflétée avec credentials ({label})."
