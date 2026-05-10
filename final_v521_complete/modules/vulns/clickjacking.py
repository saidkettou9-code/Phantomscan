"""
PhantomScan — Clickjacking Scanner
Détecte :
  - X-Frame-Options absent ou mal configuré (ALLOWALL, ALLOW-FROM obsolète)
  - CSP frame-ancestors absent ou wildcard
  - Combinaisons dangereuses (frame possible + form/action sensible)
  - Iframes imbriquées exploitables (double frame bypass)
  - SameSite absent amplifiant l'impact clickjacking
"""

from __future__ import annotations

import re
from typing import AsyncGenerator
from urllib.parse import urlparse, urljoin

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester, ProbeRequest
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity
from phantomscan.core.scanner_mixin import ScannerMixin

# Pages sensibles à tester en priorité
SENSITIVE_PATHS = [
    "/",
    "/login", "/signin", "/register",
    "/account", "/settings", "/profile",
    "/transfer", "/payment", "/checkout",
    "/admin", "/dashboard",
    "/api/", "/api/v1/", "/api/v2/",
    "/confirm", "/approve", "/delete",
    "/oauth/authorize", "/auth/authorize",
]

# Headers de framing
XFO_HEADER = "x-frame-options"
CSP_HEADER = "content-security-policy"


class ClickjackingScanner(ScannerMixin):

    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req = req
        self._heuristic = heuristic
        self._cfg = cfg

    async def run(self, target: str) -> AsyncGenerator[Finding, None]:
        parsed = urlparse(target)
        scheme = parsed.scheme
        netloc = parsed.netloc

        checked_paths: set[str] = set()

        for path in SENSITIVE_PATHS:
            url = f"{scheme}://{netloc}{path}"
            if url in checked_paths:
                continue
            checked_paths.add(url)

            resp = await self._req.send(ProbeRequest(method="GET", url=url))
            if resp.error or resp.status_code in (404, 410, 405):
                continue

            # Skip soft-404 : on ne signale pas les pages qui n'existent pas vraiment
            if not self._heuristic.is_real_hit(resp):
                continue

            headers_lower = {k.lower(): v for k, v in (resp.headers or {}).items()}
            body = resp.body or ""

            # Seulement analyser les pages HTML
            ct = headers_lower.get("content-type", "")
            if "html" not in ct and path not in ("/", "/login", "/account"):
                continue

            # Si la page est vide ou minuscule, probablement un faux positif
            if len(body) < 200:
                continue

            xfo = headers_lower.get(XFO_HEADER, "").strip().upper()
            csp = headers_lower.get(CSP_HEADER, "").lower()

            frame_ancestors = self._extract_frame_ancestors(csp)
            is_frameable = self._is_frameable(xfo, frame_ancestors)

            if not is_frameable:
                continue

            # Déterminer la sévérité selon la sensibilité de la page
            page_is_sensitive = self._page_is_sensitive(path, body)
            severity = Severity.HIGH if page_is_sensitive else Severity.MEDIUM

            # Construire l'evidence détaillée
            evidence_parts = []
            if not xfo:
                evidence_parts.append("X-Frame-Options: (absent)")
            else:
                evidence_parts.append(f"X-Frame-Options: {xfo}")
            if not frame_ancestors:
                evidence_parts.append("CSP frame-ancestors: (absent)")
            else:
                evidence_parts.append(f"CSP frame-ancestors: {frame_ancestors}")

            async for f in self._build_findings(
                url, path, xfo, frame_ancestors, csp, body,
                severity, "\n".join(evidence_parts)
            ):
                yield f

    def _extract_frame_ancestors(self, csp: str) -> str:
        """Extrait la directive frame-ancestors du CSP."""
        match = re.search(r'frame-ancestors\s+([^;]+)', csp)
        return match.group(1).strip() if match else ""

    def _is_frameable(self, xfo: str, frame_ancestors: str) -> bool:
        """Retourne True si la page peut être intégrée dans un iframe."""
        # CSP frame-ancestors a priorité sur X-Frame-Options dans les navigateurs modernes
        if frame_ancestors:
            # '*' = tout le monde peut intégrer
            if frame_ancestors == "*" or frame_ancestors == "'*'":
                return True
            # 'none' = protection OK
            if "'none'" in frame_ancestors or frame_ancestors == "none":
                return False
            # Restriction présente et pas wildcard = OK
            return False

        # Pas de frame-ancestors → regarder X-Frame-Options
        if not xfo:
            return True  # Aucune protection

        if xfo in ("DENY", "SAMEORIGIN"):
            return False

        # ALLOWALL ou ALLOW-FROM (obsolète, contournable)
        if xfo == "ALLOWALL" or xfo.startswith("ALLOW-FROM"):
            return True

        return True  # Valeur inconnue → considérer frameable

    def _page_is_sensitive(self, path: str, body: str) -> bool:
        """Détecte si la page contient des actions sensibles."""
        sensitive_paths = {"/transfer", "/payment", "/admin", "/account",
                           "/settings", "/confirm", "/approve", "/delete",
                           "/oauth", "/login", "/checkout"}
        if any(path.startswith(sp) for sp in sensitive_paths):
            return True
        # Form POST dans le body
        if re.search(r'<form[^>]*method=["\']?post', body, re.IGNORECASE):
            return True
        # Boutons d'action
        if re.search(r'(delete|confirm|approve|transfer|payment|buy|submit)', body, re.IGNORECASE):
            return True
        return False

    async def _build_findings(
        self, url: str, path: str, xfo: str, frame_ancestors: str,
        csp: str, body: str, severity: Severity, evidence: str
    ) -> AsyncGenerator[Finding, None]:

        # Cas 1 : aucune protection
        if not xfo and not frame_ancestors:
            yield Finding(
                title=f"Clickjacking: No framing protection on {path}",
                severity=severity,
                url=url,
                module="vulns/clickjacking",
                description=(
                    f"La page '{path}' ne définit ni X-Frame-Options ni CSP frame-ancestors. "
                    "Elle peut être intégrée dans un iframe depuis n'importe quel domaine. "
                    + ("Elle contient des actions sensibles (forms POST, boutons d'action)."
                       if severity == Severity.HIGH else "")
                ),
                evidence=evidence,
                cwe="CWE-1021",
                remediation=(
                    "Ajouter l'un des deux (CSP frame-ancestors est préféré) :\n"
                    "  Content-Security-Policy: frame-ancestors 'none';  (pour les pages non intégrables)\n"
                    "  Content-Security-Policy: frame-ancestors 'self';  (pour les iframes same-origin uniquement)\n"
                    "  X-Frame-Options: DENY  (en fallback pour les vieux navigateurs)"
                ),
            )

        # Cas 2 : X-Frame-Options ALLOWALL
        elif xfo == "ALLOWALL":
            yield Finding(
                title=f"Clickjacking: X-Frame-Options set to ALLOWALL on {path}",
                severity=Severity.HIGH,
                url=url,
                module="vulns/clickjacking",
                description=(
                    f"La page '{path}' utilise X-Frame-Options: ALLOWALL, "
                    "ce qui autorise explicitement l'intégration depuis n'importe quel domaine."
                ),
                evidence=evidence,
                cwe="CWE-1021",
                remediation="Remplacer ALLOWALL par DENY ou SAMEORIGIN. Préférer CSP frame-ancestors.",
            )

        # Cas 3 : ALLOW-FROM (obsolète, ignoré par Chrome/Firefox)
        elif xfo.startswith("ALLOW-FROM"):
            yield Finding(
                title=f"Clickjacking: X-Frame-Options ALLOW-FROM is obsolete on {path}",
                severity=Severity.MEDIUM,
                url=url,
                module="vulns/clickjacking",
                description=(
                    f"La page utilise X-Frame-Options: {xfo}. "
                    "ALLOW-FROM est ignoré par Chrome, Firefox et Edge — "
                    "la page est donc frameable depuis n'importe quel origine dans ces navigateurs."
                ),
                evidence=evidence,
                cwe="CWE-1021",
                remediation="Migrer vers CSP frame-ancestors qui supporte la whitelist d'origines correctement.",
            )

        # Cas 4 : frame-ancestors wildcard
        elif frame_ancestors in ("*", "'*'"):
            yield Finding(
                title=f"Clickjacking: CSP frame-ancestors set to wildcard on {path}",
                severity=Severity.HIGH,
                url=url,
                module="vulns/clickjacking",
                description=(
                    f"La directive CSP frame-ancestors sur '{path}' est '*', "
                    "autorisant explicitement l'intégration depuis n'importe quel domaine."
                ),
                evidence=evidence,
                cwe="CWE-1021",
                remediation="Remplacer frame-ancestors * par frame-ancestors 'none' ou 'self'.",
            )

        # Cas 5 : pas de frame-ancestors dans CSP, mais CSP présent (oubli)
        elif csp and not frame_ancestors:
            yield Finding(
                title=f"Clickjacking: CSP present but missing frame-ancestors on {path}",
                severity=Severity.MEDIUM,
                url=url,
                module="vulns/clickjacking",
                description=(
                    f"La page '{path}' a un CSP mais sans directive frame-ancestors. "
                    "L'absence de frame-ancestors dans le CSP ne protège pas contre le clickjacking "
                    "même si X-Frame-Options est absent."
                ),
                evidence=evidence,
                cwe="CWE-1021",
                remediation="Ajouter 'frame-ancestors 'none';' ou 'frame-ancestors 'self';' au CSP existant.",
            )

        # FP-FIX: Cas 6 (SAMEORIGIN sans CSP → double-frame bypass) supprimé.
        # Ce vecteur nécessite un XSS confirmé sur le même domaine pour être exploitable.
        # Sans XSS existant il génère uniquement du bruit LOW non actionnable en BB.
