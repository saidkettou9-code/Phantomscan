"""
PhantomScan — CSRF Scanner
Détecte :
  - Absence de token CSRF sur les forms POST
  - SameSite cookie manquant ou lax sur cookies de session
  - CSRF possible via GET qui modifie un état
  - Double Submit Cookie pattern absent
  - Referer/Origin validation absente
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

# Noms de tokens CSRF courants
CSRF_TOKEN_NAMES = {
    "csrf", "csrf_token", "csrftoken", "_csrf", "xsrf", "xsrf_token",
    "_xsrf", "authenticity_token", "__requestverificationtoken",
    "csrf-token", "x-csrf-token", "anti-csrf-token", "_token",
    "token", "form_token", "security_token", "nonce",
}

# Endpoints typiquement sensibles au CSRF
SENSITIVE_POST_PATHS = [
    "/login", "/signin", "/register", "/signup",
    "/api/login", "/api/register", "/api/auth/login",
    "/profile", "/settings", "/account",
    "/api/user", "/api/profile", "/api/settings",
    "/password", "/change-password", "/reset-password",
    "/api/password", "/api/change-password",
    "/transfer", "/payment", "/api/transfer", "/api/payment",
    "/api/v1/user", "/api/v2/user",
    "/admin", "/api/admin",
    "/delete", "/api/delete",
    "/api/v1/", "/api/v2/",
]

# Paramètres GET qui modifient l'état
STATE_CHANGING_GET_PARAMS = {
    "delete", "remove", "action", "do", "cmd", "op",
    "confirm", "approve", "accept", "grant", "revoke",
}


class CSRFScanner(ScannerMixin):

    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req = req
        self._heuristic = heuristic
        self._cfg = cfg

    async def run(self, target: str) -> AsyncGenerator[Finding, None]:
        parsed = urlparse(target)
        scheme = parsed.scheme
        netloc = parsed.netloc

        # 1. Analyser les cookies de session (SameSite)
        async for f in self._check_session_cookies(target):
            yield f

        # 2. Checker les forms POST pour token CSRF
        async for f in self._check_post_endpoints(scheme, netloc):
            yield f

        # 3. Checker GET state-changing
        async for f in self._check_get_state_change(target):
            yield f

        # 4. Vérifier validation Origin/Referer
        async for f in self._check_origin_validation(target, scheme, netloc):
            yield f

    # ─────────────────── Cookie SameSite ────────────────────────────────────

    async def _check_session_cookies(self, target: str) -> AsyncGenerator[Finding, None]:
        resp = await self._req.send(ProbeRequest(method="GET", url=target))
        if resp.error:
            return

        raw_cookies = resp.headers.get("Set-Cookie", "")
        if not raw_cookies:
            return

        # Splitter sur plusieurs Set-Cookie (certains serveurs les concatènent)
        cookie_headers = [raw_cookies] if isinstance(raw_cookies, str) else raw_cookies

        for cookie_str in cookie_headers:
            cookie_lower = cookie_str.lower()
            name = cookie_str.split("=")[0].strip()

            # Identifier les cookies de session
            is_session = any(k in name.lower() for k in (
                "session", "sess", "auth", "token", "jwt", "access", "user", "id", "sid"
            ))
            if not is_session:
                continue

            # SameSite absent
            if "samesite" not in cookie_lower:
                yield Finding(
                    title=f"CSRF: SameSite attribute missing on session cookie '{name}'",
                    severity=Severity.MEDIUM,
                    url=target,
                    module="vulns/csrf",
                    description=(
                        f"Le cookie de session '{name}' n'a pas d'attribut SameSite. "
                        "Sans SameSite=Strict ou Lax, le cookie est envoyé dans les "
                        "requêtes cross-site, permettant les attaques CSRF classiques."
                    ),
                    evidence=f"Set-Cookie: {cookie_str[:200]}",
                    cwe="CWE-352",
                    remediation=(
                        "Ajouter SameSite=Strict (recommandé) ou SameSite=Lax sur tous les cookies de session. "
                        "SameSite=None nécessite Secure et est à éviter sauf pour les iframes légitimes."
                    ),
                )

            # SameSite=None sans Secure
            elif "samesite=none" in cookie_lower and "secure" not in cookie_lower:
                yield Finding(
                    title=f"CSRF: SameSite=None without Secure on cookie '{name}'",
                    severity=Severity.HIGH,
                    url=target,
                    module="vulns/csrf",
                    description=(
                        f"Le cookie '{name}' utilise SameSite=None sans l'attribut Secure. "
                        "Cela expose le cookie en clair sur HTTP et permet les attaques CSRF cross-site."
                    ),
                    evidence=f"Set-Cookie: {cookie_str[:200]}",
                    cwe="CWE-352",
                    remediation="SameSite=None doit toujours être combiné avec Secure.",
                )

            # HttpOnly absent (bonus: pas CSRF direct mais renforce l'impact)
            if "httponly" not in cookie_lower and is_session:
                yield Finding(
                    title=f"CSRF: HttpOnly missing on session cookie '{name}'",
                    severity=Severity.LOW,
                    url=target,
                    module="vulns/csrf",
                    description=(
                        f"Le cookie '{name}' n'a pas l'attribut HttpOnly. "
                        "Un XSS peut voler ce cookie, amplifiant l'impact d'une attaque CSRF."
                    ),
                    evidence=f"Set-Cookie: {cookie_str[:200]}",
                    cwe="CWE-1004",
                    remediation="Ajouter HttpOnly à tous les cookies de session.",
                )

    # ─────────────────── POST endpoints — token CSRF ─────────────────────────

    async def _check_post_endpoints(
        self, scheme: str, netloc: str
    ) -> AsyncGenerator[Finding, None]:
        for path in SENSITIVE_POST_PATHS:
            url = f"{scheme}://{netloc}{path}"

            # GET d'abord pour récupérer le form HTML
            resp = await self._req.send(ProbeRequest(method="GET", url=url))
            if resp.error or resp.status_code in (404, 410):
                continue

            body = resp.body or ""

            # Chercher des forms POST dans le HTML
            forms = re.findall(
                r'<form[^>]*method=["\']?post["\']?[^>]*>(.*?)</form>',
                body, re.IGNORECASE | re.DOTALL
            )
            if not forms:
                # Tenter quand même un POST sans token
                async for f in self._probe_post_no_token(url):
                    yield f
                continue

            for form_html in forms:
                has_csrf_token = self._form_has_csrf_token(form_html)
                if not has_csrf_token:
                    yield Finding(
                        title=f"CSRF: No CSRF token in POST form at {path}",
                        severity=Severity.HIGH,
                        url=url,
                        module="vulns/csrf",
                        description=(
                            f"Le formulaire POST sur '{path}' ne contient aucun token CSRF. "
                            "Un attaquant peut forger une requête valide depuis n'importe quel domaine "
                            "si le cookie de session est envoyé cross-site (SameSite absent/Lax)."
                        ),
                        evidence=f"Form HTML (extrait): {form_html[:300]}",
                        cwe="CWE-352",
                        remediation=(
                            "Implémenter le pattern Synchronizer Token : générer un token CSRF aléatoire "
                            "par session, l'inclure dans chaque form POST comme champ caché, "
                            "et le valider côté serveur. Combiner avec SameSite=Strict."
                        ),
                    )

    def _form_has_csrf_token(self, form_html: str) -> bool:
        """Vérifie si un form HTML contient un champ ressemblant à un token CSRF."""
        inputs = re.findall(r'<input[^>]+>', form_html, re.IGNORECASE)
        for inp in inputs:
            name_match = re.search(r'name=["\']?([^"\'>\s]+)["\']?', inp, re.IGNORECASE)
            if name_match:
                name = name_match.group(1).lower()
                if name in CSRF_TOKEN_NAMES:
                    return True
        # Chercher aussi dans les headers meta
        if re.search(r'csrf|xsrf|authenticity.token', form_html, re.IGNORECASE):
            return True
        return False

    async def _probe_post_no_token(self, url: str) -> AsyncGenerator[Finding, None]:
        """POST direct sans token.
        
        ANTI-FP : on compare la réponse sans token avec une réponse GET de référence.
        Si le status est identique ET le body similaire → le serveur n'a probablement
        pas exécuté d'action réelle (ex: login qui retourne 200 + message d'erreur).
        On ne signale que si le POST sans token semble déclencher quelque chose de différent.
        """
        # Baseline GET pour comparer
        resp_get = await self._req.send(ProbeRequest(method="GET", url=url))
        
        resp = await self._req.send(ProbeRequest(
            method="POST",
            url=url,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body="test=csrf_probe",
        ))
        if resp.error:
            return

        # Si 200 sans CSRF header de protection → potentiellement vulnérable
        if resp.status_code == 200:
            csrf_headers = {
                "x-csrf-token", "x-xsrf-token", "x-requested-with"
            }
            resp_headers_lower = {k.lower() for k in (resp.headers or {}).keys()}
            has_csrf_header = bool(csrf_headers & resp_headers_lower)

            if has_csrf_header:
                return

            # Anti-FP : si GET et POST retournent tous deux 200 et un body de taille
            # très similaire, c'est probablement la même page (formulaire affiché = pas d'action)
            if not resp_get.error and resp_get.status_code == 200:
                get_size = resp_get.content_length or len(resp_get.body or "")
                post_size = resp.content_length or len(resp.body or "")
                if get_size > 0:
                    ratio = abs(post_size - get_size) / get_size
                    if ratio < 0.15:
                        # Réponse POST quasi-identique au GET → le serveur a juste affiché la page
                        return

            yield Finding(
                title=f"CSRF: POST endpoint accepts requests without CSRF token",
                severity=Severity.MEDIUM,
                url=url,
                module="vulns/csrf",
                description=(
                    f"L'endpoint POST '{url}' répond 200 à une requête sans token CSRF "
                    "et sans header de protection (X-CSRF-Token, X-Requested-With). "
                    "Vérifier manuellement si l'action est bien protégée."
                ),
                evidence=f"POST {url} → HTTP {resp.status_code} (aucun header CSRF en réponse)",
                cwe="CWE-352",
                remediation="Valider un token CSRF sur tous les endpoints POST mutants.",
            )

    # ─────────────────── GET state-changing ──────────────────────────────────

    async def _check_get_state_change(self, target: str) -> AsyncGenerator[Finding, None]:
        """Cherche des liens GET qui déclenchent des actions (delete, confirm...)."""
        resp = await self._req.send(ProbeRequest(method="GET", url=target))
        if resp.error:
            return

        body = resp.body or ""
        hrefs = re.findall(r'href=["\']([^"\']+)["\']', body, re.IGNORECASE)

        for href in hrefs:
            parsed = urlparse(href)
            qs = parsed.query.lower()
            if any(p in qs for p in STATE_CHANGING_GET_PARAMS):
                full_url = href if href.startswith("http") else urljoin(target, href)
                yield Finding(
                    title="CSRF: State-changing GET action detected",
                    severity=Severity.MEDIUM,
                    url=full_url,
                    module="vulns/csrf",
                    description=(
                        f"Un lien GET semble déclencher une action avec état (params: {qs[:100]}). "
                        "Les actions via GET sont triviales à forger via img src ou lien externe "
                        "même si SameSite est configuré, car les GET cross-origin passent SameSite=Lax."
                    ),
                    evidence=f"href={href[:200]}",
                    cwe="CWE-352",
                    remediation=(
                        "Toutes les actions qui modifient l'état (delete, confirm, update) "
                        "doivent utiliser POST avec un token CSRF, jamais GET."
                    ),
                )
                break  # Un seul exemple suffit

    # ─────────────────── Origin/Referer validation ───────────────────────────

    async def _check_origin_validation(
        self, target: str, scheme: str, netloc: str
    ) -> AsyncGenerator[Finding, None]:
        """Envoie un POST avec un Origin différent pour voir si le serveur le refuse."""
        parsed = urlparse(target)
        path = parsed.path or "/"

        # Trouver un endpoint POST existant
        for post_path in ("/api/user", "/api/profile", "/login", "/api/login"):
            url = f"{scheme}://{netloc}{post_path}"
            resp_legit = await self._req.send(ProbeRequest(
                method="POST",
                url=url,
                headers={
                    "Origin": f"{scheme}://{netloc}",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                body="test=legit",
            ))
            if resp_legit.error or resp_legit.status_code == 404:
                continue

            # POST avec origin malveillant
            resp_evil = await self._req.send(ProbeRequest(
                method="POST",
                url=url,
                headers={
                    "Origin": "https://evil-csrf-test.com",
                    "Referer": "https://evil-csrf-test.com/csrf.html",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                body="test=evil",
            ))
            if resp_evil.error:
                continue

            # Si même status code → pas de validation Origin/Referer
            if (
                resp_legit.status_code == resp_evil.status_code
                and resp_legit.status_code not in (405, 403, 401)
            ):
                yield Finding(
                    title="CSRF: Origin/Referer header not validated on POST",
                    severity=Severity.HIGH,
                    url=url,
                    module="vulns/csrf",
                    description=(
                        f"L'endpoint '{post_path}' retourne le même code HTTP ({resp_legit.status_code}) "
                        "pour un POST avec Origin légitime et un POST avec Origin malveillant. "
                        "Le serveur ne semble pas valider l'en-tête Origin ou Referer."
                    ),
                    evidence=(
                        f"Legit Origin → HTTP {resp_legit.status_code}\n"
                        f"Evil Origin (evil-csrf-test.com) → HTTP {resp_evil.status_code}"
                    ),
                    cwe="CWE-352",
                    remediation=(
                        "Implémenter une validation côté serveur de l'en-tête Origin (et Referer en fallback). "
                        "Rejeter toute requête POST dont l'Origin ne figure pas dans la whitelist. "
                        "Combiner avec des tokens CSRF pour une défense en profondeur."
                    ),
                )
            break
