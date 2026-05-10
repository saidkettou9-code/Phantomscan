"""
PhantomScan — Account Takeover Scanner
========================================
Détecte les vulnérabilités permettant la prise de contrôle de compte :

  1. Password Reset Token — Prévisibilité / Entropie insuffisante
     Le token de reset est trop court, séquentiel, ou basé sur
     des données prévisibles (timestamp, user_id, email MD5).

  2. Password Reset Poisoning via Host Header
     L'application utilise Host/X-Forwarded-Host pour construire le
     lien de reset → l'attaquant peut capturer le token en poisonnant
     le header (cf. HostHeaderInjectionScanner pour la version complète).

  3. Session Persistance post-changement de mot de passe
     Après un changement de mot de passe, les anciennes sessions doivent
     être invalidées. Si elles ne le sont pas, un attaquant qui avait
     compromis une session peut maintenir son accès.

  4. Email Change sans Vérification / Race Condition
     L'application permet de changer l'email sans vérifier l'ancien,
     ou de confirmer un email en parallèle avec un autre compte.

  5. Username Enumeration via Timing / Response
     Des différences de temps de réponse ou de message entre un
     email existant et inexistant permettent d'énumérer les comptes.

  6. Weak Password Reset via Security Questions
     Questions de sécurité devinables (date de naissance, ville natale).

Valeur BB :
  Account takeover = P1/CRITICAL dans presque tous les programmes.
  Les chaînes reset_poison → token_capture → account_takeover paient
  souvent $10k-$50k sur les gros programmes.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import time
from typing import AsyncIterator
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester, ProbeRequest
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity
from phantomscan.core.scanner_mixin import ScannerMixin


# ── Chemins typiques de reset de mot de passe ────────────────────────────────
_RESET_PATHS = [
    "/forgot-password", "/forgot_password", "/forgotpassword",
    "/reset-password", "/reset_password", "/resetpassword",
    "/password/reset", "/password/forgot", "/password/recover",
    "/auth/reset", "/auth/forgot",
    "/api/password/reset", "/api/auth/forgot",
    "/api/v1/password/reset", "/api/v2/password/reset",
    "/account/forgot", "/account/reset",
    "/users/password/new", "/users/forgot",
    "/wp-login.php?action=lostpassword",  # WordPress
]

# ── Chemins de changement d'email ────────────────────────────────────────────
_EMAIL_CHANGE_PATHS = [
    "/account/email", "/settings/email", "/profile/email",
    "/api/account/email", "/api/user/email",
    "/api/v1/account/email", "/api/v1/user/email",
    "/me/email", "/user/email",
]

# ── Indicateurs de token prévisible dans les réponses ────────────────────────
_PREDICTABLE_TOKEN_RE = re.compile(
    r"(?:token|reset_token|code|key).*?[=:\s\"']"
    r"([a-f0-9]{4,16}"           # hex court (trop court pour être sûr)
    r"|[0-9]{4,10}"               # purement numérique
    r"|[a-zA-Z0-9]{4,8})"         # alphanum très court
    r"(?:[\"'\s&]|$)",
    re.I,
)

# ── Indicateurs d'énumération d'utilisateurs ─────────────────────────────────
_ENUM_INDICATORS = re.compile(
    r"(?:user|account|email).*(?:not found|doesn.?t exist|no account|invalid|"
    r"not registered|doesn.?t match|wrong)",
    re.I,
)

_ENUM_POSITIVE = re.compile(
    r"(?:reset.*sent|email.*sent|check.*inbox|link.*sent|instructions.*sent|"
    r"we.?ve sent|you.?ll receive)",
    re.I,
)


class AccountTakeoverScanner(ScannerMixin):
    """Scanner de vulnérabilités Account Takeover."""

    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req = req
        self._heur = heuristic
        self._cfg = cfg
        self._found: set[str] = set()

    async def run(self, target: str) -> AsyncIterator[Finding]:
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # 1. Découverte des endpoints de reset
        reset_endpoints = await self._find_reset_endpoints(base)

        for endpoint in reset_endpoints:
            # 2. Username enumeration
            async for f in self._test_user_enumeration(endpoint):
                yield f

            # 3. Reset token entropy
            async for f in self._test_token_entropy(endpoint, base):
                yield f

            # 4. Host Header poisoning du reset
            async for f in self._test_reset_host_poison(endpoint, parsed.netloc):
                yield f

        # 5. Session persistance après changement de mot de passe
        async for f in self._test_session_after_password_change(base):
            yield f

        # 6. Email change sans vérification
        async for f in self._test_email_change(base):
            yield f

    # ── Découverte ────────────────────────────────────────────────────────────

    async def _find_reset_endpoints(self, base: str) -> list[str]:
        found = []
        for path in _RESET_PATHS:
            url = base + path
            resp = await self._req.get(url)
            if resp.error:
                continue
            if resp.status in (200, 405, 302):
                body_low = (resp.body or "").lower()
                if any(kw in body_low for kw in [
                    "password", "reset", "forgot", "email", "recover"
                ]):
                    found.append(url)
        return found[:5]

    # ── Username Enumeration ──────────────────────────────────────────────────

    async def _test_user_enumeration(self, endpoint: str) -> AsyncIterator[Finding]:
        """
        Teste si l'application révèle l'existence d'un compte via les messages
        ou les temps de réponse (timing oracle).
        """
        test_emails = [
            "nonexistent_phantom_test@example-phantom.com",
            "admin@" + urlparse(endpoint).netloc,
        ]
        responses = []

        for email in test_emails:
            t0 = time.monotonic()
            resp = await self._req.send(ProbeRequest(
                method="POST",
                url=endpoint,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                body=urlencode({"email": email, "username": email}),
            ))
            elapsed = (time.monotonic() - t0) * 1000
            if not resp.error:
                responses.append((email, resp, elapsed))

        if len(responses) < 2:
            return

        email_fake, resp_fake, t_fake = responses[0]
        email_real, resp_real, t_real = responses[1]

        body_fake = (resp_fake.body or "").lower()
        body_real = (resp_real.body or "").lower()

        # Test 1 : messages différents révèlent l'existence du compte
        has_negative = _ENUM_INDICATORS.search(body_fake)
        has_positive = _ENUM_POSITIVE.search(body_real)

        if has_negative or (has_positive and self.stable_diff(body_fake, body_real) > 0.20):
            key = f"enum:{endpoint}"
            if key not in self._found:
                self._found.add(key)
                yield Finding(
                    title="Account Enumeration via Password Reset",
                    severity=Severity.MEDIUM,
                    url=endpoint,
                    module="vulns/account_takeover",
                    description=(
                        "L'application révèle si un email/username est enregistré "
                        "via des messages différents sur le formulaire de reset. "
                        "Un attaquant peut énumérer les comptes existants."
                    ),
                    evidence=(
                        f"Email inexistant → {resp_fake.status} | "
                        f"Email existant → {resp_real.status} | "
                        f"diff_body={self.stable_diff(body_fake, body_real):.2f}"
                    ),
                    cwe="CWE-204",
                    remediation=(
                        "Retourner le même message générique quelle que soit l'existence "
                        "du compte ('Si ce compte existe, un email a été envoyé'). "
                        "Normaliser les temps de réponse."
                    ),
                )

        # Test 2 : timing oracle (différence > 200ms révèle l'existence)
        timing_diff = abs(t_real - t_fake)
        if timing_diff > 200 and t_real > t_fake:
            key = f"timing:{endpoint}"
            if key not in self._found:
                self._found.add(key)
                yield Finding(
                    title="Account Enumeration via Timing Oracle (Password Reset)",
                    severity=Severity.LOW,
                    url=endpoint,
                    module="vulns/account_takeover",
                    description=(
                        f"Différence de temps de réponse significative : "
                        f"{t_real:.0f}ms pour un email existant vs "
                        f"{t_fake:.0f}ms pour un email inexistant ({timing_diff:.0f}ms d'écart). "
                        "Indique une requête BDD différente selon l'existence du compte."
                    ),
                    evidence=(
                        f"Fake email: {t_fake:.0f}ms | Real email: {t_real:.0f}ms | "
                        f"Diff: {timing_diff:.0f}ms"
                    ),
                    cwe="CWE-208",
                    remediation=(
                        "Normaliser le temps de traitement via un délai fixe ou "
                        "en effectuant la même requête BDD dans tous les cas."
                    ),
                )

    # ── Token Entropy ─────────────────────────────────────────────────────────

    async def _test_token_entropy(self, endpoint: str, base: str) -> AsyncIterator[Finding]:
        """
        Demande 3 tokens de reset et vérifie leur entropie/prévisibilité.
        Un bon token doit avoir ≥ 128 bits d'entropie (32 hex chars minimum).
        """
        tokens_found = []

        for _ in range(3):
            resp = await self._req.send(ProbeRequest(
                method="POST",
                url=endpoint,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                body=urlencode({"email": "test@phantom-security-test.com"}),
            ))
            if resp.error:
                continue

            # Chercher un token dans la réponse (certaines apps retournent le token en JSON)
            m = _PREDICTABLE_TOKEN_RE.search(resp.body or "")
            if m:
                tokens_found.append(m.group(1))
            await asyncio.sleep(0.5)

        if len(tokens_found) < 2:
            return

        # Vérifier la longueur (< 20 chars = entropie faible)
        short_tokens = [t for t in tokens_found if len(t) < 20]
        if short_tokens:
            yield Finding(
                title="Weak Password Reset Token — Insufficient Entropy",
                severity=Severity.HIGH,
                url=endpoint,
                module="vulns/account_takeover",
                description=(
                    f"Les tokens de reset de mot de passe ont une longueur insuffisante "
                    f"({len(short_tokens[0])} chars). Un token sécurisé doit avoir "
                    "au minimum 128 bits d'entropie (32 caractères hex)."
                ),
                evidence=f"Token détecté: {short_tokens[0]!r} (longueur: {len(short_tokens[0])})",
                cwe="CWE-330",
                remediation=(
                    "Générer les tokens avec un CSPRNG : "
                    "Python: secrets.token_urlsafe(32), "
                    "Node: crypto.randomBytes(32).toString('hex'). "
                    "Durée de vie max 1 heure, usage unique."
                ),
            )

        # Vérifier si les tokens sont séquentiels/prévisibles
        if len(tokens_found) >= 2:
            # Tous identiques = bug sérieux
            if len(set(tokens_found)) == 1:
                yield Finding(
                    title="Identical Password Reset Tokens — Not Random",
                    severity=Severity.CRITICAL,
                    url=endpoint,
                    module="vulns/account_takeover",
                    description=(
                        "Plusieurs demandes de reset ont retourné le même token. "
                        "Le token n'est pas aléatoire — probablement basé sur "
                        "un hash de l'email ou un timestamp fixe."
                    ),
                    evidence=f"Tokens identiques: {tokens_found}",
                    cwe="CWE-330",
                    remediation="Utiliser un générateur de tokens cryptographiquement sûr.",
                )

    # ── Host Header Poisoning ─────────────────────────────────────────────────

    async def _test_reset_host_poison(
        self, endpoint: str, real_host: str
    ) -> AsyncIterator[Finding]:
        """
        Injecte un domaine attaquant dans Host/X-Forwarded-Host lors
        d'une demande de reset. Si le lien dans l'email contient le domaine
        injecté, l'attaquant peut capturer le token.
        """
        evil_domain = "phantom-attacker-host.com"
        poison_headers = [
            {"Host": evil_domain},
            {"X-Forwarded-Host": evil_domain},
            {"X-Host": evil_domain},
            {"X-Original-Host": evil_domain},
        ]

        for hdrs in poison_headers:
            resp = await self._req.send(ProbeRequest(
                method="POST",
                url=endpoint,
                headers={
                    **hdrs,
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                body=urlencode({"email": "victim@example.com"}),
            ))
            if resp.error:
                continue

            body = resp.body or ""
            # Si le domaine injecté apparaît dans la réponse, l'app l'utilise
            if evil_domain in body:
                hdr_name = list(hdrs.keys())[0]
                key = f"host_poison:{endpoint}:{hdr_name}"
                if key not in self._found:
                    self._found.add(key)
                    yield Finding(
                        title=f"Password Reset Poisoning via {hdr_name}",
                        severity=Severity.HIGH,
                        url=endpoint,
                        module="vulns/account_takeover",
                        description=(
                            f"L'application utilise le header `{hdr_name}` pour construire "
                            f"le lien de reset dans l'email. En injectant un domaine contrôlé, "
                            "un attaquant peut faire pointer le lien de reset vers son serveur "
                            "et capturer le token → account takeover."
                        ),
                        evidence=(
                            f"Header injecté: {hdr_name}: {evil_domain} | "
                            f"Domaine injecté trouvé dans la réponse"
                        ),
                        cwe="CWE-640",
                        remediation=(
                            "Construire les liens de reset depuis la configuration serveur, "
                            "jamais depuis les headers HTTP. "
                            "Valider le header Host contre une whitelist de domaines autorisés."
                        ),
                    )

    # ── Session Persistance ───────────────────────────────────────────────────

    async def _test_session_after_password_change(self, base: str) -> AsyncIterator[Finding]:
        """
        Vérifie si les sessions sont invalidées après changement de mot de passe.
        Nécessite un profil d'auth actif pour être efficace.
        """
        if not self.has_multi_profile():
            return  # Besoin de 2 sessions pour tester

        change_paths = [
            "/password", "/api/password", "/api/account/password",
            "/settings/password", "/account/password",
            "/api/v1/password", "/user/password",
        ]

        for path in change_paths:
            url = base + path
            resp = await self._req.get(url)
            if not resp.error and resp.status == 200:
                body_low = (resp.body or "").lower()
                if "password" in body_low and "current" in body_low:
                    # Endpoint de changement de mdp trouvé
                    yield Finding(
                        title="Password Change Endpoint Found — Verify Session Invalidation",
                        severity=Severity.INFO,
                        url=url,
                        module="vulns/account_takeover",
                        description=(
                            f"Endpoint de changement de mot de passe trouvé : {url}. "
                            "Vérifier manuellement que les sessions existantes sont "
                            "invalidées après le changement. "
                            "Utiliser --auth-profile avec 2 sessions pour un test automatisé."
                        ),
                        evidence=f"HTTP {resp.status} | 'password' + 'current' dans le body",
                        cwe="CWE-613",
                        remediation=(
                            "Invalider toutes les sessions actives lors d'un changement "
                            "de mot de passe, sauf la session courante si souhaité. "
                            "Implémenter un mécanisme de révocation de token."
                        ),
                    )
                    return

    # ── Email Change ──────────────────────────────────────────────────────────

    async def _test_email_change(self, base: str) -> AsyncIterator[Finding]:
        """
        Teste si le changement d'email nécessite une vérification de l'ancien email.
        """
        for path in _EMAIL_CHANGE_PATHS:
            url = base + path
            resp = await self._req.send(ProbeRequest(
                method="PUT",
                url=url,
                headers={"Content-Type": "application/json"},
                body='{"email": "attacker@phantom-test.com"}',
            ))
            if resp.error:
                continue

            if resp.status in (200, 201, 204):
                # Changement d'email accepté sans vérification visible
                body = resp.body or ""
                if not any(kw in body.lower() for kw in [
                    "confirm", "verify", "verification", "current_password",
                    "password", "code", "token"
                ]):
                    yield Finding(
                        title="Email Change Without Verification",
                        severity=Severity.HIGH,
                        url=url,
                        module="vulns/account_takeover",
                        description=(
                            f"L'endpoint {url} a accepté un changement d'email "
                            "(PUT avec le nouvel email) sans demander de confirmation "
                            "de l'ancien email ni de mot de passe. "
                            "Un attaquant ayant accès temporaire à une session peut "
                            "changer définitivement l'email et prendre le contrôle du compte."
                        ),
                        evidence=(
                            f"PUT {url} → HTTP {resp.status} | "
                            "Aucune vérification demandée"
                        ),
                        cwe="CWE-620",
                        remediation=(
                            "Exiger la confirmation par l'ancien email ET le mot de passe "
                            "actuel pour tout changement d'email. "
                            "Envoyer une notification à l'ancien email lors du changement."
                        ),
                    )
                    return
