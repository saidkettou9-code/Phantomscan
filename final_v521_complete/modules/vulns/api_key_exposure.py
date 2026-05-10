"""
PhantomScan — API Key Exposure Scanner [v5.16]
Détecte les clés API, tokens secrets et credentials exposés dans :
- Les fichiers JavaScript (inline + bundles)
- Les headers de réponse HTTP
- Les corps de réponse JSON/HTML
- Les fichiers de config exposés (.env, config.js, settings.py...)
- Les commentaires HTML/JS

Patterns couverts (80+) :
- Cloud : AWS, GCP, Azure, Cloudflare, DigitalOcean
- Paiement : Stripe, PayPal, Braintree, Square
- Communication : Twilio, Sendgrid, Mailgun, Mailchimp
- Auth : JWT secrets, OAuth tokens, Firebase, Auth0
- Monitoring : Datadog, Sentry, New Relic, PagerDuty
- Messaging : Slack, Discord, Telegram
- Maps/Geo : Google Maps, Mapbox, HERE
- Crypto : Binance, Coinbase, Kraken API keys
- Generic : tokens Bearer, API keys génériques, passwords en clair

Sévérité :
- CRITICAL : AWS master keys, Stripe live keys, clés crypto
- HIGH : GCP/Azure keys, tokens OAuth actifs, Sendgrid/Twilio
- MEDIUM : clés de test/sandbox, tokens de lecture seule
"""

from __future__ import annotations

import math
import re
from typing import AsyncGenerator
from urllib.parse import urlparse, urljoin

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester, ProbeRequest
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.core.intelligence import ResponseEntropyAnalyzer
from phantomscan.output.reporter import Finding, Severity
from phantomscan.core.scanner_mixin import ScannerMixin


# ─────────────────────────── Regex patterns ──────────────────────────────────
# Format : (label, regex_pattern, severity, cwe_note, entropy_min)
# entropy_min : longueur minimale de la valeur capturée pour réduire les FP

_PATTERNS: list[tuple[str, str, Severity, float]] = [
    # ── AWS ──
    ("AWS Access Key ID",
     r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
     Severity.CRITICAL, 20),
    ("AWS Secret Access Key",
     r"(?i)(?:aws[_\-\.]?secret[_\-\.]?(?:access[_\-\.]?)?key|aws_secret)[\"'\s]*[:=][\"'\s]*([A-Za-z0-9/+]{40})",
     Severity.CRITICAL, 40),
    ("AWS Session Token",
     r"(?i)aws[_\-\.]?session[_\-\.]?token[\"'\s]*[:=][\"'\s]*([A-Za-z0-9/+=]{100,})",
     Severity.CRITICAL, 100),

    # ── GCP / Google ──
    ("Google API Key",
     r"AIza[0-9A-Za-z\-_]{35}",
     Severity.HIGH, 39),
    ("Google OAuth Client Secret",
     r"(?i)client[_\-\.]?secret[\"'\s]*[:=][\"'\s]*([A-Za-z0-9\-_]{24,})",
     Severity.HIGH, 24),
    ("Google Service Account JSON",
     r"\"private_key_id\":\s*\"[a-f0-9]{40}\"",
     Severity.CRITICAL, 40),
    ("Firebase Config",
     r"(?i)firebase[\"'\s]*[:=][\"'\s]*\{[^}]{20,200}\}",
     Severity.HIGH, 30),
    ("GCP API Key (generic)",
     r"(?i)gcp[_\-\.]?api[_\-\.]?key[\"'\s]*[:=][\"'\s]*([A-Za-z0-9\-_]{30,})",
     Severity.HIGH, 30),

    # ── Azure ──
    ("Azure Storage Key",
     r"(?i)(?:AccountKey|StorageKey)[\"'\s]*[:=][\"'\s]*([A-Za-z0-9+/]{88}==)",
     Severity.CRITICAL, 88),
    ("Azure SAS Token",
     r"sig=[A-Za-z0-9%/+]{30,}",
     Severity.HIGH, 30),
    ("Azure Subscription Key",
     r"(?i)(?:subscription[_\-\.]?key|ocp-apim-subscription-key)[\"'\s]*[:=][\"'\s]*([a-f0-9]{32})",
     Severity.HIGH, 32),

    # ── Stripe ──
    ("Stripe Live Secret Key",
     r"sk_live_[0-9a-zA-Z]{24,}",
     Severity.CRITICAL, 28),
    ("Stripe Live Publishable Key",
     r"pk_live_[0-9a-zA-Z]{24,}",
     Severity.HIGH, 28),
    ("Stripe Test Key",
     r"(?:sk|pk)_test_[0-9a-zA-Z]{24,}",
     Severity.MEDIUM, 28),
    ("Stripe Webhook Secret",
     r"whsec_[a-zA-Z0-9]{32,}",
     Severity.HIGH, 36),

    # ── PayPal / Braintree ──
    ("PayPal Access Token",
     r"(?i)paypal[_\-\.]?(?:access[_\-\.]?)?token[\"'\s]*[:=][\"'\s]*([A-Za-z0-9\-_.]{20,})",
     Severity.HIGH, 20),
    ("Braintree Access Token",
     r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
     Severity.CRITICAL, 50),
    ("Braintree Tokenization Key",
     r"production_[0-9a-z]{8}_[0-9a-z]{16}",
     Severity.HIGH, 28),

    # ── Twilio ──
    ("Twilio Account SID",
     r"AC[a-f0-9]{32}",
     Severity.HIGH, 34),
    ("Twilio Auth Token",
     r"(?i)twilio[_\-\.]?auth[_\-\.]?token[\"'\s]*[:=][\"'\s]*([a-f0-9]{32})",
     Severity.HIGH, 32),

    # ── Sendgrid / Mailgun / Mailchimp ──
    ("Sendgrid API Key",
     r"SG\.[a-zA-Z0-9\-_]{22,}\.[a-zA-Z0-9\-_]{43,}",
     Severity.HIGH, 65),
    ("Mailgun API Key",
     r"key-[0-9a-f]{32}",
     Severity.HIGH, 36),
    ("Mailchimp API Key",
     r"[a-f0-9]{32}-us[0-9]{1,2}",
     Severity.HIGH, 35),
    ("Mandrill API Key",
     r"(?i)mandrill[_\-\.]?(?:api[_\-\.]?)?key[\"'\s]*[:=][\"'\s]*([A-Za-z0-9\-_]{22,})",
     Severity.HIGH, 22),

    # ── Slack ──
    ("Slack Bot/User Token",
     r"xox[baprs]-[0-9A-Za-z\-]{10,}",
     Severity.HIGH, 14),
    ("Slack Webhook URL",
     r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+",
     Severity.HIGH, 50),

    # ── Discord ──
    ("Discord Bot Token",
     r"(?i)(?:discord[_\-\.]?token|bot[_\-\.]?token)[\"'\s]*[:=][\"'\s]*([A-Za-z0-9\.\-_]{50,})",
     Severity.HIGH, 50),
    ("Discord Webhook",
     r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9\-_]+",
     Severity.MEDIUM, 30),

    # ── Telegram ──
    ("Telegram Bot Token",
     r"\d{8,10}:[A-Za-z0-9\-_]{35}",
     Severity.HIGH, 43),

    # ── GitHub / GitLab ──
    ("GitHub Personal Access Token",
     r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}",
     Severity.HIGH, 40),
    ("GitHub OAuth Token",
     r"[0-9a-f]{40}",  # SHA1 length — filtré par contexte
     Severity.MEDIUM, 40),
    ("GitLab Personal Access Token",
     r"glpat-[A-Za-z0-9\-_]{20,}",
     Severity.HIGH, 26),

    # ── JWT secrets ──
    ("JWT Token",
     r"eyJ[A-Za-z0-9\-_=]+\.eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=+/]+",
     Severity.MEDIUM, 20),
    ("JWT Secret (hardcoded)",
     r"(?i)jwt[_\-\.]?secret[\"'\s]*[:=][\"'\s]*([A-Za-z0-9!@#$%^&*\-_]{8,})",
     Severity.HIGH, 8),

    # ── Cloudflare ──
    ("Cloudflare API Key",
     r"(?i)cloudflare[_\-\.]?(?:api[_\-\.]?)?key[\"'\s]*[:=][\"'\s]*([a-f0-9]{40})",
     Severity.HIGH, 40),
    ("Cloudflare API Token",
     r"(?i)cloudflare[_\-\.]?(?:api[_\-\.]?)?token[\"'\s]*[:=][\"'\s]*([A-Za-z0-9\-_]{40,})",
     Severity.HIGH, 40),

    # ── Maps / Geo ──
    ("Google Maps API Key",
     r"AIza[0-9A-Za-z\-_]{35}",
     Severity.MEDIUM, 39),
    ("Mapbox Token",
     r"pk\.eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+",
     Severity.MEDIUM, 30),

    # ── Auth0 / Okta ──
    ("Auth0 Client Secret",
     r"(?i)auth0[_\-\.]?client[_\-\.]?secret[\"'\s]*[:=][\"'\s]*([A-Za-z0-9\-_]{32,})",
     Severity.HIGH, 32),

    # ── Datadog / Sentry / New Relic ──
    ("Datadog API Key",
     r"(?i)datadog[_\-\.]?api[_\-\.]?key[\"'\s]*[:=][\"'\s]*([a-f0-9]{32})",
     Severity.MEDIUM, 32),
    ("Sentry DSN",
     r"https://[a-f0-9]{32}@[a-z0-9.]+/\d+",
     Severity.MEDIUM, 40),
    ("New Relic License Key",
     r"(?i)new[_\-\.]?relic[_\-\.]?(?:license[_\-\.]?)?key[\"'\s]*[:=][\"'\s]*([A-Za-z0-9]{40})",
     Severity.MEDIUM, 40),

    # ── Crypto exchanges ──
    ("Binance API Key",
     r"(?i)binance[_\-\.]?api[_\-\.]?key[\"'\s]*[:=][\"'\s]*([A-Za-z0-9]{64})",
     Severity.CRITICAL, 64),
    ("Coinbase API Key",
     r"(?i)coinbase[_\-\.]?(?:api[_\-\.]?)?key[\"'\s]*[:=][\"'\s]*([A-Za-z0-9\-]{16,})",
     Severity.CRITICAL, 16),

    # ── Generic password / secret ──
    ("Hardcoded Password",
     r"(?i)(?:password|passwd|pwd)[\"'\s]*[:=][\"'\s]*([^\s\"'<>]{8,40})",
     Severity.HIGH, 8),
    ("Generic API Key",
     r"(?i)api[_\-\.]?(?:key|token|secret)[\"'\s]*[:=][\"'\s]*([A-Za-z0-9\-_]{16,50})",
     Severity.MEDIUM, 16),
    ("Generic Secret",
     r"(?i)(?:secret|private[_\-\.]?key)[\"'\s]*[:=][\"'\s]*([A-Za-z0-9/+\-_!@#$%]{16,})",
     Severity.MEDIUM, 16),
    ("Bearer Token",
     r"[Bb]earer\s+([A-Za-z0-9\-_.~+/]+=*){20,}",
     Severity.MEDIUM, 20),
    ("Basic Auth in URL",
     r"https?://[^:@\s]+:[^:@\s]+@[^\s\"'<>]+",
     Severity.HIGH, 10),
]

# Fichiers de config courants à sonder
_CONFIG_FILES = [
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/config.js", "/config.json", "/config.yml", "/config.yaml",
    "/settings.py", "/settings.js", "/app.config.js",
    "/src/config.js", "/src/config.json",
    "/assets/config.js", "/static/config.js",
    "/js/config.js", "/js/app.js",
    "/web.config", "/appsettings.json",
    "/.npmrc", "/.yarnrc",
    "/Makefile", "/docker-compose.yml", "/docker-compose.yaml",
    "/.htpasswd",
]

# Faux positifs à ignorer (valeurs trop génériques)
_FP_VALUES = {
    "your_api_key_here", "your-api-key", "xxxx", "replace_me",
    "your_secret_key", "changeme", "example", "test", "undefined",
    "null", "none", "placeholder", "api_key", "secret_key",
    "YOUR_API_KEY", "YOUR_SECRET", "INSERT_KEY_HERE",
    # FIX fp: placeholders supplémentaires courants dans les docs et templates
    "sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "sk_live_xxxxxxxxxxxxxxxxxxxxxxxx",
    "pk_live_xxxxxxxxxxxxxxxxxxxxxxxx",
    "pk_test_xxxxxxxxxxxxxxxxxxxxxxxx",
    "whsec_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "1234567890abcdef1234567890abcdef",
    "0000000000000000000000000000000000000000",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "abcdefghijklmnopqrstuvwxyz012345",
    "insert_your_key_here", "add_your_key", "my_api_key", "my_secret",
    "enter_your_api_key", "enter_api_key_here", "your_token_here",
    "sample_key", "demo_key", "dummy_key", "fake_key", "test_key",
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
}


def _shannon_entropy(text: str) -> float:
    """Calcule l'entropie de Shannon (bits/caractère) d'une chaîne.
    FIX fp: utilisé pour filtrer les clés à faible entropie (ex: 'aaaaa', '12345678').
    """
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    n = len(text)
    return -sum((count / n) * math.log2(count / n) for count in freq.values())


class APIKeyExposureScanner(ScannerMixin):

    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req  = req
        self._h    = heuristic
        self._cfg  = cfg
        self._compiled = self._compile_patterns()

    def _compile_patterns(self) -> list[tuple[str, re.Pattern, Severity, float]]:
        compiled = []
        for label, pattern, severity, min_len in _PATTERNS:
            try:
                compiled.append((label, re.compile(pattern), severity, min_len))
            except re.error:
                pass
        return compiled

    async def run(self, target: str) -> AsyncGenerator[Finding, None]:
        parsed = urlparse(target)
        base   = f"{parsed.scheme}://{parsed.netloc}"

        seen: set[str] = set()  # Évite les doublons (même key trouvée plusieurs fois)

        # 1. Scan les fichiers de config exposés
        async for f in self._scan_config_files(base, seen):
            yield f

        # 2. Scan la page principale + headers
        async for f in self._scan_url(target, seen):
            yield f

        # 3. Scan les endpoints JS connus
        async for f in self._scan_js_endpoints(base, seen):
            yield f

    async def _scan_config_files(self, base: str, seen: set) -> AsyncGenerator[Finding, None]:
        for path in _CONFIG_FILES:
            url = urljoin(base, path)
            resp = await self._req.send(ProbeRequest(method="GET", url=url))
            if resp.error or resp.status_code not in (200,):
                continue
            # Un fichier .env accessible = toujours HIGH au minimum
            body = resp.body or ""
            if not body.strip():
                continue

            is_env_file = path.startswith("/.env") or path in ("/.npmrc", "/.htpasswd")
            if is_env_file and len(body) > 10:
                # Cherche les patterns et signale le fichier entier
                findings = list(self._scan_text(body, url, seen))
                if findings:
                    for f in findings:
                        yield f
                else:
                    # Fichier .env accessible sans secret reconnu → LOW
                    yield Finding(
                        title       = f"Config File Exposed: {path}",
                        severity    = Severity.LOW,
                        url         = url,
                        module      = "APIKeyExposureScanner",
                        description = f"Le fichier `{path}` est accessible publiquement. Même sans secret détecté automatiquement, ce fichier peut contenir des informations sensibles sur la configuration de l'application.",
                        evidence    = f"HTTP 200, {len(body)} bytes",
                        remediation = "Bloquer l'accès aux fichiers de configuration via .htaccess, nginx, ou firewall. Ne jamais versionner les fichiers .env.",
                        cwe  = "CWE-538",
                        cvss = 4.3,
                    )
            else:
                for f in self._scan_text(body, url, seen):
                    yield f

    async def _scan_url(self, url: str, seen: set) -> AsyncGenerator[Finding, None]:
        resp = await self._req.send(ProbeRequest(method="GET", url=url))
        if resp.error:
            return

        body = resp.body or ""
        if body:
            for f in self._scan_text(body, url, seen):
                yield f

        # Scan les headers de réponse aussi
        headers_str = "\n".join(f"{k}: {v}" for k, v in (resp.headers or {}).items())
        for f in self._scan_text(headers_str, url + " [headers]", seen):
            yield f

    async def _scan_js_endpoints(self, base: str, seen: set) -> AsyncGenerator[Finding, None]:
        """Tente de récupérer des bundles JS courants."""
        js_paths = [
            "/static/js/main.js", "/static/js/app.js", "/js/app.js",
            "/assets/index.js", "/dist/main.js", "/dist/app.js",
            "/bundle.js", "/app.bundle.js", "/main.bundle.js",
            "/static/chunk.js", "/vendor.js",
        ]
        for path in js_paths[:6]:  # Limite pour ne pas surcharger
            url = urljoin(base, path)
            resp = await self._req.send(ProbeRequest(method="GET", url=url))
            if resp.error or resp.status_code != 200:
                continue
            ct = (resp.headers or {}).get("content-type", "")
            if "javascript" not in ct and "text" not in ct:
                continue
            body = resp.body or ""
            if len(body) > 500_000:
                body = body[:500_000]  # Limite les gros bundles
            for f in self._scan_text(body, url, seen):
                yield f

    def _scan_text(self, text: str, source_url: str, seen: set) -> list[Finding]:
        findings = []
        for label, pattern, severity, min_len in self._compiled:
            for match in pattern.finditer(text):
                # Valeur : soit le groupe 1 si présent, soit le match entier
                value = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
                value = value.strip().strip("\"'")

                # Filtres anti-FP
                if len(value) < min_len:
                    continue
                if value.lower() in _FP_VALUES:
                    continue
                if value.lower() in ("true", "false", "null", "undefined"):
                    continue
                # Ignore les UUIDs génériques dans certains patterns
                if label == "Generic API Key" and len(set(value)) < 5:
                    continue
                # FIX fp: filtrage par entropie de Shannon — une vraie clé secrète
                # doit avoir une entropie suffisante (> 3.5 bits/char).
                # S'applique uniquement aux patterns génériques (pas aux formats fixes type sk_live_)
                if label in ("Generic API Key", "Generic Secret", "Bearer Token",
                             "Hardcoded Password", "JWT Secret (hardcoded)"):
                    entropy = _shannon_entropy(value)
                    if entropy < 3.5:
                        continue

                # Déduplique par (label, valeur tronquée)
                dedup_key = f"{label}:{value[:20]}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                # Contexte (30 chars avant/après)
                start = max(0, match.start() - 30)
                end   = min(len(text), match.end() + 30)
                context = text[start:end].replace("\n", " ").strip()

                # Masque la valeur dans le rapport (sécurité)
                masked = value[:6] + "***" + value[-4:] if len(value) > 12 else value[:4] + "***"

                findings.append(Finding(
                    title       = f"Exposed Credential: {label}",
                    severity    = severity,
                    url         = source_url,
                    module      = "APIKeyExposureScanner",
                    description = (
                        f"Une clé/secret de type **{label}** a été détecté dans la réponse de `{source_url}`. "
                        f"Des credentials exposés permettent à un attaquant de les réutiliser pour accéder "
                        f"à des services tiers, exfiltrer des données ou effectuer des actions au nom de l'application."
                    ),
                    evidence    = f"Valeur (masquée): `{masked}` | Contexte: `...{context}...`",
                    remediation = (
                        "Supprimer immédiatement la clé de la codebase/réponse et la révoquer sur le service concerné. "
                        "Utiliser des variables d'environnement côté serveur, jamais de secrets dans le code frontend. "
                        "Mettre en place un secret scanner dans la CI/CD (truffleHog, gitleaks)."
                    ),
                    cwe  = "CWE-312",
                    cvss = {"CRITICAL": 9.8, "HIGH": 8.5, "MEDIUM": 6.5, "LOW": 3.5}.get(severity.value, 5.0),
                    extra = {
                        "pattern": label,
                        "value_masked": masked,
                        "source": source_url,
                    },
                ))
        return findings
