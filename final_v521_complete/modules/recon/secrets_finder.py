"""
PhantomScan — Secrets Finder  v1.0
Scan des fichiers publics pour clés API, tokens et credentials exposés.

Fichiers ciblés :
  - .env, .env.*, .env.backup, .env.local, .env.production
  - config.js, config.json, config.php, config.yml, settings.py
  - docker-compose.yml, docker-compose.yaml, docker-compose.override.yml
  - .git/config, .git/HEAD, .gitconfig
  - package.json (scripts, engines — parfois credentials dans les scripts)
  - app.yaml, app.json, Procfile, Makefile
  - robots.txt, sitemap.xml (pour découverte de paths cachés)
  - phpinfo.php, info.php, test.php (pages de debug)
  - wp-config.php, wp-config.php.bak, configuration.php

Patterns secrets recherchés (superset des patterns JS Analyzer) :
  - API keys cloud (AWS, GCP, Azure)
  - Tokens (GitHub, Slack, Discord, Stripe, etc.)
  - Credentials hardcodés (DB_PASSWORD, SECRET_KEY, etc.)
  - Private keys PEM
  - JWT secrets
"""

from __future__ import annotations

import re
from typing import AsyncGenerator
from urllib.parse import urljoin, urlparse

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester, ProbeRequest
from phantomscan.output.reporter import Finding, Severity


# ─────────────────────── Fichiers cibles ─────────────────────────────────────

_TARGET_FILES: list[tuple[str, str]] = [
    # .env files
    ("/.env",                       "dotenv"),
    ("/.env.backup",                "dotenv"),
    ("/.env.local",                 "dotenv"),
    ("/.env.production",            "dotenv"),
    ("/.env.staging",               "dotenv"),
    ("/.env.development",           "dotenv"),
    ("/.env.example",               "dotenv"),
    ("/.env.old",                   "dotenv"),
    # Git
    ("/.git/config",                "git"),
    ("/.git/HEAD",                  "git"),
    ("/.gitconfig",                 "git"),
    ("/.gitignore",                 "git"),
    # Config files
    ("/config.js",                  "config"),
    ("/config.json",                "config"),
    ("/config.php",                 "config"),
    ("/config.yml",                 "config"),
    ("/config.yaml",                "config"),
    ("/settings.py",                "config"),
    ("/settings.php",               "config"),
    ("/configuration.php",          "config"),
    ("/application.properties",     "config"),
    ("/application.yml",            "config"),
    ("/appsettings.json",           "config"),
    # Docker / CI
    ("/docker-compose.yml",         "docker"),
    ("/docker-compose.yaml",        "docker"),
    ("/docker-compose.override.yml","docker"),
    ("/.dockerenv",                 "docker"),
    ("/.travis.yml",                "ci"),
    ("/.circleci/config.yml",       "ci"),
    ("/Jenkinsfile",                "ci"),
    ("/bitbucket-pipelines.yml",    "ci"),
    # WordPress / CMS
    ("/wp-config.php",              "cms"),
    ("/wp-config.php.bak",          "cms"),
    ("/wp-config.php.old",          "cms"),
    ("/wp-config.bak",              "cms"),
    ("/sites/default/settings.php", "cms"),  # Drupal
    # Debug / info
    ("/phpinfo.php",                "debug"),
    ("/info.php",                   "debug"),
    ("/test.php",                   "debug"),
    ("/debug.php",                  "debug"),
    ("/_profiler/phpinfo",          "debug"),
    # Package/project files
    ("/package.json",               "project"),
    ("/composer.json",              "project"),
    ("/Gemfile",                    "project"),
    ("/requirements.txt",           "project"),
    ("/Pipfile",                    "project"),
    ("/Procfile",                   "project"),
    # Backup / dumps
    ("/backup.sql",                 "backup"),
    ("/db.sql",                     "backup"),
    ("/database.sql",               "backup"),
    ("/dump.sql",                   "backup"),
    # Logs
    ("/error.log",                  "log"),
    ("/access.log",                 "log"),
    ("/debug.log",                  "log"),
    ("/laravel.log",                "log"),
    ("/storage/logs/laravel.log",   "log"),
    # Cloud
    ("/aws.json",                   "cloud"),
    ("/.aws/credentials",           "cloud"),
    ("/gcloud.json",                "cloud"),
    ("/service-account.json",       "cloud"),
    # SSH / certs
    ("/.ssh/id_rsa",                "key"),
    ("/.ssh/id_ecdsa",              "key"),
    ("/.ssh/authorized_keys",       "key"),
    ("/server.key",                 "key"),
    ("/private.key",                "key"),
    ("/cert.pem",                   "key"),
]

# ─────────────────────── Patterns secrets ────────────────────────────────────

_SECRET_PATTERNS: list[tuple[str, str, Severity]] = [
    # PEM / SSH private keys
    (r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY',                   "Private Key PEM",          Severity.CRITICAL),
    # AWS
    (r'AKIA[0-9A-Z]{16}',                                                    "AWS Access Key ID",        Severity.CRITICAL),
    (r'(?i)aws.{0,30}secret.{0,20}["\']([A-Za-z0-9/+=]{40})',               "AWS Secret Access Key",    Severity.CRITICAL),
    # GitHub
    (r'gh[ps]_[A-Za-z0-9]{36}',                                             "GitHub Token",             Severity.CRITICAL),
    (r'github_pat_[A-Za-z0-9_]{82}',                                        "GitHub Fine-Grained PAT",  Severity.CRITICAL),
    # Stripe
    (r'sk_live_[0-9a-zA-Z]{24,}',                                           "Stripe Secret Key",        Severity.CRITICAL),
    (r'rk_live_[0-9a-zA-Z]{24,}',                                           "Stripe Restricted Key",    Severity.CRITICAL),
    # OpenAI / Anthropic
    (r'sk-[A-Za-z0-9]{48}',                                                  "OpenAI API Key",           Severity.CRITICAL),
    (r'sk-ant-[A-Za-z0-9_-]{40,}',                                           "Anthropic API Key",        Severity.CRITICAL),
    # Slack
    (r'xox[bpsa]-[A-Za-z0-9\-]{10,}',                                       "Slack Token",              Severity.HIGH),
    (r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+', "Slack Webhook",        Severity.HIGH),
    # Discord
    (r'https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+',     "Discord Webhook",          Severity.HIGH),
    # SendGrid / Twilio / Mailgun
    (r'SG\.[A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{22,}',                      "SendGrid API Key",         Severity.HIGH),
    (r'AC[a-f0-9]{32}',                                                      "Twilio Account SID",       Severity.HIGH),
    (r'key-[a-zA-Z0-9]{32}',                                                 "Mailgun API Key",          Severity.HIGH),
    # npm / Doppler / Linear
    (r'npm_[A-Za-z0-9]{36}',                                                 "npm Token",                Severity.HIGH),
    (r'dp\.pt\.[A-Za-z0-9]{40,}',                                            "Doppler Token",            Severity.HIGH),
    (r'lin_api_[A-Za-z0-9]{40}',                                             "Linear API Key",           Severity.HIGH),
    # JWT
    (r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',    "JWT Token",                Severity.MEDIUM),
    # Credentials hardcodés (heuristiques)
    (r'(?i)(?:DB_PASSWORD|DATABASE_PASSWORD|MYSQL_PASSWORD|POSTGRES_PASSWORD)\s*=\s*["\']?([^\s"\'#]{4,})',
                                                                              "Database Password",        Severity.CRITICAL),
    (r'(?i)(?:SECRET_KEY|APP_SECRET|JWT_SECRET|FLASK_SECRET)\s*=\s*["\']?([^\s"\'#]{8,})',
                                                                              "Application Secret Key",   Severity.HIGH),
    (r'(?i)(?:API_KEY|APIKEY|ACCESS_KEY|ACCESS_TOKEN)\s*=\s*["\']?([A-Za-z0-9_\-]{16,})',
                                                                              "Generic API Key/Token",    Severity.HIGH),
    # Google
    (r'AIza[0-9A-Za-z_-]{35}',                                               "Google API Key",           Severity.HIGH),
    # Heroku
    (r'(?i)heroku.{0,20}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
                                                                              "Heroku API Key",           Severity.HIGH),
    # Connection strings
    (r'(?i)(?:mongodb|postgres|postgresql|mysql|redis|amqp|jdbc)://[^\s"\'<>]{10,}',
                                                                              "Database Connection String",Severity.CRITICAL),
]

# Contenu révélateur dans des fichiers spécifiques (même sans pattern secret)
_REVEALING_CONTENT_PATTERNS: list[tuple[str, str, Severity]] = [
    (r'\[remote\s+"origin"\]',          "Fichier .git/config avec remote origin",    Severity.MEDIUM),
    (r'define\s*\(\s*[\'"]DB_',         "Config WordPress avec credentials DB",      Severity.HIGH),
    (r'memory_limit|upload_max_filesize|expose_php', "phpinfo() exposé",             Severity.MEDIUM),
    (r'(?i)DocumentRoot|ServerName',    "Config Apache/Nginx exposée",               Severity.MEDIUM),
]


class SecretsFinder:
    """Scan des fichiers publics pour secrets et credentials exposés."""

    def __init__(self, req: Requester, cfg: PhantomConfig) -> None:
        self._req = req
        self._cfg = cfg

    async def run(self, target: str) -> AsyncGenerator[Finding, None]:
        base = self._base_url(target)

        found_files: list[tuple[str, str, str]] = []  # (url, file_type, body)

        # Scan de tous les fichiers cibles
        for path, ftype in _TARGET_FILES:
            url = urljoin(base, path)
            body = await self._fetch_file(url)
            if body:
                found_files.append((url, ftype, body))

        if not found_files:
            return

        yield Finding(
            title="Secrets Finder — Fichiers publics accessibles",
            url=target,
            severity=Severity.INFO,
            description=f"{len(found_files)} fichier(s) potentiellement exposé(s) détecté(s).",
            evidence="\n".join(f[0] for f in found_files),
        )

        seen_secrets: set[str] = set()

        for url, ftype, body in found_files:
            # Finding de base pour le fichier accessible
            file_severity = self._file_base_severity(ftype)
            yield Finding(
                title=f"Fichier exposé : {url.split('/')[-1] or path}",
                url=url,
                severity=file_severity,
                description=(
                    f"Le fichier `{url}` est accessible publiquement (HTTP 200).\n"
                    f"Type : {ftype}"
                ),
                evidence=f"Taille : {len(body)} bytes\nExtrait :\n{body[:500]}",
            )

            # Scan des patterns secrets dans le contenu
            for pattern, label, severity in _SECRET_PATTERNS:
                match = re.search(pattern, body, re.MULTILINE)
                if match:
                    secret_key = f"{label}:{url}"
                    if secret_key in seen_secrets:
                        continue
                    seen_secrets.add(secret_key)

                    snippet = match.group(0)[:200]
                    # Masquer partiellement le secret dans l'evidence
                    masked = self._mask_secret(snippet)

                    yield Finding(
                        title=f"Secret exposé — {label}",
                        url=url,
                        severity=severity,
                        description=(
                            f"Pattern `{label}` détecté dans `{url}`.\n"
                            "Ce secret est accessible publiquement et doit être révoqué immédiatement."
                        ),
                        evidence=f"Pattern : {pattern}\nMatch (masqué) : {masked}",
                    )

            # Contenu révélateur (sans nécessairement avoir un pattern secret)
            for pattern, label, severity in _REVEALING_CONTENT_PATTERNS:
                if re.search(pattern, body, re.IGNORECASE | re.MULTILINE):
                    key = f"{label}:{url}"
                    if key not in seen_secrets:
                        seen_secrets.add(key)
                        yield Finding(
                            title=f"Contenu sensible — {label}",
                            url=url,
                            severity=severity,
                            description=f"`{label}` trouvé dans `{url}`.",
                            evidence=f"Pattern : {pattern}",
                        )

    async def _fetch_file(self, url: str) -> str | None:
        """Tente de récupérer un fichier. Retourne None si non accessible."""
        try:
            probe = ProbeRequest(url=url, method="GET", timeout=10)
            resp = await self._req.probe(probe)
            if not resp:
                return None
            # On accepte uniquement les 200 avec un corps non-vide et non-HTML
            if resp.status_code != 200 or not resp.body:
                return None
            # Ignorer les pages HTML (souvent des 200 avec custom error page)
            ct = (resp.headers or {}).get("content-type", "").lower()
            if "text/html" in ct and len(resp.body) > 2000:
                return None
            return resp.body
        except Exception:
            return None

    @staticmethod
    def _file_base_severity(ftype: str) -> Severity:
        mapping = {
            "dotenv":  Severity.CRITICAL,
            "key":     Severity.CRITICAL,
            "cloud":   Severity.CRITICAL,
            "backup":  Severity.HIGH,
            "git":     Severity.HIGH,
            "config":  Severity.HIGH,
            "cms":     Severity.HIGH,
            "docker":  Severity.MEDIUM,
            "ci":      Severity.MEDIUM,
            "debug":   Severity.MEDIUM,
            "log":     Severity.MEDIUM,
            "project": Severity.LOW,
        }
        return mapping.get(ftype, Severity.MEDIUM)

    @staticmethod
    def _mask_secret(text: str) -> str:
        """Masque partiellement un secret pour l'evidence (évite de leak dans les rapports)."""
        if len(text) <= 12:
            return "*" * len(text)
        visible = 4
        return text[:visible] + "*" * (len(text) - visible * 2) + text[-visible:]

    @staticmethod
    def _base_url(target: str) -> str:
        parsed = urlparse(target)
        return f"{parsed.scheme}://{parsed.netloc}"
