"""
PhantomScan — JS Analyzer  v2.0
Extraction de secrets, endpoints cachés, source maps depuis le JS.

Enrichissements v2.0:
  - Patterns secrets étendus (Anthropic, OpenAI, Cloudflare, Datadog, etc.)
  - Patterns endpoints enrichis (gRPC, tRPC, WebSocket, GraphQL subscriptions)
  - Déduplication des findings par (type, snippet) cross-fichiers JS
  - Détection de webpack chunk manifest (.js.map implicite via chunk ids)
  - Score de confiance par pattern (évite les faux positifs)
"""

from __future__ import annotations

import json
import re
from typing import AsyncIterator
from urllib.parse import urljoin, urlparse

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester
from phantomscan.output.reporter import Finding, Severity


# ─────────────────────────── Patterns secrets ────────────────────────────────
# Format: (name, pattern, severity, min_confidence)
# min_confidence: 0.0–1.0 — filtre les matches trop génériques

SECRET_PATTERNS: list[tuple[str, str, Severity, float]] = [
    # Cloud — AWS
    ("AWS Access Key",          r'AKIA[0-9A-Z]{16}',                                           Severity.CRITICAL, 0.95),
    ("AWS Secret Key",          r'(?i)aws.{0,20}secret.{0,20}["\']([A-Za-z0-9/+=]{40})',       Severity.CRITICAL, 0.85),
    # Clés privées
    ("Private Key PEM",         r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY',               Severity.CRITICAL, 0.99),
    # Google
    ("Google API Key",          r'AIza[0-9A-Za-z_-]{35}',                                      Severity.HIGH,     0.90),
    ("Google OAuth Client",     r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',      Severity.MEDIUM,   0.80),
    # Stripe
    ("Stripe Secret",           r'sk_live_[0-9a-zA-Z]{24,}',                                   Severity.CRITICAL, 0.99),
    ("Stripe Publishable",      r'pk_live_[0-9a-zA-Z]{24,}',                                   Severity.MEDIUM,   0.90),
    ("Stripe Webhook",          r'whsec_[0-9a-zA-Z]{32,}',                                     Severity.HIGH,     0.95),
    # GitHub
    ("GitHub Token (classic)",  r'ghp_[A-Za-z0-9]{36}',                                        Severity.CRITICAL, 0.99),
    ("GitHub Actions Token",    r'ghs_[A-Za-z0-9]{36}',                                        Severity.CRITICAL, 0.99),
    ("GitHub OAuth Token",      r'gho_[A-Za-z0-9]{36}',                                        Severity.CRITICAL, 0.99),
    ("GitHub Fine-Grained PAT", r'github_pat_[A-Za-z0-9_]{82}',                                Severity.CRITICAL, 0.99),
    # OpenAI / Anthropic
    ("OpenAI API Key",          r'sk-[A-Za-z0-9]{48}',                                         Severity.CRITICAL, 0.90),
    ("Anthropic API Key",       r'sk-ant-[A-Za-z0-9_-]{40,}',                                  Severity.CRITICAL, 0.99),
    # Cloudflare
    ("Cloudflare API Token",    r'(?i)cloudflare.{0,20}["\']([A-Za-z0-9_-]{40})["\']',         Severity.HIGH,     0.75),
    ("Cloudflare API Key",      r'[0-9a-f]{37}',                                                Severity.MEDIUM,   0.60),  # bas confidence — très générique
    # Datadog
    ("Datadog API Key",         r'(?i)datadog.{0,10}["\']([a-f0-9]{32})["\']',                 Severity.HIGH,     0.80),
    ("Datadog App Key",         r'(?i)dd_app_key.{0,10}["\']([a-f0-9]{40})["\']',              Severity.HIGH,     0.85),
    # Auth générique
    ("Generic Bearer Token",    r'(?i)bearer\s+[A-Za-z0-9\-_\.]{20,}',                         Severity.HIGH,     0.70),
    ("Basic Auth Header",       r'(?i)authorization[":;\s]+basic\s+[A-Za-z0-9+/=]{8,}',        Severity.HIGH,     0.75),
    ("JWT Token",               r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', Severity.MEDIUM, 0.85),
    # Mots de passe hardcodés
    ("Password in code",        r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\'`][^"\'`]{4,}["\'`]', Severity.HIGH,  0.70),
    ("API Key generic",         r'(?i)api[_-]?key\s*[:=]\s*["\'`][A-Za-z0-9_\-]{16,}["\'`]',   Severity.HIGH,   0.65),
    # Slack
    ("Slack Bot Token",         r'xoxb-[A-Za-z0-9\-]{10,}',                                    Severity.HIGH,     0.95),
    ("Slack User Token",        r'xoxp-[A-Za-z0-9\-]{10,}',                                    Severity.HIGH,     0.95),
    ("Slack App Token",         r'xapp-[A-Za-z0-9\-]{10,}',                                    Severity.HIGH,     0.95),
    ("Slack Webhook",           r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+', Severity.HIGH, 0.99),
    # Discord
    ("Discord Token",           r'(?i)discord.{0,10}["\'`][A-Za-z0-9_\-\.]{59}["\'`]',        Severity.HIGH,     0.80),
    ("Discord Webhook",         r'https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+', Severity.HIGH, 0.99),
    # Divers SaaS
    ("Twilio SID",              r'AC[a-f0-9]{32}',                                              Severity.HIGH,     0.80),
    ("Twilio Auth Token",       r'(?i)twilio.{0,20}["\']([a-f0-9]{32})["\']',                  Severity.CRITICAL, 0.80),
    ("SendGrid Key",            r'SG\.[A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{22,}',               Severity.HIGH,     0.95),
    ("Mailgun Key",             r'key-[a-zA-Z0-9]{32}',                                         Severity.MEDIUM,   0.75),
    ("npm Token",               r'npm_[A-Za-z0-9]{36}',                                         Severity.HIGH,     0.99),
    ("Doppler Token",           r'dp\.pt\.[A-Za-z0-9]{40,}',                                    Severity.HIGH,     0.99),
    ("Linear API Key",          r'lin_api_[A-Za-z0-9]{40}',                                     Severity.HIGH,     0.99),
    ("Heroku API Key",          r'(?i)heroku.{0,10}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', Severity.HIGH, 0.85),
    # Firebase
    ("Firebase URL",            r'https://[a-z0-9-]+\.firebaseio\.com',                         Severity.MEDIUM,   0.90),
    ("Firebase Config",         r'(?i)firebase.{0,20}apiKey.{0,5}:\s*["\'`][A-Za-z0-9_\-]{20,}', Severity.HIGH, 0.80),
    # Infrastructure
    ("Internal IP",             r'(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}', Severity.LOW,  0.80),
    ("Internal endpoint",       r'(?:localhost|127\.0\.0\.1|::1)(?::\d+)?(?:/\S*)?',            Severity.MEDIUM,   0.85),
    ("Connection string",       r'(?i)(?:mongodb|mysql|postgres|redis|amqp)://[^\s"\'<>]{8,}',  Severity.CRITICAL, 0.90),
    # Terraform / HashiCorp
    ("HashiCorp Vault Token",   r'hvs\.[A-Za-z0-9_\-]{24,}',                                    Severity.CRITICAL, 0.99),
    ("Terraform Cloud Token",   r'(?i)terraform.{0,20}["\']([A-Za-z0-9\.]{14,})["\']',         Severity.HIGH,     0.70),
    # GCP
    ("GCP Service Account",     r'"type":\s*"service_account"',                                  Severity.CRITICAL, 0.95),
]

ENDPOINT_PATTERNS: list[tuple[str, str]] = [
    # REST classique
    ("rest",        r'(?:"|\'|`)(/(?:api|v\d|admin|internal|debug|graphql|rest|backend|service|auth)[^\s"\'`<>]*)'),
    ("sensitive",   r'(?:"|\'|`)(/[a-z0-9_\-/]+\.(?:json|xml|yaml|yml|bak|sql|env|config|cfg|log))'),
    # Fetch / Axios
    ("fetch",       r'fetch\(["\'`]([^"\'`\s]+)["\'`]'),
    ("axios",       r'axios\.(?:get|post|put|delete|patch|head)\(["\'`]([^"\'`\s]+)["\'`]'),
    # Variables de config
    ("url-var",     r'url\s*[:=]\s*["\'`]([^"\'`\s]{5,})["\'`]'),
    ("endpoint",    r'endpoint\s*[:=]\s*["\'`]([^"\'`\s]{5,})["\'`]'),
    ("baseURL",     r'baseURL\s*[:=]\s*["\'`]([^"\'`\s]{5,})["\'`]'),
    ("apiUrl",      r'(?i)api[_-]?(?:url|host|base)\s*[:=]\s*["\'`]([^"\'`\s]{5,})["\'`]'),
    # Absolute URLs
    ("absolute",    r'(?:"|\'|`)(https?://[^"\'`\s]{10,})'),
    # WebSocket
    ("websocket",   r'new\s+WebSocket\(["\'`]([^"\'`\s]+)["\'`]\)'),
    ("ws-url",      r'(?:ws|wss)://[^\s"\'`<>]{5,}'),
    # gRPC / tRPC
    ("grpc",        r'(?i)grpc[_\-.]?(?:client|channel|service)\s*\([^)]*["\'`]([^"\'`]+)["\'`]'),
    ("trpc",        r'createTRPCClient\s*\(\s*\{[^}]*url\s*:\s*["\'`]([^"\'`]+)["\'`]'),
    # GraphQL subscriptions
    ("gql-sub",     r'(?i)subscription\s*(?:[A-Za-z_]\w*)?\s*\{'),
    # Import dynamique / lazy load
    ("lazy",        r'import\s*\(\s*["\'`]([^"\'`]+)["\'`]\s*\)'),
]

SOURCE_MAP_PATTERN = re.compile(r'//[#@]\s*sourceMappingURL=(\S+)', re.I)


class JSAnalyzer:
    def __init__(self, req: Requester, cfg: PhantomConfig) -> None:
        self._req = req
        self._cfg = cfg
        # Déduplication cross-fichiers JS : (name, snippet_prefix)
        self._seen_secrets: set[tuple[str, str]] = set()
        self._seen_endpoints: set[str] = set()

    async def run(self, target: str) -> AsyncIterator[Finding]:
        resp = await self._req.get(target)
        if resp.error:
            return

        js_urls = self._extract_js_urls(resp.body, target)

        for js_url in js_urls[:30]:
            js_resp = await self._req.get(js_url)
            if js_resp.error or not js_resp.body:
                continue

            body = js_resp.body

            # 1. Secrets dans le JS minifié
            async for f in self._scan_secrets(body, js_url):
                yield f

            # 2. Endpoints cachés
            async for f in self._scan_endpoints(body, js_url, target):
                yield f

            # 3. Source maps — détection + fetch + parsing complet
            async for f in self._process_source_map(body, js_url, target):
                yield f

            # 4. Webpack chunk manifest
            async for f in self._check_webpack_chunks(body, js_url, target):
                yield f

    # ── Secrets ───────────────────────────────────────────────────────────────

    async def _scan_secrets(self, body: str, source_url: str) -> AsyncIterator[Finding]:
        for name, pattern, severity, min_confidence in SECRET_PATTERNS:
            try:
                matches = re.findall(pattern, body)
            except re.error:
                continue
            for match in matches[:5]:
                snippet = (match[:80] if isinstance(match, str) else str(match)[:80]).strip()
                if not snippet:
                    continue

                # Filtre de confiance : longueur minimale selon sévérité
                confidence = self._estimate_confidence(snippet, min_confidence)
                if confidence < min_confidence:
                    continue

                dedup_key = (name, snippet[:40])
                if dedup_key in self._seen_secrets:
                    continue
                self._seen_secrets.add(dedup_key)

                yield Finding(
                    title=f"Secret exposed: {name}",
                    severity=severity,
                    url=source_url,
                    module="recon/js_analyzer",
                    description=f"Secret potentiel trouvé dans {source_url} (confiance: {confidence:.0%})",
                    evidence=snippet,
                    cwe="CWE-312",
                    remediation="Ne jamais exposer de secrets dans le code JS côté client.",
                )

    @staticmethod
    def _estimate_confidence(snippet: str, base: float) -> float:
        """
        Ajuste la confiance selon des heuristiques simples :
        - snippet trop court → pénalité
        - caractères répétitifs (ex: 'aaaa...') → pénalité
        - entropy élevée → bonus
        """
        if len(snippet) < 8:
            return 0.0
        # Pénalité si trop de répétitions
        if len(set(snippet)) < 4:
            return base * 0.3
        # Bonus si entropy > seuil (présence de chiffres + lettres + symboles)
        has_digits = any(c.isdigit() for c in snippet)
        has_alpha = any(c.isalpha() for c in snippet)
        has_special = any(not c.isalnum() for c in snippet)
        bonus = 0.05 if (has_digits and has_alpha and has_special) else 0.0
        return min(1.0, base + bonus)

    # ── Endpoints ─────────────────────────────────────────────────────────────

    async def _scan_endpoints(
        self, body: str, js_url: str, target: str
    ) -> AsyncIterator[Finding]:
        for _label, pattern in ENDPOINT_PATTERNS:
            try:
                for m in re.finditer(pattern, body, re.I):
                    endpoint = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
                    if not endpoint or len(endpoint) < 3 or len(endpoint) > 200:
                        continue
                    # Ignorer les data URIs, placeholders, etc.
                    if endpoint.startswith(("data:", "{{", "${", "<%")):
                        continue
                    if endpoint in self._seen_endpoints:
                        continue
                    self._seen_endpoints.add(endpoint)

                    full_url = urljoin(target, endpoint) if endpoint.startswith("/") else endpoint
                    yield Finding(
                        title="Hidden endpoint discovered",
                        severity=Severity.LOW,
                        url=full_url,
                        module="recon/js_analyzer",
                        description=f"Endpoint extrait du JS ({_label}): {js_url}",
                        evidence=endpoint,
                    )
            except re.error:
                continue

    # ── Source maps ───────────────────────────────────────────────────────────

    async def _process_source_map(
        self, js_body: str, js_url: str, target: str
    ) -> AsyncIterator[Finding]:
        map_match = SOURCE_MAP_PATTERN.search(js_body)
        if not map_match:
            map_url = js_url + ".map"
        else:
            map_ref = map_match.group(1)
            if map_ref.startswith("data:application/json"):
                async for f in self._parse_inline_map(map_ref, js_url, target):
                    yield f
                return
            map_url = urljoin(js_url, map_ref)

        map_resp = await self._req.get(map_url)
        if map_resp.error or map_resp.status != 200:
            return

        async for f in self._parse_map_content(map_resp.body, map_url, js_url, target):
            yield f

    async def _parse_inline_map(
        self, data_uri: str, js_url: str, target: str
    ) -> AsyncIterator[Finding]:
        import base64
        try:
            _, encoded = data_uri.split(",", 1)
            raw = base64.b64decode(encoded).decode("utf-8", errors="replace")
            async for f in self._parse_map_content(raw, js_url + " (inline)", js_url, target):
                yield f
        except Exception:
            return

    async def _parse_map_content(
        self, raw: str, map_url: str, js_url: str, target: str
    ) -> AsyncIterator[Finding]:
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            yield Finding(
                title="Source map accessible (non parseable)",
                severity=Severity.LOW,
                url=map_url,
                module="recon/js_analyzer",
                description=f"Fichier .map accessible mais JSON invalide — issu de {js_url}",
                evidence=map_url,
                cwe="CWE-540",
            )
            return

        sources: list[str] = data.get("sources", [])
        sources_content: list[str | None] = data.get("sourcesContent", [])

        if not sources:
            return

        yield Finding(
            title=f"Source map exposed — {len(sources)} original files leaked",
            severity=Severity.HIGH,
            url=map_url,
            module="recon/js_analyzer",
            description=(
                f"La source map expose {len(sources)} fichier(s) source original(aux). "
                f"Le code source complet (TypeScript/React/Vue) est récupérable."
            ),
            evidence="\n".join(sources[:15]),
            cwe="CWE-540",
            remediation="Désactiver la génération de source maps en production (webpack: devtool: false).",
        )

        for i, content in enumerate(sources_content):
            if not content or not isinstance(content, str):
                continue
            src_name = sources[i] if i < len(sources) else f"source_{i}"
            async for f in self._scan_secrets(content, f"{map_url}#{src_name}"):
                f.severity = Severity.CRITICAL
                f.title = f"[SOURCE MAP] {f.title}"
                f.description = (
                    f"Secret dans le code source original `{src_name}` "
                    f"via la source map de {js_url}"
                )
                yield f

    # ── Webpack chunk manifest ────────────────────────────────────────────────

    async def _check_webpack_chunks(
        self, js_body: str, js_url: str, target: str
    ) -> AsyncIterator[Finding]:
        """
        Détecte les manifests de chunks webpack exposés (chunk-manifest.json,
        asset-manifest.json, webpack-stats.json) et yield un finding si accessible.
        """
        base = urljoin(js_url, "/")
        manifest_paths = [
            "asset-manifest.json",
            "chunk-manifest.json",
            "webpack-stats.json",
            "build-manifest.json",
        ]
        # Détecte aussi si le JS contient des chunk IDs webpack
        chunk_pattern = re.compile(r'webpackChunk[A-Za-z_]*\s*=\s*\[', re.I)
        if not chunk_pattern.search(js_body):
            return  # Pas de webpack détecté → skip

        for path in manifest_paths:
            url = urljoin(base, path)
            if url in self._seen_endpoints:
                continue
            resp = await self._req.get(url)
            if resp.error or resp.status != 200:
                continue
            # Vérifier que c'est bien du JSON
            try:
                json.loads(resp.body)
            except (json.JSONDecodeError, ValueError):
                continue

            self._seen_endpoints.add(url)
            yield Finding(
                title=f"Webpack manifest exposed: {path}",
                severity=Severity.MEDIUM,
                url=url,
                module="recon/js_analyzer",
                description=(
                    f"Le fichier `{path}` est accessible publiquement. "
                    f"Il expose la liste complète des chunks JS de l'application."
                ),
                evidence=resp.body[:300],
                cwe="CWE-540",
                remediation=(
                    "Restreindre l'accès aux fichiers de manifest en production "
                    "ou les exclure du répertoire public."
                ),
            )

    # ── Extraction d'URLs JS ──────────────────────────────────────────────────

    def _extract_js_urls(self, body: str, base_url: str) -> list[str]:
        pattern = re.compile(r'<script[^>]+src=["\'`]([^"\'`>\s]+\.js[^"\'`>\s]*)["\'`]', re.I)
        urls: list[str] = []
        seen: set[str] = set()
        for m in pattern.finditer(body):
            src = m.group(1)
            full = urljoin(base_url, src)
            if urlparse(full).scheme in ("http", "https") and full not in seen:
                seen.add(full)
                urls.append(full)
        return urls
