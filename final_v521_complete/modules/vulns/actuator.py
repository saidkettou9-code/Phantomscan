"""
PhantomScan — Spring Boot Actuator Scanner  v1.0
Détection et exploitation des endpoints Spring Boot Actuator exposés.

Stratégie:
  1. Découverte via /actuator (index JSON) + probing direct des endpoints connus
  2. Classification par sévérité (env/heapdump/logfile = CRITICAL, health/info = INFO)
  3. Extraction de secrets depuis /actuator/env (masquage partiel Spring → bypass)
  4. Détection de l'endpoint /actuator/gateway/routes (Spring Cloud Gateway — SSRF possible)
  5. Tentative de shutdown via POST /actuator/shutdown
"""

from __future__ import annotations

import json
import re
from typing import AsyncIterator

from phantomscan.core.requester import Requester, ProbeRequest
from phantomscan.config import PhantomConfig
from phantomscan.output.reporter import Finding, Severity
from phantomscan.core.scanner_mixin import ScannerMixin


# ---------------------------------------------------------------------------
# Catalogue des endpoints Actuator connus
# ---------------------------------------------------------------------------
_ACTUATOR_ENDPOINTS: list[dict] = [
    # ── CRITICAL ────────────────────────────────────────────────────────────
    {
        "path": "env",
        "severity": Severity.CRITICAL,
        "description": (
            "Expose toutes les propriétés d'environnement : variables système, "
            "credentials de base de données, clés API, secrets Spring Cloud Config."
        ),
        "cwe": "CWE-200",
        "remediation": "Désactiver ou protéger /actuator/env avec Spring Security.",
    },
    {
        "path": "heapdump",
        "severity": Severity.CRITICAL,
        "description": (
            "Télécharge un dump mémoire JVM complet. "
            "Peut contenir des mots de passe, tokens, données utilisateurs en clair."
        ),
        "cwe": "CWE-200",
        "remediation": "Désactiver /actuator/heapdump en production.",
    },
    {
        "path": "threaddump",
        "severity": Severity.HIGH,
        "description": "Expose l'état complet des threads JVM (stack traces, locks).",
        "cwe": "CWE-200",
        "remediation": "Restreindre l'accès à /actuator/threaddump.",
    },
    {
        "path": "logfile",
        "severity": Severity.HIGH,
        "description": "Retourne le fichier de log applicatif — peut contenir des données sensibles.",
        "cwe": "CWE-532",
        "remediation": "Désactiver ou protéger /actuator/logfile.",
    },
    {
        "path": "httptrace",
        "severity": Severity.HIGH,
        "description": (
            "Expose les 100 dernières requêtes HTTP traitées par l'application "
            "(URL, headers, body partiels). Peut révéler des tokens Bearer, cookies."
        ),
        "cwe": "CWE-200",
        "remediation": "Désactiver /actuator/httptrace.",
    },
    {
        "path": "mappings",
        "severity": Severity.MEDIUM,
        "description": "Liste toutes les routes Spring MVC/WebFlux de l'application.",
        "cwe": "CWE-200",
        "remediation": "Restreindre /actuator/mappings aux équipes internes.",
    },
    {
        "path": "beans",
        "severity": Severity.MEDIUM,
        "description": "Expose tous les Spring Beans instanciés — architecture complète révélée.",
        "cwe": "CWE-200",
        "remediation": "Désactiver /actuator/beans en production.",
    },
    {
        "path": "configprops",
        "severity": Severity.HIGH,
        "description": "Expose toutes les @ConfigurationProperties — souvent des credentials partiels.",
        "cwe": "CWE-200",
        "remediation": "Désactiver ou protéger /actuator/configprops.",
    },
    {
        "path": "loggers",
        "severity": Severity.MEDIUM,
        "description": "Permet de modifier les niveaux de log à chaud via POST. Risque de log flooding.",
        "cwe": "CWE-400",
        "remediation": "Protéger /actuator/loggers contre les modifications non autorisées.",
    },
    {
        "path": "metrics",
        "severity": Severity.LOW,
        "description": "Expose des métriques applicatives (JVM, HTTP, custom).",
        "cwe": "CWE-200",
        "remediation": "Filtrer les métriques exposées publiquement.",
    },
    {
        "path": "scheduledtasks",
        "severity": Severity.LOW,
        "description": "Liste les tâches planifiées Spring (@Scheduled) et leurs expressions cron.",
        "cwe": "CWE-200",
        "remediation": "Désactiver /actuator/scheduledtasks en production.",
    },
    {
        "path": "caches",
        "severity": Severity.LOW,
        "description": "Expose et permet de vider les caches applicatifs via DELETE.",
        "cwe": "CWE-284",
        "remediation": "Protéger /actuator/caches contre les suppressions non autorisées.",
    },
    {
        "path": "health",
        "severity": Severity.INFO,
        "description": "Endpoint de health check — peut exposer des détails d'infrastructure.",
        "cwe": "CWE-200",
        "remediation": "Utiliser management.endpoint.health.show-details=never en production.",
    },
    {
        "path": "info",
        "severity": Severity.INFO,
        "description": "Expose des métadonnées de l'application (version, git commit, build).",
        "cwe": "CWE-200",
        "remediation": "Vider ou restreindre les informations exposées via /actuator/info.",
    },
    # ── Spring Cloud Gateway (SSRF via routage) ────────────────────────────
    {
        "path": "gateway/routes",
        "severity": Severity.HIGH,
        "description": (
            "Spring Cloud Gateway : expose toutes les routes configurées. "
            "L'ajout de routes via POST peut permettre des SSRF côté serveur."
        ),
        "cwe": "CWE-918",
        "remediation": "Désactiver les endpoints gateway Actuator ou les protéger avec Spring Security.",
    },
    # ── Spring Boot Admin (registre de services) ───────────────────────────
    {
        "path": "jolokia",
        "severity": Severity.CRITICAL,
        "description": (
            "Jolokia JMX-over-HTTP : permet l'exécution de MBeans arbitraires. "
            "Peut mener à une RCE via MLet ou ClassLoader."
        ),
        "cwe": "CWE-284",
        "remediation": "Désactiver Jolokia en production ou restreindre les MBeans autorisés.",
    },
]

# Chemins préfixe candidats (Spring Boot 1.x vs 2.x+)
_ACTUATOR_PREFIXES = ["/actuator", "/manage", "/management", "/_manage"]

# Patterns de secrets dans /actuator/env (Spring masque avec *** mais pas toujours)
_ENV_SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("password",    re.compile(r'(?i)"[^"]*(?:password|passwd|pwd|secret|token|key|auth)[^"]*"\s*:\s*\{[^}]*"value"\s*:\s*"([^*][^"]+)"')),
    ("masked",      re.compile(r'"value"\s*:\s*"\*{3,}"')),  # détecte les champs masqués → signaler leur existence
    ("db_url",      re.compile(r'(?i)"(?:spring\.datasource\.url|jdbc\.url)"\s*:\s*\{[^}]*"value"\s*:\s*"([^"]+)"')),
]


class ActuatorScanner(ScannerMixin):
    def __init__(self, req: Requester, heuristic=None, cfg: "PhantomConfig | None" = None) -> None:
        self._req = req
        # heuristic accepté pour compatibilité avec le moteur (non utilisé)
        self._cfg = cfg

    async def run(self, target: str) -> AsyncIterator[Finding]:
        base = target.rstrip("/")

        for prefix in _ACTUATOR_PREFIXES:
            async for f in self._probe_prefix(base, prefix):
                yield f

    async def _probe_prefix(self, base: str, prefix: str) -> AsyncIterator[Finding]:
        actuator_root = f"{base}{prefix}"

        # ── Étape 1 : vérifier l'index /actuator ────────────────────────────
        index_resp = await self._req.get(actuator_root)
        enabled_paths: set[str] = set()

        if not index_resp.error and index_resp.status == 200:
            enabled_paths = self._parse_actuator_index(index_resp.body)
            if enabled_paths:
                yield Finding(
                    title=f"Spring Boot Actuator exposed: {actuator_root}",
                    severity=Severity.HIGH,
                    url=actuator_root,
                    module="vulns/actuator",
                    description=(
                        f"L'index Actuator est accessible et liste {len(enabled_paths)} endpoint(s) actif(s)."
                    ),
                    evidence=f"Endpoints: {', '.join(sorted(enabled_paths)[:20])}",
                    cwe="CWE-200",
                    remediation=(
                        "Désactiver l'exposition de l'index Actuator ou le protéger avec Spring Security. "
                        "Utiliser management.endpoints.web.exposure.include=health,info uniquement."
                    ),
                )

        # ── Étape 2 : probe de chaque endpoint connu ─────────────────────────
        for ep_def in _ACTUATOR_ENDPOINTS:
            ep_path = ep_def["path"]
            ep_url = f"{actuator_root}/{ep_path}"

            # v5.20 — DedupIndex : skip si déjà testé sur cet endpoint
            if await self.should_skip(ep_url, "GET", "actuator"):
                continue

            # Skip si l'index a répondu et ne liste pas cet endpoint
            # (mais tester quand même — l'index peut être incomplet)
            resp = await self._req.get(ep_url)
            if resp.error or resp.status not in (200, 204):
                continue

            # Ignorer les réponses HTML génériques (ex: page 200 par défaut)
            if resp.status == 200 and self._looks_like_html_catch_all(resp.body):
                continue

            # FIX fp: pour les endpoints non-triviaux, exiger du JSON structuré valide
            # Un vrai endpoint Actuator retourne du JSON, pas du texte ou du JSON générique
            if resp.status == 200 and ep_path not in ("health", "info", "logfile"):
                if not self._looks_like_actuator_json(resp.body, ep_path):
                    continue

            # v5.20 — re-probe pour confirmer (évite les FP transitoires)
            resp2 = await self.re_probe(ep_url, delay_s=0.4)
            if resp2 is None or resp2.status not in (200, 204):
                continue  # non reproductible → FP
            await self.mark_tested(ep_url, "GET", "actuator")

            yield Finding(
                title=f"Actuator endpoint exposed: /{ep_path}",
                severity=ep_def["severity"],
                url=ep_url,
                module="vulns/actuator",
                description=ep_def["description"],
                evidence=f"HTTP {resp.status} — {resp.content_length}B",
                cwe=ep_def.get("cwe", "CWE-200"),
                remediation=ep_def["remediation"],
            )

            # ── Analyse spéciale /actuator/env ───────────────────────────────
            if ep_path == "env" and resp.status == 200:
                async for f in self._analyze_env(resp.body, ep_url):
                    yield f

            # ── Détection shutdown (POST) ────────────────────────────────────
            if ep_path == "health":
                async for f in self._probe_shutdown(actuator_root):
                    yield f

    # ── Analyse /actuator/env ────────────────────────────────────────────────

    async def _analyze_env(self, body: str, env_url: str) -> AsyncIterator[Finding]:
        """
        Parse le JSON /actuator/env et recherche :
        - Credentials en clair (non masqués)
        - Champs masqués (***) — signaler leur existence
        - URLs JDBC exposées
        """
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            return

        # Chercher dans propertySources
        property_sources = data.get("propertySources", [])
        exposed_secrets: list[str] = []
        masked_fields: list[str] = []

        for source in property_sources:
            source_name = source.get("name", "?")
            properties = source.get("properties", {})
            for prop_key, prop_val in properties.items():
                val = prop_val.get("value", "") if isinstance(prop_val, dict) else str(prop_val)
                val_str = str(val)

                if "***" in val_str:
                    masked_fields.append(f"{source_name}::{prop_key}")
                elif re.search(r'(?i)(password|secret|token|api[_-]?key|credential)', prop_key):
                    exposed_secrets.append(f"{prop_key}={val_str[:60]}")

        if exposed_secrets:
            yield Finding(
                title="Actuator /env — credentials exposed in plaintext",
                severity=Severity.CRITICAL,
                url=env_url,
                module="vulns/actuator",
                description=(
                    f"{len(exposed_secrets)} propriété(s) sensible(s) exposée(s) en clair "
                    f"dans /actuator/env. Non masquées par Spring Security."
                ),
                evidence="\n".join(exposed_secrets[:10]),
                cwe="CWE-312",
                remediation=(
                    "Utiliser spring.config.import=configserver: et ne jamais stocker "
                    "de secrets dans application.properties. Protéger /actuator/env."
                ),
            )

        if masked_fields:
            yield Finding(
                title="Actuator /env — sensitive properties present (masked)",
                severity=Severity.MEDIUM,
                url=env_url,
                module="vulns/actuator",
                description=(
                    f"{len(masked_fields)} propriété(s) masquée(s) détectée(s) dans /actuator/env. "
                    f"Spring les masque avec *** mais confirme leur existence."
                ),
                evidence="\n".join(masked_fields[:10]),
                cwe="CWE-200",
                remediation="Désactiver /actuator/env en production.",
            )

    # ── Shutdown probe ───────────────────────────────────────────────────────

    async def _probe_shutdown(self, actuator_root: str) -> AsyncIterator[Finding]:
        """Teste si POST /actuator/shutdown est activé (DoS potentiel)."""
        shutdown_url = f"{actuator_root}/shutdown"
        resp = await self._req.send(ProbeRequest(
            method="POST",
            url=shutdown_url,
            headers={"Content-Type": "application/json"},
            body="{}",
            timeout=5,
        ))
        # Un 200 ou 204 indique que l'endpoint est actif et a traité la requête
        if not resp.error and resp.status in (200, 204):
            yield Finding(
                title="Actuator /shutdown ENABLED — DoS possible",
                severity=Severity.CRITICAL,
                url=shutdown_url,
                module="vulns/actuator",
                description=(
                    "L'endpoint POST /actuator/shutdown est actif. "
                    "N'importe qui peut arrêter le serveur applicatif à distance."
                ),
                evidence=f"POST {shutdown_url} → HTTP {resp.status}",
                cwe="CWE-284",
                remediation=(
                    "Désactiver shutdown : management.endpoint.shutdown.enabled=false "
                    "ou protéger avec Spring Security."
                ),
            )
        elif not resp.error and resp.status == 405:
            # 405 Method Not Allowed → endpoint existe mais méthode refusée (normal)
            pass

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _parse_actuator_index(body: str) -> set[str]:
        """Parse l'index JSON /actuator et retourne les paths des endpoints listés."""
        try:
            data = json.loads(body)
            links = data.get("_links", {})
            paths: set[str] = set()
            for key, val in links.items():
                if key == "self":
                    continue
                href = val.get("href", "") if isinstance(val, dict) else ""
                if href:
                    # Extraire le segment final du href
                    paths.add(href.rstrip("/").rsplit("/", 1)[-1])
            return paths
        except (json.JSONDecodeError, ValueError, AttributeError):
            return set()

    @staticmethod
    def _looks_like_html_catch_all(body: str) -> bool:
        """Détecte une page HTML générique (catch-all 200) pour éviter les faux positifs."""
        if not body:
            return False
        b = body[:500].lower()
        # Pas de JSON → probablement HTML
        if b.lstrip().startswith("{") or b.lstrip().startswith("["):
            return False
        return "<html" in b or "<!doctype" in b

    @staticmethod
    def _looks_like_actuator_json(body: str, ep_path: str) -> bool:
        """
        FIX fp: vérifie que le JSON retourné ressemble vraiment à un endpoint Actuator.
        Les soft-404 JSON génériques (ex: {"status":"ok","message":"not found"})
        ne contiennent pas les clés spécifiques aux endpoints Spring Boot.
        """
        if not body:
            return False
        b = body.lstrip()
        # Doit être du JSON
        if not (b.startswith("{") or b.startswith("[")):
            return False
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            return False

        # Clés attendues par endpoint
        _EXPECTED_KEYS: dict[str, list[str]] = {
            "env":           ["propertySources", "activeProfiles", "systemProperties"],
            "beans":         ["contexts", "beans"],
            "configprops":   ["contexts", "beans"],
            "mappings":      ["contexts", "mappings"],
            "metrics":       ["names", "availableTags"],
            "threaddump":    ["threads"],
            "httptrace":     ["traces"],
            "scheduledtasks":["cron", "fixedDelay", "fixedRate"],
            "caches":        ["cacheManagers"],
            "loggers":       ["levels", "loggers"],
            "heapdump":      [],  # binaire, toujours valide si 200
        }

        expected = _EXPECTED_KEYS.get(ep_path, [])
        if not expected:
            # endpoint inconnu ou binaire → laisser passer
            return True

        if isinstance(data, dict):
            return any(k in data for k in expected)

        # Réponse en liste → inattendu pour Actuator, probablement FP
        return False
