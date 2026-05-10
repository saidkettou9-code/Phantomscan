"""
PhantomScan — Exposed Panels Scanner [v5.16]
Détecte les panneaux d'administration et de monitoring exposés sans authentification
ou avec des credentials par défaut.

Panneaux ciblés (50+) :
- DevOps/CI : Jenkins, GitLab, Grafana, Kibana, Prometheus, Portainer, ArgoCD,
  Drone CI, Buildkite, CircleCI self-hosted, Concourse CI
- Admin DB : phpMyAdmin, Adminer, pgAdmin, MongoDB Express, Redis Commander,
  Elasticsearch, InfluxDB, CouchDB, RabbitMQ Management
- Infra/Cloud : Traefik Dashboard, Nginx Plus, Kong Admin, Consul UI, Vault UI,
  Nomad UI, etcd, Jaeger UI, Zipkin, Eureka, Swagger UI
- App Admin : Django Admin, Laravel Telescope, Laravel Horizon, Rails Admin,
  Spring Boot Admin, Strapi Admin, KeyCloak Admin, Netdata

Critères de confirmation :
- Titre/body HTML caractéristique
- Header WWW-Authenticate absent (panel ouvert)
- Credentials default testés si formulaire détecté
- Réponse 200 ou 302 avec redirection vers dashboard

Findings : CRITICAL si accès direct non authentifié, HIGH si default creds, MEDIUM si panel exposé (auth OK)
"""

from __future__ import annotations

import asyncio
import re
from typing import AsyncGenerator
from urllib.parse import urlparse, urljoin

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester, ProbeRequest
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity
from phantomscan.core.scanner_mixin import ScannerMixin


# ─────────────────────────── Panel signatures ────────────────────────────────

# (path, panel_name, body_signatures, title_signatures, severity_if_open)
_PANELS: list[tuple[str, str, list[str], list[str], Severity]] = [
    # DevOps / CI
    ("/",           "Jenkins",          ["var isRunAsRoot", "jenkins-head", "executors"],
                                        ["Dashboard [Jenkins]", "Jenkins"],                     Severity.CRITICAL),
    ("/jenkins",    "Jenkins",          ["var isRunAsRoot", "jenkins-head"],
                                        ["Dashboard [Jenkins]"],                                Severity.CRITICAL),
    ("/jenkins/",   "Jenkins",          ["jenkins-head", "executors"],
                                        ["Jenkins"],                                            Severity.CRITICAL),
    ("/login",      "GitLab",           ["gl-form-input", "data-testid=\"username-field\"", "GitLab Community"],
                                        ["Sign in · GitLab"],                                   Severity.MEDIUM),
    ("/grafana",    "Grafana",          ["grafana", "GrafanaBootData", "grafana-app"],
                                        ["Grafana"],                                            Severity.HIGH),
    ("/grafana/",   "Grafana",          ["grafana", "GrafanaBootData"],
                                        ["Grafana"],                                            Severity.HIGH),
    ("/",           "Grafana",          ["GrafanaBootData", "grafana-app"],
                                        ["Grafana"],                                            Severity.HIGH),
    ("/app/kibana", "Kibana",           ["kbn-global-banner", "kibanaWelcomeMessage", "__kbnBootstrap__"],
                                        ["Kibana"],                                             Severity.HIGH),
    ("/",           "Kibana",           ["kbn-global-banner", "__kbnBootstrap__"],
                                        ["Kibana"],                                             Severity.HIGH),
    ("/-/metrics",  "GitLab Metrics",  ["ruby_gc_stat", "puma_thread_pool"],
                                        [],                                                     Severity.HIGH),
    ("/portainer",  "Portainer",        ["portainer", "ng-app=\"portainer\""],
                                        ["Portainer"],                                          Severity.CRITICAL),
    ("/",           "Portainer",        ["ng-app=\"portainer\"", "portainer/logo"],
                                        ["Portainer"],                                          Severity.CRITICAL),
    ("/argo",       "ArgoCD",           ["argo-logo", "argocd-application"],
                                        ["Argo CD"],                                            Severity.CRITICAL),
    ("/",           "ArgoCD",           ["argo-logo", "argocd"],
                                        ["Argo CD"],                                            Severity.CRITICAL),
    ("/drone",      "Drone CI",         ["drone-logo", "drone/build"],
                                        ["Drone"],                                              Severity.HIGH),
    ("/concourse",  "Concourse CI",     ["concourse-logo"],
                                        ["Concourse"],                                          Severity.HIGH),

    # Database Admin
    ("/phpmyadmin", "phpMyAdmin",       ["phpmyadmin", "pma_password", "PMA_VERSION"],
                                        ["phpMyAdmin"],                                         Severity.CRITICAL),
    ("/phpmyadmin/","phpMyAdmin",       ["pma_password", "PMA_VERSION"],
                                        ["phpMyAdmin"],                                         Severity.CRITICAL),
    ("/pma",        "phpMyAdmin",       ["pma_password", "PMA_VERSION"],
                                        ["phpMyAdmin"],                                         Severity.CRITICAL),
    ("/adminer",    "Adminer",          ["adminer", "Adminer", "loginform"],
                                        ["Adminer"],                                            Severity.HIGH),
    ("/adminer.php","Adminer",          ["adminer", "loginform"],
                                        ["Adminer"],                                            Severity.HIGH),
    ("/pgadmin",    "pgAdmin",          ["pgadmin", "pgAdmin4"],
                                        ["pgAdmin 4"],                                          Severity.HIGH),
    ("/mongo-express", "Mongo Express", ["mongo_express", "db_list"],
                                        ["Home - Mongo Express"],                               Severity.CRITICAL),
    ("/redis-commander", "Redis Commander", ["redis_commander", "keyList"],
                                        ["Redis Commander"],                                    Severity.CRITICAL),
    ("/_cat/indices","Elasticsearch",  ["\"health\":", "\"index\":", "\"docs.count\":"],
                                        [],                                                     Severity.HIGH),
    ("/_cluster/health", "Elasticsearch", ["\"cluster_name\":", "\"status\":"],
                                        [],                                                     Severity.HIGH),
    ("/",           "CouchDB Fauxton", ["couchdb", "fauxton"],
                                        ["Project Fauxton", "Apache CouchDB"],                  Severity.HIGH),
    ("/couchdb",    "CouchDB",         ["couchdb"],
                                        ["Apache CouchDB"],                                     Severity.HIGH),
    ("/influxdb",   "InfluxDB",        ["influxdb", "InfluxDB"],
                                        ["InfluxDB"],                                           Severity.HIGH),

    # Infra / Monitoring
    ("/prometheus", "Prometheus",       ["prometheus_build_info", "tsdb_head_samples"],
                                        ["Prometheus"],                                         Severity.HIGH),
    ("/metrics",    "Prometheus Metrics",["prometheus_build_info", "go_gc_duration_seconds"],
                                        [],                                                     Severity.MEDIUM),
    ("/traefik",    "Traefik Dashboard",["traefik", "Traefik", "routers"],
                                        ["Traefik"],                                            Severity.HIGH),
    ("/dashboard/", "Traefik Dashboard",["traefik-ui", "Traefik"],
                                        ["Traefik"],                                            Severity.HIGH),
    ("/api/v1/services", "Kong Admin",  ["\"data\":", "\"next\":", "\"id\":"],
                                        [],                                                     Severity.CRITICAL),
    ("/v1/agent/self", "Consul UI",    ["\"Config\":", "\"NodeName\":"],
                                        [],                                                     Severity.HIGH),
    ("/ui/",        "Consul UI",        ["consul-ui", "consul"],
                                        ["Consul"],                                             Severity.HIGH),
    ("/ui",         "Vault UI",         ["vault-ui", "vault"],
                                        ["Vault"],                                              Severity.HIGH),
    ("/v1/sys/health", "Vault API",    ["\"initialized\":", "\"sealed\":"],
                                        [],                                                     Severity.HIGH),
    ("/ui/",        "Nomad UI",         ["nomad", "NomadUiRoutes"],
                                        ["Nomad"],                                              Severity.HIGH),
    ("/v2/keys",    "etcd",            ["\"action\":\"get\"", "\"node\":"],
                                        [],                                                     Severity.CRITICAL),
    ("/search",     "Jaeger UI",        ["jaeger", "jaeger-ui"],
                                        ["Jaeger UI"],                                          Severity.MEDIUM),
    ("/zipkin",     "Zipkin UI",        ["zipkin", "zipkin-ui"],
                                        ["Zipkin"],                                             Severity.MEDIUM),
    ("/eureka",     "Eureka",           ["eureka", "EUREKA"],
                                        ["Eureka"],                                             Severity.HIGH),
    ("/eureka/apps", "Eureka API",      ["<applications>", "<app>"],
                                        [],                                                     Severity.HIGH),
    ("/swagger-ui", "Swagger UI",       ["swagger-ui", "SwaggerUIBundle", "swagger.json"],
                                        ["Swagger UI"],                                         Severity.MEDIUM),
    ("/swagger-ui.html", "Swagger UI",  ["swagger-ui", "SwaggerUIBundle"],
                                        ["Swagger UI"],                                         Severity.MEDIUM),
    ("/api-docs",   "Swagger/OpenAPI",  ["swagger", "openapi"],
                                        ["API Docs", "Swagger"],                                Severity.MEDIUM),
    ("/api/swagger","Swagger/OpenAPI",  ["swagger", "openapi"],
                                        [],                                                     Severity.MEDIUM),
    ("/v3/api-docs","SpringDoc OpenAPI",["openapi", "\"paths\":"],
                                        [],                                                     Severity.MEDIUM),
    ("/netdata",    "Netdata",          ["netdata", "NETDATA"],
                                        ["Netdata"],                                            Severity.HIGH),
    ("/",           "Netdata",          ["netdata_version", "NETDATA.registry"],
                                        ["Netdata"],                                            Severity.HIGH),
    ("/rabbitmq",   "RabbitMQ Mgmt",   ["rabbitmq_management", "Management"],
                                        ["RabbitMQ Management"],                                Severity.HIGH),
    ("/api/overview", "RabbitMQ API",  ["\"rabbitmq_version\":"],
                                        [],                                                     Severity.HIGH),

    # App Admin panels
    ("/admin",      "Django Admin",     ["django-admin", "csrfmiddlewaretoken", "Log in | Django"],
                                        ["Site administration | Django", "Log in | Django"],    Severity.HIGH),
    ("/admin/",     "Django Admin",     ["django-admin", "csrfmiddlewaretoken"],
                                        ["Site administration | Django"],                       Severity.HIGH),
    ("/telescope",  "Laravel Telescope",["telescope", "Laravel Telescope"],
                                        ["Telescope"],                                          Severity.HIGH),
    ("/horizon",    "Laravel Horizon",  ["horizon", "Laravel Horizon"],
                                        ["Horizon"],                                            Severity.HIGH),
    ("/rails/info", "Rails Info",       ["Rails Info", "ruby_version", "rails_version"],
                                        ["Rails Info"],                                         Severity.HIGH),
    ("/rails/mailers", "Rails Mailers", ["rails", "ActionMailer"],
                                        ["Action Mailer"],                                      Severity.MEDIUM),
    ("/admin/strapi", "Strapi Admin",   ["strapi", "Strapi"],
                                        ["Strapi"],                                             Severity.HIGH),
    ("/auth/admin", "Keycloak Admin",   ["keycloak", "kc-locale-menu"],
                                        ["Keycloak Administration", "Welcome to Keycloak"],     Severity.HIGH),
    ("/instances",  "Spring Boot Admin",["spring-boot-admin", "sba-sidebar"],
                                        ["Spring Boot Admin"],                                  Severity.HIGH),
    ("/actuator",   "Spring Actuator",  ["\"_links\":", "\"health\":", "actuator"],
                                        [],                                                     Severity.HIGH),
    ("/actuator/env", "Spring Env",     ["\"activeProfiles\":", "\"propertySources\":"],
                                        [],                                                     Severity.CRITICAL),
    ("/actuator/heapdump", "Spring Heapdump", [],
                                        [],                                                     Severity.CRITICAL),
    # Misc
    ("/wp-admin",   "WordPress Admin",  ["wp-admin", "wp-login", "WordPress"],
                                        ["WordPress"],                                          Severity.MEDIUM),
    ("/wp-login.php","WordPress Login", ["wp-login", "user_login"],
                                        ["WordPress"],                                          Severity.MEDIUM),
    ("/manager/html", "Tomcat Manager", ["Tomcat Web Application Manager"],
                                        ["Tomcat Web Application Manager"],                     Severity.CRITICAL),
    ("/jmx-console","JBoss JMX Console",["JMX Agent View", "jmx-console"],
                                        ["JMX Agent View"],                                     Severity.CRITICAL),
]

# Credentials par défaut à tester sur les panels avec form POST
_DEFAULT_CREDS: list[tuple[str, str]] = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", ""),
    ("admin", "admin123"),
    ("root",  "root"),
    ("root",  ""),
    ("user",  "user"),
    ("admin", "grafana"),
    ("admin", "kibana"),
    ("admin", "portainer"),
]

# Panels où tester les creds par défaut (path prefix → form POST path + fields)
_DEFAULT_CRED_PANELS: dict[str, dict] = {
    "grafana": {
        "login_path": "/login",
        "method": "POST",
        "json_body": {"user": "{username}", "password": "{password}"},
        "success_status": [200],
        "success_body": ["\"message\":\"Logged in\"", "orgId"],
    },
    "portainer": {
        "login_path": "/api/auth",
        "method": "POST",
        "json_body": {"Username": "{username}", "Password": "{password}"},
        "success_status": [200],
        "success_body": ["jwt"],
    },
    "kibana": {
        "login_path": "/internal/security/login",
        "method": "POST",
        "json_body": {"providerType": "basic", "providerName": "basic",
                      "currentURL": "/", "params": {"username": "{username}", "password": "{password}"}},
        "success_status": [200, 204],
        "success_body": ["location", "redirectUrl"],
    },
}


class ExposedPanelsScanner(ScannerMixin):

    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req  = req
        self._h    = heuristic
        self._cfg  = cfg

    async def run(self, target: str) -> AsyncGenerator[Finding, None]:
        parsed = urlparse(target)
        base   = f"{parsed.scheme}://{parsed.netloc}"

        # Déduplique les paths à tester
        seen_paths: set[str] = set()
        tasks = []
        for path, panel, body_sigs, title_sigs, sev in _PANELS:
            if path not in seen_paths:
                seen_paths.add(path)
            tasks.append((path, panel, body_sigs, title_sigs, sev))

        # Regroupe par path unique → envoie 1 requête par path, vérifie N panels
        path_to_panels: dict[str, list] = {}
        for path, panel, body_sigs, title_sigs, sev in tasks:
            path_to_panels.setdefault(path, []).append((panel, body_sigs, title_sigs, sev))

        for path, panel_checks in path_to_panels.items():
            url = urljoin(base, path)
            resp = await self._req.send(ProbeRequest(method="GET", url=url))
            if resp.error or resp.status_code in (404, 400, 500):
                continue

            body  = (resp.body or "")[:8000]
            title = self._extract_title(body)

            for panel, body_sigs, title_sigs, base_sev in panel_checks:
                matched_body  = [s for s in body_sigs  if s.lower() in body.lower()]
                matched_title = [s for s in title_sigs if s.lower() in title.lower()]

                if not matched_body and not matched_title:
                    continue

                # FP-FIX: exiger une confirmation minimale pour éviter les faux positifs
                # sur des pages qui mentionnent le nom d'un panel sans l'héberger.
                # Règle : au moins 2 signatures body, OU (1 body + 1 title), OU 2 title.
                confidence = len(matched_body) * 2 + len(matched_title)
                # fix v5.18-fp: seuil relevé 2→4 (1 sig body = confidence=2 passait, FP sur footer/meta)
                if confidence < 4:
                    continue

                # Panel trouvé — détermine si ouvert ou auth
                is_open = resp.status_code == 200 and not self._has_auth(resp)
                sev = base_sev if is_open else Severity.MEDIUM

                # Teste les creds par défaut si panel connu
                default_cred_result = await self._try_default_creds(base, panel, resp)

                if default_cred_result:
                    sev = Severity.CRITICAL
                    evidence = f"HTTP {resp.status_code} — panel détecté + credentials par défaut valides : {default_cred_result}"
                    description = (
                        f"Le panel {panel} à `{url}` est accessible avec des credentials par défaut "
                        f"({default_cred_result}). Accès non autorisé probable à des fonctionnalités privilégiées."
                    )
                elif is_open:
                    evidence = f"HTTP {resp.status_code} — pas d'auth requise. Signatures: {matched_body or matched_title}"
                    description = (
                        f"Le panel d'administration {panel} à `{url}` est accessible sans authentification. "
                        f"Ce type d'interface expose des fonctionnalités critiques (exécution de code, accès données, "
                        f"configuration infrastructure) directement à des tiers non autorisés."
                    )
                else:
                    evidence = f"HTTP {resp.status_code} — panel détecté (auth présente). Signatures: {matched_body or matched_title}"
                    description = (
                        f"Le panel {panel} à `{url}` est exposé sur Internet (auth requise). "
                        f"Vérifier que l'accès est restreint par IP ou VPN."
                    )

                yield Finding(
                    title       = f"Exposed Panel: {panel}" + (" [No Auth]" if is_open else "") + (" [Default Creds]" if default_cred_result else ""),
                    severity    = sev,
                    url         = url,
                    module      = "ExposedPanelsScanner",
                    description = description,
                    evidence    = evidence,
                    remediation = (
                        "Restreindre l'accès à ce panel par IP (firewall/allowlist), VPN, ou supprimer "
                        "l'exposition publique. Si des credentials par défaut sont valides, les changer immédiatement. "
                        "Ne jamais exposer des interfaces d'administration sur Internet sans MFA."
                    ),
                    cwe  = "CWE-284",
                    cvss = 9.8 if default_cred_result else (8.6 if is_open else 5.3),
                    extra = {
                        "panel": panel,
                        "path": path,
                        "is_open": is_open,
                        "default_creds": default_cred_result,
                        "matched_signatures": matched_body + matched_title,
                    },
                )
                break  # Un seul finding par path (premier match)

    # ─────────────────────────── Helpers ────────────────────────────────────

    def _extract_title(self, body: str) -> str:
        m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        return m.group(1).strip() if m else ""

    def _has_auth(self, resp) -> bool:
        """Retourne True si la réponse indique une authentification requise."""
        headers = {k.lower(): v for k, v in (resp.headers or {}).items()}
        if "www-authenticate" in headers:
            return True
        if resp.status_code in (401, 403):
            return True
        body_lower = (resp.body or "").lower()
        # FP-FIX: seuil relevé 3→4 et mots plus spécifiques.
        # "login" seul est trop générique (pages publiques, footer links, etc.)
        # On exige des marqueurs d'un vrai formulaire de connexion.
        auth_keywords = ["password", "passwd", "username", "authenticate",
                         "sign in", "log in", "email", "remember me"]
        hits = sum(1 for kw in auth_keywords if kw in body_lower)
        # Vérifier aussi la présence d'un form avec method POST pointant vers un endpoint auth
        has_login_form = bool(re.search(
            r'<form[^>]*(?:action=["\'][^"\']*(?:login|signin|auth|session)[^"\']*["\']|method=["\']post["\'])[^>]*>',
            body_lower, re.I
        ))
        return hits >= 4 or has_login_form

    async def _try_default_creds(self, base: str, panel: str, initial_resp) -> str | None:
        """Teste les credentials par défaut sur les panels supportés. Retourne 'user:pass' si succès."""
        panel_key = panel.lower().split()[0]  # Ex: "grafana" de "Grafana Dashboard"
        if panel_key not in _DEFAULT_CRED_PANELS:
            return None

        import json
        spec = _DEFAULT_CRED_PANELS[panel_key]
        login_url = urljoin(base, spec["login_path"])

        for username, password in _DEFAULT_CREDS[:4]:  # Limite à 4 paires pour éviter lockout
            body_template = spec.get("json_body", {})
            body_str = json.dumps({
                k: v.replace("{username}", username).replace("{password}", password)
                if isinstance(v, str) else v
                for k, v in body_template.items()
            })
            resp = await self._req.send(ProbeRequest(
                method  = spec["method"],
                url     = login_url,
                headers = {"Content-Type": "application/json"},
                body    = body_str,
            ))
            if resp.error:
                continue
            if resp.status_code in spec["success_status"]:
                body = resp.body or ""
                if any(sig in body for sig in spec["success_body"]):
                    return f"{username}:{password}"
            await asyncio.sleep(0.3)  # Petit délai anti-lockout

        return None
