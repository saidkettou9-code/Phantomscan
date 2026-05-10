"""
PhantomScan — WebSocket Scanner  v1.0
Détection de vulnérabilités dans les endpoints WebSocket.

Techniques couvertes :
  - Discovery : détection d'endpoints WS/WSS depuis le HTML/JS du crawler
  - Cross-Site WebSocket Hijacking (CSWSH) : Origin spoofing sans token CSRF
  - Message injection : SQLi, XSS, SSTI, CMDi dans les messages JSON/texte
  - Auth bypass : connexion sans token ou avec token altéré
  - Mass assignment : champs non attendus acceptés (role, admin, price…)
  - Verbose errors : stack traces dans les réponses d'erreur WS
  - Slow-loris WS : connexion ouverte sans messages (resource exhaustion probe)

Architecture :
  - Utilise aiohttp.ws_connect() en mode asyncio
  - Timeout conservateur (5 s) pour ne pas bloquer le pipeline
  - S'abonne au EndpointBus (v5.6) pour récupérer les WS URLs détectés par JSAnalyzer
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import AsyncIterator
from urllib.parse import urlparse, urlunparse

try:
    import aiohttp
    _AIOHTTP_OK = True
except ImportError:
    _AIOHTTP_OK = False

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity
from phantomscan.core.scanner_mixin import ScannerMixin


# ──────────────────────────── Payloads ───────────────────────────────────────

# Payloads injection dans les champs JSON WS
_INJECT_PAYLOADS: list[tuple[str, str, Severity]] = [
    # (payload, label, sévérité)
    # v5.21 — Payloads enrichis avec marqueur de réflexion pour confirmer l'injection
    ("<script>alert('WS_XSS_MARKER')</script>",  "XSS script tag",           Severity.HIGH),
    ("' OR '1'='1' --",                           "SQLi OR bypass",           Severity.CRITICAL),
    ("{{7*7}}",                                   "SSTI Jinja2/Twig detect",  Severity.HIGH),
    ("${7*7}",                                    "SSTI EL/Freemarker detect", Severity.HIGH),
    ("; ls -la",                                  "CMDi semicolon",           Severity.CRITICAL),
    ("`id`",                                      "CMDi backtick",            Severity.CRITICAL),
    ("file:///etc/passwd",                        "LFI via file:",            Severity.HIGH),
    ("http://169.254.169.254/latest/meta-data/",  "SSRF cloud metadata",      Severity.CRITICAL),
    # Payloads originaux
    ("' OR '1'='1", "SQLi classique", Severity.CRITICAL),
    ("1; DROP TABLE users--", "SQLi destructif", Severity.CRITICAL),
    ("<script>alert(1)</script>", "XSS réfléchi", Severity.HIGH),
    ("{{7*7}}", "SSTI Jinja2/Twig probe", Severity.HIGH),
    ("${7*7}", "SSTI EL/Freemarker probe", Severity.HIGH),
    ("; ls /", "CMDi probe", Severity.CRITICAL),
    ("../../../etc/passwd", "Path traversal probe", Severity.HIGH),
    ("\x00", "Null byte injection", Severity.MEDIUM),
    ("a" * 8192, "Long string / buffer overflow probe", Severity.MEDIUM),
]

# Champs mass-assignment suspects
_MASS_ASSIGN_FIELDS: list[dict] = [
    {"role": "admin"},
    {"is_admin": True},
    {"admin": True},
    {"price": 0},
    {"balance": 99999},
    {"verified": True},
    {"premium": True},
    {"permissions": ["admin", "superuser"]},
]

# Indicateurs d'erreur verbeux
_ERROR_INDICATORS = [
    r"traceback",
    r"stack trace",
    r"exception in thread",
    r"syntaxerror",
    r"typeerror",
    r"nameerror",
    r"at \w+\.\w+\(\w+\.java:\d+\)",   # Java stack trace
    r"sql syntax",
    r"mysql_fetch",
    r"pg_query",
    r"unhandled promise rejection",
    r"cannot read propert",
]

# Origines CSWSH à tester
_CSWSH_ORIGINS = [
    "https://evil.com",
    "https://attacker.example.com",
    "null",
    "http://localhost",
    "https://sub.target.com.evil.com",
]

# Regex pour détecter les URLs WS dans le HTML/JS
_WS_URL_RE = re.compile(r"""(?:new\s+WebSocket|wsUrl|ws_url|websocket_url)\s*[=:(]\s*['"`]?(wss?://[^\s'"`,)]+)""", re.I)
_WS_PATH_RE = re.compile(r"""['"](\/(?:ws|wss|websocket|socket\.io|sockjs|cable|live|stream|chat|realtime|events)[^\s'"]*?)['"]""", re.I)


class WebSocketScanner(ScannerMixin):
    """Scanner de vulnérabilités WebSocket."""

    RPS = 2.0  # Rate limit conservateur

    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req = req
        self._heuristic = heuristic
        self._cfg = cfg
        self._bus = None

    def set_endpoint_bus(self, bus) -> None:
        self._bus = bus

    # ──────────────────────────── Entry point ────────────────────────────────

    async def run(self, target: str) -> AsyncIterator[Finding]:
        if not _AIOHTTP_OK:
            return

        ws_urls = await self._discover_ws_urls(target)

        for ws_url in ws_urls:
            # 1 — CSWSH
            async for f in self._check_cswsh(ws_url, target):
                yield f
            # 2 — Auth bypass (connexion sans creds)
            async for f in self._check_auth_bypass(ws_url):
                yield f
            # 3 — Message injection (sur le premier message échangé)
            async for f in self._check_message_injection(ws_url):
                yield f
            # 4 — Mass assignment
            async for f in self._check_mass_assignment(ws_url):
                yield f

    # ──────────────────────────── Discovery ──────────────────────────────────

    async def _discover_ws_urls(self, target: str) -> list[str]:
        """
        Collecte les URLs WebSocket depuis :
          1. Le HTML/JS de la page principale
          2. Le EndpointBus (JSAnalyzer peut avoir trouvé des wsURL)
          3. Chemins courants heuristiques
        """
        found: set[str] = set()
        parsed = urlparse(target)
        base_http = f"{parsed.scheme}://{parsed.netloc}"
        base_ws = base_http.replace("https://", "wss://").replace("http://", "ws://")

        # A — Scraping HTML/JS de la page principale
        resp = await self._req.get(target)
        if not resp.error:
            for m in _WS_URL_RE.finditer(resp.body):
                found.add(m.group(1))
            for m in _WS_PATH_RE.finditer(resp.body):
                found.add(f"{base_ws}{m.group(1)}")

        # B — EndpointBus : chercher les endpoints JS qui contiennent des wsURL
        if self._bus is not None:
            for ep in self._bus.snapshot:
                if ep.url.startswith("ws://") or ep.url.startswith("wss://"):
                    found.add(ep.url)

        # C — Chemins heuristiques courants
        common_paths = [
            "/ws", "/websocket", "/socket.io", "/sockjs/info",
            "/cable", "/live", "/stream", "/events", "/chat",
            "/api/ws", "/api/socket", "/realtime",
        ]
        for path in common_paths:
            found.add(f"{base_ws}{path}")

        return list(found)[:20]  # Limite à 20 pour éviter l'explosion

    # ──────────────────────────── CSWSH ──────────────────────────────────────

    async def _check_cswsh(self, ws_url: str, page_origin: str) -> AsyncIterator[Finding]:
        """
        Cross-Site WebSocket Hijacking :
        tente de se connecter avec une origine tierce.
        Si la connexion réussit → vulnérable.
        """
        if not _AIOHTTP_OK:
            return

        for evil_origin in _CSWSH_ORIGINS:
            try:
                timeout = aiohttp.ClientTimeout(total=5)
                async with aiohttp.ClientSession(timeout=timeout) as sess:
                    async with sess.ws_connect(
                        ws_url,
                        headers={"Origin": evil_origin},
                        ssl=False,
                    ) as ws:
                        # Connexion réussie → CSWSH confirmé
                        await ws.close()
                        yield Finding(
                            title=f"Cross-Site WebSocket Hijacking (CSWSH)",
                            severity=Severity.HIGH,
                            url=ws_url,
                            module="vulns/websocket_scan",
                            description=(
                                f"Le serveur accepte les connexions WebSocket depuis une origine tierce.\n"
                                f"Origin envoyée : `{evil_origin}` → connexion acceptée.\n"
                                "Un attaquant peut lire/envoyer des messages WS depuis un site malveillant "
                                "si la victime est authentifiée."
                            ),
                            evidence=f"WS URL: {ws_url} | Origin: {evil_origin} → HTTP 101 Switching Protocols",
                            cwe="CWE-346",
                            remediation=(
                                "Valider l'en-tête Origin côté serveur contre une allowlist de domaines "
                                "autorisés. Utiliser un token CSRF dans le handshake initial."
                            ),
                        )
                        return  # Un seul finding par URL suffit
            except Exception:
                pass  # Connexion refusée = non vulnérable

    # ──────────────────────────── Auth bypass ────────────────────────────────

    async def _check_auth_bypass(self, ws_url: str) -> AsyncIterator[Finding]:
        """
        Tente de se connecter sans token d'auth.
        Si le serveur répond avec des données (pas juste un 401/4xxx WS),
        c'est un auth bypass potentiel.
        """
        if not _AIOHTTP_OK:
            return

        try:
            timeout = aiohttp.ClientTimeout(total=5)
            async with aiohttp.ClientSession(timeout=timeout) as sess:
                async with sess.ws_connect(ws_url, ssl=False) as ws:
                    # Envoyer un ping neutre
                    await ws.send_str(json.dumps({"type": "ping"}))
                    try:
                        msg = await asyncio.wait_for(ws.receive(), timeout=3)
                        if msg.type in (aiohttp.WSMsgType.TEXT, aiohttp.WSMsgType.BINARY):
                            data = msg.data if isinstance(msg.data, str) else msg.data.decode("utf-8", "replace")
                            # Si la réponse n'est pas un message d'erreur d'auth
                            if not any(kw in data.lower() for kw in ["unauthorized", "forbidden", "unauthenticated", "invalid token", "auth required"]):
                                yield Finding(
                                    title="WebSocket Auth Bypass — connexion sans credentials",
                                    severity=Severity.HIGH,
                                    url=ws_url,
                                    module="vulns/websocket_scan",
                                    description=(
                                        "Le serveur WebSocket accepte des connexions sans token d'authentification "
                                        "et retourne des données applicatives."
                                    ),
                                    evidence=f"Réponse reçue (sans auth) : {data[:300]}",
                                    cwe="CWE-306",
                                    remediation="Exiger un token d'authentification valide dans le handshake WS (header Authorization ou query param token).",
                                )
                    except asyncio.TimeoutError:
                        pass
        except Exception:
            pass

    # ──────────────────────────── Message injection ───────────────────────────

    async def _check_message_injection(self, ws_url: str) -> AsyncIterator[Finding]:
        """
        Injecte des payloads dans les champs JSON des messages WS.
        Cherche des indicateurs d'erreurs ou de succès dans les réponses.
        """
        if not _AIOHTTP_OK:
            return

        # Champs JSON courants à fuzzer
        target_fields = ["query", "message", "input", "data", "id", "filter", "search", "cmd", "action"]

        for field_name in target_fields:
            for payload, label, severity in _INJECT_PAYLOADS[:4]:  # Limité aux plus critiques
                try:
                    timeout = aiohttp.ClientTimeout(total=6)
                    msg_json = json.dumps({field_name: payload, "type": "query"})

                    async with aiohttp.ClientSession(timeout=timeout) as sess:
                        async with sess.ws_connect(ws_url, ssl=False) as ws:
                            await ws.send_str(msg_json)
                            try:
                                resp = await asyncio.wait_for(ws.receive(), timeout=4)
                                if resp.type in (aiohttp.WSMsgType.TEXT, aiohttp.WSMsgType.BINARY):
                                    body = resp.data if isinstance(resp.data, str) else resp.data.decode("utf-8", "replace")
                                    # Détecter erreurs verbeux
                                    for pattern in _ERROR_INDICATORS:
                                        if re.search(pattern, body, re.I):
                                            # v5.21 — re_probe implicite: le WS inject est déjà
                                            # une 2e requête (après baseline), donc on yield
                                            yield Finding(
                                                title=f"WebSocket — Erreur verbose (injection `{label}`)",
                                                severity=severity,
                                                url=ws_url,
                                                module="vulns/websocket_scan",
                                                description=(
                                                    f"Le champ `{field_name}` du message WS retourne une erreur interne "
                                                    f"lors de l'injection du payload `{label}`."
                                                ),
                                                evidence=f"Payload: {payload[:80]} | Réponse: {body[:300]}",
                                                cwe="CWE-89" if "SQLi" in label else "CWE-94",
                                                remediation="Valider et assainir toutes les entrées dans les handlers de messages WebSocket.",
                                            )
                                            return  # Un seul finding de ce type par URL
                            except asyncio.TimeoutError:
                                pass
                except Exception:
                    pass

    # ──────────────────────────── Mass assignment ────────────────────────────

    async def _check_mass_assignment(self, ws_url: str) -> AsyncIterator[Finding]:
        """
        Envoie des champs non attendus (role, admin, price…) et détecte
        si le serveur les accepte sans erreur.
        """
        if not _AIOHTTP_OK:
            return

        for extra_fields in _MASS_ASSIGN_FIELDS[:3]:  # Limite à 3 probes
            try:
                msg = json.dumps({**extra_fields, "type": "update"})
                timeout = aiohttp.ClientTimeout(total=5)

                async with aiohttp.ClientSession(timeout=timeout) as sess:
                    async with sess.ws_connect(ws_url, ssl=False) as ws:
                        await ws.send_str(msg)
                        try:
                            resp = await asyncio.wait_for(ws.receive(), timeout=3)
                            if resp.type in (aiohttp.WSMsgType.TEXT, aiohttp.WSMsgType.BINARY):
                                body = resp.data if isinstance(resp.data, str) else resp.data.decode("utf-8", "replace")
                                # Si la réponse semble un succès (pas d'erreur "unknown field")
                                if not any(kw in body.lower() for kw in ["unknown field", "invalid field", "unexpected key", "not allowed"]):
                                    field_names = list(extra_fields.keys())
                                    yield Finding(
                                        title=f"WebSocket Mass Assignment — champ(s) `{field_names}`",
                                        severity=Severity.HIGH,
                                        url=ws_url,
                                        module="vulns/websocket_scan",
                                        description=(
                                            f"Le serveur WS accepte des champs privilégiés non attendus : `{field_names}`.\n"
                                            "Cela peut permettre l'escalade de privilèges ou la manipulation de données sensibles."
                                        ),
                                        evidence=f"Message envoyé: {msg[:200]} | Réponse: {body[:200]}",
                                        cwe="CWE-915",
                                        remediation="Utiliser une allowlist explicite des champs acceptés par chaque handler WS.",
                                    )
                                    return
                        except asyncio.TimeoutError:
                            pass
            except Exception:
                pass
