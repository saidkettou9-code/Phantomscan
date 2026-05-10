"""
PhantomScan — Param Miner  v1.0
================================
Découverte de paramètres cachés / non-documentés via analyse différentielle
de réponses HTTP (inspiré de Burp Suite Param Miner).

Techniques couvertes :
  - Wordlist de ~400 paramètres suspects (cache, debug, admin, internal…)
  - Injection query-string (GET) + form body (POST/application/x-www-form-urlencoded)
  - Injection par batch de 30 params (réduction du nombre de requêtes)
  - Differential analysis : variation de status, body-length, Set-Cookie, headers
  - Détection de params de cache-poisoning (X-Forwarded-Host, X-Host, X-Forwarded-Prefix…)
  - Scoring de confiance : HIGH/MEDIUM/LOW selon les deltas observés
  - Intégration EndpointBus : mine aussi les endpoints POST découverts par le crawler

Référence : https://portswigger.net/research/web-cache-entanglement
"""

from __future__ import annotations

import asyncio
import hashlib
import random
import re
import string
from typing import AsyncIterator
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester, ProbeRequest, ProbeResponse
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity

# ─────────────────────────── Wordlist ────────────────────────────────────────

_PARAM_WORDLIST: list[str] = [
    # Debug / internal
    "debug", "test", "dev", "internal", "admin", "superuser", "root",
    "trace", "verbose", "log", "logging", "inspect", "diagnostic",
    "profiling", "profile", "benchmark", "mode", "env", "environment",
    "stage", "staging", "preview", "beta", "alpha", "canary",
    # Cache / CDN
    "nocache", "no_cache", "cache", "cache_buster", "cb", "v", "ver",
    "version", "bust", "ts", "timestamp", "t", "rand", "random",
    "x_forwarded_host", "x_host", "forwarded_host", "x_forwarded_prefix",
    "x_original_url", "x_rewrite_url",
    # Output / format
    "format", "output", "type", "content_type", "encoding", "charset",
    "lang", "language", "locale", "timezone", "tz",
    "jsonp", "callback", "cb", "json", "xml", "html", "text", "csv",
    # Auth / session
    "token", "access_token", "auth_token", "api_key", "apikey", "key",
    "secret", "password", "pass", "pwd", "user", "username", "uid",
    "session", "sid", "jwt",
    # Pagination / filtering
    "page", "p", "offset", "limit", "per_page", "pagesize", "size",
    "sort", "order", "asc", "desc", "filter", "q", "query", "search",
    "fields", "select", "include", "exclude", "expand",
    # Redirect / URL
    "redirect", "return", "next", "goto", "url", "uri", "href", "link",
    "back", "continue", "forward",
    # File / path
    "file", "path", "dir", "folder", "filename", "name", "src", "source",
    "dest", "destination", "target", "load", "read",
    # Feature flags
    "feature", "flag", "enable", "disable", "toggle", "switch",
    "experiment", "exp", "ab", "variant", "group",
    # Misc common
    "id", "ref", "reference", "code", "hash", "checksum",
    "action", "method", "cmd", "command", "op", "operation",
    "from", "to", "start", "end", "begin",
    "width", "height", "size", "resize", "thumbnail", "thumb",
    "email", "phone", "address", "country", "region", "city",
    "origin", "referer", "host",
    # Spring / Framework specific
    "noop", "required", "suffix", "prefix", "wrapper",
    # Spring Boot Actuator discovery
    "management.endpoints.web.exposure.include",
    # GraphQL
    "query", "mutation", "subscription", "operationName", "variables",
    # Internal headers as params (cache poisoning)
    "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto",
    "X-Host", "X-Original-URL", "X-Rewrite-URL", "X-Custom-IP-Authorization",
    # Prototype pollution candidates
    "__proto__", "constructor", "prototype",
    # Node / express
    "next", "layer", "route", "middleware",
    # PHP legacy
    "PHPSESSID", "phpinfo", "xdebug_session_start",
    # ASP.NET
    "__VIEWSTATE", "__EVENTVALIDATION", "ASPX_SESSIONID",
]

# Headers potentiellement réfléchis (cache poisoning via param → header)
_HEADER_PARAMS: list[str] = [
    "X-Forwarded-Host", "X-Host", "X-Forwarded-For",
    "X-Original-URL", "X-Rewrite-URL", "X-Forwarded-Prefix",
    "X-Forwarded-Proto", "X-Custom-IP-Authorization",
]

_BATCH_SIZE = 30          # Nombre de params injectés par requête
_CANARY_LEN  = 8          # Longueur du canary unique par param


# ─────────────────────────── Helpers ─────────────────────────────────────────

def _canary() -> str:
    """Génère une valeur canary unique et reconnaissable."""
    return "pm" + "".join(random.choices(string.ascii_lowercase, k=_CANARY_LEN))


def _response_fingerprint(r: ProbeResponse) -> tuple:
    """Fingerprint d'une réponse pour détecter des changements."""
    body_hash = hashlib.md5(r.body[:4096].encode("utf-8", errors="replace")).hexdigest()
    set_cookie = r.headers.get("set-cookie", "")
    vary = r.headers.get("vary", "")
    cache_control = r.headers.get("cache-control", "")
    content_type = r.headers.get("content-type", "")
    return (r.status, r.content_length, body_hash, set_cookie, vary, cache_control, content_type)


def _delta(base: tuple, probe: tuple) -> list[str]:
    """Retourne la liste des dimensions qui ont changé entre base et probe."""
    labels = ["status", "content_length", "body_hash", "set_cookie", "vary", "cache_control", "content_type"]
    return [labels[i] for i, (b, p) in enumerate(zip(base, probe)) if b != p]


def _canary_reflected(canary: str, body: str) -> bool:
    """Vérifie si la valeur canary est réfléchie dans la réponse."""
    return canary.lower() in body.lower()


# ─────────────────────────── Scanner ─────────────────────────────────────────

class ParamMinerScanner:
    """
    Mine les paramètres cachés sur l'URL cible et les endpoints POST du bus.
    Utilise une stratégie par batch pour limiter le nombre de requêtes.
    """

    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req = req
        self._heuristic = heuristic
        self._cfg = cfg
        self._bus = None

    def set_endpoint_bus(self, bus) -> None:
        self._bus = bus

    async def run(self, target: str) -> AsyncIterator[Finding]:
        # ── 1. Mine l'URL cible (GET) ────────────────────────────────────────
        async for f in self._mine_url(target, method="GET"):
            yield f

        # ── 2. Mine les headers comme params (cache poisoning) ───────────────
        async for f in self._mine_headers(target):
            yield f

        # ── 3. Mine les endpoints POST du bus ────────────────────────────────
        if self._bus:
            endpoints = self._bus.filter_by_score(0.3)
            post_eps = [ep for ep in endpoints if ep.method == "POST"]
            for ep in post_eps[:20]:  # limit
                async for f in self._mine_url(ep.url, method="POST", form_inputs=ep.form_inputs):
                    yield f

    # ── GET param mining ──────────────────────────────────────────────────────

    async def _mine_url(
        self,
        target: str,
        method: str = "GET",
        form_inputs: dict | None = None,
    ) -> AsyncIterator[Finding]:
        # Baseline
        base_resp = await self._req.get(target)
        if base_resp.error or base_resp.status >= 500:
            return
        base_fp = _response_fingerprint(base_resp)

        # Inject stable filler param pour détecter les pages dynamiques
        filler_canary = _canary()
        if method == "GET":
            parsed = urlparse(target)
            existing = parse_qs(parsed.query, keep_blank_values=True)
            filler_params = dict(existing)
            filler_params["__pm_filler__"] = [filler_canary]
            filler_url = urlunparse(parsed._replace(query=urlencode(filler_params, doseq=True)))
            filler_resp = await self._req.get(filler_url)
        else:
            filler_resp = await self._req.send(ProbeRequest(
                method="POST", url=target,
                body=urlencode({"__pm_filler__": filler_canary}),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            ))
        if filler_resp.error:
            return

        filler_fp = _response_fingerprint(filler_resp)
        dynamic_dims = set(_delta(base_fp, filler_fp))

        # Batch inject
        wordlist = list(_PARAM_WORDLIST)
        for batch_start in range(0, len(wordlist), _BATCH_SIZE):
            batch = wordlist[batch_start:batch_start + _BATCH_SIZE]
            canaries = {p: _canary() for p in batch}

            if method == "GET":
                parsed = urlparse(target)
                existing = parse_qs(parsed.query, keep_blank_values=True)
                probe_params = dict(existing)
                for p, c in canaries.items():
                    probe_params[p] = [c]
                probe_url = urlunparse(parsed._replace(query=urlencode(probe_params, doseq=True)))
                probe_resp = await self._req.get(probe_url)
            else:
                body_params = {p: c for p, c in canaries.items()}
                if form_inputs:
                    body_params.update(form_inputs)
                probe_resp = await self._req.send(ProbeRequest(
                    method="POST", url=target,
                    body=urlencode(body_params),
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                ))

            if probe_resp.error:
                continue

            probe_fp = _response_fingerprint(probe_resp)
            changed = [d for d in _delta(base_fp, probe_fp) if d not in dynamic_dims]

            if not changed and not any(_canary_reflected(c, probe_resp.body) for c in canaries.values()):
                continue

            # Le batch a eu un effet — bisect pour trouver le param responsable
            async for f in self._bisect_batch(
                target, method, base_fp, dynamic_dims,
                list(canaries.items()), form_inputs or {},
            ):
                yield f

    async def _bisect_batch(
        self, target: str, method: str, base_fp: tuple,
        dynamic_dims: set, canary_items: list[tuple[str, str]],
        form_inputs: dict,
    ) -> AsyncIterator[Finding]:
        """Bisection récursive pour isoler le param responsable dans un batch."""
        if not canary_items:
            return

        if len(canary_items) == 1:
            param, canary = canary_items[0]
            # Vérification finale
            if method == "GET":
                parsed = urlparse(target)
                existing = parse_qs(parsed.query, keep_blank_values=True)
                probe_params = dict(existing)
                probe_params[param] = [canary]
                probe_url = urlunparse(parsed._replace(query=urlencode(probe_params, doseq=True)))
                resp = await self._req.get(probe_url)
            else:
                body = {param: canary}
                body.update(form_inputs)
                resp = await self._req.send(ProbeRequest(
                    method="POST", url=target,
                    body=urlencode(body),
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                ))
            if resp.error:
                return

            probe_fp = _response_fingerprint(resp)
            changed = [d for d in _delta(base_fp, probe_fp) if d not in dynamic_dims]
            reflected = _canary_reflected(canary, resp.body)

            if not changed and not reflected:
                return

            # Determine severity
            if "status" in changed:
                severity = Severity.HIGH
            elif reflected:
                severity = Severity.HIGH
            elif "body_hash" in changed and "content_length" in changed:
                severity = Severity.MEDIUM
            elif "set_cookie" in changed or "vary" in changed:
                severity = Severity.MEDIUM
            else:
                severity = Severity.LOW

            evidence_parts = []
            if changed:
                evidence_parts.append(f"Dimensions modifiées: {', '.join(changed)}")
            if reflected:
                evidence_parts.append(f"Valeur canary réfléchie dans la réponse")
            evidence_parts.append(f"Paramètre: {param}={canary}")

            yield Finding(
                title=f"Paramètre caché découvert: `{param}`",
                severity=severity,
                url=target,
                module="recon/param_miner",
                description=(
                    f"Le paramètre `{param}` non-documenté a modifié le comportement du serveur "
                    f"({method} {target}).\n"
                    + "\n".join(evidence_parts)
                ),
                evidence=" | ".join(evidence_parts),
                cwe="CWE-200",
                remediation=(
                    "Supprimer les paramètres de debug/internes en production. "
                    "Ne pas exposer de comportement différent selon des paramètres non-documentés. "
                    "Auditer les feature flags accessibles publiquement."
                ),
            )
            return

        # Bisect
        mid = len(canary_items) // 2
        left  = canary_items[:mid]
        right = canary_items[mid:]

        for half in (left, right):
            # Probe le demi-batch
            if method == "GET":
                parsed = urlparse(target)
                existing = parse_qs(parsed.query, keep_blank_values=True)
                probe_params = dict(existing)
                for p, c in half:
                    probe_params[p] = [c]
                probe_url = urlunparse(parsed._replace(query=urlencode(probe_params, doseq=True)))
                resp = await self._req.get(probe_url)
            else:
                body = {p: c for p, c in half}
                body.update(form_inputs)
                resp = await self._req.send(ProbeRequest(
                    method="POST", url=target,
                    body=urlencode(body),
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                ))

            if resp.error:
                continue
            probe_fp = _response_fingerprint(resp)
            changed = [d for d in _delta(base_fp, probe_fp) if d not in dynamic_dims]
            reflected = any(_canary_reflected(c, resp.body) for _, c in half)

            if changed or reflected:
                async for f in self._bisect_batch(
                    target, method, base_fp, dynamic_dims, half, form_inputs,
                ):
                    yield f

    # ── Header cache poisoning ────────────────────────────────────────────────

    async def _mine_headers(self, target: str) -> AsyncIterator[Finding]:
        """
        Injecte les headers suspects un par un et détecte les réponses différentes.
        Cible principale : cache poisoning via headers réfléchis (Host, Forwarded-Host…)
        """
        base_resp = await self._req.get(target)
        if base_resp.error:
            return
        base_fp = _response_fingerprint(base_resp)

        for header in _HEADER_PARAMS:
            canary = _canary() + ".attacker.com"
            resp = await self._req.send(ProbeRequest(
                method="GET",
                url=target,
                headers={header: canary},
            ))
            if resp.error:
                continue

            probe_fp = _response_fingerprint(resp)
            changed = _delta(base_fp, probe_fp)
            reflected = _canary_reflected(canary.split(".")[0], resp.body)

            if not changed and not reflected:
                continue

            severity = Severity.HIGH if (reflected or "body_hash" in changed) else Severity.MEDIUM

            evidence = f"Header: {header}: {canary}"
            if reflected:
                evidence += " | Valeur RÉFLÉCHIE dans le body"
            if changed:
                evidence += f" | Dims modifiées: {', '.join(changed)}"

            yield Finding(
                title=f"Cache Poisoning via header réfléchi: {header}",
                severity=severity,
                url=target,
                module="recon/param_miner",
                description=(
                    f"Le header `{header}` est pris en compte par le serveur et modifie la réponse. "
                    f"Si le cache stocke cette réponse, l'attaquant peut empoisonner le cache "
                    f"pour tous les utilisateurs.\n{evidence}"
                ),
                evidence=evidence,
                cwe="CWE-444",
                remediation=(
                    "Ne pas refléter les headers X-Forwarded-* dans les réponses sans validation. "
                    "Configurer le CDN/reverse-proxy pour supprimer les headers non-de-confiance. "
                    "Utiliser une allowlist de headers acceptés par le cache."
                ),
            )
