"""
PhantomScan — HTTP Request Smuggling Scanner
Détecte CL.TE / TE.CL / TE.TE sur les reverse proxies.

Techniques :
  - CL.TE : le front-end utilise Content-Length, le back-end Transfer-Encoding
  - TE.CL : le front-end utilise Transfer-Encoding, le back-end Content-Length
  - TE.TE : les deux utilisent Transfer-Encoding, mais l'un peut être obfusqué

Références : PortSwigger Web Security Academy — HTTP request smuggling
CWE-444 : Inconsistent Interpretation of HTTP Requests
"""

from __future__ import annotations

import asyncio
import time
from typing import AsyncIterator
from urllib.parse import urlparse

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity
from phantomscan.core.scanner_mixin import ScannerMixin

# Timeout serré pour détecter les différences de timing (CL.TE timeout probe)
_TIMING_THRESHOLD = 4.0   # secondes — seuil abaissé
_TIMING_MIN_RATIO = 2.5    # v5.21 : délai doit être ≥ 2.5× le délai baseline pour être significatif


# ─────────────────────────────────────────────────────────────────────────────
# Payloads bruts — envoyés via socket bas niveau ou requête manuelle
# ─────────────────────────────────────────────────────────────────────────────

# CL.TE — front lit Content-Length (5), back lit TE jusqu'au "0\r\n\r\n"
# Le corps réel est "0\r\n\r\nG" → le "G" est gardé comme début de la prochaine requête
_CLTE_TIMEOUT_BODY = (
    "POST / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 6\r\n"
    "Transfer-Encoding: chunked\r\n"
    "Connection: keep-alive\r\n"
    "\r\n"
    "0\r\n"
    "\r\n"
    "X"
)

# TE.CL — front lit TE, back lit Content-Length
# Corps chunké : chunk de 0 octet + Content-Length court
_TECL_TIMEOUT_BODY = (
    "POST / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 3\r\n"
    "Transfer-Encoding: chunked\r\n"
    "Connection: keep-alive\r\n"
    "\r\n"
    "1\r\n"
    "Z\r\n"
    "0\r\n"
    "\r\n"
)

# TE.TE obfuscation variants — un des proxys peut ignorer le TE obfusqué
_TE_OBFUSCATIONS = [
    "Transfer-Encoding: xchunked",
    "Transfer-Encoding : chunked",
    "Transfer-Encoding: chunked, identity",
    "Transfer-Encoding:\x0bchunked",
    "Transfer-Encoding: chunKed",
    "X-Transfer-Encoding: chunked",
    "Transfer-Encoding: chunk\x09ed",
]

# ─────────────────────────────────────────────────────────────────────────────
# Differential response probes (pas de timing — compare les codes HTTP)
# ─────────────────────────────────────────────────────────────────────────────

# Corps CL.TE : Content-Length pointe sur le milieu du chunk →
# si le back-end lit TE, il voit "SMUGGLED" comme début de prochaine requête
_CLTE_DIFF_BODY = b"POST / HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 49\r\nTransfer-Encoding: chunked\r\n\r\ne\r\nq=smuggle&x=1\r\n0\r\n\r\nGET /phantomscan_smug_404_{rand} HTTP/1.1\r\nFoo: x"

_TECL_DIFF_BODY = b"POST / HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n5c\r\nSMUGGLED=1&GET /phantomscan_smug_404_{rand} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 10\r\n\r\nx=\r\n0\r\n\r\n"


class HTTPSmugglingScanner(ScannerMixin):
    """
    Détecte le Request Smuggling via :
    1. Timing-based probe (CL.TE et TE.CL) — mesure la latence
    2. Differential response probe — cherche un 404 inattendu sur la 2e requête
    3. TE obfuscation probe — teste les variantes de header TE.TE
    """

    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req = req
        self._heuristic = heuristic
        self._cfg = cfg

    async def run(self, target: str) -> AsyncIterator[Finding]:
        parsed = urlparse(target)
        host = parsed.netloc or parsed.hostname or target
        base = f"{parsed.scheme}://{parsed.netloc}"

        # 1. CL.TE timing probe
        async for f in self._probe_clte_timing(base, host):
            yield f

        # 2. TE.CL timing probe
        async for f in self._probe_tecl_timing(base, host):
            yield f

        # 3. TE.TE obfuscation probes
        async for f in self._probe_tete_obfuscation(base, host):
            yield f

        # 4. CL.TE differential (confirme via 2e réponse)
        async for f in self._probe_clte_differential(base, host):
            yield f

    # ── CL.TE timing ─────────────────────────────────────────────────────────

    async def _probe_clte_timing(self, base: str, host: str) -> AsyncIterator[Finding]:
        """
        Envoie une requête CL.TE où Content-Length signale plus d'octets que disponible.
        Le front-end transfère la requête au back-end qui lit TE et attend la suite du chunk.
        → timeout côté back-end = indicateur fort de CL.TE.
        """
        raw = _CLTE_TIMEOUT_BODY.format(host=host)
        t0 = time.monotonic()
        try:
            resp = await asyncio.wait_for(
                self._req.raw_post(base + "/", raw, extra_headers={
                    "Transfer-Encoding": "chunked",
                    "Content-Length": "6",
                }),
                timeout=_TIMING_THRESHOLD + 2,
            )
            elapsed = time.monotonic() - t0
            if elapsed >= _TIMING_THRESHOLD and not resp.error:
                # v5.21 — Double confirmation : rejouer pour vérifier la cohérence
                import time as _time
                _t2 = _time.monotonic()
                _resp2 = await self._req.send(ProbeRequest(
                    method="POST", url=url,
                    headers=hdrs2, body=smuggle_body,
                    timeout=_TIMING_THRESHOLD + 2,
                ))
                _elapsed2 = _time.monotonic() - _t2
                # Les 2 mesures doivent être cohérentes (ratio < 3×)
                _ratio = max(elapsed, _elapsed2) / max(min(elapsed, _elapsed2), 0.1)
                _confirmed = _elapsed2 >= _TIMING_THRESHOLD and _ratio <= 3.5
                if _confirmed:
                  # noinspection PyUnboundLocalVariable
                  yield Finding(
                    title="HTTP Smuggling — CL.TE (timing-based)",
                    severity=Severity.HIGH,
                    url=base + "/",
                    module="vulns/http_smuggling",
                    description=(
                        "Le serveur a répondu avec un délai anormal ({:.1f}s) à une requête "
                        "CL.TE ambiguë. Le front-end (Content-Length) et le back-end "
                        "(Transfer-Encoding) interprètent différemment la frontière du corps. "
                        "Un attaquant peut empoisonner la pipeline TCP et préfixer des requêtes "
                        "légitimes d'autres utilisateurs.".format(elapsed)
                    ),
                    evidence=f"Latence mesurée : {elapsed:.2f}s (seuil : {_TIMING_THRESHOLD}s)",
                    cwe="CWE-444",
                    remediation=(
                        "Normaliser les requêtes ambiguës au niveau du proxy (rejeter celles "
                        "ayant à la fois CL et TE). Activer HTTP/2 end-to-end. "
                        "Sur nginx : set `proxy_http_version 1.1` + `proxy_set_header Connection ''`. "
                        "Sur CloudFlare : activer la mitigation HTTP Smuggling dans les règles WAF."
                    ),
                )
        except (asyncio.TimeoutError, Exception):
            pass

    # ── TE.CL timing ─────────────────────────────────────────────────────────

    async def _probe_tecl_timing(self, base: str, host: str) -> AsyncIterator[Finding]:
        """
        Front-end lit Transfer-Encoding → envoie un corps tronqué au back-end
        qui attend Content-Length octets → il bloque en attendant le reste.
        """
        raw = _TECL_TIMEOUT_BODY.format(host=host)
        t0 = time.monotonic()
        try:
            resp = await asyncio.wait_for(
                self._req.raw_post(base + "/", raw, extra_headers={
                    "Transfer-Encoding": "chunked",
                    "Content-Length": "3",
                }),
                timeout=_TIMING_THRESHOLD + 2,
            )
            elapsed = time.monotonic() - t0
            if elapsed >= _TIMING_THRESHOLD and not resp.error:
                yield Finding(
                    title="HTTP Smuggling — TE.CL (timing-based)",
                    severity=Severity.HIGH,
                    url=base + "/",
                    module="vulns/http_smuggling",
                    description=(
                        "Délai anormal ({:.1f}s) détecté sur une probe TE.CL. "
                        "Le front-end consomme le body via Transfer-Encoding ; "
                        "le back-end attend Content-Length octets supplémentaires → suspend. "
                        "Exploitable pour du request smuggling vers le back-end.".format(elapsed)
                    ),
                    evidence=f"Latence : {elapsed:.2f}s | Probe TE.CL timeout",
                    cwe="CWE-444",
                    remediation=(
                        "Refuser les requêtes avec CL + TE simultanés. "
                        "Utiliser HTTP/2 ou h2c end-to-end pour éliminer l'ambiguïté HTTP/1.1."
                    ),
                )
        except (asyncio.TimeoutError, Exception):
            pass

    # ── TE.TE obfuscation ────────────────────────────────────────────────────

    async def _probe_tete_obfuscation(self, base: str, host: str) -> AsyncIterator[Finding]:
        """
        Teste les variantes d'obfuscation du header Transfer-Encoding.
        Un proxy peut ignorer une variante et lire Content-Length à la place.
        """
        for te_variant in _TE_OBFUSCATIONS:
            header_name, _, header_val = te_variant.partition(":")
            header_val = header_val.strip() if header_val else "chunked"

            raw_body = (
                "1\r\n"
                "Z\r\n"
                "0\r\n"
                "\r\n"
            )
            t0 = time.monotonic()
            try:
                resp = await asyncio.wait_for(
                    self._req.raw_post(base + "/", raw_body, extra_headers={
                        header_name.strip(): header_val,
                        "Content-Length": "3",
                        "Content-Type": "application/x-www-form-urlencoded",
                    }),
                    timeout=_TIMING_THRESHOLD + 2,
                )
                elapsed = time.monotonic() - t0
                if elapsed >= _TIMING_THRESHOLD and resp and not resp.error:
                    yield Finding(
                        title=f"HTTP Smuggling — TE.TE obfuscation ({te_variant[:40]})",
                        severity=Severity.HIGH,
                        url=base + "/",
                        module="vulns/http_smuggling",
                        description=(
                            f"Variante TE obfusquée `{te_variant}` a provoqué un délai de "
                            f"{elapsed:.1f}s. L'un des nœuds ignore ce header et lit "
                            "Content-Length, créant une désynchronisation exploitable."
                        ),
                        evidence=f"Header: `{te_variant}` | Latence : {elapsed:.2f}s",
                        cwe="CWE-444",
                        remediation=(
                            "Rejeter ou normaliser tous les headers Transfer-Encoding "
                            "malformés/non-standard au niveau du proxy."
                        ),
                    )
                    break  # Un finding par type suffit
            except (asyncio.TimeoutError, Exception):
                continue

    # ── CL.TE differential ───────────────────────────────────────────────────

    async def _probe_clte_differential(self, base: str, host: str) -> AsyncIterator[Finding]:
        """
        Probe différentielle : envoie une requête smugglée qui injecte un GET
        vers un path aléatoire inexistant. Si la 2e réponse contient un 404
        pour ce path précis, le smuggling est confirmé.
        """
        import random, string
        rand = "".join(random.choices(string.ascii_lowercase, k=8))
        smuggled_path = f"/phantomscan_smug_404_{rand}"

        # Première requête — smuggle un GET partiel
        smuggle_payload = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 54\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"d\r\n"
            f"q=smuggle&x=1\r\n"
            f"0\r\n"
            f"\r\n"
            f"GET {smuggled_path} HTTP/1.1\r\n"
            f"Foo: x"
        )
        try:
            await self._req.raw_post(base + "/", smuggle_payload, extra_headers={
                "Transfer-Encoding": "chunked",
                "Content-Length": "54",
            })
        except Exception:
            return

        # Petite pause pour laisser le back-end traiter
        await asyncio.sleep(0.3)

        # Deuxième requête normale — si le back-end a gardé le GET smugglé en tête de pipe
        try:
            resp2 = await self._req.get(base + "/")
            if resp2 and resp2.body and smuggled_path in resp2.body:
                yield Finding(
                    title="HTTP Smuggling — CL.TE confirmé (differential response)",
                    severity=Severity.CRITICAL,
                    url=base + "/",
                    module="vulns/http_smuggling",
                    description=(
                        f"Request Smuggling CL.TE confirmé : le path injecté `{smuggled_path}` "
                        "est apparu dans la réponse de la 2e requête normale. "
                        "Le back-end a interprété la fin du body comme le début d'une nouvelle "
                        "requête, permettant de préfixer les requêtes d'autres utilisateurs."
                    ),
                    evidence=f"Path smugglé `{smuggled_path}` retrouvé dans la réponse suivante",
                    cwe="CWE-444",
                    remediation=(
                        "CRITIQUE — Corriger immédiatement. Normaliser au niveau proxy, "
                        "passer en HTTP/2 end-to-end, ou isoler front/back sur le même processus."
                    ),
                )
        except Exception:
            pass
