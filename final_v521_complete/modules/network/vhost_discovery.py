"""
PhantomScan — VHost Discovery
Découverte de virtual hosts via fuzzing du header Host.
Compare chaque réponse contre une baseline pour détecter
les vhosts actifs retournant un contenu différent.
"""

from __future__ import annotations

import asyncio
import hashlib
from typing import AsyncIterator
from urllib.parse import urlparse

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester, ProbeRequest
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity


# ─────────────────────────── Wordlist par défaut ────────────────────────────

DEFAULT_VHOST_WORDLIST: list[str] = [
    "admin", "api", "api2", "app", "app2", "auth",
    "beta", "blog", "cdn", "console", "dashboard", "data",
    "dev", "dev2", "devops", "docs", "download",
    "ftp", "git", "gitlab", "grafana", "hub",
    "internal", "intranet", "jenkins", "jira", "kibana",
    "legacy", "logs", "mail", "manage", "monitor", "mx",
    "ns1", "ns2", "old", "ops",
    "panel", "portal", "prod", "proxy",
    "qa", "queue",
    "sandbox", "secure", "shop", "smtp", "staging", "static", "status",
    "test", "test2", "testing",
    "vault", "vpn",
    "wiki", "www2",
]


# ─────────────────────────── Scanner ────────────────────────────────────────

class VHostDiscovery:
    """
    Virtual Host Discovery.

    Stratégie :
    1. Récupère une baseline avec un Host aléatoire (invalide) pour établir
       la réponse par défaut du serveur.
    2. Pour chaque candidat wordlist, envoie une requête avec Host: <candidat>.<domaine>.
    3. Compare status, content-length et hash du body contre la baseline.
    4. Si différent → potentiel vhost actif → Finding.
    """

    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req = req
        self._heuristic = heuristic
        self._cfg = cfg
        self._wordlist: list[str] = getattr(cfg, "vhost_wordlist", DEFAULT_VHOST_WORDLIST)
        self._concurrency: int = getattr(cfg, "vhost_concurrency", 30)

    # ── Point d'entrée ───────────────────────────────────────────────────────

    async def run(self, target: str) -> AsyncIterator[Finding]:
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        domain = parsed.hostname or parsed.netloc

        baseline = await self._get_baseline(base_url, domain)
        if baseline is None:
            return

        sem = asyncio.Semaphore(self._concurrency)
        tasks = [
            self._probe_vhost(base_url, domain, word, baseline, sem)
            for word in self._wordlist
        ]

        for coro in asyncio.as_completed(tasks):
            finding = await coro
            if finding:
                yield finding

    # ── Baseline ─────────────────────────────────────────────────────────────

    async def _get_baseline(self, base_url: str, domain: str) -> dict | None:
        """Établit la réponse baseline avec un Host invalide."""
        fake_host = f"phantomscan-nonexistent-{id(self)}.{domain}"
        req = ProbeRequest(
            method="GET",
            url=base_url,
            headers={"Host": fake_host},
            allow_redirects=False,
        )
        resp = await self._req.send(req)
        if resp.error:
            return None
        return {
            "status": resp.status,
            "length": resp.content_length,
            "hash": hashlib.md5(resp.body.encode("utf-8", errors="replace")).hexdigest(),
        }

    # ── Probe individuel ─────────────────────────────────────────────────────

    async def _probe_vhost(
        self,
        base_url: str,
        domain: str,
        word: str,
        baseline: dict,
        sem: asyncio.Semaphore,
    ) -> Finding | None:
        candidate_host = f"{word}.{domain}"
        async with sem:
            req = ProbeRequest(
                method="GET",
                url=base_url,
                headers={"Host": candidate_host},
                allow_redirects=False,
            )
            resp = await self._req.send(req)

        if resp.error:
            return None

        # ── Comparaison contre baseline ──────────────────────────────────────
        body_hash = hashlib.md5(resp.body.encode("utf-8", errors="replace")).hexdigest()
        status_diff = resp.status != baseline["status"]
        length_diff = abs(resp.content_length - baseline["length"]) > 50
        hash_diff = body_hash != baseline["hash"]

        # Ignorer les réponses identiques à la baseline
        if not (status_diff or length_diff or hash_diff):
            return None

        # Ignorer si le status est clairement un 404/erreur générique
        if resp.status in (404, 400, 410) and not status_diff:
            return None

        severity = Severity.MEDIUM
        if resp.status in (200, 301, 302):
            severity = Severity.HIGH

        title_snippet = self._extract_title(resp.body)
        diff_details = []
        if status_diff:
            diff_details.append(f"status baseline={baseline['status']} → vhost={resp.status}")
        if length_diff:
            diff_details.append(f"length baseline={baseline['length']} → vhost={resp.content_length}")
        if hash_diff:
            diff_details.append("body différent")

        return Finding(
            title=f"VHost découvert : {candidate_host}",
            severity=severity,
            url=f"{base_url} [Host: {candidate_host}]",
            module="network/vhost_discovery",
            description=(
                f"Le virtual host `{candidate_host}` retourne une réponse différente "
                f"de la baseline, indiquant qu'il est actif sur ce serveur. "
                f"Titre de la page : {title_snippet or 'N/A'}"
            ),
            evidence=" | ".join(diff_details),
            cwe="CWE-200",
            remediation=(
                "Vérifier si ce vhost expose des interfaces d'administration ou "
                "des données non prévues pour être publiques. "
                "Restreindre l'accès aux vhosts internes par IP ou authentification."
            ),
        )

    # ── Helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _extract_title(body: str) -> str:
        import re
        m = re.search(r"<title[^>]*>([^<]{1,120})</title>", body, re.I)
        return m.group(1).strip() if m else ""
