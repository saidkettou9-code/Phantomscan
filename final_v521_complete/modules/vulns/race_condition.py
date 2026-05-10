"""
PhantomScan — Race Condition Scanner
Détecte :
  - Race conditions sur endpoints transactionnels (transfer, payment, coupon)
  - Double-submit sur actions critiques (vote, like, apply)
  - TOCTOU sur endpoints de validation (coupon valid → used en parallèle)
  - Race sur la création de ressources (duplicate account, double registration)
  - Time-of-check Time-of-use sur privilege escalation
"""

from __future__ import annotations

import asyncio
import time
from collections import Counter
from typing import AsyncGenerator
from urllib.parse import urlparse, urljoin

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester, ProbeRequest
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity
from phantomscan.core.scanner_mixin import ScannerMixin


# Endpoints typiquement vulnérables aux race conditions
RACE_TARGETS: list[dict] = [
    # Transactionnel
    {"path": "/api/transfer",           "method": "POST", "body": "amount=1&to=race_probe",     "category": "financial"},
    {"path": "/api/payment",            "method": "POST", "body": "amount=1",                   "category": "financial"},
    {"path": "/api/checkout",           "method": "POST", "body": "quantity=1",                  "category": "financial"},
    {"path": "/api/withdraw",           "method": "POST", "body": "amount=1",                   "category": "financial"},
    {"path": "/api/redeem",             "method": "POST", "body": "code=RACE_PROBE",             "category": "coupon"},
    {"path": "/api/coupon",             "method": "POST", "body": "code=RACE_PROBE",             "category": "coupon"},
    {"path": "/api/promo",              "method": "POST", "body": "code=RACE_PROBE",             "category": "coupon"},
    {"path": "/api/apply-coupon",       "method": "POST", "body": "code=RACE_PROBE",             "category": "coupon"},
    # Vote / like
    {"path": "/api/vote",               "method": "POST", "body": "item_id=1",                  "category": "vote"},
    {"path": "/api/like",               "method": "POST", "body": "post_id=1",                  "category": "vote"},
    {"path": "/api/upvote",             "method": "POST", "body": "id=1",                       "category": "vote"},
    {"path": "/api/react",              "method": "POST", "body": "type=like",                  "category": "vote"},
    # Registration / création
    {"path": "/register",               "method": "POST", "body": "username=race_user&password=Race1234!&email=race@test.com", "category": "register"},
    {"path": "/api/register",           "method": "POST", "body": "username=race_user&email=race@test.com", "category": "register"},
    {"path": "/api/v1/register",        "method": "POST", "body": "username=race_user&email=race@test.com", "category": "register"},
    # Validation / confirmation
    {"path": "/api/confirm",            "method": "POST", "body": "token=race_probe",            "category": "confirm"},
    {"path": "/api/verify",             "method": "POST", "body": "code=000000",                "category": "confirm"},
    # Privilege
    {"path": "/api/upgrade",            "method": "POST", "body": "plan=premium",               "category": "privilege"},
    {"path": "/api/subscribe",          "method": "POST", "body": "plan=premium",               "category": "privilege"},
    # Points / credits
    {"path": "/api/points/redeem",      "method": "POST", "body": "points=100",                 "category": "points"},
    {"path": "/api/credits/use",        "method": "POST", "body": "amount=10",                  "category": "points"},
    {"path": "/api/reward",             "method": "POST", "body": "reward_id=1",                "category": "points"},
]

# Combien de requêtes en parallèle pour le race test
RACE_CONCURRENCY = 20
# Fenêtre de temps max pour considérer les requêtes comme simultanées (ms)
RACE_WINDOW_MS = 100


class RaceConditionScanner(ScannerMixin):

    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req = req
        self._heuristic = heuristic
        self._cfg = cfg

    async def run(self, target: str) -> AsyncGenerator[Finding, None]:
        parsed = urlparse(target)
        scheme = parsed.scheme
        netloc = parsed.netloc

        for entry in RACE_TARGETS:
            url = f"{scheme}://{netloc}{entry['path']}"
            method = entry["method"]
            body = entry.get("body", "")
            category = entry["category"]

            # Probe rapide : est-ce que l'endpoint existe ?
            probe = await self._req.send(ProbeRequest(
                method=method,
                url=url,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                body=body,
            ))

            if probe.error or probe.status_code in (404, 405, 410):
                continue

            # Endpoint accessible → lancer le race test
            async for f in self._race_probe(url, method, body, category, probe.status_code):
                yield f

    async def _race_probe(
        self,
        url: str,
        method: str,
        body: str,
        category: str,
        baseline_status: int,
    ) -> AsyncGenerator[Finding, None]:
        """
        Envoie RACE_CONCURRENCY requêtes simultanées et analyse les réponses.
        Indicateurs de race condition :
          - Réponses 2xx multiples là où une seule devrait passer (coupon reuse, double vote)
          - Statuts incohérents dans la même fenêtre (certains 200, d'autres 409/429)
          - Timing anormalement proche entre plusieurs 200
        """

        results: list[dict] = []
        start = time.monotonic()

        async def _send_one(idx: int) -> None:
            t0 = time.monotonic()
            resp = await self._req.send(ProbeRequest(
                method=method,
                url=url,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                body=body,
            ))
            elapsed = (time.monotonic() - t0) * 1000
            results.append({
                "idx": idx,
                "status": resp.status_code if not resp.error else -1,
                "error": resp.error,
                "body_snippet": (resp.body or "")[:200],
                "elapsed_ms": elapsed,
                "abs_time": time.monotonic() - start,
            })

        # v5.21 — Last-byte synchronization : préparer TOUTES les requêtes,
        # attendre que la connexion TCP soit établie, puis envoyer le dernier
        # octet simultanément sur toutes → fenêtre de race maximisée.
        # Note : asyncio.gather() approxime ce comportement en Python pur.
        # Pour un vrai last-byte sync, utiliser h2/httpx avec HTTP/2.
        tasks = [asyncio.create_task(_send_one(i)) for i in range(RACE_CONCURRENCY)]
        await asyncio.gather(*tasks, return_exceptions=True)

        if not results:
            return

        # Analyse des résultats
        status_counts = Counter(r["status"] for r in results)
        success_results = [r for r in results if r["status"] in range(200, 300)]
        conflict_results = [r for r in results if r["status"] in (409, 429, 400)]

        n_success = len(success_results)
        n_conflict = len(conflict_results)
        n_total = len(results)

        # Cas 1 : plusieurs 2xx sur endpoint qui ne devrait accepter qu'une fois
        # v5.21 — FP guard : un endpoint idempotent retourne 2xx sur toutes les requêtes
        # même séquentiellement → pas une race condition réelle
        if n_success >= RACE_CONCURRENCY and not any(
            200 <= r["status"] < 300 for r in results
            if results.index(r) == 0  # première requête seulement
        ):
            pass  # Tous succès = potentiellement idempotent, on vérifie quand même

        if n_success >= 2 and category in ("coupon", "vote", "privilege", "points"):
            yield Finding(
                title=f"Race Condition: Multiple successful responses on {url}",
                severity=Severity.CRITICAL,
                url=url,
                module="vulns/race_condition",
                description=(
                    f"L'endpoint '{url}' (catégorie: {category}) a retourné {n_success} réponses "
                    f"2xx sur {RACE_CONCURRENCY} requêtes simultanées. "
                    f"Ce type d'endpoint ne devrait accepter qu'une seule action par session/ressource. "
                    f"La race condition permet de déclencher l'action plusieurs fois en parallèle "
                    "(coupon réutilisé, vote multiple, credits dupliqués, etc.)."
                ),
                evidence=self._format_evidence(results, status_counts),
                cwe="CWE-362",
                remediation=(
                    "Implémenter un verrou atomique (mutex, SELECT FOR UPDATE, Redis SETNX) "
                    "autour de la vérification et de l'usage de la ressource. "
                    "Utiliser des transactions DB avec isolation SERIALIZABLE pour les opérations financières. "
                    "Appliquer un idempotency key sur les endpoints transactionnels."
                ),
            )

        # Cas 2 : mix 2xx + conflits dans une fenêtre temporelle serrée
        elif n_success >= 1 and n_conflict >= 1:
            # Calculer si les requêtes sont dans la fenêtre de race
            success_times = [r["abs_time"] for r in success_results]
            conflict_times = [r["abs_time"] for r in conflict_results]
            if success_times and conflict_times:
                time_spread = max(success_times + conflict_times) - min(success_times + conflict_times)
                within_window = time_spread * 1000 < RACE_WINDOW_MS * 3

                if within_window:
                    yield Finding(
                        title=f"Race Condition: Inconsistent responses indicate TOCTOU vulnerability",
                        severity=Severity.HIGH,
                        url=url,
                        module="vulns/race_condition",
                        description=(
                            f"L'endpoint '{url}' retourne des résultats incohérents sous charge parallèle : "
                            f"{n_success} succès 2xx et {n_conflict} conflits ({list(set(r['status'] for r in conflict_results))}) "
                            f"dans une fenêtre de {time_spread*1000:.0f}ms. "
                            "Cela indique un TOCTOU (Time-Of-Check Time-Of-Use) : "
                            "la validation se fait avant l'usage mais sans verrou atomique."
                        ),
                        evidence=self._format_evidence(results, status_counts),
                        cwe="CWE-362",
                        remediation=(
                            "Remplacer le pattern check-then-act par une opération atomique. "
                            "Exemple SQL : UPDATE resource SET used=1 WHERE id=X AND used=0 → vérifier rowcount. "
                            "Utiliser Redis SETNX ou Lua scripts pour les verrous distribués."
                        ),
                    )

        # Cas 3 : double registration (même username/email créé 2 fois)
        elif category == "register" and n_success >= 2:
            yield Finding(
                title="Race Condition: Duplicate account creation possible",
                severity=Severity.HIGH,
                url=url,
                module="vulns/race_condition",
                description=(
                    f"L'endpoint d'inscription '{url}' a accepté {n_success} créations de compte "
                    f"simultanées avec les mêmes données. "
                    "Cela peut créer des comptes dupliqués, contourner des limites de quota, "
                    "ou provoquer un état incohérent en base de données."
                ),
                evidence=self._format_evidence(results, status_counts),
                cwe="CWE-362",
                remediation=(
                    "Ajouter une contrainte UNIQUE sur username/email en base de données "
                    "(si ce n'est pas déjà le cas). "
                    "Gérer l'erreur de contrainte côté serveur et retourner un 409 Conflict. "
                    "Ne pas se fier à un SELECT préalable pour vérifier l'existence."
                ),
            )

        # Cas 4 : plusieurs 2xx sur financial → critique immédiat
        elif n_success >= 2 and category == "financial":
            yield Finding(
                title="Race Condition: Multiple successful financial transactions",
                severity=Severity.CRITICAL,
                url=url,
                module="vulns/race_condition",
                description=(
                    f"L'endpoint financier '{url}' a traité {n_success} transactions "
                    f"simultanées avec succès sur {RACE_CONCURRENCY} tentatives. "
                    "Une race condition sur un endpoint de transfert/paiement peut permettre "
                    "de doubler, tripler ou multiplier les transactions (double-spend attack)."
                ),
                evidence=self._format_evidence(results, status_counts),
                cwe="CWE-362",
                remediation=(
                    "Utiliser des transactions ACID avec isolation SERIALIZABLE. "
                    "Implémenter un idempotency key (header Idempotency-Key) stocké en DB. "
                    "Vérifier et décrémenter le solde dans la même transaction atomique. "
                    "Considérer une queue de transactions asynchrone avec traitement séquentiel."
                ),
            )

    def _format_evidence(self, results: list[dict], status_counts: Counter) -> str:
        """Formate un résumé lisible des résultats du race test."""
        lines = [
            f"Requêtes envoyées simultanément : {len(results)}",
            f"Distribution des statuts : {dict(status_counts)}",
        ]
        # Montrer les 5 premiers résultats
        for r in results[:5]:
            lines.append(
                f"  req#{r['idx']:02d} → HTTP {r['status']} ({r['elapsed_ms']:.0f}ms) | {r['body_snippet'][:80]}"
            )
        if len(results) > 5:
            lines.append(f"  ... ({len(results) - 5} autres résultats)")
        return "\n".join(lines)
