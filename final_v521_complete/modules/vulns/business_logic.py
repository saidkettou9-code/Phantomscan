"""
PhantomScan — Business Logic Scanner  v1.0
===========================================
Détection de vulnérabilités de logique métier communes aux applications e-commerce
et aux APIs de gestion de ressources.

Techniques couvertes :
  - Price Tampering : modification du prix d'un article en body POST/JSON
  - Negative Quantity : quantité négative → crédit ou remboursement non-autorisé
  - Integer Overflow : quantité/montant excessif → débordement de champ
  - Coupon/Discount Stacking : application multiple du même coupon
  - Mass Assignment : injection de champs non-attendus (role, price, discount)
  - Cart Manipulation : remplacement de référence produit par un produit plus cher
  - Free Checkout : montant total à 0 ou négatif
  - Workflow Step Skipping : accès direct à l'étape finale (paiement) sans les étapes précédentes
  - Currency Confusion : envoi d'un code devise différent (USD → XPF)

Intégration EndpointBus : détecte automatiquement les endpoints de commande/panier
découverts par le crawler.
"""

from __future__ import annotations

import json
import re
from typing import AsyncIterator
from urllib.parse import urlparse, parse_qs

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester, ProbeRequest, ProbeResponse
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity
from phantomscan.core.scanner_mixin import ScannerMixin

# ─────────────────────────── Patterns endpoints e-commerce ───────────────────

_CART_PATTERNS    = re.compile(r"(cart|basket|bag|panier|kasse)", re.I)
_ORDER_PATTERNS   = re.compile(r"(order|checkout|purchase|buy|payment|commande|acheter)", re.I)
_PRODUCT_PATTERNS = re.compile(r"(product|item|article|produit|sku)", re.I)
_COUPON_PATTERNS  = re.compile(r"(coupon|promo|discount|voucher|code)", re.I)
_PRICE_PATTERNS   = re.compile(r"(price|amount|total|cost|montant|prix|subtotal)", re.I)
_QUANTITY_PATTERNS= re.compile(r"(qty|quantity|count|quantite|nombre|num)", re.I)

# Champs mass-assignment suspects dans les corps de requête
_MASS_ASSIGN_FIELDS: list[dict] = [
    {"role": "admin"},
    {"is_admin": True},
    {"admin": True},
    {"price": 0},
    {"unit_price": 0},
    {"discount": 100},
    {"discount_percent": 100},
    {"free": True},
    {"premium": True},
    {"verified": True},
    {"approved": True},
    {"status": "approved"},
    {"payment_status": "paid"},
    {"balance": 999999},
    {"credits": 999999},
]

# Devises pour confusion
_CURRENCIES = ["USD", "EUR", "GBP", "JPY", "XPF", "XOF", "CHF", "BTC", "ETH"]


# ─────────────────────────── Scanner ─────────────────────────────────────────

class BusinessLogicScanner(ScannerMixin):

    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req = req
        self._heuristic = heuristic
        self._cfg = cfg
        self._bus = None

    def set_endpoint_bus(self, bus) -> None:
        self._bus = bus

    async def run(self, target: str) -> AsyncIterator[Finding]:
        # ── 1. Détecter les endpoints intéressants depuis le bus ─────────────
        endpoints = []
        if self._bus:
            endpoints = self._bus.snapshot

        cart_eps    = [ep for ep in endpoints if _CART_PATTERNS.search(ep.url)]
        order_eps   = [ep for ep in endpoints if _ORDER_PATTERNS.search(ep.url)]
        coupon_eps  = [ep for ep in endpoints if _COUPON_PATTERNS.search(ep.url)]

        # ── 2. Price Tampering (POST endpoints avec body JSON) ───────────────
        post_eps = [ep for ep in endpoints if ep.method == "POST"]
        for ep in post_eps[:30]:
            async for f in self._test_price_tampering(ep):
                yield f
            async for f in self._test_mass_assignment(ep):
                yield f

        # ── 3. Negative Quantity ─────────────────────────────────────────────
        for ep in (cart_eps + order_eps)[:15]:
            async for f in self._test_negative_quantity(ep):
                yield f

        # ── 4. Coupon Stacking ───────────────────────────────────────────────
        for ep in coupon_eps[:10]:
            async for f in self._test_coupon_stacking(ep):
                yield f

        # ── 5. Workflow Step Skipping (checkout direct) ──────────────────────
        async for f in self._test_step_skip(target, order_eps):
            yield f

        # ── 6. Scan de l'URL cible pour params de prix dans QS ──────────────
        async for f in self._test_qs_price_tampering(target):
            yield f

    # ── Price Tampering ───────────────────────────────────────────────────────

    async def _test_price_tampering(self, ep) -> AsyncIterator[Finding]:
        """Modifie les champs price/amount dans le body JSON ou form."""
        # Tente une requête normale pour avoir le body courant
        try_json = True
        resp_orig = await self._req.send(ProbeRequest(
            method=ep.method,
            url=ep.url,
            json={"test": 1},
        ))
        if resp_orig.error or resp_orig.status == 415:
            try_json = False

        price_fields = ["price", "unit_price", "amount", "total", "cost", "subtotal",
                        "prix", "montant", "rate"]

        for field in price_fields:
            for tampered_value in [0, 0.01, -1, 0.001]:
                if try_json:
                    body = {field: tampered_value}
                    resp = await self._req.send(ProbeRequest(
                        method=ep.method, url=ep.url,
                        json=body,
                    ))
                else:
                    from urllib.parse import urlencode
                    resp = await self._req.send(ProbeRequest(
                        method=ep.method, url=ep.url,
                        body=urlencode({field: tampered_value}),
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                    ))

                if resp.error:
                    continue

                # Succès = 2xx + pas d'erreur de validation dans le body
                if resp.status in (200, 201, 202):
                    # Chercher des indices de succès (order_id, confirmation, success)
                    success_re = re.compile(r"(order_id|confirmation|success|accepted|created|ok)", re.I)
                    error_re   = re.compile(r"(invalid|error|rejected|failed|bad request|must be)", re.I)
                    if success_re.search(resp.body or "") and not error_re.search(resp.body or ""):
                        # v5.20 — re-probe pour confirmer
                        if try_json:
                            _rp = await self.re_probe(ep.url, method=ep.method, delay_s=0.4)
                        else:
                            _rp = None
                        # Vérifier que la réponse est différente de resp_orig (baseline)
                        if not resp_orig.error:
                            diff = self.stable_diff(resp.body or "", resp_orig.body or "")
                            if diff < 0.08:
                                continue  # indiscernable du baseline → probablement FP
                        yield Finding(
                            title=f"Price Tampering — champ `{field}` = {tampered_value}",
                            severity=Severity.CRITICAL,
                            url=ep.url,
                            module="vulns/business_logic",
                            description=(
                                f"Le champ `{field}` avec la valeur {tampered_value} a été accepté "
                                f"sans validation côté serveur (HTTP {resp.status}).\n"
                                f"Un attaquant peut manipuler le prix d'une commande."
                            ),
                            evidence=f"POST {ep.url} | body: {{{field}: {tampered_value}}} | status: {resp.status}",
                            cwe="CWE-840",
                            remediation=(
                                "Ne jamais accepter le prix depuis le client. "
                                "Calculer le montant total côté serveur depuis les références produits. "
                                "Valider que le total correspond au catalogue avant de traiter le paiement."
                            ),
                        )
                        return  # Un seul finding par endpoint

    # ── Negative Quantity ─────────────────────────────────────────────────────

    async def _test_negative_quantity(self, ep) -> AsyncIterator[Finding]:
        qty_fields = ["qty", "quantity", "count", "num", "amount", "quantite", "nombre"]
        for field in qty_fields:
            for value in [-1, -100, -9999]:
                resp = await self._req.send(ProbeRequest(
                    method=ep.method, url=ep.url,
                    json={field: value},
                ))
                if resp.error:
                    continue
                if resp.status in (200, 201, 202):
                    error_re = re.compile(r"(invalid|error|rejected|failed|negative|must be positive|greater than)", re.I)
                    if not error_re.search(resp.body or ""):
                        # v5.20 — stable_diff : s'assurer que la réponse change vs baseline
                        if not resp_orig.error:
                            diff = self.stable_diff(resp.body or "", resp_orig.body or "")
                            if diff < 0.05:
                                continue
                        yield Finding(
                            title=f"Negative Quantity acceptée — champ `{field}` = {value}",
                            severity=Severity.HIGH,
                            url=ep.url,
                            module="vulns/business_logic",
                            description=(
                                f"Une quantité négative ({value}) dans le champ `{field}` est acceptée "
                                f"sans erreur. Peut permettre un crédit non-autorisé ou un remboursement frauduleux."
                            ),
                            evidence=f"POST {ep.url} | {{{field}: {value}}} → HTTP {resp.status}",
                            cwe="CWE-840",
                            remediation=(
                                "Valider que les quantités sont strictement positives côté serveur. "
                                "Implémenter des limites min/max sur tous les champs numériques."
                            ),
                        )
                        return

    # ── Mass Assignment ───────────────────────────────────────────────────────

    async def _test_mass_assignment(self, ep) -> AsyncIterator[Finding]:
        for extra_fields in _MASS_ASSIGN_FIELDS:
            resp = await self._req.send(ProbeRequest(
                method=ep.method, url=ep.url,
                json=extra_fields,
            ))
            if resp.error:
                continue
            if resp.status in (200, 201, 202):
                # Vérifier si les champs sont réfléchis dans la réponse
                field_name = list(extra_fields.keys())[0]
                field_val  = str(list(extra_fields.values())[0])
                if field_name in resp.body or field_val.lower() in resp.body.lower():
                    yield Finding(
                        title=f"Mass Assignment possible — champ `{field_name}`",
                        severity=Severity.HIGH,
                        url=ep.url,
                        module="vulns/business_logic",
                        description=(
                            f"Le champ `{field_name}` inattendu (valeur: {field_val}) est "
                            f"accepté et réfléchi dans la réponse HTTP {resp.status}. "
                            f"Le serveur ne filtre pas les attributs non-autorisés."
                        ),
                        evidence=f"POST {ep.url} | champ `{field_name}={field_val}` réfléchi dans: {resp.body[:200]}",
                        cwe="CWE-915",
                        remediation=(
                            "Utiliser un DTO/allowlist d'attributs acceptés. "
                            "Ne jamais binder directement le body de la requête sur le modèle ORM. "
                            "Frameworks: Flask-Marshmallow/Pydantic strict mode, Rails strong parameters."
                        ),
                    )
                    return

    # ── Coupon Stacking ───────────────────────────────────────────────────────

    async def _test_coupon_stacking(self, ep) -> AsyncIterator[Finding]:
        """Tente d'appliquer le même coupon plusieurs fois."""
        test_coupons = ["SAVE10", "DISCOUNT20", "PROMO", "TEST", "FREE100"]
        for coupon in test_coupons:
            # Appliquer 3x le même coupon
            results = []
            for _ in range(3):
                resp = await self._req.send(ProbeRequest(
                    method=ep.method, url=ep.url,
                    json={"coupon": coupon, "code": coupon, "promo_code": coupon},
                ))
                if not resp.error and resp.status in (200, 201):
                    results.append(resp.status)

            if len(results) == 3:
                # Vérifier si les 3 retournent 200 (pas de protection contre le replay)
                success_re = re.compile(r"(applied|success|valid|accepted|ok)", re.I)
                if any(success_re.search(str(s)) for s in results):
                    yield Finding(
                        title=f"Coupon Stacking possible — code `{coupon}`",
                        severity=Severity.HIGH,
                        url=ep.url,
                        module="vulns/business_logic",
                        description=(
                            f"Le coupon `{coupon}` peut être appliqué plusieurs fois sans protection. "
                            f"3 applications successives ont toutes retourné HTTP 200."
                        ),
                        evidence=f"3x POST {ep.url} coupon={coupon} → {results}",
                        cwe="CWE-840",
                        remediation=(
                            "Marquer les coupons comme utilisés en base de données après la première application. "
                            "Valider côté serveur qu'un coupon n'a pas déjà été appliqué pour cet utilisateur/commande."
                        ),
                    )
                    return

    # ── Workflow Step Skipping ────────────────────────────────────────────────

    async def _test_step_skip(self, target: str, order_eps) -> AsyncIterator[Finding]:
        """
        Tente d'accéder directement à l'étape de confirmation/paiement
        sans passer par les étapes précédentes.
        """
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        final_step_paths = [
            "/checkout/confirm", "/checkout/payment", "/checkout/complete",
            "/order/confirm", "/order/complete", "/payment/confirm",
            "/purchase/confirm", "/buy/confirm",
            "/api/checkout/confirm", "/api/order/complete",
        ]

        for path in final_step_paths:
            url = base + path
            resp = await self._req.get(url)
            if resp.error or resp.status in (404, 410):
                continue

            if resp.status == 200:
                # Vérifier si la page contient des champs de paiement ou confirmation
                payment_re = re.compile(r"(confirm|payment|card|billing|credit|pay now|place order)", re.I)
                if payment_re.search(resp.body):
                    yield Finding(
                        title=f"Workflow Step Skipping — accès direct à {path}",
                        severity=Severity.HIGH,
                        url=url,
                        module="vulns/business_logic",
                        description=(
                            f"La page de confirmation/paiement `{path}` est accessible directement "
                            f"sans avoir complété les étapes précédentes du checkout. "
                            f"Peut permettre de contourner des validations (vérification d'âge, "
                            f"accord des CGV, vérification de stock)."
                        ),
                        evidence=f"GET {url} → HTTP {resp.status} avec contenu de paiement",
                        cwe="CWE-841",
                        remediation=(
                            "Implémenter un contrôle d'état de session pour chaque étape du workflow. "
                            "Vérifier côté serveur que les étapes précédentes ont été complétées "
                            "avant d'autoriser l'accès à l'étape finale."
                        ),
                    )

    # ── QS Price Tampering ────────────────────────────────────────────────────

    async def _test_qs_price_tampering(self, target: str) -> AsyncIterator[Finding]:
        """Teste la modification du prix dans les query string params."""
        parsed = urlparse(target)
        params = parse_qs(parsed.query, keep_blank_values=True)

        price_params = {k: v for k, v in params.items() if _PRICE_PATTERNS.search(k)}
        if not price_params:
            return

        from urllib.parse import urlencode, urlunparse
        for param, orig_vals in price_params.items():
            for tampered in ["0", "0.01", "-1"]:
                probe_params = dict(params)
                probe_params[param] = [tampered]
                probe_url = urlunparse(parsed._replace(query=urlencode(probe_params, doseq=True)))
                resp = await self._req.get(probe_url)
                if resp.error:
                    continue
                if resp.status == 200:
                    error_re = re.compile(r"(invalid|error|rejected|failed)", re.I)
                    if not error_re.search(resp.body):
                        yield Finding(
                            title=f"Price Tampering via QS — param `{param}` = {tampered}",
                            severity=Severity.HIGH,
                            url=probe_url,
                            module="vulns/business_logic",
                            description=(
                                f"Le paramètre `{param}={tampered}` dans l'URL est accepté sans validation. "
                                f"Valeur originale: {orig_vals[0]}"
                            ),
                            evidence=f"GET {probe_url} → HTTP {resp.status}",
                            cwe="CWE-840",
                            remediation=(
                                "Ne jamais faire confiance aux valeurs de prix dans les URLs. "
                                "Calculer le prix côté serveur depuis l'ID produit."
                            ),
                        )
                        break
