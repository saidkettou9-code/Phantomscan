"""
PhantomScan — IDOR Detection  v3.0  (bug bounty edition)
=========================================================
Améliorations v3.0 :
  - POST/PUT/PATCH/DELETE body IDOR  (JSON + form-encoded)
  - BOLA REST  : détection sur patterns /api/vN/<resource>/<id>
  - UUID fuzzing  : IDs non-numériques (UUID v4, base64, MD5-like)
  - Header-based IDOR  : X-User-Id, X-Account-Id, X-Forwarded-User, etc.
  - Score de similarité Jaccard pour réduire les faux positifs
  - Hashed/encoded ID detection  : base64url, hex32
  - Diff JSON amélioré  : comparaison récursive ignorant les champs volatils
  - Rate-limit awareness  : skip si 429 répété
  - Confidence level sur chaque Finding  (LOW / MEDIUM / HIGH / CONFIRMED)
"""

from __future__ import annotations

import base64
import json
import re
import uuid
from dataclasses import dataclass
from typing import AsyncIterator
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester, ProbeRequest
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity

# ─────────────────────────── Constantes ─────────────────────────────────────

ID_PARAMS: frozenset[str] = frozenset({
    "id", "user_id", "uid", "account_id", "profile_id",
    "order_id", "invoice_id", "doc_id", "file_id", "record_id",
    "ticket_id", "message_id", "comment_id", "post_id", "customer_id",
    "item_id", "product_id", "pid", "rid", "oid", "ref", "object_id",
    "entity_id", "resource_id", "member_id", "org_id", "team_id",
    "project_id", "task_id", "issue_id", "case_id", "report_id",
    "transaction_id", "payment_id", "subscription_id", "billing_id",
    "session_id", "device_id", "token_id", "key_id", "plan_id",
})

IDOR_HEADERS: list[str] = [
    "X-User-Id",
    "X-Account-Id",
    "X-Forwarded-User",
    "X-Customer-Id",
    "X-Tenant-Id",
    "X-Member-Id",
    "X-Org-Id",
    "X-Team-Id",
    "X-Client-Id",
]

_VOLATILE_KEYS: frozenset[str] = frozenset({
    # IDs (souvent différents entre deux ressources → ne pas les utiliser seuls)
    "id", "user_id", "uid", "account_id", "object_id", "resource_id",
    # Timestamps
    "created_at", "updated_at", "deleted_at", "timestamp", "ts",
    "created", "modified", "last_modified", "last_seen", "last_login",
    "expires_at", "expires_in", "expiry",
    # Tokens & sessions (changent à chaque requête)
    "nonce", "csrf_token", "xsrf_token", "_token", "authenticity_token",
    "session_id", "session", "token", "access_token", "refresh_token",
    "authorization", "bearer",
    # Tracing infra
    "request_id", "trace_id", "span_id", "correlation_id", "x_request_id",
    # Métriques live
    "view_count", "like_count", "comment_count", "hit_count",
    # Cache & ETags
    "etag", "cache_version", "version", "rev",
})

_PATH_NUM_RE  = re.compile(r'/(\d{1,12})(?:/|$|\?)')
_PATH_UUID_RE = re.compile(
    r'/([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})(?:/|$|\?)',
    re.IGNORECASE,
)
_PATH_HASH_RE = re.compile(r'/([0-9a-f]{32}|[A-Za-z0-9_-]{16,64})(?:/|$|\?)')
_BOLA_REST_RE = re.compile(
    r'(?:/api(?:/v\d+)?)?(/[a-z_-]+)/(\d{1,12}|[0-9a-f-]{36})(?:/|$)',
    re.IGNORECASE,
)
_BODY_METHODS = ("POST", "PUT", "PATCH", "DELETE")


# ─────────────────────────── Helpers ────────────────────────────────────────

def _generate_alt_ids(orig: int) -> list[int]:
    candidates = []
    for delta in (-1, 1, -2, 2, 5, 10, 50, 100):
        alt = orig + delta
        if alt > 0:
            candidates.append(alt)
    if orig > 10:
        candidates.append(1)
    if orig == 1:
        candidates.extend([2, 3, 5])
    return list(dict.fromkeys(candidates))


def _generate_alt_uuids(orig: str) -> list[str]:
    """
    v5.20 — Génère des UUIDs proches de l'original plutôt que complètement random.
    Les UUIDs random retournent 200 sur les apps qui ne valident pas l'existence
    de la ressource (soft-200) → FP massif en v5.18.

    Stratégie : muter 1-2 caractères de l'UUID original pour rester dans un
    espace "probable" (IDs qui existent peut-être) plutôt que des UUIDs
    inventés qui n'existeront presque certainement jamais.
    """
    alts = []
    if len(orig) != 36:
        return alts
    parts = orig.split("-")  # [8, 4, 4, 4, 12]
    if len(parts) != 5:
        return alts

    import secrets
    hex_chars = "0123456789abcdef"

    # Mutation 1 : changer le dernier octet du segment de 12
    last = parts[4]
    for delta in (1, -1, 2):
        try:
            val = int(last[-2:], 16)
            new_val = (val + delta) & 0xFF
            mutated = last[:-2] + format(new_val, "02x")
            alts.append("-".join(parts[:4] + [mutated]))
        except ValueError:
            pass

    # Mutation 2 : changer un char du segment de 8 (1 position aléatoire fixe)
    first = parts[0]
    if len(first) == 8:
        pos = 6  # position fixe pour reproductibilité
        orig_char = first[pos]
        for c in hex_chars:
            if c != orig_char:
                mutated_first = first[:pos] + c + first[pos+1:]
                alts.append("-".join([mutated_first] + parts[1:]))
                break  # 1 seul suffit

    return alts[:3]


def _generate_alt_hashes(orig: str) -> list[str]:
    alts = []
    try:
        padding = 4 - len(orig) % 4
        decoded = base64.urlsafe_b64decode(orig + "=" * padding)
        mutated = bytearray(decoded)
        mutated[0] ^= 0x01
        alts.append(base64.urlsafe_b64encode(bytes(mutated)).rstrip(b"=").decode())
    except Exception:
        pass
    if re.fullmatch(r'[0-9a-f]{32}', orig, re.I):
        prefix = format((int(orig[:2], 16) ^ 1) & 0xFF, '02x')
        alts.append(prefix + orig[2:])
    return alts


def _jaccard_similarity(text_a: str, text_b: str, window: int = 3000) -> float:
    a = text_a[:window]
    b = text_b[:window]
    if not a or not b:
        return 1.0 if a == b else 0.0
    trigrams_a = {a[i:i+3] for i in range(len(a) - 2)}
    trigrams_b = {b[i:i+3] for i in range(len(b) - 2)}
    inter = len(trigrams_a & trigrams_b)
    union = len(trigrams_a | trigrams_b)
    return inter / union if union else 1.0


def _responses_differ(body_a: str, body_b: str, threshold: float = 0.20) -> bool:
    """
    v5.20 — Wrappeur utilisant fp_guard.stable_diff (normalisé) au lieu de
    Jaccard brut. threshold = différence minimale pour conclure à un diff réel.

    On maintient cette fonction pour la rétrocompatibilité des call sites,
    mais elle délègue maintenant à la logique normalisée.
    """
    from phantomscan.core.fp_guard import stable_diff as _sd

    # Comparaison JSON structurée (plus fiable que la similarité textuelle)
    try:
        import json
        ja = json.loads(body_a)
        jb = json.loads(body_b)

        def _strip(obj):
            if isinstance(obj, dict):
                return {k: _strip(v) for k, v in obj.items() if k not in _VOLATILE_KEYS}
            if isinstance(obj, list):
                return [_strip(i) for i in obj]
            return obj

        ca, cb = _strip(ja), _strip(jb)
        if isinstance(ca, dict) and isinstance(cb, dict):
            keys = (set(ca) | set(cb)) - _VOLATILE_KEYS
            return any(ca.get(k) != cb.get(k) for k in keys)
        if isinstance(ca, list) and isinstance(cb, list):
            return len(ca) != len(cb)
        return ca != cb
    except (json.JSONDecodeError, ValueError, TypeError):
        pass

    # Comparaison HTML : titre différent = ressource différente
    _title_re = re.compile(r'<title[^>]*>([^<]*)</title>', re.I)
    ta = _title_re.search(body_a)
    tb = _title_re.search(body_b)
    if ta and tb and ta.group(1).strip() != tb.group(1).strip():
        return True

    # v5.20 — stable_diff normalisé (timestamp/tokens/UUIDs filtrés)
    diff = _sd(body_a, body_b)
    return diff >= threshold


@dataclass
class _IDORHit:
    param_or_path: str
    orig_id: str
    alt_id: str
    orig_url: str
    alt_url: str
    orig_size: int
    alt_size: int
    method: str = "GET"
    confirmed_by_swap: bool = False
    confidence: str = "MEDIUM"


# ─────────────────────────── Scanner principal ───────────────────────────────

from phantomscan.core.scanner_mixin import ScannerMixin


class IDORScanner(ScannerMixin):
    """
    Scanner IDOR/BOLA v3.0 — couverture maximale pour bug bounty.

    Vecteurs couverts :
      • Paramètres query string  (numeric / UUID / hash)
      • Segments de chemin REST  (numeric / UUID / hash)
      • Body JSON  POST / PUT / PATCH / DELETE
      • Headers portant un ID  (X-User-Id, X-Account-Id, etc.)
      • Patterns BOLA  /api/v1/resource/{id}
      • Session swap cross-account pour confirmation CRITICAL

    v5.19 — Multi-profils via AuthContext :
      Si ≥ 2 profils sont configurés (--auth-profile alice:... bob:...),
      chaque hit potentiel est rejoué avec le profil opposé pour confirmer
      l'accès cross-user. Le finding est alors marqué [CONFIRMED CROSS-USER]
      avec le nom des deux profils impliqués.
    """

    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req = req
        self._heuristic = heuristic
        self._cfg = cfg
        # Mode legacy v5.18 : alt_cookies / alt_bearer_token via cfg
        self._alt_cookies: dict[str, str] = getattr(cfg, "alt_cookies", {}) or {}
        self._alt_token: str | None = getattr(cfg, "alt_bearer_token", None)
        self._rate_limit_hits: int = 0

    @property
    def _has_alt_session(self) -> bool:
        # v5.19 — vrai si on a ≥ 2 profils OU les anciennes alt_cookies/token
        if self.has_multi_profile():
            return True
        return bool(self._alt_cookies or self._alt_token)

    # ── Point d'entrée ────────────────────────────────────────────────────────

    async def run(self, target: str) -> AsyncIterator[Finding]:
        parsed = urlparse(target)
        params = parse_qs(parsed.query, keep_blank_values=True)

        # 1. Query params
        for param, values in params.items():
            if param.lower() not in ID_PARAMS:
                continue
            raw = values[0] if values else ""
            id_type = self._detect_id_type(raw)
            if id_type:
                async for f in self._probe_param(target, parsed, params, param, raw, id_type):
                    yield f

        # 2. Path numerique
        path = parsed.path
        for match in _PATH_NUM_RE.finditer(path):
            async for f in self._probe_path_segment(target, parsed, path, match.group(1), "numeric"):
                yield f

        # 3. Path UUID
        for match in _PATH_UUID_RE.finditer(path):
            async for f in self._probe_path_segment(target, parsed, path, match.group(1), "uuid"):
                yield f

        # 4. Path hash/base64url
        for match in _PATH_HASH_RE.finditer(path):
            seg = match.group(1)
            if not re.fullmatch(r'\d{1,12}', seg) and not re.fullmatch(
                r'[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}', seg, re.I
            ):
                async for f in self._probe_path_segment(target, parsed, path, seg, "hash"):
                    yield f

        # 5. Headers
        async for f in self._probe_headers(target):
            yield f

        # 6. BOLA REST
        async for f in self._probe_bola_rest(target, parsed):
            yield f

    # ── Probe : query param ───────────────────────────────────────────────────

    async def _probe_param(
        self, target: str, parsed, params: dict, param: str, orig_id: str, id_type: str,
    ) -> AsyncIterator[Finding]:
        if self._rate_limit_hits >= 3:
            return

        orig_resp = await self._req.get(target)
        if orig_resp.error or orig_resp.status not in (200, 201):
            return

        for alt_id in self._alt_ids(orig_id, id_type):
            fuzzed = dict(params)
            fuzzed[param] = [str(alt_id)]
            new_url = urlunparse(parsed._replace(query=urlencode(fuzzed, doseq=True)))

            alt_resp = await self._req.get(new_url)
            if alt_resp.error:
                continue
            if alt_resp.status == 429:
                self._rate_limit_hits += 1
                continue
            self._rate_limit_hits = 0

            if alt_resp.status == 200 and _responses_differ(orig_resp.body, alt_resp.body):
                hit = _IDORHit(
                    param_or_path=f"param:{param}", orig_id=orig_id, alt_id=str(alt_id),
                    orig_url=target, alt_url=new_url,
                    orig_size=orig_resp.content_length, alt_size=alt_resp.content_length,
                )
                hit = await self._confirm_with_swap(hit, new_url)
                yield self._to_finding(hit, f"IDOR — param `{param}` ({id_type})")
                break

    # ── Probe : segment de chemin ─────────────────────────────────────────────

    async def _probe_path_segment(
        self, target: str, parsed, path: str, seg: str, id_type: str,
    ) -> AsyncIterator[Finding]:
        if self._rate_limit_hits >= 3:
            return

        orig_resp = await self._req.get(target)
        if orig_resp.error or orig_resp.status not in (200, 201):
            return

        for alt_id in self._alt_ids(seg, id_type):
            new_path = path.replace(f"/{seg}", f"/{alt_id}", 1)
            new_url = urlunparse(parsed._replace(path=new_path))
            if new_url == target:
                continue

            alt_resp = await self._req.get(new_url)
            if alt_resp.error:
                continue
            if alt_resp.status == 429:
                self._rate_limit_hits += 1
                continue
            self._rate_limit_hits = 0

            if alt_resp.status == 200 and _responses_differ(orig_resp.body, alt_resp.body):
                hit = _IDORHit(
                    param_or_path=f"path:{seg}", orig_id=seg, alt_id=str(alt_id),
                    orig_url=target, alt_url=new_url,
                    orig_size=orig_resp.content_length, alt_size=alt_resp.content_length,
                )
                hit = await self._confirm_with_swap(hit, new_url)
                yield self._to_finding(hit, f"IDOR — path segment `{seg}` ({id_type})")
                break

    # ── Probe : body JSON (POST/PUT/PATCH/DELETE) ─────────────────────────────

    async def probe_body(
        self, target: str, method: str, original_body: str,
        extra_headers: dict[str, str] | None = None,
    ) -> AsyncIterator[Finding]:
        """
        Méthode publique appelée par l'engine pour les requêtes avec body capturé.
        Supporte POST, PUT, PATCH, DELETE avec payload JSON.
        """
        if method.upper() not in _BODY_METHODS:
            return
        headers = extra_headers or {}

        try:
            payload = json.loads(original_body)
        except (json.JSONDecodeError, ValueError):
            return

        if not isinstance(payload, dict):
            return

        orig_resp = await self._req.send(
            ProbeRequest(method=method, url=target, headers=headers, body=original_body)
        )
        if orig_resp.error or orig_resp.status not in (200, 201, 204):
            return

        for key, value in payload.items():
            if key.lower() not in ID_PARAMS:
                continue
            raw = str(value)
            id_type = self._detect_id_type(raw)
            if id_type is None:
                continue

            for alt_id in self._alt_ids(raw, id_type):
                mutated = {**payload, key: alt_id if id_type == "numeric" else str(alt_id)}
                mutated_body = json.dumps(mutated)
                alt_resp = await self._req.send(
                    ProbeRequest(method=method, url=target, headers=headers, body=mutated_body)
                )
                if alt_resp.error or alt_resp.status == 429:
                    continue
                if alt_resp.status in (200, 201, 204) and _responses_differ(orig_resp.body, alt_resp.body):
                    hit = _IDORHit(
                        param_or_path=f"body:{key}", orig_id=raw, alt_id=str(alt_id),
                        orig_url=target, alt_url=target,
                        orig_size=orig_resp.content_length, alt_size=alt_resp.content_length,
                        method=method.upper(),
                    )
                    hit = await self._confirm_with_swap(hit, target, method=method, body=mutated_body)
                    yield self._to_finding(hit, f"IDOR — body field `{key}` ({method.upper()})")
                    break

    # ── Probe : headers ───────────────────────────────────────────────────────

    async def _probe_headers(self, target: str) -> AsyncIterator[Finding]:
        """Injecte des IDs arbitraires dans les headers porteurs d'identité."""
        if self._rate_limit_hits >= 3:
            return

        orig_resp = await self._req.get(target)
        if orig_resp.error or orig_resp.status not in (200, 201):
            return

        for header in IDOR_HEADERS:
            for alt_id in (1, 2, 9999, 0):
                probe = ProbeRequest(method="GET", url=target, headers={header: str(alt_id)})
                alt_resp = await self._req.send(probe)
                if alt_resp.error or alt_resp.status == 429:
                    continue
                if alt_resp.status == 200 and _responses_differ(orig_resp.body, alt_resp.body):
                    hit = _IDORHit(
                        param_or_path=f"header:{header}", orig_id="(none)", alt_id=str(alt_id),
                        orig_url=target, alt_url=target,
                        orig_size=orig_resp.content_length, alt_size=alt_resp.content_length,
                        confidence="HIGH",
                    )
                    hit = await self._confirm_with_swap(hit, target, extra_headers={header: str(alt_id)})
                    yield self._to_finding(hit, f"IDOR — header `{header}`")
                    break

    # ── Probe : BOLA REST ─────────────────────────────────────────────────────

    async def _probe_bola_rest(self, target: str, parsed) -> AsyncIterator[Finding]:
        """Pattern /api/v*/resource/{id} — énumération horizontale."""
        path = parsed.path
        for match in _BOLA_REST_RE.finditer(path):
            resource = match.group(1)
            raw_id   = match.group(2)
            id_type  = self._detect_id_type(raw_id)
            if id_type is None:
                continue

            orig_resp = await self._req.get(target)
            if orig_resp.error or orig_resp.status not in (200, 201):
                continue

            for alt_id in self._alt_ids(raw_id, id_type):
                new_path = path[:match.start(2)] + str(alt_id) + path[match.end(2):]
                new_url = urlunparse(parsed._replace(path=new_path))
                if new_url == target:
                    continue

                alt_resp = await self._req.get(new_url)
                if alt_resp.error or alt_resp.status == 429:
                    continue

                if alt_resp.status == 200 and _responses_differ(orig_resp.body, alt_resp.body):
                    hit = _IDORHit(
                        param_or_path=f"bola:{resource}/{raw_id}", orig_id=raw_id, alt_id=str(alt_id),
                        orig_url=target, alt_url=new_url,
                        orig_size=orig_resp.content_length, alt_size=alt_resp.content_length,
                        confidence="HIGH",
                    )
                    hit = await self._confirm_with_swap(hit, new_url)
                    yield self._to_finding(hit, f"BOLA — REST `{resource}/{{{raw_id}}}`")
                    break

    # ── Session swap ──────────────────────────────────────────────────────────

    async def _confirm_with_swap(
        self, hit: _IDORHit, url: str, method: str = "GET",
        body: str | None = None, extra_headers: dict[str, str] | None = None,
    ) -> _IDORHit:
        """
        v5.19 — Confirmation cross-account.

        Stratégie :
          1. Si AuthContext a ≥ 2 profils, on prend le 1er profil DIFFÉRENT
             du profil actif et on rejoue la requête avec ses credentials.
          2. Sinon, fallback sur les anciennes alt_cookies/alt_bearer.

        Si le rejeu donne un 200 (et n'est pas un redirect login), c'est une
        confirmation FORTE qu'un autre utilisateur peut accéder à la
        ressource → finding promu en CRITICAL.
        """
        if not self._has_alt_session:
            return hit

        headers: dict[str, str] = dict(extra_headers or {})
        confirmation_label = ""

        # v5.19 — Mode multi-profils
        ctx = self.auth_context
        if ctx is not None and ctx.has_multiple_profiles():
            current_profile = self._req.active_profile
            # Trouver le 1er autre profil
            other = next(
                (p for p in ctx.profiles if p.name != current_profile),
                None,
            )
            if other is not None:
                # Bascule le requester sur l'autre profil pour le rejeu
                self._req.use_profile(other.name)
                try:
                    swap_resp = await self._req.send(
                        ProbeRequest(method=method, url=url, headers=headers, body=body)
                    )
                finally:
                    # Restaurer le profil d'origine
                    if current_profile:
                        self._req.use_profile(current_profile)
                # Validation : 200 ET pas redirect vers login
                if (
                    not swap_resp.error
                    and swap_resp.status == 200
                    and "login" not in swap_resp.url.lower()
                ):
                    hit.confirmed_by_swap = True
                    hit.confidence = "CONFIRMED"
                    confirmation_label = (
                        f" [{current_profile or 'default'} → {other.name}]"
                    )
                    if not hasattr(hit, "swap_label") or not hit.swap_label:
                        try:
                            setattr(hit, "swap_label", confirmation_label)
                        except Exception:
                            pass
                return hit

        # Fallback legacy
        if self._alt_token:
            headers["Authorization"] = f"Bearer {self._alt_token}"
        cookie_str = "; ".join(f"{k}={v}" for k, v in self._alt_cookies.items())
        if cookie_str:
            headers["Cookie"] = cookie_str
        swap_resp = await self._req.send(
            ProbeRequest(method=method, url=url, headers=headers, body=body)
        )
        if not swap_resp.error and swap_resp.status == 200:
            hit.confirmed_by_swap = True
            hit.confidence = "CONFIRMED"
        return hit

    # ── Fabrique Finding ──────────────────────────────────────────────────────

    def _to_finding(self, hit: _IDORHit, title: str) -> Finding:
        severity = Severity.CRITICAL if hit.confirmed_by_swap else Severity.HIGH
        prefix   = "[CONFIRMED] " if hit.confirmed_by_swap else ""

        parts = [
            f"Vecteur       : `{hit.param_or_path}`",
            f"ID original   : `{hit.orig_id}` → ID testé : `{hit.alt_id}`",
            f"Méthode HTTP  : {hit.method}",
            f"Confidence    : {hit.confidence}",
        ]
        if hit.confirmed_by_swap:
            # v5.19 — Inclure le label des profils impliqués si disponible
            swap_label = getattr(hit, "swap_label", "") or ""
            parts.append(
                f"[SESSION SWAP CONFIRMED]{swap_label} Un second compte a accédé "
                f"à la ressource avec l'ID `{hit.alt_id}`. Accès cross-account confirmé."
            )

        return Finding(
            title=f"{prefix}{title}",
            severity=severity,
            url=hit.alt_url,
            module="vulns/idor",
            description="\n".join(parts),
            evidence=(
                f"Origine : {hit.orig_url} ({hit.orig_size}B) | "
                f"Altéré : {hit.alt_url} ({hit.alt_size}B)"
            ),
            cwe="CWE-639",
            remediation=(
                "1. Valider côté serveur que l'utilisateur est propriétaire de la ressource.\n"
                "2. Utiliser des identifiants non-séquentiels et non-prédictibles (UUID v4).\n"
                "3. Implémenter un contrôle d'accès basé sur les objets (ABAC/PBAC).\n"
                "4. Ne jamais faire confiance aux IDs fournis côté client sans vérification d'autorisation."
            ),
        )

    # ── Utilitaires ───────────────────────────────────────────────────────────

    @staticmethod
    def _detect_id_type(raw: str) -> str | None:
        if re.fullmatch(r'\d{1,12}', raw):
            return "numeric"
        if re.fullmatch(
            r'[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',
            raw, re.I,
        ):
            return "uuid"
        if re.fullmatch(r'[0-9a-f]{32}', raw, re.I):
            return "hash"
        if re.fullmatch(r'[A-Za-z0-9_-]{16,64}', raw):
            return "hash"
        return None

    @staticmethod
    def _alt_ids(orig: str, id_type: str) -> list:
        if id_type == "numeric":
            return _generate_alt_ids(int(orig))
        if id_type == "uuid":
            return _generate_alt_uuids(orig)
        if id_type == "hash":
            return _generate_alt_hashes(orig)
        return []

    # ── IDOR prédictif ────────────────────────────────────────────────────────

    @staticmethod
    def predict_next_ids(observed_ids: list[int], n: int = 5) -> list[int]:
        """
        v5.11 — Prédit les prochains IDs séquentiels à partir d'une liste d'IDs
        observés (extraits du crawl ou du JS). Détecte le pattern d'incrément
        (±1, ±2, ±5, ±10, ±100) pour cibler l'énumération.

        Ex : [1042, 1045, 1048] → incrément 3 → [1051, 1054, 1057, ...]
        Ex : [10, 20, 30, 40] → incrément 10 → [50, 60, 70, ...]

        Utile pour le BOLA sur des APIs qui auto-incrémentent visiblement.
        """
        if len(observed_ids) < 2:
            return _generate_alt_ids(observed_ids[0]) if observed_ids else []

        sorted_ids = sorted(observed_ids)
        deltas = [sorted_ids[i+1] - sorted_ids[i] for i in range(len(sorted_ids)-1)]

        # Incrément le plus fréquent
        delta_mode = max(set(deltas), key=deltas.count)

        if delta_mode == 0:
            # Pas de pattern clair → fallback generate_alt_ids sur le max
            return _generate_alt_ids(sorted_ids[-1])

        last = sorted_ids[-1]
        predictions = []
        # IDs suivants (forward)
        for i in range(1, n + 1):
            predictions.append(last + delta_mode * i)
        # IDs précédents (backward enumeration)
        first = sorted_ids[0]
        for i in range(1, 3):
            pred = first - delta_mode * i
            if pred > 0:
                predictions.append(pred)

        return [p for p in predictions if p > 0]

    async def run_predictive(
        self, observed_ids: list[int], base_url_template: str, param: str
    ) -> AsyncIterator[Finding]:
        """
        v5.11 — IDOR prédictif : teste les IDs inférés du pattern d'incrément
        sur une URL template. Ex: base_url_template="https://api.target.com/users?id={id}"

        Appelé par l'engine quand plusieurs IDs numériques ont été collectés
        par le bus sur la même ressource.
        """
        predicted = self.predict_next_ids(observed_ids, n=5)
        if not predicted:
            return

        # Baseline sur le premier ID connu
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        ref_url = base_url_template.replace("{id}", str(observed_ids[0]))
        parsed = urlparse(ref_url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        ref_resp = await self._req.get(ref_url)
        if ref_resp.error or ref_resp.status not in (200, 201):
            return

        for pred_id in predicted:
            if self._rate_limit_hits >= 3:
                break
            fuzzed = dict(params)
            fuzzed[param] = [str(pred_id)]
            test_url = urlunparse(parsed._replace(query=urlencode(fuzzed, doseq=True)))

            resp = await self._req.get(test_url)
            if resp.error:
                continue
            if resp.status == 429:
                self._rate_limit_hits += 1
                continue
            self._rate_limit_hits = 0

            if resp.status == 200 and _responses_differ(ref_resp.body, resp.body):
                hit = _IDORHit(
                    param_or_path=f"param:{param}",
                    orig_id=str(observed_ids[0]),
                    alt_id=str(pred_id),
                    orig_url=ref_url,
                    alt_url=test_url,
                    orig_size=ref_resp.content_length,
                    alt_size=resp.content_length,
                    confidence="HIGH",
                )
                hit = await self._confirm_with_swap(hit, test_url)
                yield self._to_finding(hit, f"IDOR Prédictif — param `{param}` (incrément détecté)")
                break

    # ── GraphQL IDOR ──────────────────────────────────────────────────────────

    async def probe_graphql(
        self,
        endpoint: str,
        operation_body: str,
        extra_headers: dict[str, str] | None = None,
    ) -> AsyncIterator[Finding]:
        """
        v5.11 — Détecte les IDOR dans les opérations GraphQL (queries et mutations)
        en mutant les champs contenant des IDs dans les variables ou inline args.

        Supporte :
          - Variables GraphQL : {"query": "...", "variables": {"userId": 42}}
          - Arguments inline : query { user(id: 42) { ... } }
          - IDs numériques, UUID et base64url dans les variables

        Exemple de finding : une mutation updateProfile(userId: 42) répond 200
        avec les données d'un autre user quand userId est muté à 43.
        """
        headers = {
            "Content-Type": "application/json",
            **(extra_headers or {}),
        }

        try:
            payload = json.loads(operation_body)
        except (json.JSONDecodeError, ValueError):
            return

        if not isinstance(payload, dict):
            return

        # Cas 1 : variables GraphQL
        variables = payload.get("variables") or {}
        if isinstance(variables, dict):
            for key, value in list(variables.items()):
                raw = str(value)
                id_type = self._detect_id_type(raw)
                if id_type is None:
                    continue

                orig_resp = await self._req.send(
                    ProbeRequest(method="POST", url=endpoint, headers=headers, body=operation_body)
                )
                if orig_resp.error or orig_resp.status not in (200, 201):
                    continue

                for alt_id in self._alt_ids(raw, id_type):
                    mutated_vars = {**variables, key: alt_id if id_type == "numeric" else str(alt_id)}
                    mutated_payload = {**payload, "variables": mutated_vars}
                    mutated_body = json.dumps(mutated_payload)

                    alt_resp = await self._req.send(
                        ProbeRequest(method="POST", url=endpoint, headers=headers, body=mutated_body)
                    )
                    if alt_resp.error or alt_resp.status == 429:
                        continue

                    # GraphQL retourne souvent 200 même en cas d'erreur
                    # Vérifier l'absence d'erreurs dans la réponse altérée
                    try:
                        resp_json = json.loads(alt_resp.body)
                        has_errors = bool(resp_json.get("errors"))
                    except (json.JSONDecodeError, ValueError):
                        has_errors = True

                    if not has_errors and _responses_differ(orig_resp.body, alt_resp.body):
                        hit = _IDORHit(
                            param_or_path=f"graphql:variable:{key}",
                            orig_id=raw,
                            alt_id=str(alt_id),
                            orig_url=endpoint,
                            alt_url=endpoint,
                            orig_size=orig_resp.content_length,
                            alt_size=alt_resp.content_length,
                            method="POST",
                            confidence="HIGH",
                        )
                        hit = await self._confirm_with_swap(
                            hit, endpoint, method="POST", body=mutated_body, extra_headers=headers
                        )
                        yield self._to_finding(
                            hit,
                            f"IDOR GraphQL — variable `{key}` ({id_type})"
                        )
                        break

        # Cas 2 : arguments inline dans la query string
        query_str = payload.get("query", "")
        if query_str:
            # Regex pour trouver les args inline : fieldName(id: 42) ou (userId: "uuid")
            inline_re = re.compile(
                r'(\w+)\s*:\s*("?)(\d{1,12}|[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\2',
                re.IGNORECASE,
            )
            for match in inline_re.finditer(query_str):
                arg_name = match.group(1)
                quote = match.group(2)
                raw_val = match.group(3)
                id_type = self._detect_id_type(raw_val)
                if id_type is None or arg_name.lower() not in ID_PARAMS:
                    continue

                orig_resp = await self._req.send(
                    ProbeRequest(method="POST", url=endpoint, headers=headers, body=operation_body)
                )
                if orig_resp.error or orig_resp.status not in (200, 201):
                    continue

                for alt_id in self._alt_ids(raw_val, id_type)[:3]:
                    mutated_query = query_str.replace(
                        match.group(0),
                        f'{arg_name}: {quote}{alt_id}{quote}'
                    )
                    mutated_body = json.dumps({**payload, "query": mutated_query})

                    alt_resp = await self._req.send(
                        ProbeRequest(method="POST", url=endpoint, headers=headers, body=mutated_body)
                    )
                    if alt_resp.error or alt_resp.status == 429:
                        continue

                    try:
                        resp_json = json.loads(alt_resp.body)
                        has_errors = bool(resp_json.get("errors"))
                    except (json.JSONDecodeError, ValueError):
                        has_errors = True

                    if not has_errors and _responses_differ(orig_resp.body, alt_resp.body):
                        hit = _IDORHit(
                            param_or_path=f"graphql:inline:{arg_name}",
                            orig_id=raw_val,
                            alt_id=str(alt_id),
                            orig_url=endpoint,
                            alt_url=endpoint,
                            orig_size=orig_resp.content_length,
                            alt_size=alt_resp.content_length,
                            method="POST",
                            confidence="HIGH",
                        )
                        hit = await self._confirm_with_swap(
                            hit, endpoint, method="POST", body=mutated_body, extra_headers=headers
                        )
                        yield self._to_finding(
                            hit,
                            f"IDOR GraphQL — arg inline `{arg_name}` ({id_type})"
                        )
                        break
