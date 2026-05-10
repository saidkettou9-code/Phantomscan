"""
PhantomScan — Technology Detector
Reconnaissance passive : identification de CMS, frameworks, serveurs, CDN, WAF.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import AsyncIterator

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester
from phantomscan.output.reporter import Finding, Severity


# ── Signatures ────────────────────────────────────────────────────────────────

@dataclass
class Signature:
    name: str
    category: str               # cms | framework | server | cdn | waf | language | db
    header: str | None = None   # Header HTTP à inspecter (None = tous)
    header_pattern: re.Pattern | None = None
    body_pattern: re.Pattern | None = None
    cookie_pattern: re.Pattern | None = None
    confidence: int = 80        # 0–100


def _sig(
    name: str,
    category: str,
    *,
    header: str | None = None,
    hp: str | None = None,
    bp: str | None = None,
    cp: str | None = None,
    confidence: int = 80,
) -> Signature:
    return Signature(
        name=name,
        category=category,
        header=header,
        header_pattern=re.compile(hp, re.I) if hp else None,
        body_pattern=re.compile(bp, re.I) if bp else None,
        cookie_pattern=re.compile(cp, re.I) if cp else None,
        confidence=confidence,
    )


SIGNATURES: list[Signature] = [
    # ── Serveurs ──────────────────────────────────────────────────────────────
    _sig("Apache",       "server",    header="Server",   hp=r"Apache(?:/[\d.]+)?"),
    _sig("Nginx",        "server",    header="Server",   hp=r"nginx(?:/[\d.]+)?"),
    _sig("IIS",          "server",    header="Server",   hp=r"Microsoft-IIS(?:/[\d.]+)?"),
    _sig("LiteSpeed",    "server",    header="Server",   hp=r"LiteSpeed"),
    _sig("Caddy",        "server",    header="Server",   hp=r"Caddy"),
    _sig("OpenResty",    "server",    header="Server",   hp=r"openresty"),
    _sig("Gunicorn",     "server",    header="Server",   hp=r"gunicorn(?:/[\d.]+)?"),
    _sig("Uvicorn",      "server",    header="Server",   hp=r"uvicorn(?:/[\d.]+)?"),
    _sig("Tomcat",       "server",    header="Server",   hp=r"Apache-Coyote|Tomcat"),

    # ── Langages / runtimes ───────────────────────────────────────────────────
    _sig("PHP",          "language",  header="X-Powered-By", hp=r"PHP/[\d.]+"),
    _sig("ASP.NET",      "language",  header="X-Powered-By", hp=r"ASP\.NET"),
    _sig("Express.js",   "framework", header="X-Powered-By", hp=r"Express"),
    _sig("Ruby on Rails","framework", header="X-Powered-By", hp=r"Phusion Passenger|Rack"),

    # ── CMS ───────────────────────────────────────────────────────────────────
    _sig("WordPress",    "cms",
         bp=r'<(?:link|meta)[^>]+wp-content|wordpress|/wp-json/',
         cp=r"wordpress_|wp-settings",
         confidence=90),
    _sig("Drupal",       "cms",
         bp=r'(?:Drupal\.settings|drupal\.js|/sites/default/files)',
         header="X-Generator", hp=r"Drupal",
         confidence=90),
    _sig("Joomla",       "cms",
         bp=r'/components/com_|Joomla!|/media/jui/',
         cp=r"joomla_user_state",
         confidence=85),
    _sig("Shopify",      "cms",
         bp=r'cdn\.shopify\.com|Shopify\.theme',
         header="X-ShopId", hp=r"\d+",
         confidence=95),
    _sig("Magento",      "cms",
         bp=r'Mage\.Cookies|/skin/frontend/default/|mage-translation',
         cp=r"frontend=[a-f0-9]{26,}",
         confidence=85),
    _sig("TYPO3",        "cms",
         bp=r'typo3temp|typo3conf|This website is powered by TYPO3',
         confidence=85),
    _sig("PrestaShop",   "cms",
         bp=r'prestashop|/modules/(?:ps_|blockcart)',
         cp=r"PrestaShop",
         confidence=85),
    _sig("Ghost",        "cms",
         bp=r'content="Ghost \d+\.\d+|ghost-url',
         header="X-Ghost-Cache-Status", hp=r".+",
         confidence=90),
    _sig("Strapi",       "cms",
         header="X-Powered-By", hp=r"Strapi",
         confidence=90),

    # ── Frameworks frontend ───────────────────────────────────────────────────
    _sig("React",        "framework", bp=r'react(?:\.development|\.production|Dom)|__REACT_DEVTOOLS'),
    _sig("Next.js",      "framework",
         bp=r'_next/static|__NEXT_DATA__',
         header="X-Powered-By", hp=r"Next\.js",
         confidence=95),
    _sig("Nuxt.js",      "framework", bp=r'__nuxt|_nuxt/'),
    _sig("Angular",      "framework", bp=r'ng-version=|angular\.min\.js|ng-app'),
    _sig("Vue.js",       "framework", bp=r'vue(?:\.min)?\.js|__vue_'),
    _sig("Svelte",       "framework", bp=r'svelte-[a-z0-9]{7}|__svelte'),
    _sig("Gatsby",       "framework", bp=r'___gatsby|gatsby-chunk-mapping'),

    # ── Frameworks backend ────────────────────────────────────────────────────
    _sig("Django",       "framework",
         header="X-Frame-Options", hp=r"SAMEORIGIN",
         bp=r'csrfmiddlewaretoken|__admin_media_prefix__',
         cp=r"csrftoken|sessionid",
         confidence=70),
    _sig("Laravel",      "framework",
         cp=r"laravel_session",
         confidence=85),
    _sig("Spring Boot",  "framework",
         header="X-Application-Context", hp=r".+",
         confidence=90),
    _sig("Flask",        "framework",
         header="Server", hp=r"Werkzeug",
         confidence=85),
    _sig("FastAPI",      "framework",
         bp=r'"openapi":"3\.\d+\.\d+"|/docs#/|/redoc',
         confidence=80),
    _sig("Rails",        "framework",
         cp=r"_session_id|_rails",
         confidence=75),

    # ── CDN ───────────────────────────────────────────────────────────────────
    _sig("Cloudflare",   "cdn",
         header="CF-Ray", hp=r"[0-9a-f]+-[A-Z]{3}",
         confidence=99),
    _sig("Fastly",       "cdn",
         header="X-Served-By", hp=r"cache-",
         confidence=85),
    _sig("Akamai",       "cdn",
         header="X-Check-Cacheable", hp=r".+",
         confidence=80),
    _sig("AWS CloudFront","cdn",
         header="X-Amz-Cf-Id", hp=r".+",
         confidence=99),
    _sig("Varnish",      "cdn",
         header="X-Varnish", hp=r"\d+",
         confidence=95),
    _sig("Vercel",       "cdn",
         header="X-Vercel-Id", hp=r".+",
         confidence=99),
    _sig("Netlify",      "cdn",
         header="X-Nf-Request-Id", hp=r".+",
         confidence=99),

    # ── WAF ───────────────────────────────────────────────────────────────────
    _sig("AWS WAF",      "waf",
         header="X-Amzn-Requestid", hp=r".+",
         confidence=70),
    _sig("ModSecurity",  "waf",
         bp=r"Mod_Security|NOYB",
         confidence=85),
    _sig("Sucuri WAF",   "waf",
         header="X-Sucuri-Id", hp=r".+",
         confidence=99),
    _sig("Imperva",      "waf",
         header="X-Iinfo", hp=r".+",
         confidence=95),
    _sig("F5 BIG-IP",    "waf",
         header="X-WA-Info", hp=r".+",
         cp=r"BIGipServer",
         confidence=90),

    # ── Analytics / tag managers ──────────────────────────────────────────────
    _sig("Google Analytics", "analytics",
         bp=r'google-analytics\.com/(?:analytics|ga)\.js|gtag\(\'config\'|UA-\d+-\d+',
         confidence=95),
    _sig("Google Tag Manager", "analytics",
         bp=r'googletagmanager\.com/gtm\.js|GTM-[A-Z0-9]+',
         confidence=95),

    # ── Bases de données (exposition) ─────────────────────────────────────────
    _sig("Elasticsearch", "db",
         bp=r'"cluster_name"\s*:\s*"',
         confidence=90),
    _sig("MongoDB",      "db",
         bp=r'"errmsg"\s*:\s*"not authorized|MongoError',
         confidence=85),
]


# ── Scanner ───────────────────────────────────────────────────────────────────

@dataclass
class TechResult:
    name: str
    category: str
    confidence: int


class TechDetector:
    """
    Détecte les technologies utilisées par la cible via inspection passive
    des headers, du body et des cookies.
    """

    def __init__(self, req: Requester, cfg: PhantomConfig) -> None:
        self._req = req
        self._cfg = cfg

    async def run(self, target: str) -> AsyncIterator[Finding]:
        resp = await self._req.get(target)
        if resp.error:
            return

        detected: list[TechResult] = []
        seen: set[str] = set()

        for sig in SIGNATURES:
            if sig.name in seen:
                continue

            matched = False

            # Vérifie le header spécifique
            if sig.header and sig.header_pattern:
                val = resp.headers.get(sig.header, "")
                if sig.header_pattern.search(val):
                    matched = True

            # Vérifie tous les headers si pas de header ciblé
            if sig.header is None and sig.header_pattern:
                for val in resp.headers.values():
                    if sig.header_pattern.search(val):
                        matched = True
                        break

            # Vérifie le body
            if not matched and sig.body_pattern and sig.body_pattern.search(resp.body):
                matched = True

            # Vérifie les cookies
            if not matched and sig.cookie_pattern:
                set_cookie = resp.headers.get("Set-Cookie", "")
                cookie_header = resp.headers.get("Cookie", "")
                if sig.cookie_pattern.search(set_cookie) or sig.cookie_pattern.search(cookie_header):
                    matched = True

            if matched:
                detected.append(TechResult(sig.name, sig.category, sig.confidence))
                seen.add(sig.name)

        if not detected:
            return

        # Regroupe par catégorie pour le rapport
        by_category: dict[str, list[TechResult]] = {}
        for tech in detected:
            by_category.setdefault(tech.category, []).append(tech)

        summary_parts = []
        for cat, techs in sorted(by_category.items()):
            names = ", ".join(f"{t.name} ({t.confidence}%)" for t in techs)
            summary_parts.append(f"**{cat.upper()}**: {names}")

        # Vérifie les risques de divulgation de version
        version_disclosures = self._check_version_disclosure(resp)

        sev = Severity.INFO
        extra_info = ""
        if version_disclosures:
            sev = Severity.LOW
            extra_info = "\n\n**Versions exposées**: " + ", ".join(version_disclosures)

        yield Finding(
            title=f"Technologies détectées ({len(detected)} technologie(s))",
            severity=sev,
            url=target,
            module="recon/tech_detect",
            description=(
                "Empreinte technologique de la cible identifiée via analyse passive "
                "des headers HTTP, du contenu HTML et des cookies.\n\n"
                + "\n".join(summary_parts)
                + extra_info
            ),
            evidence=f"{len(detected)} technologie(s) détectée(s) : "
                     + ", ".join(t.name for t in detected),
            cwe="CWE-200",
            remediation=(
                "Masquer les headers révélateurs (Server, X-Powered-By) via la config serveur. "
                "Supprimer les commentaires HTML exposant le CMS ou la version. "
                "Envisager une politique de sécurité par obscurcissement pour réduire la surface d'attaque."
            ),
        )

    @staticmethod
    def _check_version_disclosure(resp) -> list[str]:
        """Détecte les divulgations de version précise dans les headers."""
        disclosures: list[str] = []
        version_re = re.compile(r'[\d]+\.[\d]+\.[\d]+')

        sensitive_headers = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]
        for h in sensitive_headers:
            val = resp.headers.get(h, "")
            if val and version_re.search(val):
                disclosures.append(f"{h}: {val}")

        return disclosures
