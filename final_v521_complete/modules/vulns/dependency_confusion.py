"""
PhantomScan — Dependency Confusion Scanner  v1.0
=================================================
Détecte les artefacts exposés permettant d'identifier des noms de packages internes
susceptibles d'être ciblés par une attaque de confusion de dépendances
(Dependency Confusion / Namespace Confusion).

Contexte :
  En 2021, Alex Birsan a démontré qu'en publiant un paquet public portant le même
  nom qu'un paquet interne (npm, PyPI, RubyGems, Maven, NuGet…) avec un numéro de
  version supérieur, il est possible de forcer des systèmes CI/CD à télécharger et
  exécuter du code malveillant. Cela vaut généralement entre $1 000 et $30 000 en BB.

Vecteurs de découverte couverts :
  1. package.json / package-lock.json exposés → noms de scopes privés (@company/*)
  2. requirements.txt / Pipfile / pyproject.toml → packages internes (noms courts,
     préfixes d'entreprise, non trouvables sur PyPI)
  3. pom.xml / build.gradle exposés → groupIds/artifactIds internes
  4. .npmrc / pip.conf / nuget.config exposés → registries privés configurés
  5. go.mod exposé → modules Go internes (domaine interne, replace directives)
  6. composer.json exposé → repositories Composer privés
  7. Gemfile exposé → source gems privées
  8. Cargo.toml exposé → crates.io private alternatives (git sources)
  9. nuget.config / *.csproj exposés → NuGet privé
 10. yarn.lock / pnpm-lock.yaml → résolution vers registries privés

Findings émis :
  HIGH    — package.json/requirements exposé avec noms de packages internes identifiés
  HIGH    — fichier de config registry privé exposé (.npmrc, pip.conf…)
  MEDIUM  — lockfile exposé révélant des packages potentiellement internes
  LOW     — pom.xml / build.gradle exposé (nécessite analyse manuelle)
  INFO    — fichier de dépendances trouvé (sans packages suspects identifiés)
"""

from __future__ import annotations

import json
import re
from typing import AsyncIterator
from urllib.parse import urlparse, urljoin

from phantomscan.config import PhantomConfig
from phantomscan.core.requester import Requester, ProbeRequest
from phantomscan.core.heuristic import HeuristicEngine
from phantomscan.output.reporter import Finding, Severity
from phantomscan.core.scanner_mixin import ScannerMixin


# ── Fichiers à sonder ────────────────────────────────────────────────────────

DEPENDENCY_FILES: list[tuple[str, str]] = [
    # (path, label)
    ("/package.json",           "npm package.json"),
    ("/package-lock.json",      "npm lockfile"),
    ("/yarn.lock",              "Yarn lockfile"),
    ("/pnpm-lock.yaml",         "pnpm lockfile"),
    ("/requirements.txt",       "Python requirements"),
    ("/requirements-dev.txt",   "Python dev requirements"),
    ("/Pipfile",                "Pipfile"),
    ("/Pipfile.lock",           "Pipfile.lock"),
    ("/pyproject.toml",         "pyproject.toml"),
    ("/setup.py",               "setup.py"),
    ("/pom.xml",                "Maven pom.xml"),
    ("/build.gradle",           "Gradle build"),
    ("/build.gradle.kts",       "Gradle Kotlin DSL"),
    ("/settings.gradle",        "Gradle settings"),
    ("/go.mod",                 "Go module"),
    ("/go.sum",                 "Go sum"),
    ("/Gemfile",                "Ruby Gemfile"),
    ("/Gemfile.lock",           "Ruby Gemfile.lock"),
    ("/Cargo.toml",             "Rust Cargo.toml"),
    ("/composer.json",          "PHP Composer"),
    ("/composer.lock",          "PHP Composer lock"),
    ("/nuget.config",           "NuGet config"),
    ("/.npmrc",                 ".npmrc (registry config)"),
    ("/.yarnrc",                ".yarnrc (registry config)"),
    ("/.yarnrc.yml",            ".yarnrc.yml (registry config)"),
    ("/pip.conf",               "pip.conf (registry config)"),
    ("/pip.ini",                "pip.ini (registry config)"),
    ("/.pip/pip.conf",          ".pip/pip.conf"),
]

# Patterns révélant des noms de packages potentiellement internes
_PRIVATE_SCOPE_RE = re.compile(r"\"(@[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+)\"", re.I)
_PRIVATE_REGISTRY_URL_RE = re.compile(
    r"(https?://[^\s\"'<>]+(?:artifactory|nexus|jfrog|packagecloud|gemfury|"
    r"myget|proget|verdaccio|npm\.corp|npm\.internal|pypi\.internal|"
    r"packages\.internal)[^\s\"'<>]*)",
    re.I,
)
_PRIVATE_NPM_REGISTRY_RE = re.compile(
    r"(?:registry\s*=\s*|\"registry\"\s*:\s*\")(https?://[^\"'\s]+)", re.I
)
_REPLACE_DIRECTIVE_RE = re.compile(
    r"replace\s+([^\s]+)\s+=>\s+([^\s]+)", re.I  # Go replace directives → internal forks
)
_INTERNAL_DOMAIN_RE = re.compile(
    r"(?:git|https?|ssh)://[^/\s\"']+\.(?:internal|corp|local|intranet|lan)[/\s\"']",
    re.I,
)

# Préfixes souvent utilisés pour les packages internes (heuristique)
_INTERNAL_PACKAGE_HINTS = re.compile(
    r"\"((?:internal|private|lib|core|shared|common|platform|infra|backend|"
    r"frontend|base)-[a-zA-Z0-9_-]+)\"",
    re.I,
)


class DependencyConfusionScanner(ScannerMixin):

    def __init__(self, req: Requester, heuristic: HeuristicEngine, cfg: PhantomConfig) -> None:
        self._req = req
        self._heuristic = heuristic
        self._cfg = cfg

    async def run(self, target: str) -> AsyncIterator[Finding]:
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path, label in DEPENDENCY_FILES:
            url = base + path
            async for f in self._probe_file(url, label):
                yield f

    async def _probe_file(self, url: str, label: str) -> AsyncIterator[Finding]:
        resp = await self._req.send(ProbeRequest(method="GET", url=url))
        if resp is None:
            return
        if resp.status_code != 200:
            return

        body = (resp.body or b"").decode("utf-8", errors="replace")
        if len(body) < 10:
            return

        content_type = resp.headers.get("content-type", "")

        # ── Registry configs → HIGH directement ──────────────────────────────
        if any(x in url for x in (".npmrc", ".yarnrc", "pip.conf", "pip.ini", "nuget.config")):
            registry_match = _PRIVATE_REGISTRY_URL_RE.search(body) or \
                             _PRIVATE_NPM_REGISTRY_RE.search(body)
            if registry_match:
                registry_url = registry_match.group(1)
                # v5.20 — entropy check sur l'URL registry
                if not self.sig_entropy_ok(registry_url, body, min_entropy=2.0):
                    return  # signature trop générique → FP
                yield Finding(
                    title=f"Dependency Confusion — Registry privé exposé ({label})",
                    url=url,
                    severity=Severity.HIGH,
                    description=(
                        f"Le fichier `{label}` est accessible publiquement et référence "
                        f"un registry privé : `{registry_url}`.\n\n"
                        "Un attaquant peut identifier les packages internes hébergés sur ce registry "
                        "et publier des versions malveillantes portant le même nom sur le registry public "
                        "(npm, PyPI…) avec un numéro de version supérieur.\n\n"
                        f"Contenu partiel :\n{body[:400]}"
                    ),
                    param=label,
                    evidence=registry_url,
                    remediation=(
                        "Retirer le fichier de configuration du registry de l'arborescence web publique. "
                        "Utiliser un scope npm privé (@company) avec un proxy registry qui préfère toujours "
                        "le registry interne pour les packages scopés. "
                        "Configurer 'lockfileVersion' et des checksums pour les lockfiles."
                    ),
                )
            else:
                yield Finding(
                    title=f"Dependency Confusion — Fichier config registry exposé ({label})",
                    url=url,
                    severity=Severity.MEDIUM,
                    description=(
                        f"Le fichier `{label}` est accessible publiquement. "
                        "Il peut contenir des informations sur des registries privés "
                        "ou des tokens d'authentification.\n\n"
                        f"Contenu partiel :\n{body[:300]}"
                    ),
                    param=label,
                    evidence=body[:200],
                    remediation=(
                        "Retirer les fichiers de configuration de registry du répertoire public. "
                        "Ne jamais inclure de tokens dans ces fichiers; utiliser des variables d'environnement."
                    ),
                )
            return

        # ── package.json — le plus intéressant ───────────────────────────────
        if "package.json" in url and "lock" not in url:
            private_scopes = _PRIVATE_SCOPE_RE.findall(body)
            internal_names = _INTERNAL_PACKAGE_HINTS.findall(body)
            registry_urls = _PRIVATE_REGISTRY_URL_RE.findall(body)

            suspects = list(set(private_scopes + internal_names))

            if private_scopes or registry_urls:
                sev = Severity.HIGH
                title = "Dependency Confusion — package.json expose des packages scopés privés"
                desc = (
                    f"Le fichier `package.json` est accessible et référence "
                    f"{len(private_scopes)} package(s) avec scope privé :\n"
                    + "\n".join(f"  • `{s}`" for s in private_scopes[:20])
                )
                if registry_urls:
                    desc += f"\n\nRegistry privé détecté : `{registry_urls[0]}`"
            elif internal_names:
                sev = Severity.MEDIUM
                title = "Dependency Confusion — package.json expose des noms de packages potentiellement internes"
                desc = (
                    f"Le fichier `package.json` est accessible et contient des noms de packages "
                    f"qui pourraient être internes :\n"
                    + "\n".join(f"  • `{s}`" for s in internal_names[:20])
                )
            else:
                yield Finding(
                    title="Dependency Confusion — package.json exposé (audit manuel recommandé)",
                    url=url,
                    severity=Severity.INFO,
                    description=f"Le fichier `package.json` est accessible publiquement.\n\n{body[:300]}",
                    param=label,
                    evidence=body[:200],
                    remediation="Vérifier que package.json ne contient pas de packages internes.",
                )
                return

            desc += (
                f"\n\nUn attaquant peut publier un paquet malveillant portant ces noms sur npm public "
                "avec une version supérieure (ex: 9999.0.0). Lors du prochain `npm install`, "
                "les systèmes CI/CD téléchargeront le paquet malveillant."
            )
            yield Finding(
                title=title,
                url=url,
                severity=sev,
                description=desc,
                param="package names",
                evidence=", ".join(suspects[:10]),
                remediation=(
                    "1. Publier immédiatement des packages placeholder vides sur npm public "
                    "   pour chaque nom de package interne détecté, afin de prévenir la squatting.\n"
                    "2. Utiliser des scopes npm (@company) et configurer le registre pour préférer "
                    "   le registre interne pour ces scopes.\n"
                    "3. Utiliser `npm config set @company:registry https://registry.interne/` "
                    "   et valider avec `--prefer-dedupe`.\n"
                    "4. Retirer le package.json du répertoire web public."
                ),
            )
            return

        # ── requirements.txt ─────────────────────────────────────────────────
        if "requirements" in url or "Pipfile" in url or "pyproject" in url:
            lines = [l.strip() for l in body.splitlines() if l.strip() and not l.startswith("#")]
            registry_urls = _PRIVATE_REGISTRY_URL_RE.findall(body)
            internal_domain = _INTERNAL_DOMAIN_RE.search(body)

            # Heuristique : packages sans version pinning + noms courts → suspects
            unpinned = []
            internal_hints = []
            for line in lines:
                pkg_name = re.split(r"[>=<!;\[]", line)[0].strip()
                if not pkg_name:
                    continue
                if any(x in pkg_name.lower() for x in [
                    "internal", "private", "corp", "company", "core-", "lib-", "shared-", "platform-"
                ]):
                    internal_hints.append(pkg_name)
                elif "==" not in line and len(pkg_name) > 3:
                    unpinned.append(pkg_name)

            if registry_urls or internal_domain:
                yield Finding(
                    title="Dependency Confusion — Requirements expose un registry Python privé",
                    url=url,
                    severity=Severity.HIGH,
                    description=(
                        f"Le fichier `{label}` est exposé et référence un registry privé :\n"
                        + (f"  Registry URL : `{registry_urls[0]}`\n" if registry_urls else "")
                        + (f"  Dépôt interne : `{internal_domain.group(0)}`\n" if internal_domain else "")
                        + f"\nExtrait :\n{body[:400]}"
                    ),
                    param=label,
                    evidence=(registry_urls[0] if registry_urls else internal_domain.group(0) if internal_domain else ""),
                    remediation=(
                        "Retirer le fichier requirements du répertoire public. "
                        "Utiliser un proxy PyPI privé avec une résolution prioritaire des packages internes. "
                        "Publier des placeholder packages sur PyPI pour les noms internes."
                    ),
                )
            elif internal_hints:
                yield Finding(
                    title="Dependency Confusion — Requirements expose des packages Python potentiellement internes",
                    url=url,
                    severity=Severity.MEDIUM,
                    description=(
                        f"Le fichier `{label}` est exposé et contient des noms de packages "
                        f"qui pourraient être internes : {', '.join(internal_hints[:10])}\n\n"
                        f"Extrait :\n{body[:400]}"
                    ),
                    param=label,
                    evidence=", ".join(internal_hints[:5]),
                    remediation=(
                        "Vérifier que chaque package listé existe sur PyPI public. "
                        "Si des packages internes sont présents, publier des placeholders. "
                        "Retirer le fichier du répertoire web public."
                    ),
                )
            else:
                yield Finding(
                    title=f"Dependency Confusion — {label} exposé (audit recommandé)",
                    url=url,
                    severity=Severity.INFO,
                    description=f"`{label}` accessible publiquement.\n\n{body[:300]}",
                    param=label,
                    evidence=body[:150],
                    remediation="Vérifier l'absence de packages internes dans ce fichier.",
                )
            return

        # ── go.mod ────────────────────────────────────────────────────────────
        if "go.mod" in url or "go.sum" in url:
            replace_directives = _REPLACE_DIRECTIVE_RE.findall(body)
            internal_domain = _INTERNAL_DOMAIN_RE.search(body)

            if replace_directives or internal_domain:
                yield Finding(
                    title="Dependency Confusion — go.mod expose des modules Go internes",
                    url=url,
                    severity=Severity.HIGH,
                    description=(
                        f"Le fichier `go.mod` est accessible et contient des références à des modules internes :\n"
                        + (f"  Directives replace : {replace_directives[:5]}\n" if replace_directives else "")
                        + (f"  Domaine interne : {internal_domain.group(0)}\n" if internal_domain else "")
                        + f"\nExtrait :\n{body[:400]}"
                    ),
                    param="go.mod",
                    evidence=body[:200],
                    remediation=(
                        "Retirer go.mod du répertoire web public. "
                        "Utiliser GONOSUMCHECK et GONOSUMDB pour les modules internes. "
                        "Configurer GOPROXY avec un proxy interne prioritaire."
                    ),
                )
            else:
                yield Finding(
                    title="Dependency Confusion — go.mod exposé",
                    url=url,
                    severity=Severity.INFO,
                    description=f"Le fichier `go.mod` est accessible publiquement.\n\n{body[:300]}",
                    param="go.mod",
                    evidence=body[:150],
                    remediation="Retirer go.mod du répertoire web public.",
                )
            return

        # ── Maven / Gradle ────────────────────────────────────────────────────
        if any(x in url for x in ("pom.xml", "build.gradle", "settings.gradle")):
            internal_domain = _INTERNAL_DOMAIN_RE.search(body)
            private_registry = _PRIVATE_REGISTRY_URL_RE.search(body)

            sev = Severity.HIGH if (internal_domain or private_registry) else Severity.LOW
            evidence = ""
            if private_registry:
                evidence = private_registry.group(1)
            elif internal_domain:
                evidence = internal_domain.group(0)

            yield Finding(
                title=f"Dependency Confusion — {label} exposé",
                url=url,
                severity=sev,
                description=(
                    f"Le fichier `{label}` est accessible publiquement.\n"
                    + (f"Registry interne détecté : `{evidence}`\n" if evidence else "")
                    + f"\nExtrait :\n{body[:400]}"
                ),
                param=label,
                evidence=evidence or body[:100],
                remediation=(
                    "Retirer les fichiers de build du répertoire web public. "
                    "Si un Nexus/Artifactory interne est référencé, vérifier que les "
                    "artifactIds ne sont pas squattables sur Maven Central."
                ),
            )
            return

        # ── Fallback générique ────────────────────────────────────────────────
        private_registry = _PRIVATE_REGISTRY_URL_RE.search(body)
        if private_registry:
            yield Finding(
                title=f"Dependency Confusion — Registry privé référencé dans {label}",
                url=url,
                severity=Severity.MEDIUM,
                description=(
                    f"Le fichier `{label}` est accessible et référence un registry privé :\n"
                    f"`{private_registry.group(1)}`\n\n{body[:300]}"
                ),
                param=label,
                evidence=private_registry.group(1),
                remediation="Retirer le fichier du répertoire public et auditer les packages internes.",
            )
        else:
            yield Finding(
                title=f"Dependency Confusion — {label} exposé publiquement",
                url=url,
                severity=Severity.INFO,
                description=f"`{label}` accessible publiquement, audit manuel recommandé.\n\n{body[:250]}",
                param=label,
                evidence=body[:100],
                remediation="Vérifier l'absence de packages/registries internes.",
            )
