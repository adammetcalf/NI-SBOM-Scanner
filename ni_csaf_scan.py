#!/usr/bin/env python3

from __future__ import annotations

import argparse
import concurrent.futures
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Iterable


NI_CSAF_BASES = (
    "https://raw.githubusercontent.com/ni/product-security-center/main/csaf/advisories",
    "https://raw.githubusercontent.com/ni/product-security-center/main/csaf/vex",
)

USER_AGENT = "ni-csaf-scan/0.1 (+local SBOM vulnerability scanner)"
HTTP_TIMEOUT_S = 20
MAX_WORKERS = 12


PACKAGE_PRODUCT_RULES = (
    (re.compile(r"^ni-labview-\d{4}-core(?:-|$)", re.I), "LabVIEW", "definite"),
    (re.compile(r"^ni-labview-\d{4}-vilib(?:-|$)", re.I), "LabVIEW", "candidate"),
    (re.compile(r"^ni-syscfg-labview-support$", re.I), "System Configuration", "candidate"),
    (re.compile(r"^ni-vision-labview-support$", re.I), "Vision Development Module", "candidate"),
    (re.compile(r"^ni-vision-common-labview-support$", re.I), "Vision", "candidate"),
    (re.compile(r"^ni-rgt-labview-support$", re.I), "Report Generation Toolkit", "candidate"),
)


@dataclass(frozen=True)
class Component:
    name: str
    version: str
    purl: str
    display_name: str
    display_version: str
    ni_version: tuple[int, int, int] | None


@dataclass(frozen=True)
class ProductLeaf:
    product_id: str
    product_name: str
    family: str
    category: str
    version_expression: str
    cpe: str


@dataclass
class Finding:
    component: str
    component_version: str
    display_name: str
    display_version: str
    product_family: str
    match_confidence: str
    status: str
    cve: str
    title: str
    severity: str
    cvss: float | None
    installed_ni_version: str
    csaf_version_expression: str
    csaf_product_name: str
    remediation: str
    advisory_url: str
    source_document: str


def http_get_text(url: str) -> str:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/json,text/plain,*/*",
        },
    )
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_S) as response:
        return response.read().decode("utf-8-sig")


def http_get_json(url: str) -> dict[str, Any]:
    return json.loads(http_get_text(url))


def load_sbom(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8-sig") as f:
        return json.load(f)


def properties_to_dict(component: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for p in component.get("properties", []):
        name = p.get("name")
        value = p.get("value")
        if isinstance(name, str) and isinstance(value, str):
            out[name] = value
    return out


def ni_semver_from_nipkg_version(version: str) -> tuple[int, int, int] | None:

    m = re.match(r"^\s*(\d+)\.(\d+)\.(\d+)", version)
    if not m:
        return None
    return tuple(int(x) for x in m.groups())


def version_str(v: tuple[int, int, int] | None) -> str:
    return ".".join(map(str, v)) if v else "unknown"


def extract_ni_components(sbom: dict[str, Any]) -> list[Component]:
    result: list[Component] = []

    for c in sbom.get("components", []):
        purl = str(c.get("purl") or c.get("bom-ref") or "")
        if not purl.lower().startswith("pkg:nipkg/"):
            continue

        props = properties_to_dict(c)
        version = str(c.get("version") or "")
        result.append(
            Component(
                name=str(c.get("name") or ""),
                version=version,
                purl=purl,
                display_name=props.get("vipm:display-name", ""),
                display_version=props.get("vipm:display-version", ""),
                ni_version=ni_semver_from_nipkg_version(version),
            )
        )

    return result


def fetch_feed_urls(base: str) -> list[str]:

    index_url = base.rstrip("/") + "/index.txt"
    text = http_get_text(index_url)

    urls: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        urls.append(base.rstrip("/") + "/" + urllib.parse.quote(line, safe="/._-"))
    return urls


def fetch_all_csaf_documents() -> list[tuple[str, dict[str, Any]]]:
    urls: list[str] = []
    for base in NI_CSAF_BASES:
        try:
            urls.extend(fetch_feed_urls(base))
        except urllib.error.HTTPError as e:
            # An empty/not-yet-populated VEX feed should not prevent advisory use.
            if e.code != 404:
                raise

    # Remove duplicates while preserving order.
    urls = list(dict.fromkeys(urls))

    docs: list[tuple[str, dict[str, Any]]] = []

    def fetch(url: str) -> tuple[str, dict[str, Any]]:
        return url, http_get_json(url)

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        future_to_url = {pool.submit(fetch, url): url for url in urls}
        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            try:
                docs.append(future.result())
            except Exception as e:
                print(f"WARNING: failed to read CSAF document {url}: {e}", file=sys.stderr)

    return docs


def walk_product_tree(
    branches: Iterable[dict[str, Any]],
    family: str = "",
) -> list[ProductLeaf]:
    leaves: list[ProductLeaf] = []

    for branch in branches:
        category = str(branch.get("category") or "")
        branch_name = str(branch.get("name") or "")
        next_family = family

        if category == "product_name":
            next_family = branch_name

        product = branch.get("product")
        if isinstance(product, dict):
            helper = product.get("product_identification_helper") or {}
            leaves.append(
                ProductLeaf(
                    product_id=str(product.get("product_id") or ""),
                    product_name=str(product.get("name") or ""),
                    family=next_family or str(product.get("name") or ""),
                    category=category,
                    version_expression=branch_name,
                    cpe=str(helper.get("cpe") or ""),
                )
            )

        children = branch.get("branches")
        if isinstance(children, list):
            leaves.extend(walk_product_tree(children, next_family))

    return leaves


def parse_semver3(value: str) -> tuple[int, int, int] | None:
    value = value.strip()
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)(?:\D.*)?$", value)
    if not m:
        return None
    return tuple(int(x) for x in m.groups())


def compare(a: tuple[int, int, int], b: tuple[int, int, int]) -> int:
    return (a > b) - (a < b)


def version_matches_expression(
    installed: tuple[int, int, int] | None,
    category: str,
    expression: str,
) -> bool:
    if installed is None:
        return False

    expression = expression.strip()

    if category == "product_version":
        wanted = parse_semver3(expression)
        return wanted is not None and installed == wanted

    if category != "product_version_range":
        return False

    if expression.startswith("vers:semver/"):
        expression = expression[len("vers:semver/"):]

    clauses = [c.strip() for c in expression.split("|") if c.strip()]
    if not clauses:
        return False

    for clause in clauses:
        m = re.match(r"^(<=|>=|<|>|=)?\s*(\d+\.\d+\.\d+)", clause)
        if not m:
            return False

        op = m.group(1) or "="
        target = parse_semver3(m.group(2))
        if target is None:
            return False

        cmp = compare(installed, target)

        ok = {
            "<": cmp < 0,
            "<=": cmp <= 0,
            ">": cmp > 0,
            ">=": cmp >= 0,
            "=": cmp == 0,
        }[op]

        if not ok:
            return False

    return True


def normalize_name(value: str) -> str:
    value = value.lower()
    value = value.replace("national instruments", "ni")
    value = re.sub(r"\b(32|64)[ -]?bit\b", " ", value)
    value = re.sub(r"\benglish\b", " ", value)
    value = re.sub(r"\blabview\b", "labview", value)
    value = re.sub(r"[^a-z0-9]+", " ", value)
    return " ".join(value.split())


def explicit_product_match(component: Component) -> tuple[str, str] | None:
    for pattern, family, confidence in PACKAGE_PRODUCT_RULES:
        if pattern.search(component.name):
            return family, confidence
    return None


def family_matches_component(component: Component, family: str) -> tuple[bool, str]:
    
    explicit = explicit_product_match(component)
    if explicit:
        explicit_family, confidence = explicit
        if normalize_name(explicit_family) == normalize_name(family):
            return True, confidence
        return False, ""

    comp_text = normalize_name(
        " ".join((component.name, component.display_name))
    )
    fam = normalize_name(family)

    if not fam:
        return False, ""

    # Avoid very short/generic families.
    fam_tokens = fam.split()
    if len(fam) < 5:
        return False, ""

    if fam in comp_text:
        return True, "candidate"

    meaningful = [t for t in fam_tokens if t not in {"ni"}]
    if meaningful and all(t in comp_text.split() for t in meaningful):
        return True, "candidate"

    return False, ""


def product_status_for_id(vuln: dict[str, Any], product_id: str) -> str:
    statuses = vuln.get("product_status") or {}

    precedence = (
        ("known_affected", "AFFECTED"),
        ("under_investigation", "UNDER_INVESTIGATION"),
        ("fixed", "FIXED"),
        ("known_not_affected", "NOT_AFFECTED"),
    )

    for key, label in precedence:
        if product_id in (statuses.get(key) or []):
            return label

    return "UNKNOWN"


def score_for_product(
    vuln: dict[str, Any],
    product_id: str,
) -> tuple[float | None, str]:
    best_score: float | None = None
    best_severity = ""

    for score_entry in vuln.get("scores", []) or []:
        products = score_entry.get("products") or []
        if products and product_id not in products:
            continue

        for key in ("cvss_v4", "cvss_v3", "cvss_v2"):
            cvss = score_entry.get(key)
            if not isinstance(cvss, dict):
                continue

            score = cvss.get("baseScore")
            severity = str(cvss.get("baseSeverity") or "")

            try:
                numeric = float(score)
            except (TypeError, ValueError):
                continue

            if best_score is None or numeric > best_score:
                best_score = numeric
                best_severity = severity

    return best_score, best_severity


def remediation_for_product(vuln: dict[str, Any], product_id: str) -> str:
    texts: list[str] = []

    for remediation in vuln.get("remediations", []) or []:
        product_ids = remediation.get("product_ids") or []
        if product_ids and product_id not in product_ids:
            continue

        details = str(remediation.get("details") or "").strip()
        if details:
            texts.append(details)

    return " | ".join(dict.fromkeys(texts))


def advisory_url(doc: dict[str, Any]) -> str:
    for ref in (doc.get("document") or {}).get("references", []) or []:
        if ref.get("category") == "external" and ref.get("url"):
            return str(ref["url"])
    return ""


def scan(
    components: list[Component],
    docs: list[tuple[str, dict[str, Any]]],
) -> tuple[list[Finding], dict[str, list[str]]]:
    findings: list[Finding] = []
    candidate_families: dict[str, set[str]] = {c.name: set() for c in components}

    for source_url, doc in docs:
        tree = doc.get("product_tree") or {}
        leaves = walk_product_tree(tree.get("branches") or [])
        if not leaves:
            continue

        vulnerabilities = doc.get("vulnerabilities") or []
        if not vulnerabilities:
            continue

        for component in components:
            for leaf in leaves:
                matched, confidence = family_matches_component(component, leaf.family)
                if not matched:
                    continue

                candidate_families[component.name].add(leaf.family)

                if not version_matches_expression(
                    component.ni_version,
                    leaf.category,
                    leaf.version_expression,
                ):
                    continue

                for vuln in vulnerabilities:
                    status = product_status_for_id(vuln, leaf.product_id)
                    if status == "UNKNOWN":
                        continue

                    cve = str(vuln.get("cve") or "")
                    title = str(
                        vuln.get("title")
                        or (doc.get("document") or {}).get("title")
                        or ""
                    )
                    cvss, severity = score_for_product(vuln, leaf.product_id)

                    findings.append(
                        Finding(
                            component=component.name,
                            component_version=component.version,
                            display_name=component.display_name,
                            display_version=component.display_version,
                            product_family=leaf.family,
                            match_confidence=confidence,
                            status=status,
                            cve=cve,
                            title=title,
                            severity=severity,
                            cvss=cvss,
                            installed_ni_version=version_str(component.ni_version),
                            csaf_version_expression=leaf.version_expression,
                            csaf_product_name=leaf.product_name,
                            remediation=remediation_for_product(vuln, leaf.product_id),
                            advisory_url=advisory_url(doc),
                            source_document=source_url,
                        )
                    )

    # Deduplicate identical matches that can occur across overlapping tree paths.
    unique: dict[tuple[Any, ...], Finding] = {}
    for f in findings:
        key = (
            f.component,
            f.product_family,
            f.status,
            f.cve,
            f.csaf_version_expression,
        )
        unique[key] = f

    sorted_findings = sorted(
        unique.values(),
        key=lambda f: (
            f.component.lower(),
            0 if f.status == "AFFECTED" else 1,
            f.cve,
        ),
    )

    return sorted_findings, {
        name: sorted(values)
        for name, values in candidate_families.items()
    }


def print_report(
    components: list[Component],
    findings: list[Finding],
    candidate_families: dict[str, list[str]],
    show_candidates: bool,
) -> None:
    definite_affected = [
        f for f in findings
        if f.status == "AFFECTED" and f.match_confidence == "definite"
    ]
    candidate_affected = [
        f for f in findings
        if f.status == "AFFECTED" and f.match_confidence != "definite"
    ]

    print()
    print("NI CSAF SBOM SCAN")
    print("=" * 78)
    print(f"NI/NIPM components:           {len(components)}")
    print(f"Definite affected findings:  {len(definite_affected)}")
    print(f"Candidate affected findings: {len(candidate_affected)}")
    print()

    for component in components:
        component_findings = [f for f in findings if f.component == component.name]

        print("-" * 78)
        print(component.name)
        print(f"  NIPM version:    {component.version}")
        print(f"  NI version:      {version_str(component.ni_version)}")
        if component.display_name:
            print(f"  Display name:    {component.display_name}")
        if component.display_version:
            print(f"  Display version: {component.display_version}")

        if not component_findings:
            families = candidate_families.get(component.name, [])
            if families:
                print(f"  Result:          No CSAF version range matched ({', '.join(families)})")
            else:
                print("  Result:          UNRESOLVED - no trustworthy CSAF product mapping")
            continue

        visible = [
            f for f in component_findings
            if f.match_confidence == "definite" or show_candidates
        ]

        if not visible:
            print(
                "  Result:          RELATED/CANDIDATE matches exist "
                "(use --show-candidates)"
            )
            continue

        for f in visible:
            marker = "!" if f.status == "AFFECTED" else "-"
            cvss = f"{f.cvss:.1f}" if f.cvss is not None else "n/a"
            severity = f.severity or "n/a"

            print(
                f"  {marker} {f.status:<19} {f.cve or '(no CVE)':<18} "
                f"{severity:<9} CVSS {cvss}"
            )
            print(
                f"    Product:       {f.product_family} "
                f"[{f.match_confidence}]"
            )
            print(f"    CSAF range:    {f.csaf_version_expression}")
            if f.remediation:
                print(f"    Remediation:   {f.remediation}")
            if f.advisory_url:
                print(f"    Advisory:      {f.advisory_url}")

    print()
    print("=" * 78)
    if definite_affected:
        print("RESULT: FAIL - definite NI vulnerabilities found.")
    elif candidate_affected:
        print(
            "RESULT: REVIEW - no definite vulnerability found, "
            "but candidate NI product matches are affected."
        )
    else:
        print("RESULT: PASS - no definite affected NI component found.")
    print()


def write_json_report(
    path: Path,
    components: list[Component],
    findings: list[Finding],
    candidate_families: dict[str, list[str]],
) -> None:
    output = {
        "components": [
            {
                **asdict(c),
                "ni_version": version_str(c.ni_version),
            }
            for c in components
        ],
        "findings": [asdict(f) for f in findings],
        "candidate_families": candidate_families,
    }

    path.write_text(json.dumps(output, indent=2), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan CycloneDX NI/NIPM components against NI public CSAF."
    )
    parser.add_argument("sbom", type=Path, help="CycloneDX JSON SBOM")
    parser.add_argument(
        "--json",
        dest="json_report",
        type=Path,
        help="Also write a machine-readable JSON report",
    )
    parser.add_argument(
        "--show-candidates",
        action="store_true",
        help="Show related/candidate product matches as well as definite matches",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    try:
        sbom = load_sbom(args.sbom)
        components = extract_ni_components(sbom)

        if not components:
            print("No pkg:nipkg components found in the SBOM.")
            return 0

        print(f"Found {len(components)} NI/NIPM component(s).")
        print("Reading current NI CSAF feeds...")

        docs = fetch_all_csaf_documents()
        print(f"Loaded {len(docs)} NI CSAF document(s).")

        findings, candidate_families = scan(components, docs)
        print_report(
            components,
            findings,
            candidate_families,
            args.show_candidates,
        )

        if args.json_report:
            write_json_report(
                args.json_report,
                components,
                findings,
                candidate_families,
            )
            print(f"JSON report written to: {args.json_report}")

        definite_affected = any(
            f.status == "AFFECTED" and f.match_confidence == "definite"
            for f in findings
        )
        return 1 if definite_affected else 0

    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
        urllib.error.URLError,
    ) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
