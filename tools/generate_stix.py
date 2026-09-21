#!/usr/bin/env python3
"""
generate_stix.py — Generate a STIX 2.1 bundle from current-list-meta.csv

Produces a STIX 2.1 bundle containing:
  - One Identity object (the chrome-mal-ids project)
  - One Malware object per unique campaign/threat cluster
  - One Indicator object per extension ID (with Chrome Web Store URL pattern)
  - Relationship objects linking each Indicator to its Malware object
  - One Report object wrapping the full bundle

Indicators whose TPCI Stage 5A analysis disagreed with the contributing
source's classification carry the label `tpci:classification-disputed` and
say so in their description. They are published, not withheld — see
is_disputed().

Output: chrome-mal-ids-stix.json (in the repo root by default)

Compatible with:
  - MISP (File → Import → STIX 2.1)
  - OpenCTI
  - Any TAXII 2.1 server
  - Threat intelligence platforms supporting STIX 2.1

Usage:
    python3 generate_stix.py [--csv PATH] [--out PATH] [--pretty] [--dry-run]

Requirements:
    pip install stix2 --break-system-packages
"""

import argparse
import csv
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

try:
    import stix2
except ImportError:
    sys.exit("stix2 not installed. Run: pip install stix2 --break-system-packages")

# ── Config ────────────────────────────────────────────────────────────────────

SCRIPT_DIR   = Path(__file__).parent
# Check multiple possible locations for the CSV
_locations   = [
    SCRIPT_DIR / "data" / "current-list-meta.csv",   # server: /opt/chrome-mal-ids/repo/
    SCRIPT_DIR / "current-list-meta.csv",             # dev: same dir as script
    Path("/opt/chrome-mal-ids/repo/data/current-list-meta.csv"),  # absolute fallback
]
_repo_csv    = next((p for p in _locations if p.exists()), _locations[0])
DEFAULT_CSV  = _repo_csv
DEFAULT_OUT  = (
    Path("/opt/chrome-mal-ids/repo/formats/chrome-mal-ids-stix.json")
    if Path("/opt/chrome-mal-ids/repo/formats").exists()
    else SCRIPT_DIR.parent / "formats" / "chrome-mal-ids-stix.json"
)

PROJECT_URL  = "https://github.com/The-Privacy-Commons-Institute/chrome-mal-ids"
STORE_URL    = "https://chromewebstore.google.com/detail/{ext_id}"
EDGE_URL     = "https://microsoftedge.microsoft.com/addons/detail/{ext_id}"

DISPUTED_LABEL = "tpci:classification-disputed"

# Map our threat types to STIX malware-types vocabulary
THREAT_TYPE_MAP = {
    "spyware":            "spyware",
    "data-theft":         "spyware",
    "browser-hijack":     "adware",
    "adware":             "adware",
    "click-fraud":        "adware",
    "credential-theft":   "credential-stealer",
    "session-hijack":     "credential-stealer",
    "cryptojacking":      "coin-miner",
    "ransomware":         "ransomware",
    "backdoor":           "backdoor",
    "trojan":             "trojan",
    "rootkit":            "rootkit",
}

# ── Campaign extraction ────────────────────────────────────────────────────────
#
# NOTES values that are a CLASSIFICATION or a status remark, not a campaign.
#
# Delta-feed entries often carry a bare category as their entire NOTES —
# "Adware", "Policy Violation", "Search Hijacking". The previous extractor read
# that leading fragment as a campaign name, so the bundle gained Malware objects
# named after threat categories rather than campaigns.
#
# Kept byte-identical to generate_stats.py's implementation. Four copies of this
# logic exist (here, generate_stats.py, generate_misp.py, index.html); they
# disagreed for months. If you change one, change all four.
NON_CAMPAIGN_NOTES = {
    "adware", "malware", "spyware",
    "policy violation",
    "search hijacking", "search-hijacker",
    "bundling unwanted software",
    "potentially unwanted software",
    "critical vulnerability",
    "in store but not whitelisted",
    "in store but suspicious",
    "unknown",
}

NON_CAMPAIGN_PREFIXES = (
    "stub entry imported from",
    "stage 5a static analysis",
    "the reporter did not correlate",
    "these extensions have not all been confirmed",
    "the extension was",
    "source:",
)

# Leading quote characters must be stripped before prefix matching — a note
# opening with a typographic quote does not match a bare startswith() test.
LEADING_PUNCT = "“”‘’\"' \t"

UNATTRIBUTED = "Unattributed"


def parse_date(date_str: str) -> datetime | None:
    """Parse YYYY-MM-DD to timezone-aware datetime, return None if invalid."""
    if not date_str or date_str.upper() in ("UNKNOWN", "MISSING", ""):
        return None
    try:
        return datetime.strptime(date_str.strip(), "%Y-%m-%d").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        return None


def threat_types_to_stix(threat_str: str) -> list[str]:
    """Convert our threat-type field to STIX malware-type vocabulary entries."""
    if not threat_str or threat_str.upper() in ("UNKNOWN", ""):
        return ["malware"]
    types = []
    for t in threat_str.lower().split(","):
        t = t.strip()
        stix_type = THREAT_TYPE_MAP.get(t)
        if stix_type and stix_type not in types:
            types.append(stix_type)
    return types or ["malware"]


def extract_campaign(notes: str) -> str | None:
    """
    Return the campaign label for an entry, or None when the note carries no
    campaign attribution.

    None is distinct from "Unknown": it means the entry was never attributed
    to a campaign, rather than belonging to one we cannot name.
    """
    n = (notes or "").strip().lstrip(LEADING_PUNCT)
    if not n:
        return None
    low = n.lower()
    if low in NON_CAMPAIGN_NOTES:
        return None
    if any(low.startswith(p) for p in NON_CAMPAIGN_PREFIXES):
        return None

    # Named-campaign pattern: "...clusters: Phoenix Invicta and ...".
    m_named = re.search(
        r'(?:campaign|cluster|group)s?:\s*([A-Z][^,.(]{3,50}?)'
        r'(?:\s*(?:extensions?|and\s|,|\.))', n, re.I)
    if m_named:
        c = m_named.group(1).strip()
        if c.lower() not in NON_CAMPAIGN_NOTES:
            return c

    # A period only ends the label when followed by whitespace or end of
    # string — otherwise the dot in a domain truncates campaigns named after
    # their C2 infrastructure ("Palant serasearchtop.com campaign").
    m = re.match(r'^([A-Z][^(]{3,60}?)(?:\s*\((?!\s)|\.(?=\s|$)|\s*$)', n)
    if m:
        c = m.group(1).strip().rstrip(".")
        if len(c.split()) <= 8:
            return None if c.lower() in NON_CAMPAIGN_NOTES else c
    head = n.split(".")[0].strip()
    if len(head) > 60:
        cut = head[:60].rsplit(" ", 1)[0].rstrip(" ,;:—-")
        head = (cut or head[:60]) + "…"
    if not head or head.lower().rstrip("…") in NON_CAMPAIGN_NOTES:
        return None
    return head


def unattributed_label(row: dict) -> str:
    """
    Malware-object label for an entry with no campaign attribution.

    Sub-grouped by threat type so the bundle carries something meaningful
    rather than one undifferentiated "Unattributed" object. Components are
    sorted, which also collapses the ordering variants the classifier emits —
    "spyware,data-theft" and "data-theft,spyware" are one group, not two.
    """
    raw   = (row.get("THREAT-TYPE") or "").strip()
    parts = sorted({t.strip().lower() for t in raw.split(",") if t.strip()})
    parts = [p for p in parts if p and p != "unknown"]
    if not parts:
        return f"{UNATTRIBUTED}: unclassified"
    return f"{UNATTRIBUTED}: " + ", ".join(parts)


def is_disputed(row: dict) -> bool:
    """
    True when TPCI's own Stage 5A analysis found nothing above the scoring
    threshold while the contributing source classified the extension as
    malicious.

    A recorded disagreement between two methods — NOT a finding that the
    extension is safe. A below-threshold score means the scanner found nothing
    under the scoring logic in force at the time; static analysis can be
    evaded, and extensions change after they are analyzed. The indicator is
    published either way, with the source's classification intact.
    """
    return (row.get("TPCI-BEHAVIORAL") or "").strip() == "below-threshold"


def load_csv(csv_path: Path, verified_only: bool = True) -> list[dict]:
    """Load and validate the meta CSV, filtering unverified delta imports."""
    if not csv_path.exists():
        sys.exit(f"CSV not found: {csv_path}")
    rows   = []
    skipped = 0
    with open(csv_path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            ext_id = row.get("EXTID", "").strip().lower()
            if not ext_id or ext_id == "unknown":
                continue
            if verified_only:
                method      = row.get("CONTRIB-METHOD", "").strip()
                tpci_verify = row.get("TPCI-VERIFY", "0").strip()
                confirm_mal = row.get("CONFIRM-MAL", "1").strip()
                is_delta    = "Delta_Import" in method
                is_verified = tpci_verify in ("1","2","3","4","5")
                is_google   = confirm_mal in ("2","3")
                if is_delta and not is_verified and not is_google:
                    skipped += 1
                    continue
            rows.append(row)
    if verified_only and skipped:
        print(f"  [filter] Excluded {skipped} unverified delta import entries")
    return rows


# ── STIX object builders ───────────────────────────────────────────────────────

def build_identity() -> stix2.Identity:
    return stix2.Identity(
        name="Malicious Chrome Extension IOC Database",
        identity_class="organization",
        description=(
            "Community-maintained database of malicious Chrome and Edge browser "
            "extension indicators of compromise (IOCs). "
            f"See {PROJECT_URL} for details."
        ),
        contact_information=PROJECT_URL,
    )


def build_malware(campaign: str, threat_types: list[str],
                  first_seen: datetime | None,
                  identity_id: str) -> stix2.Malware:
    kwargs = dict(
        name=campaign,
        malware_types=threat_types,
        is_family=True,
        description=f"Malicious browser extension campaign: {campaign}",
        created_by_ref=identity_id,
        external_references=[
            stix2.ExternalReference(
                source_name="Malicious Chrome Extension IOC Database",
                url=PROJECT_URL,
            )
        ],
    )
    if first_seen:
        kwargs["first_seen"] = first_seen
    return stix2.Malware(**kwargs)


def build_indicator(row: dict, identity_id: str,
                    malware_obj: stix2.Malware) -> stix2.Indicator:
    ext_id   = row["EXTID"].strip().lower()
    ext_name = row.get("EXTID-NAME", "Unknown Extension").strip()
    browser  = row.get("BROWSER", "chrome").strip().lower()
    notes    = row.get("NOTES", "").strip()
    source   = row.get("SOURCE", "").strip()
    article  = row.get("ARTICLE", "").strip()
    date_dis = parse_date(row.get("DATE-DIS", ""))
    still_active = row.get("STILL-ACTIVE", "0").strip()
    disputed = is_disputed(row)

    # STIX pattern — match the extension ID as a URL in the appropriate store
    if browser == "edge":
        store_url = EDGE_URL.format(ext_id=ext_id)
    else:
        store_url = STORE_URL.format(ext_id=ext_id)

    # Use a domain-name pattern since STIX doesn't have a browser-extension SCO
    # We encode the extension ID in the value for easy searching
    pattern = f"[url:value = '{store_url}']"

    # Build description
    desc_parts = [f"Malicious browser extension: {ext_name} ({ext_id})"]
    if notes and notes.upper() != "UNKNOWN":
        desc_parts.append(notes[:500])
    if still_active == "1":
        desc_parts.append("⚠ Still active in browser store at time of reporting.")
    if disputed:
        desc_parts.append(
            "⚠ Classification disputed: TPCI Stage 5A static analysis found no "
            "indicators above its scoring threshold. The contributing source's "
            "classification is retained and this indicator is published; a "
            "below-threshold result is not a safety verification."
        )
    description = " ".join(desc_parts)

    # External references
    ext_refs = [
        stix2.ExternalReference(
            source_name="Chrome Web Store" if browser != "edge" else "Edge Add-ons",
            url=store_url,
            external_id=ext_id,
        )
    ]
    if source and source != article:
        ext_refs.append(stix2.ExternalReference(
            source_name="Original Research",
            url=source,
        ))
    if article:
        ext_refs.append(stix2.ExternalReference(
            source_name="Article",
            url=article,
        ))

    labels = [f"ext-id:{ext_id}", f"browser:{browser}"]
    if disputed:
        labels.append(DISPUTED_LABEL)

    kwargs = dict(
        name=f"Malicious Extension: {ext_name}",
        indicator_types=["malicious-activity"],
        pattern=pattern,
        pattern_type="stix",
        valid_from=date_dis or malware_obj.get("first_seen",
                   datetime.now(timezone.utc)),
        description=description,
        created_by_ref=identity_id,
        external_references=ext_refs,
        labels=labels,
    )

    # Add kill chain phase
    kwargs["kill_chain_phases"] = [
        stix2.KillChainPhase(
            kill_chain_name="mitre-attack",
            phase_name="collection" if "data-theft" in row.get("THREAT-TYPE","")
                       else "impact",
        )
    ]

    return stix2.Indicator(**kwargs)


def build_relationship(indicator: stix2.Indicator,
                       malware: stix2.Malware,
                       identity_id: str) -> stix2.Relationship:
    return stix2.Relationship(
        relationship_type="indicates",
        source_ref=indicator.id,
        target_ref=malware.id,
        created_by_ref=identity_id,
    )


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Generate STIX 2.1 bundle from chrome-mal-ids CSV")
    parser.add_argument("--csv",    type=Path, default=DEFAULT_CSV,
                        help="Path to current-list-meta.csv")
    parser.add_argument("--out",    type=Path, default=DEFAULT_OUT,
                        help="Output path for STIX bundle JSON")
    parser.add_argument("--pretty", action="store_true",
                        help="Pretty-print JSON output")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be written without writing files")
    args = parser.parse_args()

    print(f"Loading {args.csv}...")
    rows = load_csv(args.csv)
    print(f"  {len(rows)} extension entries loaded")

    identity = build_identity()
    all_objects = [identity]

    # Group rows by campaign for Malware objects
    campaign_map: dict[str, stix2.Malware] = {}
    indicators  = []
    relationships = []
    skipped     = 0
    disputed_n  = 0

    for i, row in enumerate(rows, 1):
        if i % 100 == 0 or i == len(rows):
            print(f"  Processing {i}/{len(rows)}...", end="\r", flush=True)

        ext_id      = row["EXTID"].strip().lower()
        threat_str  = row.get("THREAT-TYPE", "").strip()
        notes       = row.get("NOTES", "").strip()
        source      = row.get("SOURCE", "").strip()
        date_dis    = parse_date(row.get("DATE-DIS", ""))
        ext_name    = row.get("EXTID-NAME", "Unknown").strip()

        # Entries with no campaign attribution group by threat type rather
        # than by the leading fragment of their NOTES field.
        campaign_name  = extract_campaign(notes) or unattributed_label(row)
        threat_types   = threat_types_to_stix(threat_str)

        # Deduplicate campaigns by name
        if campaign_name not in campaign_map:
            malware_obj = build_malware(
                campaign=campaign_name,
                threat_types=threat_types,
                first_seen=date_dis,
                identity_id=identity.id,
            )
            campaign_map[campaign_name] = malware_obj
            all_objects.append(malware_obj)
        else:
            malware_obj = campaign_map[campaign_name]

        # Build indicator
        try:
            indicator = build_indicator(row, identity.id, malware_obj)
            rel       = build_relationship(indicator, malware_obj, identity.id)
            indicators.append(indicator)
            relationships.append(rel)
            if is_disputed(row):
                disputed_n += 1
        except Exception as e:
            print(f"  [warn] Skipping {ext_id}: {e}", file=sys.stderr)
            skipped += 1

    all_objects.extend(indicators)
    all_objects.extend(relationships)

    # Build Report object
    report = stix2.Report(
        name="Malicious Chrome Extension IOC Database",
        description=(
            f"Community-maintained list of {len(indicators)} malicious Chrome and Edge "
            f"browser extension indicators of compromise across {len(campaign_map)} "
            f"campaigns. Generated from {PROJECT_URL}"
        ),
        published=datetime.now(timezone.utc),
        created_by_ref=identity.id,
        object_refs=[obj.id for obj in all_objects],
        external_references=[
            stix2.ExternalReference(
                source_name="Malicious Chrome Extension IOC Database",
                url=PROJECT_URL,
            )
        ],
    )
    all_objects.append(report)

    # Build bundle
    bundle = stix2.Bundle(objects=all_objects, allow_custom=True)

    if args.dry_run:
        print(f"\n[DRY RUN] STIX 2.1 bundle would be written to {args.out}")
        print(f"  {len(indicators)} indicators")
        print(f"  {len(campaign_map)} malware/campaign objects")
        print(f"  {len(relationships)} relationships")
        print(f"  {len(all_objects)} total STIX objects")
        if disputed_n:
            print(f"  {disputed_n} indicator(s) labelled {DISPUTED_LABEL}")
        if skipped:
            print(f"  {skipped} entries skipped (see warnings above)")
        return

    # Write output
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        if args.pretty:
            f.write(bundle.serialize(pretty=True))
        else:
            f.write(bundle.serialize())

    print(f"\n✓ STIX 2.1 bundle written to {args.out}")
    print(f"  {len(indicators)} indicators")
    print(f"  {len(campaign_map)} malware/campaign objects")
    print(f"  {len(relationships)} relationships")
    print(f"  {len(all_objects)} total STIX objects")
    if disputed_n:
        print(f"  {disputed_n} indicator(s) labelled {DISPUTED_LABEL}")
    if skipped:
        print(f"  {skipped} entries skipped (see warnings above)")
    print(f"\nImport into MISP: Events → Import → STIX 2.1 → select {args.out.name}")
    print(f"Import into OpenCTI: Data → Import → {args.out.name}")


if __name__ == "__main__":
    main()
