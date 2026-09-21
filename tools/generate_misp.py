#!/usr/bin/env python3
"""
generate_misp.py — Generate MISP-compatible export formats from current-list-meta.csv

Produces two formats:

1. misp-export.json
   A single MISP event JSON file containing all malicious extension IOCs.
   Import via: MISP → Events → Import → MISP JSON

2. misp-feed/ directory
   A MISP feed directory that MISP can poll automatically as a live threat feed.
   Configure via: MISP → Feeds → Add Feed → type: MISP feed
   Feed URL: https://raw.githubusercontent.com/The-Privacy-Commons-Institute/chrome-mal-ids/master/formats/misp-feed/

The feed format creates one event per campaign for cleaner MISP organization.
Entries with no campaign attribution are grouped under "Unattributed" rather
than under the leading fragment of their NOTES field — see extract_campaign().

Attributes whose TPCI Stage 5A analysis disagreed with the contributing
source's classification are tagged `tpci:classification-disputed`. They are
still published: the source's classification stands, and the disagreement is
recorded so consumers can filter on it.

Usage:
    python3 generate_misp.py [--csv PATH] [--out-dir PATH] [--dry-run]

Requirements:
    None — uses stdlib only (no PyMISP needed)
"""

import argparse
import csv
import hashlib
import json
import os
import re
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR   = Path(__file__).parent
# Check multiple possible locations for the CSV
_locations   = [
    SCRIPT_DIR / "data" / "current-list-meta.csv",   # server: /opt/chrome-mal-ids/repo/
    SCRIPT_DIR / "current-list-meta.csv",             # dev: same dir as script
    Path("/opt/chrome-mal-ids/repo/data/current-list-meta.csv"),  # absolute fallback
]
_repo_csv    = next((p for p in _locations if p.exists()), _locations[0])
DEFAULT_CSV  = _repo_csv
DEFAULT_OUT  = _repo_csv.parent.parent / "formats" if _repo_csv.exists() else SCRIPT_DIR
PROJECT_URL  = "https://github.com/The-Privacy-Commons-Institute/chrome-mal-ids"
PROJECT_NAME = "Malicious Chrome Extension IOC Database"
ORG_NAME     = "chrome-mal-ids"
ORG_UUID     = "5e2e6e1a-4f8c-4b2a-9c1d-3a7f8e9b0c2d"  # stable org UUID
DISPUTED_TAG = "tpci:classification-disputed"

# MISP threat level: 1=High, 2=Medium, 3=Low, 4=Undefined
THREAT_LEVEL_MAP = {
    "spyware":          1,
    "data-theft":       1,
    "credential-theft": 1,
    "session-hijack":   1,
    "ransomware":       1,
    "backdoor":         1,
    "trojan":           1,
    "browser-hijack":   2,
    "adware":           2,
    "click-fraud":      2,
    "cryptojacking":    2,
}


def stable_uuid(seed: str) -> str:
    """Generate a stable RFC 4122 UUID5 from a seed string for reproducible IDs."""
    # Use UUID5 with DNS namespace for RFC 4122 compliant stable UUIDs
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"chrome-mal-ids.tpc.institute/{seed}"))


def now_misp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def now_ts() -> int:
    return int(datetime.now(timezone.utc).timestamp())


# NOTES values that are a CLASSIFICATION or a status remark, not a campaign.
#
# Delta-feed entries often carry a bare category as their entire NOTES —
# "Adware", "Policy Violation", "Search Hijacking". The previous extractor took
# the leading fragment of NOTES, so each became its own "campaign" and its own
# set of MISP events: 82 of 188 published events were named after a threat
# category rather than a campaign ("Adware (part 17 of 32)").
#
# Kept byte-identical to generate_stats.py's implementation. Three copies of
# this logic exist (here, generate_stats.py, index.html); they disagreed for
# months. If you change one, change all three.
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
LEADING_PUNCT = "\u201c\u201d\u2018\u2019\"' \t"

UNATTRIBUTED = "Unattributed"


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
        cut = head[:60].rsplit(" ", 1)[0].rstrip(" ,;:\u2014-")
        head = (cut or head[:60]) + "\u2026"
    if not head or head.lower().rstrip("\u2026") in NON_CAMPAIGN_NOTES:
        return None
    return head


def unattributed_label(row: dict) -> str:
    """
    Bucket label for an entry with no campaign attribution.

    Grouping ~5,900 unattributed entries under one name produces events
    titled "Unattributed (part 87 of 119)", which a MISP consumer cannot
    select on. Sub-grouping by threat type gives each event a meaning.

    Components are sorted, which also collapses the ordering variants the
    classifier emits — "spyware,data-theft" and "data-theft,spyware" are the
    same bucket rather than two.
    """
    raw   = (row.get("THREAT-TYPE") or "").strip()
    parts = sorted({t.strip().lower() for t in raw.split(",") if t.strip()})
    parts = [p for p in parts if p and p != "unknown"]
    if not parts:
        return f"{UNATTRIBUTED}: unclassified"
    return f"{UNATTRIBUTED}: " + ", ".join(parts)


def tag_slug(label: str) -> str:
    """
    MISP tag name from a campaign label.

    The previous form was label.lower().replace(" ", "-"), which passed
    commas, colons and periods straight through into tag names. Collapses
    anything that is not alphanumeric to a single hyphen instead.
    """
    out = []
    for ch in label.lower():
        out.append(ch if ch.isalnum() else "-")
    return "-".join(s for s in "".join(out).split("-") if s) or "unlabelled"


def is_disputed(row: dict) -> bool:
    """
    True when TPCI's own Stage 5A analysis found nothing above the scoring
    threshold while the contributing source classified the extension as
    malicious.

    This is a recorded disagreement between two methods, not a judgment that
    the extension is safe. A below-threshold score is not a safety
    verification — static analysis can be evaded, and extensions change after
    they are analyzed. The entry is published either way, with the source's
    classification intact; the tag exists so consumers who want to weight or
    filter these can do so.
    """
    return (row.get("TPCI-BEHAVIORAL") or "").strip() == "below-threshold"


def threat_level(threat_str: str) -> int:
    if not threat_str or threat_str.upper() == "UNKNOWN":
        return 3
    for t in threat_str.lower().split(","):
        level = THREAT_LEVEL_MAP.get(t.strip())
        if level:
            return level
    return 3


def load_csv(path: Path, verified_only: bool = True) -> list[dict]:
    rows    = []
    skipped = 0
    with open(path, newline="", encoding="utf-8") as f:
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


def build_attribute(row: dict, sequence: int) -> dict:
    """Build a MISP attribute for a single extension ID."""
    ext_id   = row["EXTID"].strip().lower()
    name     = row.get("EXTID-NAME", "UNKNOWN").strip()
    browser  = (row.get("BROWSER") or "chrome").strip().lower()
    notes    = row.get("NOTES", "").strip()
    source   = row.get("SOURCE", "").strip()
    article  = row.get("ARTICLE", "").strip()
    threat   = row.get("THREAT-TYPE", "").strip()
    active   = row.get("STILL-ACTIVE", "").strip()

    # Store URL as the attribute value — unique and actionable
    if browser == "edge":
        store_url = f"https://microsoftedge.microsoft.com/addons/detail/{ext_id}"
    else:
        store_url = f"https://chromewebstore.google.com/detail/{ext_id}"

    disputed = is_disputed(row)

    comment_parts = []
    if disputed:
        comment_parts.append(
            "\u26a0 TPCI classification disputed — Stage 5A found no indicators "
            "above threshold; source classification retained"
        )
    if name and name.upper() != "UNKNOWN":
        comment_parts.append(f"Name: {name}")
    if threat and threat.upper() != "UNKNOWN":
        comment_parts.append(f"Threat: {threat}")
    if active == "1":
        comment_parts.append("⚡ Still active in store")
    if notes and notes.upper() != "UNKNOWN":
        comment_parts.append(notes[:200])

    attr = {
        "uuid":              stable_uuid(f"attr-{ext_id}"),
        "type":              "url",
        "category":          "External analysis",
        "value":             store_url,
        "comment":           " | ".join(comment_parts) if comment_parts else f"Extension ID: {ext_id}",
        "to_ids":            False,
        "distribution":      5,  # inherit from event
        "timestamp":         str(now_ts()),
        "disable_correlation": False,
    }
    if disputed:
        attr["Tag"] = [{"name": DISPUTED_TAG}]

    # Also add the raw extension ID as a custom attribute
    id_attr = {
        "uuid":              stable_uuid(f"attr-id-{ext_id}"),
        "type":              "text",
        "category":          "Payload delivery",
        "value":             ext_id,
        "comment":           f"Chrome/Edge extension ID — {name if name.upper() != 'UNKNOWN' else 'name unknown'}",
        "to_ids":            True,
        "distribution":      5,
        "timestamp":         str(now_ts()),
        "disable_correlation": False,
    }
    if disputed:
        id_attr["Tag"] = [{"name": DISPUTED_TAG}]

    return [attr, id_attr]


def build_event(event_uuid: str, title: str, rows: list[dict],
                threat_lvl: int, date: str) -> dict:
    """Build a complete MISP event dict."""
    attributes = []
    for row in rows:
        attributes.extend(build_attribute(row, len(attributes)))

    # Add source/article URLs as references
    sources = set()
    for row in rows:
        for field in ("SOURCE", "ARTICLE"):
            val = row.get(field, "").strip()
            if val and val.upper() not in ("UNKNOWN", ""):
                sources.add(val)

    for src_url in sorted(sources)[:10]:  # cap at 10 refs per event
        attributes.append({
            "uuid":     stable_uuid(f"attr-ref-{event_uuid}-{src_url}"),
            "type":     "url",
            "category": "External analysis",
            "value":    src_url,
            "comment":  "Research source / article",
            "to_ids":   False,
            "distribution": 5,
            "timestamp": str(now_ts()),
            "disable_correlation": False,
        })

    return {
        "Event": {
            "uuid":            event_uuid,
            "info":            title,
            "date":            date,
            "threat_level_id": str(threat_lvl),
            "analysis":        "2",   # completed
            "distribution":    "3",   # all communities
            "published":       True,
            "timestamp":       str(now_ts()),
            "Org": {
                "uuid": ORG_UUID,
                "name": ORG_NAME,
            },
            "Orgc": {
                "uuid": ORG_UUID,
                "name": ORG_NAME,
            },
            "Tag": [
                {"name": "tlp:white",          "colour": "#ffffff"},
                {"name": "chrome-mal-ids",     "colour": "#c41e35"},
                {"name": "malicious-extension","colour": "#8b0000"},
            ],
            "Attribute": attributes,
        }
    }


# ── Single event export ────────────────────────────────────────────────────────

def generate_misp_event(rows: list[dict], out_path: Path, dry_run: bool = False):
    """Single MISP event containing all IOCs — for manual import."""
    total      = len(rows)
    date       = now_misp()
    event_uuid = stable_uuid("chrome-mal-ids-master-event")

    all_attrs = []
    for row in rows:
        all_attrs.extend(build_attribute(row, len(all_attrs)))

    event = {
        "Event": {
            "uuid":            event_uuid,
            "info":            f"{PROJECT_NAME} — {total} malicious extension IOCs",
            "date":            date,
            "threat_level_id": "2",   # medium overall
            "analysis":        "2",
            "distribution":    "3",
            "published":       True,
            "timestamp":       str(now_ts()),
            "Org":  {"uuid": ORG_UUID, "name": ORG_NAME},
            "Orgc": {"uuid": ORG_UUID, "name": ORG_NAME},
            "Tag": [
                {"name": "tlp:white",           "colour": "#ffffff"},
                {"name": "chrome-mal-ids",      "colour": "#c41e35"},
                {"name": "malicious-extension", "colour": "#8b0000"},
                {"name": "misp-galaxy:threat-actor",  "colour": "#0088cc"},
            ],
            "Attribute": all_attrs,
            "description": (
                f"Community-maintained database of {total} confirmed malicious Chrome "
                f"and Edge browser extension IOCs across 30+ campaigns. "
                f"Source: {PROJECT_URL} — License: CC BY 4.0"
            ),
        }
    }

    if dry_run:
        print(f"[DRY RUN] misp-export.json would be written → {total} extensions, "
              f"{len(all_attrs)} attributes")
    else:
        out_path.write_text(json.dumps(event, indent=2, ensure_ascii=False) + "\n",
                            encoding="utf-8")
        print(f"✓ misp-export.json → {total} extensions, {len(all_attrs)} attributes")


# ── MISP feed format ───────────────────────────────────────────────────────────

def generate_misp_feed(rows: list[dict], feed_dir: Path, dry_run: bool = False):
    """
    MISP feed directory format.
    Creates one event per campaign + a manifest.json index.
    MISP polls this directory structure directly from GitHub raw URLs.

    Event files whose UUID is no longer in the manifest are removed. Campaign
    labels feed into the event UUID, so relabelling an entry orphans its old
    event file — left behind, those keep being served from the repo while
    absent from manifest.json, and MISP consumers see events the feed no
    longer claims.
    """
    feed_dir.mkdir(exist_ok=True)
    date = now_misp()

    # Group by campaign
    campaigns = defaultdict(list)
    for row in rows:
        campaign = extract_campaign(row.get("NOTES", ""))
        if campaign is None:
            campaign = unattributed_label(row)
        campaigns[campaign].append(row)

    manifest = {}
    event_count = 0
    CHUNK_SIZE = 50  # max extensions per MISP event to stay under size limits

    for campaign, camp_rows in sorted(campaigns.items()):
        threat_lvl  = min(threat_level(r.get("THREAT-TYPE", "")) for r in camp_rows)
        total       = len(camp_rows)

        # Split large campaigns into chunks to avoid MISP feed size limits
        chunks = [camp_rows[i:i+CHUNK_SIZE] for i in range(0, total, CHUNK_SIZE)]

        for chunk_idx, chunk_rows in enumerate(chunks):
            # Use stable UUID per chunk so re-runs don't create duplicates
            suffix     = f"-part{chunk_idx+1}" if len(chunks) > 1 else ""
            event_uuid = stable_uuid(f"feed-event-{campaign}{suffix}")
            part_label = f" (part {chunk_idx+1} of {len(chunks)})" if len(chunks) > 1 else ""
            title      = f"[chrome-mal-ids] {campaign} — {len(chunk_rows)} malicious extension(s){part_label}"

            if not dry_run:
                event      = build_event(event_uuid, title, chunk_rows, threat_lvl, date)
                event_file = feed_dir / f"{event_uuid}.json"
                event_file.write_text(json.dumps(event, indent=2, ensure_ascii=False) + "\n",
                                      encoding="utf-8")

            manifest[event_uuid] = {
                "Orgc": {"uuid": ORG_UUID, "name": ORG_NAME},
                "Tag":  [
                    {"name": "tlp:white"},
                    {"name": "chrome-mal-ids"},
                    {"name": tag_slug(campaign)},
                ],
                "info":            title,
                "date":            date,
                "analysis":        "2",
                "threat_level_id": str(threat_lvl),
                "timestamp":       str(now_ts()),
                "distribution":    "3",
            }
            event_count += 1

    # Remove event files no longer referenced by the manifest.
    stale = [p for p in feed_dir.glob("*.json")
             if p.name != "manifest.json" and p.stem not in manifest]

    if dry_run:
        print(f"[DRY RUN] misp-feed/ would be written → {event_count} events "
              f"({len(rows)} total extensions)")
        if stale:
            print(f"[DRY RUN] {len(stale)} stale event file(s) would be removed")
        return

    for p in stale:
        p.unlink()
    if stale:
        print(f"  removed {len(stale)} stale event file(s) no longer in the manifest")

    # Write manifest.json
    manifest_path = feed_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
                             encoding="utf-8")

    # Write hashes.csv for feed integrity verification
    hashes = []
    for event_uuid in manifest:
        event_file = feed_dir / f"{event_uuid}.json"
        content    = event_file.read_bytes()
        md5        = hashlib.md5(content).hexdigest()
        sha1       = hashlib.sha1(content).hexdigest()
        hashes.append(f"{event_uuid}.json,{md5},{sha1}")

    hashes_path = feed_dir / "hashes.csv"
    hashes_path.write_text("\n".join(hashes) + "\n", encoding="utf-8")

    disputed_n = sum(1 for r in rows if is_disputed(r))
    print(f"✓ misp-feed/ → {event_count} events ({len(rows)} total extensions)")
    if disputed_n:
        print(f"  {disputed_n} attribute set(s) tagged {DISPUTED_TAG}")
    print(f"  Configure feed URL in MISP:")
    print(f"  {PROJECT_URL.replace('github.com', 'raw.githubusercontent.com')}/master/formats/misp-feed/")


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Generate MISP export formats from chrome-mal-ids CSV"
    )
    parser.add_argument("--csv",     type=Path, default=DEFAULT_CSV)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be written without writing files")
    args = parser.parse_args()

    rows = load_csv(args.csv)
    print(f"Loaded {len(rows)} entries from {args.csv.name}")

    # Single event export
    generate_misp_event(rows, args.out_dir / "misp-export.json", args.dry_run)

    # Feed directory
    generate_misp_feed(rows, args.out_dir / "misp-feed", args.dry_run)

    if args.dry_run:
        print(f"\n[DRY RUN] No files written to {args.out_dir}")
        return

    print(f"\nMISP formats written to {args.out_dir}")
    print(f"""
Import options:
  Manual:  MISP → Events → Import → MISP JSON → select misp-export.json
  Feed:    MISP → Feeds → Add Feed:
             Name:    Malicious Chrome Extension IOC Database
             Type:    MISP Feed
             URL:     https://raw.githubusercontent.com/The-Privacy-Commons-Institute/chrome-mal-ids/master/formats/misp-feed/
             Input source: Network
             Distribution: Your organisation only (adjust as needed)
""")


if __name__ == "__main__":
    main()
