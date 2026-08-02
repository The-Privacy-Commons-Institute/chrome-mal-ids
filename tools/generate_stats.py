#!/usr/bin/env python3
"""
generate_stats.py — Generate STATS.md from current-list-meta.csv

Produces a human-readable statistics summary committed alongside the data.
Run automatically as part of the commit pipeline, or manually:

    python3 generate_stats.py [--csv PATH] [--out PATH]
"""

import csv
import argparse
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR  = Path(__file__).parent
_locations  = [
    SCRIPT_DIR / "data" / "current-list-meta.csv",
    SCRIPT_DIR / "current-list-meta.csv",
    Path("/opt/chrome-mal-ids/repo/data/current-list-meta.csv"),
]
_repo_csv   = next((p for p in _locations if p.exists()), _locations[0])
DEFAULT_CSV = _repo_csv

# STATS.md belongs in the repo (it gets committed alongside the data), not
# necessarily next to this script — this script may live one directory up
# (e.g. /opt/chrome-mal-ids/generate_stats.py vs. the actual repo at
# /opt/chrome-mal-ids/repo/). Bug history: this used to be hardcoded to
# SCRIPT_DIR / "STATS.md", which silently wrote to the wrong location for
# ~2 months (May 29 - Jul 9 2026) once the script and repo diverged —
# `git status` correctly showed nothing to commit, because the tracked file
# was never actually touched. Fixed by deriving the repo root from wherever
# DEFAULT_CSV was actually found, matching the same fallback logic above
# rather than assuming the script's own location.
if DEFAULT_CSV.parent.name == "data":
    _repo_root = DEFAULT_CSV.parent.parent
else:
    _repo_root = DEFAULT_CSV.parent
DEFAULT_OUT = _repo_root / "STATS.md"

PROJECT_URL = "https://github.com/The-Privacy-Commons-Institute/chrome-mal-ids"


def find_sources_file() -> Path | None:
    """Find monitor_sources.json — check server path then local monitor dir."""
    candidates = [
        Path("/opt/chrome-mal-ids/monitor_sources.json"),          # server
        SCRIPT_DIR.parent / "monitor" / "monitor_sources.json",    # local laptop
        SCRIPT_DIR / "monitor_sources.json",                       # repo root fallback
    ]
    for p in candidates:
        if p.exists():
            return p
    return None


def load_csv(path: Path, verified_only: bool = False) -> list[dict]:
    """Load CSV. Stats default to all entries; pass verified_only=True for filtered view."""
    rows    = []
    skipped = 0
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row.get("EXTID", "").strip().lower() in ("", "unknown"):
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
    return rows


def extract_campaign(notes: str) -> str:
    import re
    if not notes or notes.upper() == "UNKNOWN":
        return "Unknown"
    m = re.match(r'^([A-Z][^.(]{3,60}?)(?:\s*[\.(])', notes)
    if m:
        c = m.group(1).strip()
        if len(c.split()) <= 8:
            return c
    return notes.split(".")[0].strip()[:60] or "Unknown"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", type=Path, default=DEFAULT_CSV)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()

    rows = load_csv(args.csv)
    total = len(rows)

    # ── Aggregate stats ────────────────────────────────────────────────────────
    browsers        = defaultdict(int)
    threat_types    = defaultdict(int)
    campaigns       = defaultdict(int)
    still_active    = 0
    ownership_xfer  = 0
    stubs_pending   = 0  # UNKNOWN name, still searchable (empty/searched ENRICH-STATUS)
    stubs_exhausted = 0  # UNKNOWN name, enrichment tried and gave up
    dates           = []

    for row in rows:
        # Browser
        b = row.get("BROWSER", "chrome").strip().lower() or "chrome"
        browsers[b] += 1

        # Threat types (can be comma-separated)
        tt = row.get("THREAT-TYPE", "").strip()
        if tt and tt.upper() != "UNKNOWN":
            for t in tt.split(","):
                threat_types[t.strip()] += 1
        else:
            threat_types["unknown"] += 1

        # Campaign
        campaigns[extract_campaign(row.get("NOTES", ""))] += 1

        # Flags
        if row.get("STILL-ACTIVE", "0").strip() == "1":
            still_active += 1
        if row.get("OWNERSHIP-TRANSFER", "0").strip() == "1":
            ownership_xfer += 1
        if row.get("EXTID-NAME", "").strip().upper() == "UNKNOWN":
            if row.get("ENRICH-STATUS", "").strip().lower() == "exhausted":
                stubs_exhausted += 1
            else:
                stubs_pending += 1

        # Dates
        d = row.get("DATE-DIS", "").strip()
        if d and d.upper() not in ("UNKNOWN", "MISSING", ""):
            try:
                dates.append(datetime.strptime(d, "%Y-%m-%d"))
            except ValueError:
                pass

    oldest = min(dates).strftime("%Y-%m-%d") if dates else "unknown"
    newest = max(dates).strftime("%Y-%m-%d") if dates else "unknown"
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Sort campaigns by count
    top_campaigns = sorted(campaigns.items(), key=lambda x: x[1], reverse=True)
    top_threats   = sorted(threat_types.items(), key=lambda x: x[1], reverse=True)

    # ── Write STATS.md ─────────────────────────────────────────────────────────
    lines = [
        "# Malicious Chrome Extension IOC Database — Statistics",
        "",
        f"> Auto-generated {generated} · [Full list]({PROJECT_URL})",
        "",
        "---",
        "",
        "## Summary",
        "",
        f"| Metric | Count |",
        f"|--------|-------|",
        f"| Total malicious extensions | **{total:,}** |",
        f"| Unique campaigns | **{len(campaigns):,}** |",
        # NOTE: "Still active in store" count suppressed — under embargo until June 30 2026.
        # Paper 1 ("Still There") is under 30-day coordinated disclosure with Google.
        # Restore after publication:  f"| Still active in store | **{still_active:,}** |",
        f"| Ownership transfer cases | **{ownership_xfer:,}** |",
        f"| Stubs — pending (ID confirmed, still searchable) | **{stubs_pending:,}** |",
        f"| Stubs — exhausted (ID confirmed, enrichment attempted and unsuccessful) | **{stubs_exhausted:,}** |",
        f"| Earliest discovery | **{oldest}** |",
        f"| Most recent discovery | **{newest}** |",
        "",
        "---",
        "",
        "## By Browser",
        "",
        "| Browser | Extensions |",
        "|---------|-----------|",
    ]
    for b, count in sorted(browsers.items(), key=lambda x: x[1], reverse=True):
        pct = count / total * 100
        lines.append(f"| {b.title()} | {count:,} ({pct:.1f}%) |")

    lines += [
        "",
        "---",
        "",
        "## By Threat Type",
        "",
        "| Threat Type | Extensions |",
        "|-------------|-----------|",
    ]
    for t, count in top_threats:
        pct = count / total * 100
        lines.append(f"| {t} | {count:,} ({pct:.1f}%) |")

    lines += [
        "",
        "---",
        "",
        "## Campaigns",
        "",
        f"A total of **{len(campaigns):,}** distinct campaigns are tracked.",
        "",
        "| Campaign | Extensions |",
        "|----------|-----------|",
    ]
    for campaign, count in top_campaigns[:50]:  # top 50
        lines.append(f"| {campaign} | {count:,} |")

    if len(top_campaigns) > 50:
        lines.append(f"| *(+ {len(top_campaigns) - 50} more)* | |")

    lines += [
        "",
        "---",
        "",
        "## Monitoring Sources",
        "",
        "The following sources are monitored daily for new malicious extension reports:",
        "",
    ]

    # Load sources from monitor_sources.json if available
    sources_file = find_sources_file()
    if sources_file and sources_file.exists():
        import json
        with open(sources_file, encoding="utf-8") as f:
            sources = json.load(f)

        rss     = [s for s in sources.get("rss_feeds",    []) if s.get("enabled", True)]
        github  = [s for s in sources.get("github_repos", []) if s.get("enabled", True)]
        # csv_sources exists in the review UI's Sources tab (review.html manages
        # a third sourcesData.csv_sources array alongside rss_feeds/github_repos,
        # and the backend's write_sources() persists whatever the client POSTs —
        # it isn't schema-limited on write, only this read path was) but was never
        # read here, so any CSV sources added via the UI silently never appeared
        # in STATS.md. Fixed July 2026.
        csv_srcs = [s for s in sources.get("csv_sources",  []) if s.get("enabled", True)]

        lines += [
            "### RSS Feeds",
            "",
            "| Source | Filter Keywords |",
            "|--------|----------------|",
        ]
        for s in rss:
            filters = ", ".join(s.get("filter") or []) or "*all posts*"
            url     = s.get("url", "")
            name    = s.get("name", "")
            lines.append(f"| [{name}]({url}) | `{filters}` |")

        lines += [
            "",
            "### GitHub Repositories",
            "",
            "| Repository | Type |",
            "|-----------|------|",
        ]
        for s in github:
            url  = s.get("url", "").replace("/commits?per_page=5","").replace("/issues?state=open&per_page=10","")
            name = s.get("name", "")
            kind = s.get("type", "commits")
            lines.append(f"| [{name}]({url}) | {kind} |")

        lines += [
            "",
            "### CSV Sources",
            "",
            "| Source | Contributor |",
            "|--------|-------------|",
        ]
        for s in csv_srcs:
            url     = s.get("url", "")
            name    = s.get("name", "")
            contrib = s.get("contrib_handle") or s.get("contrib") or "—"
            lines.append(f"| [{name}]({url}) | {contrib} |")
        if not csv_srcs:
            lines.append("| *(none configured)* | |")

        lines.append("")
        lines.append(f"*{len(rss)} RSS feeds · {len(github)} GitHub repos · "
                      f"{len(csv_srcs)} CSV sources · edit via the review UI Sources tab*")
    else:
        lines.append("*Source list not available — `monitor_sources.json` not found*")

    # ── By Contribution Method ──────────────────────────────────────────────
    # Covers one-off/non-recurring imports (PDF ingestion, manual rescue, delta
    # imports, AI enrichment, etc.) that don't fit the "continuously monitored
    # feed" model above — those are per-record provenance (CONTRIB-METHOD),
    # not persistent sources, so they're driven directly from the data rather
    # than from monitor_sources.json. Automatically reflects any future
    # contribution method without needing this script updated again.
    contrib_methods = defaultdict(int)
    for row in rows:
        m = row.get("CONTRIB-METHOD", "").strip() or "(unspecified)"
        contrib_methods[m] += 1
    top_contrib_methods = sorted(contrib_methods.items(), key=lambda x: x[1], reverse=True)

    lines += [
        "",
        "---",
        "",
        "## By Contribution Method",
        "",
        "How entries entered the database — recurring monitored sources "
        "(RSS/GitHub/CSV, above) vs. one-off imports (PDF reports, manual "
        "rescue) vs. bulk/AI-assisted enrichment.",
        "",
        "| Method | Extensions |",
        "|--------|-----------|",
    ]
    for method, count in top_contrib_methods:
        pct = count / total * 100
        lines.append(f"| {method} | {count:,} ({pct:.1f}%) |")

    # ── Component glossary ──────────────────────────────────────────────────
    # Methods above are often compound (e.g. "Delta_Import+Store_Enrichment+
    # ThreatType_Classified") — meaningful internally, but opaque to anyone
    # outside the project. This explains each individual component, built
    # dynamically from whatever tokens actually appear in the data (split on
    # "+") rather than a hardcoded list, so a future new method still gets
    # listed here (with a placeholder) instead of silently going unexplained.
    GLOSSARY = {
        "csv_import":          "Extension ID sourced from an externally-provided CSV file.",
        "Delta_Import":        "Bulk incremental import from a continuously-updated external "
                                "IOC feed.",
        "Google_Search":       "Independently discovered and verified through manual web research.",
        "Store_Enrichment":    "Name and metadata resolved by looking up the extension's "
                                "Chrome/Edge Web Store listing.",
        "PDF_Import":          "Extracted from a PDF-format threat research report.",
        "AI_Enrichment":       "Metadata or classification added via AI-assisted research.",
        "ThreatType_Classified": "Threat category successfully assigned via AI-based classification.",
        "ThreatType_Fallback":  "AI classification was attempted but could not confidently "
                                "assign a category.",
        "Initial_Commit":      "Part of the batch entered when the project restarted in "
                                "May 2026 — often carrying forward original discovery dates "
                                "from years earlier (e.g. 2018-2019), reflecting when the "
                                "extension was first documented, not when it entered this database.",
        "Manual":              "Hand-entered by a human researcher outside the automated pipeline "
                                "(e.g. a manual rescue of a record that failed automated processing).",
        "(unspecified)":       "No contribution method was recorded for this entry.",
    }

    all_components = set()
    for method in contrib_methods:
        all_components.update(method.split("+"))

    lines += [
        "",
        "### Component Glossary",
        "",
        "Compound methods above (joined with `+`) mean more than one process "
        "touched that entry — e.g. `Delta_Import+Store_Enrichment+"
        "ThreatType_Classified` means it arrived via bulk import, then had its "
        "name/metadata resolved from the store listing, then got an AI-assigned "
        "threat category. Individual components:",
        "",
        "| Component | Meaning |",
        "|-----------|---------|",
    ]
    for component in sorted(all_components):
        meaning = GLOSSARY.get(component, "*(no description yet — ping the maintainers)*")
        lines.append(f"| `{component}` | {meaning} |")

    lines += [
        "",
        "---",
        "",
        f"*Generated by [generate_stats.py]({PROJECT_URL}/blob/master/generate_stats.py)*",
        "",
    ]

    args.out.write_text("\n".join(lines), encoding="utf-8")
    # Print the resolved output path explicitly — this exact gap (a success
    # message with no path shown) is why the 2-month stale-file bug went
    # unnoticed: even a manual run's own console output gave no way to
    # confirm where it landed without a separate `ls` check.
    print(f"✓ STATS.md written → {args.out} ({total:,} extensions, {len(campaigns):,} campaigns)")
    print(f"  (CSV source: {args.csv})")


if __name__ == "__main__":
    main()
