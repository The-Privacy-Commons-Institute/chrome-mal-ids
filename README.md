# Malicious Chrome Extension IOC Database

**A community-maintained database of malicious Chrome and Edge browser extension indicators of compromise (IOCs).**

*Repository: [chrome-mal-ids](https://github.com/The-Privacy-Commons-Institute/chrome-mal-ids)*

[![License: CC BY 4.0](https://img.shields.io/badge/License-CC%20BY%204.0-lightgrey.svg?style=flat-square)](LICENSE.md)
[![STIX 2.1](https://img.shields.io/badge/STIX-2.1-blue?style=flat-square)](formats/chrome-mal-ids-stix.json)

> **⚠ Schema updated May 2026** — Six new TPCI-V verification fields added (`TPCI-VERIFY`, `TPCI-VERIFY-DATE`, `TPCI-STORE-NAME`, `TPCI-STORE-DEV`, `TPCI-STORE-DATE`, `TPCI-IDENTITY`) plus four earlier additions (`ADD-SOURCES`, `CONTRIB-METHOD`, `CONTRIB-TYPE`, `CONTRIB-HANDLE`). Scripts using positional column indexing will need updating. Scripts using named headers (`csv.DictReader` or equivalent) require no changes. See [SCHEMA.md](SCHEMA.md) for full details and migration guidance.

> **⚠ Third-party source verification status** — Coverage of independent behavioral analysis differs by source. The one-time bulk delta import (`CONTRIB-METHOD=Delta_Import`) has been through Stage 5A static behavioral analysis, which confirmed malicious or elevated-risk patterns at a high rate. Ongoing ingestion labelled `csv_import` has not been through Stage 5A: those entries carry the contributing source's own classification plus store existence/liveness verification. Stage 5A coverage of these entries began 2026-09-20 and is ongoing. For current entry counts per method, see the **By Contribution Method** table in [STATS.md](STATS.md) — those numbers move as ingestion continues, so they're tracked there rather than restated here.

---

## 🔍 [Search the database →](https://the-privacy-commons-institute.github.io/chrome-mal-ids)

---

## What this is

Started in 2021 as a personal research project after noticing no single authoritative list
of malicious Chrome extension IDs existed. The database tracks thousands of documented
malicious extension IOCs across dozens of campaigns — from credential stealers and browser
hijackers to supply chain compromises and ad fraud rings. **Current totals change as
ingestion continues — see [STATS.md](STATS.md) for the live count, campaign breakdown, and
contribution-method breakdown, auto-generated on every update rather than restated here.**

The database is maintained by [The Privacy Commons Institute](https://tpc.institute/pages/project-chrome-mal-ids) (TPCI)
and is an active research platform. TPCI conducts original research on browser extension
threats including persistence measurement, removal rate analysis, IOC feed quality assessment,
and behavioral verification. Entries are updated as research progresses. All changes are
documented in [CHANGELOG.md](CHANGELOG.md).

This work is independent and self-funded. If it's been useful to you or your team,
you can [support it here](https://tpc.institute/support) — or put that same value
toward a cause you'd rather back instead.

All entries sourced from original research are human-reviewed before publication.
Distribution outputs (STIX, MISP, Sigma, blocklist) exclude unverified bulk delta
imports. See [Data quality](#data-quality) for the verification coverage each source
carries.

---

## The data

| File | Description |
|------|-------------|
| [`data/current-list-meta.csv`](data/current-list-meta.csv) | Full dataset with metadata |
| [`data/current-list.csv`](data/current-list.csv) | ID-only list for lightweight consumption |
| [`data/current-list.txt`](data/current-list.txt) | Plain text blocklist, one ID per line |
| [`data/current-list.json`](data/current-list.json) | JSON array with full metadata |
| [`data/current-list-sigma.yml`](data/current-list-sigma.yml) | Sigma detection rule for SIEMs |
| [`formats/chrome-mal-ids-stix.json`](formats/chrome-mal-ids-stix.json) | STIX 2.1 bundle for threat intel platforms |
| [`formats/misp-export.json`](formats/misp-export.json) | MISP event JSON for manual import |
| [`formats/misp-feed/`](formats/misp-feed/) | MISP feed directory for automatic polling |
| [`STATS.md`](STATS.md) | **Auto-generated statistics summary — current totals, campaign breakdown, contribution methods, and monitored sources live here** |
| [`SCHEMA.md`](SCHEMA.md) | Full schema documentation |

### Schema overview

Each entry in `current-list-meta.csv` contains:

| Field | Description |
|-------|-------------|
| `EXTID` | 32-character Chrome/Edge extension ID |
| `EXTID-NAME` | Extension display name |
| `DATE-DIS` | Date the malicious behavior was first reported |
| `THREAT-TYPE` | Type of threat (spyware, data-theft, browser-hijack, etc.) |
| `BROWSER` | `chrome` or `edge` |
| `STILL-ACTIVE` | `1` live in the store at last verification check, `0` removed, `unknown` if the check was inconclusive |
| `OWNERSHIP-TRANSFER` | `1` if a legitimate extension was acquired and turned malicious |
| `SOURCE` | Primary research source |
| `ARTICLE` | News/blog article covering the campaign |
| `NOTES` | Plain-English summary of the malicious behavior |
| `TPCI-BEHAVIORAL` | Stage 5A static analysis result, when it has run — `malicious`, `suspicious`, `elevated`, `below-threshold` or `unknown` |

Full schema: [SCHEMA.md](SCHEMA.md)

### Data quality

Entries in this database fall into two categories with different confidence levels.
**Exact current counts for both categories, plus a full breakdown by contribution
method (delta import, PDF report intake, AI enrichment, manual entry, etc.), are in
[STATS.md](STATS.md)'s "By Contribution Method" table** rather than restated here as
static numbers.

**Independently verified entries** (`CONTRIB-METHOD` ≠ `Delta_Import`, ≠ `csv_import`)
Sourced from published security research, individually reviewed by a human before
commit, with source citations and campaign attribution. These are confirmed malicious
extensions backed by original research.

**Third-party source entries** (`CONTRIB-METHOD=Delta_Import`, `csv_import`, `PDF_Import`, etc.)
These entries have not necessarily been individually human-reviewed on ingest, and
behavioral-analysis coverage differs by source: `Delta_Import` entries have been through
Stage 5A static analysis, `csv_import` entries have not.

Check `TPCI-BEHAVIORAL` for whether an entry carries a behavioral finding at all, and
`TPCI-VERIFY` for the highest verification stage reached. Note that `TPCI-VERIFY` records
a *stage*, not a confidence score: stages 1–3 establish that an extension exists, renders,
or is reachable in the store. They are not findings about what it does. Only stage 5
reflects behavioral analysis.

**Independent analysis may differ from the source.** Third-party entries carry the
contributing source's classification in `NOTES`; where TPCI Stage 5A analysis has run,
its own finding is recorded alongside it. The two may differ. A `suspicious` or
`below-threshold` Stage 5A result is not a retraction of the source's classification —
static analysis can be evaded, and an absence of detected indicators is not evidence of
benign behavior. Both signals are recorded so consumers can prioritize according to their
own risk tolerance.

**Divergent classifications are flagged, not removed.** Where TPCI Stage 5A analysis
found nothing above its scoring threshold (`TPCI-BEHAVIORAL=below-threshold`) but the
contributing source classified the extension as malicious, the two methods did not
agree and the entry is marked in every distribution format:

| Output | Form |
|---|---|
| `current-list.json` | `"classification_divergent": true`, alongside `"behavioral"` |
| `current-list.txt` | inline `[divergent]` marker |
| `current-list-sigma.yml` | separate rule `chrome-mal-ids-sigma-divergent` at `level: low` |
| MISP | attribute tag `tpci:classification-divergent` |

The flag records a divergence between two methods. It does not say which one is
right: neither result overrides the other, and a below-threshold score is not a
safety verification. We publish the source's determination with its attribution
intact rather than substituting our own judgment for it. The flag exists so you
can apply yours.

*This flag was named `disputed` when introduced on 2026-09-21 and renamed on
2026-09-22 — "disputed" implied we were contesting the source's finding, which
we are not. Consumers who pinned the earlier strings should update; see
[CHANGELOG.md](CHANGELOG.md).*

**Filtering by confidence level:**
```bash
# High confidence — independently verified entries only
grep -v "Delta_Import\|csv_import" data/current-list-meta.csv

# Entries carrying a Stage 5A behavioral finding
python3 -c "import csv; [print(r['EXTID']) for r in \
  csv.DictReader(open('data/current-list-meta.csv')) if r['TPCI-BEHAVIORAL'].strip()]"

# NOTE: parse this file with a CSV-aware reader. NOTES and extension names
# contain commas and quoted fields, so awk -F',' and cut -d',' will split
# rows incorrectly. Column positions also change as the schema grows —
# address fields by header name, not index.

# Unverified delta imports
grep "Delta_Import" data/current-list-meta.csv | grep -v "Store_Enrichment"

# Exclude divergent classifications from the plain-text blocklist
grep -v '\[divergent\]' data/current-list.txt
```

**Additional quality notes:**
- **UNKNOWN stubs** — entries with confirmed malicious IDs but incomplete metadata.
  Committed immediately (an ID is better than nothing) and enriched over time.
  Find them with: `grep ",UNKNOWN," data/current-list-meta.csv`
- **Still-active flag** — maintained by the verification pipeline, not frozen at time
  of reporting. `1` means the extension was live at the last check, `0` that it was
  removed or delisted, `unknown` that the check was inconclusive. `TPCI-VERIFY-DATE`
  records when that check last ran.
- **Supply chain victims** — some entries marked `TPCI-IDENTITY=remediated` were
  legitimate extensions compromised by supply chain attacks. The developers have
  patched the malicious code. These IDs are retained for historical accuracy but
  should not be treated as currently malicious.

---

## How to use it

### 🌐 Search UI

Browse and search the full database at:
**https://the-privacy-commons-institute.github.io/chrome-mal-ids**

Filter by campaign, threat type, browser, date, and active status. Click any entry
for full details including research article links.

### 📄 Plain text blocklist

One ID per line — works with grep, MDM tools, custom scripts:

```bash
# Download
curl -O https://raw.githubusercontent.com/The-Privacy-Commons-Institute/chrome-mal-ids/master/data/current-list.txt

# Check a specific ID
grep "YOUR_EXTENSION_ID" current-list.txt

# Scan all installed Chrome extensions (Linux/macOS)
comm -12 \
  <(ls ~/.config/google-chrome/Default/Extensions/ | sort) \
  <(grep -v '^#' current-list.txt | awk '{print $1}' | sort)
```

### 🔷 JSON

Full metadata as a JSON array — ideal for developers and custom tooling:

```
https://raw.githubusercontent.com/The-Privacy-Commons-Institute/chrome-mal-ids/master/data/current-list.json
```

```python
import urllib.request, json
url  = "https://raw.githubusercontent.com/The-Privacy-Commons-Institute/chrome-mal-ids/master/data/current-list.json"
data = json.loads(urllib.request.urlopen(url).read())
exts = {e["ext_id"]: e for e in data["extensions"]}
# Check an ID
if "your_extension_id" in exts:
    print(exts["your_extension_id"])
```

### 🔍 Sigma rule (SIEM detection)

Sigma rule covering all known malicious IDs — compatible with Splunk, Elastic, Microsoft Sentinel, and any Sigma-capable SIEM:

```
https://raw.githubusercontent.com/The-Privacy-Commons-Institute/chrome-mal-ids/master/data/current-list-sigma.yml
```

The file contains two rules. `chrome-mal-ids-sigma` (`level: high`) covers the main
population. `chrome-mal-ids-sigma-divergent` (`level: low`) covers entries where TPCI
Stage 5A analysis and the contributing source did not agree — see
[Data quality](#data-quality).
Sigma has nowhere to put per-ID metadata, so the split is the only way to express that
distinction; enable both rules for the full list.

Convert to your SIEM's native format with [sigma-cli](https://github.com/SigmaHQ/sigma-cli):

```bash
sigma convert -t splunk current-list-sigma.yml
sigma convert -t elastic-dsl current-list-sigma.yml
sigma convert -t sentinel current-list-sigma.yml
```

```bash
# Download the full metadata CSV
curl -O https://raw.githubusercontent.com/The-Privacy-Commons-Institute/chrome-mal-ids/master/data/current-list-meta.csv

# Check if a specific extension ID is malicious
grep "YOUR_EXTENSION_ID" current-list-meta.csv
```

### 🛡️ System scan scripts

**Linux / macOS:**
```bash
curl -O https://raw.githubusercontent.com/The-Privacy-Commons-Institute/chrome-mal-ids/master/contrib/scripts/linux_mac/chrome-ext-check.sh
chmod +x chrome-ext-check.sh
./chrome-ext-check.sh
```

**Windows (PowerShell):**
```powershell
Invoke-WebRequest -Uri https://raw.githubusercontent.com/The-Privacy-Commons-Institute/chrome-mal-ids/master/contrib/scripts/windows/Scan-ChromeExtensions.ps1 -OutFile Scan-ChromeExtensions.ps1
.\Scan-ChromeExtensions.ps1
```

### 🔵 MISP

Two MISP formats are available — manual import or automated feed:

**Manual import** (`misp-export.json`):
```
MISP → Events → Import → MISP JSON → select misp-export.json
```

**Automated feed** (recommended — MISP polls automatically on a schedule):
```
MISP → Feeds → Add Feed:
  Name:         Malicious Chrome Extension IOC Database
  Type:         MISP Feed
  URL:          https://raw.githubusercontent.com/The-Privacy-Commons-Institute/chrome-mal-ids/master/formats/misp-feed/
  Input source: Network
  Distribution: Your organisation only
```

The feed creates one MISP event per campaign, with full attribute metadata, TLP:WHITE tags, and source references (see [STATS.md](STATS.md) for the current campaign count). Updates automatically with every new database commit.

Entries with no campaign attribution are grouped as `Unattributed: <threat types>` — e.g. `Unattributed: data-theft, spyware` — so they remain selectable rather than landing in one undifferentiated bucket. Attributes whose classification diverged carry the tag `tpci:classification-divergent`; filter on it in MISP to include or exclude them.

### 🧩 STIX 2.1 / OpenCTI

The STIX 2.1 bundle is auto-generated on every update and available at:
```
https://raw.githubusercontent.com/The-Privacy-Commons-Institute/chrome-mal-ids/master/formats/chrome-mal-ids-stix.json
```

**MISP** — scheduled pull:
```
Events → Feeds → Add Feed → STIX 2.1 → paste URL above
```

**OpenCTI** — remote ingestion:
```
Data → Ingestion → Remote STIX2 Feeds → paste URL above
```

**Subscribe to updates** via the releases RSS feed:
```
https://github.com/The-Privacy-Commons-Institute/chrome-mal-ids/releases.atom
```

### 🐍 Python / programmatic

```python
import csv, urllib.request

url = "https://raw.githubusercontent.com/The-Privacy-Commons-Institute/chrome-mal-ids/master/data/current-list-meta.csv"
with urllib.request.urlopen(url) as r:
    rows = list(csv.DictReader(line.decode() for line in r))

# Check a specific ID
target = "your_extension_id_here"
match  = next((r for r in rows if r["EXTID"] == target), None)
if match:
    print(f"MALICIOUS: {match['EXTID-NAME']} — {match['THREAT-TYPE']}")
```

---

## Statistics

**Live, auto-generated statistics — total IOC count, verified vs. third-party
split, campaign breakdown, threat type breakdown, contribution methods, and
currently monitored sources — are maintained in [STATS.md](STATS.md), not
duplicated here.** STATS.md regenerates automatically as part of the commit
pipeline, so it reflects the database's actual current state rather than a
number frozen at whatever point this README was last edited.

---

## TPCI-V Verification

All entries in this database are subject to ongoing verification using the
**TPCI-V multi-stage verification protocol** developed by
[The Privacy Commons Institute](https://tpc.institute).

| Stage | Method | Field |
|-------|--------|-------|
| Stage 1 | Source review and ingestion | `CONFIRM-MAL`, `REPORTED-MAL` |
| Stage 2 | Chrome CRX update API | `TPCI-VERIFY`, `STILL-ACTIVE` |
| Stage 3 | Headless browser store verification | `TPCI-VERIFY`, `STILL-ACTIVE` |
| Stage 4 | Identity continuity check | `TPCI-IDENTITY`, `TPCI-STORE-NAME` |
| Stage 5 | Behavioral analysis (static CRX) | `TPCI-BEHAVIORAL`, `TPCI-BEHAVIORAL-DATE` |

Full methodology: [tpc.institute](https://tpc.institute)

---

## Monitoring Sources

The database is updated by monitoring security research RSS feeds and GitHub repositories daily.

> **Current source list:** See [STATS.md](STATS.md#monitoring-sources) for the full auto-generated list — it stays in sync with the monitoring pipeline automatically.

Sources include blogs and publications from: Koi Security / Palo Alto, Bleeping Computer, The Hacker News, Krebs on Security, Sekoia, Palant's Blog, Secure Annex, Trustwave SpiderLabs, The Record, SecurityWeek, and several GitHub IOC aggregation repositories.

To suggest a new source, [open an issue](https://github.com/The-Privacy-Commons-Institute/chrome-mal-ids/issues).

---

### Reporting a new malicious extension

[Open an issue](https://github.com/The-Privacy-Commons-Institute/chrome-mal-ids/issues) with:
- Extension ID (32-char string from the Chrome Web Store URL)
- Extension name
- Source article or research post
- Brief description of the malicious behavior

### Data format

See [SCHEMA.md](SCHEMA.md) for the full field specification before submitting a PR.

---

## Coverage highlights

Some notable campaigns tracked in this list:

- **Cyberhaven Dec 2024** — supply chain attack on a legitimate security extension
- **DarkSpectre / ShadyPanda** — 36+ extensions, 7.8M infected browsers
- **Phoenix Invicta / Netflix Party** — 60+ extensions circumventing Manifest V3 restrictions
- **unknow.com spyware** — 57 extensions, 6M users, cookie theft and remote control
- **adindex ad fraud cluster** — RCE via Firebase, session replay for ad fraud
- **Koi RedDirection** — browser hijack campaign across Chrome and Edge
- **BIScience clickstream** — browsing history collection under false pretenses
- And many more — [browse the full list →](https://the-privacy-commons-institute.github.io/chrome-mal-ids)

---

## License

This dataset is licensed under **[CC BY 4.0](LICENSE.md)**.

You are free to use, share, and adapt this data for any purpose including commercially,
provided you give appropriate credit:

> Extension IOC data sourced from **chrome-mal-ids** by The Privacy Commons Institute 
> https://github.com/The-Privacy-Commons-Institute/chrome-mal-ids

See [LICENSE.md](LICENSE.md) for full terms.

---

*Maintained by [@mallorybowes](https://github.com/mallorybowes) /
[The Privacy Commons Institute](https://tpc.institute)*  
*Support this work: [tpc.institute/support](https://tpc.institute/support)*  
*Pipeline tooling built with [Claude](https://claude.ai) (Anthropic)*  
*Verification protocol: [TPCI-V](https://tpc.institute)*
