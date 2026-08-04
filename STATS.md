# Malicious Chrome Extension IOC Database — Statistics

> Auto-generated 2026-08-04 05:08 UTC · [Full list](https://github.com/The-Privacy-Commons-Institute/chrome-mal-ids)

---

## Summary

| Metric | Count |
|--------|-------|
| Total malicious extensions | **5,756** |
| Unique campaigns | **53** |
| Ownership transfer cases | **34** |
| Stubs — pending (ID confirmed, still searchable) | **780** |
| Stubs — exhausted (ID confirmed, enrichment attempted and unsuccessful) | **372** |
| Earliest discovery | **2017-08-17** |
| Most recent discovery | **2026-08-03** |

---

## By Browser

| Browser | Extensions |
|---------|-----------|
| Chrome | 5,614 (97.5%) |
| Edge | 129 (2.2%) |
| Both | 13 (0.2%) |

---

## By Threat Type

| Threat Type | Extensions |
|-------------|-----------|
| adware | 2,392 (41.6%) |
| unknown | 1,878 (32.6%) |
| data-theft | 1,140 (19.8%) |
| spyware | 1,134 (19.7%) |
| click-fraud | 332 (5.8%) |
| browser-hijack | 305 (5.3%) |
| credential-theft | 271 (4.7%) |
| session-hijack | 155 (2.7%) |
| ownership-transfer | 29 (0.5%) |
| fake-extension | 29 (0.5%) |
| malware | 29 (0.5%) |
| phishing | 27 (0.5%) |
| ai-chat-scraper | 4 (0.1%) |
| malvertising | 1 (0.0%) |

---

## Campaigns

A total of **53** distinct campaigns are tracked.

| Campaign | Extensions |
|----------|-----------|
| Adware | 1,552 |
| Stub entry imported from malicious_extension_sentry | 1,145 |
| Policy Violation | 428 |
| Unknown | 361 |
| Spyware | 348 |
| Malware | 323 |
| “The reporter did not correlate the EXTID → EXTID-NAME | 230 |
| Bundling Unwanted Software | 221 |
| Search Hijacking | 158 |
| DBX Tecnologia / Grupo OPT WhatsApp automation campaign | 125 |
| StegoAd campaign, microsoft research; THREAT-TYPE set at cam | 107 |
| Palant Jun 2023 affiliate fraud cluster | 103 |
| Stage 5A static analysis confirmed malicious behavior | 65 |
| Socket April 2026 MaaS campaign | 62 |
| Potentially Unwanted Software | 51 |
| Source: https://github | 46 |
| YowGames cursor farm | 43 |
| DarkSpectre | 36 |
| Palant serasearchtop | 34 |
| Part of Dec 2024 Cyberhaven supply chain campaign | 31 |
| TabPlugins cursor farm | 26 |
| “These extensions have not all been confirmed to be maliciou | 22 |
| ShadyPanda Phase 1/2 affiliate fraud + search hijacking | 22 |
| Two overlapping malicious extension clusters: Phoenix Invict | 20 |
| Chrome Wallpaper Adware Network | 20 |
| GitLab TamperedChef campaign | 16 |
| Krebs/Nguyen fake brand extension network | 16 |
| Stub entry imported from gnyman/chromium-mal-ids | 16 |
| ShadyPanda Phase 4 Edge spyware | 14 |
| RedDirection campaign | 13 |
| Browser game extensions abusing broad host permissions | 13 |
| Krebs/Nguyen May 2021 fake brand extension network | 11 |
| Search-Hijacker | 11 |
| adindex ad fraud campaign (Palant Feb 2025) | 10 |
| RedDirection / Koi Security Jul 2025 campaign | 8 |
| ShadyPanda Phase 3 RCE backdoor | 5 |
| Stub entry imported from toborrm9/malicious_extension_sentry | 5 |
| McAfee affiliate fraud campaign | 4 |
| PCVARK malicious ad blocker cluster | 4 |
| Palant cluster C000003 — distinct subcluster within Jun 2023 | 4 |
| ReasonLabs cashback killer campaign | 3 |
| Cyberhaven Dec 2024 OAuth phishing supply chain attack | 3 |
| Secure Annex unknow | 3 |
| Pixatab new tab hijacking cluster | 3 |
| In store but not whitelisted | 3 |
| BiScience/Urban Cybersecurity AI chat harvesting | 2 |
| AITOPIA impersonator campaign | 2 |
| SearchBlox Roblox backdoor | 2 |
| Critical Vulnerability | 2 |
| “The extension was ‘Offered by:  Extensions’ in the Chrome W | 1 |
| *(+ 3 more)* | |

---

## Monitoring Sources

The following sources are monitored daily for new malicious extension reports:

### RSS Feeds

| Source | Filter Keywords |
|--------|----------------|
| [Koi / Palo Alto Research](https://www.koi.ai/blog/rss.xml) | `chrome extension, browser extension, malicious extension, chrome web store, edge extension, web store` |
| [Bleeping Computer](https://www.bleepingcomputer.com/feed/) | `chrome extension, browser extension, malicious extension` |
| [The Hacker News](https://feeds.feedburner.com/TheHackersNews) | `chrome extension, browser extension, malicious extension` |
| [Krebs on Security](https://krebsonsecurity.com/feed/) | `extension, chrome web store` |
| [Sekoia Blog](https://blog.sekoia.io/feed/) | `chrome, extension` |
| [Palant's Blog](https://palant.info/rss.xml) | `chrome extension, browser extension, malicious extension, chrome web store` |
| [Secure Annex](https://secureannex.com/blog/rss.xml) | `*all posts*` |
| [Trustwave SpiderLabs](https://www.trustwave.com/en-us/rss/spiderlabs-blog.rss) | `chrome, extension, browser` |
| [The Record (Recorded Future)](https://therecord.media/feed) | `chrome extension, browser extension` |
| [SecurityWeek](https://feeds.feedburner.com/securityweek) | `chrome extension, browser extension, malicious extension` |

### GitHub Repositories

| Repository | Type |
|-----------|------|
| [palant/malicious-extensions-list commits](https://api.github.com/repos/palant/malicious-extensions-list) | commits |
| [chartingshow/crypto-firewall new issues](https://api.github.com/repos/chartingshow/crypto-firewall) | issues |
| [axon-git/rapid-response commits](https://api.github.com/repos/axon-git/rapid-response) | commits |

### CSV Sources

| Source | Contributor |
|--------|-------------|
| [toborrm9/malicious_extension_sentry](https://raw.githubusercontent.com/toborrm9/malicious_extension_sentry/main/malicious_extensions_detailed.csv) | @toborrm9 |

*10 RSS feeds · 3 GitHub repos · 1 CSV sources · edit via the review UI Sources tab*

---

## By Contribution Method

How entries entered the database — recurring monitored sources (RSS/GitHub/CSV, above) vs. one-off imports (PDF reports, manual rescue) vs. bulk/AI-assisted enrichment.

| Method | Extensions |
|--------|-----------|
| csv_import+ThreatType_Classified | 3,074 (53.4%) |
| Google_Search | 945 (16.4%) |
| Delta_Import | 923 (16.0%) |
| Delta_Import+Store_Enrichment | 600 (10.4%) |
| PDF_Import | 107 (1.9%) |
| AI_Enrichment | 40 (0.7%) |
| csv_import+ThreatType_Fallback | 24 (0.4%) |
| Initial_Commit | 19 (0.3%) |
| Manual | 10 (0.2%) |
| Delta_Import+AI_Enrichment | 6 (0.1%) |
| Delta_Import+Store_Enrichment+ThreatType_Fallback | 5 (0.1%) |
| Delta_Import+Store_Enrichment+ThreatType_Classified | 2 (0.0%) |
| Delta_Import+Google_Search | 1 (0.0%) |

### Component Glossary

Compound methods above (joined with `+`) mean more than one process touched that entry — e.g. `Delta_Import+Store_Enrichment+ThreatType_Classified` means it arrived via bulk import, then had its name/metadata resolved from the store listing, then got an AI-assigned threat category. Individual components:

| Component | Meaning |
|-----------|---------|
| `AI_Enrichment` | Metadata or classification added via AI-assisted research. |
| `Delta_Import` | Bulk incremental import from a continuously-updated external IOC feed. |
| `Google_Search` | Independently discovered and verified through manual web research. |
| `Initial_Commit` | Part of the batch entered when the project restarted in May 2026 — often carrying forward original discovery dates from years earlier (e.g. 2018-2019), reflecting when the extension was first documented, not when it entered this database. |
| `Manual` | Hand-entered by a human researcher outside the automated pipeline (e.g. a manual rescue of a record that failed automated processing). |
| `PDF_Import` | Extracted from a PDF-format threat research report. |
| `Store_Enrichment` | Name and metadata resolved by looking up the extension's Chrome/Edge Web Store listing. |
| `ThreatType_Classified` | Threat category successfully assigned via AI-based classification. |
| `ThreatType_Fallback` | AI classification was attempted but could not confidently assign a category. |
| `csv_import` | Extension ID sourced from an externally-provided CSV file. |

---

*Generated by [generate_stats.py](https://github.com/The-Privacy-Commons-Institute/chrome-mal-ids/blob/master/generate_stats.py)*
