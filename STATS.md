# Malicious Chrome Extension IOC Database — Statistics

> Auto-generated 2026-09-02 16:49 UTC · [Full list](https://github.com/The-Privacy-Commons-Institute/chrome-mal-ids)

---

## Summary

| Metric | Count |
|--------|-------|
| Total malicious extensions | **6,757** |
| Unique campaigns | **34** |
| Entries without campaign attribution | **5,253** |
| Ownership transfer cases | **34** |
| Stubs — pending (ID confirmed, still searchable) | **0** |
| Stubs — exhausted (ID confirmed, enrichment attempted and unsuccessful) | **267** |
| Earliest discovery | **2017-08-17** |
| Most recent discovery | **2026-09-01** |

---

## By Browser

| Browser | Extensions |
|---------|-----------|
| Chrome | 6,615 (97.9%) |
| Edge | 129 (1.9%) |
| Both | 13 (0.2%) |

---

## By Threat Type

| Threat Type | Extensions |
|-------------|-----------|
| adware | 2,447 (36.2%) |
| unknown | 2,123 (31.4%) |
| data-theft | 2,016 (29.8%) |
| spyware | 1,460 (21.6%) |
| browser-hijack | 1,081 (16.0%) |
| click-fraud | 387 (5.7%) |
| credential-theft | 305 (4.5%) |
| session-hijack | 173 (2.6%) |
| malware | 135 (2.0%) |
| ownership-transfer | 29 (0.4%) |
| fake-extension | 29 (0.4%) |
| phishing | 27 (0.4%) |
| ai-chat-scraper | 4 (0.1%) |
| malvertising | 1 (0.0%) |

---

## Campaigns

A total of **34** distinct campaigns are tracked, covering **1,504** of 6,757 entries.

The remaining **5,253** entries carry a threat classification but no campaign attribution — typically bulk IOC-feed imports where the source recorded a category (adware, policy violation, search hijacking) rather than naming an operation. Their classification is preserved in `THREAT-TYPE`; they are excluded here because a category is not a campaign.

| Campaign | Extensions |
|----------|-----------|
| Socket Aug 2026 Myxa VPN campaign | 737 |
| DBX Tecnologia / Grupo OPT WhatsApp automation campaign | 125 |
| StegoAd campaign, microsoft research; THREAT-TYPE set at… | 107 |
| Palant Jun 2023 affiliate fraud cluster | 103 |
| Socket April 2026 MaaS campaign | 62 |
| YowGames cursor farm | 43 |
| DarkSpectre | 36 |
| Palant serasearchtop.com campaign | 34 |
| Part of Dec 2024 Cyberhaven supply chain campaign | 31 |
| TabPlugins cursor farm | 26 |
| ShadyPanda Phase 1/2 affiliate fraud + search hijacking | 22 |
| Phoenix Invicta | 20 |
| Chrome Wallpaper Adware Network | 20 |
| GitLab TamperedChef campaign | 16 |
| Krebs/Nguyen fake brand extension network | 16 |
| ShadyPanda Phase 4 Edge spyware | 14 |
| RedDirection campaign | 13 |
| Browser game extensions abusing broad host permissions | 13 |
| Krebs/Nguyen May 2021 fake brand extension network | 11 |
| adindex ad fraud campaign (Palant Feb 2025) | 10 |
| RedDirection / Koi Security Jul 2025 campaign | 8 |
| ShadyPanda Phase 3 RCE backdoor | 5 |
| McAfee affiliate fraud campaign | 4 |
| PCVARK malicious ad blocker cluster | 4 |
| Palant cluster C000003 — distinct subcluster within Jun… | 4 |
| ReasonLabs cashback killer campaign | 3 |
| Cyberhaven Dec 2024 OAuth phishing supply chain attack | 3 |
| Secure Annex unknow.com spyware campaign | 3 |
| Pixatab new tab hijacking cluster | 3 |
| BiScience/Urban Cybersecurity AI chat harvesting | 2 |
| AITOPIA impersonator campaign | 2 |
| SearchBlox Roblox backdoor | 2 |
| Dormant Colors campaign | 1 |
| VK Styles campaign | 1 |

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
| csv_import+ThreatType_Classified | 3,437 (50.9%) |
| Delta_Import+Store_Enrichment | 1,392 (20.6%) |
| Google_Search | 940 (13.9%) |
| csv_import | 515 (7.6%) |
| csv_import+ThreatType_Fallback | 129 (1.9%) |
| Delta_Import+Store_Enrichment+ThreatType_Classified | 113 (1.7%) |
| PDF_Import | 107 (1.6%) |
| AI_Enrichment | 40 (0.6%) |
| Delta_Import | 37 (0.5%) |
| Initial_Commit | 19 (0.3%) |
| Manual | 11 (0.2%) |
| Delta_Import+AI_Enrichment | 6 (0.1%) |
| Google_Search+ThreatType_Classified | 5 (0.1%) |
| Delta_Import+Store_Enrichment+ThreatType_Fallback | 5 (0.1%) |
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
