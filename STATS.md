# Malicious Chrome Extension IOC Database — Statistics

> Auto-generated 2026-08-02 15:59 UTC · [Full list](https://github.com/The-Privacy-Commons-Institute/chrome-mal-ids)

---

## Summary

| Metric | Count |
|--------|-------|
| Total malicious extensions | **5,390** |
| Unique campaigns | **52** |
| Ownership transfer cases | **34** |
| Stubs — pending (ID confirmed, still searchable) | **800** |
| Stubs — exhausted (ID confirmed, enrichment attempted and unsuccessful) | **352** |
| Earliest discovery | **2017-08-17** |
| Most recent discovery | **2026-08-02** |

---

## By Browser

| Browser | Extensions |
|---------|-----------|
| Chrome | 5,248 (97.4%) |
| Edge | 129 (2.4%) |
| Both | 13 (0.2%) |

---

## By Threat Type

| Threat Type | Extensions |
|-------------|-----------|
| adware | 2,391 (44.4%) |
| unknown | 1,878 (34.8%) |
| data-theft | 1,116 (20.7%) |
| spyware | 782 (14.5%) |
| click-fraud | 331 (6.1%) |
| browser-hijack | 305 (5.7%) |
| credential-theft | 271 (5.0%) |
| session-hijack | 155 (2.9%) |
| ownership-transfer | 29 (0.5%) |
| fake-extension | 29 (0.5%) |
| phishing | 27 (0.5%) |
| malware | 16 (0.3%) |
| ai-chat-scraper | 4 (0.1%) |
| malvertising | 1 (0.0%) |

---

## Campaigns

A total of **52** distinct campaigns are tracked.

| Campaign | Extensions |
|----------|-----------|
| Adware | 1,552 |
| Stub entry imported from malicious_extension_sentry | 1,145 |
| Policy Violation | 413 |
| Unknown | 361 |
| Malware | 321 |
| “The reporter did not correlate the EXTID → EXTID-NAME | 230 |
| Bundling Unwanted Software | 220 |
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
| Dormant Colors campaign | 1 |
| *(+ 2 more)* | |

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
| csv_import+ThreatType_Classified | 2,721 (50.5%) |
| Google_Search | 945 (17.5%) |
| Delta_Import | 923 (17.1%) |
| Delta_Import+Store_Enrichment | 600 (11.1%) |
| PDF_Import | 107 (2.0%) |
| AI_Enrichment | 40 (0.7%) |
| Initial_Commit | 19 (0.4%) |
| csv_import+ThreatType_Fallback | 11 (0.2%) |
| Manual | 10 (0.2%) |
| Delta_Import+AI_Enrichment | 6 (0.1%) |
| Delta_Import+Store_Enrichment+ThreatType_Fallback | 5 (0.1%) |
| Delta_Import+Store_Enrichment+ThreatType_Classified | 2 (0.0%) |
| Delta_Import+Google_Search | 1 (0.0%) |

---

*Generated by [generate_stats.py](https://github.com/The-Privacy-Commons-Institute/chrome-mal-ids/blob/master/generate_stats.py)*
