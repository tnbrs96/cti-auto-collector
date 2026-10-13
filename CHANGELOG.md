# Changelog

## v4.0.0 — 2026-10-09

- Added multi-type collections from CERT Polska, Phishing.Database (URL and domain) and Phishunt domain feed.
- Expanded observable validation (MD5/SHA-1/SHA-256/SHA-512, domain:port); retained IP/CIDR/URL/IP:port handling.
- Added unique IOC index with provenance, source-group information, and separate CSV/Excel lists by type.
- Rebuilt correlations around *exact matches* with explicit distinctions between publishers and known aggregators.
- Added separate, non-corroborating IP-to-CIDR and URL-to-domain contextual relations.
- Expanded read-only VirusTotal lookups to domains and URLs, subject to permissions and quotas.
- Preserved existing standard-library-only reporting, source health checks, TLS checks and CISA KEV/EPSS separation.
- Added offline regression tests and reviewed output generation against the v3 data without packaging third-party feed data.
