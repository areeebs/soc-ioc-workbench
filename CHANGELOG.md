# Changelog

## 0.1.0

- Normalize and defang URL, domain, IP, and file-hash indicators offline.
- Add explicit, read-only VirusTotal v3, AbuseIPDB check, and Shodan host lookups.
- Read provider keys from environment variables; summarize rather than echo full API responses.
- Block private/reserved indicators from external lookup and add mocked offline regression tests.
