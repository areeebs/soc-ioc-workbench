# SOC IOC Workbench

A small, defensive command-line helper for normalizing one URL, domain, IP address, or file hash and optionally looking it up with one explicitly selected threat-intelligence provider.

> **Status:** Early intermediate learning project. Provider results are signals for an analyst to review; they are not a malicious/benign verdict.

## Why this scope

Mature SOC projects show the value of focused and interoperable tools: [Sigma](https://github.com/SigmaHQ/sigma) for portable detection rules (about 11.0k stars), [MISP](https://github.com/MISP/MISP) for threat-intelligence sharing (about 6.5k stars), and [YARA Rules](https://github.com/Yara-Rules/rules) for community signatures (about 4.9k stars), as observed on 2026-11-04. This project fills a smaller analyst workflow: safely normalize one IOC and make a deliberate, source-specific lookup without inventing a final verdict.

## Install

Requires Python 3.10 or newer. It uses only the Python standard library; no API key is required for local normalization.

## Local normalization

This command does not use the network:

```sh
python3 soc_ioc.py normalize 'hxxps[://]example[.]com/login?next=home' --json
```

It recognizes URLs, domains, IPv4/IPv6 addresses, and MD5/SHA-1/SHA-256-shaped hashes; refangs common `[.]`, `[:]`, and `hxxp` notations; and emits a defanged sharing form. Private IPs and reserved hostnames are marked as non-public.

## Explicit provider lookups

Each lookup queries only the provider named on the command line. API keys come from environment variables and are never printed:

```sh
export VIRUSTOTAL_API_KEY='your-own-key'
python3 soc_ioc.py lookup virustotal 'https://example.com/' --json

export ABUSEIPDB_API_KEY='your-own-key'
python3 soc_ioc.py lookup abuseipdb 8.8.8.8 --max-age-days 90

export SHODAN_API_KEY='your-own-key'
python3 soc_ioc.py lookup shodan 8.8.8.8 --json
```

Use your own keys, review each provider's current terms and quota, and query only information you are allowed to share. There is no automatic multi-provider fan-out, batch mode, file upload, port scan, or live target scan.

### Provider and privacy notes

- **VirusTotal:** uses read-only API v3 report endpoints for URLs, domains, IPs, and file hashes. VirusTotal documents a public API allowance of 4 requests per minute and 500 per day, and says the public API is not for commercial products/services. Its API documentation also warns that indicators queried through the API may be added to its dataset. Never look up confidential or personal URLs, internal domains, or other sensitive indicators. [API limits and use](https://docs.virustotal.com/reference/public-vs-premium-api) · [URL report endpoint](https://docs.virustotal.com/reference/url-info) · [data-sharing warning](https://docs.virustotal.com/reference/ip-info)
- **AbuseIPDB:** checks one public IP using its `/check` endpoint. The tool sends the key in the `Key` header and limits `max-age-days` to the documented 1–365 range. Check your account's live quota before repeated use. [API v2 documentation](https://docs.abuseipdb.com/)
- **Shodan:** uses the host-information endpoint with `minify=true`, which requests summary data without service banners. Shodan's API requires its key as a query parameter; the tool does not print the request URL, but local network/debug logs may record it. Shodan data reflects indexed observations and is not a live scan. [Shodan API](https://developer.shodan.io/api)

Provider lookups send the indicator to that provider. A URL can contain private IDs, reset tokens, or account data in its path or query. Do not submit such a URL. VirusTotal results may differ from commercial or premium products and can be stale or false-positive.

## Output and exit codes

- `normalize` returns a typed, canonical indicator and a defanged form; JSON includes `network_used: false`.
- `lookup` returns a small provider-specific summary rather than the entire provider response.
- Exit code `0` means a local normalization or provider response completed. Exit code `2` means invalid input, missing credentials, quota/access failure, or a network/provider error. A successful lookup does not mean the indicator is safe.

## Tests

The regression suite is offline and mocks every provider request:

```sh
python3 -m unittest discover -s tests -v
```

## Contributing

Use synthetic indicators and mocked provider responses. Do not commit real API keys, confidential indicators, or provider responses that reveal private data. See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).
