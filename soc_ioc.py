#!/usr/bin/env python3
"""Normalize one IOC locally or explicitly query a selected threat-intel provider."""

from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from typing import Any


VERSION = "0.1.0"
TIMEOUT_SECONDS = 15
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
LOCAL_SUFFIXES = (".localhost", ".local", ".internal", ".test", ".invalid", ".example", ".onion")


class WorkbenchError(ValueError):
    """Input, configuration, or provider error safe to show to the user."""


@dataclass(frozen=True)
class Indicator:
    kind: str
    value: str
    defanged: str
    is_public: bool | None


def _refang(value: str) -> str:
    text = value.strip().strip("\"'")
    text = text.replace("[://]", "://").replace("[:]", ":").replace("[.]", ".").replace("(.)", ".")
    text = re.sub(r"(?i)^hxxps(?=://)", "https", text)
    text = re.sub(r"(?i)^hxxp(?=://)", "http", text)
    if "://" not in text and "/" in text and not text.startswith("/"):
        text = "http://" + text
    return text


def _domain(value: str) -> str:
    candidate = value.rstrip(".")
    try:
        hostname = candidate.encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise WorkbenchError("Domain is not valid IDNA text.") from error
    if len(hostname) > 253 or "." not in hostname:
        raise WorkbenchError("Enter a fully qualified domain name or a supported IOC.")
    labels = hostname.split(".")
    if any(not label or len(label) > 63 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) for label in labels):
        raise WorkbenchError("Domain contains an invalid DNS label.")
    return hostname


def _is_public_domain(hostname: str) -> bool:
    return not hostname.endswith(LOCAL_SUFFIXES)


def _defang(kind: str, value: str) -> str:
    text = value
    if kind == "url":
        text = re.sub(r"(?i)^https://", "hxxps[://]", text)
        text = re.sub(r"(?i)^http://", "hxxp[://]", text)
    return text.replace(".", "[.]")


def normalize_indicator(raw: str) -> Indicator:
    value = _refang(raw)
    if not value:
        raise WorkbenchError("Enter one URL, domain, IP address, or file hash.")

    if value.lower().startswith(("http://", "https://")):
        try:
            parsed = urllib.parse.urlsplit(value)
            host = parsed.hostname
            port = parsed.port
        except ValueError as error:
            raise WorkbenchError("URL is malformed.") from error
        if not host or parsed.username is not None or parsed.password is not None:
            raise WorkbenchError("URL must have a hostname and must not contain embedded credentials.")
        try:
            parsed_address = ipaddress.ip_address(host)
        except ValueError:
            parsed_address = None
        hostname = parsed_address.compressed if parsed_address else _domain(host)
        if port is not None and not 1 <= port <= 65535:
            raise WorkbenchError("URL port is outside the valid range.")
        if parsed.scheme.lower() not in {"http", "https"}:
            raise WorkbenchError("Only HTTP and HTTPS URLs are supported.")
        netloc = f"[{hostname}]" if isinstance(parsed_address, ipaddress.IPv6Address) else hostname
        if port is not None and not ((parsed.scheme.lower() == "http" and port == 80) or (parsed.scheme.lower() == "https" and port == 443)):
            netloc = f"{netloc}:{port}"
        normalized = urllib.parse.urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, parsed.fragment))
        is_public = parsed_address.is_global if parsed_address else _is_public_domain(hostname)
        return Indicator("url", normalized, _defang("url", normalized), is_public)

    if "://" in value:
        raise WorkbenchError("Only HTTP and HTTPS URLs are supported.")

    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        address = None
    if address is not None:
        normalized = address.compressed
        return Indicator("ip", normalized, _defang("ip", normalized), address.is_global)

    if re.fullmatch(r"(?i)[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}", value):
        return Indicator("hash", value.lower(), value.lower(), None)

    hostname = _domain(value)
    is_public = _is_public_domain(hostname)
    return Indicator("domain", hostname, _defang("domain", hostname), is_public)


def _api_key(env_name: str) -> str:
    value = os.environ.get(env_name, "").strip()
    if not value or "\n" in value or "\r" in value:
        raise WorkbenchError(f"Set {env_name} in your environment to use this provider.")
    return value


def _get_json(url: str, headers: dict[str, str]) -> dict[str, Any] | None:
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                raise WorkbenchError("Provider response exceeded the 2 MiB safety limit.")
            payload = json.loads(body.decode("utf-8"))
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        if error.code == 429:
            raise WorkbenchError("Provider rate limit or quota was reached. Check the account quota and retry later.") from None
        if error.code in {401, 403}:
            raise WorkbenchError(f"Provider denied the request (HTTP {error.code}); check the API key and account access.") from None
        raise WorkbenchError(f"Provider returned HTTP {error.code}.") from None
    except urllib.error.URLError:
        raise WorkbenchError("Provider connection failed. Check network access and try again.") from None
    except (TimeoutError, OSError):
        raise WorkbenchError("Provider connection failed or timed out.") from None
    except json.JSONDecodeError:
        raise WorkbenchError("Provider returned invalid JSON.") from None
    if not isinstance(payload, dict):
        raise WorkbenchError("Provider returned an unexpected JSON shape.")
    return payload


def _assert_public(indicator: Indicator) -> None:
    if indicator.is_public is False:
        raise WorkbenchError("External lookup is blocked for private or reserved indicators. Use local normalization only.")
    if indicator.is_public is None:
        return
    hostname = None
    if indicator.kind == "url":
        hostname = urllib.parse.urlsplit(indicator.value).hostname
    elif indicator.kind == "domain":
        hostname = indicator.value
    if hostname and not _is_public_domain(hostname):
        raise WorkbenchError("External lookup is blocked for local or reserved domains.")


def lookup_virustotal(indicator: Indicator) -> dict[str, Any]:
    _assert_public(indicator)
    key = _api_key("VIRUSTOTAL_API_KEY")
    if indicator.kind == "url":
        object_id = base64.urlsafe_b64encode(indicator.value.encode("utf-8")).decode("ascii").rstrip("=")
        collection = "urls"
    elif indicator.kind == "ip":
        collection = "ip_addresses"
        object_id = indicator.value
    elif indicator.kind == "domain":
        collection = "domains"
        object_id = indicator.value
    elif indicator.kind == "hash":
        collection = "files"
        object_id = indicator.value
    else:
        raise WorkbenchError("VirusTotal does not support this indicator type.")
    encoded_id = urllib.parse.quote(object_id, safe="")
    payload = _get_json(
        f"https://www.virustotal.com/api/v3/{collection}/{encoded_id}",
        {"x-apikey": key, "Accept": "application/json", "User-Agent": f"SOC-IOC-Workbench/{VERSION}"},
    )
    if payload is None:
        return {"provider": "virustotal", "found": False, "indicator": asdict(indicator)}
    data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
    attributes = data.get("attributes") if isinstance(data.get("attributes"), dict) else {}
    stats = attributes.get("last_analysis_stats") if isinstance(attributes.get("last_analysis_stats"), dict) else {}
    selected_stats = {key: stats.get(key, 0) for key in ("malicious", "suspicious", "harmless", "undetected", "timeout")}
    return {
        "provider": "virustotal",
        "found": bool(data),
        "indicator": asdict(indicator),
        "reputation": attributes.get("reputation"),
        "last_analysis_stats": selected_stats,
        "last_analysis_date": attributes.get("last_analysis_date"),
        "categories": attributes.get("categories", {}),
        "source_note": "Provider signals are not a verdict; review context and false positives.",
    }


def lookup_abuseipdb(indicator: Indicator, max_age_days: int = 90) -> dict[str, Any]:
    _assert_public(indicator)
    if indicator.kind != "ip":
        raise WorkbenchError("AbuseIPDB checks IP addresses only.")
    if not 1 <= max_age_days <= 365:
        raise WorkbenchError("AbuseIPDB max age must be from 1 to 365 days.")
    key = _api_key("ABUSEIPDB_API_KEY")
    query = urllib.parse.urlencode({"ipAddress": indicator.value, "maxAgeInDays": str(max_age_days)})
    payload = _get_json(
        f"https://api.abuseipdb.com/api/v2/check?{query}",
        {"Key": key, "Accept": "application/json", "User-Agent": f"SOC-IOC-Workbench/{VERSION}"},
    )
    if payload is None:
        return {"provider": "abuseipdb", "found": False, "indicator": asdict(indicator)}
    data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
    return {
        "provider": "abuseipdb",
        "found": bool(data),
        "indicator": asdict(indicator),
        "abuse_confidence_score": data.get("abuseConfidenceScore"),
        "total_reports": data.get("totalReports"),
        "last_reported_at": data.get("lastReportedAt"),
        "country_code": data.get("countryCode"),
        "usage_type": data.get("usageType"),
        "isp": data.get("isp"),
        "domain": data.get("domain"),
        "source_note": "Abuse reports are community signals and can be stale or context-dependent.",
    }


def lookup_shodan(indicator: Indicator) -> dict[str, Any]:
    _assert_public(indicator)
    if indicator.kind != "ip":
        raise WorkbenchError("Shodan host lookup accepts IP addresses only.")
    key = _api_key("SHODAN_API_KEY")
    query = urllib.parse.urlencode({"key": key, "minify": "true"})
    encoded_ip = urllib.parse.quote(indicator.value, safe="")
    payload = _get_json(
        f"https://api.shodan.io/shodan/host/{encoded_ip}?{query}",
        {"Accept": "application/json", "User-Agent": f"SOC-IOC-Workbench/{VERSION}"},
    )
    if payload is None:
        return {"provider": "shodan", "found": False, "indicator": asdict(indicator)}
    return {
        "provider": "shodan",
        "found": True,
        "indicator": asdict(indicator),
        "hostnames": payload.get("hostnames", []),
        "ports": payload.get("ports", []),
        "tags": payload.get("tags", []),
        "organization": payload.get("org"),
        "isp": payload.get("isp"),
        "country": payload.get("country_name"),
        "last_observed": payload.get("last_update"),
        "vulnerabilities": sorted(payload.get("vulns", {}).keys()) if isinstance(payload.get("vulns"), dict) else [],
        "source_note": "Shodan data describes indexed observations and is not a live scan or proof of current exposure.",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Normalize one IOC locally or explicitly query one threat-intel provider.")
    parser.add_argument("--version", action="version", version=f"SOC IOC Workbench {VERSION}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    normalize = subparsers.add_parser("normalize", help="Normalize or defang one indicator without network access")
    normalize.add_argument("indicator")
    normalize.add_argument("--json", action="store_true")

    lookup = subparsers.add_parser("lookup", help="Explicitly look up one indicator with one selected provider")
    lookup.add_argument("provider", choices=("virustotal", "abuseipdb", "shodan"))
    lookup.add_argument("indicator")
    lookup.add_argument("--max-age-days", type=int, default=90, help="AbuseIPDB report age window (1–365; default 90)")
    lookup.add_argument("--json", action="store_true")

    args = parser.parse_args(argv)
    try:
        indicator = normalize_indicator(args.indicator)
        if args.command == "normalize":
            result: dict[str, Any] = {"indicator": asdict(indicator), "network_used": False}
        elif args.provider == "virustotal":
            result = lookup_virustotal(indicator)
        elif args.provider == "abuseipdb":
            result = lookup_abuseipdb(indicator, args.max_age_days)
        else:
            result = lookup_shodan(indicator)
    except WorkbenchError as error:
        if getattr(args, "json", False):
            print(json.dumps({"error": str(error)}, indent=2))
        else:
            print(f"Error: {error}", file=sys.stderr)
        return 2

    if getattr(args, "json", False):
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(json.dumps(result, indent=2, sort_keys=True))
        if args.command == "lookup":
            print("Provider signals require analyst review; no malicious/benign verdict is inferred.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
