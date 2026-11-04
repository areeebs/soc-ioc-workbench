import json
import os
import urllib.parse
import unittest
from unittest.mock import patch

import soc_ioc


class FakeResponse:
    def __init__(self, payload):
        self.body = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, limit):
        return self.body


class SocIocTests(unittest.TestCase):
    def test_refangs_and_defangs_url_for_safe_sharing(self):
        indicator = soc_ioc.normalize_indicator("hxxps[://]example[.]com/a[.]b")
        self.assertEqual(indicator.kind, "url")
        self.assertEqual(indicator.value, "https://example.com/a.b")
        self.assertEqual(indicator.defanged, "hxxps[://]example[.]com/a[.]b")

    def test_normalizes_public_and_private_ips(self):
        self.assertTrue(soc_ioc.normalize_indicator("8.8.8.8").is_public)
        self.assertFalse(soc_ioc.normalize_indicator("192.168.1.10").is_public)
        self.assertFalse(soc_ioc.normalize_indicator("https://127.0.0.1/admin").is_public)
        self.assertFalse(soc_ioc.normalize_indicator("host.internal.example").is_public)

    def test_rejects_url_credentials_and_bad_hashes(self):
        for value in ("https://user:pass@example.com/", "not-a-hash-or-domain", "https://example.com:99999/"):
            with self.subTest(value=value), self.assertRaises(soc_ioc.WorkbenchError):
                soc_ioc.normalize_indicator(value)

    def test_virus_total_uses_get_and_unpadded_url_identifier(self):
        captured = {}
        payload = {"data": {"attributes": {"reputation": -3, "last_analysis_stats": {"malicious": 2, "harmless": 4}}}}

        def fake_open(request, timeout):
            captured["request"] = request
            captured["timeout"] = timeout
            return FakeResponse(payload)

        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-vt-key"}), patch.object(soc_ioc.urllib.request, "urlopen", side_effect=fake_open):
            result = soc_ioc.lookup_virustotal(soc_ioc.normalize_indicator("https://example.com/a?x=1"))
        request = captured["request"]
        parsed = urllib.parse.urlsplit(request.full_url)
        url_id = parsed.path.rsplit("/", 1)[-1]
        self.assertEqual(request.get_method(), "GET")
        self.assertNotIn("=", url_id)
        self.assertEqual(request.get_header("X-apikey"), "test-vt-key")
        self.assertEqual(result["last_analysis_stats"]["malicious"], 2)
        self.assertNotIn("test-vt-key", json.dumps(result))

    def test_virus_total_uses_hash_endpoint(self):
        sha256 = "a" * 64
        captured = {}

        def fake_open(request, timeout):
            captured["url"] = request.full_url
            return FakeResponse({"data": {"attributes": {"last_analysis_stats": {"malicious": 0}}}})

        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-vt-key"}), patch.object(soc_ioc.urllib.request, "urlopen", side_effect=fake_open):
            soc_ioc.lookup_virustotal(soc_ioc.normalize_indicator(sha256))
        self.assertIn(f"/files/{sha256}", captured["url"])

    def test_abuseipdb_sends_key_in_header_and_age_parameter(self):
        captured = {}

        def fake_open(request, timeout):
            captured["request"] = request
            return FakeResponse({"data": {"abuseConfidenceScore": 88, "totalReports": 7}})

        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test-abuse-key"}), patch.object(soc_ioc.urllib.request, "urlopen", side_effect=fake_open):
            result = soc_ioc.lookup_abuseipdb(soc_ioc.normalize_indicator("8.8.8.8"), 30)
        request = captured["request"]
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual(request.get_header("Key"), "test-abuse-key")
        self.assertIn("maxAgeInDays=30", request.full_url)
        self.assertEqual(result["abuse_confidence_score"], 88)

    def test_shodan_requests_minified_host_data(self):
        captured = {}

        def fake_open(request, timeout):
            captured["url"] = request.full_url
            return FakeResponse({"ports": [443], "org": "Example Org", "vulns": {"CVE-2024-0001": {}}})

        with patch.dict(os.environ, {"SHODAN_API_KEY": "test-shodan-key"}), patch.object(soc_ioc.urllib.request, "urlopen", side_effect=fake_open):
            result = soc_ioc.lookup_shodan(soc_ioc.normalize_indicator("8.8.8.8"))
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(captured["url"]).query)
        self.assertEqual(query["minify"], ["true"])
        self.assertEqual(query["key"], ["test-shodan-key"])
        self.assertEqual(result["ports"], [443])
        self.assertEqual(result["vulnerabilities"], ["CVE-2024-0001"])
        self.assertNotIn("test-shodan-key", json.dumps(result))

    def test_private_ip_is_blocked_before_any_external_request(self):
        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test-key"}), patch.object(soc_ioc.urllib.request, "urlopen") as mocked:
            with self.assertRaisesRegex(soc_ioc.WorkbenchError, "private or reserved"):
                soc_ioc.lookup_abuseipdb(soc_ioc.normalize_indicator("10.0.0.1"))
        mocked.assert_not_called()

    def test_missing_key_fails_before_network_request(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(soc_ioc.urllib.request, "urlopen") as mocked:
            with self.assertRaisesRegex(soc_ioc.WorkbenchError, "VIRUSTOTAL_API_KEY"):
                soc_ioc.lookup_virustotal(soc_ioc.normalize_indicator("example.com"))
        mocked.assert_not_called()

    def test_rate_limit_error_is_sanitized(self):
        error = soc_ioc.urllib.error.HTTPError("https://api.example/?key=secret", 429, "rate limited", {}, None)
        with patch.object(soc_ioc.urllib.request, "urlopen", side_effect=error):
            with self.assertRaises(soc_ioc.WorkbenchError) as caught:
                soc_ioc._get_json("https://api.example/?key=secret", {})
        self.assertIn("rate limit", str(caught.exception))
        self.assertNotIn("secret", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
