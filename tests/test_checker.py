import unittest
from io import BytesIO
from unittest.mock import patch

import checker


class CheckerTests(unittest.TestCase):
    def test_normalize_url_adds_https_and_rejects_spaces(self):
        self.assertEqual(checker.normalize_url("example.com"), "https://example.com")
        with self.assertRaises(ValueError):
            checker.normalize_url("https://example.com/bad path")

    def test_content_parser_extracts_suspicious_signals(self):
        soup = checker.BeautifulSoup(
            """
            <title>PayPal Security</title>
            <h1>Account suspended - verify immediately</h1>
            <p>Call support now.</p>
            <form action="https://evil.example/collect">
              <input type="password">
            </form>
            """,
            "html.parser",
        )
        signals = checker.analyze_content_signals(
            soup, "paypa1.example", "PayPal Security"
        )
        self.assertIn("account suspended", signals["urgency_phrases"])
        self.assertIn("call support", signals["support_scam_phrases"])
        self.assertEqual(signals["login_form_count"], 1)
        self.assertEqual(len(signals["external_form_actions"]), 1)
        self.assertIn("paypal", signals["brand_mismatch"])

    def test_scan_reads_bounded_response_and_caches_result(self):
        response = checker.requests.Response()
        response.status_code = 200
        response.url = "https://example.com/"
        response.history = []
        response.encoding = "utf-8"
        response.headers = {}
        response.raw = BytesIO(b"<html><title>Example</title><body>ok</body></html>")
        checker._scan_cache.clear()
        dns = {"resolved": True, "addresses": [], "mx_records": [], "error": None}
        whois = {
            "available": False,
            "created_at": None,
            "expires_at": None,
            "domain_age_days": None,
            "error": None,
        }
        with patch.object(checker, "inspect_dns", return_value=dns), \
                patch.object(checker, "inspect_whois_with_timeout", return_value=whois), \
                patch.object(checker.requests, "get", return_value=response) as request:
            first = checker.analyze_website("https://example.com")
            second = checker.analyze_website("https://example.com")
        self.assertTrue(first["success"])
        self.assertTrue(second["cache_hit"])
        self.assertEqual(request.call_count, 1)

    @patch.object(checker.socket, "getaddrinfo", return_value=[
        (checker.socket.AF_INET, checker.socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))
    ])
    def test_private_scan_targets_are_blocked(self, _getaddrinfo):
        result = checker.analyze_website("http://localhost")
        self.assertFalse(result["success"])
        self.assertEqual(result["error_type"], "ssrf_blocked")
        _getaddrinfo.assert_called_once()

    @patch.object(checker, "validate_scan_target")
    def test_redirect_hook_validates_destination(self, validate_target):
        response = checker.requests.Response()
        response.url = "https://example.com/start"
        response.headers = {"Location": "http://127.0.0.1/admin"}
        response.history = []
        checker.validate_redirect(response)
        validate_target.assert_called_once_with("http://127.0.0.1/admin")


if __name__ == "__main__":
    unittest.main()
