import unittest

import risk_score


class RiskScoreTests(unittest.TestCase):
    def base_analysis(self):
        return {
            "success": True,
            "url_data": {
                "is_https": True,
                "is_ip_address": False,
                "excessive_subdomains": False,
                "has_at_symbol": False,
                "is_long_url": False,
                "url_length": 20,
                "excessive_hyphens": False,
                "found_keywords": [],
            },
            "security_headers": {},
            "trust_pages": {},
            "redirect_count": 0,
            "status_code": 200,
            "original_url": "https://example.com",
            "final_url": "https://example.com",
            "content_signals": {},
        }

    def test_thresholds_and_categories_are_stable(self):
        result = risk_score.calculate_risk(self.base_analysis())
        self.assertIn(result["verdict"], {
            "Likely Trustworthy", "Needs Caution", "High Risk Indicators"
        })
        self.assertEqual(set(result["findings_by_category"]), set(risk_score.CATEGORY_NAMES))
        self.assertIn(result["confidence"], {"Low", "Medium", "High"})

    def test_insecure_login_is_critical(self):
        analysis = self.base_analysis()
        analysis["url_data"]["is_https"] = False
        analysis["has_password_field"] = True
        result = risk_score.calculate_risk(analysis)
        self.assertGreaterEqual(result["score"], 30)
        self.assertTrue(any(item["severity"] == "Critical" for item in result["findings"]))


if __name__ == "__main__":
    unittest.main()
