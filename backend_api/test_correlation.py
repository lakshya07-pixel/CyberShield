import unittest

try:
    from fastapi.testclient import TestClient
    from backend_api.main import app
    client = TestClient(app)
except Exception:
    from backend_api.main import app
    from backend_api.test_client_compat import SafeTestClient
    client = SafeTestClient(app)

from backend_api.correlation import (
    correlate_events,
    extract_canonical_indicators,
    normalize_indicator,
)


class TestCorrelationEngine(unittest.TestCase):
    def test_matches_shared_indicator_across_channels(self):
        events = [
            {"source": "network", "indicators": ["192.168.1.100"]},
            {"source": "url", "indicators": ["192.168.1.100"]},
            {"source": "sms", "indicators": ["different-indicator"]},
        ]

        result = correlate_events(events)

        self.assertEqual(result["correlated_group_count"], 1)
        group = result["correlated_groups"][0]
        self.assertEqual(group["shared_indicator"], "192.168.1.100")
        self.assertEqual(group["channels"], ["network", "url"])
        self.assertEqual(group["event_indexes"], [0, 1])

    def test_normalizes_case_and_whitespace(self):
        events = [
            {"source": "network", "indicators": ["  Example.COM  "]},
            {"source": "url", "indicators": ["example.com"]},
        ]

        result = correlate_events(events)

        self.assertEqual(result["correlated_group_count"], 1)
        self.assertEqual(
            result["correlated_groups"][0]["shared_indicator"],
            "example.com",
        )

    def test_sms_url_host_extraction_correlation(self):
        """Verify URL in SMS correlates with host indicator in URL detection."""
        events = [
            {
                "source": "sms",
                "indicators": ["http://sbi-online-banking-kyc.com/update-pan.html"],
                "severity": "HIGH",
            },
            {
                "source": "url",
                "indicators": ["host:sbi-online-banking-kyc.com"],
                "severity": "HIGH",
            },
        ]
        result = correlate_events(events)
        self.assertEqual(result["correlated_group_count"], 1)
        self.assertEqual(result["correlated_groups"][0]["shared_indicator"], "sbi-online-banking-kyc.com")
        self.assertEqual(result["correlated_groups"][0]["channels"], ["sms", "url"])

    def test_three_channel_incident_correlation(self):
        """Verify three distinct channels (SMS, URL, Network) form a single correlated incident."""
        events = [
            {
                "source": "sms",
                "indicators": ["http://sbi-online-banking-kyc.com/update-pan.html"],
                "severity": "HIGH",
            },
            {
                "source": "url",
                "indicators": ["host:sbi-online-banking-kyc.com"],
                "severity": "HIGH",
            },
            {
                "source": "network",
                "indicators": ["sbi-online-banking-kyc.com"],
                "severity": "CRITICAL",
            },
        ]
        result = correlate_events(events)
        self.assertEqual(result["correlated_group_count"], 1)
        group = result["correlated_groups"][0]
        self.assertEqual(group["shared_indicator"], "sbi-online-banking-kyc.com")
        self.assertEqual(group["channels"], ["network", "sms", "url"])
        self.assertEqual(group["priority"], "CRITICAL")
        self.assertEqual(group["event_count"], 3)

    def test_url_and_network_ip_port_correlation(self):
        """Verify IP with port from network flow correlates with IP literal URL."""
        events = [
            {"source": "url", "indicators": ["http://192.168.1.100/secure-bank-update/login.php"], "severity": "HIGH"},
            {"source": "network", "indicators": ["192.168.1.100:443"], "severity": "CRITICAL"},
        ]
        result = correlate_events(events)
        self.assertEqual(result["correlated_group_count"], 1)
        self.assertEqual(result["correlated_groups"][0]["shared_indicator"], "192.168.1.100")
        self.assertEqual(result["correlated_groups"][0]["priority"], "CRITICAL")

    def test_no_shared_indicator_returns_no_groups(self):
        events = [
            {"source": "network", "indicators": ["indicator-a"]},
            {"source": "url", "indicators": ["indicator-b"]},
        ]

        result = correlate_events(events)

        self.assertEqual(result["correlated_group_count"], 0)
        self.assertEqual(result["correlated_groups"], [])

    def test_same_channel_alone_does_not_correlate(self):
        events = [
            {"source": "network", "indicators": ["shared-value"]},
            {"source": "network", "indicators": ["shared-value"]},
        ]

        result = correlate_events(events)

        self.assertEqual(result["correlated_group_count"], 0)

    def test_rejects_unsupported_channel(self):
        events = [
            {"source": "email", "indicators": ["example.com"]},
        ]

        with self.assertRaises(ValueError):
            correlate_events(events)

    def test_rejects_more_than_500_events(self):
        events = [
            {"source": "network", "indicators": []}
            for _ in range(501)
        ]

        with self.assertRaises(ValueError):
            correlate_events(events)


class TestCorrelationEndpoint(unittest.TestCase):
    def test_endpoint_returns_shared_indicator_evidence(self):
        response = client.post(
            "/api/v1/correlation/analyze",
            json={
                "events": [
                    {
                        "source": "network",
                        "indicators": ["192.168.1.100"],
                    },
                    {
                        "source": "url",
                        "indicators": ["192.168.1.100"],
                    },
                ]
            },
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["correlated_group_count"], 1)
        self.assertEqual(
            data["correlated_groups"][0]["channels"],
            ["network", "url"],
        )
        self.assertIn("not proof", data["correlated_groups"][0]["interpretation"])

    def test_endpoint_rejects_unsupported_channel(self):
        response = client.post(
            "/api/v1/correlation/analyze",
            json={
                "events": [
                    {"source": "email", "indicators": ["example.com"]}
                ]
            },
        )

        self.assertEqual(response.status_code, 422)

    def test_endpoint_rejects_over_500_events(self):
        response = client.post(
            "/api/v1/correlation/analyze",
            json={
                "events": [
                    {"source": "network", "indicators": []}
                    for _ in range(501)
                ]
            },
        )

        self.assertEqual(response.status_code, 422)


if __name__ == "__main__":
    unittest.main(verbosity=2)
