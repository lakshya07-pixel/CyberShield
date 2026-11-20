import json
import unittest
from pathlib import Path
from fastapi.testclient import TestClient

from backend_api.main import app

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SAMPLES_DIR = PROJECT_ROOT / "threat_engine" / "samples"

client = TestClient(app)


class TestHealthEndpoint(unittest.TestCase):
    def test_health_check(self):
        response = client.get("/api/v1/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "healthy")
        self.assertEqual(data["service"], "CyberShield Threat Advisory API")
        self.assertEqual(data["engine_status"], "rule_based_active")
        self.assertIn("network_ids", data["detector_status"])
        self.assertIn("unavailable", data["detector_status"]["network_ids"])
        self.assertIn("unavailable", data["detector_status"]["url_phishing"])
        self.assertIn("unavailable", data["detector_status"]["sms_scam"])
        self.assertFalse(data["llama_status"]["enabled"])


class TestAdvisoryGenerateEndpoint(unittest.TestCase):
    def test_valid_advisory_samples(self):
        sample_files = ["intrusion.json", "phishing.json", "scam.json"]
        for sample_file in sample_files:
            file_path = SAMPLES_DIR / sample_file
            with self.subTest(sample=sample_file):
                with open(file_path, "r", encoding="utf-8") as f:
                    payload = json.load(f)

                response = client.post("/api/v1/advisory/generate", json=payload)
                self.assertEqual(response.status_code, 200)
                data = response.json()

                self.assertTrue(data["success"])
                self.assertEqual(data["calculated_severity"], "critical")
                self.assertIsInstance(data["explanation"], str)
                self.assertTrue(len(data["explanation"]) > 0)
                self.assertIsInstance(data["indicator_explanations"], list)
                self.assertEqual(
                    len(data["indicator_explanations"]), len(payload["indicators"])
                )
                self.assertIsInstance(data["recommendation"], str)
                self.assertTrue(len(data["recommendation"]) > 0)

                # Verify schema fields in threat_details
                details = data["threat_details"]
                self.assertEqual(details["source"], payload["source"])
                self.assertEqual(details["threat_type"], payload["threat_type"])
                self.assertEqual(details["severity"], "critical")
                self.assertEqual(details["confidence"], payload["confidence"])
                self.assertEqual(details["indicators"], payload["indicators"])
                self.assertFalse(data["llama_status"]["enabled"])

    def test_severity_thresholds(self):
        test_cases = [
            (0.0, "low"),
            (0.49, "low"),
            (0.50, "medium"),
            (0.74, "medium"),
            (0.75, "high"),
            (0.89, "high"),
            (0.90, "critical"),
            (1.0, "critical"),
        ]
        for confidence, expected_sev in test_cases:
            with self.subTest(confidence=confidence):
                payload = {
                    "source": "network",
                    "threat_type": "intrusion",
                    "confidence": confidence,
                    "indicators": ["port scanning"],
                }
                response = client.post("/api/v1/advisory/generate", json=payload)
                self.assertEqual(response.status_code, 200)
                data = response.json()
                self.assertEqual(data["calculated_severity"], expected_sev)
                self.assertEqual(data["threat_details"]["severity"], expected_sev)

    def test_invalid_confidence(self):
        invalid_values = [-0.1, 1.1, "very_high", True]
        for val in invalid_values:
            with self.subTest(invalid_confidence=val):
                payload = {
                    "source": "network",
                    "threat_type": "intrusion",
                    "confidence": val,
                    "indicators": [],
                }
                response = client.post("/api/v1/advisory/generate", json=payload)
                self.assertEqual(response.status_code, 422)

    def test_invalid_threat_type(self):
        invalid_types = ["ransomware", "trojan", "unknown_threat", ""]
        for t_type in invalid_types:
            with self.subTest(threat_type=t_type):
                payload = {
                    "source": "network",
                    "threat_type": t_type,
                    "confidence": 0.85,
                    "indicators": [],
                }
                response = client.post("/api/v1/advisory/generate", json=payload)
                self.assertEqual(response.status_code, 422)

    def test_malformed_requests(self):
        malformed_payloads = [
            {},  # completely empty
            {"source": "network"},  # missing threat_type, confidence
            {"threat_type": "intrusion", "confidence": 0.8},  # missing source
            {"source": "", "threat_type": "intrusion", "confidence": 0.8},  # empty source
        ]
        for payload in malformed_payloads:
            with self.subTest(payload=payload):
                response = client.post("/api/v1/advisory/generate", json=payload)
                self.assertEqual(response.status_code, 422)


class TestCorsHeaders(unittest.TestCase):
    def test_cors_preflight_allowed_origin(self):
        for origin in ["http://localhost:5173", "http://127.0.0.1:5173"]:
            with self.subTest(origin=origin):
                response = client.options(
                    "/api/v1/advisory/generate",
                    headers={
                        "Origin": origin,
                        "Access-Control-Request-Method": "POST",
                        "Access-Control-Request-Headers": "content-type",
                    },
                )
                self.assertEqual(response.status_code, 200)
                self.assertEqual(
                    response.headers.get("access-control-allow-origin"), origin
                )

    def test_cors_disallowed_origin(self):
        response = client.options(
            "/api/v1/advisory/generate",
            headers={
                "Origin": "http://malicious-website.com",
                "Access-Control-Request-Method": "POST",
            },
        )
        self.assertNotEqual(
            response.headers.get("access-control-allow-origin"),
            "http://malicious-website.com",
        )


class TestUnimplementedDetectorEndpoints(unittest.TestCase):
    def test_analyze_pcap_returns_501(self):
        response = client.post("/api/v1/threats/analyze-pcap")
        self.assertEqual(response.status_code, 501)
        self.assertIn("unavailable", response.json()["detail"].lower())

    def test_scan_url_returns_501(self):
        response = client.post("/api/v1/threats/scan-url")
        self.assertEqual(response.status_code, 501)
        self.assertIn("unavailable", response.json()["detail"].lower())

    def test_scan_sms_returns_501(self):
        response = client.post("/api/v1/threats/scan-sms")
        self.assertEqual(response.status_code, 501)
        self.assertIn("unavailable", response.json()["detail"].lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)

