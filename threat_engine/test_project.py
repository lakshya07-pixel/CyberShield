import json
import unittest
from pathlib import Path
from unittest.mock import patch

from severity import calculate_severity
from rules import get_threat_explanation, get_indicator_explanation
from recommendations import get_recommendation
from advisory import generate_advisory


PROJECT_DIR = Path(__file__).resolve().parent


class TestSeverity(unittest.TestCase):

    def test_severity_thresholds(self):
        self.assertEqual(calculate_severity(0.0), "low")
        self.assertEqual(calculate_severity(0.49), "low")
        self.assertEqual(calculate_severity(0.50), "medium")
        self.assertEqual(calculate_severity(0.75), "high")
        self.assertEqual(calculate_severity(0.90), "critical")
        self.assertEqual(calculate_severity(1.0), "critical")

    def test_invalid_confidence(self):
        for confidence in (-0.1, 1.1, "high", True):
            with self.subTest(confidence=confidence):
                with self.assertRaises(ValueError):
                    calculate_severity(confidence)


class TestRules(unittest.TestCase):

    def test_threat_explanations(self):
        for threat_type in ("phishing", "scam", "intrusion"):
            with self.subTest(threat_type=threat_type):
                explanation = get_threat_explanation(threat_type, [])
                self.assertIsInstance(explanation, str)
                self.assertTrue(explanation)

    def test_unknown_threat_explanation(self):
        self.assertTrue(get_threat_explanation("unknown", []))

    def test_indicator_explanations(self):
        result = get_indicator_explanation(["suspicious domain"])
        self.assertEqual(len(result), 1)
        self.assertIn("suspicious domain", result[0])


class TestRecommendations(unittest.TestCase):

    def test_recommendations(self):
        for threat_type in ("phishing", "scam", "intrusion", "unknown"):
            with self.subTest(threat_type=threat_type):
                recommendation = get_recommendation(threat_type)
                self.assertIsInstance(recommendation, str)
                self.assertTrue(recommendation)


class TestSampleFiles(unittest.TestCase):

    def test_sample_files(self):
        for filename in (
            "intrusion.json",
            "phishing.json",
            "scam.json",
        ):
            with self.subTest(filename=filename):
                path = PROJECT_DIR / "samples" / filename
                self.assertTrue(path.is_file())

                with path.open(encoding="utf-8") as file:
                    threat = json.load(file)

                self.assertIn("threat_type", threat)
                self.assertIn("confidence", threat)
                self.assertIn("indicators", threat)
                self.assertIsInstance(threat["indicators"], list)


class TestAdvisoryWorkflow(unittest.TestCase):

    def test_all_sample_advisories(self):
        for filename in (
            "intrusion.json",
            "phishing.json",
            "scam.json",
        ):
            with self.subTest(filename=filename):
                path = PROJECT_DIR / "samples" / filename

                with patch("builtins.print") as mock_print:
                    generate_advisory(str(path))

                output = "\n".join(
                    " ".join(str(arg) for arg in call.args)
                    for call in mock_print.call_args_list
                )

                self.assertIn("CYBER AI ADVISORY", output)
                self.assertIn("Threat Type", output)
                self.assertIn("Recommended Action:", output)
                self.assertIn(
                    "Llama output is disabled because it may contain unsupported claims.",
                    output,
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
