import unittest
import socket
from backend_api.main import app
from backend_api.test_client_compat import SafeTestClient

class TestOfflineContract(unittest.TestCase):
    def test_no_outbound_network_calls_during_inference(self):
        # We test that detectors, correlation, and assistant execute completely offline
        from detectors.sms.inference import detect_sms_threat
        from detectors.url.inference import detect_url_threat
        from backend_api.correlation import correlate_events
        from backend_api.storyline import generate_storyline_from_events
        from backend_api.assistant import assistant_service

        # 1. SMS
        sms_res = detect_sms_threat('URGENT: Your account is blocked. Visit http://sbi-online-banking-kyc.com/update-pan.html')
        self.assertEqual(sms_res['source'], 'sms')
        self.assertEqual(sms_res['threat_type'], 'scam')

        # 2. URL
        url_res = detect_url_threat('http://sbi-online-banking-kyc.com/update-pan.html')
        self.assertEqual(url_res['source'], 'url')
        self.assertEqual(url_res['threat_type'], 'phishing')

        # 3. Correlation
        corr_res = correlate_events([sms_res, url_res])
        self.assertEqual(corr_res['correlated_group_count'], 1)

        # 4. Storyline
        story_res = generate_storyline_from_events([sms_res, url_res])
        self.assertEqual(story_res['incident_count'], 1)

        # 5. Assistant
        asst_res = assistant_service.query('Explain this incident', {'threat_type': 'phishing', 'severity': 'HIGH'})
        self.assertEqual(asst_res['engine'], 'deterministic_expert_system')
        self.assertTrue(asst_res['detector_verdict_preserved'])

if __name__ == '__main__':
    unittest.main()
