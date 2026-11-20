import unittest
from backend_api.assistant import assistant_service

class TestSecurityAssistant(unittest.TestCase):
    def test_sms_threat_explanation(self):
        ctx = {
            'source': 'sms',
            'threat_type': 'scam',
            'attack_class': 'SCAM',
            'severity': 'HIGH',
            'confidence': 0.8949,
            'indicators': ['http://sbi-online-banking-kyc.com/update-pan.html', 'keyword: urgent verify']
        }
        res = assistant_service.query('Why was this SMS marked as suspicious?', ctx)
        self.assertTrue(res['grounded_in_telemetry'])
        self.assertTrue(res['detector_verdict_preserved'])
        self.assertIn('SCAM / SMISHING', res['answer'])
        self.assertIn('89.5%', res['answer'])
        self.assertIn('sbi-online-banking-kyc.com', res['answer'])

    def test_benign_sms_explanation(self):
        ctx = {
            'source': 'sms',
            'threat_type': 'benign',
            'attack_class': 'BENIGN',
            'severity': 'LOW',
            'confidence': 0.95,
            'indicators': []
        }
        res = assistant_service.query('Explain this message.', ctx)
        self.assertIn('BENIGN / SAFE', res['answer'])
        self.assertIn('95.0%', res['answer'])
        self.assertIn('No mitigation required', res['answer'])

    def test_phishing_url_explanation(self):
        ctx = {
            'source': 'url',
            'threat_type': 'phishing',
            'attack_class': 'PHISHING',
            'severity': 'HIGH',
            'confidence': 0.85,
            'indicators': ['host:sbi-online-banking-kyc.com', 'Missing HTTPS encryption']
        }
        res = assistant_service.query('Explain this phishing URL.', ctx)
        self.assertIn('PHISHING / DECEPTIVE DOMAIN', res['answer'])
        self.assertIn('sbi-online-banking-kyc.com', res['answer'])

    def test_network_intrusion_explanation(self):
        ctx = {
            'source': 'network',
            'threat_type': 'intrusion',
            'attack_class': 'SYN_FLOOD',
            'severity': 'CRITICAL',
            'confidence': 0.92,
            'indicators': ['Destination Port: 443', 'High SYN ratio']
        }
        res = assistant_service.query('What does this network alert mean?', ctx)
        self.assertIn('NETWORK INTRUSION DETECTED', res['answer'])
        self.assertIn('Destination Port: 443', res['answer'])

    def test_correlated_incident_explanation(self):
        ctx = {
            'incident_id': 'INC-CORR-SBI-ONLINE-BANKING-K',
            'severity': 'CRITICAL',
            'indicators': ['sbi-online-banking-kyc.com']
        }
        res = assistant_service.query('Explain this correlated attack.', ctx)
        self.assertIn('INC-CORR-SBI-ONLINE-BANKING-K', res['answer'])
        self.assertIn('Stage 1', res['answer'])
        self.assertIn('Stage 2', res['answer'])
        self.assertIn('Stage 3', res['answer'])

    def test_offline_fallback_indicator(self):
        res = assistant_service.query('What should I do next?')
        self.assertEqual(res['engine'], 'deterministic_expert_system')
        self.assertFalse(res['llama_status']['enabled'])
        self.assertIn('Recommended SOC Triage Playbook', res['answer'])

if __name__ == '__main__':
    unittest.main()
