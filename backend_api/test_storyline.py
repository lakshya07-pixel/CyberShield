import unittest
from backend_api.storyline import generate_storyline_from_events, build_attack_storyline

class TestAttackStoryline(unittest.TestCase):
    def test_three_stage_chronological_progression(self):
        events = [
            {
                'source': 'sms',
                'indicators': ['http://sbi-online-banking-kyc.com/update-pan.html'],
                'threat_type': 'Urgent KYC Verification Scam',
                'severity': 'HIGH',
                'timestamp': '2026-11-01T00:10:00Z',
            },
            {
                'source': 'url',
                'indicators': ['host:sbi-online-banking-kyc.com'],
                'threat_type': 'Phishing Credential Harvester',
                'severity': 'HIGH',
                'timestamp': '2026-11-01T00:11:15Z',
            },
            {
                'source': 'network',
                'indicators': ['host:sbi-online-banking-kyc.com'],
                'threat_type': 'C2 Outbound Traffic / DNS Resolution',
                'severity': 'CRITICAL',
                'timestamp': '2026-11-01T00:13:30Z',
            },
        ]
        res = generate_storyline_from_events(events)
        self.assertTrue(res['success'])
        self.assertEqual(res['incident_count'], 1)
        story = res['storylines'][0]
        self.assertEqual(story['overall_severity'], 'CRITICAL')
        self.assertEqual(len(story['stages']), 3)
        self.assertEqual(story['stages'][0]['source'], 'sms')
        self.assertEqual(story['stages'][1]['source'], 'url')
        self.assertEqual(story['stages'][2]['source'], 'network')
        self.assertIn('sbi-online-banking-kyc.com', story['simple_explanation']['evidence'])

    def test_unrelated_events_produce_no_storylines(self):
        events = [
            {'source': 'sms', 'indicators': ['http://malicious-a.com'], 'severity': 'HIGH'},
            {'source': 'url', 'indicators': ['http://malicious-b.com'], 'severity': 'HIGH'},
        ]
        res = generate_storyline_from_events(events)
        self.assertTrue(res['success'])
        self.assertEqual(res['incident_count'], 0)
        self.assertEqual(len(res['storylines']), 0)

if __name__ == '__main__':
    unittest.main()
