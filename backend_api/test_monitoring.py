import unittest
import time
from backend_api.monitoring import MonitoringEngine, check_live_capture_capability

class TestMonitoringLifecycle(unittest.TestCase):
    def setUp(self):
        self.engine = MonitoringEngine()

    def tearDown(self):
        self.engine.stop()

    def test_start_stop_lifecycle(self):
        # 1. Start engine
        res_start = self.engine.start()
        self.assertEqual(res_start['status'], 'started')
        self.assertTrue(self.engine.get_status()['is_running'])

        # 2. Duplicate start is idempotent
        res_start2 = self.engine.start()
        self.assertEqual(res_start2['status'], 'already_running')

        # 3. Stop engine
        res_stop = self.engine.stop()
        self.assertEqual(res_stop['status'], 'stopped')
        self.assertFalse(self.engine.get_status()['is_running'])

        # 4. Duplicate stop is idempotent
        res_stop2 = self.engine.stop()
        self.assertEqual(res_stop2['status'], 'not_running')

    def test_add_and_retrieve_events(self):
        self.engine.add_event(
            source='network',
            event_type='syn_burst',
            severity='high',
            details='High packet burst',
            provenance='pcap_replay',
            indicators=['SYN flood']
        )
        status = self.engine.get_status()
        self.assertEqual(status['total_events'], 1)
        self.assertEqual(status['stats']['network_events'], 1)
        self.assertEqual(status['stats']['high_count'], 1)
        
        events = self.engine.get_events(limit=10)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['source'], 'network')
        self.assertEqual(events[0]['provenance'], 'pcap_replay')

    def test_live_capture_capability_check(self):
        cap = check_live_capture_capability()
        self.assertIn('available', cap)
        self.assertIn('provider', cap)
        # Npcap is known not installed on host, verify clean explanation
        if not cap['available']:
            self.assertIn('Npcap', cap['reason'])
            self.assertIn('remedy', cap)

if __name__ == '__main__':
    unittest.main()
