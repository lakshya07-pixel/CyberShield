import unittest
from backend_api.geo_service import get_ip_geolocation

class TestGeoService(unittest.TestCase):
    def test_private_ips_have_no_location(self):
        privates = ['192.168.1.1', '10.0.0.5', '172.16.2.1', '127.0.0.1']
        for ip in privates:
            res = get_ip_geolocation(ip)
            self.assertIsNotNone(res)
            self.assertFalse(res['location_available'])
            self.assertIsNone(res['lat'])
            self.assertIsNone(res['lon'])

    def test_known_public_ip_mapping(self):
        res = get_ip_geolocation('198.51.100.24')
        self.assertIsNotNone(res)
        self.assertTrue(res['location_available'])
        self.assertEqual(res['city'], 'New Delhi')
        self.assertEqual(res['country'], 'India')
        self.assertTrue(res['is_approximate'])
        self.assertIn('Does not represent attacker physical location', res['attribution_disclaimer'])

    def test_invalid_ips_handled_safely(self):
        invalids = ['', 'not-an-ip', '999.999.999.999', None]
        for inv in invalids:
            res = get_ip_geolocation(inv)
            self.assertIsNone(res)

if __name__ == '__main__':
    unittest.main()
