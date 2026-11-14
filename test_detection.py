"""Run with: python3 -m unittest discover -s tests -v"""
import unittest
from pathlib import Path
from soc_lab.detections import (load_csv, run_all, password_spray,
                                spray_followed_by_success, suspicious_powershell,
                                privileged_group_changes)

ROOT = Path(__file__).resolve().parents[1]


class SOCDetectionsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.signins = load_csv(ROOT / 'data' / 'signin_logs.csv')
        cls.windows = load_csv(ROOT / 'data' / 'windows_events.csv')

    def test_spray_detects_multi_account_pattern(self):
        alerts = password_spray(self.signins)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]['evidence']['ip'], '198.51.100.45')
        self.assertGreaterEqual(alerts[0]['evidence']['distinct_users'], 5)

    def test_single_user_typo_does_not_trigger_spray(self):
        alerts = password_spray(self.signins)
        self.assertNotIn('203.0.113.20', [a['evidence']['ip'] for a in alerts])

    def test_spray_followed_by_success(self):
        alerts = spray_followed_by_success(self.signins, password_spray(self.signins))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]['evidence']['account'], 'admin@example.test')

    def test_encoded_powershell_flags_only_suspicious_marker(self):
        alerts = suspicious_powershell(self.windows)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]['evidence']['host'], 'WS-ENG-01')

    def test_group_addition_detected(self):
        alerts = privileged_group_changes(self.windows)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]['evidence']['group'], 'Domain Admins')

    def test_total_lab_alerts(self):
        alerts = run_all(self.signins, self.windows)
        self.assertEqual(len(alerts), 4)
        self.assertEqual([a['severity'] for a in alerts], ['Critical', 'High', 'High', 'Medium'])


if __name__ == '__main__':
    unittest.main()
