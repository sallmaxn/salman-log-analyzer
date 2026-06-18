"""
Unit tests for the Log Analyzer.
Run with:  python -m pytest tests/ -v
"""

import sys
import os
import unittest
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from log_analyzer import LogParser, AnomalyDetector, LogEntry


class TestLogParser(unittest.TestCase):

    def setUp(self):
        self.parser = LogParser()

    def test_parse_valid_web_log(self):
        line = '192.168.1.1 - - [01/Jun/2024:12:00:00 +0000] "GET /api/users HTTP/1.1" 200 1024 150'
        entry = self.parser.parse_line(line)
        assert entry is not None
        assert entry.ip == '192.168.1.1'
        assert entry.method == 'GET'
        assert entry.endpoint == '/api/users'
        assert entry.status_code == 200
        assert entry.level == 'INFO'
        assert entry.response_time_ms == 150.0

    def test_parse_500_error_web_log(self):
        line = '10.0.0.1 - - [01/Jun/2024:12:00:00 +0000] "POST /api/orders HTTP/1.1" 500 512 300'
        entry = self.parser.parse_line(line)
        assert entry is not None
        assert entry.status_code == 500
        assert entry.level == 'ERROR'

    def test_parse_valid_app_log(self):
        line = '2024-06-01 12:30:45 ERROR Database connection timeout'
        entry = self.parser.parse_line(line)
        assert entry is not None
        assert entry.level == 'ERROR'
        assert entry.message == 'Database connection timeout'
        assert entry.ip is None

    def test_parse_critical_app_log(self):
        line = '2024-06-01 09:00:00 CRITICAL Out of memory error'
        entry = self.parser.parse_line(line)
        assert entry is not None
        assert entry.level == 'CRITICAL'

    def test_parse_empty_line(self):
        assert self.parser.parse_line('') is None
        assert self.parser.parse_line('   ') is None

    def test_parse_garbage_line(self):
        assert self.parser.parse_line('this is not a log line!!!') is None


class TestAnomalyDetector(unittest.TestCase):

    def setUp(self):
        self.detector = AnomalyDetector()

    def _make_entry(self, level='INFO', status=200, ip='1.2.3.4',
                    endpoint='/api', response_time=100.0):
        return LogEntry(
            timestamp=datetime.now(),
            level=level,
            ip=ip,
            method='GET',
            endpoint=endpoint,
            status_code=status,
            response_time_ms=response_time,
            message='test',
            raw='raw line'
        )

    def test_no_anomalies_clean_log(self):
        entries = [self._make_entry() for _ in range(50)]
        result = self.detector.detect(entries)
        assert result == ['✅ No anomalies detected']

    def test_detects_slow_requests(self):
        entries = [self._make_entry(response_time=5000.0) for _ in range(5)]
        result = self.detector.detect(entries)
        assert any('slow requests' in r for r in result)

    def test_detects_critical_events(self):
        entries = [self._make_entry(level='CRITICAL') for _ in range(3)]
        result = self.detector.detect(entries)
        assert any('CRITICAL' in r for r in result)

    def test_detects_brute_force(self):
        entries = [self._make_entry(status=401, ip='99.99.99.99') for _ in range(25)]
        result = self.detector.detect(entries)
        assert any('brute force' in r.lower() for r in result)

    def test_detects_high_error_rate(self):
        entries = (
            [self._make_entry(status=500, level='ERROR') for _ in range(20)] +
            [self._make_entry() for _ in range(80)]
        )
        result = self.detector.detect(entries)
        assert any('error rate' in r.lower() for r in result)
if __name__ == '__main__': unittest.main()
