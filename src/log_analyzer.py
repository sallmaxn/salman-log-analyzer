"""
Log Analyzer - Core Analysis Engine
Author: Salman Paris
Description: Parses and analyzes web server and application logs
             to detect anomalies, errors, and usage patterns.
"""

import re
import json
from datetime import datetime
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import List, Optional


# ──────────────────────────────────────────────
# Data Models
# ──────────────────────────────────────────────

@dataclass
class LogEntry:
    timestamp: datetime
    level: str          # INFO, WARNING, ERROR, CRITICAL
    ip: Optional[str]
    method: Optional[str]
    endpoint: Optional[str]
    status_code: Optional[int]
    response_time_ms: Optional[float]
    message: str
    raw: str


@dataclass
class AnalysisReport:
    total_entries: int = 0
    error_count: int = 0
    warning_count: int = 0
    critical_count: int = 0
    top_endpoints: List = field(default_factory=list)
    top_errors: List = field(default_factory=list)
    top_ips: List = field(default_factory=list)
    avg_response_time_ms: float = 0.0
    slow_requests: List = field(default_factory=list)
    anomalies: List = field(default_factory=list)
    time_range: dict = field(default_factory=dict)


# ──────────────────────────────────────────────
# Parser
# ──────────────────────────────────────────────

class LogParser:
    """Parses multiple log formats into unified LogEntry objects."""

    # Apache/Nginx combined log format
    WEB_PATTERN = re.compile(
        r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+-\s+-\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<method>\w+)\s+(?P<endpoint>\S+)[^"]*"\s+'
        r'(?P<status>\d{3})\s+\d+\s*'
        r'(?P<response_time>\d+)?'
    )

    # Application log format: 2024-01-15 12:30:45 ERROR Message here
    APP_PATTERN = re.compile(
        r'(?P<timestamp>\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})\s+'
        r'(?P<level>INFO|WARNING|ERROR|CRITICAL|DEBUG)\s+'
        r'(?P<message>.+)'
    )

    def parse_line(self, line: str) -> Optional[LogEntry]:
        line = line.strip()
        if not line:
            return None

        # Try web log format
        m = self.WEB_PATTERN.match(line)
        if m:
            try:
                ts = datetime.strptime(m.group('timestamp'), '%d/%b/%Y:%H:%M:%S %z')
            except ValueError:
                ts = datetime.now()

            status = int(m.group('status'))
            level = 'ERROR' if status >= 500 else 'WARNING' if status >= 400 else 'INFO'
            rt = float(m.group('response_time')) if m.group('response_time') else None

            return LogEntry(
                timestamp=ts,
                level=level,
                ip=m.group('ip'),
                method=m.group('method'),
                endpoint=m.group('endpoint'),
                status_code=status,
                response_time_ms=rt,
                message=f"{m.group('method')} {m.group('endpoint')} → {status}",
                raw=line
            )

        # Try application log format
        m = self.APP_PATTERN.match(line)
        if m:
            try:
                ts = datetime.strptime(m.group('timestamp'), '%Y-%m-%d %H:%M:%S')
            except ValueError:
                ts = datetime.now()

            return LogEntry(
                timestamp=ts,
                level=m.group('level'),
                ip=None,
                method=None,
                endpoint=None,
                status_code=None,
                response_time_ms=None,
                message=m.group('message'),
                raw=line
            )

        return None

    def parse_file(self, filepath: str) -> List[LogEntry]:
        entries = []
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                entry = self.parse_line(line)
                if entry:
                    entries.append(entry)
        return entries


# ──────────────────────────────────────────────
# Anomaly Detector
# ──────────────────────────────────────────────

class AnomalyDetector:
    """Detects suspicious patterns and anomalies in log data."""

    SLOW_REQUEST_THRESHOLD_MS = 2000   # 2 seconds
    ERROR_SPIKE_THRESHOLD = 10         # errors per minute
    BRUTE_FORCE_THRESHOLD = 20         # failed requests per IP

    def detect(self, entries: List[LogEntry]) -> List[str]:
        anomalies = []

        # 1. Slow requests
        slow = [e for e in entries if e.response_time_ms and e.response_time_ms > self.SLOW_REQUEST_THRESHOLD_MS]
        if slow:
            anomalies.append(f"⚠️  {len(slow)} slow requests detected (>{self.SLOW_REQUEST_THRESHOLD_MS}ms)")

        # 2. High 5xx error rate
        errors_5xx = [e for e in entries if e.status_code and e.status_code >= 500]
        if len(entries) > 0:
            error_rate = len(errors_5xx) / len(entries) * 100
            if error_rate > 5:
                anomalies.append(f"🔴 High 5xx error rate: {error_rate:.1f}% of all requests")

        # 3. Brute force / IP flooding
        ip_errors = defaultdict(int)
        for e in entries:
            if e.ip and e.status_code in (401, 403):
                ip_errors[e.ip] += 1
        for ip, count in ip_errors.items():
            if count >= self.BRUTE_FORCE_THRESHOLD:
                anomalies.append(f"🚨 Possible brute force from IP {ip}: {count} failed auth attempts")

        # 4. Critical log messages
        criticals = [e for e in entries if e.level == 'CRITICAL']
        if criticals:
            anomalies.append(f"💀 {len(criticals)} CRITICAL events found — immediate attention needed")

        return anomalies if anomalies else ["✅ No anomalies detected"]


# ──────────────────────────────────────────────
# Analyzer (Main Engine)
# ──────────────────────────────────────────────

class LogAnalyzer:
    """Main analysis engine — orchestrates parsing, analysis, and reporting."""

    def __init__(self):
        self.parser = LogParser()
        self.detector = AnomalyDetector()

    def analyze(self, filepath: str) -> AnalysisReport:
        print(f"\n🔍 Analyzing: {filepath}")
        entries = self.parser.parse_file(filepath)
        print(f"   Parsed {len(entries)} log entries\n")

        if not entries:
            print("   No entries found.")
            return AnalysisReport()

        report = AnalysisReport()
        report.total_entries = len(entries)

        # Count by level
        level_counts = Counter(e.level for e in entries)
        report.error_count    = level_counts.get('ERROR', 0)
        report.warning_count  = level_counts.get('WARNING', 0)
        report.critical_count = level_counts.get('CRITICAL', 0)

        # Top endpoints
        endpoints = [e.endpoint for e in entries if e.endpoint]
        report.top_endpoints = Counter(endpoints).most_common(5)

        # Top error messages
        errors = [e.message for e in entries if e.level in ('ERROR', 'CRITICAL')]
        report.top_errors = Counter(errors).most_common(5)

        # Top IPs
        ips = [e.ip for e in entries if e.ip]
        report.top_ips = Counter(ips).most_common(5)

        # Response times
        times = [e.response_time_ms for e in entries if e.response_time_ms]
        if times:
            report.avg_response_time_ms = sum(times) / len(times)
            report.slow_requests = [
                e.endpoint for e in entries
                if e.response_time_ms and e.response_time_ms > AnomalyDetector.SLOW_REQUEST_THRESHOLD_MS
            ]

        # Time range
        timestamps = [e.timestamp for e in entries]
        report.time_range = {
            'start': str(min(timestamps)),
            'end':   str(max(timestamps))
        }

        # Anomaly detection
        report.anomalies = self.detector.detect(entries)

        return report

    def print_report(self, report: AnalysisReport):
        print("=" * 55)
        print("        📊 LOG ANALYSIS REPORT")
        print("=" * 55)
        print(f"  Total Entries   : {report.total_entries}")
        print(f"  Errors          : {report.error_count}")
        print(f"  Warnings        : {report.warning_count}")
        print(f"  Critical Events : {report.critical_count}")
        print(f"  Avg Response    : {report.avg_response_time_ms:.1f} ms")

        if report.time_range:
            print(f"\n  Time Range:")
            print(f"    From : {report.time_range['start']}")
            print(f"    To   : {report.time_range['end']}")

        if report.top_endpoints:
            print(f"\n  Top Endpoints:")
            for ep, count in report.top_endpoints:
                print(f"    {count:>5}x  {ep}")

        if report.top_ips:
            print(f"\n  Top IPs:")
            for ip, count in report.top_ips:
                print(f"    {count:>5}x  {ip}")

        if report.top_errors:
            print(f"\n  Top Errors:")
            for err, count in report.top_errors:
                print(f"    {count:>3}x  {err[:60]}")

        if report.slow_requests:
            print(f"\n  Slow Requests ({len(report.slow_requests)} total):")
            for ep in report.slow_requests[:5]:
                print(f"    ⏱  {ep}")

        print(f"\n  Anomaly Detection:")
        for a in report.anomalies:
            print(f"    {a}")

        print("=" * 55)

    def save_report(self, report: AnalysisReport, output_path: str):
        data = {
            'total_entries':      report.total_entries,
            'error_count':        report.error_count,
            'warning_count':      report.warning_count,
            'critical_count':     report.critical_count,
            'avg_response_ms':    round(report.avg_response_time_ms, 2),
            'top_endpoints':      report.top_endpoints,
            'top_errors':         report.top_errors,
            'top_ips':            report.top_ips,
            'slow_requests':      report.slow_requests,
            'anomalies':          report.anomalies,
            'time_range':         report.time_range,
            'generated_at':       datetime.now().isoformat()
        }
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        print(f"\n  💾 Report saved → {output_path}")
