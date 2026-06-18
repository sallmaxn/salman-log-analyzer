"""
salman-log-analyzer
Entry point — run this to analyze your log files.

Usage:
    python main.py                        # analyze sample logs
    python main.py --file path/to/log     # analyze a specific file
    python main.py --file app.log --save  # analyze + save JSON report
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))
from log_analyzer import LogAnalyzer


def main():
    parser = argparse.ArgumentParser(description='Salman Log Analyzer — AI-powered log analysis tool')
    parser.add_argument('--file', type=str, default='logs/sample/web_server.log',
                        help='Path to log file (default: logs/sample/web_server.log)')
    parser.add_argument('--save', action='store_true',
                        help='Save JSON report to reports/ directory')
    args = parser.parse_args()

    analyzer = LogAnalyzer()

    if not os.path.exists(args.file):
        print(f"❌ File not found: {args.file}")
        print("   Run: python generate_sample_logs.py  to create sample logs first.")
        sys.exit(1)

    report = analyzer.analyze(args.file)
    analyzer.print_report(report)

    if args.save:
        os.makedirs('reports', exist_ok=True)
        out = f"reports/report_{os.path.basename(args.file)}.json"
        analyzer.save_report(report, out)


if __name__ == '__main__':
    main()
