"""
Generates realistic sample log files for testing the analyzer.
Run this once before running main.py.
"""

import random
import os
from datetime import datetime, timedelta

os.makedirs('logs/sample', exist_ok=True)

ENDPOINTS = ['/api/users', '/api/orders', '/api/products', '/login', '/dashboard', '/health']
IPS       = ['192.168.1.10', '192.168.1.22', '10.0.0.5', '203.0.113.42', '198.51.100.7']
METHODS   = ['GET', 'POST', 'PUT', 'DELETE']
STATUSES  = [200]*70 + [201]*10 + [400]*5 + [401]*4 + [403]*3 + [404]*5 + [500]*2 + [503]*1

# ── Web Server Log ──────────────────────────────────────
lines = []
ts = datetime(2024, 6, 1, 0, 0, 0)
for _ in range(500):
    ts += timedelta(seconds=random.randint(10, 120))
    ip     = random.choice(IPS)
    method = random.choice(METHODS)
    ep     = random.choice(ENDPOINTS)
    status = random.choice(STATUSES)
    rt     = random.randint(50, 5000)
    ts_str = ts.strftime('%d/%b/%Y:%H:%M:%S +0000')
    lines.append(f'{ip} - - [{ts_str}] "{method} {ep} HTTP/1.1" {status} 1024 {rt}')

# Inject brute force pattern from one IP
for _ in range(25):
    ts += timedelta(seconds=2)
    ts_str = ts.strftime('%d/%b/%Y:%H:%M:%S +0000')
    lines.append(f'45.33.32.156 - - [{ts_str}] "POST /login HTTP/1.1" 401 512 120')

with open('logs/sample/web_server.log', 'w') as f:
    f.write('\n'.join(lines))

# ── Application Log ─────────────────────────────────────
app_lines = []
ts = datetime(2024, 6, 1, 8, 0, 0)
APP_MESSAGES = {
    'INFO':     ['Server started on port 8080', 'Database connection established',
                 'Cache cleared successfully', 'User login successful'],
    'WARNING':  ['High memory usage detected: 85%', 'Slow query detected (1.8s)',
                 'Retry attempt 2/3 for payment service', 'Deprecated API endpoint called'],
    'ERROR':    ['Database connection timeout', 'Payment gateway returned 503',
                 'NullPointerException in OrderService.process()', 'Redis cache miss — falling back to DB'],
    'CRITICAL': ['Out of memory — JVM heap exceeded', 'Primary database unreachable']
}

for _ in range(300):
    ts += timedelta(seconds=random.randint(5, 60))
    level = random.choices(
        ['INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        weights=[70, 15, 12, 3]
    )[0]
    msg = random.choice(APP_MESSAGES[level])
    app_lines.append(f"{ts.strftime('%Y-%m-%d %H:%M:%S')} {level} {msg}")

with open('logs/sample/app.log', 'w') as f:
    f.write('\n'.join(app_lines))

print("✅ Sample logs generated:")
print("   logs/sample/web_server.log  (500 entries + brute force pattern)")
print("   logs/sample/app.log         (300 entries with errors & criticals)")
print("\nNow run:  python main.py")
print("       or: python main.py --file logs/sample/app.log --save")
