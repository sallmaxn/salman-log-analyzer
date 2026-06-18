# 🔍 salman-log-analyzer

An intelligent log processing and anomaly detection system built with Python.
Parses web server (Apache/Nginx) and application logs, detects patterns, surfaces anomalies, and generates structured reports.

---

## 🚀 Features

- **Multi-format parsing** — handles Apache/Nginx combined logs and application logs (INFO/WARNING/ERROR/CRITICAL)
- **Anomaly detection** — automatically flags slow requests, high error rates, and brute-force patterns
- **Pattern analysis** — top endpoints, top IPs, most frequent errors
- **Response time analysis** — average response times and slow request identification
- **JSON report export** — save structured reports for downstream processing
- **Unit tested** — full test coverage with pytest

---

## 📁 Project Structure

```
salman-log-analyzer/
├── main.py                    # Entry point
├── generate_sample_logs.py    # Generate test data
├── requirements.txt
├── src/
│   └── log_analyzer.py        # Core engine (parser, detector, analyzer)
├── logs/
│   └── sample/                # Sample log files (auto-generated)
├── reports/                   # JSON reports output here
└── tests/
    └── test_analyzer.py       # Unit tests
```

---

## ⚙️ Setup & Usage

### 1. Clone and install

```bash
git clone https://github.com/salmanparis/salman-log-analyzer.git
cd salman-log-analyzer
pip install -r requirements.txt
```

### 2. Generate sample logs (first time)

```bash
python generate_sample_logs.py
```

### 3. Run analysis

```bash
# Analyze default sample web log
python main.py

# Analyze application log
python main.py --file logs/sample/app.log

# Analyze and save JSON report
python main.py --file logs/sample/web_server.log --save
```

### 4. Run tests

```bash
python -m pytest tests/ -v
```

---

## 📊 Sample Output

```
=======================================================
        📊 LOG ANALYSIS REPORT
=======================================================
  Total Entries   : 525
  Errors          : 47
  Warnings        : 12
  Critical Events : 2
  Avg Response    : 1823.4 ms

  Top Endpoints:
    142x  /api/users
     98x  /api/orders
     76x  /dashboard

  Anomaly Detection:
    🚨 Possible brute force from IP 45.33.32.156: 25 failed auth attempts
    ⚠️  31 slow requests detected (>2000ms)
    💀 2 CRITICAL events found — immediate attention needed
=======================================================
```

---

## 🧠 How It Works

1. **LogParser** reads each line and matches it against regex patterns for web and app log formats
2. **LogAnalyzer** aggregates the parsed entries — counting by severity, ranking endpoints and IPs, computing response time statistics
3. **AnomalyDetector** applies rule-based detection: slow request thresholds, 5xx error rate thresholds, and brute-force IP detection
4. Results are printed to the terminal and optionally saved as a JSON report

---

## 🛠️ Tech Stack

- **Python 3.9+** — standard library only (re, json, collections, dataclasses)
- **pytest** — unit testing

---

## 📚 What I Learned

- Designing clean data pipelines with Python dataclasses
- Writing robust regex patterns for real-world log formats
- Building rule-based anomaly detection systems
- Structuring Python projects for readability and testability
- Thinking like a data engineer: parse → aggregate → detect → report

---

## 👤 Author

**Salman Paris**
BSc Artificial Intelligence & Machine Learning
[LinkedIn](https://linkedin.com/in/salman-paris-6386103a3) . [GitHub](https://github.com/sallmaxn)
