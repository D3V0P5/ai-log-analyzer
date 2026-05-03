# AI-Powered Log Analyzer

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Gemini API](https://img.shields.io/badge/Gemini-Cloud-orange.svg)](https://ai.google.dev/gemini-api)
[![Ollama](https://img.shields.io/badge/Ollama-Local-cyan.svg)](https://ollama.ai)
[![Tests](https://img.shields.io/badge/tests-22%20passed-brightgreen.svg)](tests/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Uses LLMs (cloud or local) to analyze log files and detect suspicious activity. Supports **Google Gemini** for cloud-based inference and **Ollama** for fully local, unlimited, privacy-first analysis.

## Features

- Synthetic log generation (no real data exposed)
- Batch analysis of multiple log files
- **REST API** with Swagger documentation
- Structured JSON output
- **Dual backend support** — switch between cloud (Gemini) and local (Ollama)
- **Unit tests** — 22 passing tests with coverage

## Backend Options

| Backend                  | Rate Limits                  | Internet Required | Cost | Best For                                 |
| ------------------------ | ---------------------------- | ----------------- | ---- | ---------------------------------------- |
| **Gemini (Cloud)** | ~20 requests/day (free tier) | Yes               | Free | Quick prototyping                        |
| **Ollama (Local)** | Unlimited                    | No                | Free | Batch processing, privacy-sensitive data |

## Setup

### 1. Clone & Install Dependencies

```bash
git clone https://github.com/D3V0P5/ai-log-analyzer.git
cd ai-log-analyzer
pip install -r requirements.txt
```

### 2. Choose Your Backend

#### Option A: Google Gemini (Cloud)

1. Get a free API key from [Google AI Studio](https://aistudio.google.com/)
2. Set your API key:

**bash**

```
export GEMINI_KEY="your_api_key_here"
```

#### Option B: Ollama (Local — Recommended)

1. Install Ollama:

**bash**

```
# Direct installation
curl -fsSL https://ollama.ai/install.sh | sh

# Or run with Docker
docker run -d -v ollama:/root/.ollama -p 11434:11434 --name ollama ollama/ollama
```

2. Pull a lightweight model (tested with log analysis):

**bash**

```
ollama pull qwen2.5-coder:7b   # 4.7GB — excellent for log analysis
```

Alternative models: `deepseek-coder:7b`, `phi3:mini`, `llama3.2:3b`

3. Verify Ollama is running:

**bash**

```
curl http://localhost:11434/api/tags
```

4. Set the Ollama host (if not localhost):

**bash**

```
export OLLAMA_HOST="http://localhost:11434"
```

### 3. Configure Environment

Copy the example environment file and add your API keys:

**bash**

```
cp .env.example .env
# Edit .env with your actual API keys
```

### 4. Generate Synthetic Logs

**bash**

```
python generate_logs.py
```

This creates `synthetic_logs/` directory with realistic-but-safe log files.

### 5. Run Analysis

#### With Gemini (Cloud):

**bash**

```
python batch_analyze.py
```

#### With Ollama (Local):

**bash**

```
python batch_analyze_ollama.py
```

#### Start REST API Server:

**bash**

```
python api_server.py
```

Then open Swagger UI: [http://localhost:8000/docs](http://localhost:8000/docs)

## Project Structure

**text**

```
ai-log-analyzer/
├── api_server.py               # FastAPI REST server with Swagger
├── batch_analyze.py            # Gemini (cloud) batch processor
├── batch_analyze_ollama.py     # Ollama (local) batch processor
├── generate_logs.py            # Synthetic log generator
├── requirements.txt            # Python dependencies
├── .env.example                # Environment variables template
├── .gitignore                  # Git ignore rules
├── README.md                   # This file
├── synthetic_logs/             # Generated logs (gitignored)
├── tests/
│   ├── requirements-test.txt   # Test dependencies
│   ├── test_ollama_parser.py   # Parser and fallback tests (13 tests)
│   ├── test_api_server.py      # API endpoint tests (5 tests)
│   ├── test_log_analyzer.py    # Integration tests (4 tests)
│   └── test_generate_logs.py   # Log generation tests (placeholder)
└── .venv/                      # Virtual environment (gitignored)
```

## Files Explained

| File                        | Purpose                                                                                                                   |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `api_server.py`           | REST API server with Swagger documentation.<br />Endpoints:`/analyze`, /analyze/file `, `/analyze/batch `, `/health |
| `batch_analyze.py`        | Reads log files, sends each line to Google Gemini API, saves structured results                                           |
| `batch_analyze_ollama.py` | Same as above but uses local Ollama instead of cloud API.<br />Includes keyword fallback when JSON parsing fails          |
| `generate_logs.py`        | Generates synthetic log files with realistic but fake data (RFC 5737 IPs, generic usernames)                              |
| `requirements.txt`        | Python package dependencies:`br`, `ollama`, `fastapi`, `uvicorn`, `pytest`, `pytest-cov`                      |
| `tests/`                  | Unit tests for parsers, API endpoints, and fallback logic — 22 passing tests                                             |
| `synthetic_logs/`         | Directory containing generated `.log` files (gitignored)                                                                |
| `.env.example`            | Template for environment variables (`GEMINI_KEY`, `OLLAMA_HOST`, `OLLAMA_MODEL`)                                    |

## API Endpoints (FastAPI)

When running `python api_server.py`, the following endpoints are available:

| Method | Endpoint           | Description                             |
| ------ | ------------------ | --------------------------------------- |
| GET    | `/`              | API information and available endpoints |
| GET    | `/health`        | Health check with backend status        |
| POST   | `/analyze`       | Analyze a single log line               |
| POST   | `/analyze/file`  | Upload and analyze a log file           |
| POST   | `/analyze/batch` | Analyze multiple log lines (max 20)     |

**Interactive documentation:** [http://localhost:8000/docs](http://localhost:8000/docs) (Swagger UI)

**Example API call:**

**bash**

```
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"line": "Failed password for root from 203.0.113.89 port 22"}'
```

## Running Tests

**bash**

```
# Install test dependencies
pip install -r tests/requirements-test.txt

# Run all tests
pytest tests/ -v

# Run with coverage report
pytest tests/ -v --cov=. --cov-report=term-missing
```

**Test output:**

**text**

```
==================== 22 passed in 0.73s ====================
```

## Example Output

### Console Output

**text**

```
🔍 Log Analysis Tool
========================================
📁 Analyzing access_1.log (150 lines)
  → Line 1... ⚠️  SUSPICIOUS: Invalid user deployer from 192.168.1.94
  → Line 2... ✓ medium
  → Line 3... ✓ low

========================================
📊 ANALYSIS SUMMARY
========================================
Total lines analyzed: 50
Suspicious lines: 15 (30.0%)
Errors: 0

Severity:
  low: 10
  medium: 18
  high: 14
  critical: 0

Categories:
  auth: 23
  application: 6
  system: 8
  network: 5

⚠️  SUSPICIOUS LINES FOUND (15):
  [access_1.log:42] Invalid user deployer from 192.168.1.94
    → 2026-04-29 10:10:18 Invalid user deployer from 192.168.1.94 port 8080

💾 Full results saved to analysis_results.json
```

### JSON Output

**json**

```
[
  {
    "line_number": 42,
    "source_file": "access_1.log",
    "severity": "high",
    "category": "auth",
    "is_suspicious": true,
    "brief_reason": "Invalid user deployer from 192.168.1.94",
    "original_line": "2026-04-29 10:10:18 Invalid user deployer from 192.168.1.94 port 8080",
    "analysis_timestamp": 1777704343.0129335
  }
]
```

## Troubleshooting

### Rate Limits (Gemini)

If you see `429 RESOURCE_EXHAUSTED` errors:

* Free tier allows \~20 requests/day for `gemini-2.5-flash`
* Switch to Ollama for unlimited analysis
* Or wait 24 hours for quota reset

### Ollama Connection Issues

**bash**

```
# Check if Ollama is running
systemctl status ollama

# Or for Docker
docker ps | grep ollama

# Test API directly
curl http://localhost:11434/api/generate -d '{"model": "qwen2.5-coder:7b", "prompt": "OK"}'
```

### Module Import Errors

If you see `ModuleNotFoundError`, install missing dependencies:

**bash**

```
pip install -r requirements.txt
pip install -r tests/requirements-test.txt
```

## Security Note

All logs are **synthetically generated** using:

* RFC 5737 reserved IPs (`192.0.2.0/24`, `203.0.113.0/24`)
* Generic usernames (`admin`, `deployer`, `www-data`)
* No real PII, credentials, or system paths

For production use with real logs, **use the Ollama backend** to keep data entirely local and private.

## License

MIT — free for personal, educational, and commercial use.

## Author

Zrubavel Sharon — [GitHub D3V9P5](https://github.com/D3V0P5/)




**Built with Python, Google Gemini, and Ollama**
