# AI-Powered Log Analyzer

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Gemini API](https://img.shields.io/badge/Gemini-Cloud-orange.svg)](https://ai.google.dev/gemini-api)
[![Ollama](https://img.shields.io/badge/Ollama-Local-cyan.svg)](https://ollama.ai)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Uses LLMs (cloud or local) to analyze log files and detect suspicious activity. Supports **Google Gemini** for cloud-based inference and **Ollama** for fully local, unlimited, privacy-first analysis.

## Features

- Synthetic log generation (no real data exposed)
- Batch analysis of multiple log files
- REST API with Swagger documentation
- Structured JSON output
- **Dual backend support** — switch between cloud (Gemini) and local (Ollama)

## Backend Options


| Backend            | Rate Limits                  | Internet Required | Cost | Best For                                 |
| ------------------ | ---------------------------- | ----------------- | ---- | ---------------------------------------- |
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

```bash
export GEMINI_KEY="your_api_key_here"
```

#### Option B: Ollama (Local — Recommended)

1. Install Ollama:

```bash
# Direct installation
curl -fsSL https://ollama.ai/install.sh | sh

# Or run with Docker
docker run -d -v ollama:/root/.ollama -p 11434:11434 --name ollama ollama/ollama
```

2. Pull a lightweight model (tested with log analysis):

```bash
ollama pull deepseek-coder:7b   # 776MB — minimal CPU impact
```

Alternative models: `phi3:mini`, `llama3.2:3b`, `qwen2.5:3b`

3. Verify Ollama is running:

```bash
curl http://localhost:11434/api/tags
```

4. Set the Ollama host (if not localhost):

```bash
export OLLAMA_HOST="http://localhost:11434"
```

### 3. Generate Synthetic Logs

```bash
python generate_logs.py
```

This creates `synthetic_logs/` directory with realistic-but-safe log files.

### 4. Run Analysis

**With Gemini (Cloud):**

```bash
python batch_analyze.py
```

**With Ollama (Local):**

```bash
python batch_analyze_ollama.py
```

## Example Output

### Console Output

```text
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
Errors: 8

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
  unknown: 8

⚠️  SUSPICIOUS LINES FOUND (15):
  [access_1.log:42] Invalid user deployer from 192.168.1.94
    → 2026-04-29 10:10:18 Invalid user deployer from 192.168.1.94 port 8080
  [access_1.log:87] Failed password for admin from 10.0.0.157
    → 2026-04-29 10:18:08 Failed password for admin from 10.0.0.157 port 8080 ssh2
  [access_2.log:23] Failed password for mwilson from 10.0.0.1
    → 2026-05-01 14:59:09 Failed password for mwilson from 10.0.0.1 port 8443 ssh2

💾 Full results saved to analysis_results.json
```

### JSON Output

```json
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
  },
  {
    "line_number": 87,
    "source_file": "access_1.log",
    "severity": "medium",
    "category": "application",
    "is_suspicious": false,
    "brief_reason": "API DELETE request failed with 503 error",
    "original_line": "2026-05-01 20:20:08 API request DELETE from 203.0.113.44 returned 503 in 1101ms",
    "analysis_timestamp": 1777704377.446939
  },
  {
    "line_number": 23,
    "source_file": "access_2.log",
    "severity": "medium",
    "category": "auth",
    "is_suspicious": true,
    "brief_reason": "Failed password for admin from 10.0.0.157",
    "original_line": "2026-04-29 10:18:08 Failed password for admin from 10.0.0.157 port 8080 ssh2",
    "analysis_timestamp": 1777704411.1136029
  }
]
```

## Project Structure

```
ai-log-analyzer/
├── generate_logs.py          # Creates synthetic log files
├── batch_analyze.py          # Gemini (cloud) batch processor
├── batch_analyze_ollama.py   # Ollama (local) batch processor
├── synthetic_logs/           # Generated logs (gitignored)
├── requirements.txt          # Python dependencies
└── README.md                 # This file
```

## Files Explained


| File                      | Purpose                                                                                      |
| ------------------------- | -------------------------------------------------------------------------------------------- |
| `generate_logs.py`        | Generates synthetic log files with realistic but fake data (RFC 5737 IPs, generic usernames) |
| `batch_analyze.py`        | Reads log files, sends each line to Google Gemini API, saves structured results              |
| `batch_analyze_ollama.py` | Same as above but uses local Ollama instead of cloud API                                     |
| `requirements.txt`        | Python package dependencies                                                                  |
| `synthetic_logs/`         | Directory containing generated`.log` files (gitignored)                                      |

## Optional: REST API Server

For programmatic access, an experimental FastAPI server is included:

```bash
python api_server.py
# Swagger UI: http://localhost:8000/docs
```


## Troubleshooting

### Rate Limits (Gemini)

If you see `429 RESOURCE_EXHAUSTED` errors:

- Free tier allows ~20 requests/day for `gemini-2.5-flash`
- Switch to Ollama for unlimited analysis
- Or wait 24 hours for quota reset

### Ollama Connection Issues

```bash
# Check if Ollama is running
systemctl status ollama

# Or for Docker
docker ps | grep ollama

# Test API directly
curl http://localhost:11434/api/generate -d '{"model": "deepseek-coder:7b", "prompt": "OK"}'

# For remote/LXC setups, ensure port 11434 is exposed
```

### Model Not Found

```bash
# List available models
ollama list

# Pull missing model
ollama pull deepseek-coder:7b
```

### JSON Parse Errors

If the model returns malformed JSON, the script will log the error and continue. This typically happens with:

- Very long log lines
- Unusual character encoding
- Model output truncation

## Security Note

All logs are **synthetically generated** using:

- RFC 5737 reserved IPs (`192.0.2.0/24`, `203.0.113.0/24`)
- Generic usernames (`admin`, `deployer`, `www-data`)
- No real PII, credentials, or system paths

For production use with real logs, **use the Ollama backend** to keep data entirely local and private.

## Requirements

Create `requirements.txt` with:

```text
google-genai>=0.3.0
ollama>=0.3.0
```

## License

MIT — free for personal, educational, and commercial use.

## Author

Zrubavel Sharon — [GitHub D3V9P5](https://github.com/D3V0P5/)

---

**Built with Python, Google Gemini, and Ollama**
