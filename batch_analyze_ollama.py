#!/usr/bin/env python
"""
Log Analysis Tool using Local Ollama
Analyzes log files and detects suspicious activity with structured output
"""

import os
import json
import time
from pathlib import Path
from typing import Dict, Any, Optional
import ollama

# ============================================================
# Configuration
# ============================================================
from pathlib import Path
# Load .env file if it exists
env_file = Path('.env')
if env_file.exists():
    with open(env_file) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                os.environ[key.strip()] = value.strip()

# Now get your variables 
#GEMINI_KEY = os.environ.get('GEMINI_KEY') # Not on this script 
OLLAMA_HOST = os.environ.get('OLLAMA_HOST', 'http://localhost:11434')
MODEL_NAME = os.environ.get('OLLAMA_MODEL', 'deepseek-coder:7b')  # Use 7b, not 'latest'

# Try to connect
try:
    client = ollama.Client(host=OLLAMA_HOST)
    client.list()
    print(f"✓ Connected to Ollama at {OLLAMA_HOST}")
    print(f"✓ Using model: {MODEL_NAME}")
except Exception as e:
    print(f"❌ Cannot connect to Ollama: {e}")
    exit(1)

# ============================================================
# Analysis Function with Improved Prompt
# ============================================================

def analyze_log_line(line: str, line_num: int, file_name: str) -> Dict[str, Any]:
    """Analyze a single log line using local Ollama model"""
    
    # Improved prompt with examples and strict instructions
    prompt = f"""You are a log analysis expert. Analyze this log line and return ONLY valid JSON.

Log line: {line}

Return a JSON object with these exact fields:
- "severity": one of "low", "medium", "high", "critical"
- "category": one of "auth", "network", "system", "application"
- "is_suspicious": true or false
- "brief_reason": short explanation (max 50 chars)

Examples:
Input: "Failed password for root from 203.0.113.89 port 22"
Output: {{"severity":"high","category":"auth","is_suspicious":true,"brief_reason":"Failed SSH login from external IP"}}

Input: "User jsmith logged in successfully from 10.0.0.5"
Output: {{"severity":"low","category":"auth","is_suspicious":false,"brief_reason":"Successful local login"}}

Input: "Connection closed by 192.168.1.100 port 22"
Output: {{"severity":"low","category":"network","is_suspicious":false,"brief_reason":"Normal connection close"}}

Now analyze this line: {line}

ONLY output valid JSON. No other text. No markdown. No explanation."""

    try:
        response = client.generate(
            model=MODEL_NAME,
            prompt=prompt,
            options={
                'temperature': 0.1,      # Low temperature for consistent output
                'num_predict': 200,      # Limit output length
                'stop': ['</s>', '```'], # Stop at markdown
            }
        )
        
        raw_text = response['response'].strip()
        
        # Clean up common issues
        if raw_text.startswith('```json'):
            raw_text = raw_text[7:]
        if raw_text.startswith('```'):
            raw_text = raw_text[3:]
        if raw_text.endswith('```'):
            raw_text = raw_text[:-3]
        
        # Try to extract JSON if surrounded by text
        import re
        json_match = re.search(r'\{[^{}]*\}', raw_text)
        if json_match:
            raw_text = json_match.group()
        
        result = json.loads(raw_text)
        
        # Validate and normalize fields
        severity = result.get('severity', 'low').lower()
        if severity not in ['low', 'medium', 'high', 'critical']:
            severity = 'low'
        
        category = result.get('category', 'unknown').lower()
        if category not in ['auth', 'network', 'system', 'application']:
            category = 'unknown'
        
        return {
            'line_number': line_num,
            'source_file': file_name,
            'original_line': line,
            'severity': severity,
            'category': category,
            'is_suspicious': bool(result.get('is_suspicious', False)),
            'brief_reason': result.get('brief_reason', 'No reason provided')[:50],
            'analysis_timestamp': time.time()
        }
        
    except json.JSONDecodeError as e:
        # Fallback: manual analysis based on keywords
        return manual_analysis_fallback(line, line_num, file_name, raw_text)
        
    except Exception as e:
        return {
            'line_number': line_num,
            'source_file': file_name,
            'original_line': line,
            'severity': 'unknown',
            'category': 'unknown',
            'is_suspicious': None,
            'brief_reason': f'Error: {str(e)[:40]}',
            'error': str(e),
            'analysis_timestamp': time.time()
        }

def manual_analysis_fallback(line: str, line_num: int, file_name: str, raw_response: str = '') -> Dict[str, Any]:
    """Fallback when JSON parsing fails - keyword-based analysis"""
    
    line_lower = line.lower()
    
    # Determine severity and suspicion
    suspicious = False
    severity = 'low'
    category = 'unknown'
    reason = ''
    
    # Auth related
    if any(word in line_lower for word in ['failed password', 'invalid user', 'authentication failure', 'pam_unix']):
        category = 'auth'
        suspicious = True
        severity = 'high'
        reason = 'Authentication failure'
        
        if 'root' in line_lower or 'admin' in line_lower:
            severity = 'critical'
            reason = 'Root/admin auth failure'
    
    # Successful auth
    elif 'accepted password' in line_lower:
        category = 'auth'
        suspicious = False
        severity = 'low'
        reason = 'Successful login'
    
    # Network
    elif any(word in line_lower for word in ['connection closed', 'port', 'firewall', 'allow', 'deny']):
        category = 'network'
        suspicious = 'deny' in line_lower or 'drop' in line_lower
        severity = 'medium' if suspicious else 'low'
        reason = 'Network connection event'
    
    # System
    elif any(word in line_lower for word in ['memory', 'backup', 'process', 'sudo', 'exceeded']):
        category = 'system'
        suspicious = 'exceeded' in line_lower or 'failed' in line_lower
        severity = 'high' if suspicious else 'low'
        reason = 'System event'
    
    # Application
    elif any(word in line_lower for word in ['api', 'request', 'get', 'post', 'delete', 'put', 'http']):
        category = 'application'
        suspicious = '503' in line or '500' in line or '401' in line or '403' in line
        severity = 'high' if suspicious else 'low'
        reason = 'Application request'
    
    else:
        reason = 'Unclassified log entry'
    
    return {
        'line_number': line_num,
        'source_file': file_name,
        'original_line': line,
        'severity': severity,
        'category': category,
        'is_suspicious': suspicious,
        'brief_reason': reason,
        'analysis_timestamp': time.time(),
        'fallback_used': True
    }

# ============================================================
# File Processing Functions
# ============================================================

def analyze_log_file(file_path: Path, max_lines: int = None, delay: float = 0.5) -> list:
    """Analyze all lines in a log file"""
    results = []
    
    with open(file_path, 'r') as f:
        lines = f.readlines()
    
    if max_lines:
        lines = lines[:max_lines]
    
    print(f"\n📁 Analyzing {file_path.name} ({len(lines)} lines)")
    print(f"   Using {MODEL_NAME} on Ollama")
    
    for idx, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue
        
        # Find timestamp and clean it
        parts = line.split(' ', 2)
        if len(parts) >= 2 and parts[0].startswith('202'):  # Year 202X
            clean_line = parts[2] if len(parts) > 2 else line
        else:
            clean_line = line
        
        print(f"  → Line {idx}...", end=' ', flush=True)
        
        result = analyze_log_line(clean_line, idx, file_path.name)
        
        if result.get('is_suspicious'):
            print(f"⚠️  {result.get('brief_reason', 'Suspicious')[:40]}")
        elif result.get('severity') and result['severity'] != 'unknown':
            print(f"✓ {result['severity']} - {result.get('brief_reason', '')[:30]}")
        elif result.get('fallback_used'):
            print(f"🟡 fallback: {result.get('brief_reason', '')[:30]}")
        else:
            print(f"? {result.get('severity', 'unknown')}")
        
        results.append(result)
        
        # Small delay to avoid overwhelming the model
        time.sleep(delay)
    
    return results

def generate_summary(results: list) -> Dict[str, Any]:
    """Generate summary statistics"""
    total = len(results)
    suspicious = sum(1 for r in results if r.get('is_suspicious') is True)
    fallback = sum(1 for r in results if r.get('fallback_used') is True)
    
    severity_counts = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
    category_counts = {}
    
    for r in results:
        sev = r.get('severity', 'unknown')
        if sev in severity_counts:
            severity_counts[sev] += 1
        
        cat = r.get('category', 'unknown')
        category_counts[cat] = category_counts.get(cat, 0) + 1
    
    return {
        'total_lines': total,
        'suspicious_lines': suspicious,
        'suspicious_percentage': (suspicious / total * 100) if total > 0 else 0,
        'fallback_lines': fallback,
        'severity_distribution': severity_counts,
        'category_distribution': category_counts
    }

def save_results(results: list, output_file: str = 'analysis_results_ollama.json'):
    """Save results to JSON"""
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\n💾 Full results saved to {output_file}")

# ============================================================
# Main Execution
# ============================================================

if __name__ == '__main__':
    print("🔍 Log Analysis Tool with Local Ollama")
    print("=" * 40)
    
    # Find log files
    log_dir = Path('synthetic_logs')
    if not log_dir.exists():
        print("❌ Error: synthetic_logs/ directory not found")
        print("   Run: python generate_logs.py first")
        exit(1)
    
    log_files = list(log_dir.glob('*.log'))
    print(f"Found {len(log_files)} log files")
    
    all_results = []
    
    # Analyze each file
    for log_file in sorted(log_files):
        results = analyze_log_file(log_file, max_lines=10)
        all_results.extend(results)
    
    # Generate and display summary
    summary = generate_summary(all_results)
    
    print("\n" + "=" * 40)
    print("📊 ANALYSIS SUMMARY")
    print("=" * 40)
    print(f"Total lines analyzed: {summary['total_lines']}")
    print(f"Suspicious lines: {summary['suspicious_lines']} ({summary['suspicious_percentage']:.1f}%)")
    print(f"Fallback (keyword) analysis used: {summary['fallback_lines']} lines")
    print(f"\nSeverity:")
    for sev, count in summary['severity_distribution'].items():
        if count > 0:
            print(f"  {sev}: {count}")
    print(f"\nCategories:")
    for cat, count in summary['category_distribution'].items():
        if count > 0:
            print(f"  {cat}: {count}")
    
    # Show suspicious lines
    suspicious_results = [r for r in all_results if r.get('is_suspicious') is True]
    if suspicious_results:
        print(f"\n⚠️  SUSPICIOUS LINES FOUND ({len(suspicious_results)}):")
        for r in suspicious_results[:10]:
            print(f"  [{r['source_file']}:{r['line_number']}] {r.get('brief_reason', 'No reason')}")
            print(f"    → {r['original_line'][:80]}")
    
    save_results(all_results)