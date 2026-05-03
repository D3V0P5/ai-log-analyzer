#!/usr/bin/env python
import os
import json
import time
from pathlib import Path
from google import genai  # NEW SDK IMPORT
from google.genai import errors
from typing import Dict, Any

# Configure the NEW client
GEMINI_KEY = os.environ.get('GEMINI_KEY')

if not GEMINI_KEY:
    print("Error: Set GEMINI_KEY environment variable")
    exit(1)

# Initialize the new client
client = genai.Client(api_key=GEMINI_KEY)

def analyze_log_line_with_retry(line: str, line_num: int, file_name: str, max_retries: int = 5):
    """Call Gemini with automatic retry on rate limits"""
    
    import time
    import re
    
    prompt = f"""..."""  # Your existing prompt
    
    for attempt in range(max_retries):
        try:
            response = client.models.generate_content(
                model='gemini-2.0-flash', #gemini-2.5-flash-lite
                contents=prompt,
                config={'response_mime_type': 'application/json'}
            )
            # Parse success case (your existing success code)
            return json.loads(response.text.strip())
            
        except Exception as e:
            error_str = str(e)
            if '429' in error_str or 'RESOURCE_EXHAUSTED' in error_str:
                # Extract wait time from error message
                delay_match = re.search(r'retry in (\d+(?:\.\d+)?)s', error_str)
                wait_time = float(delay_match.group(1)) if delay_match else (2 ** attempt)
                
                print(f"  ⏳ Rate limited. Waiting {wait_time:.0f}s...")
                time.sleep(wait_time)
                # Continue to next retry
            else:
                # Non-rate-limit error
                return {'error': str(e), 'is_suspicious': None}
    
    return {'error': 'Max retries exceeded', 'is_suspicious': None}


def analyze_log_line(line: str, line_num: int, file_name: str) -> Dict[str, Any]:
    """Analyze a single log line using the NEW Gemini SDK."""
    
    # Your prompt remains exactly the same
    prompt = f"""
Analyze this log line and return ONLY valid JSON. No explanation, no markdown.

Log line: {line}

Return JSON with these exact fields:
- line_number (int)
- source_file (string)
- severity (one of: low, medium, high, critical)
- category (one of: auth, network, system, application, unknown)
- is_suspicious (boolean)
- brief_reason (string, max 50 chars)
"""

    try:
        # THE KEY CHANGE: Using the new client
        response = client.models.generate_content(
            model= 'gemini-2.5-flash', #,gemini-2.0-flash',  # Use a current model name
            contents=prompt,
            config={
                'response_mime_type': 'application/json',
            }
        )
        
        # The new SDK returns response.text directly
        text = response.text.strip()
        
        # Clean up markdown if present (same as before)
        if text.startswith('```json'):
            text = text[7:]
        if text.startswith('```'):
            text = text[3:]
        if text.endswith('```'):
            text = text[:-3]
        
        result = json.loads(text)
        result['original_line'] = line
        result['analysis_timestamp'] = time.time()
        return result
        
    except Exception as e:
        print(f"Error: {e}")  # Improved error logging
        return {
            'line_number': line_num,
            'source_file': file_name,
            'original_line': line,
            'error': str(e),
            'is_suspicious': None
        }


def analyze_log_file(file_path: Path, max_lines: int = None) -> List[Dict]:
    """Analyze all lines in a log file"""
    results = []
    
    with open(file_path, 'r') as f:
        lines = f.readlines()
    
    if max_lines:
        lines = lines[:max_lines]
    
    print(f"\n📁 Analyzing {file_path.name} ({len(lines)} lines)")
    
    for idx, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue
            
        print(f"  → Line {idx}...", end=' ', flush=True)
        result = analyze_log_line_with_retry(line, idx, file_path.name)
        if result.get('is_suspicious'):
            print(f"⚠️  SUSPICIOUS: {result.get('brief_reason', '')}")
        else:
            print(f"✓ {result.get('severity', 'unknown')}")
        
        results.append(result)
        time.sleep(30)  # Respect rate limits
    
    return results

def generate_summary(results: List[Dict]) -> Dict:
    """Generate summary statistics"""
    total = len(results)
    suspicious = sum(1 for r in results if r.get('is_suspicious') is True)
    errors = sum(1 for r in results if 'error' in r)
    
    severity_counts = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
    category_counts = {}
    
    for r in results:
        if r.get('severity') in severity_counts:
            severity_counts[r['severity']] += 1
        cat = r.get('category', 'unknown')
        category_counts[cat] = category_counts.get(cat, 0) + 1
    
    return {
        'total_lines': total,
        'suspicious_lines': suspicious,
        'suspicious_percentage': (suspicious / total * 100) if total > 0 else 0,
        'error_count': errors,
        'severity_distribution': severity_counts,
        'category_distribution': category_counts
    }

def save_results(results: List[Dict], output_file: str = 'analysis_results.json'):
    """Save results to JSON"""
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\n💾 Full results saved to {output_file}")

# Main execution
if __name__ == '__main__':
    print("🔍 Log Analysis Tool with Gemini AI")
    print("=" * 40)
    
    # Find log files
    log_dir = Path('synthetic_logs')
    if not log_dir.exists():
        print("Error: Run generate_logs.py first")
        exit(1)
    
    log_files = list(log_dir.glob('*.log'))
    print(f"Found {len(log_files)} log files")
    
    all_results = []
    
    # Analyze each file (limit lines for demo)
    for log_file in log_files:
        results = analyze_log_file(log_file, max_lines=10)  # Start with 10 lines per file
        all_results.extend(results)
    
    # Generate and display summary
    summary = generate_summary(all_results)
    
    print("\n" + "=" * 40)
    print("📊 ANALYSIS SUMMARY")
    print("=" * 40)
    print(f"Total lines analyzed: {summary['total_lines']}")
    print(f"Suspicious lines: {summary['suspicious_lines']} ({summary['suspicious_percentage']:.1f}%)")
    print(f"Errors: {summary['error_count']}")
    print(f"\nSeverity:")
    for sev, count in summary['severity_distribution'].items():
        print(f"  {sev}: {count}")
    print(f"\nCategories:")
    for cat, count in summary['category_distribution'].items():
        print(f"  {cat}: {count}")
    
    # Show suspicious lines
    suspicious_results = [r for r in all_results if r.get('is_suspicious') is True]
    if suspicious_results:
        print(f"\n⚠️  SUSPICIOUS LINES FOUND ({len(suspicious_results)}):")
        for r in suspicious_results[:5]:  # Show first 5
            print(f"  [{r['source_file']}:{r['line_number']}] {r['brief_reason']}")
            print(f"    → {r['original_line'][:100]}")
    
    # Save full results
    save_results(all_results)