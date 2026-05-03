#!/usr/bin/env python
"""Tests for Ollama response parsing and fallback (NO API CALLS)"""

import sys
from pathlib import Path

# Add parent directory to import from batch_analyze_ollama
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import the pure logic functions (no API calls)
from batch_analyze_ollama import parse_model_response, keyword_fallback


class TestParseModelResponse:
    """Test JSON parsing from model responses"""

    def test_parse_valid_json(self):
        """Should parse valid JSON correctly"""
        raw = '{"severity":"high","category":"auth","is_suspicious":true,"brief_reason":"Failed login"}'
        
        result = parse_model_response(raw, 1, "test.log", "original line")
        
        assert result is not None
        assert result['severity'] == 'high'
        assert result['category'] == 'auth'
        assert result['is_suspicious'] is True
        assert result['brief_reason'] == 'Failed login'

    def test_parse_markdown_wrapped_json(self):
        """Should handle JSON wrapped in markdown code blocks"""
        raw = '```json\n{"severity":"medium","category":"network","is_suspicious":false,"brief_reason":"Normal"}\n```'
        
        result = parse_model_response(raw, 2, "test.log", "original")
        
        assert result is not None
        assert result['severity'] == 'medium'
        assert result['category'] == 'network'
        assert result['is_suspicious'] is False

    def test_parse_json_with_extra_text(self):
        """Should extract JSON even when surrounded by extra text"""
        raw = 'Here is my analysis: {"severity":"low","category":"system","is_suspicious":false,"brief_reason":"Backup completed"} Hope this helps!'
        
        result = parse_model_response(raw, 3, "test.log", "original")
        
        assert result is not None
        assert result['severity'] == 'low'
        assert result['category'] == 'system'

    def test_parse_invalid_json_returns_none(self):
        """Should return None for invalid JSON"""
        raw = 'This is not JSON at all just plain text'
        
        result = parse_model_response(raw, 4, "test.log", "original")
        
        assert result is None

    def test_parse_empty_response_returns_none(self):
        """Should return None for empty response"""
        result = parse_model_response("", 5, "test.log", "original")
        
        assert result is None

    def test_parse_invalid_severity_falls_back_to_low(self):
        """Should set invalid severity to 'low'"""
        raw = '{"severity":"invalid","category":"auth","is_suspicious":false,"brief_reason":"test"}'
        
        result = parse_model_response(raw, 6, "test.log", "original")
        
        assert result is not None
        assert result['severity'] == 'low'  # Fallback

    def test_parse_invalid_category_falls_back_to_unknown(self):
        """Should set invalid category to 'unknown'"""
        raw = '{"severity":"medium","category":"invalid","is_suspicious":false,"brief_reason":"test"}'
        
        result = parse_model_response(raw, 7, "test.log", "original")
        
        assert result is not None
        assert result['category'] == 'unknown'  # Fallback


class TestKeywordFallback:
    """Test keyword-based fallback analysis"""
    def test_system_event_detection(self):
        """Should detect system events"""
        line = "Process nginx (PID:1234) exceeded memory limit (2000MB > 1024MB)"
        
        result = keyword_fallback(line, 1, "test.log")
        
        # DEBUG: Print what we actually got
        print(f"\nDEBUG: result = {result}")
        
        assert result['category'] == 'system'

    def test_auth_failure_detection(self):
        """Should detect failed password attempts"""
        test_lines = [
            ("Failed password for root from 203.0.113.89", True, "auth", "high"),
            ("Invalid user admin from 192.168.1.1", True, "auth", "high"),
            ("authentication failure; logname=uid=0", True, "auth", "high"),
        ]
        
        for line, expected_suspicious, expected_category, expected_severity in test_lines:
            result = keyword_fallback(line, 1, "test.log")
            assert result['is_suspicious'] == expected_suspicious, f"Failed on: {line}"
            assert result['category'] == expected_category, f"Failed on: {line}"
            assert result['severity'] == expected_severity, f"Failed on: {line}"

    def test_successful_auth_detection(self):
        """Should detect successful logins as benign"""
        line = "Accepted password for jsmith from 10.0.0.5 port 22 ssh2"
        
        result = keyword_fallback(line, 1, "test.log")
        
        assert result['is_suspicious'] is False
        assert result['category'] == 'auth'
        assert result['severity'] == 'low'

    def test_network_event_detection(self):
        """Should detect network events"""
        line = "Connection closed by 192.168.1.100 port 22"
        
        result = keyword_fallback(line, 1, "test.log")
        
        assert result['category'] == 'network'
        assert result['severity'] == 'low'

    def test_system_event_detection(self):
        """Should detect system events"""
        line = "Process nginx (PID:1234) exceeded memory limit (2000MB > 1024MB)"
        
        result = keyword_fallback(line, 1, "test.log")
        
        assert result['category'] == 'system'
        assert result['is_suspicious'] is True
        assert result['severity'] == 'high'

    def test_application_event_detection(self):
        """Should detect application/api events"""
        line = "API request GET from 203.0.113.44 returned 503 in 1101ms"
        
        result = keyword_fallback(line, 1, "test.log")
        
        assert result['category'] == 'application'
        assert result['is_suspicious'] is True  # 503 error
        assert result['severity'] == 'high'

    def test_default_fallback(self):
        """Should return default values for unknown log lines"""
        line = "Something completely random that doesn't match any keywords"
        
        result = keyword_fallback(line, 1, "test.log")
        
        assert result['category'] == 'unknown'
        assert result['is_suspicious'] is False
        assert result['severity'] == 'low'
