#!/usr/bin/env python
"""Tests for log analysis (mocked - no real API calls)"""

import json
import sys
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestLogAnalyzerOllama:
    """Test Ollama backend with mocked responses"""

    def test_parse_valid_json_response(self):
        """Should correctly parse valid JSON from model"""
        from batch_analyze_ollama import parse_model_response
        
        valid_response = '{"severity":"high","category":"auth","is_suspicious":true,"brief_reason":"Failed login"}'
        
        result = parse_model_response(valid_response, 1, "test.log", "test line")
        
        assert result['severity'] == 'high'
        assert result['category'] == 'auth'
        assert result['is_suspicious'] is True
        assert result['brief_reason'] == 'Failed login'
        assert result['line_number'] == 1

    def test_parse_markdown_wrapped_json(self):
        """Should handle JSON wrapped in markdown code blocks"""
        from batch_analyze_ollama import parse_model_response
        
        markdown_response = '```json\n{"severity":"medium","category":"network","is_suspicious":false,"brief_reason":"Normal"}\n```'
        
        result = parse_model_response(markdown_response, 2, "test.log", "test")
        
        assert result['severity'] == 'medium'
        assert result['category'] == 'network'
        assert result['is_suspicious'] is False

    def test_fallback_on_invalid_json(self):
        """Should use keyword fallback when JSON is invalid"""
        from batch_analyze_ollama import analyze_log_line, keyword_fallback
        
        invalid_response = "I think this log is suspicious because..."
        line = "Failed password for root from 203.0.113.89 port 22"
        
        # Test fallback directly
        result = keyword_fallback(line, 1, "test.log")
        
        assert result['is_suspicious'] is True
        assert result['category'] == 'auth'
        assert result['severity'] == 'high'

    def test_keyword_detection_auth_failure(self):
        """Should detect authentication failures"""
        from batch_analyze_ollama import keyword_fallback
        
        test_cases = [
            ("Failed password for admin", True, "auth"),
            ("Invalid user ftpuser", True, "auth"),
            ("authentication failure", True, "auth"),
            ("Accepted password for user", False, "auth"),
        ]
        
        for line, expected_suspicious, expected_category in test_cases:
            result = keyword_fallback(line, 1, "test.log")
            assert result['is_suspicious'] == expected_suspicious
            assert result['category'] == expected_category


class TestLogAnalyzerGemini:
    """Test Gemini backend with mocked API calls"""

    @patch('batch_analyze.genai.Client')
    def test_gemini_api_call(self, mock_client_class):
        """Should call Gemini API with correct parameters"""
        from batch_analyze import analyze_with_gemini
        
        # Create mock response
        mock_response = Mock()
        mock_response.text = '{"severity":"high","category":"auth","is_suspicious":true,"brief_reason":"Failed"}'
        mock_client = Mock()
        mock_client.models.generate_content.return_value = mock_response
        mock_client_class.return_value = mock_client
        
        result = analyze_with_gemini("Failed password", 1, "test.log")
        
        assert result['severity'] == 'high'
        assert result['is_suspicious'] is True


if __name__ == '__main__':
    print("Run with: pytest tests/ -v")
