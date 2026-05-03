#!/usr/bin/env python3
"""
Log Analysis REST API Server
Provides HTTP endpoints for AI-powered log analysis with Gemini or Ollama
"""

import os
import json
import tempfile
from pathlib import Path
from typing import Optional, List
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import uvicorn

# ============================================================
# Configuration
# ============================================================

# Try Gemini first, fallback to Ollama
USE_GEMINI = os.environ.get("GEMINI_KEY") is not None
USE_OLLAMA = not USE_GEMINI

if USE_GEMINI:
    try:
        from google import genai
        client = genai.Client(api_key=os.environ["GEMINI_KEY"])
        MODEL_NAME = "gemini-2.5-flash"
        print(f"✓ Using Gemini backend with model: {MODEL_NAME}")
    except ImportError:
        print("⚠️ google-genai not installed. Falling back to Ollama.")
        USE_GEMINI = False
        USE_OLLAMA = True

if USE_OLLAMA:
    try:
        import ollama
        OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        client = ollama.Client(host=OLLAMA_HOST)
        MODEL_NAME = os.environ.get("OLLAMA_MODEL", "deepseek-coder:7b")
        print(f"✓ Using Ollama backend at {OLLAMA_HOST} with model: {MODEL_NAME}")
    except ImportError:
        print("❌ Neither google-genai nor ollama is installed.")
        print("   Run: pip install google-genai ollama fastapi uvicorn")
        exit(1)

# ============================================================
# Request/Response Models
# ============================================================

class LogLine(BaseModel):
    line: str = Field(..., description="The log line to analyze", example="Failed password for root from 203.0.113.89 port 22")
    line_number: Optional[int] = Field(None, description="Optional line number")

class AnalysisResponse(BaseModel):
    line_number: Optional[int]
    source_file: str = "api_call"
    severity: str
    category: str
    is_suspicious: bool
    brief_reason: str
    original_line: str

class HealthResponse(BaseModel):
    status: str
    backend: str
    model: str
    rate_limits: dict

# ============================================================
# FastAPI App
# ============================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events"""
    print("\n" + "=" * 50)
    print("🚀 Log Analysis API Server Starting")
    print("=" * 50)
    print(f"Backend: {'Gemini' if USE_GEMINI else 'Ollama'}")
    print(f"Model: {MODEL_NAME}")
    print("=" * 50 + "\n")
    yield
    print("\n👋 Shutting down API server...")

app = FastAPI(
    title="AI Log Analysis API",
    description="Analyze log files and detect suspicious activity using LLMs",
    version="1.0.0",
    lifespan=lifespan
)

# Enable CORS for web apps
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================
# Backend Functions
# ============================================================

def analyze_with_gemini(line: str, line_num: Optional[int] = None) -> dict:
    """Analyze log line using Google Gemini"""
    prompt = f"""
Analyze this log line and return ONLY valid JSON. No explanation, no markdown.

Log line: {line}

Return JSON with these exact fields:
- severity (one of: low, medium, high, critical)
- category (one of: auth, network, system, application)
- is_suspicious (boolean)
- brief_reason (string, max 50 chars)

Example: {{"severity":"high","category":"auth","is_suspicious":true,"brief_reason":"Failed login from external IP"}}
"""
    response = client.models.generate_content(
        model=MODEL_NAME,
        contents=prompt,
        config={'response_mime_type': 'application/json'}
    )
    
    text = response.text.strip()
    if text.startswith('```json'):
        text = text[7:]
    if text.startswith('```'):
        text = text[3:]
    if text.endswith('```'):
        text = text[:-3]
    
    return json.loads(text)

def analyze_with_ollama(line: str, line_num: Optional[int] = None) -> dict:
    """Analyze log line using local Ollama"""
    prompt = f"""
Analyze this log line and return ONLY valid JSON. No explanation, no markdown.

Log line: {line}

Return JSON with these exact fields:
- severity (one of: low, medium, high, critical)
- category (one of: auth, network, system, application)
- is_suspicious (boolean)
- brief_reason (string, max 50 chars)

Example: {{"severity":"high","category":"auth","is_suspicious":true,"brief_reason":"Failed login from external IP"}}
"""
    response = client.generate(
        model=MODEL_NAME,
        prompt=prompt,
        options={
            'temperature': 0.1,
            'num_predict': 256,
        }
    )
    
    text = response['response'].strip()
    if text.startswith('```json'):
        text = text[7:]
    if text.startswith('```'):
        text = text[3:]
    if text.endswith('```'):
        text = text[:-3]
    
    return json.loads(text)

def analyze_log_line(line: str, line_num: Optional[int] = None) -> dict:
    """Route to appropriate backend"""
    if USE_GEMINI:
        return analyze_with_gemini(line, line_num)
    else:
        return analyze_with_ollama(line, line_num)

# ============================================================
# API Endpoints
# ============================================================

@app.get("/", tags=["Info"])
async def root():
    """API information"""
    return {
        "service": "AI Log Analysis API",
        "version": "1.0.0",
        "backend": "Gemini" if USE_GEMINI else "Ollama",
        "model": MODEL_NAME,
        "endpoints": ["POST /analyze", "POST /analyze/file", "GET /health"]
    }

@app.get("/health", response_model=HealthResponse, tags=["Info"])
async def health():
    """Health check endpoint"""
    return HealthResponse(
        status="healthy",
        backend="Gemini" if USE_GEMINI else "Ollama",
        model=MODEL_NAME,
        rate_limits={
            "gemini": "~20 requests/day (free tier)" if USE_GEMINI else "N/A",
            "ollama": "None (local)" if USE_OLLAMA else "N/A"
        }
    )

@app.post("/analyze", response_model=AnalysisResponse, tags=["Analysis"])
async def analyze_single(log: LogLine):
    """Analyze a single log line"""
    try:
        result = analyze_log_line(log.line, log.line_number)
        return AnalysisResponse(
            line_number=log.line_number,
            source_file="api_call",
            severity=result.get("severity", "unknown"),
            category=result.get("category", "unknown"),
            is_suspicious=result.get("is_suspicious", False),
            brief_reason=result.get("brief_reason", "No reason provided"),
            original_line=log.line
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.post("/analyze/file", tags=["Analysis"])
async def analyze_file(file: UploadFile = File(...)):
    """Upload and analyze a log file"""
    if not file.filename.endswith(('.log', '.txt')):
        raise HTTPException(status_code=400, detail="Only .log and .txt files are supported")
    
    with tempfile.NamedTemporaryFile(delete=False, suffix='.log') as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = tmp.name
    
    try:
        lines = []
        results = []
        with open(tmp_path, 'r') as f:
            lines = f.readlines()
        
        max_lines = min(len(lines), 50)
        for idx, line in enumerate(lines[:max_lines], 1):
            line = line.strip()
            if not line:
                continue
            
            result = analyze_log_line(line, idx)
            results.append({
                "line_number": idx,
                "original_line": line,
                "severity": result.get("severity", "unknown"),
                "category": result.get("category", "unknown"),
                "is_suspicious": result.get("is_suspicious", False),
                "brief_reason": result.get("brief_reason", "No reason provided")
            })
        
        suspicious_count = sum(1 for r in results if r.get("is_suspicious"))
        return {
            "filename": file.filename,
            "total_lines_in_file": len(lines),
            "lines_analyzed": len(results),
            "suspicious_count": suspicious_count,
            "results": results
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"File analysis failed: {str(e)}")
    finally:
        os.unlink(tmp_path)

@app.post("/analyze/batch", tags=["Analysis"])
async def analyze_batch(lines: List[str]):
    """Analyze multiple log lines"""
    if len(lines) > 20:
        raise HTTPException(status_code=400, detail="Maximum 20 lines per batch request")
    
    results = []
    for idx, line in enumerate(lines, 1):
        if not line.strip():
            continue
        result = analyze_log_line(line, idx)
        results.append({
            "line_number": idx,
            "original_line": line,
            "severity": result.get("severity", "unknown"),
            "category": result.get("category", "unknown"),
            "is_suspicious": result.get("is_suspicious", False),
            "brief_reason": result.get("brief_reason", "No reason provided")
        })
    
    return {
        "total_analyzed": len(results),
        "suspicious_count": sum(1 for r in results if r.get("is_suspicious")),
        "results": results
    }

# ============================================================
# Main Entry Point
# ============================================================

if __name__ == '__main__':
    print("""
    ╔══════════════════════════════════════════════════════════╗
    ║     🔍 AI Log Analysis API Server                        ║
    ║                                                          ║
    ║     Swagger UI: http://localhost:8000/docs               ║
    ║     ReDoc:      http://localhost:8000/redoc              ║
    ║                                                          ║
    ║     Endpoints:                                           ║
    ║     POST /analyze       - Single log line                ║
    ║     POST /analyze/file  - Upload log file                ║
    ║     POST /analyze/batch - Multiple log lines             ║
    ║     GET  /health        - Health check                   ║
    ╚══════════════════════════════════════════════════════════╝
    """)
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")