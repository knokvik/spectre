"""
SPECTRE LLM Classifier — Vulnerability Severity Analysis

Ollama-ready severity classifier with a rule-based fallback.
When Ollama is running, uses it for intelligent severity analysis.
When it's not available, falls back to deterministic keyword-based classification.
"""

import json
import os
import time
import logging
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import httpx
import redis
import uvicorn

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
REDIS_ADDR = os.getenv("REDIS_ADDR", "localhost:6379")
REDIS_HOST, REDIS_PORT = REDIS_ADDR.split(":")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [llm-classifier] %(message)s")
log = logging.getLogger("llm-classifier")

app = FastAPI(title="SPECTRE LLM Classifier", version="1.0.0")

# ---------------------------------------------------------------------------
# Redis client
# ---------------------------------------------------------------------------
_redis: Optional[redis.Redis] = None


def get_redis() -> redis.Redis:
    global _redis
    if _redis is None:
        _redis = redis.Redis(host=REDIS_HOST, port=int(REDIS_PORT), decode_responses=True)
        _redis.ping()
        log.info("Connected to Redis at %s", REDIS_ADDR)
    return _redis


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------
class ClassifyRequest(BaseModel):
    session_id: str = ""
    vulnerability_type: str          # e.g. "SQL Injection", "XSS"
    attack_result: str = ""          # response body snippet or description
    http_status: int = 0
    confidence: float = 0.0          # ML prediction confidence
    target_url: str = ""


class ClassifyResponse(BaseModel):
    session_id: str
    vulnerability_type: str
    severity: str                    # CRITICAL, HIGH, MEDIUM, LOW, INFO
    severity_score: float            # 0.0 – 10.0
    description: str
    remediation: str
    classified_by: str               # "ollama" or "rule-engine"
    timestamp: str


# ---------------------------------------------------------------------------
# Ollama Client
# ---------------------------------------------------------------------------
SEVERITY_PROMPT_TEMPLATE = """You are a cybersecurity expert analyzing vulnerability scan results.

Vulnerability Type: {vuln_type}
Attack Result: {attack_result}
HTTP Status Code: {http_status}
ML Confidence Score: {confidence}
Target URL: {target_url}

Based on the above information, classify the severity of this vulnerability.
Respond in EXACTLY this JSON format, nothing else:
{{
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "severity_score": <float 0.0-10.0>,
  "description": "<one-line description of the vulnerability impact>",
  "remediation": "<one-line recommended fix>"
}}"""


async def classify_with_ollama(req: ClassifyRequest) -> Optional[dict]:
    """Try to classify using Ollama. Returns None if Ollama is unavailable."""
    prompt = SEVERITY_PROMPT_TEMPLATE.format(
        vuln_type=req.vulnerability_type,
        attack_result=req.attack_result[:500],  # truncate
        http_status=req.http_status,
        confidence=req.confidence,
        target_url=req.target_url,
    )

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(f"{OLLAMA_URL}/api/generate", json={
                "model": OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False,
                "format": "json",
            })
            if resp.status_code == 200:
                body = resp.json()
                response_text = body.get("response", "")
                parsed = json.loads(response_text)
                # Validate expected fields
                if all(k in parsed for k in ["severity", "severity_score", "description", "remediation"]):
                    log.info("Ollama classified %s as %s", req.vulnerability_type, parsed["severity"])
                    return parsed
    except Exception as e:
        log.info("Ollama unavailable (%s), using rule-based fallback", type(e).__name__)

    return None


# ---------------------------------------------------------------------------
# Rule-Based Fallback Classifier
# ---------------------------------------------------------------------------
SEVERITY_RULES = {
    "SQL Injection": {
        "severity": "HIGH",
        "severity_score": 8.5,
        "description": "SQL injection can lead to unauthorized data access, modification, or deletion of database contents.",
        "remediation": "Use parameterized queries/prepared statements. Implement input validation and ORM-based data access.",
    },
    "Cross-Site Scripting (XSS)": {
        "severity": "MEDIUM",
        "severity_score": 6.5,
        "description": "XSS enables attackers to inject client-side scripts, potentially stealing session tokens or defacing content.",
        "remediation": "Encode output, implement Content-Security-Policy header, and sanitize all user input.",
    },
    "Path Traversal / LFI": {
        "severity": "HIGH",
        "severity_score": 7.5,
        "description": "Path traversal can expose sensitive server files including configuration and credentials.",
        "remediation": "Validate and sanitize file paths. Use chroot jails and restrict file access to designated directories.",
    },
    "Information Disclosure": {
        "severity": "MEDIUM",
        "severity_score": 5.0,
        "description": "Exposed server information aids attackers in crafting targeted exploits against known software versions.",
        "remediation": "Remove or mask Server/X-Powered-By headers. Disable verbose error pages in production.",
    },
    "Security Misconfiguration": {
        "severity": "MEDIUM",
        "severity_score": 6.0,
        "description": "Misconfigured security controls create exploitable attack surface and weaken overall defense posture.",
        "remediation": "Apply security hardening checklist. Enable all security headers. Close unnecessary ports.",
    },
    "Weak Cryptography / TLS": {
        "severity": "HIGH",
        "severity_score": 7.0,
        "description": "Weak or missing TLS allows traffic interception and man-in-the-middle attacks.",
        "remediation": "Enforce TLS 1.2+ with strong cipher suites. Enable HSTS with long max-age.",
    },
}

DEFAULT_RULE = {
    "severity": "LOW",
    "severity_score": 3.0,
    "description": "Potential vulnerability detected — manual analysis recommended.",
    "remediation": "Investigate the finding manually and apply appropriate security controls.",
}


def classify_rule_based(req: ClassifyRequest) -> dict:
    """Deterministic severity classification based on vulnerability type and signals."""
    rule = SEVERITY_RULES.get(req.vulnerability_type, DEFAULT_RULE).copy()

    # Adjust severity based on additional signals
    if req.confidence >= 0.8:
        rule["severity_score"] = min(rule["severity_score"] + 1.0, 10.0)
    if req.http_status == 500:
        rule["severity_score"] = min(rule["severity_score"] + 0.5, 10.0)

    # Promote to CRITICAL if score is >= 9.0
    if rule["severity_score"] >= 9.0:
        rule["severity"] = "CRITICAL"
    elif rule["severity_score"] >= 7.0:
        rule["severity"] = "HIGH"
    elif rule["severity_score"] >= 4.0:
        rule["severity"] = "MEDIUM"
    elif rule["severity_score"] >= 2.0:
        rule["severity"] = "LOW"
    else:
        rule["severity"] = "INFO"

    return rule


# ---------------------------------------------------------------------------
# Redis publisher
# ---------------------------------------------------------------------------
def publish_classification(session_id: str, resp: ClassifyResponse):
    """Publish classification to the llm-classifications Redis stream."""
    try:
        r = get_redis()
        payload = json.dumps({
            "session_id": session_id,
            "type": "llm-classification",
            "vulnerability_type": resp.vulnerability_type,
            "severity": resp.severity,
            "severity_score": resp.severity_score,
            "description": resp.description,
            "remediation": resp.remediation,
            "classified_by": resp.classified_by,
            "timestamp": resp.timestamp,
        })
        r.xadd("llm-classifications", {"payload": payload})
        log.info("Published classification for %s [%s]", resp.vulnerability_type, resp.severity)
    except Exception as e:
        log.warning("Failed to publish classification to Redis: %s", e)


# ---------------------------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------------------------
@app.get("/health")
def health():
    return {"status": "ok", "service": "llm-classifier"}


@app.post("/classify", response_model=ClassifyResponse)
async def classify(req: ClassifyRequest):
    """Classify vulnerability severity using Ollama (with rule-based fallback)."""
    if not req.session_id:
        raise HTTPException(status_code=400, detail="session_id is required")

    log.info("Classifying %s for session %s", req.vulnerability_type, req.session_id)

    # Try Ollama first
    ollama_result = await classify_with_ollama(req)
    classified_by = "ollama"

    if ollama_result is None:
        # Fallback to rule-based
        ollama_result = classify_rule_based(req)
        classified_by = "rule-engine"

    now = time.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    response = ClassifyResponse(
        session_id=req.session_id,
        vulnerability_type=req.vulnerability_type,
        severity=ollama_result["severity"],
        severity_score=ollama_result["severity_score"],
        description=ollama_result["description"],
        remediation=ollama_result["remediation"],
        classified_by=classified_by,
        timestamp=now,
    )

    publish_classification(req.session_id, response)
    return response


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=5002, reload=True)
