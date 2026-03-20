"""
SPECTRE Scoring Engine — Risk Score Aggregation

Aggregates vulnerability findings from the ML Engine, attack results,
and LLM classifications into a single CVSS-like risk score per session.
"""

import json
import os
import time
import logging
from typing import Optional
import resource

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import redis
import uvicorn

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
REDIS_ADDR = os.getenv("REDIS_ADDR", "localhost:6379")
REDIS_HOST, REDIS_PORT = REDIS_ADDR.split(":")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [scoring-engine] %(message)s")
log = logging.getLogger("scoring-engine")

app = FastAPI(title="SPECTRE Scoring Engine", version="1.0.0")

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
class Finding(BaseModel):
    type: str                         # vulnerability category
    severity: str = "MEDIUM"          # CRITICAL, HIGH, MEDIUM, LOW, INFO
    severity_score: float = 5.0       # 0.0 – 10.0
    confirmed: bool = False           # whether the attack confirmed the vuln


class ScoreRequest(BaseModel):
    session_id: str = ""
    target_url: str = ""
    findings: list[Finding] = []
    missing_security_headers: int = 0
    weak_tls: bool = False
    total_open_ports: int = 0
    risky_ports_open: int = 0
    service_count: int = 0
    api_count: int = 0
    request_count: int = 0
    error_rate: float = 0.0
    auth_failures: int = 0
    db_errors: int = 0
    anomaly_count: int = 0
    request_spikes: int = 0
    epss_score: float = 0.0
    kev_hits: int = 0
    exploit_references: int = 0


class ScoreBreakdown(BaseModel):
    vulnerability_score: float        # weighted vuln impact
    attack_surface_score: float       # based on open ports, missing headers
    exposure_score: float             # TLS, encryption
    confirmed_bonus: float            # bonus for confirmed vulns
    total_findings: int
    confirmed_findings: int
    severity_distribution: dict       # e.g. {"CRITICAL": 1, "HIGH": 2, ...}


class ScoreResponse(BaseModel):
    session_id: str
    risk_score: float                 # 0.0 – 10.0
    risk_level: str                   # CRITICAL, HIGH, MEDIUM, LOW
    risk_grade: str                   # A, B, C, D, F
    ebss_score: int
    ebss_grade: str
    confidence: float
    priority: str
    breakdown: ScoreBreakdown
    summary: str
    timestamp: str


# ---------------------------------------------------------------------------
# Scoring Algorithm
# ---------------------------------------------------------------------------
SEVERITY_WEIGHTS = {
    "CRITICAL": 10.0,
    "HIGH": 7.5,
    "MEDIUM": 5.0,
    "LOW": 2.5,
    "INFO": 1.0,
}


def compute_score(req: ScoreRequest) -> tuple[float, ScoreBreakdown]:
    """
    CVSS-inspired risk scoring algorithm.
    
    Components:
    1. Vulnerability Score (50% weight) — based on finding count and severity
    2. Attack Surface Score (25% weight) — open ports, missing headers
    3. Exposure Score (15% weight) — TLS/crypto weakness
    4. Confirmed Bonus (10% weight) — boost for confirmed vulnerabilities
    """
    # --- 1. Vulnerability Score (0-10) ---
    if not req.findings:
        vuln_score = 0.0
    else:
        # Weighted average of severity scores, capped at 10
        total_weight = sum(SEVERITY_WEIGHTS.get(f.severity, 5.0) for f in req.findings)
        vuln_score = min(total_weight / max(len(req.findings), 1), 10.0)
        # Scale up based on number of findings (more vulns = worse)
        count_multiplier = min(1.0 + (len(req.findings) - 1) * 0.15, 2.0)
        vuln_score = min(vuln_score * count_multiplier, 10.0)

    # --- 2. Attack Surface Score (0-10) ---
    surface_score = 0.0
    if req.missing_security_headers >= 4:
        surface_score += 4.0
    elif req.missing_security_headers >= 2:
        surface_score += 2.5
    elif req.missing_security_headers >= 1:
        surface_score += 1.0

    if req.api_count >= 8:
        surface_score += 3.0
    elif req.api_count >= 3:
        surface_score += 1.8
    elif req.api_count >= 1:
        surface_score += 0.8

    if req.service_count >= 4:
        surface_score += 2.0
    elif req.service_count >= 2:
        surface_score += 1.0

    if req.request_count >= 20:
        surface_score += 1.5
    elif req.request_count >= 8:
        surface_score += 0.8
    if req.anomaly_count >= 5:
        surface_score += 1.5
    elif req.anomaly_count >= 1:
        surface_score += 0.75
    if req.request_spikes >= 1:
        surface_score += min(req.request_spikes * 0.5, 1.5)

    surface_score = min(surface_score, 10.0)

    # --- 3. Exposure Score (0-10) ---
    exposure_score = 0.0
    if req.weak_tls:
        exposure_score += 7.0
    if req.db_errors >= 5:
        exposure_score += 1.5
    if req.auth_failures >= 10:
        exposure_score += 1.0
    if req.error_rate >= 0.2:
        exposure_score += 1.0
    # No TLS at all would be caught as weak_tls too
    exposure_score = min(exposure_score, 10.0)

    # --- 4. Confirmed Bonus (0-10) ---
    confirmed_count = sum(1 for f in req.findings if f.confirmed)
    confirmed_bonus = 0.0
    if confirmed_count > 0:
        confirmed_bonus = min(confirmed_count * 3.0, 10.0)

    # --- Severity distribution ---
    severity_dist: dict[str, int] = {}
    for f in req.findings:
        severity_dist[f.severity] = severity_dist.get(f.severity, 0) + 1

    # --- Weighted final score ---
    final = (
        vuln_score * 0.50 +
        surface_score * 0.25 +
        exposure_score * 0.15 +
        confirmed_bonus * 0.10
    )
    final = round(min(final, 10.0), 1)

    breakdown = ScoreBreakdown(
        vulnerability_score=round(vuln_score, 2),
        attack_surface_score=round(surface_score, 2),
        exposure_score=round(exposure_score, 2),
        confirmed_bonus=round(confirmed_bonus, 2),
        total_findings=len(req.findings),
        confirmed_findings=confirmed_count,
        severity_distribution=severity_dist,
    )

    return final, breakdown


def score_to_level(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    else:
        return "LOW"


def score_to_grade(score: float) -> str:
    """Security grade (inverted — lower risk = better grade)."""
    if score <= 2.0:
        return "A"
    elif score <= 4.0:
        return "B"
    elif score <= 6.0:
        return "C"
    elif score <= 8.0:
        return "D"
    else:
        return "F"


def compute_ebss(req: ScoreRequest, risk_score: float, breakdown: ScoreBreakdown) -> tuple[int, str, float, str]:
    ml_component = min(risk_score * 10, 40)
    log_component = min((req.error_rate * 25) + (req.db_errors * 1.5) + (req.auth_failures * 0.5) + (req.anomaly_count * 1.2), 20)
    intel_component = min((req.epss_score * 20) + (req.kev_hits * 6) + (req.exploit_references * 2), 30)
    behavior_component = min((req.api_count * 1.5) + (req.service_count * 1.2) + (req.request_spikes * 2), 10)
    total = int(round(min(100, ml_component + log_component + intel_component + behavior_component)))

    if total >= 90:
        grade = "A"
    elif total >= 80:
        grade = "A-"
    elif total >= 70:
        grade = "B"
    elif total >= 60:
        grade = "C"
    else:
        grade = "D"

    if total >= 85:
        priority = "CRITICAL"
    elif total >= 70:
        priority = "HIGH"
    elif total >= 50:
        priority = "MEDIUM"
    else:
        priority = "LOW"

    confidence = round(min(0.99, 0.45 + (breakdown.confirmed_findings * 0.08) + (req.epss_score * 0.2) + min(req.anomaly_count, 5) * 0.03), 2)
    return total, grade, confidence, priority


def generate_summary(risk_level: str, breakdown: ScoreBreakdown) -> str:
    """Generate a human-readable risk summary."""
    parts = []

    if breakdown.total_findings == 0:
        return "No vulnerabilities detected. The target appears to have a clean security posture."

    parts.append(f"{breakdown.total_findings} vulnerability finding(s) detected")

    if breakdown.confirmed_findings > 0:
        parts.append(f"{breakdown.confirmed_findings} confirmed via active testing")

    dist_parts = []
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = breakdown.severity_distribution.get(sev, 0)
        if count > 0:
            dist_parts.append(f"{count} {sev}")
    if dist_parts:
        parts.append("severity breakdown: " + ", ".join(dist_parts))

    if breakdown.attack_surface_score >= 5.0:
        parts.append("significant attack surface exposure")
    if breakdown.exposure_score >= 5.0:
        parts.append("weak cryptographic posture")

    return ". ".join(parts) + "."


# ---------------------------------------------------------------------------
# Redis publisher
# ---------------------------------------------------------------------------
def publish_score(session_id: str, resp: ScoreResponse):
    """Publish the final risk score to the scoring-results Redis stream."""
    try:
        r = get_redis()
        payload = json.dumps({
            "session_id": session_id,
            "type": "risk-score",
            "risk_score": resp.risk_score,
            "risk_level": resp.risk_level,
            "risk_grade": resp.risk_grade,
            "summary": resp.summary,
            "breakdown": {
                "vulnerability_score": resp.breakdown.vulnerability_score,
                "attack_surface_score": resp.breakdown.attack_surface_score,
                "exposure_score": resp.breakdown.exposure_score,
                "confirmed_bonus": resp.breakdown.confirmed_bonus,
                "total_findings": resp.breakdown.total_findings,
                "confirmed_findings": resp.breakdown.confirmed_findings,
                "severity_distribution": resp.breakdown.severity_distribution,
            },
            "timestamp": resp.timestamp,
        })
        r.xadd("scoring-results", {"payload": payload})
        log.info("Published risk score %.1f (%s) for session %s", resp.risk_score, resp.risk_level, session_id)
    except Exception as e:
        log.warning("Failed to publish score to Redis: %s", e)


def publish_service_metric(session_id: str, phase: str, impact: str, extra: Optional[dict] = None):
    try:
        usage = resource.getrusage(resource.RUSAGE_SELF)
        payload = {
            "session_id": session_id,
            "service": "scoring-engine",
            "phase": phase,
            "impact": impact,
            "type": "service-metric",
            "memory_mb": round(usage.ru_maxrss / 1024, 2),
            "cpu_user_s": round(usage.ru_utime, 3),
            "cpu_system_s": round(usage.ru_stime, 3),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        }
        if extra:
            payload.update(extra)
        get_redis().xadd("service-metrics", {"payload": json.dumps(payload)})
    except Exception as e:
        log.warning("Failed to publish service metric: %s", e)


# ---------------------------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------------------------
@app.get("/health")
def health():
    return {"status": "ok", "service": "scoring-engine"}


@app.post("/score", response_model=ScoreResponse)
def score(req: ScoreRequest):
    """Compute the final risk score for a session."""
    if not req.session_id:
        raise HTTPException(status_code=400, detail="session_id is required")

    log.info("Scoring session %s with %d findings", req.session_id, len(req.findings))
    started = time.perf_counter()

    risk_score, breakdown = compute_score(req)
    risk_level = score_to_level(risk_score)
    risk_grade = score_to_grade(risk_score)
    summary = generate_summary(risk_level, breakdown)

    now = time.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    ebss_score, ebss_grade, confidence, priority = compute_ebss(req, risk_score, breakdown)
    response = ScoreResponse(
        session_id=req.session_id,
        risk_score=risk_score,
        risk_level=risk_level,
        risk_grade=risk_grade,
        ebss_score=ebss_score,
        ebss_grade=ebss_grade,
        confidence=confidence,
        priority=priority,
        breakdown=breakdown,
        summary=summary,
        timestamp=now,
    )

    publish_score(req.session_id, response)
    publish_service_metric(
        req.session_id,
        "score",
        "Aggregated microservice outputs into final risk score",
        {
            "findings": len(req.findings),
            "risk_score": response.risk_score,
            "risk_level": response.risk_level,
            "ebss_score": response.ebss_score,
            "priority": response.priority,
            "duration_ms": round((time.perf_counter() - started) * 1000, 2),
        },
    )
    return response


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=5003, reload=True)
