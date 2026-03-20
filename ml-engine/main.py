"""
SPECTRE ML Engine — Vulnerability Prediction Service

Consumes recon data (open ports, headers, TLS info, error probes)
and predicts which vulnerability categories are most likely present.
Uses a weighted rule-based model — no heavy ML libraries needed.
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

logging.basicConfig(level=logging.INFO, format="%(asctime)s [ml-engine] %(message)s")
log = logging.getLogger("ml-engine")

app = FastAPI(title="SPECTRE ML Engine", version="1.0.0")

# ---------------------------------------------------------------------------
# Redis client (lazy init)
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
class ReconData(BaseModel):
    session_id: str = ""
    open_ports: list[int] = []
    missing_headers: list[str] = []
    tls_version: str = ""
    tls_available: bool = True
    server_header: str = ""
    x_powered_by: str = ""
    error_probe_sqli: bool = False
    error_probe_traversal: bool = False
    stack_trace_detected: bool = False
    robots_found: bool = False
    disallowed_paths: list[str] = []
    url_classification: str = ""
    classification_confidence: float = 0.0
    backend_endpoints: list[dict] = []
    backend_endpoint_count: int = 0
    rest_endpoint_count: int = 0
    graphql_endpoint_count: int = 0
    idor_candidate_count: int = 0
    auth_surface_count: int = 0


class VulnPrediction(BaseModel):
    category: str
    confidence: float          # 0.0 – 1.0
    reasoning: str
    recommended_payloads: list[str]


class PredictionResponse(BaseModel):
    session_id: str
    predictions: list[VulnPrediction]
    feature_vector: dict
    timestamp: str


# ---------------------------------------------------------------------------
# Feature Extraction
# ---------------------------------------------------------------------------
RISKY_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 3306: "mysql",
    5432: "postgres", 6379: "redis", 27017: "mongodb", 11211: "memcached",
    9200: "elasticsearch", 5900: "vnc", 1433: "mssql", 1521: "oracle",
    8080: "http-alt", 8443: "https-alt", 445: "smb", 139: "netbios",
}

SECURITY_HEADERS = [
    "X-Frame-Options", "X-Content-Type-Options", "Content-Security-Policy",
    "Strict-Transport-Security", "Referrer-Policy",
]


def extract_features(data: ReconData) -> dict:
    """Convert raw recon data into a numerical feature vector."""
    open_set = set(data.open_ports)

    # Port-based features
    db_ports_open = len(open_set & {3306, 5432, 27017, 1433, 1521})
    cache_ports_open = len(open_set & {6379, 11211})
    risky_ports_open = len(open_set & set(RISKY_PORTS.keys()))
    total_open = len(data.open_ports)

    # Header-based features
    missing_count = len(data.missing_headers)
    has_server_leak = 1 if data.server_header else 0
    has_powered_by = 1 if data.x_powered_by else 0

    # TLS features
    weak_tls = 0
    if data.tls_version in ("TLS 1.0", "TLS 1.1"):
        weak_tls = 1
    no_tls = 0 if data.tls_available else 1

    # Error-probe features
    sqli_signal = 1 if data.error_probe_sqli else 0
    traversal_signal = 1 if data.error_probe_traversal else 0
    stack_trace = 1 if data.stack_trace_detected else 0

    # Discovery features
    robots = 1 if data.robots_found else 0
    hidden_paths = len(data.disallowed_paths)
    backend_class = 1 if data.url_classification in ("api-only", "full-backend", "graphql", "microservice-cluster") else 0
    frontend_only = 1 if data.url_classification == "frontend-only" else 0
    backend_endpoints = data.backend_endpoint_count or len(data.backend_endpoints)

    return {
        "total_open_ports": total_open,
        "db_ports_open": db_ports_open,
        "cache_ports_open": cache_ports_open,
        "risky_ports_open": risky_ports_open,
        "missing_security_headers": missing_count,
        "server_header_leak": has_server_leak,
        "powered_by_leak": has_powered_by,
        "weak_tls": weak_tls,
        "no_tls": no_tls,
        "sqli_signal": sqli_signal,
        "traversal_signal": traversal_signal,
        "stack_trace_detected": stack_trace,
        "robots_found": robots,
        "hidden_paths_count": hidden_paths,
        "url_is_backend": backend_class,
        "url_is_frontend_only": frontend_only,
        "classification_confidence": data.classification_confidence,
        "backend_endpoint_count": backend_endpoints,
        "rest_endpoint_count": data.rest_endpoint_count,
        "graphql_endpoint_count": data.graphql_endpoint_count,
        "idor_candidate_count": data.idor_candidate_count,
        "auth_surface_count": data.auth_surface_count,
    }


# ---------------------------------------------------------------------------
# Vulnerability Prediction Model (weighted rule-based)
# ---------------------------------------------------------------------------
def predict_vulnerabilities(features: dict) -> list[VulnPrediction]:
    """
    Rule-based vulnerability prediction.
    Each rule contributes a weighted score (0-1) to a vulnerability category.
    """
    predictions: list[VulnPrediction] = []

    # --- SQL Injection ---
    sqli_score = 0.0
    reasons_sqli = []
    if features["sqli_signal"]:
        sqli_score += 0.50
        reasons_sqli.append("SQL error detected in error-probe response")
    if features["db_ports_open"] > 0:
        sqli_score += 0.25
        reasons_sqli.append(f"{features['db_ports_open']} database port(s) exposed")
    if features["stack_trace_detected"]:
        sqli_score += 0.15
        reasons_sqli.append("Stack trace leakage detected")
    if features["backend_endpoint_count"] > 0:
        sqli_score += 0.20
        reasons_sqli.append(f"{features['backend_endpoint_count']} backend API endpoint(s) discovered")
    if features["rest_endpoint_count"] > 0:
        sqli_score += 0.15
        reasons_sqli.append(f"{features['rest_endpoint_count']} REST endpoint(s) expose parameterized surface")
    if features["url_is_backend"]:
        sqli_score += 0.10
        reasons_sqli.append("URL classification indicates backend/API behavior")
    sqli_score = min(sqli_score, 1.0)
    if sqli_score >= 0.15:
        predictions.append(VulnPrediction(
            category="SQL Injection",
            confidence=round(sqli_score, 2),
            reasoning="; ".join(reasons_sqli),
            recommended_payloads=["' OR '1'='1", "1; DROP TABLE--", "' UNION SELECT NULL--", "1' AND SLEEP(5)--"],
        ))

    # --- IDOR ---
    idor_score = 0.0
    reasons_idor = []
    if features["idor_candidate_count"] > 0:
        idor_score += 0.45
        reasons_idor.append(f"{features['idor_candidate_count']} object-style endpoint(s) discovered")
    if features["backend_endpoint_count"] >= 2:
        idor_score += 0.20
        reasons_idor.append("Multiple backend endpoints increase object access surface")
    if features["url_is_backend"]:
        idor_score += 0.15
        reasons_idor.append("Target classified as backend/API capable")
    if features["graphql_endpoint_count"] > 0:
        idor_score += 0.10
        reasons_idor.append("GraphQL endpoint may expose object traversal paths")
    idor_score = min(idor_score, 1.0)
    if idor_score >= 0.15:
        predictions.append(VulnPrediction(
            category="Insecure Direct Object Reference (IDOR)",
            confidence=round(idor_score, 2),
            reasoning="; ".join(reasons_idor),
            recommended_payloads=["/api/users/2", "/api/orders/1002", "?id=2", "?account_id=2"],
        ))

    # --- Weak Authentication / Authorization ---
    auth_score = 0.0
    reasons_auth = []
    if features["auth_surface_count"] > 0:
        auth_score += 0.45
        reasons_auth.append(f"{features['auth_surface_count']} authentication-facing endpoint(s) discovered")
    if features["graphql_endpoint_count"] > 0:
        auth_score += 0.20
        reasons_auth.append("GraphQL API discovered for introspection and auth checks")
    if features["backend_endpoint_count"] > 0:
        auth_score += 0.15
        reasons_auth.append("Backend APIs discovered for token/session validation")
    if features["missing_security_headers"] >= 3:
        auth_score += 0.10
        reasons_auth.append("Weak browser-side security headers may amplify auth risk")
    auth_score = min(auth_score, 1.0)
    if auth_score >= 0.15:
        predictions.append(VulnPrediction(
            category="Weak Authentication / Authorization",
            confidence=round(auth_score, 2),
            reasoning="; ".join(reasons_auth),
            recommended_payloads=["/login", "/auth/token", "/session/refresh", "{\"query\":\"{ viewer { id } }\"}"],
        ))

    # --- Cross-Site Scripting (XSS) ---
    xss_score = 0.0
    reasons_xss = []
    missing = features["missing_security_headers"]
    if missing >= 3:
        xss_score += 0.40
        reasons_xss.append(f"{missing} security headers missing")
    elif missing >= 1:
        xss_score += 0.20
        reasons_xss.append(f"{missing} security header(s) missing")
    if features["stack_trace_detected"]:
        xss_score += 0.20
        reasons_xss.append("Verbose error pages may reflect input")
    if features["powered_by_leak"]:
        xss_score += 0.10
        reasons_xss.append("X-Powered-By header reveals tech stack")
    xss_score = min(xss_score, 1.0)
    if xss_score >= 0.15:
        predictions.append(VulnPrediction(
            category="Cross-Site Scripting (XSS)",
            confidence=round(xss_score, 2),
            reasoning="; ".join(reasons_xss),
            recommended_payloads=["<script>alert('SPECTRE')</script>", "<img src=x onerror=alert(1)>",
                                  "'\"><svg/onload=alert(1)>"],
        ))

    # --- Path Traversal / LFI ---
    traversal_score = 0.0
    reasons_trav = []
    if features["traversal_signal"]:
        traversal_score += 0.50
        reasons_trav.append("Path traversal signature detected in error probe")
    if features["hidden_paths_count"] > 3:
        traversal_score += 0.20
        reasons_trav.append(f"{features['hidden_paths_count']} hidden paths in robots.txt")
    if features["server_header_leak"]:
        traversal_score += 0.10
        reasons_trav.append("Server header reveals software version")
    traversal_score = min(traversal_score, 1.0)
    if traversal_score >= 0.15:
        predictions.append(VulnPrediction(
            category="Path Traversal / LFI",
            confidence=round(traversal_score, 2),
            reasoning="; ".join(reasons_trav),
            recommended_payloads=["../../../../etc/passwd", "....//....//etc/passwd",
                                  "..%252f..%252f..%252fetc/passwd"],
        ))

    # --- Information Disclosure ---
    info_score = 0.0
    reasons_info = []
    if features["server_header_leak"]:
        info_score += 0.25
        reasons_info.append("Server header leaks software name/version")
    if features["powered_by_leak"]:
        info_score += 0.25
        reasons_info.append("X-Powered-By leaks tech stack")
    if features["stack_trace_detected"]:
        info_score += 0.30
        reasons_info.append("Stack traces reveal internal code paths")
    if features["robots_found"] and features["hidden_paths_count"] > 0:
        info_score += 0.15
        reasons_info.append("robots.txt reveals hidden directories")
    info_score = min(info_score, 1.0)
    if info_score >= 0.15:
        predictions.append(VulnPrediction(
            category="Information Disclosure",
            confidence=round(info_score, 2),
            reasoning="; ".join(reasons_info),
            recommended_payloads=["/.env", "/.git/config", "/server-status", "/phpinfo.php",
                                  "/wp-config.php.bak"],
        ))

    # --- Security Misconfiguration ---
    misconfig_score = 0.0
    reasons_misc = []
    if features["missing_security_headers"] >= 4:
        misconfig_score += 0.35
        reasons_misc.append("Most security headers absent")
    if features["risky_ports_open"] >= 3:
        misconfig_score += 0.25
        reasons_misc.append(f"{features['risky_ports_open']} risky ports exposed")
    if features["cache_ports_open"] > 0:
        misconfig_score += 0.20
        reasons_misc.append("Cache ports (Redis/Memcached) exposed")
    if features["no_tls"]:
        misconfig_score += 0.20
        reasons_misc.append("No TLS configured")
    misconfig_score = min(misconfig_score, 1.0)
    if misconfig_score >= 0.15:
        predictions.append(VulnPrediction(
            category="Security Misconfiguration",
            confidence=round(misconfig_score, 2),
            reasoning="; ".join(reasons_misc),
            recommended_payloads=["/.env", "/admin", "/debug", "/actuator/health",
                                  "/.well-known/security.txt"],
        ))

    # --- Weak TLS / Crypto ---
    tls_score = 0.0
    reasons_tls = []
    if features["weak_tls"]:
        tls_score += 0.60
        reasons_tls.append("Weak TLS version in use (< 1.2)")
    if features["no_tls"]:
        tls_score += 0.80
        reasons_tls.append("No TLS/SSL configured at all")
    tls_score = min(tls_score, 1.0)
    if tls_score >= 0.15:
        predictions.append(VulnPrediction(
            category="Weak Cryptography / TLS",
            confidence=round(tls_score, 2),
            reasoning="; ".join(reasons_tls),
            recommended_payloads=[],  # no active payloads, this is config-based
        ))

    # Sort by confidence descending
    predictions.sort(key=lambda p: p.confidence, reverse=True)
    return predictions


# ---------------------------------------------------------------------------
# Redis publisher
# ---------------------------------------------------------------------------
def publish_predictions(session_id: str, predictions: list[VulnPrediction]):
    """Publish predictions to the ml-predictions Redis stream."""
    try:
        r = get_redis()
        for pred in predictions:
            payload = json.dumps({
                "session_id": session_id,
                "type": "ml-prediction",
                "category": pred.category,
                "confidence": pred.confidence,
                "reasoning": pred.reasoning,
                "recommended_payloads": pred.recommended_payloads,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            })
            r.xadd("ml-predictions", {"payload": payload})
        log.info("Published %d predictions for session %s", len(predictions), session_id)
    except Exception as e:
        log.warning("Failed to publish predictions to Redis: %s", e)


def publish_service_metric(session_id: str, phase: str, impact: str, extra: Optional[dict] = None):
    try:
        usage = resource.getrusage(resource.RUSAGE_SELF)
        payload = {
            "session_id": session_id,
            "service": "ml-engine",
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
    return {"status": "ok", "service": "ml-engine"}


@app.post("/predict", response_model=PredictionResponse)
def predict(data: ReconData):
    """
    Accept recon summary, extract features, predict vulnerabilities.
    """
    if not data.session_id:
        raise HTTPException(status_code=400, detail="session_id is required")

    log.info("Received prediction request for session %s", data.session_id)
    started = time.perf_counter()

    features = extract_features(data)
    predictions = predict_vulnerabilities(features)

    log.info("Predicted %d vulnerability categories for session %s", len(predictions), data.session_id)
    publish_service_metric(
        data.session_id,
        "ml-analysis",
        "Model 1 weighted backend API signals for vulnerability prediction",
        {
            "predictions": len(predictions),
            "backend_endpoints": features["backend_endpoint_count"],
            "graphql_endpoints": features["graphql_endpoint_count"],
            "duration_ms": round((time.perf_counter() - started) * 1000, 2),
        },
    )

    # Publish to Redis asynchronously (best-effort)
    publish_predictions(data.session_id, predictions)

    return PredictionResponse(
        session_id=data.session_id,
        predictions=predictions,
        feature_vector=features,
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=5001, reload=True)
