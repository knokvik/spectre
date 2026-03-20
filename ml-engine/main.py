"""
SPECTRE ML Engine — Vulnerability Prediction Service

Consumes behavior-driven recon data, observed services/endpoints,
and normalized log signals to predict which vulnerability categories
are most likely present.
Uses a hybrid pickled model when available, with a weighted rule fallback.
"""

import json
import os
import time
import logging
from typing import Optional
import resource
import pickle

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import redis
import uvicorn

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
REDIS_ADDR = os.getenv("REDIS_ADDR", "localhost:6379")
REDIS_HOST, REDIS_PORT = REDIS_ADDR.split(":")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.getenv("MODEL_PATH", os.path.join(BASE_DIR, "model.pkl"))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [ml-engine] %(message)s")
log = logging.getLogger("ml-engine")

app = FastAPI(title="SPECTRE ML Engine", version="1.0.0")

# ---------------------------------------------------------------------------
# Redis client (lazy init)
# ---------------------------------------------------------------------------
_redis: Optional[redis.Redis] = None
_model = None


def get_redis() -> redis.Redis:
    global _redis
    if _redis is None:
        _redis = redis.Redis(host=REDIS_HOST, port=int(REDIS_PORT), decode_responses=True)
        _redis.ping()
        log.info("Connected to Redis at %s", REDIS_ADDR)
    return _redis


def load_model():
    global _model
    if _model is not None:
        return _model
    if not os.path.exists(MODEL_PATH):
        log.info("No pickle model found at %s, using hybrid fallback", MODEL_PATH)
        _model = {}
        return _model
    try:
        with open(MODEL_PATH, "rb") as fh:
            _model = pickle.load(fh)
        log.info("Loaded pickle model from %s", MODEL_PATH)
    except Exception as exc:
        log.warning("Failed to load pickle model (%s), using hybrid fallback", exc)
        _model = {}
    return _model


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
    service_inventory: list[dict] = []
    service_count: int = 0
    backend_service_count: int = 0
    db_service_count: int = 0
    external_service_count: int = 0
    request_count: int = 0
    logs_enabled: bool = False
    log_signals: dict = {}


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
SECURITY_HEADERS = [
    "X-Frame-Options", "X-Content-Type-Options", "Content-Security-Policy",
    "Strict-Transport-Security", "Referrer-Policy",
]


def extract_features(data: ReconData) -> dict:
    """Convert raw recon data into a numerical feature vector."""
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
    log_signals = data.log_signals or {}
    request_spikes = int(log_signals.get("request_spikes", 0))

    return {
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
        "service_count": data.service_count or len(data.service_inventory),
        "backend_service_count": data.backend_service_count,
        "db_service_count": data.db_service_count,
        "external_service_count": data.external_service_count,
        "request_count": data.request_count,
        "logs_enabled": 1 if data.logs_enabled else 0,
        "log_error_rate": float(log_signals.get("error_rate", 0.0)),
        "log_auth_failures": int(log_signals.get("auth_failures", 0)),
        "log_db_errors": int(log_signals.get("db_errors", 0)),
        "log_unusual_requests": int(log_signals.get("unusual_requests", 0)),
        "log_stack_traces": int(log_signals.get("stack_traces", 0)),
        "log_anomaly_count": int(log_signals.get("anomaly_count", 0)),
        "request_spikes": request_spikes,
        "api_count": backend_endpoints,
        "error_rate": float(log_signals.get("error_rate", 0.0)),
        "auth_failures": int(log_signals.get("auth_failures", 0)),
        "db_errors": int(log_signals.get("db_errors", 0)),
        "anomaly_score": int(log_signals.get("anomaly_count", 0)),
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
    if features["db_service_count"] > 0:
        sqli_score += 0.25
        reasons_sqli.append(f"{features['db_service_count']} database-backed service(s) observed")
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
    if features["log_db_errors"] > 0:
        sqli_score += min(0.30, features["log_db_errors"] * 0.03)
        reasons_sqli.append(f"{features['log_db_errors']} database error log event(s) observed")
    if features["log_stack_traces"] > 0:
        sqli_score += 0.10
        reasons_sqli.append("Log stack traces indicate backend exception leakage")
    if features["request_spikes"] > 0:
        sqli_score += min(0.12, features["request_spikes"] * 0.04)
        reasons_sqli.append(f"{features['request_spikes']} request spike signal(s) observed")
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
    if features["service_count"] >= 3:
        idor_score += 0.08
        reasons_idor.append("Multi-service topology increases cross-service object exposure")
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
    if features["log_auth_failures"] > 0:
        auth_score += min(0.25, features["log_auth_failures"] * 0.02)
        reasons_auth.append(f"{features['log_auth_failures']} authentication failure log event(s) observed")
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
    if features["log_error_rate"] >= 0.2:
        xss_score += 0.08
        reasons_xss.append("Elevated application error rate suggests fragile input handling")
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
    if features["log_unusual_requests"] > 0:
        traversal_score += min(0.20, features["log_unusual_requests"] * 0.03)
        reasons_trav.append(f"{features['log_unusual_requests']} suspicious request log event(s) observed")
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
    if features["log_stack_traces"] > 0:
        info_score += 0.20
        reasons_info.append("Logs expose stack traces or exception details")
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
    if features["external_service_count"] > 0:
        misconfig_score += 0.16
        reasons_misc.append(f"{features['external_service_count']} external dependency surface(s) observed")
    if features["no_tls"]:
        misconfig_score += 0.20
        reasons_misc.append("No TLS configured")
    if features["db_service_count"] > 0:
        misconfig_score += 0.10
        reasons_misc.append(f"{features['db_service_count']} database service(s) observed")
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


def predict_with_pickle_model(features: dict) -> list[VulnPrediction]:
    model = load_model()
    if not model:
        return []
    feature_order = model.get("feature_order", [])
    class_profiles = model.get("class_profiles", {})
    if not feature_order or not class_profiles:
        return []

    ordered_values = {name: float(features.get(name, 0)) for name in feature_order}
    predictions: list[VulnPrediction] = []
    for category, profile in class_profiles.items():
        score = float(profile.get("bias", 0.0))
        matches = []
        for feature_name in feature_order:
            weight = float(profile.get("weights", {}).get(feature_name, 0.0))
            if weight == 0:
                continue
            contribution = ordered_values[feature_name] * weight
            score += contribution
            if contribution > 0.05:
                matches.append(f"{feature_name}={ordered_values[feature_name]:.2f}")
        confidence = max(0.0, min(score, 0.99))
        threshold = float(profile.get("threshold", 0.15))
        if confidence >= threshold:
            predictions.append(VulnPrediction(
                category=category,
                confidence=round(confidence, 2),
                reasoning="Pickle model signals: " + ", ".join(matches[:4]) if matches else "Pickle model baseline confidence",
                recommended_payloads=profile.get("recommended_payloads", []),
            ))
    predictions.sort(key=lambda p: p.confidence, reverse=True)
    return predictions


def merge_predictions(model_predictions: list[VulnPrediction], rule_predictions: list[VulnPrediction]) -> list[VulnPrediction]:
    merged: dict[str, VulnPrediction] = {}
    for pred in rule_predictions:
        merged[pred.category] = pred
    for pred in model_predictions:
        existing = merged.get(pred.category)
        if existing is None or pred.confidence > existing.confidence:
            merged[pred.category] = pred
        elif existing is not None:
            existing.reasoning = f"{existing.reasoning}; {pred.reasoning}"
    return sorted(merged.values(), key=lambda item: item.confidence, reverse=True)


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
    rule_predictions = predict_vulnerabilities(features)
    pickle_predictions = predict_with_pickle_model(features)
    predictions = merge_predictions(pickle_predictions, rule_predictions)

    log.info("Predicted %d vulnerability categories for session %s", len(predictions), data.session_id)
    publish_service_metric(
        data.session_id,
        "ml-analysis",
        "Model 1 weighted backend API signals for vulnerability prediction",
        {
            "predictions": len(predictions),
            "backend_endpoints": features["backend_endpoint_count"],
            "graphql_endpoints": features["graphql_endpoint_count"],
            "services": features["service_count"],
            "anomaly_count": features["log_anomaly_count"],
            "model_source": "pickle+rules" if pickle_predictions else "rules",
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
