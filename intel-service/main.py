"""
SPECTRE Intel Service — Threat Intelligence Enrichment

Enriches findings with CVE intelligence from NVD, CISA KEV, EPSS, and
optional SploitScan output when available locally.
"""

import json
import os
import re
import resource
import subprocess
import tempfile
import time
import logging
from typing import Any, Optional

import httpx
import redis
import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field


REDIS_ADDR = os.getenv("REDIS_ADDR", "localhost:6379")
REDIS_HOST, REDIS_PORT = REDIS_ADDR.split(":")
SPLOITSCAN_PATH = os.getenv("SPLOITSCAN_PATH", "")
SPLOITSCAN_PYTHON = os.getenv("SPLOITSCAN_PYTHON", "python3")
NVD_API_URL = os.getenv("NVD_API_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")
EPSS_API_URL = os.getenv("EPSS_API_URL", "https://api.first.org/data/v1/epss")
KEV_FEED_URL = os.getenv("KEV_FEED_URL", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
INTEL_CACHE_TTL_SECONDS = int(os.getenv("INTEL_CACHE_TTL_SECONDS", "21600"))
SESSION_INTEL_TTL_SECONDS = int(os.getenv("SESSION_INTEL_TTL_SECONDS", "172800"))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [intel-service] %(message)s")
log = logging.getLogger("intel-service")

app = FastAPI(title="SPECTRE Intel Service", version="1.0.0")
_redis: Optional[redis.Redis] = None
_kev_cache: dict[str, Any] = {"fetched_at": 0.0, "items": {}}

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def get_redis() -> redis.Redis:
    global _redis
    if _redis is None:
        _redis = redis.Redis(host=REDIS_HOST, port=int(REDIS_PORT), decode_responses=True)
        _redis.ping()
        log.info("Connected to Redis at %s", REDIS_ADDR)
    return _redis


class IntelRequest(BaseModel):
    session_id: str = ""
    target_url: str = ""
    finding_type: str = ""
    attack_result: str = ""
    cves: list[str] = Field(default_factory=list)


class CVEIntel(BaseModel):
    cve: str
    cvss_score: float = 0.0
    cvss_severity: str = "UNKNOWN"
    description: str = ""
    epss: float = 0.0
    kev: bool = False
    exploit_references: list[str] = Field(default_factory=list)
    source: str = "intel-service"


class IntelResponse(BaseModel):
    session_id: str
    target_url: str
    finding_type: str
    cves: list[str]
    intel_items: list[CVEIntel]
    highest_epss: float
    kev_count: int
    exploit_reference_count: int
    priority: str
    priority_score: float
    rationale: str
    timestamp: str


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "intel-service",
        "sploitscan_configured": bool(resolve_sploitscan_command()),
        "sploitscan_path": SPLOITSCAN_PATH or "",
    }


@app.get("/intel/cve/{cve_id}", response_model=IntelResponse)
async def get_cve_intel(cve_id: str):
    normalized = normalize_cves([cve_id])
    if not normalized:
        raise HTTPException(status_code=400, detail="valid CVE required")
    return await enrich_intel(IntelRequest(cves=normalized, finding_type="Direct CVE Query"))


@app.post("/intel", response_model=IntelResponse)
async def enrich_intel(req: IntelRequest):
    started = time.perf_counter()
    cves = normalize_cves(req.cves or extract_cves(req.attack_result))
    intel_items = await enrich_cves(cves)
    highest_epss = max((item.epss for item in intel_items), default=0.0)
    kev_count = sum(1 for item in intel_items if item.kev)
    exploit_reference_count = sum(len(item.exploit_references) for item in intel_items)
    priority_score = compute_priority_score(req.finding_type, intel_items)
    priority = priority_band(priority_score)
    rationale = build_rationale(req.finding_type, intel_items, priority)
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    response = IntelResponse(
        session_id=req.session_id,
        target_url=req.target_url,
        finding_type=req.finding_type,
        cves=cves,
        intel_items=intel_items,
        highest_epss=round(highest_epss, 3),
        kev_count=kev_count,
        exploit_reference_count=exploit_reference_count,
        priority=priority,
        priority_score=round(priority_score, 2),
        rationale=rationale,
        timestamp=timestamp,
    )
    store_session_intel(response)
    publish_intel(response, round((time.perf_counter() - started) * 1000, 2))
    return response


@app.post("/intel/session/enrich", response_model=IntelResponse)
async def enrich_session_intel(req: IntelRequest):
    if not req.session_id:
        raise HTTPException(status_code=400, detail="session_id is required")
    return await enrich_intel(req)


@app.get("/intel/session/{session_id}")
def get_session_intel(session_id: str):
    session_key = session_intel_list_key(session_id)
    items = get_redis().lrange(session_key, 0, 24)
    return {
        "session_id": session_id,
        "count": len(items),
        "items": [json.loads(item) for item in items],
    }


def normalize_cves(cves: list[str]) -> list[str]:
    out: list[str] = []
    seen = set()
    for cve in cves:
        match = CVE_PATTERN.search(cve or "")
        if not match:
            continue
        value = match.group(0).upper()
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out[:10]


def extract_cves(raw: str) -> list[str]:
    return [match.group(0).upper() for match in CVE_PATTERN.finditer(raw or "")]


async def enrich_cves(cves: list[str]) -> list[CVEIntel]:
    sploitscan = run_sploitscan(cves) if cves else {}
    kev_items = await fetch_kev_items()
    results: list[CVEIntel] = []
    async with httpx.AsyncClient(timeout=15.0) as client:
        for cve in cves:
            cached = get_cached_cve_intel(cve)
            if cached is not None:
                cached.exploit_references = merge_refs(cached.exploit_references, sploitscan.get(cve, []))
                results.append(cached)
                continue
            nvd = await fetch_nvd_cve(client, cve)
            epss = await fetch_epss(client, cve)
            kev = cve in kev_items
            exploit_refs = sploitscan.get(cve, [])
            item = CVEIntel(
                cve=cve,
                cvss_score=nvd.get("cvss_score", 0.0),
                cvss_severity=nvd.get("cvss_severity", "UNKNOWN"),
                description=nvd.get("description", ""),
                epss=epss,
                kev=kev,
                exploit_references=exploit_refs,
            )
            cache_cve_intel(item)
            results.append(item)
    return results


async def fetch_nvd_cve(client: httpx.AsyncClient, cve: str) -> dict[str, Any]:
    try:
        resp = await client.get(NVD_API_URL, params={"cveId": cve})
        resp.raise_for_status()
        payload = resp.json()
        vulnerabilities = payload.get("vulnerabilities", [])
        if not vulnerabilities:
            return {}
        cve_payload = vulnerabilities[0].get("cve", {})
        metrics = cve_payload.get("metrics", {})
        cvss_score = 0.0
        cvss_severity = "UNKNOWN"
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if entries:
                cvss_data = entries[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                cvss_severity = cvss_data.get("baseSeverity", entries[0].get("baseSeverity", "UNKNOWN"))
                break
        description = ""
        for desc in cve_payload.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        return {
            "cvss_score": float(cvss_score or 0.0),
            "cvss_severity": cvss_severity,
            "description": description,
        }
    except Exception as exc:
        log.info("NVD lookup failed for %s: %s", cve, type(exc).__name__)
        return {}


async def fetch_epss(client: httpx.AsyncClient, cve: str) -> float:
    try:
        resp = await client.get(EPSS_API_URL, params={"cve": cve})
        resp.raise_for_status()
        payload = resp.json()
        data = payload.get("data", [])
        if not data:
            return 0.0
        return float(data[0].get("epss", 0.0))
    except Exception as exc:
        log.info("EPSS lookup failed for %s: %s", cve, type(exc).__name__)
        return 0.0


async def fetch_kev_items() -> dict[str, Any]:
    now = time.time()
    if now - _kev_cache["fetched_at"] < 1800 and _kev_cache["items"]:
        return _kev_cache["items"]
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.get(KEV_FEED_URL)
            resp.raise_for_status()
            payload = resp.json()
            items = {item.get("cveID", "").upper(): item for item in payload.get("vulnerabilities", []) if item.get("cveID")}
            _kev_cache["items"] = items
            _kev_cache["fetched_at"] = now
            return items
    except Exception as exc:
        log.info("KEV feed lookup failed: %s", type(exc).__name__)
        return _kev_cache.get("items", {})


def run_sploitscan(cves: list[str]) -> dict[str, list[str]]:
    command = resolve_sploitscan_command()
    if not command:
        return {}
    try:
        with tempfile.NamedTemporaryFile("w+", delete=False) as handle:
            handle.write("\n".join(cves))
            handle.flush()
            tmp_path = handle.name
        cmd = command + ["-i", tmp_path, "-e", "json"]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        os.unlink(tmp_path)
        if proc.returncode != 0:
            log.info("SploitScan returned %s", proc.returncode)
            return {}
        payload = json.loads(proc.stdout or "{}")
        normalized: dict[str, list[str]] = {}
        if isinstance(payload, list):
            for item in payload:
                cve = str(item.get("cve") or item.get("cve_id") or "").upper()
                if not cve:
                    continue
                refs = extract_refs(item)
                normalized[cve] = refs
        elif isinstance(payload, dict):
            for cve, item in payload.items():
                normalized[cve.upper()] = extract_refs(item if isinstance(item, dict) else {})
        return normalized
    except Exception as exc:
        log.info("SploitScan execution failed: %s", type(exc).__name__)
        return {}


def resolve_sploitscan_command() -> list[str]:
    if not SPLOITSCAN_PATH:
        return []
    if os.path.isdir(SPLOITSCAN_PATH):
        candidate = os.path.join(SPLOITSCAN_PATH, "sploitscan.py")
        if os.path.exists(candidate):
            return [SPLOITSCAN_PYTHON, candidate]
        return []
    if not os.path.exists(SPLOITSCAN_PATH):
        return []
    if SPLOITSCAN_PATH.endswith(".py"):
        return [SPLOITSCAN_PYTHON, SPLOITSCAN_PATH]
    return [SPLOITSCAN_PATH]


def extract_refs(item: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    for key in ("exploits", "references", "sources", "metasploit", "nuclei", "github"):
        value = item.get(key)
        if isinstance(value, list):
            refs.extend(str(entry) for entry in value if entry)
        elif isinstance(value, str) and value:
            refs.append(value)
    # Keep the result short and deduped for dashboard/report use.
    deduped: list[str] = []
    seen = set()
    for ref in refs:
        if ref not in seen:
            seen.add(ref)
            deduped.append(ref)
    return deduped[:6]


def merge_refs(existing: list[str], new_refs: list[str]) -> list[str]:
    merged: list[str] = []
    seen = set()
    for ref in existing + new_refs:
        if ref and ref not in seen:
            seen.add(ref)
            merged.append(ref)
    return merged[:6]


def compute_priority_score(finding_type: str, intel_items: list[CVEIntel]) -> float:
    if not intel_items:
        baseline = {
            "SQL Injection": 6.8,
            "Insecure Direct Object Reference (IDOR)": 6.4,
            "Weak Authentication / Authorization": 6.6,
        }
        return baseline.get(finding_type, 4.8)
    top_cvss = max((item.cvss_score for item in intel_items), default=0.0)
    highest_epss = max((item.epss for item in intel_items), default=0.0)
    kev_bonus = 1.4 if any(item.kev for item in intel_items) else 0.0
    exploit_bonus = min(sum(len(item.exploit_references) for item in intel_items) * 0.15, 1.2)
    return min(10.0, top_cvss * 0.55 + highest_epss * 4.0 + kev_bonus + exploit_bonus)


def priority_band(score: float) -> str:
    if score >= 8.8:
        return "A+"
    if score >= 7.4:
        return "A"
    if score >= 6.0:
        return "B"
    if score >= 4.5:
        return "C"
    return "D"


def build_rationale(finding_type: str, intel_items: list[CVEIntel], priority: str) -> str:
    if not intel_items:
        return f"{finding_type or 'Finding'} has no mapped CVE yet, so priority is based on runtime evidence only."
    parts: list[str] = [f"Priority {priority} from mapped CVE intelligence"]
    highest_epss = max((item.epss for item in intel_items), default=0.0)
    if highest_epss > 0:
        parts.append(f"highest EPSS {highest_epss:.3f}")
    kev_hits = sum(1 for item in intel_items if item.kev)
    if kev_hits:
        parts.append(f"{kev_hits} KEV hit(s)")
    exploit_refs = sum(len(item.exploit_references) for item in intel_items)
    if exploit_refs:
        parts.append(f"{exploit_refs} exploit reference(s)")
    return "; ".join(parts)


def cve_cache_key(cve: str) -> str:
    return f"intel:cve:{cve.upper()}"


def session_intel_list_key(session_id: str) -> str:
    return f"intel:session:{session_id}:history"


def session_intel_latest_key(session_id: str) -> str:
    return f"intel:session:{session_id}:latest"


def get_cached_cve_intel(cve: str) -> Optional[CVEIntel]:
    try:
        cached = get_redis().get(cve_cache_key(cve))
        if not cached:
            return None
        return CVEIntel(**json.loads(cached))
    except Exception as exc:
        log.info("cached CVE read failed for %s: %s", cve, type(exc).__name__)
        return None


def cache_cve_intel(item: CVEIntel):
    try:
        get_redis().setex(cve_cache_key(item.cve), INTEL_CACHE_TTL_SECONDS, item.model_dump_json())
    except Exception as exc:
        log.info("cached CVE write failed for %s: %s", item.cve, type(exc).__name__)


def store_session_intel(resp: IntelResponse):
    if not resp.session_id:
        return
    try:
        payload = resp.model_dump_json()
        rdb = get_redis()
        rdb.setex(session_intel_latest_key(resp.session_id), SESSION_INTEL_TTL_SECONDS, payload)
        rdb.lpush(session_intel_list_key(resp.session_id), payload)
        rdb.ltrim(session_intel_list_key(resp.session_id), 0, 24)
        rdb.expire(session_intel_list_key(resp.session_id), SESSION_INTEL_TTL_SECONDS)
    except Exception as exc:
        log.info("session intel persistence failed for %s: %s", resp.session_id, type(exc).__name__)


def publish_intel(resp: IntelResponse, duration_ms: float):
    try:
        payload = resp.model_dump()
        payload["type"] = "threat-intel"
        payload["message"] = f"Threat intelligence priority {resp.priority} for {resp.finding_type or 'finding'}"
        payload["duration_ms"] = duration_ms
        get_redis().xadd("threat-intel", {"payload": json.dumps(payload)})
        publish_service_metric(resp.session_id, "intel", "Threat intelligence enrichment completed", {
            "cves": len(resp.cves),
            "priority": resp.priority,
            "priority_score": resp.priority_score,
            "duration_ms": duration_ms,
        })
    except Exception as exc:
        log.warning("Failed to publish threat intel: %s", exc)


def publish_service_metric(session_id: str, phase: str, impact: str, extra: Optional[dict] = None):
    try:
        usage = resource.getrusage(resource.RUSAGE_SELF)
        payload = {
            "session_id": session_id,
            "service": "intel-service",
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
    except Exception as exc:
        log.warning("Failed to publish service metric: %s", exc)


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=5004, reload=True)
