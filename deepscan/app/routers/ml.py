from fastapi import APIRouter, HTTPException, Query, Request
import httpx
import os
import logging

router = APIRouter(prefix="/ml", tags=["Machine Learning"])
logger = logging.getLogger(__name__)

ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL", "http://elasticsearch:9200")

@router.post("/create-jobs")
async def create_ml_jobs(scan_id: str = Query(..., description="Unique ID for the scan to correlate anomalies")):
    """
    Creates and starts 3 Elasticsearch native ML Anomaly Detection jobs for the given scan_id:
    1. deepscan-log-rate-{scan_id}: Detects unusual volume spikes in typical application logs.
    2. deepscan-falco-anomaly-{scan_id}: Detects unusual runtime security events (by rule name).
    3. deepscan-http-traffic-{scan_id}: Detects anomalies in HTTP request traffic volume.
    """
    
    headers = {"Content-Type": "application/json"}
    results = {}
    
    # Define the 3 jobs
    jobs = [
        {
            "id": f"deepscan-log-rate-{scan_id}",
            "description": f"Detects unusual log volume spikes for scan {scan_id}",
            "index": "deepscan-logs",
            "analysis_config": {
                "bucket_span": "5m",
                "detectors": [{"function": "count"}]
            },
            "data_description": {"time_field": "@timestamp"},
            "query": {
                "bool": {"filter": [{"term": {"scan_id": scan_id}}]}
            }
        },
        {
            "id": f"deepscan-falco-anomaly-{scan_id}",
            "description": f"Detects unusual Falco runtime events for scan {scan_id}",
            "index": "deepscan-falco",
            "analysis_config": {
                "bucket_span": "5m",
                "detectors": [{"function": "rare", "by_field_name": "rule"}]
            },
            "data_description": {"time_field": "@timestamp"},
            "query": {
               "bool": {"filter": [{"term": {"customfields.environment": "deepscan"}}]}
            }
        },
        {
            "id": f"deepscan-http-traffic-{scan_id}",
            "description": f"Detects HTTP traffic anomalies for scan {scan_id}",
            "index": "deepscan-logs",
            "analysis_config": {
                "bucket_span": "5m",
                "detectors": [{"function": "high_count", "partition_field_name": "event.dataset"}]
            },
            "data_description": {"time_field": "@timestamp"},
            "query": {
                "bool": {"filter": [{"term": {"scan_id": scan_id}}, {"term": {"event.dataset": "deepscan.target"}}]}
            }
        }
    ]
    
    async with httpx.AsyncClient(base_url=ELASTICSEARCH_URL) as client:
        for job in jobs:
            job_id = job["id"]
            
            # 1. Create Job
            job_payload = {
                "description": job["description"],
                "analysis_config": job["analysis_config"],
                "data_description": job["data_description"]
            }
            res_job = await client.put(f"/_ml/anomaly_detectors/{job_id}", json=job_payload, headers=headers)
            
            if res_job.status_code not in (200, 400): # 400 likely means it already exists
                logger.error(f"Failed to create job {job_id}: {res_job.text}")
                results[job_id] = {"status": "error", "message": "Failed to create job", "details": res_job.text}
                continue
                
            # 2. Create Datafeed
            datafeed_id = f"datafeed-{job_id}"
            datafeed_payload = {
                "job_id": job_id,
                "indices": [job["index"]],
                "query": job["query"]
            }
            res_df = await client.put(f"/_ml/datafeeds/{datafeed_id}", json=datafeed_payload, headers=headers)
            
            # 3. Open Job
            res_open = await client.post(f"/_ml/anomaly_detectors/{job_id}/_open", headers=headers)
            
            # 4. Start Datafeed
            res_start = await client.post(f"/_ml/datafeeds/{datafeed_id}/_start", json={"start": "now-1h"}, headers=headers)
            
            results[job_id] = {
                "status": "success",
                "job_created": res_job.status_code == 200,
                "datafeed_created": res_df.status_code == 200,
                "job_opened": res_open.status_code == 200,
                "datafeed_started": res_start.status_code == 200
            }
            
    return {"message": f"ML Jobs provisioning completed for {scan_id}", "details": results}

