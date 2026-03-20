# DeepScan Enhanced Task 1.5 — Real-Time Logs + ML Anomaly Detection

Welcome to the **DeepScan Context-Aware Defense Platform**. This module runs a complete CNAPP (Cloud-Native Application Protection Platform) pipeline with native **Machine Learning Anomaly Detection**.

## 🚀 Architecture Highlights
- **Falco 0.39** runs in modern BPF mode monitoring the kernel context.
- **Falcosidekick** receives Falco JSON events and streams them with a 2-second batch interval into `deepscan-falco` Elasticsearch index.
- **Fluent Bit 3.1** acts as the log router, enriching container logs with ECS (Elastic Common Schema) tags and a `scan_id` correlation ID into the `deepscan-logs` index.
- **Elasticsearch + Kibana 8.15** processes the unified data lake.
- **FastAPI Backend** acts as the orchestration layer, configuring live ML jobs directly on the ES cluster via the REST framework.

---

## 🏃 Setup & Run (Zero-Config)

1. Boot the entire stack:
   ```bash
   docker compose up --build -d
   ```
   *(Ensure you have ~4GB of RAM allocated to Docker. The stack enforces strict memory limits on Falco and Fluent Bit to keep overhead low).*

2. Wait ~45 seconds for Elasticsearch and Kibana to form the cluster and become healthy. You can check the status via:
   ```bash
   docker compose ps
   ```

3. Connect to the Live Dashboard:
   Open [http://localhost:5601](http://localhost:5601) completely credential-free.

---

## 🧠 Real-Time Anomalies in 30 Seconds

The true capability of this module is the native Kibana Machine Learning integration triggered by the API.

1. **Trigger the ML Anomaly Creation**  
   Run this `curl` command to tell the FastAPI router to build and launch 3 independent Machine Learning anomaly detection jobs on Elasticsearch:
   ```bash
   curl -X POST "http://localhost:8000/ml/create-jobs?scan_id=DEMO-001"
   ```
   *Expected Response:* 
   ```json
   {
     "message": "ML Jobs provisioning completed for DEMO-001",
     "details": {
       "deepscan-log-rate-DEMO-001": {"status": "success", ...},
       "deepscan-falco-anomaly-DEMO-001": {"status": "success", ...},
       "deepscan-http-traffic-DEMO-001": {"status": "success", ...}
     }
   }
   ```

2. **Simulate an Anomaly (Attack)**
   Generate an unusual amount of traffic or spawn a reverse shell to trigger a Falco anomaly:
   ```bash
   # Create a traffic anomaly
   for i in {1..50}; do curl -s "http://localhost:3000" > /dev/null; done

   # Trigger Falco by reading a sensitive file inside the target container
   docker exec deepscan-target cat /etc/shadow
   ```

3. **View the Results in Kibana**
   - Head to Kibana **(http://localhost:5601/app/ml/anomaly_detection/explorer)**.
   - You will see the jobs running. Within minutes, the system will identify the deviations from the 5-minute bucket baselines and flag them with standard Kibana anomaly severity scores (0-100).

---

## 🔌 Import the Dashboard

A complete pre-built dashboard combines Falco runtime events and Fluent Bit logs on a single unified timeline.

1. Go to **Kibana → Stack Management → Saved Objects**.
2. Click **Import** in the top right.
3. Upload `kibana/deepscan-dashboard.ndjson`.
4. Navigate back to **Dashboards** and open **DeepScan Timeline + Anomalies**.

*Note: Enable "Auto-refresh" (top right, set to 5 seconds) to watch logs and container alerts stream in real-time.*

---

## ⚙️ Adding to Your Own App
To protect a different Node/React app, simply match the structured logging:
1. Wrap your app inside `docker-compose.yml`.
2. Add the Fluentd logging driver to your service (see `example-target` configuration).
3. The logs automatically arrive in Elasticsearch with the proper `scan_id` injected via the Lua filter.
