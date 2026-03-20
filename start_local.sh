#!/bin/bash

echo "========================================="
echo "  SPECTRE Local Development Environment  "
echo "========================================="

# ── Cleanup: kill any leftover SPECTRE processes from previous runs ──
echo "[cleanup] Killing stale processes..."
pkill -f "uvicorn main:app --port 500" 2>/dev/null
pkill -f "go run \." 2>/dev/null
lsof -ti:8080 -ti:5001 -ti:5002 -ti:5003 -ti:5004 2>/dev/null | xargs kill -9 2>/dev/null
sleep 1

# ── Flush Redis streams to avoid stale consumer groups ──
echo "[cleanup] Flushing Redis streams..."
redis-cli FLUSHALL > /dev/null 2>&1

# Ensure all background jobs are gracefully killed when the script stops
trap "echo -e '\nStopping all SPECTRE services...'; kill 0" EXIT

# Tell all Go services to connect to your native local Redis and use IPv4 loopback for Python services
export REDIS_ADDR="localhost:6379"
export ML_ENGINE_URL="http://127.0.0.1:5001"
export LLM_CLASSIFIER_URL="http://127.0.0.1:5002"
export SCORING_ENGINE_URL="http://127.0.0.1:5003"
export INTEL_SERVICE_URL="http://127.0.0.1:5004"

echo "[1/7] Starting ML Engine (Port 5001)..."
(cd ml-engine && python3 -m pip install -q -r requirements.txt 2>/dev/null && python3 -m uvicorn main:app --port 5001 --log-level warning) &

echo "[2/7] Starting LLM Classifier (Port 5002)..."
(cd llm-classifier && python3 -m pip install -q -r requirements.txt 2>/dev/null && python3 -m uvicorn main:app --port 5002 --log-level warning) &

echo "[3/7] Starting Scoring Engine (Port 5003)..."
(cd scoring-engine && python3 -m pip install -q -r requirements.txt 2>/dev/null && python3 -m uvicorn main:app --port 5003 --log-level warning) &

echo "[4/7] Starting Intel Service (Port 5004)..."
(cd intel-service && python3 -m pip install -q -r requirements.txt 2>/dev/null && python3 -m uvicorn main:app --port 5004 --log-level warning) &

# Give Python services a moment to start
sleep 2

echo "[5/7] Starting API Gateway (Port 8080)..."
(cd api-gateway && go run .) &

echo "[6/7] Starting Recon Engine..."
(cd recon-engine && go run .) &

echo "[7/7] Starting Attack Orchestrator..."
(cd attack-orchestrator && go run .) &

echo ""
echo "✅ All services successfully launched!"
echo "  🧠 ML Engine        → http://localhost:5001"
echo "  🏷️  LLM Classifier   → http://localhost:5002"
echo "  📊 Scoring Engine   → http://localhost:5003"
echo "  🔎 Intel Service    → http://localhost:5004"
echo "  🌐 API Gateway      → http://localhost:8080"
echo ""
echo "👉 Open http://localhost:8080 in your browser."
echo "   (Press Ctrl+C here to safely shut everything down)"
echo "-----------------------------------------"

# Block and stream the combined logs of all 7 background processes
wait
