#!/bin/bash

echo "========================================="
echo "  SPECTRE Local Development Environment  "
echo "========================================="

# Ensure all background jobs are gracefully killed when the script stops
trap "echo -e '\nStopping all SPECTRE services...'; kill 0" EXIT

# Tell all Go services to connect to your native local Redis
export REDIS_ADDR="localhost:6379"

echo "[1/6] Starting ML Engine (Port 5001)..."
(cd ml-engine && pip install -q -r requirements.txt 2>/dev/null && python -m uvicorn main:app --port 5001 --log-level warning) &

echo "[2/6] Starting LLM Classifier (Port 5002)..."
(cd llm-classifier && pip install -q -r requirements.txt 2>/dev/null && python -m uvicorn main:app --port 5002 --log-level warning) &

echo "[3/6] Starting Scoring Engine (Port 5003)..."
(cd scoring-engine && pip install -q -r requirements.txt 2>/dev/null && python -m uvicorn main:app --port 5003 --log-level warning) &

# Give Python services a moment to start
sleep 2

echo "[4/6] Starting API Gateway (Port 8080)..."
(cd api-gateway && go run .) &

echo "[5/6] Starting Recon Engine..."
(cd recon-engine && go run .) &

echo "[6/6] Starting Attack Orchestrator..."
(cd attack-orchestrator && go run .) &

echo ""
echo "✅ All services successfully launched!"
echo "  🧠 ML Engine        → http://localhost:5001"
echo "  🏷️  LLM Classifier   → http://localhost:5002"
echo "  📊 Scoring Engine   → http://localhost:5003"
echo "  🌐 API Gateway      → http://localhost:8080"
echo ""
echo "👉 Open http://localhost:8080 in your browser."
echo "   (Press Ctrl+C here to safely shut everything down)"
echo "-----------------------------------------"

# Block and stream the combined logs of all 6 background processes
wait
