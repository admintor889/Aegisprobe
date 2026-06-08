#!/usr/bin/env bash
# ============================================================
# AegisProbe Web UI Launcher (Linux / macOS)
# Prerequisites: Node.js >= 22.14.0, pnpm >= 10.0.0
# ============================================================

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Check Node.js
if ! command -v node &> /dev/null; then
    echo "[ERROR] Node.js is not installed or not in PATH."
    echo "Please install Node.js >= 22.14.0 from https://nodejs.org"
    exit 1
fi

# Check pnpm
if ! command -v pnpm &> /dev/null; then
    echo "[INFO] pnpm not found, installing..."
    npm install -g pnpm
fi

# Install dependencies if needed
if [ ! -d "node_modules" ]; then
    echo "[INFO] Installing dependencies..."
    pnpm install
fi

# Build if dist missing
if [ ! -f "apps/cli/dist/index.js" ]; then
    echo "[INFO] Building packages..."
    pnpm build
fi

# Set API key if not configured
if [ ! -f ".env" ]; then
    echo "[WARN] .env file not found. Copy .env.example to .env and set DEEPSEEK_API_KEY"
    cp .env.example .env
    echo "Please edit .env with your DeepSeek API key, then re-run."
    exit 1
fi

echo "[INFO] Starting AegisProbe Web UI on http://127.0.0.1:3000"
node apps/cli/dist/index.js webui --port 3000
