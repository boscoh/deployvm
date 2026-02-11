#!/bin/bash
# Deploy tspots Nuxt app
# Usage: ./deploy-tspots.sh [--ssl]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "$1" = "--ssl" ]; then
    echo "Deploying tspots to tangiblespots.com"
    uv run deploy-vm nuxt deploy \
        tspots \
        "$SCRIPT_DIR/../nimago" \
        --port 3000 \
        --app-name tspots \
        --local-build \
        --domain tangiblespots.com \
        --email apposite@gmail.com
else
    echo "Deploying tspots (IP-only, local build)"
    uv run deploy-vm nuxt deploy \
        tspots2 \
        "$SCRIPT_DIR/../nimago" \
        --port 3000 \
        --app-name tspots \
        --local-build \
        --no-ssl
fi
