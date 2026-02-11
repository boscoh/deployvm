#!/bin/bash
# Deploy chatboti FastAPI app to a new cloud instance
# Usage: ./deploy-chatboti.sh [--ssl]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "$1" = "--ssl" ]; then
    echo "Deploying chatboti to chatboti.io"
    uv run deploy-vm fastapi deploy \
        chatboti \
        "$SCRIPT_DIR/../chatboti" \
        --app-module "chatboti.server:app" \
        --app-name "chatboti" \
        --port 8000 \
        --workers 1 \
        --domain chatboti.io \
        --email apposite@gmail.com
else
    echo "Deploying chatboti (IP-only, no SSL)"
    uv run deploy-vm fastapi deploy \
        chatboti \
        "$SCRIPT_DIR/../chatboti" \
        --app-module "chatboti.server:app" \
        --app-name "chatboti" \
        --port 8000 \
        --workers 1 \
        --no-ssl
fi
