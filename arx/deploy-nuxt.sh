#!/bin/bash

# Nuxt Deployment Script
# Deploys Nuxt app with Node.js and PM2

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  --ip IP               Server IP address (required)"
    echo "  --source PATH         Path to local Nuxt codebase (required)"
    echo "  --app-user USER       User to run the app as (required)"
    echo "  --user USER           SSH user (default: root)"
    echo "  --port PORT           Port for Nuxt to listen on (default: 3000)"
    echo "  --local-build         Build locally and upload .output (for low-memory servers)"
    echo "  --force-build         Force rebuild even if source unchanged"
    echo "  -h, --help            Show this help message"
    echo ""
    echo "Example:"
    echo "  $0 --ip 192.168.1.100 --source ../my-nuxt-app --app-user deploy"
    exit 0
}

parse_args() {
while [[ $# -gt 0 ]]; do
    case $1 in
        --ip)
                [[ -z "$2" || "$2" == --* ]] && { log_error "--ip requires a value"; exit 1; }
            SERVER_IP="$2"
            shift 2
            ;;
        --source)
                [[ -z "$2" || "$2" == --* ]] && { log_error "--source requires a value"; exit 1; }
            NUXT_SOURCE="$2"
            shift 2
            ;;
        --app-user)
                [[ -z "$2" || "$2" == --* ]] && { log_error "--app-user requires a value"; exit 1; }
            APP_USER="$2"
            shift 2
            ;;
        --user)
                [[ -z "$2" || "$2" == --* ]] && { log_error "--user requires a value"; exit 1; }
            SSH_USER="$2"
            shift 2
            ;;
        --port)
                [[ -z "$2" || "$2" == --* ]] && { log_error "--port requires a value"; exit 1; }
            APP_PORT="$2"
            shift 2
            ;;
            --local-build)
                LOCAL_BUILD=1
                shift
                ;;
            --force-build)
                FORCE_BUILD=1
                shift
                ;;
        -h|--help)
            usage
            ;;
        *)
                log_error "Unknown option: $1"
            usage
            ;;
    esac
done

SSH_USER="${SSH_USER:-root}"
APP_PORT="${APP_PORT:-3000}"
SSH_OPTS="-o StrictHostKeyChecking=no -o BatchMode=no"

if [ -z "$SERVER_IP" ]; then
    log_error "Server IP is required. Use --ip"
    exit 1
fi
if [ -z "$NUXT_SOURCE" ]; then
    log_error "Nuxt source path is required. Use --source"
    exit 1
fi
if [ ! -d "$NUXT_SOURCE" ]; then
    log_error "Nuxt source directory not found: $NUXT_SOURCE"
    exit 1
fi
if [ -z "$APP_USER" ]; then
    log_error "App user is required. Use --app-user"
    exit 1
fi
}

setup_node_pm2() {
log_info "Installing Node.js and PM2..."

ssh $SSH_OPTS "$SSH_USER@$SERVER_IP" bash -s "$APP_USER" "$APP_PORT" << 'ENDSSH'
APP_USER="$1"
APP_PORT="$2"
set -e

echo "Installing Node.js..."
if ! command -v node &> /dev/null; then
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
    sudo apt-get install -y nodejs
fi
node --version

echo "Installing PM2..."
if ! command -v pm2 &> /dev/null; then
    sudo npm install -g pm2
fi

echo "Preparing app directory..."
sudo mkdir -p /home/$APP_USER/nuxt
sudo chown -R $APP_USER:$APP_USER /home/$APP_USER/nuxt

echo "Creating PM2 ecosystem config..."
cat > /tmp/ecosystem.config.cjs <<PMCONF
module.exports = {
  apps: [{
    name: 'nuxt',
    script: './.output/server/index.mjs',
    cwd: '/home/$APP_USER/nuxt',
    node_args: '-r dotenv/config',
    instances: 'max',
    exec_mode: 'cluster',
    env: {
      NODE_ENV: 'production',
      PORT: $APP_PORT
    }
  }]
};
PMCONF
sudo mv /tmp/ecosystem.config.cjs /home/$APP_USER/nuxt/ecosystem.config.cjs
sudo chown $APP_USER:$APP_USER /home/$APP_USER/nuxt/ecosystem.config.cjs

echo "Node.js and PM2 ready!"
ENDSSH
}

compute_source_hash() {
    log_info "Computing source checksum..."

    LOCAL_HASH=$(find "$NUXT_SOURCE" -type f \
        ! -path "*node_modules*" \
        ! -path "*.output*" \
        ! -path "*.nuxt*" \
        ! -path "*.git*" \
        ! -path "*public/projects*" \
        ! -path "*data/scripts/models*" \
        ! -path "*json/projects*" \
        -exec md5sum {} \; 2>/dev/null | sort | md5sum | cut -d' ' -f1)

    REMOTE_HASH=$(ssh $SSH_OPTS "$SSH_USER@$SERVER_IP" "cat /home/$APP_USER/nuxt/.source_hash 2>/dev/null || echo ''")

    if [ -z "$FORCE_BUILD" ] && [ "$LOCAL_HASH" = "$REMOTE_HASH" ] && [ -n "$REMOTE_HASH" ]; then
        log_info "Source unchanged (hash: $LOCAL_HASH). Skipping upload and build."
        SKIP_BUILD=1
    else
        if [ -n "$FORCE_BUILD" ]; then
            log_info "Force build requested"
        elif [ -z "$REMOTE_HASH" ]; then
            log_info "No previous build found"
        else
            log_info "Source changed (local: $LOCAL_HASH, remote: $REMOTE_HASH)"
        fi
    fi
}

restart_app() {
    log_info "Restarting app (no rebuild needed)..."

    ssh $SSH_OPTS "$SSH_USER@$SERVER_IP" bash -s "$APP_USER" << 'ENDSSH'
APP_USER="$1"
set -e
if ! sudo -u $APP_USER pm2 reload nuxt 2>/dev/null; then
    echo "PM2 reload failed, cleaning up and restarting..."
    sudo -u $APP_USER pm2 kill 2>/dev/null || true
    rm -f /home/$APP_USER/.pm2/*.sock /home/$APP_USER/.pm2/pm2.pid 2>/dev/null || true
    sudo -u $APP_USER pm2 start /home/$APP_USER/nuxt/ecosystem.config.cjs
    sudo -u $APP_USER pm2 save
fi
echo "App restarted!"
ENDSSH
}

build_locally() {
    log_info "Building locally..."
    (cd "$NUXT_SOURCE" && npm install && npm run build)

    if [ ! -d "$NUXT_SOURCE/.output" ]; then
        log_error "Local build failed - no .output directory"
        exit 1
    fi

    log_info "Uploading built app..."
    rsync -avz --delete \
        --exclude='node_modules' \
        --exclude='.nuxt' \
        --exclude='.git' \
        --exclude='public/projects/' \
        --exclude='data/scripts/models/' \
        --exclude='json/projects*' \
        --exclude='ecosystem.config.cjs' \
        --exclude='.source_hash' \
        "$NUXT_SOURCE/" "$SSH_USER@$SERVER_IP:/home/$APP_USER/nuxt/"

    start_pm2
}

build_on_server() {
    log_info "Uploading source code..."
rsync -avz --delete \
    --exclude='node_modules' \
    --exclude='.output' \
    --exclude='.nuxt' \
    --exclude='.git' \
    --exclude='public/projects/' \
    --exclude='data/scripts/models/' \
    --exclude='json/projects*' \
        --exclude='ecosystem.config.cjs' \
        --exclude='.source_hash' \
    "$NUXT_SOURCE/" "$SSH_USER@$SERVER_IP:/home/$APP_USER/nuxt/"

    log_info "Building on server..."
    ssh $SSH_OPTS "$SSH_USER@$SERVER_IP" bash -s "$APP_USER" "$LOCAL_HASH" << 'ENDSSH'
APP_USER="$1"
LOCAL_HASH="$2"
set -e

cd /home/$APP_USER/nuxt

echo "Installing dependencies..."
sudo -u $APP_USER rm -rf package-lock.json .nuxt
export NODE_OPTIONS="--max-old-space-size=1024"
sudo -u $APP_USER npm install

echo "Building Nuxt..."
sudo -u $APP_USER npm run build

echo "Saving source hash..."
echo "$LOCAL_HASH" | sudo -u $APP_USER tee /home/$APP_USER/nuxt/.source_hash > /dev/null

echo "Setting permissions..."
sudo chown -R $APP_USER:$APP_USER /home/$APP_USER/nuxt

echo "Cleaning up stale PM2..."
pkill -u $APP_USER -f pm2 2>/dev/null || true
pkill -u $APP_USER -f "node.*index.mjs" 2>/dev/null || true
rm -rf /home/$APP_USER/.pm2 2>/dev/null || true
sleep 1

echo "Starting PM2..."
su - $APP_USER -c "cd /home/$APP_USER/nuxt && pm2 start ecosystem.config.cjs && pm2 save"

sudo env PATH=$PATH:/usr/bin pm2 startup systemd -u $APP_USER --hp /home/$APP_USER 2>/dev/null || true

echo "Nuxt deployed and running!"
ENDSSH
}

start_pm2() {
    log_info "Starting app on server..."

    ssh $SSH_OPTS "$SSH_USER@$SERVER_IP" bash -s "$APP_USER" "$LOCAL_HASH" << 'ENDSSH'
APP_USER="$1"
LOCAL_HASH="$2"
set -e

echo "Saving source hash..."
echo "$LOCAL_HASH" | sudo -u $APP_USER tee /home/$APP_USER/nuxt/.source_hash > /dev/null

echo "Setting permissions..."
sudo chown -R $APP_USER:$APP_USER /home/$APP_USER/nuxt

echo "Cleaning up stale PM2..."
pkill -u $APP_USER -f pm2 2>/dev/null || true
pkill -u $APP_USER -f "node.*index.mjs" 2>/dev/null || true
rm -rf /home/$APP_USER/.pm2 2>/dev/null || true
sleep 1

echo "Starting PM2..."
su - $APP_USER -c "cd /home/$APP_USER/nuxt && pm2 start ecosystem.config.cjs && pm2 save"

sudo env PATH=$PATH:/usr/bin pm2 startup systemd -u $APP_USER --hp /home/$APP_USER 2>/dev/null || true

echo "Nuxt deployed and running!"
ENDSSH
}

print_next_steps() {
log_info "Deployment completed!"
echo ""
echo -e "${GREEN}Next steps:${NC}"
echo "  1. Check status: ssh $APP_USER@$SERVER_IP 'pm2 status'"
echo "  2. View logs:    ssh $APP_USER@$SERVER_IP 'pm2 logs nuxt'"
echo "  3. Setup nginx:  ./setup-nginx-ssl.sh --ip $SERVER_IP --domain YOUR_DOMAIN --port $APP_PORT --email YOUR_EMAIL"
}

# Main
parse_args "$@"

log_info "Deploying Nuxt to $SERVER_IP"
echo "=================================================="

setup_node_pm2
compute_source_hash

if [ -n "$SKIP_BUILD" ]; then
    restart_app
elif [ -n "$LOCAL_BUILD" ]; then
    build_locally
else
    build_on_server
fi

print_next_steps
