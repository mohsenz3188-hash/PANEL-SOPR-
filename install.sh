#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# VPN SOPR Pro v5.3 — One-Line Installer & x-ui Style CLI Manager
# Repo: https://github.com/mohsenz3188-hash/PANEL-SOPR-
# Supports Ubuntu 22.04 LTS / 24.04 LTS+ & Debian 11/12
# ==============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

REPO_RAW="https://raw.githubusercontent.com/mohsenz3188-hash/PANEL-SOPR-/main"
INSTALL_DIR="/opt/vpn-sopr"
DATA_DIR="/opt/vpn-sopr/data"
BACKUP_DIR="/opt/vpn-sopr/backups"
SERVICE_FILE="/etc/systemd/system/vpn-sopr.service"
CLI_BIN="/usr/local/bin/vpnsopr"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || echo "")"

gen_rand_str() {
    tr -dc 'a-zA-Z0-9' </dev/urandom | head -c "${1:-10}" || echo "sopr$(date +%s)"
}

clear || true
echo -e "${CYAN}"
echo "╔════════════════════════════════════════════════════════════╗"
echo "║             VPN SOPR Pro v5.3 — Auto Installer             ║"
echo "║    WireGuard • AmneziaWG • OpenVPN • IP-Auth Private DNS   ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[ERROR] Please run as root: sudo bash install.sh${NC}"
   exit 1
fi

if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    echo -e "${GREEN}[OK] Detected OS: ${PRETTY_NAME}${NC}"
fi

echo ""
echo -e "${YELLOW}--- x-ui Style Panel Access Configuration ---${NC}"
echo -e "${CYAN}Tip: Press Enter on any prompt to auto-generate secure x-ui credentials & path.${NC}"
echo ""

read -rp "1. Panel Web Port [Enter for random 10000-60000, or type e.g. 2053]: " INPUT_PORT
if [[ -z "$INPUT_PORT" ]]; then
    PANEL_PORT=$((10000 + RANDOM % 50000))
else
    PANEL_PORT="$INPUT_PORT"
fi

read -rp "2. Admin Username [Enter for random]: " INPUT_USER
ADMIN_USER=${INPUT_USER:-$(gen_rand_str 8)}

read -rp "3. Admin Password [Enter for random]: " INPUT_PASS
ADMIN_PASS=${INPUT_PASS:-$(gen_rand_str 12)}

read -rp "4. Secret Web Base Path [Enter for random e.g. /a8f2k9x1]: " INPUT_PATH
if [[ -z "$INPUT_PATH" ]]; then
    WEB_PATH="/$(gen_rand_str 8)"
else
    [[ "$INPUT_PATH" != /* ]] && INPUT_PATH="/$INPUT_PATH"
    WEB_PATH="${INPUT_PATH%/}"
fi

read -rp "5. Private DNS Server Port [default: 5353, or 53 for standard DNS]: " DNS_PORT
DNS_PORT=${DNS_PORT:-5353}

read -rp "6. Custom Domain for Panel & Sub Links (optional, press Enter to skip): " PANEL_DOMAIN
PANEL_DOMAIN=${PANEL_DOMAIN:-}

echo ""
echo -e "${CYAN}[1/6] Installing system dependencies...${NC}"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y || true
apt-get install -y python3 python3-venv python3-pip wireguard-tools openvpn easy-rsa curl jq ufw iptables nginx certbot python3-certbot-nginx unzip

if [[ "$DNS_PORT" == "53" ]] && [[ -f /etc/systemd/resolved.conf ]]; then
    echo -e "${YELLOW}[INFO] Freeing port 53 from systemd-resolved...${NC}"
    sed -i 's/^#*DNSStubListener=.*/DNSStubListener=no/' /etc/systemd/resolved.conf
    grep -q "^DNSStubListener=no" /etc/systemd/resolved.conf || echo "DNSStubListener=no" >> /etc/systemd/resolved.conf
    systemctl restart systemd-resolved || true
fi

echo -e "${CYAN}[2/6] Enabling Kernel IPv4/IPv6 Forwarding...${NC}"
cat >/etc/sysctl.d/99-vpnsopr.conf <<EOF
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF
sysctl --system >/dev/null 2>&1 || true

echo -e "${CYAN}[3/6] Deploying VPN SOPR Pro files to ${INSTALL_DIR}...${NC}"
mkdir -p "${INSTALL_DIR}/backend" "${INSTALL_DIR}/frontend" "${DATA_DIR}" "${BACKUP_DIR}"

if [[ -n "$SCRIPT_DIR" && -f "${SCRIPT_DIR}/backend/main.py" && -f "${SCRIPT_DIR}/frontend/index.html" ]]; then
    cp -f "${SCRIPT_DIR}/backend/main.py" "${INSTALL_DIR}/backend/main.py"
    cp -f "${SCRIPT_DIR}/frontend/index.html" "${INSTALL_DIR}/frontend/index.html"
else
    echo -e "${YELLOW}[INFO] Fetching latest panel source from GitHub...${NC}"
    curl -fsSL "${REPO_RAW}/backend/main.py" -o "${INSTALL_DIR}/backend/main.py"
    curl -fsSL "${REPO_RAW}/frontend/index.html" -o "${INSTALL_DIR}/frontend/index.html"
fi

echo -e "${CYAN}[4/6] Setting up Python virtual environment...${NC}"
python3 -m venv "${INSTALL_DIR}/venv"
"${INSTALL_DIR}/venv/bin/pip" install --upgrade pip >/dev/null
"${INSTALL_DIR}/venv/bin/pip" install fastapi uvicorn psutil pydantic httpx python-multipart >/dev/null

get_public_ip() {
    local ip=""
    for url in "https://api.ipify.org" "https://ipv4.icanhazip.com" "https://ifconfig.me/ip"; do
        ip=$(curl -4 -fsS --max-time 4 "$url" 2>/dev/null | tr -d '[:space:]' || true)
        if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "$ip"
            return
        fi
    done
    hostname -I | awk '{print $1}'
}
SERVER_IP=$(get_public_ip)
SUB_BASE="http://${SERVER_IP}:${PANEL_PORT}"
PANEL_URL="http://${SERVER_IP}:${PANEL_PORT}${WEB_PATH}/"
if [[ -n "$PANEL_DOMAIN" ]]; then
    SUB_BASE="https://${PANEL_DOMAIN}"
    PANEL_URL="https://${PANEL_DOMAIN}${WEB_PATH}/"
fi

cat >"${DATA_DIR}/config.json" <<EOF
{
  "panel_port": ${PANEL_PORT},
  "web_base_path": "${WEB_PATH}",
  "dns_port": ${DNS_PORT},
  "dns_upstream": "1.1.1.1",
  "admin_user": "${ADMIN_USER}",
  "admin_pass": "${ADMIN_PASS}",
  "server_ip": "${SERVER_IP}",
  "domain": "${PANEL_DOMAIN}",
  "ssl_enabled": false,
  "sub_base_url": "${SUB_BASE}",
  "tg_bot_token": "",
  "tg_admin_id": "",
  "tg_enabled": false,
  "auto_backup_hours": 24
}
EOF

echo -e "${CYAN}[5/6] Creating systemd service and x-ui style CLI (vpnsopr)...${NC}"
cat >"${SERVICE_FILE}" <<EOF
[Unit]
Description=VPN SOPR Pro v5.3 Management Panel, Telegram Bot & Private DNS
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
Environment="VPNSOPR_DATA=${DATA_DIR}"
Environment="VPNSOPR_BACKUP=${BACKUP_DIR}"
Environment="VPNSOPR_FRONTEND=${INSTALL_DIR}/frontend"
ExecStart=${INSTALL_DIR}/venv/bin/python -m uvicorn backend.main:app --host 0.0.0.0 --port ${PANEL_PORT}
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

rm -f "${CLI_BIN}"
cat >"${CLI_BIN}" <<'EOF'
#!/usr/bin/env bash
SERVICE="vpn-sopr"
INSTALL_DIR="/opt/vpn-sopr"
DATA_FILE="/opt/vpn-sopr/data/config.json"
REPO_RAW="https://raw.githubusercontent.com/mohsenz3188-hash/PANEL-SOPR-/main"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

show_credentials() {
    if [[ ! -f "$DATA_FILE" ]]; then
        echo -e "${RED}Config file not found!${NC}"
        return
    fi
    IP=$(jq -r '.server_ip' "$DATA_FILE")
    PORT=$(jq -r '.panel_port' "$DATA_FILE")
    WPATH=$(jq -r '.web_base_path // ""' "$DATA_FILE")
    USER=$(jq -r '.admin_user' "$DATA_FILE")
    PASS=$(jq -r '.admin_pass' "$DATA_FILE")
    DOMAIN=$(jq -r '.domain // ""' "$DATA_FILE")
    SSL=$(jq -r '.ssl_enabled // false' "$DATA_FILE")
    DNSPORT=$(jq -r '.dns_port' "$DATA_FILE")

    if [[ -n "$DOMAIN" && "$SSL" == "true" ]]; then
        URL="https://${DOMAIN}${WPATH}/"
    else
        URL="http://${IP}:${PORT}${WPATH}/"
    fi

    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║              VPN SOPR Pro — Panel Access Info                ║"
    echo "╠══════════════════════════════════════════════════════════════╣"
    echo -e "║  Web Panel URL  : ${CYAN}${BOLD}${URL}${NC}${GREEN}"
    echo -e "║  Username       : ${YELLOW}${BOLD}${USER}${NC}${GREEN}"
    echo -e "║  Password       : ${YELLOW}${BOLD}${PASS}${NC}${GREEN}"
    echo -e "║  Web Base Path  : ${CYAN}${WPATH}/${NC}${GREEN}"
    echo -e "║  Panel Port     : ${CYAN}${PORT}${NC}${GREEN}"
    echo -e "║  Private DNS    : ${CYAN}${IP}:${DNSPORT} (UDP/TCP)${NC}${GREEN}"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

setup_ssl() {
    local DOMAIN="${1:-}"
    if [[ -z "$DOMAIN" ]]; then
        read -rp "Enter your domain (e.g. sub.yourdomain.com): " DOMAIN
    fi
    read -rp "Enter email for Let's Encrypt SSL [admin@${DOMAIN}]: " EMAIL
    EMAIL=${EMAIL:-admin@${DOMAIN}}
    PORT=$(jq -r '.panel_port' "$DATA_FILE")
    cat >/etc/nginx/sites-available/vpnsopr <<NGX
server {
    listen 80;
    server_name ${DOMAIN};
    location / {
        proxy_pass http://127.0.0.1:${PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
NGX
    ln -sf /etc/nginx/sites-available/vpnsopr /etc/nginx/sites-enabled/vpnsopr
    nginx -t && systemctl reload nginx
    certbot --nginx -d "${DOMAIN}" --non-interactive --agree-tos -m "${EMAIL}" --redirect
    tmp=$(mktemp)
    jq --arg d "$DOMAIN" '.domain=$d | .ssl_enabled=true | .sub_base_url=("https://"+$d)' "$DATA_FILE" > "$tmp" && mv "$tmp" "$DATA_FILE"
    systemctl restart $SERVICE
    echo -e "${GREEN}[OK] SSL enabled!${NC}"
    show_credentials
}

change_creds() {
    read -rp "New Admin Username (Enter for random): " NEW_U
    NEW_U=${NEW_U:-$(tr -dc 'a-zA-Z0-9' </dev/urandom | head -c 8)}
    read -rp "New Admin Password (Enter for random): " NEW_P
    NEW_P=${NEW_P:-$(tr -dc 'a-zA-Z0-9' </dev/urandom | head -c 12)}
    read -rp "New Web Base Path (e.g. /sopr88, Enter to keep current): " NEW_PATH
    tmp=$(mktemp)
    if [[ -n "$NEW_PATH" ]]; then
        [[ "$NEW_PATH" != /* ]] && NEW_PATH="/$NEW_PATH"
        NEW_PATH="${NEW_PATH%/}"
        jq --arg u "$NEW_U" --arg p "$NEW_P" --arg wp "$NEW_PATH" '.admin_user=$u | .admin_pass=$p | .web_base_path=$wp' "$DATA_FILE" > "$tmp" && mv "$tmp" "$DATA_FILE"
    else
        jq --arg u "$NEW_U" --arg p "$NEW_P" '.admin_user=$u | .admin_pass=$p' "$DATA_FILE" > "$tmp" && mv "$tmp" "$DATA_FILE"
    fi
    systemctl restart $SERVICE
    echo -e "${GREEN}[OK] Admin credentials updated!${NC}"
    show_credentials
}

change_port() {
    read -rp "New Panel Web Port: " NEW_PORT
    tmp=$(mktemp)
    IP=$(jq -r '.server_ip' "$DATA_FILE")
    jq --argjson pt "$NEW_PORT" --arg url "http://${IP}:${NEW_PORT}" '.panel_port=$pt | .sub_base_url=$url' "$DATA_FILE" > "$tmp" && mv "$tmp" "$DATA_FILE"
    sed -i "s/--port [0-9]*/--port ${NEW_PORT}/" /etc/systemd/system/vpn-sopr.service
    systemctl daemon-reload
    systemctl restart $SERVICE
    echo -e "${GREEN}[OK] Panel port changed to ${NEW_PORT}${NC}"
    show_credentials
}

update_panel() {
    echo -e "${CYAN}Updating VPN SOPR Pro from GitHub...${NC}"
    curl -fsSL "${REPO_RAW}/backend/main.py" -o "${INSTALL_DIR}/backend/main.py"
    curl -fsSL "${REPO_RAW}/frontend/index.html" -o "${INSTALL_DIR}/frontend/index.html"
    systemctl restart $SERVICE
    echo -e "${GREEN}[OK] Panel updated and restarted!${NC}"
}

show_menu() {
    clear || true
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════════════╗"
    echo "║              VPN SOPR Pro — Management Menu            ║"
    echo "╠════════════════════════════════════════════════════════╣"
    echo "║  1. Start Panel Service                                ║"
    echo "║  2. Stop Panel Service                                 ║"
    echo "║  3. Restart Panel Service                              ║"
    echo "║  4. Check Service Status                               ║"
    echo "║  5. View Live Panel & DNS Logs                         ║"
    echo "║  6. Show Web Panel URL, Username & Password            ║"
    echo "║  7. Reset / Change Username, Password & Web Path       ║"
    echo "║  8. Change Panel Web Port                              ║"
    echo "║  9. Connect Domain & Issue Free SSL (Certbot)          ║"
    echo "║ 10. Update Panel from GitHub                           ║"
    echo "║ 11. Uninstall VPN SOPR Pro                             ║"
    echo "║  0. Exit                                               ║"
    echo "╚════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    read -rp "Select an option [0-11]: " OPT
    case "$OPT" in
        1) systemctl start $SERVICE && echo -e "${GREEN}Started.${NC}" ;;
        2) systemctl stop $SERVICE && echo -e "${YELLOW}Stopped.${NC}" ;;
        3) systemctl restart $SERVICE && echo -e "${GREEN}Restarted.${NC}" ;;
        4) systemctl status $SERVICE --no-pager ;;
        5) journalctl -u $SERVICE -n 60 --no-pager ;;
        6) show_credentials ;;
        7) change_creds ;;
        8) change_port ;;
        9) setup_ssl ;;
        10) update_panel ;;
        11)
            systemctl stop $SERVICE || true
            systemctl disable $SERVICE || true
            rm -f /etc/systemd/system/vpn-sopr.service /usr/local/bin/vpnsopr /etc/nginx/sites-enabled/vpnsopr /etc/nginx/sites-available/vpnsopr
            rm -rf /opt/vpn-sopr
            systemctl daemon-reload
            echo -e "${RED}VPN SOPR Pro uninstalled.${NC}"
            exit 0
            ;;
        0) exit 0 ;;
        *) echo "Invalid option." ;;
    esac
}

case "${1:-}" in
  start) systemctl start $SERVICE ;;
  stop) systemctl stop $SERVICE ;;
  restart) systemctl restart $SERVICE ;;
  status) systemctl status $SERVICE --no-pager ;;
  logs) journalctl -u $SERVICE -n 60 --no-pager ;;
  info) show_credentials ;;
  ssl) setup_ssl "${2:-}" ;;
  update) update_panel ;;
  *) show_menu ;;
esac
EOF
chmod +x "${CLI_BIN}"

echo -e "${CYAN}[6/6] Configuring firewall and starting service...${NC}"
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
    ufw allow 80/tcp >/dev/null || true
    ufw allow 443/tcp >/dev/null || true
    ufw allow "${PANEL_PORT}/tcp" >/dev/null || true
    ufw allow "${DNS_PORT}/udp" >/dev/null || true
    ufw allow "${DNS_PORT}/tcp" >/dev/null || true
    ufw allow 51820/udp >/dev/null || true
    ufw allow 1194/tcp >/dev/null || true
fi

systemctl daemon-reload
systemctl enable vpn-sopr >/dev/null
systemctl restart vpn-sopr

if [[ -n "$PANEL_DOMAIN" ]]; then
    vpnsopr ssl "${PANEL_DOMAIN}" || echo -e "${YELLOW}[WARNING] SSL setup skipped. Run 'vpnsopr' -> option 9 once DNS points to ${SERVER_IP}.${NC}"
fi

echo ""
echo -e "${GREEN}${BOLD}Installation Complete! Here are your x-ui style panel details:${NC}"
vpnsopr info
echo -e "${CYAN}Tip: Type ${BOLD}vpnsopr${NC}${CYAN} in terminal anytime to view credentials or manage the panel.${NC}"
