#!/usr/bin/env bash
# ==============================================================================
#  TIKWatch - Nginx Reverse Proxy & HTTPS Management Script
# ==============================================================================
#  Deskripsi: Mengaktifkan / menonaktifkan Nginx Reverse Proxy dengan HTTPS
#             self-signed (Port 80 -> 443) dan IP Lock subnet kampus.
#  Penggunaan:
#             sudo ./manage_proxy.sh enable
#             sudo ./manage_proxy.sh disable
# ==============================================================================

set -euo pipefail

# Warna untuk output terminal
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# File Konfigurasi Nginx & SSL
NGINX_AVAILABLE="/etc/nginx/sites-available/netmon"
NGINX_ENABLED="/etc/nginx/sites-enabled/netmon"
NGINX_DEFAULT_AVAILABLE="/etc/nginx/sites-available/default"
NGINX_DEFAULT_ENABLED="/etc/nginx/sites-enabled/default"
SSL_DIR="/etc/ssl/tikwatch"
SSL_CERT="${SSL_DIR}/tikwatch.crt"
SSL_KEY="${SSL_DIR}/tikwatch.key"
ALLOWED_CIDR="${TIKWATCH_ALLOWED_CIDR:-10.122.100.0/24}"

# Pastikan dijalankan sebagai root/sudo
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[ERROR] Perintah ini harus dijalankan sebagai root! Gunakan: sudo $0 <action>${NC}" >&2
    exit 1
fi

# Cek apakah Nginx terinstal
if ! command -v nginx &>/dev/null; then
    echo -e "${YELLOW}Nginx belum terinstal. Menginstal Nginx terlebih dahulu...${NC}"
    apt update && apt install nginx -y
    echo -e "${GREEN}Nginx berhasil diinstal.${NC}"
fi

# Fungsi membuat sertifikat self-signed SSL untuk LAN kampus
ensure_ssl_cert() {
    local ip_addr="$1"
    if [[ -f "$SSL_CERT" && -f "$SSL_KEY" ]]; then
        return 0
    fi
    if ! command -v openssl &>/dev/null; then
        apt update && apt install openssl -y
    fi
    mkdir -p "$SSL_DIR"
    chmod 700 "$SSL_DIR"
    local san_ext="DNS:tikwatch.local"
    if [[ "$ip_addr" != "_" ]]; then
        san_ext="IP:${ip_addr},IP:127.0.0.1,DNS:tikwatch.local"
    fi
    echo -e "${CYAN}Membuat sertifikat SSL self-signed untuk TIKWatch (${san_ext})...${NC}"
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout "$SSL_KEY" -out "$SSL_CERT" \
        -subj "/C=ID/ST=Jawa Timur/L=Jember/O=Politeknik Negeri Jember/OU=UPT TIK/CN=${ip_addr}" \
        -addext "subjectAltName=${san_ext}" >/dev/null 2>&1
    chmod 600 "$SSL_KEY"
    chmod 644 "$SSL_CERT"
    echo -e "${GREEN}Sertifikat SSL berhasil dibuat di ${SSL_DIR}.${NC}"
}

# Fungsi untuk membuat konfigurasi TIKWatch di Nginx (HTTPS + IP Lock)
generate_nginx_config() {
    local ip_addr
    ip_addr=$(hostname -I | awk '{print $1}') || ip_addr="_"
    if [[ -z "$ip_addr" ]]; then
        ip_addr="_"
    fi

    ensure_ssl_cert "$ip_addr"

    echo -e "${CYAN}Membuat konfigurasi Nginx HTTPS + IP Lock (${ALLOWED_CIDR}) di ${NGINX_AVAILABLE}...${NC}"
    cat << EOF > "$NGINX_AVAILABLE"
server {
    listen 80;
    server_name $ip_addr _;

    # IP Allowlist kampus
    allow $ALLOWED_CIDR;
    allow 127.0.0.1;
    deny all;

    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl;
    server_name $ip_addr _;

    ssl_certificate     $SSL_CERT;
    ssl_certificate_key $SSL_KEY;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    # IP Allowlist kampus
    allow $ALLOWED_CIDR;
    allow 127.0.0.1;
    deny all;

    client_max_body_size 32M;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;

        # Konfigurasi WebSocket / Socket.IO
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 86400;

        # Header untuk meneruskan IP & skema asli client ke ProxyFix Flask
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
    echo -e "${GREEN}Konfigurasi Nginx berhasil dibuat (HTTPS 443 + IP Lock ${ALLOWED_CIDR}).${NC}"
}

# Fungsi untuk mengaktifkan Proxy
enable_proxy() {
    echo -e "${CYAN}Mengaktifkan Nginx Reverse Proxy HTTPS untuk TIKWatch...${NC}"
    
    # 1. Generate/perbarui konfigurasi Nginx agar selalu sinkron dengan HTTPS & IP Lock
    generate_nginx_config
    
    # 2. Buat symlink di sites-enabled
    if [[ ! -L "$NGINX_ENABLED" ]]; then
        ln -s "$NGINX_AVAILABLE" "$NGINX_ENABLED"
        echo -e "${GREEN}Symlink TIKWatch dibuat di sites-enabled.${NC}"
    else
        echo -e "${YELLOW}Konfigurasi TIKWatch di sites-enabled diperbarui.${NC}"
    fi

    # 3. Nonaktifkan situs default Nginx agar tidak bentrok
    if [[ -L "$NGINX_DEFAULT_ENABLED" || -f "$NGINX_DEFAULT_ENABLED" ]]; then
        rm -f "$NGINX_DEFAULT_ENABLED"
        echo -e "${GREEN}Situs default Nginx dinonaktifkan.${NC}"
    fi

    # 4. Uji dan muat ulang Nginx
    if nginx -t &>/dev/null; then
        systemctl restart nginx
        local srv_ip
        srv_ip=$(hostname -I | awk '{print $1}')
        echo -e "${GREEN}${BOLD}======================================================${NC}"
        echo -e "${GREEN}${BOLD}   BERHASIL: TIKWatch aktif via HTTPS (Port 443)!     ${NC}"
        echo -e "${GREEN}${BOLD}   IP Lock : ${ALLOWED_CIDR}                          ${NC}"
        echo -e "${GREEN}${BOLD}   Akses   : https://${srv_ip}/                       ${NC}"
        echo -e "${GREEN}${BOLD}======================================================${NC}"
    else
        echo -e "${RED}[ERROR] Konfigurasi Nginx tidak valid! Membatalkan pengaktifan proxy.${NC}" >&2
        nginx -t || true
        rm -f "$NGINX_ENABLED"
        if [[ -f "$NGINX_DEFAULT_AVAILABLE" && ! -L "$NGINX_DEFAULT_ENABLED" ]]; then
            ln -s "$NGINX_DEFAULT_AVAILABLE" "$NGINX_DEFAULT_ENABLED"
        fi
        systemctl reload nginx
        exit 1
    fi
}

# Fungsi untuk menonaktifkan Proxy
disable_proxy() {
    echo -e "${CYAN}Menonaktifkan Nginx Reverse Proxy untuk NetMon...${NC}"

    # 1. Hapus symlink NetMon
    if [[ -L "$NGINX_ENABLED" || -f "$NGINX_ENABLED" ]]; then
        rm -f "$NGINX_ENABLED"
        echo -e "${GREEN}Symlink NetMon dihapus dari sites-enabled.${NC}"
    else
        echo -e "${YELLOW}Proxy NetMon memang tidak aktif sebelumnya.${NC}"
    fi

    # 2. Aktifkan kembali situs default Nginx (jika ada)
    if [[ -f "$NGINX_DEFAULT_AVAILABLE" && ! -L "$NGINX_DEFAULT_ENABLED" ]]; then
        ln -s "$NGINX_DEFAULT_AVAILABLE" "$NGINX_DEFAULT_ENABLED"
        echo -e "${GREEN}Situs default Nginx diaktifkan kembali.${NC}"
    fi

    # 3. Muat ulang Nginx
    if nginx -t &>/dev/null; then
        systemctl restart nginx
        echo -e "${GREEN}${BOLD}======================================================${NC}"
        echo -e "${GREEN}${BOLD}   BERHASIL: Proxy dinonaktifkan.                    ${NC}"
        echo -e "${GREEN}${BOLD}   NetMon dikembalikan hanya bisa diakses di Port 5000.${NC}"
        echo -e "${GREEN}${BOLD}======================================================${NC}"
    else
        echo -e "${RED}[ERROR] Konfigurasi default Nginx tidak valid setelah penonaktifan!${NC}" >&2
        systemctl reload nginx
        exit 1
    fi
}

# Periksa argumen tindakan
if [[ $# -lt 1 ]]; then
    echo -e "${YELLOW}Penggunaan: sudo $0 {enable|disable}${NC}"
    exit 1
fi

ACTION=$(echo "$1" | tr '[:upper:]' '[:lower:]')

case "$ACTION" in
    enable)
        enable_proxy
        ;;
    disable)
        disable_proxy
        ;;
    *)
        echo -e "${RED}[ERROR] Tindakan tidak dikenal: $1. Gunakan 'enable' atau 'disable'.${NC}" >&2
        exit 1
        ;;
esac
