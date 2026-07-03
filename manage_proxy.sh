#!/usr/bin/env bash
# ==============================================================================
#  NetMon - Nginx Reverse Proxy Management Script
# ==============================================================================
#  Deskripsi: Script ini digunakan untuk mengaktifkan atau menonaktifkan
#             Nginx reverse proxy untuk NetMon (Port 5000 -> Port 80).
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

# File Konfigurasi Nginx
NGINX_AVAILABLE="/etc/nginx/sites-available/netmon"
NGINX_ENABLED="/etc/nginx/sites-enabled/netmon"
NGINX_DEFAULT_AVAILABLE="/etc/nginx/sites-available/default"
NGINX_DEFAULT_ENABLED="/etc/nginx/sites-enabled/default"

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

# Fungsi untuk membuat konfigurasi NetMon di Nginx
generate_nginx_config() {
    # Dapatkan IP Address utama server
    local ip_addr
    ip_addr=$(hostname -I | awk '{print $1}') || ip_addr="_"
    if [[ -z "$ip_addr" ]]; then
        ip_addr="_"
    fi

    echo -e "${CYAN}Membuat file konfigurasi Nginx untuk NetMon di ${NGINX_AVAILABLE}...${NC}"
    cat << EOF > "$NGINX_AVAILABLE"
server {
    listen 80;
    server_name $ip_addr;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;
        
        # Konfigurasi WebSocket / Socket.IO
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Header untuk meneruskan IP asli client
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
    echo -e "${GREEN}Konfigurasi Nginx berhasil dibuat dengan server_name: $ip_addr${NC}"
}

# Fungsi untuk mengaktifkan Proxy
enable_proxy() {
    echo -e "${CYAN}Mengaktifkan Nginx Reverse Proxy untuk NetMon...${NC}"
    
    # 1. Buat file konfigurasi jika belum ada
    if [[ ! -f "$NGINX_AVAILABLE" ]]; then
        generate_nginx_config()
    fi
    
    # 2. Buat symlink di sites-enabled
    if [[ ! -L "$NGINX_ENABLED" ]]; then
        ln -s "$NGINX_AVAILABLE" "$NGINX_ENABLED"
        echo -e "${GREEN}Symlink NetMon dibuat di sites-enabled.${NC}"
    else
        echo -e "${YELLOW}Konfigurasi NetMon sudah aktif sebelumnya.${NC}"
    fi

    # 3. Nonaktifkan situs default Nginx agar tidak bentrok
    if [[ -L "$NGINX_DEFAULT_ENABLED" || -f "$NGINX_DEFAULT_ENABLED" ]]; then
        rm -f "$NGINX_DEFAULT_ENABLED"
        echo -e "${GREEN}Situs default Nginx dinonaktifkan.${NC}"
    fi

    # 4. Uji dan muat ulang Nginx
    if nginx -t &>/dev/null; then
        systemctl restart nginx
        echo -e "${GREEN}${BOLD}======================================================${NC}"
        echo -e "${GREEN}${BOLD}   BERHASIL: NetMon kini dapat diakses di Port 80!    ${NC}"
        echo -e "${GREEN}${BOLD}   Silakan buka browser: http://$(hostname -I | awk '{print $1}')/ ${NC}"
        echo -e "${GREEN}${BOLD}======================================================${NC}"
    else
        echo -e "${RED}[ERROR] Konfigurasi Nginx tidak valid! Membatalkan pengaktifan proxy.${NC}" >&2
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
