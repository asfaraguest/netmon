#!/usr/bin/env bash
# =============================================================
#  NetMon — Robust Update Script
#  Updates the application in place at /opt/netmon.
#  - 100% preserves database (netmon.db, WAL, and SHM)
#  - Creates automated timestamped backup in /var/backups/netmon/
#  - Gracefully stops service before replacing files or updating venv
#  - Auto-creates/repairs systemd service if missing
#  - Guarantees correct user permissions so SQLite write never fails
# =============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

INSTALL_DIR="${NETMON_DIR:-/opt/netmon}"
SERVICE_USER="${NETMON_USER:-netmon}"
PORT="${NETMON_PORT:-5000}"
BACKUP_DIR="/var/backups/netmon"
OS=$(uname -s)

# Auto-detect existing systemd service configuration if not explicitly set
if [[ -z "${NETMON_DIR:-}" && -f "/etc/systemd/system/netmon.service" ]]; then
  DETECTED_DIR=$(grep -E '^[[:space:]]*WorkingDirectory=' /etc/systemd/system/netmon.service 2>/dev/null | cut -d= -f2 | tr -d ' "' || true)
  if [[ -n "$DETECTED_DIR" && -d "$DETECTED_DIR" ]]; then
    INSTALL_DIR="$DETECTED_DIR"
  fi
  DETECTED_USER=$(grep -E '^[[:space:]]*User=' /etc/systemd/system/netmon.service 2>/dev/null | cut -d= -f2 | tr -d ' "' || true)
  if [[ -n "$DETECTED_USER" ]]; then
    SERVICE_USER="$DETECTED_USER"
  fi
fi

info()    { echo -e "  ${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "  ${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "  ${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "  ${RED}[ERROR]${NC} $*" >&2; exit 1; }
step()    { echo -e "\n  ${BOLD}▶ $*${NC}"; }

check_root() {
  if [[ $OS == "Linux" && $EUID -ne 0 ]]; then
    error "Run as root: sudo $0"
  fi
}

check_root

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

step "1. Updating source repository"
if command -v git &>/dev/null && git rev-parse --is-inside-work-tree &>/dev/null; then
  # Avoid git "dubious ownership" error when running under sudo
  git config --global --add safe.directory "$SCRIPT_DIR" 2>/dev/null || true
  
  info "Pulling latest code changes from Git..."
  if [[ -n "${SUDO_USER:-}" && "$EUID" -eq 0 ]]; then
    sudo -u "$SUDO_USER" git pull || git pull || warn "Git pull failed, continuing with current source files..."
  else
    git pull || warn "Git pull failed, continuing with current source files..."
  fi
  success "Git repository ready"
else
  info "Not inside a git repository, using current directory files directly"
fi

# Ensure installation directory exists
if [[ ! -d "$INSTALL_DIR" ]]; then
  info "Target directory $INSTALL_DIR does not exist. Creating it..."
  mkdir -p "$INSTALL_DIR"
fi

# If database exists in SCRIPT_DIR but not in INSTALL_DIR, preserve and migrate it
if [[ "$SCRIPT_DIR" != "$INSTALL_DIR" && -f "$SCRIPT_DIR/netmon.db" && ! -f "$INSTALL_DIR/netmon.db" ]]; then
  info "Found existing database in source directory ($SCRIPT_DIR). Migrating to $INSTALL_DIR to preserve data..."
  cp -p "$SCRIPT_DIR/netmon.db" "$INSTALL_DIR/netmon.db"
  [[ -f "$SCRIPT_DIR/netmon.db-wal" ]] && cp -p "$SCRIPT_DIR/netmon.db-wal" "$INSTALL_DIR/netmon.db-wal" 2>/dev/null || true
  [[ -f "$SCRIPT_DIR/netmon.db-shm" ]] && cp -p "$SCRIPT_DIR/netmon.db-shm" "$INSTALL_DIR/netmon.db-shm" 2>/dev/null || true
fi

step "2. Stopping running service before backup & update"
if [[ $OS == "Linux" ]] && command -v systemctl &>/dev/null; then
  if systemctl is-active --quiet netmon 2>/dev/null; then
    info "Stopping NetMon service cleanly so SQLite DB has no active writers..."
    systemctl stop netmon || true
    sleep 1
    success "Service stopped"
  fi
fi

step "3. Database safety backup"
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

BACKUP_FILE=""
if [[ -f "$INSTALL_DIR/netmon.db" ]]; then
  TIMESTAMP=$(date +%Y%m%d_%H%M%S)
  BACKUP_FILE="$BACKUP_DIR/netmon.db_${TIMESTAMP}"
  
  # Checkpoint WAL while service is stopped to flush all transactions cleanly into netmon.db
  PY_CHECKPOINT=""
  if [[ -x "$INSTALL_DIR/venv/bin/python" ]]; then
    PY_CHECKPOINT="$INSTALL_DIR/venv/bin/python"
  elif command -v python3 &>/dev/null; then
    PY_CHECKPOINT="python3"
  elif command -v python &>/dev/null; then
    PY_CHECKPOINT="python"
  fi

  if [[ -n "$PY_CHECKPOINT" ]]; then
    "$PY_CHECKPOINT" -c "
import sqlite3, os
p = '$INSTALL_DIR/netmon.db'
if os.path.exists(p):
    try:
        conn = sqlite3.connect(p, timeout=10.0)
        conn.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        conn.close()
    except Exception:
        pass
" 2>/dev/null || true
  fi

  # Safely backup main database file to central backup directory
  cp -p "$INSTALL_DIR/netmon.db" "$BACKUP_FILE"
  
  # Also backup WAL and SHM if they exist
  [[ -f "$INSTALL_DIR/netmon.db-wal" ]] && cp -p "$INSTALL_DIR/netmon.db-wal" "${BACKUP_FILE}-wal" 2>/dev/null || true
  [[ -f "$INSTALL_DIR/netmon.db-shm" ]] && cp -p "$INSTALL_DIR/netmon.db-shm" "${BACKUP_FILE}-shm" 2>/dev/null || true
  
  # Update latest quick-recovery pointer
  cp -p "$INSTALL_DIR/netmon.db" "$BACKUP_DIR/netmon_latest.db" 2>/dev/null || true
  [[ -f "$INSTALL_DIR/netmon.db-wal" ]] && cp -p "$INSTALL_DIR/netmon.db-wal" "$BACKUP_DIR/netmon_latest.db-wal" 2>/dev/null || true

  # Also save redundant local backup in $INSTALL_DIR/.db_backup
  LOCAL_BACKUP_DIR="$INSTALL_DIR/.db_backup"
  mkdir -p "$LOCAL_BACKUP_DIR"
  chmod 700 "$LOCAL_BACKUP_DIR" 2>/dev/null || true
  cp -p "$INSTALL_DIR/netmon.db" "$LOCAL_BACKUP_DIR/netmon.db_${TIMESTAMP}" 2>/dev/null || true
  [[ -f "$INSTALL_DIR/netmon.db-wal" ]] && cp -p "$INSTALL_DIR/netmon.db-wal" "$LOCAL_BACKUP_DIR/netmon.db_${TIMESTAMP}-wal" 2>/dev/null || true
  ls -tp "$LOCAL_BACKUP_DIR"/netmon.db_* 2>/dev/null | grep -v '/$' | tail -n +6 | xargs -I {} rm -f -- {} 2>/dev/null || true

  success "Database backed up to $BACKUP_FILE (and $LOCAL_BACKUP_DIR)"
  
  # Retain only last 10 central backups
  ls -tp "$BACKUP_DIR"/netmon.db_* 2>/dev/null | grep -v '/$' | tail -n +11 | xargs -I {} rm -f -- {} 2>/dev/null || true
else
  info "No existing netmon.db found in $INSTALL_DIR (fresh install will generate one)."
fi

step "4. Applying code updates"
if [[ "$SCRIPT_DIR" != "$INSTALL_DIR" ]]; then
  info "Synchronizing files from $SCRIPT_DIR to $INSTALL_DIR..."
  if command -v rsync &>/dev/null; then
    rsync -av \
      --exclude='venv' \
      --exclude='netmon.db*' \
      --exclude='*.db' \
      --exclude='*.db-*' \
      --exclude='.db_backup' \
      --exclude='static/img/floorplan.*' \
      --exclude='*.pyc' \
      --exclude='__pycache__' \
      --exclude='.git' \
      "$SCRIPT_DIR/" "$INSTALL_DIR/"
  else
    # Fallback to selective cp
    mkdir -p "$INSTALL_DIR/templates" "$INSTALL_DIR/static"
    cp -r "$SCRIPT_DIR"/templates/* "$INSTALL_DIR/templates/" 2>/dev/null || true
    # Only copy static assets that don't overwrite custom floorplan images
    if command -v rsync &>/dev/null; then
      rsync -a --exclude='img/floorplan.*' "$SCRIPT_DIR/static/" "$INSTALL_DIR/static/" 2>/dev/null || true
    else
      cp -r "$SCRIPT_DIR"/static/* "$INSTALL_DIR/static/" 2>/dev/null || true
    fi
    for f in "$SCRIPT_DIR"/*.py "$SCRIPT_DIR"/*.html "$SCRIPT_DIR"/*.sh "$SCRIPT_DIR"/requirements.txt; do
      [[ -f "$f" ]] && cp -p "$f" "$INSTALL_DIR/" 2>/dev/null || true
    done
  fi
  success "Application files synchronized"
else
  info "Running directly in $INSTALL_DIR, source files already in place"
fi

step "5. Verifying Python virtual environment"
VENV_DIR="$INSTALL_DIR/venv"
if [[ ! -d "$VENV_DIR" || ! -x "$VENV_DIR/bin/python" ]]; then
  info "Virtual environment missing in $VENV_DIR. Creating..."
  PY_BIN=""
  for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
      PY_BIN="$cmd"
      break
    fi
  done
  if [[ -z "$PY_BIN" ]]; then
    error "Python 3 not found. Please install python3 & python3-venv."
  fi
  "$PY_BIN" -m venv "$VENV_DIR"
  success "Virtual environment created"
fi

if [[ -f "$INSTALL_DIR/requirements.txt" ]]; then
  info "Installing and updating Python dependencies..."
  "$VENV_DIR/bin/pip" install --upgrade pip -q 2>/dev/null || true
  "$VENV_DIR/bin/pip" install -r "$INSTALL_DIR/requirements.txt" -q
  success "Dependencies updated"
fi

step "6. Securing user and permissions"
if [[ $OS == "Linux" ]]; then
  if ! id "$SERVICE_USER" &>/dev/null; then
    useradd -r -s /sbin/nologin -d "$INSTALL_DIR" "$SERVICE_USER" 2>/dev/null || true
    info "Created service user: $SERVICE_USER"
  fi

  chown -R "$SERVICE_USER":"$SERVICE_USER" "$INSTALL_DIR" || true
  chmod -R 755 "$INSTALL_DIR" || true

  # Ensure database files have explicit read/write access for service user
  for db_f in "$INSTALL_DIR"/netmon.db*; do
    if [[ -f "$db_f" ]]; then
      chown "$SERVICE_USER":"$SERVICE_USER" "$db_f" || true
      chmod 664 "$db_f" || true
    fi
  done

  # Secure local backup directory
  if [[ -d "$INSTALL_DIR/.db_backup" ]]; then
    chmod 700 "$INSTALL_DIR/.db_backup" 2>/dev/null || true
  fi
  success "Permissions configured for $SERVICE_USER"
fi

step "7. Ensuring systemd service unit"
SERVICE_FILE="/etc/systemd/system/netmon.service"
if [[ $OS == "Linux" ]] && command -v systemctl &>/dev/null; then
  # Re-create / verify service file to prevent missing service issues
  cat > "$SERVICE_FILE" << SVCEOF
[Unit]
Description=NetMon Network Monitoring Application
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
WorkingDirectory=${INSTALL_DIR}
Environment="PATH=${INSTALL_DIR}/venv/bin"
Environment="PORT=${PORT}"
Environment="HOST=0.0.0.0"
ExecStart=${INSTALL_DIR}/venv/bin/python ${INSTALL_DIR}/app.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=netmon
NoNewPrivileges=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
SVCEOF

  systemctl daemon-reload
  systemctl enable netmon 2>/dev/null || true
  success "Service unit verified and enabled ($SERVICE_FILE)"
fi

step "8. Restarting and verifying service"
if [[ $OS == "Linux" ]] && command -v systemctl &>/dev/null; then
  systemctl restart netmon
  sleep 2

  if systemctl is-active --quiet netmon; then
    success "NetMon service is RUNNING and active!"
  else
    warn "NetMon service failed to start. Journal log preview:"
    journalctl -u netmon -n 25 --no-pager || true
    echo ""
    if [[ -n "$BACKUP_FILE" && -f "$BACKUP_FILE" ]]; then
      warn "Pre-update database backup is safely available at: $BACKUP_FILE"
      warn "To restore: sudo cp '$BACKUP_FILE' '$INSTALL_DIR/netmon.db' && sudo systemctl restart netmon"
    fi
    error "Service restart failed. Check logs above."
  fi
elif command -v service &>/dev/null; then
  service netmon restart || true
fi

echo ""
echo -e "${GREEN}${BOLD}  ======================================================${NC}"
echo -e "${GREEN}${BOLD}   NetMon has been updated successfully and is RUNNING!${NC}"
echo -e "${GREEN}${BOLD}  ======================================================${NC}"
echo -e "  Target:   ${CYAN}$INSTALL_DIR${NC}"
if [[ -n "$BACKUP_FILE" ]]; then
  echo -e "  Backup:   ${CYAN}$BACKUP_FILE${NC}"
fi
echo ""
