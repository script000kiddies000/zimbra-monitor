#!/bin/bash
# Setup deployment untuk Zimbra Mail Monitoring Bot.
# Idempotent - aman dijalankan ulang. Jalankan sebagai root, dari folder
# project ini (yang berisi app.py & config.yaml).
#
# Lihat PRD.md §13 untuk penjelasan tiap keputusan di sini.
#
# Yang TIDAK dikerjakan otomatis oleh script ini (harus manual):
#   - Isi ZIMBRA_MONITOR_BOT_TOKEN di /opt/zimbra-monitor/zimbra-monitor.env
#   - Isi admin_chat_id & admin_user_id di /opt/zimbra-monitor/config.yaml
#   - Verifikasi ulang bahwa grup yang di-assign ke user zmonitor memang
#     bisa membaca /var/log/zimbra.log (script ini coba deteksi otomatis,
#     tapi cek manual tetap disarankan)
#   - systemctl start zimbra-monitor (baru dijalankan setelah 2 poin di atas diisi)

set -euo pipefail

APP_USER="zmonitor"
APP_DIR="/opt/zimbra-monitor"
SERVICE_NAME="zimbra-monitor"
ZMPROV_PATH="/opt/zimbra/bin/zmprov"
POSTSUPER_PATH="/opt/zimbra/common/sbin/postsuper"
ZIMBRA_LOG="/var/log/zimbra.log"
SUDOERS_FILE="/etc/sudoers.d/${SERVICE_NAME}"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
ENV_FILE="${APP_DIR}/zimbra-monitor.env"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log()  { echo "[setup] $*"; }
warn() { echo "[setup] WARNING: $*" >&2; }

# Cari Python3 - server ini gak punya python3 di PATH sistem (CentOS 7,
# masih Python2 default). Kalau ada di PATH pakai itu, kalau tidak fallback
# ke instalasi standalone di /opt/python3-standalone (lihat PRD - dipilih
# karena repo yum CentOS 7 di server ini sudah EOL/mati, gak bisa `yum
# install python3`). Override dengan env var PYTHON3_BIN kalau lokasinya beda.
find_python3() {
    if [[ -n "${PYTHON3_BIN:-}" ]]; then
        echo "${PYTHON3_BIN}"
    elif command -v python3 &>/dev/null; then
        command -v python3
    elif [[ -x /opt/python3-standalone/bin/python3 ]]; then
        echo /opt/python3-standalone/bin/python3
    else
        echo ""
    fi
}
PYTHON3_BIN="$(find_python3)"
if [[ -z "${PYTHON3_BIN}" ]]; then
    echo "Python3 tidak ditemukan (bukan di PATH, bukan di /opt/python3-standalone)." >&2
    echo "Install dulu, atau set env var PYTHON3_BIN ke path binary python3." >&2
    exit 1
fi
log "Pakai Python3: ${PYTHON3_BIN} ($(${PYTHON3_BIN} --version 2>&1))"

if [[ "$(id -u)" -ne 0 ]]; then
    echo "Script ini harus dijalankan sebagai root (sudo $0)." >&2
    exit 1
fi

if [[ ! -f "${SCRIPT_DIR}/app.py" || ! -f "${SCRIPT_DIR}/config.yaml" ]]; then
    echo "app.py / config.yaml tidak ditemukan di ${SCRIPT_DIR}." >&2
    echo "Jalankan script ini dari folder project (hasil clone/copy repo)." >&2
    exit 1
fi

# --------------------------------------------------------------------
# 1. User khusus (non-login) - least privilege, lihat PRD §6.5/§13
# --------------------------------------------------------------------
if id "${APP_USER}" &>/dev/null; then
    log "User '${APP_USER}' sudah ada, skip."
else
    log "Membuat user system '${APP_USER}' (no-login, no home)..."
    useradd --system --no-create-home --shell /usr/sbin/nologin "${APP_USER}"
fi

# --------------------------------------------------------------------
# 2. Folder deploy - satu folder untuk semuanya (PRD §13)
# --------------------------------------------------------------------
log "Menyiapkan folder ${APP_DIR}..."
mkdir -p "${APP_DIR}"
# Wajib di-chown ke zmonitor - tanpa ini, mkdir default owner root:root
# bikin zmonitor gak punya izin nulis ke folder sendiri (misal pas bikin
# venv/state.db/tail_state.json).
chown "${APP_USER}:${APP_USER}" "${APP_DIR}"

log "Menyalin app.py..."
install -o "${APP_USER}" -g "${APP_USER}" -m 640 "${SCRIPT_DIR}/app.py" "${APP_DIR}/app.py"

if [[ -f "${APP_DIR}/config.yaml" ]]; then
    log "config.yaml sudah ada di ${APP_DIR}, TIDAK ditimpa (biar konfigurasi custom lo aman)."
else
    log "Menyalin config.yaml (pertama kali)..."
    install -o "${APP_USER}" -g "${APP_USER}" -m 640 "${SCRIPT_DIR}/config.yaml" "${APP_DIR}/config.yaml"
fi

if [[ -f "${ENV_FILE}" ]]; then
    log "${ENV_FILE} sudah ada, skip (biar token yang sudah diisi gak ketiban)."
else
    log "Membuat template ${ENV_FILE}..."
    cat > "${ENV_FILE}" <<'EOF'
# Isi token bot dari @BotFather di bawah ini, lalu:
#   chmod 600 /opt/zimbra-monitor/zimbra-monitor.env
ZIMBRA_MONITOR_BOT_TOKEN=
EOF
    chown "${APP_USER}:${APP_USER}" "${ENV_FILE}"
    chmod 600 "${ENV_FILE}"
    warn "${ENV_FILE} masih kosong - isi ZIMBRA_MONITOR_BOT_TOKEN sebelum start service."
fi

# --------------------------------------------------------------------
# 3. Virtualenv - dependency ringan, tidak ganggu Python sistem/Zimbra
# --------------------------------------------------------------------
if [[ -x "${APP_DIR}/venv/bin/python3" ]]; then
    log "venv sudah ada, skip pembuatan (tetap re-install dependency untuk jaga-jaga versi)."
else
    log "Membuat virtualenv di ${APP_DIR}/venv..."
    sudo -u "${APP_USER}" "${PYTHON3_BIN}" -m venv "${APP_DIR}/venv"
fi
log "Memasang dependency (requests, PyYAML)..."
sudo -u "${APP_USER}" "${APP_DIR}/venv/bin/pip" install --quiet --upgrade pip
sudo -u "${APP_USER}" "${APP_DIR}/venv/bin/pip" install --quiet requests PyYAML

# --------------------------------------------------------------------
# 4. Akses baca /var/log/zimbra.log - deteksi grup otomatis, best-effort
# --------------------------------------------------------------------
if [[ -f "${ZIMBRA_LOG}" ]]; then
    LOG_GROUP="$(stat -c '%G' "${ZIMBRA_LOG}")"
    if [[ -n "${LOG_GROUP}" && "${LOG_GROUP}" != "${APP_USER}" ]]; then
        log "Menambahkan ${APP_USER} ke grup '${LOG_GROUP}' (owner grup dari ${ZIMBRA_LOG})..."
        usermod -aG "${LOG_GROUP}" "${APP_USER}"
        warn "Verifikasi manual: 'sudo -u ${APP_USER} tail -n1 ${ZIMBRA_LOG}' harus berhasil tanpa Permission denied."
    fi
else
    warn "${ZIMBRA_LOG} tidak ditemukan di server ini - cek log_path di config.yaml."
fi

# --------------------------------------------------------------------
# 5. Sudoers - HANYA pola argumen zmprov yang persis dipakai app.py,
#    TANPA wrapper script (lihat PRD §6.5 poin 5-6 untuk alasannya)
# --------------------------------------------------------------------
if [[ ! -x "${ZMPROV_PATH}" ]]; then
    warn "${ZMPROV_PATH} tidak ditemukan/tidak executable - cek zmprov_path di config.yaml."
fi
if [[ ! -x "${POSTSUPER_PATH}" ]]; then
    warn "${POSTSUPER_PATH} tidak ditemukan/tidak executable - cek postsuper_path di config.yaml."
fi

TMP_SUDOERS="$(mktemp)"
cat > "${TMP_SUDOERS}" <<EOF
# Dikelola oleh setup.sh (zimbra-monitor). Jangan edit manual - re-run setup.sh.
Cmnd_Alias ZM_LOCK = ${ZMPROV_PATH} ma * zimbraAccountStatus locked description *
Cmnd_Alias ZM_SETPW = ${ZMPROV_PATH} sp * *
Cmnd_Alias ZM_MUSTCHANGE = ${ZMPROV_PATH} ma * zimbraPasswordMustChange TRUE
# Tombol "Delete Queue" (khusus incident queue_pileup) - hapus pesan dari
# mail queue. Queue ID di argumen selalu hasil regex hex dari postqueue -p
# (app.py: list_queue_entries), bukan input bebas.
Cmnd_Alias ZM_QUEUE_DELETE = ${POSTSUPER_PATH} -d *

${APP_USER} ALL=(zimbra) NOPASSWD: ZM_LOCK, ZM_SETPW, ZM_MUSTCHANGE
# postsuper menolak jalan lewat runas non-root ("reserved for the
# superuser") - beda dari zmprov di atas, makanya baris terpisah sebagai
# root, dibatasi SANGAT ketat ke pattern persis ini saja.
${APP_USER} ALL=(root) NOPASSWD: ZM_QUEUE_DELETE
EOF

if visudo -cf "${TMP_SUDOERS}" >/dev/null 2>&1; then
    install -o root -g root -m 440 "${TMP_SUDOERS}" "${SUDOERS_FILE}"
    log "Sudoers terpasang di ${SUDOERS_FILE}."
else
    rm -f "${TMP_SUDOERS}"
    echo "Sudoers tidak valid (visudo -cf gagal) - TIDAK dipasang. Cek manual." >&2
    exit 1
fi
rm -f "${TMP_SUDOERS}"

# --------------------------------------------------------------------
# 6. systemd service
# --------------------------------------------------------------------
log "Menulis ${SERVICE_FILE}..."
cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=Zimbra Mail Monitoring Bot
After=network.target

[Service]
Type=simple
User=${APP_USER}
Group=${APP_USER}
WorkingDirectory=${APP_DIR}
EnvironmentFile=${ENV_FILE}
ExecStart=${APP_DIR}/venv/bin/python3 ${APP_DIR}/app.py -c ${APP_DIR}/config.yaml
Restart=on-failure
RestartSec=5
# NoNewPrivileges tidak diset true di sini - proses ini butuh sudo (setuid)
# untuk memanggil zmprov sebagai user zimbra, lihat PRD §13.

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "${SERVICE_NAME}" >/dev/null

log "Setup selesai."
echo
echo "Langkah manual yang masih perlu dilakukan sebelum jalan:"
echo "  1. Isi token bot: nano ${ENV_FILE}"
echo "  2. Isi admin_chat_id & admin_user_id: nano ${APP_DIR}/config.yaml"
echo "  3. Verifikasi baca log: sudo -u ${APP_USER} tail -n1 ${ZIMBRA_LOG}"
echo "  4. Jalankan: systemctl start ${SERVICE_NAME}"
echo "  5. Cek log service: journalctl -u ${SERVICE_NAME} -f"
