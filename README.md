# Zimbra Mail Monitoring Bot

Bot Telegram untuk deteksi dini akun Zimbra yang compromise — monitor `/var/log/zimbra.log` secara real-time, notifikasi ke Telegram, dan tombol aksi cepat langsung dari chat (Lock, Reset Password, Block IP, Whitelist).

Dirancang untuk berjalan langsung di server Zimbra 8/9 sebagai proses ringan, tanpa dependensi eksternal selain Python stdlib + `requests` + `PyYAML`.

---

## Fitur

- **Deteksi 3 rule secara simultan:**
  - `outbound_blast` — akun kirim > N email dalam M menit dari IP eksternal
  - `credential_stuffing` — akun di-auth dari > N IP eksternal berbeda dalam 1 jam
  - `queue_pileup` — mail queue menumpuk > N pesan dari sender internal
- **Tombol aksi inline di Telegram:** Lock akun, Reset password, Block IP, Whitelist IP/akun, Ignore
- **Dedulikasi otomatis** — incident dari akun yang sama digabung ke 1 pesan selama 24 jam
- **Audit log** — semua aksi tersimpan ke SQLite
- **Graceful restart** — state (posisi baca log + incidents) survive restart service
- **Fase kalibrasi** (`actions_enabled: false`) — alert-only dulu, tombol aktif setelah threshold dikalibrasi

## Prasyarat

| Kebutuhan | Versi |
|---|---|
| Zimbra | 8 atau 9 (Community/OSE) |
| OS | CentOS 7+ / Ubuntu 18.04+ |
| Python | 3.9+ |
| Akses | Root (untuk setup), service jalan sebagai user `zmonitor` |

> **CentOS 7:** Python 3 tidak ada di repo default. Lihat bagian [Instalasi Python 3 di CentOS 7](#instalasi-python-3-di-centos-7).

## Instalasi

### 1. Clone repo

```bash
git clone https://github.com/script000kiddies000/zimbra-monitor.git
cd zimbra-monitor
```

### 2. Buat bot Telegram

1. Buka [@BotFather](https://t.me/BotFather) di Telegram → `/newbot`
2. Catat **token** yang diberikan
3. Kirim pesan ke bot kamu, lalu buka `https://api.telegram.org/bot<TOKEN>/getUpdates` untuk dapat **chat ID**
4. Untuk **user ID** kamu: kirim `/start` ke [@userinfobot](https://t.me/userinfobot)

### 3. Buat config

```bash
cp config.example.yaml config.yaml
nano config.yaml
```

Yang wajib diisi:
- `own_domains` — domain mail organisasimu (misal `example.com`)
- `internal_cidrs` — CIDR jaringan internal (IP di luar ini dianggap eksternal)
- `telegram.admin_chat_id` — chat ID tujuan notifikasi
- `telegram.admin_user_id` — user ID admin yang boleh pencet tombol

Mulai dengan `actions_enabled: false` (fase kalibrasi) — tombol aksi tidak aktif, hanya notifikasi. Aktifkan setelah 1–2 minggu kalibrasi threshold.

### 4. Jalankan setup

```bash
sudo bash setup.sh
```

Script ini secara otomatis:
- Membuat user system `zmonitor` (non-login, least privilege)
- Membuat virtualenv + install dependency di `/opt/zimbra-monitor/venv/`
- Menyalin `app.py` dan `config.yaml` ke `/opt/zimbra-monitor/`
- Mendaftarkan sudoers (dibatasi ketat ke pola `zmprov`/`postsuper` yang dipakai saja)
- Mendaftarkan dan meng-enable systemd service `zimbra-monitor`

### 5. Isi bot token

```bash
nano /opt/zimbra-monitor/zimbra-monitor.env
```

```env
ZIMBRA_MONITOR_BOT_TOKEN=123456:ABC-xyz...
```

### 6. Jalankan

```bash
# Verifikasi akses log dulu
sudo -u zmonitor tail -n1 /var/log/zimbra.log

# Start
sudo systemctl start zimbra-monitor

# Cek status
sudo systemctl status zimbra-monitor
sudo journalctl -u zimbra-monitor -f
```

---

## Update Kode

Kalau ada perubahan di `app.py`:

```bash
sudo install -o zmonitor -g zmonitor -m 640 app.py /opt/zimbra-monitor/app.py
sudo systemctl restart zimbra-monitor
```

Kalau ada perubahan di `config.yaml`:

```bash
sudo install -o zmonitor -g zmonitor -m 640 config.yaml /opt/zimbra-monitor/config.yaml
sudo systemctl restart zimbra-monitor
```

---

## Struktur File

```
zimbra-monitor/
├── app.py               # Bot utama — log watcher, rule engine, Telegram handler
├── config.example.yaml  # Template konfigurasi (salin ke config.yaml)
├── setup.sh             # Script setup idempotent (jalankan sebagai root)
└── README.md
```

File yang dibuat saat runtime (di `/opt/zimbra-monitor/`, tidak di repo):

```
/opt/zimbra-monitor/
├── app.py               # Disalin dari repo
├── config.yaml          # Konfigurasi aktif (berisi data sensitif)
├── zimbra-monitor.env   # Bot token
├── state.db             # SQLite — incidents, audit log, whitelist
├── tail_state.json      # Posisi baca log (survive restart)
└── venv/                # Python virtualenv
```

---

## Instalasi Python 3 di CentOS 7

Repo default CentOS 7 sudah EOL — Python 3 tidak tersedia via `yum`. Gunakan binary standalone:

```bash
# Download Python 3.11 standalone (sesuaikan versi jika perlu)
wget https://github.com/indygreg/python-build-standalone/releases/download/20240107/cpython-3.11.7+20240107-x86_64-unknown-linux-gnu-install_only.tar.gz
tar -xzf cpython-3.11.7*.tar.gz -C /opt
mv /opt/python /opt/python3-standalone

# Verifikasi
/opt/python3-standalone/bin/python3 --version
```

`setup.sh` otomatis mendeteksi Python di `/opt/python3-standalone/bin/python3` jika tidak ada di PATH. Atau set manual:

```bash
sudo PYTHON3_BIN=/opt/python3-standalone/bin/python3 bash setup.sh
```

---

## Diagnosis

```bash
# Status service
systemctl status zimbra-monitor
journalctl -u zimbra-monitor -f

# Verifikasi status akun di LDAP
sudo -u zimbra /opt/zimbra/bin/zmprov ga user@domain.com zimbraAccountStatus

# Cek mail queue
sudo -u zimbra /opt/zimbra/common/sbin/postqueue -p | head -20

# Lihat audit log aksi
sqlite3 /opt/zimbra-monitor/state.db "SELECT * FROM audit_log ORDER BY ts DESC LIMIT 20;"

# Lihat incidents aktif
sqlite3 /opt/zimbra-monitor/state.db "SELECT * FROM incidents WHERE status='open';"
```

> **Catatan:** `zimbraAccountStatus: locked` hanya memblokir **login baru**. Sesi SMTP yang sudah terautentikasi sebelum lock tetap aktif sampai disconnect.

---

## Keamanan

- Bot token disimpan di env file (`chmod 600`), tidak pernah di config atau source code
- Hanya satu Telegram user ID (`admin_user_id`) yang bisa menekan tombol aksi
- Sudoers dibatasi ketat hanya ke pola argumen `zmprov`/`postsuper` yang dipakai (bukan wildcard penuh)
- Service jalan sebagai user `zmonitor` (non-root, non-login)
- `config.yaml` dan `zimbra-monitor.env` tidak masuk repo (ada di `.gitignore`)
