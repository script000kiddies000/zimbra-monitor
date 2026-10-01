#!/usr/bin/env python3
"""Zimbra mail monitoring bot.

Tails /var/log/zimbra.log for outbound sends authenticated from external
IPs, dedupes matches into "incidents", and notifies + lets a single admin
act via Telegram inline buttons (Lock, Reset Password, Block IP, Ignore).

Dependencies: requests, PyYAML (both pip-installable, everything else stdlib).
See PRD.md for the design rationale behind each decision below.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import re
import secrets
import sqlite3
import string
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import requests
import urllib3.util.connection
import yaml

# api.telegram.org punya alamat IPv6 selain IPv4, dan requests/urllib3 TIDAK
# punya fallback "Happy Eyeballs" seperti curl - dia coba alamat pertama dari
# getaddrinfo() apa adanya. Di jaringan server ini jalur IPv6 keluar kadang
# macet/gak stabil, yang bikin getUpdates() (long-poll, dipanggil terus-
# menerus) sesekali nyangkut tanpa exception/log apa pun (DNS-nya sendiri
# cepat, ini soal koneksi TCP-nya yang diam). Paksa IPv4-only buat semua
# request requests/urllib3 di proses ini - lihat PRD §14 kasus nyata
# telegram_loop macet berjam-jam gara-gara ini.
urllib3.util.connection.HAS_IPV6 = False

log = logging.getLogger("zimbra-monitor")

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

# NOTE: pola ini dibuat berdasarkan format umum postfix smtpd log dengan SASL
# auth (baris seperti: "... postfix/smtpd[PID]: QUEUEID: client=host[1.2.3.4],
# sasl_method=PLAIN, sasl_username=user@domain.com"). VERIFIKASI ULANG
# terhadap sample real /var/log/zimbra.log di server ini sebelum dianggap final.
LOG_LINE_RE = re.compile(
    r"client=[^\[\s]*\[(?P<ip>[0-9a-fA-F:.]+)\].*?sasl_username=(?P<account>[^\s,]+)"
)

# Setiap baris mailq/postqueue -p yang bukan header/footer punya bentuk:
#   QUEUEID FLAG SIZE Weekday Mon DD HH:MM:SS sender@domain
QUEUE_ENTRY_RE = re.compile(
    r"^(?P<id>[0-9A-F]+)[*!]?\s+\d+\s+\S+\s+\S+\s+\S+\s+\S+\s+(?P<sender>\S+@\S+)$"
)

HARI = ["Senin", "Selasa", "Rabu", "Kamis", "Jumat", "Sabtu", "Minggu"]
BULAN = ["", "Januari", "Februari", "Maret", "April", "Mei", "Juni", "Juli",
         "Agustus", "September", "Oktober", "November", "Desember"]

RULE_LABELS = {
    "outbound_blast_external_ip": "Outbound blast dari IP eksternal",
    "queue_pileup": "Mail queue menumpuk",
    "credential_stuffing_multi_ip": "Kredensial dipakai dari banyak IP berbeda",
}

STATUS_LABELS = {
    "open": "\U0001F7E2 Open",
    "acked": "\U0001F7E1 Diabaikan (acked)",
    "expired": "⚪ Expired (gap timeout - tombol tetap aktif)",
    "closed": "\U0001F534 Closed",
}


def list_queue_entries(postqueue_path: str) -> list[tuple[str, str]]:
    """(queue_id, sender) buat tiap entry di mail queue - dipakai baik oleh
    polling rule (_check_queue) maupun aksi Delete Queue (ActionExecutor),
    biar parsing `postqueue -p` cuma ada di satu tempat."""
    out = subprocess.run(
        [postqueue_path, "-p"], capture_output=True, text=True, timeout=20
    ).stdout
    entries = []
    for line in out.splitlines():
        m = QUEUE_ENTRY_RE.match(line)
        if not m:
            continue
        entries.append((m.group("id"), m.group("sender")))
    return entries


def format_dt(ts: float, tz: ZoneInfo) -> str:
    dt = datetime.fromtimestamp(ts, tz=tz)
    hari = HARI[dt.weekday()]
    bulan = BULAN[dt.month]
    return f"{hari}, {dt.day} {bulan} {dt.year} {dt.strftime('%H:%M:%S')} {dt.strftime('%Z')}"


# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------

@dataclass
class Config:
    log_path: str
    tail_state_path: str
    db_path: str
    zmprov_path: str
    postqueue_path: str
    postsuper_path: str
    own_domains: list
    timezone: str
    internal_cidrs: list
    window_minutes: int
    threshold: int
    multi_ip_window_minutes: int
    multi_ip_threshold: int
    queue_threshold: int
    queue_check_interval: int
    gap_timeout_minutes: int
    edit_throttle_seconds: int
    bot_token: str
    admin_chat_id: int
    admin_user_id: int
    actions_enabled: bool

    @classmethod
    def load(cls, path: str) -> "Config":
        raw = yaml.safe_load(Path(path).read_text())
        telegram = raw["telegram"]
        token_env = telegram.get("bot_token_env", "ZIMBRA_MONITOR_BOT_TOKEN")
        token = os.environ.get(token_env) or telegram.get("bot_token")
        if not token:
            raise RuntimeError(
                f"Bot token tidak ditemukan. Set env var {token_env} atau "
                f"'bot_token' di config (tidak disarankan)."
            )
        rule = raw["rules"]["outbound_blast_external_ip"]
        queue_rule = raw["rules"].get("queue_pileup", {})
        incident = raw.get("incident", {})
        return cls(
            log_path=raw["log_path"],
            tail_state_path=raw.get("tail_state_path", "tail_state.json"),
            db_path=raw.get("db_path", "state.db"),
            zmprov_path=raw.get("zmprov_path", "/opt/zimbra/bin/zmprov"),
            postqueue_path=raw.get("postqueue_path", "/opt/zimbra/common/sbin/postqueue"),
            postsuper_path=raw.get("postsuper_path", "/opt/zimbra/common/sbin/postsuper"),
            own_domains=[d.lower().lstrip("@") for d in raw.get("own_domains", [])],
            timezone=raw.get("timezone", "Asia/Jakarta"),
            internal_cidrs=[ipaddress.ip_network(c) for c in raw["internal_cidrs"]],
            window_minutes=int(rule["window_minutes"]),
            threshold=int(rule["threshold"]),
            multi_ip_window_minutes=int(raw["rules"].get("credential_stuffing_multi_ip", {}).get("window_minutes", 60)),
            multi_ip_threshold=int(raw["rules"].get("credential_stuffing_multi_ip", {}).get("distinct_ip_threshold", 5)),
            queue_threshold=int(queue_rule.get("threshold_messages", 100)),
            queue_check_interval=int(raw.get("queue_check_interval_seconds", 60)),
            gap_timeout_minutes=int(incident.get("gap_timeout_minutes", 15)),
            edit_throttle_seconds=int(incident.get("edit_throttle_seconds", 25)),
            bot_token=token,
            admin_chat_id=int(telegram["admin_chat_id"]),
            admin_user_id=int(telegram["admin_user_id"]),
            # Fase 0 (PRD §11): default False - notifikasi tanpa tombol aksi
            # dulu selama kalibrasi threshold. Set true setelah yakin
            # threshold/internal_cidrs pas, baru tombol Lock/Reset/dst aktif.
            actions_enabled=bool(raw.get("actions_enabled", False)),
        )


# --------------------------------------------------------------------------
# Storage (SQLite) - events for the rule window, incidents, flagged IPs, audit
# --------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    account TEXT NOT NULL,
    client_ip TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_account_ts ON events(account, ts);

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT NOT NULL,
    account TEXT NOT NULL,
    client_ip TEXT NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    event_count INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    chat_id INTEGER,
    message_id INTEGER,
    last_edit_ts REAL
);

CREATE TABLE IF NOT EXISTS flagged_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    incident_id INTEGER,
    flagged_at REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending_review'
);

-- IP yang di-whitelist manual lewat tombol "Whitelist IP" - diperlakukan
-- sama seperti internal_cidrs di config, tapi ditambahkan on-the-fly tanpa
-- perlu tau CIDR persis di depan (PRD §10 - IP yang gak dikenal originnya
-- tapi ternyata legit).
CREATE TABLE IF NOT EXISTS whitelist_ips (
    ip TEXT PRIMARY KEY,
    incident_id INTEGER,
    added_at REAL NOT NULL
);

-- Akun yang di-whitelist lewat tombol "Whitelist Akun" - skip alert dari
-- rule IP-based (outbound_blast/credential_stuffing) tanpa peduli IP-nya
-- dari mana. expires_at NULL = permanen; isi = Unix timestamp kedaluwarsa.
-- Queue_pileup TIDAK terpengaruh whitelist ini (cek di _check_queue,
-- bukan di process_event) - masih bisa kena alert queue kalau spam.
CREATE TABLE IF NOT EXISTS whitelist_accounts (
    account TEXT PRIMARY KEY,
    incident_id INTEGER,
    added_at REAL NOT NULL,
    expires_at REAL
);

-- Akun yang sudah di-lock via tombol Lock - dipakai untuk suppress notifikasi
-- baru dari IP berbeda agar admin tidak dibanjiri alert untuk akun yang sama.
-- Incident tetap dibuat (untuk audit trail) tapi langsung auto-closed dengan note.
CREATE TABLE IF NOT EXISTS locked_accounts (
    account TEXT PRIMARY KEY,
    incident_id INTEGER,
    locked_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER,
    action TEXT NOT NULL,
    detail TEXT,
    ts REAL NOT NULL
);
"""


def open_db(db_path: str) -> sqlite3.Connection:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    conn.commit()
    return conn


# --------------------------------------------------------------------------
# Log tailer - rotation-safe (tracks inode + offset, see PRD §6.7)
# --------------------------------------------------------------------------

class LogTailer:
    def __init__(self, path: str, state_path: str):
        self.path = path
        self.state_path = state_path
        self._inode = None
        self._offset = 0
        Path(state_path).parent.mkdir(parents=True, exist_ok=True)
        self._load_state()

    def _load_state(self):
        try:
            data = json.loads(Path(self.state_path).read_text())
            self._inode = data.get("inode")
            self._offset = data.get("offset", 0)
        except (FileNotFoundError, json.JSONDecodeError):
            pass

    def _save_state(self):
        Path(self.state_path).write_text(
            json.dumps({"inode": self._inode, "offset": self._offset})
        )

    def read_new_lines(self) -> list[str]:
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            return []

        if self._inode is None:
            # First run: don't replay the whole file's history, start at EOF.
            self._inode = st.st_ino
            self._offset = st.st_size
            self._save_state()
            return []

        if st.st_ino != self._inode:
            # Rotated via rename+create (logrotate "create" mode): new file, start from 0.
            self._inode = st.st_ino
            self._offset = 0
        elif st.st_size < self._offset:
            # File shrank under the same inode: likely a "copytruncate" rotation.
            self._offset = 0

        lines = []
        with open(self.path, "r", errors="replace") as f:
            f.seek(self._offset)
            for line in f:
                lines.append(line.rstrip("\n"))
            self._offset = f.tell()
        self._save_state()
        return lines


@dataclass
class Event:
    account: str
    client_ip: str


def parse_line(line: str) -> Event | None:
    m = LOG_LINE_RE.search(line)
    if not m:
        return None
    # Lowercase - SASL username casing dari client bisa beda-beda
    # ("Yogi.Sumarsono@..." vs "yogi.sumarsono@..."), kalau gak dinormalisasi
    # count per-account di rule engine bakal terpecah jadi 2 "akun" berbeda.
    return Event(account=m.group("account").lower(), client_ip=m.group("ip"))


@dataclass
class Trigger:
    rule_id: str
    account: str
    client_ip: str
    count: int


# --------------------------------------------------------------------------
# Rule engine
# --------------------------------------------------------------------------

class RuleEngine:
    def __init__(self, cfg: Config, db: sqlite3.Connection, lock: threading.Lock):
        self.cfg = cfg
        self.db = db
        self.lock = lock

    def is_internal(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return True  # unparseable -> fail safe, don't alert on it
        if any(addr in net for net in self.cfg.internal_cidrs):
            return True
        # IP yang di-whitelist manual lewat tombol "Whitelist IP" (§6.4) -
        # dicek belakangan karena ini query DB, internal_cidrs di atas gratis.
        with self.lock:
            row = self.db.execute("SELECT 1 FROM whitelist_ips WHERE ip=?", (ip,)).fetchone()
        return row is not None

    def is_whitelisted_account(self, account: str) -> bool:
        now = time.time()
        with self.lock:
            row = self.db.execute(
                "SELECT 1 FROM whitelist_accounts WHERE account=? "
                "AND (expires_at IS NULL OR expires_at > ?)",
                (account, now),
            ).fetchone()
        return row is not None

    def is_locked_account(self, account: str) -> bool:
        with self.lock:
            row = self.db.execute(
                "SELECT 1 FROM locked_accounts WHERE account=?", (account,)
            ).fetchone()
        return row is not None

    def process_event(self, event: Event) -> list[Trigger]:
        if self.is_internal(event.client_ip):
            return []
        now = time.time()
        window_start = now - self.cfg.window_minutes * 60
        multi_ip_window_start = now - self.cfg.multi_ip_window_minutes * 60
        retention = max(self.cfg.window_minutes, self.cfg.multi_ip_window_minutes) * 60 * 3
        with self.lock, self.db:
            self.db.execute(
                "INSERT INTO events (ts, account, client_ip) VALUES (?, ?, ?)",
                (now, event.account, event.client_ip),
            )
            count = self.db.execute(
                "SELECT COUNT(*) FROM events WHERE account=? AND ts>=?",
                (event.account, window_start),
            ).fetchone()[0]
            # Rule kedua: akun yang sama diauth dari BANYAK IP eksternal
            # berbeda dalam window yang lebih panjang - sinyal kredensial
            # bocor/credential-stuffing yang independen dari volume kirim
            # (kasus nyata: satu akun dicoba dari puluhan IP sedikit-sedikit
            # tersebar ~1 jam, tidak pernah lewat threshold volume per menit).
            distinct_ips = self.db.execute(
                "SELECT COUNT(DISTINCT client_ip) FROM events WHERE account=? AND ts>=?",
                (event.account, multi_ip_window_start),
            ).fetchone()[0]
            if secrets.randbelow(50) == 0:  # occasional housekeeping
                self.db.execute("DELETE FROM events WHERE ts < ?", (now - retention,))

        # Event tetap dicatat ke DB di atas (berguna kalau whitelist habis dan
        # butuh history), tapi trigger di-skip kalau akun lagi di-whitelist.
        if self.is_whitelisted_account(event.account):
            return []

        triggers = []
        if count >= self.cfg.threshold:
            triggers.append(Trigger("outbound_blast_external_ip", event.account, event.client_ip, count))
        if distinct_ips >= self.cfg.multi_ip_threshold:
            triggers.append(Trigger("credential_stuffing_multi_ip", event.account, event.client_ip, distinct_ips))
        return triggers


# --------------------------------------------------------------------------
# Telegram client - thin wrapper over the HTTP API, no bot framework
# --------------------------------------------------------------------------

class Telegram:
    def __init__(self, token: str):
        self._token = token
        self.base = f"https://api.telegram.org/bot{token}"

    def _redact(self, exc: Exception) -> Exception:
        # requests.HTTPError/ConnectionError dkk nyimpen full URL (termasuk
        # token) di message-nya - itu bisa keluar polos di journalctl lewat
        # log.exception(). Ganti sebelum di-raise ulang / di-log.
        text = str(exc).replace(self._token, "***REDACTED***")
        return exc.__class__(text)

    def _post(self, method: str, payload: dict) -> dict:
        try:
            r = requests.post(f"{self.base}/{method}", json=payload, timeout=20)
            r.raise_for_status()
        except requests.RequestException as exc:
            raise self._redact(exc) from None
        return r.json()

    def send_message(self, chat_id: int, text: str, keyboard: dict | None = None) -> dict:
        payload = {"chat_id": chat_id, "text": text, "parse_mode": "HTML"}
        if keyboard:
            payload["reply_markup"] = keyboard
        return self._post("sendMessage", payload)

    def edit_message(self, chat_id: int, message_id: int, text: str, keyboard: dict | None):
        payload = {"chat_id": chat_id, "message_id": message_id, "text": text, "parse_mode": "HTML"}
        payload["reply_markup"] = keyboard or {"inline_keyboard": []}
        try:
            return self._post("editMessageText", payload)
        except requests.RequestException:
            log.exception("gagal edit message chat_id=%s message_id=%s", chat_id, message_id)

    def answer_callback(self, callback_id: str, text: str | None = None):
        payload = {"callback_query_id": callback_id}
        if text:
            payload["text"] = text
        try:
            self._post("answerCallbackQuery", payload)
        except requests.RequestException:
            log.exception("gagal answerCallbackQuery")

    def edit_reply_markup(self, chat_id: int, message_id: int, keyboard: dict):
        payload = {"chat_id": chat_id, "message_id": message_id, "reply_markup": keyboard}
        try:
            return self._post("editMessageReplyMarkup", payload)
        except requests.RequestException:
            log.exception("gagal edit reply markup chat_id=%s message_id=%s", chat_id, message_id)

    def get_updates(self, offset: int, timeout: int = 30) -> dict:
        try:
            r = requests.get(
                f"{self.base}/getUpdates",
                params={"offset": offset, "timeout": timeout},
                # Margin lebih longgar dari nilai long-poll-nya sendiri -
                # kalau cuma +10 kadang kekejar ReadTimeout pas Telegram
                # agak lambat balas persis di ujung window long-poll.
                timeout=timeout + 20,
            )
            r.raise_for_status()
        except requests.RequestException as exc:
            raise self._redact(exc) from None
        return r.json()


# --------------------------------------------------------------------------
# Action executor - only place that shells out to zmprov (see PRD §6.5/§6.9/§13)
# --------------------------------------------------------------------------

class ActionExecutor:
    def __init__(self, cfg: Config):
        self.cfg = cfg

    @staticmethod
    def validate_account(account: str):
        if not EMAIL_RE.match(account):
            raise ValueError(f"format akun tidak valid: {account!r}")

    @staticmethod
    def validate_ip(ip: str):
        ipaddress.ip_address(ip)  # raises ValueError kalau tidak valid

    def _zmprov(self, *args: str):
        # Proses ini jalan sebagai user non-root 'zmonitor'. sudoers hanya
        # izinkan menjalankan zmprov sebagai user 'zimbra' dengan pola
        # argumen yang persis sesuai lock_account/reset_password di bawah
        # (lihat setup.sh) - tidak ada wrapper script tambahan yang bisa
        # jadi target tampering kalau akun zmonitor kebobolan.
        cmd = ["sudo", "-u", "zimbra", self.cfg.zmprov_path, *args]
        subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=30)

    def lock_account(self, account: str, description: str):
        self.validate_account(account)
        self._zmprov("ma", account, "zimbraAccountStatus", "locked", "description", description)

    def reset_password(self, account: str) -> str:
        self.validate_account(account)
        password = self._generate_password()
        self._zmprov("sp", account, password)
        self._zmprov("ma", account, "zimbraPasswordMustChange", "TRUE")
        return password

    @staticmethod
    def _generate_password(length: int = 16) -> str:
        alphabet = string.ascii_letters + string.digits + "!@#%^*-_="
        return "".join(secrets.choice(alphabet) for _ in range(length))

    def delete_queue(self, account: str) -> int:
        """Hapus semua pesan milik `account` yang masih ada di mail queue
        SEKARANG (di-query ulang di sini, bukan pakai count lama dari
        incident, biar gak kehapus lebih/kurang dari kondisi riil - lihat
        PRD §6.2/§14 soal queue_pileup). Return jumlah pesan yang dihapus."""
        self.validate_account(account)
        ids = [
            qid for qid, sender in list_queue_entries(self.cfg.postqueue_path)
            if sender.lower() == account.lower()
        ]
        if not ids:
            return 0
        # postsuper WAJIB dijalankan sebagai root literal ("reserved for the
        # superuser" kalau dicoba via `sudo -u zimbra`/`-u postfix` - beda
        # dari zmprov) - baru di dalamnya Postfix drop privilege sendiri ke
        # mail_owner (postfix). Sudoers dibatasi ketat ke pattern persis
        # "postsuper -d <ids>" (lihat setup.sh) - id-id ini sudah divalidasi
        # regex hex di QUEUE_ENTRY_RE, bukan dari input bebas, jadi aman
        # dilempar langsung ke argv (bukan shell) meski runas-nya root.
        cmd = ["sudo", self.cfg.postsuper_path, "-d", *ids]
        subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=30)
        return len(ids)


# --------------------------------------------------------------------------
# Incident manager - dedupe (PRD §6.8) + Telegram message formatting
# --------------------------------------------------------------------------

class IncidentManager:
    def __init__(self, cfg: Config, db: sqlite3.Connection, lock: threading.Lock, tg: Telegram, tz: ZoneInfo):
        self.cfg = cfg
        self.db = db
        self.lock = lock
        self.tg = tg
        self.tz = tz

    def _recent_ips(self, account: str, as_of: float, limit: int = 15) -> list[str]:
        window_start = as_of - self.cfg.multi_ip_window_minutes * 60
        with self.lock:
            rows = self.db.execute(
                "SELECT DISTINCT client_ip FROM events WHERE account=? AND ts>=? "
                "ORDER BY ts DESC LIMIT ?",
                (account, window_start, limit),
            ).fetchall()
        return [r[0] for r in rows]

    def format_message(
        self, incident_id, rule_id, account, ip, count, first_seen,
        last_seen=None, status="open", note=None,
    ) -> str:
        last_seen = last_seen or first_seen
        label = RULE_LABELS.get(rule_id, rule_id)
        status_label = STATUS_LABELS.get(status, status)

        if rule_id == "queue_pileup":
            batas = f"Threshold: {self.cfg.queue_threshold} pesan di queue"
            # postqueue -p sendiri gak nyimpen IP pengirim - cross-reference
            # ke tabel events (log SASL auth) buat kasih konteks IP mana
            # yang login sbg akun ini belakangan, meski rule ini gak trigger
            # berdasarkan IP (lihat penjelasan di chat).
            ips = self._recent_ips(account, last_seen)
            if ips:
                ip_line = (
                    f"IP eksternal yang login sbg akun ini ({len(ips)}, "
                    f"{self.cfg.multi_ip_window_minutes} menit terakhir): "
                    f"<code>{', '.join(ips)}</code>\n"
                )
            else:
                ip_line = (
                    "IP sumber: tidak ada login SASL dari IP eksternal terdeteksi - "
                    "kemungkinan dari jaringan internal atau relay tanpa auth\n"
                )
        elif rule_id == "credential_stuffing_multi_ip":
            batas = (
                f"Threshold: {self.cfg.multi_ip_threshold} IP eksternal berbeda "
                f"dalam {self.cfg.multi_ip_window_minutes} menit"
            )
            ips = self._recent_ips(account, last_seen)
            ip_line = f"IP yang terdeteksi ({len(ips)}): <code>{', '.join(ips)}</code>\n"
        else:
            batas = f"Threshold: {self.cfg.threshold} email / {self.cfg.window_minutes} menit"
            ip_line = f"IP sumber: <code>{ip}</code> (eksternal)\n"

        durasi_detik = int(last_seen - first_seen)
        durasi = f"{durasi_detik // 60} menit {durasi_detik % 60} detik" if durasi_detik > 0 else "baru saja"

        lines = [
            f"\U0001F6A8 <b>{label}</b>",
            f"Status: {status_label}",
            f"Akun: <code>{account}</code>",
        ]
        if ip_line:
            lines.append(ip_line.rstrip("\n"))
        lines += [
            f"Jumlah terdeteksi: <b>{count}</b>",
            batas,
            f"Terdeteksi sejak: {format_dt(first_seen, self.tz)}",
            f"Update terakhir: {format_dt(last_seen, self.tz)}",
            f"Durasi berlangsung: {durasi}",
            f"Incident #{incident_id}",
        ]
        text = "\n".join(lines)
        if note:
            text += f"\n\n{note}"
        return text

    def keyboard(self, incident_id: int, rule_id: str) -> dict | None:
        if not self.cfg.actions_enabled:
            # Fase 0 (PRD §11) - notifikasi read-only dulu, belum ada
            # tombol aksi sama sekali selama kalibrasi threshold.
            return None
        if rule_id == "queue_pileup":
            # queue_pileup gak punya client_ip terkait (Block/Whitelist IP
            # selalu no-op buat rule ini) - ganti dengan tombol khusus buat
            # hapus pesan sender ini dari mail queue langsung.
            # "Whitelist Akun" juga tidak ditampilkan untuk queue_pileup -
            # whitelist account hanya suppress rule IP-based, bukan queue_pileup,
            # jadi tidak relevan (dan queue_pileup tetap jadi safety net).
            return {
                "inline_keyboard": [
                    [
                        {"text": "\U0001F512 Lock", "callback_data": f"lock:{incident_id}"},
                        {"text": "\U0001F511 Reset", "callback_data": f"reset:{incident_id}"},
                    ],
                    [
                        {"text": "\U0001F5D1 Delete Queue", "callback_data": f"delete_queue:{incident_id}"},
                    ],
                    [
                        {"text": "✅ Ignore", "callback_data": f"ignore:{incident_id}"},
                    ],
                ]
            }
        return {
            "inline_keyboard": [
                [
                    {"text": "\U0001F512 Lock", "callback_data": f"lock:{incident_id}"},
                    {"text": "\U0001F511 Reset", "callback_data": f"reset:{incident_id}"},
                ],
                [
                    {"text": "\U0001F6AB Block IP", "callback_data": f"block:{incident_id}"},
                    {"text": "\U0001F7E2 Whitelist IP", "callback_data": f"whitelist:{incident_id}"},
                ],
                [
                    {"text": "\U0001F464 Whitelist Akun", "callback_data": f"whitelist_account:{incident_id}"},
                ],
                [
                    {"text": "✅ Ignore", "callback_data": f"ignore:{incident_id}"},
                ],
            ]
        }

    def handle_trigger(self, trig: Trigger):
        now = time.time()
        with self.lock, self.db:
            row = self.db.execute(
                "SELECT id, chat_id, message_id, last_edit_ts, first_seen FROM incidents "
                "WHERE rule_id=? AND account=? AND status='open'",
                (trig.rule_id, trig.account),
            ).fetchone()

            if row is None:
                # Cek apakah akun sudah pernah di-lock sebelumnya.
                # Kalau iya: buat incident tapi langsung auto-closed + kirim notif
                # informatif (bukan alert kritis) agar admin tahu ada IP baru.
                already_locked = self.db.execute(
                    "SELECT incident_id FROM locked_accounts WHERE account=?",
                    (trig.account,),
                ).fetchone()

                cur = self.db.execute(
                    "INSERT INTO incidents "
                    "(rule_id, account, client_ip, first_seen, last_seen, event_count, status) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (trig.rule_id, trig.account, trig.client_ip, now, now, trig.count,
                     "closed" if already_locked else "open"),
                )
                incident_id = cur.lastrowid

                if already_locked:
                    prev_incident_id = already_locked[0]
                    note = (
                        f"ℹ️ Akun ini sudah terkunci sejak incident #{prev_incident_id}. "
                        f"Percobaan baru dari IP <code>{trig.client_ip}</code> diabaikan secara otomatis."
                    )
                    text = self.format_message(
                        incident_id, trig.rule_id, trig.account, trig.client_ip, trig.count,
                        first_seen=now, last_seen=now, status="closed", note=note,
                    )
                    resp = self.tg.send_message(self.cfg.admin_chat_id, text, keyboard=None)
                else:
                    text = self.format_message(
                        incident_id, trig.rule_id, trig.account, trig.client_ip, trig.count,
                        first_seen=now, last_seen=now, status="open",
                    )
                    resp = self.tg.send_message(self.cfg.admin_chat_id, text, self.keyboard(incident_id, trig.rule_id))

                message_id = resp["result"]["message_id"]
                self.db.execute(
                    "UPDATE incidents SET chat_id=?, message_id=?, last_edit_ts=? WHERE id=?",
                    (self.cfg.admin_chat_id, message_id, now, incident_id),
                )
                return

            incident_id, chat_id, message_id, last_edit_ts, first_seen = row
            self.db.execute(
                "UPDATE incidents SET last_seen=?, event_count=? WHERE id=?",
                (now, trig.count, incident_id),
            )
            if now - (last_edit_ts or 0) >= self.cfg.edit_throttle_seconds:
                text = self.format_message(
                    incident_id, trig.rule_id, trig.account, trig.client_ip, trig.count,
                    first_seen=first_seen, last_seen=now, status="open",
                )
                self.tg.edit_message(chat_id, message_id, text, self.keyboard(incident_id, trig.rule_id))
                self.db.execute("UPDATE incidents SET last_edit_ts=? WHERE id=?", (now, incident_id))

    def sweep_stale(self):
        # 'expired' (bukan 'closed') - ini cuma nutup dedup window (biar
        # event baru bikin incident baru), BUKAN keputusan admin. Tombol di
        # message Telegram yang sudah terkirim tetap harus aktif kalau admin
        # masih mau bertindak di incident lama ini (misal baru sempat buka
        # notif-nya belakangan) - lihat _refresh_message, hanya status
        # 'closed' (keputusan eksplisit admin: Lock/Whitelist) yang
        # menyembunyikan tombol.
        cutoff = time.time() - self.cfg.gap_timeout_minutes * 60
        with self.lock, self.db:
            self.db.execute(
                "UPDATE incidents SET status='expired' WHERE status='open' AND last_seen < ?",
                (cutoff,),
            )


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------

class MonitorBot:
    def __init__(self, config_path: str):
        self.cfg = Config.load(config_path)
        self.tz = ZoneInfo(self.cfg.timezone)
        self.db = open_db(self.cfg.db_path)
        self.lock = threading.Lock()
        self.tailer = LogTailer(self.cfg.log_path, self.cfg.tail_state_path)
        self.tg = Telegram(self.cfg.bot_token)
        self.executor = ActionExecutor(self.cfg)
        self.rules = RuleEngine(self.cfg, self.db, self.lock)
        self.incidents = IncidentManager(self.cfg, self.db, self.lock, self.tg, self.tz)
        self._stop = threading.Event()
        self._start_ts = time.time()
        self._last_poll_ts = time.time()  # watchdog: diupdate tiap iterasi telegram_loop

    # -- log tailing -------------------------------------------------

    def tail_loop(self):
        while not self._stop.is_set():
            try:
                for line in self.tailer.read_new_lines():
                    event = parse_line(line)
                    if event is None:
                        continue
                    for trig in self.rules.process_event(event):
                        self.incidents.handle_trigger(trig)
                self.incidents.sweep_stale()
            except Exception:
                log.exception("tail_loop error")
            time.sleep(2)

    # -- mail queue polling -------------------------------------------

    def queue_loop(self):
        while not self._stop.is_set():
            try:
                self._check_queue()
            except Exception:
                log.exception("queue check gagal")
            time.sleep(self.cfg.queue_check_interval)

    def _check_queue(self):
        # Zimbra punya Postfix sendiri di bawah /opt/zimbra/common/ - binary
        # `mailq` sistem (/usr/bin/mailq) TIDAK terhubung ke instance itu dan
        # akan gagal dengan "mail system is down". Sudah dikonfirmasi di
        # server produksi: postqueue_path (bawaan Zimbra) yang benar.
        counts: dict[str, int] = {}
        for _qid, sender in list_queue_entries(self.cfg.postqueue_path):
            # Cuma hitung sender dari domain sendiri - mailq juga berisi
            # backlog inbound (NDR/bounce dari domain eksternal) yang bukan
            # sinyal "akun lokal kompromise", lihat PRD §10 (temuan sample
            # queue nyata di server).
            if not any(sender.lower().endswith("@" + d) for d in self.cfg.own_domains):
                continue
            counts[sender] = counts.get(sender, 0) + 1
        for sender, count in counts.items():
            if count >= self.cfg.queue_threshold:
                self.incidents.handle_trigger(Trigger("queue_pileup", sender, "-", count))

    # -- telegram polling + callback handling --------------------------

    def telegram_loop(self):
        offset = 0
        while not self._stop.is_set():
            try:
                resp = self.tg.get_updates(offset, timeout=30)
            except requests.Timeout:
                # Wajar sesekali kejadian di long-polling (Telegram lambat
                # balas persis di ujung window) - bukan kegagalan nyata,
                # langsung retry tanpa spam traceback ke log.
                log.debug("getUpdates timeout (normal untuk long-poll), retry")
                self._last_poll_ts = time.time()
                continue
            except requests.RequestException:
                log.exception("getUpdates gagal, retry dalam 5s")
                self._last_poll_ts = time.time()
                time.sleep(5)
                continue
            self._last_poll_ts = time.time()
            for update in resp.get("result", []):
                offset = update["update_id"] + 1
                cq = update.get("callback_query")
                if cq:
                    try:
                        self._handle_callback(cq)
                    except Exception:
                        log.exception("gagal proses callback (incident tetap jalan, tombol berikutnya tetap dicoba)")
                msg = update.get("message")
                if msg and msg.get("text", "").startswith("/"):
                    try:
                        self._handle_command(msg)
                    except Exception:
                        log.exception("gagal proses command")

    def _handle_callback(self, cq: dict):
        if cq["from"]["id"] != self.cfg.admin_user_id:
            self.tg.answer_callback(cq["id"], "Unauthorized")
            log.warning("callback ditolak dari user_id=%s", cq["from"]["id"])
            return

        if not self.cfg.actions_enabled:
            # Fase 0 (PRD §11) - tolak eksekusi meski ada tombol lama yang
            # somehow masih tampil (misal actions_enabled baru dimatikan
            # setelah message dengan tombol sudah terkirim sebelumnya).
            self.tg.answer_callback(cq["id"], "Tombol aksi belum diaktifkan (Fase 0)")
            return

        try:
            action, incident_id_s = cq.get("data", "").split(":", 1)
            incident_id = int(incident_id_s)
        except ValueError:
            self.tg.answer_callback(cq["id"], "Bad callback")
            return

        with self.lock:
            row = self.db.execute(
                "SELECT rule_id, account, client_ip, event_count FROM incidents WHERE id=?",
                (incident_id,),
            ).fetchone()
        if row is None:
            self.tg.answer_callback(cq["id"], "Incident tidak ditemukan")
            return
        rule_id, account, client_ip, event_count = row

        # Defensive re-validation sebelum dipakai ke zmprov/DB - lihat PRD §6.9.
        try:
            self.executor.validate_account(account)
            self.executor.validate_ip(client_ip) if client_ip != "-" else None
        except ValueError as exc:
            self.tg.answer_callback(cq["id"], "Data invalid")
            log.error("validasi gagal untuk incident %s: %s", incident_id, exc)
            return

        # --- Aksi 2-langkah: tidak lewat alur audit+refresh biasa -----------

        if action == "whitelist_account":
            # Langkah 1: tampilkan sub-tombol pilihan durasi - ganti keyboard
            # saja (teks notif tidak berubah), belum ada aksi nyata yang dicatat.
            sub_kb = {
                "inline_keyboard": [
                    [
                        {"text": "\U0001F4C5 30 Hari", "callback_data": f"whitelist_account_30d:{incident_id}"},
                        {"text": "♾️ Permanen", "callback_data": f"whitelist_account_perm:{incident_id}"},
                    ],
                    [
                        {"text": "↩️ Batal", "callback_data": f"whitelist_account_cancel:{incident_id}"},
                    ],
                ]
            }
            self.tg.answer_callback(cq["id"], "Pilih durasi whitelist akun")
            with self.lock:
                loc = self.db.execute(
                    "SELECT chat_id, message_id FROM incidents WHERE id=?", (incident_id,)
                ).fetchone()
            if loc:
                self.tg.edit_reply_markup(loc[0], loc[1], sub_kb)
            return

        if action == "whitelist_account_cancel":
            # Langkah batal: kembalikan keyboard asli tanpa mencatat apa pun.
            self.tg.answer_callback(cq["id"], "Dibatalkan")
            self._refresh_message(incident_id)
            return

        # --- Akhir aksi 2-langkah -----------------------------------------

        note = None
        try:
            if action == "lock":
                desc = (
                    f"Locked by zimbra-monitor bot: ip={client_ip}, count={event_count}, "
                    f"at={datetime.now(self.tz).isoformat()}"
                )
                self.executor.lock_account(account, desc)
                self._set_status(incident_id, "closed")
                with self.db:
                    self.db.execute(
                        "INSERT OR REPLACE INTO locked_accounts (account, incident_id, locked_at) "
                        "VALUES (?, ?, ?)",
                        (account, incident_id, time.time()),
                    )
                note = f"\U0001F512 Akun <code>{account}</code> berhasil di-lock."
            elif action == "reset":
                password = self.executor.reset_password(account)
                # Sengaja TIDAK menutup incident - reset password sering
                # diikuti Lock (atau sebaliknya) pada incident yang sama,
                # jadi tombol lain harus tetap aktif setelah reset.
                note = f"\U0001F511 Password baru untuk <code>{account}</code>: <code>{password}</code>"
            elif action == "block":
                if client_ip == "-":
                    note = "Rule ini tidak punya IP terkait (mis. queue_pileup) - tidak ada yang bisa di-block."
                else:
                    with self.lock, self.db:
                        self.db.execute(
                            "INSERT INTO flagged_ips (ip, incident_id, flagged_at, status) "
                            "VALUES (?, ?, ?, 'pending_review')",
                            (client_ip, incident_id, time.time()),
                        )
                    note = f"\U0001F6AB IP <code>{client_ip}</code> ditambahkan ke daftar review (belum di-block)."
            elif action == "whitelist":
                if client_ip == "-":
                    note = "Rule ini tidak punya IP terkait (mis. queue_pileup) - tidak ada yang bisa di-whitelist."
                else:
                    with self.lock, self.db:
                        self.db.execute(
                            "INSERT OR REPLACE INTO whitelist_ips (ip, incident_id, added_at) VALUES (?, ?, ?)",
                            (client_ip, incident_id, time.time()),
                        )
                    self._set_status(incident_id, "closed")
                    note = (
                        f"\U0001F7E2 IP <code>{client_ip}</code> di-whitelist permanen - "
                        f"tidak akan dialert lagi ke depannya."
                    )
            elif action == "whitelist_account_30d":
                expires_at = time.time() + 30 * 24 * 3600
                with self.lock, self.db:
                    self.db.execute(
                        "INSERT OR REPLACE INTO whitelist_accounts "
                        "(account, incident_id, added_at, expires_at) VALUES (?, ?, ?, ?)",
                        (account, incident_id, time.time(), expires_at),
                    )
                self._set_status(incident_id, "closed")
                note = (
                    f"\U0001F464 Akun <code>{account}</code> di-whitelist selama <b>30 hari</b> - "
                    f"tidak akan dialert lagi sampai {format_dt(expires_at, self.tz)}. "
                    f"Queue pileup tetap bisa kena alert."
                )
            elif action == "whitelist_account_perm":
                with self.lock, self.db:
                    self.db.execute(
                        "INSERT OR REPLACE INTO whitelist_accounts "
                        "(account, incident_id, added_at, expires_at) VALUES (?, ?, ?, NULL)",
                        (account, incident_id, time.time()),
                    )
                self._set_status(incident_id, "closed")
                note = (
                    f"\U0001F464 Akun <code>{account}</code> di-whitelist <b>permanen</b> - "
                    f"tidak akan pernah dialert dari rule IP-based. "
                    f"Queue pileup tetap bisa kena alert."
                )
            elif action == "delete_queue":
                if rule_id != "queue_pileup":
                    note = "Aksi ini cuma berlaku untuk incident queue_pileup."
                else:
                    deleted = self.executor.delete_queue(account)
                    if deleted == 0:
                        note = (
                            "\U0001F5D1 Tidak ada pesan <code>{}</code> di queue saat ini "
                            "(mungkin sudah terkirim/expired sejak notif ini muncul)."
                        ).format(account)
                    else:
                        self._set_status(incident_id, "closed")
                        note = (
                            f"\U0001F5D1 {deleted} pesan milik <code>{account}</code> "
                            f"berhasil dihapus permanen dari mail queue."
                        )
            elif action == "ignore":
                self._set_status(incident_id, "acked")
                note = "✅ Incident ditandai diabaikan."
            else:
                note = f"Aksi tidak dikenal: {action}"
        except subprocess.CalledProcessError as exc:
            log.exception("perintah shell (zmprov/postsuper) gagal")
            note = f"⚠️ Aksi gagal: {exc.stderr}"
        except Exception as exc:
            log.exception("aksi gagal")
            note = f"⚠️ Aksi gagal: {exc}"

        self._audit(incident_id, action, note)
        self.tg.answer_callback(cq["id"], "OK")
        self._refresh_message(incident_id)

    # -- command handler (/whitelist_ip, /whitelist_akun, dst) -------------

    _HELP = (
        "<b>Command tersedia:</b>\n"
        "/whitelist_ip — daftar IP yang di-whitelist\n"
        "/whitelist_akun — daftar akun yang di-whitelist\n"
        "/del_ip &lt;ip&gt; — hapus IP dari whitelist\n"
        "/del_akun &lt;email&gt; — hapus akun dari whitelist\n"
        "/incidents — incident yang masih aktif\n"
        "/flagged — IP yang di-flag pending review\n"
        "/status — kesehatan bot"
    )

    def _handle_command(self, msg: dict):
        if msg.get("from", {}).get("id") != self.cfg.admin_user_id:
            return
        chat_id = msg["chat"]["id"]
        if chat_id != self.cfg.admin_chat_id:
            return

        text = msg.get("text", "").strip()
        parts = text.split()
        # handle /cmd@botname format
        cmd = parts[0].lower().split("@")[0]
        args = parts[1:]

        dispatch = {
            "/whitelist_ip":   lambda: self._cmd_whitelist_ip(chat_id),
            "/whitelist_akun": lambda: self._cmd_whitelist_akun(chat_id),
            "/incidents":      lambda: self._cmd_incidents(chat_id),
            "/flagged":        lambda: self._cmd_flagged(chat_id),
            "/status":         lambda: self._cmd_status(chat_id),
            "/del_ip":         lambda: self._cmd_del_ip(chat_id, args),
            "/del_akun":       lambda: self._cmd_del_akun(chat_id, args),
            "/help":           lambda: self.tg.send_message(chat_id, self._HELP),
            "/start":          lambda: self.tg.send_message(chat_id, self._HELP),
        }
        fn = dispatch.get(cmd)
        if fn:
            fn()
        else:
            self.tg.send_message(chat_id, f"❓ Command tidak dikenal.\n\n{self._HELP}")

    def _cmd_whitelist_ip(self, chat_id: int):
        with self.lock:
            rows = self.db.execute(
                "SELECT w.ip, i.account, datetime(w.added_at,'unixepoch','localtime') "
                "FROM whitelist_ips w LEFT JOIN incidents i ON w.incident_id = i.id "
                "ORDER BY w.added_at DESC"
            ).fetchall()
        if not rows:
            self.tg.send_message(chat_id, "✅ Tidak ada IP di whitelist.")
            return
        lines = ["<b>Whitelist IP</b> ({} entri):".format(len(rows))]
        for ip, account, added_at in rows:
            akun = account or "-"
            lines.append(f"• <code>{ip}</code> — {akun} ({added_at})")
        self.tg.send_message(chat_id, "\n".join(lines))

    def _cmd_whitelist_akun(self, chat_id: int):
        now = time.time()
        with self.lock:
            rows = self.db.execute(
                "SELECT account, added_at, expires_at "
                "FROM whitelist_accounts ORDER BY added_at DESC"
            ).fetchall()
        if not rows:
            self.tg.send_message(chat_id, "✅ Tidak ada akun di whitelist.")
            return
        lines = ["<b>Whitelist Akun</b> ({} entri):".format(len(rows))]
        for account, added_at, expires_at in rows:
            if expires_at is None:
                durasi = "permanen"
            elif expires_at <= now:
                durasi = "⚠️ sudah expired"
            else:
                sisa = int((expires_at - now) / 86400)
                durasi = f"expires {format_dt(expires_at, self.tz)} (sisa {sisa} hari)"
            lines.append(f"• <code>{account}</code>\n  {durasi}")
        self.tg.send_message(chat_id, "\n".join(lines))

    def _cmd_del_ip(self, chat_id: int, args: list):
        if not args:
            self.tg.send_message(chat_id, "❓ Pakai: /del_ip &lt;ip&gt;")
            return
        ip = args[0]
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            self.tg.send_message(chat_id, f"⚠️ Format IP tidak valid: <code>{ip}</code>")
            return
        with self.lock, self.db:
            self.db.execute("DELETE FROM whitelist_ips WHERE ip=?", (ip,))
            deleted = self.db.execute("SELECT changes()").fetchone()[0]
        if deleted:
            self.tg.send_message(chat_id, f"🗑 IP <code>{ip}</code> dihapus dari whitelist.")
        else:
            self.tg.send_message(chat_id, f"⚠️ IP <code>{ip}</code> tidak ditemukan di whitelist.")

    def _cmd_del_akun(self, chat_id: int, args: list):
        if not args:
            self.tg.send_message(chat_id, "❓ Pakai: /del_akun &lt;email&gt;")
            return
        account = args[0].lower()
        if not EMAIL_RE.match(account):
            self.tg.send_message(chat_id, f"⚠️ Format email tidak valid: <code>{account}</code>")
            return
        with self.lock, self.db:
            self.db.execute("DELETE FROM whitelist_accounts WHERE account=?", (account,))
            deleted = self.db.execute("SELECT changes()").fetchone()[0]
        if deleted:
            self.tg.send_message(chat_id, f"🗑 Akun <code>{account}</code> dihapus dari whitelist.")
        else:
            self.tg.send_message(chat_id, f"⚠️ Akun <code>{account}</code> tidak ditemukan di whitelist.")

    def _cmd_incidents(self, chat_id: int):
        with self.lock:
            rows = self.db.execute(
                "SELECT id, rule_id, account, event_count, status, first_seen, last_seen "
                "FROM incidents WHERE status IN ('open','expired') "
                "ORDER BY last_seen DESC LIMIT 15"
            ).fetchall()
        if not rows:
            self.tg.send_message(chat_id, "✅ Tidak ada incident aktif.")
            return
        lines = [f"<b>Incident aktif</b> (maks 15):"]
        for inc_id, rule_id, account, count, status, first_seen, last_seen in rows:
            label = RULE_LABELS.get(rule_id, rule_id)
            st = "🟢" if status == "open" else "⚪"
            lines.append(
                f"{st} <b>#{inc_id}</b> — <code>{account}</code>\n"
                f"  {label}, {count}x | {format_dt(last_seen, self.tz)}"
            )
        self.tg.send_message(chat_id, "\n".join(lines))

    def _cmd_flagged(self, chat_id: int):
        with self.lock:
            rows = self.db.execute(
                "SELECT f.ip, i.account, f.status, datetime(f.flagged_at,'unixepoch','localtime') "
                "FROM flagged_ips f LEFT JOIN incidents i ON f.incident_id = i.id "
                "ORDER BY f.flagged_at DESC LIMIT 20"
            ).fetchall()
        if not rows:
            self.tg.send_message(chat_id, "✅ Tidak ada IP yang di-flag.")
            return
        lines = [f"<b>Flagged IPs</b> ({len(rows)} entri):"]
        for ip, account, status, flagged_at in rows:
            akun = account or "-"
            lines.append(f"• <code>{ip}</code> — {akun}\n  {status} | {flagged_at}")
        self.tg.send_message(chat_id, "\n".join(lines))

    def _cmd_status(self, chat_id: int):
        now = time.time()
        uptime_s = int(now - self._start_ts)
        uptime = f"{uptime_s // 3600}j {(uptime_s % 3600) // 60}m {uptime_s % 60}d"
        poll_age = int(now - self._last_poll_ts)
        with self.lock:
            open_inc = self.db.execute(
                "SELECT COUNT(*) FROM incidents WHERE status='open'"
            ).fetchone()[0]
            total_events = self.db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            wl_ip = self.db.execute("SELECT COUNT(*) FROM whitelist_ips").fetchone()[0]
            wl_akun = self.db.execute(
                "SELECT COUNT(*) FROM whitelist_accounts WHERE expires_at IS NULL OR expires_at > ?",
                (now,)
            ).fetchone()[0]
        lines = [
            "<b>Status Bot</b>",
            f"Uptime: {uptime}",
            f"Poll terakhir: {poll_age}d lalu",
            f"Incident open: {open_inc}",
            f"Events di DB: {total_events}",
            f"Whitelist IP: {wl_ip} entri",
            f"Whitelist Akun: {wl_akun} aktif",
        ]
        self.tg.send_message(chat_id, "\n".join(lines))

    def _set_status(self, incident_id: int, status: str):
        with self.lock, self.db:
            self.db.execute("UPDATE incidents SET status=? WHERE id=?", (status, incident_id))

    def _audit(self, incident_id: int, action: str, detail: str | None):
        with self.lock, self.db:
            self.db.execute(
                "INSERT INTO audit_log (incident_id, action, detail, ts) VALUES (?, ?, ?, ?)",
                (incident_id, action, detail, time.time()),
            )

    def _refresh_message(self, incident_id: int):
        with self.lock:
            row = self.db.execute(
                "SELECT rule_id, account, client_ip, event_count, first_seen, last_seen, "
                "chat_id, message_id, status FROM incidents WHERE id=?",
                (incident_id,),
            ).fetchone()
            # Histori SEMUA aksi yang udah dilakukan di incident ini, bukan
            # cuma aksi terakhir - kalau gak gini, info penting kayak
            # "password baru: xxx" dari Reset bisa ketiban/ilang begitu
            # admin lanjut klik Lock sesudahnya (editMessageText replace
            # total, gak nambah).
            audit_rows = self.db.execute(
                "SELECT detail FROM audit_log WHERE incident_id=? AND detail IS NOT NULL ORDER BY id ASC",
                (incident_id,),
            ).fetchall()
        if row is None:
            return
        rule_id, account, client_ip, count, first_seen, last_seen, chat_id, message_id, status = row
        note = "\n".join(r[0] for r in audit_rows) if audit_rows else None
        text = self.incidents.format_message(
            incident_id, rule_id, account, client_ip, count,
            first_seen=first_seen, last_seen=last_seen, status=status, note=note,
        )
        keyboard = {"inline_keyboard": []} if status == "closed" else self.incidents.keyboard(incident_id, rule_id)
        self.tg.edit_message(chat_id, message_id, text, keyboard)

    # -- entrypoint -----------------------------------------------------

    def run(self):
        threads = [
            threading.Thread(target=self.tail_loop, name="tail", daemon=True),
            threading.Thread(target=self.queue_loop, name="queue", daemon=True),
            threading.Thread(target=self.telegram_loop, name="telegram", daemon=True),
        ]
        for t in threads:
            t.start()
        try:
            tick = 0
            while True:
                time.sleep(30)
                tick += 1
                dead = [t.name for t in threads if not t.is_alive()]
                if dead:
                    log.critical("THREAD MATI: %s - bot mungkin tidak berfungsi penuh", dead)

                # Watchdog: telegram_loop bisa hang diam-diam (DNS macet,
                # TCP half-open, dll) tanpa exception/log sama sekali - thread
                # masih "alive" tapi gak pernah poll. Kalau _last_poll_ts tidak
                # diupdate dalam 90 detik (jauh lebih dari siklus normal 30-50
                # detik), paksa os._exit(1) biar systemd restart seluruh proses.
                # 90 detik = long-poll 30s + timeout requests 50s + buffer 10s.
                poll_age = time.time() - self._last_poll_ts
                if poll_age > 90:
                    log.critical(
                        "WATCHDOG: telegram_loop tidak poll selama %.0fs - "
                        "kemungkinan hang di DNS/TCP. Force restart via os._exit.",
                        poll_age,
                    )
                    os._exit(1)

                if not dead and tick % 10 == 0:
                    log.info("heartbeat: semua thread jalan (%d menit)", tick // 2)
        except KeyboardInterrupt:
            log.info("stopping...")
            self._stop.set()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-c", "--config", default="config.yaml")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s [%(threadName)s] %(message)s",
    )

    MonitorBot(args.config).run()


if __name__ == "__main__":
    main()
