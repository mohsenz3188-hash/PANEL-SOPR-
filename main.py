import os
import io
import json
import time
import base64
import socket
import sqlite3
import secrets
import zipfile
import threading
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional
import psutil
import httpx
from fastapi import FastAPI, HTTPException, Request, UploadFile, File
from fastapi.responses import HTMLResponse, PlainTextResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

DATA_DIR = Path(os.environ.get("VPNSOPR_DATA", "./data"))
BACKUP_DIR = Path(os.environ.get("VPNSOPR_BACKUP", "./backups"))
FRONTEND_DIR = Path(os.environ.get("VPNSOPR_FRONTEND", "./frontend"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
BACKUP_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "vpnsopr.db"
CONFIG_PATH = DATA_DIR / "config.json"


def load_config() -> dict:
    default_cfg = {
        "panel_port": 2053,
        "web_base_path": "",
        "dns_port": 5353,
        "dns_upstream": "1.1.1.1",
        "admin_user": "admin",
        "admin_pass": "admin",
        "server_ip": "127.0.0.1",
        "domain": "",
        "ssl_enabled": False,
        "sub_base_url": "http://127.0.0.1:2053",
        "tg_bot_token": "",
        "tg_admin_id": "",
        "tg_enabled": False,
        "auto_backup_hours": 24,
    }
    if CONFIG_PATH.exists():
        saved = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        default_cfg.update(saved)
    else:
        CONFIG_PATH.write_text(json.dumps(default_cfg, indent=2), encoding="utf-8")
    return default_cfg


def save_config(cfg: dict):
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2, ensure_ascii=False), encoding="utf-8")


CFG = load_config()
DNS_STATS = {"total_queries": 0, "blocked_queries": 0, "rejected_unauth": 0}


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def gen_wg_keypair():
    try:
        priv = subprocess.check_output(["wg", "genkey"], stderr=subprocess.DEVNULL).decode().strip()
        pub = subprocess.check_output(["wg", "pubkey"], input=priv.encode(), stderr=subprocess.DEVNULL).decode().strip()
        return priv, pub
    except Exception:
        return secrets.token_urlsafe(32), secrets.token_urlsafe(32)


def add_audit_log(category: str, message: str):
    try:
        conn = get_db()
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn.execute("INSERT INTO audit_logs (created_at, category, message) VALUES (?, ?, ?)", (ts, category, message))
        conn.execute("DELETE FROM audit_logs WHERE id NOT IN (SELECT id FROM audit_logs ORDER BY id DESC LIMIT 200)")
        conn.commit()
        conn.close()
    except Exception:
        pass


def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.executescript(
        '''
        CREATE TABLE IF NOT EXISTS inbounds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            enabled INTEGER DEFAULT 1,
            remark TEXT NOT NULL,
            protocol TEXT NOT NULL,
            port INTEGER NOT NULL,
            endpoint TEXT NOT NULL,
            server_privkey TEXT,
            server_pubkey TEXT,
            awg_params TEXT
        );

        CREATE TABLE IF NOT EXISTS clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            inbound_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            enabled INTEGER DEFAULT 1,
            used_gb REAL DEFAULT 0,
            total_gb REAL DEFAULT 50,
            days INTEGER DEFAULT 30,
            expires_at INTEGER DEFAULT 0,
            token TEXT UNIQUE NOT NULL,
            allowed_ip TEXT,
            privkey TEXT,
            pubkey TEXT,
            registered_ip TEXT DEFAULT '',
            ip_limit INTEGER DEFAULT 1,
            notified_expired INTEGER DEFAULT 0,
            FOREIGN KEY(inbound_id) REFERENCES inbounds(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS blocked_domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pattern TEXT UNIQUE NOT NULL
        );

        CREATE TABLE IF NOT EXISTS custom_dns_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE NOT NULL,
            target_ip TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS block_categories (
            id TEXT PRIMARY KEY,
            label TEXT NOT NULL,
            enabled INTEGER DEFAULT 1,
            sample TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            category TEXT NOT NULL,
            message TEXT NOT NULL
        );
        '''
    )
    cols = [r[1] for r in cur.execute("PRAGMA table_info(clients)").fetchall()]
    if "enabled" not in cols:
        cur.execute("ALTER TABLE clients ADD COLUMN enabled INTEGER DEFAULT 1")
    if "expires_at" not in cols:
        cur.execute("ALTER TABLE clients ADD COLUMN expires_at INTEGER DEFAULT 0")
    if "notified_expired" not in cols:
        cur.execute("ALTER TABLE clients ADD COLUMN notified_expired INTEGER DEFAULT 0")
    if "ip_limit" not in cols:
        cur.execute("ALTER TABLE clients ADD COLUMN ip_limit INTEGER DEFAULT 1")

    count = cur.execute("SELECT COUNT(*) FROM inbounds").fetchone()[0]
    if count == 0:
        ip = CFG.get("server_ip", "127.0.0.1")
        exp_30 = int(time.time()) + 30 * 86400
        priv1, pub1 = gen_wg_keypair()
        priv2, pub2 = gen_wg_keypair()

        cur.execute(
            "INSERT INTO inbounds (enabled, remark, protocol, port, endpoint, server_privkey, server_pubkey, awg_params) VALUES (1, ?, 'WireGuard', 51820, ?, ?, ?, '')",
            ("SOPR-WG-Main", ip, priv1, pub1),
        )
        wg_id = cur.lastrowid
        c_priv, c_pub = gen_wg_keypair()
        cur.execute(
            "INSERT INTO clients (inbound_id, name, enabled, used_gb, total_gb, days, expires_at, token, allowed_ip, privkey, pubkey, ip_limit) VALUES (?, 'mohsen_pc', 1, 1.4, 100, 30, ?, ?, '10.66.66.2/32', ?, ?, 2)",
            (wg_id, exp_30, secrets.token_hex(6), c_priv, c_pub),
        )

        cur.execute(
            "INSERT INTO inbounds (enabled, remark, protocol, port, endpoint, server_privkey, server_pubkey, awg_params) VALUES (1, ?, 'AmneziaWG', 44320, ?, ?, ?, 'Jc=4|Jmin=40|Jmax=70|S1=32|S2=64')",
            ("SOPR-Amnezia-AntiDPI", ip, priv2, pub2),
        )
        awg_id = cur.lastrowid
        c2_priv, c2_pub = gen_wg_keypair()
        cur.execute(
            "INSERT INTO clients (inbound_id, name, enabled, used_gb, total_gb, days, expires_at, token, allowed_ip, privkey, pubkey, ip_limit) VALUES (?, 'mobile_awg', 1, 0.8, 80, 30, ?, ?, '10.77.77.2/32', ?, ?, 1)",
            (awg_id, exp_30, secrets.token_hex(6), c2_priv, c2_pub),
        )

        cur.execute(
            "INSERT INTO inbounds (enabled, remark, protocol, port, endpoint, server_privkey, server_pubkey, awg_params) VALUES (1, ?, 'OpenVPN', 1194, ?, '', '', '')",
            ("SOPR-OpenVPN-TCP", ip),
        )
        ovpn_id = cur.lastrowid
        cur.execute(
            "INSERT INTO clients (inbound_id, name, enabled, used_gb, total_gb, days, expires_at, token, allowed_ip, ip_limit) VALUES (?, 'laptop_ovpn', 1, 0.5, 60, 30, ?, ?, '10.8.0.2', 1)",
            (ovpn_id, exp_30, secrets.token_hex(6)),
        )

        cur.execute(
            "INSERT INTO inbounds (enabled, remark, protocol, port, endpoint, server_privkey, server_pubkey, awg_params) VALUES (1, ?, 'Private DNS', ?, ?, '', '', '')",
            ("SOPR-Gaming-DNS", CFG.get("dns_port", 5353), ip),
        )
        dns_id = cur.lastrowid
        cur.execute(
            "INSERT INTO clients (inbound_id, name, enabled, used_gb, total_gb, days, expires_at, token, registered_ip, ip_limit) VALUES (?, 'fc_mobile_dns', 1, 0.1, 500, 30, ?, ?, '', 1)",
            (dns_id, exp_30, secrets.token_hex(6)),
        )

        cats = [
            ("ads", "Ads & Trackers", 1, "doubleclick.net"),
            ("adult", "Adult Content", 1, "pornhub.com"),
            ("gambling", "Gambling & Betting", 1, "bet365.com"),
            ("malware", "Malware & Phishing", 1, "phish-login.xyz"),
            ("social", "Social Media", 0, "instagram.com"),
        ]
        cur.executemany("INSERT INTO block_categories (id, label, enabled, sample) VALUES (?, ?, ?, ?)", cats)
        cur.executemany(
            "INSERT INTO blocked_domains (pattern) VALUES (?)",
            [("*.ads-tracker.com",), ("doubleclick.net",), ("telemetry.microsoft.com",)],
        )
        cur.execute("INSERT INTO custom_dns_records (domain, target_ip) VALUES ('panel.vpnsopr.local', ?)", (ip,))

    conn.commit()
    conn.close()


init_db()
add_audit_log("SYSTEM", "VPN SOPR Pro v5.3 service initialized.")


# ==============================================================================
# TELEGRAM BOT & BACKUP HELPERS
# ==============================================================================
def tg_send_message(text: str, chat_id: Optional[str] = None):
    token = CFG.get("tg_bot_token", "").strip()
    target = (chat_id or CFG.get("tg_admin_id", "")).strip()
    if not token or not target:
        return False
    try:
        httpx.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": target, "text": text, "parse_mode": "HTML"},
            timeout=8.0,
        )
        return True
    except Exception:
        return False


def create_backup_archive() -> Path:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    zip_path = BACKUP_DIR / f"vpnsopr_backup_{ts}.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        if DB_PATH.exists():
            zf.write(DB_PATH, arcname="vpnsopr.db")
        if CONFIG_PATH.exists():
            zf.write(CONFIG_PATH, arcname="config.json")
    backups = sorted(BACKUP_DIR.glob("vpnsopr_backup_*.zip"), key=os.path.getmtime, reverse=True)
    for old in backups[20:]:
        old.unlink(missing_ok=True)
    return zip_path


def tg_send_backup(chat_id: Optional[str] = None) -> bool:
    token = CFG.get("tg_bot_token", "").strip()
    target = (chat_id or CFG.get("tg_admin_id", "")).strip()
    if not token or not target:
        return False
    try:
        bpath = create_backup_archive()
        with open(bpath, "rb") as f:
            res = httpx.post(
                f"https://api.telegram.org/bot{token}/sendDocument",
                data={"chat_id": target, "caption": f"📦 <b>VPN SOPR Pro Backup</b>\n🕒 {datetime.now().strftime('%Y-%m-%d %H:%M')}"},
                files={"document": (bpath.name, f, "application/zip")},
                timeout=20.0,
            )
        return res.status_code == 200
    except Exception:
        return False


def telegram_bot_worker():
    offset = 0
    while True:
        try:
            if not CFG.get("tg_enabled") or not CFG.get("tg_bot_token"):
                time.sleep(4)
                continue
            token = CFG["tg_bot_token"].strip()
            admin_id = str(CFG.get("tg_admin_id", "")).strip()
            resp = httpx.get(
                f"https://api.telegram.org/bot{token}/getUpdates",
                params={"offset": offset, "timeout": 20},
                timeout=25.0,
            )
            if resp.status_code != 200:
                time.sleep(5)
                continue
            for upd in resp.json().get("result", []):
                offset = upd["update_id"] + 1
                msg = upd.get("message") or {}
                text = (msg.get("text") or "").strip()
                chat_id = str((msg.get("chat") or {}).get("id", ""))
                if not text or not chat_id:
                    continue
                if admin_id and chat_id != admin_id:
                    tg_send_message("⛔ Unauthorized access to VPN SOPR Bot.", chat_id)
                    continue

                if text.startswith("/start") or text.startswith("/help"):
                    tg_send_message(
                        "🛡️ <b>VPN SOPR Pro Management Bot</b>\n\n"
                        "/stats — Server CPU, RAM, Disk & DNS Metrics\n"
                        "/clients — Active Clients Quota & Expiry Status\n"
                        "/backup — Generate & Download Database Backup\n"
                        "/info — Show Web Panel URL & Login Info\n"
                        "/id — Show Your Telegram Chat ID",
                        chat_id,
                    )
                elif text.startswith("/id"):
                    tg_send_message(f"🆔 Your Chat ID: <code>{chat_id}</code>", chat_id)
                elif text.startswith("/info"):
                    wpath = CFG.get("web_base_path", "")
                    base = CFG.get("sub_base_url", f"http://{CFG.get('server_ip')}:{CFG.get('panel_port')}")
                    tg_send_message(
                        f"🔐 <b>VPN SOPR Panel Access</b>\n"
                        f"• URL: <code>{base}{wpath}/</code>\n"
                        f"• User: <code>{CFG.get('admin_user')}</code>\n"
                        f"• Pass: <code>{CFG.get('admin_pass')}</code>",
                        chat_id,
                    )
                elif text.startswith("/stats"):
                    mem = psutil.virtual_memory()
                    disk = psutil.disk_usage("/")
                    cpu = psutil.cpu_percent(interval=0.2)
                    tg_send_message(
                        f"📊 <b>VPN SOPR Server Telemetry</b>\n"
                        f"• CPU: <code>{cpu}%</code>\n"
                        f"• RAM: <code>{round(mem.used/(1024**3),2)} / {round(mem.total/(1024**3),2)} GB ({mem.percent}%)</code>\n"
                        f"• Disk: <code>{round(disk.used/(1024**3),1)} / {round(disk.total/(1024**3),1)} GB</code>\n"
                        f"• DNS Queries: <code>{DNS_STATS['total_queries']}</code> (Blocked: <code>{DNS_STATS['blocked_queries']}</code>)",
                        chat_id,
                    )
                elif text.startswith("/clients"):
                    conn = get_db()
                    rows = conn.execute(
                        "SELECT c.*, i.protocol FROM clients c JOIN inbounds i ON c.inbound_id = i.id ORDER BY c.id DESC LIMIT 25"
                    ).fetchall()
                    conn.close()
                    if not rows:
                        tg_send_message("No clients found.", chat_id)
                    else:
                        lines = ["👥 <b>Client Accounts:</b>\n"]
                        now_ts = int(time.time())
                        for r in rows:
                            rem_days = max(0, round((r["expires_at"] - now_ts) / 86400)) if r["expires_at"] else r["days"]
                            st = "✅" if r["enabled"] else "⛔"
                            lines.append(f"{st} <b>{r['name']}</b> ({r['protocol']}) — {r['used_gb']}/{r['total_gb']} GB | {rem_days}d left")
                        tg_send_message("\n".join(lines), chat_id)
                elif text.startswith("/backup"):
                    tg_send_message("⏳ Generating backup archive...", chat_id)
                    tg_send_backup(chat_id)
        except Exception:
            time.sleep(5)


threading.Thread(target=telegram_bot_worker, daemon=True).start()


# ==============================================================================
# QUOTA & EXPIRATION ENFORCER + AUTO BACKUP SCHEDULER
# ==============================================================================
def quota_and_backup_scheduler():
    last_auto_backup = time.time()
    while True:
        try:
            now_ts = int(time.time())
            conn = get_db()
            clients = conn.execute("SELECT * FROM clients WHERE enabled = 1").fetchall()
            for c in clients:
                expired_time = c["expires_at"] and c["expires_at"] > 0 and now_ts >= c["expires_at"]
                expired_quota = c["total_gb"] > 0 and c["used_gb"] >= c["total_gb"]
                if expired_time or expired_quota:
                    reason = "Time Expired" if expired_time else "Traffic Quota Reached"
                    conn.execute("UPDATE clients SET enabled = 0, notified_expired = 1 WHERE id = ?", (c["id"],))
                    add_audit_log("QUOTA", f"Client {c['name']} auto-disabled ({reason}).")
                    if CFG.get("tg_enabled"):
                        tg_send_message(f"⚠️ <b>Account Expired</b>\nUser <code>{c['name']}</code> has been disabled due to <b>{reason}</b>.")
            conn.commit()
            conn.close()

            hours = int(CFG.get("auto_backup_hours", 24))
            if hours > 0 and (time.time() - last_auto_backup) >= hours * 3600:
                last_auto_backup = time.time()
                if CFG.get("tg_enabled"):
                    tg_send_backup()
                else:
                    create_backup_archive()
                add_audit_log("BACKUP", "Scheduled automatic backup created.")
        except Exception:
            pass
        time.sleep(30)


threading.Thread(target=quota_and_backup_scheduler, daemon=True).start()


# ==============================================================================
# EMBEDDED IP-AUTHENTICATED DNS SINKHOLE & CUSTOM RECORDS SERVER (UDP)
# ==============================================================================
def parse_dns_qname(data: bytes) -> str:
    idx = 12
    labels = []
    while idx < len(data):
        length = data[idx]
        if length == 0:
            break
        idx += 1
        labels.append(data[idx : idx + length].decode("utf-8", errors="ignore"))
        idx += length
    return ".".join(labels).lower()


def get_custom_dns_ip(domain: str) -> Optional[str]:
    conn = get_db()
    row = conn.execute("SELECT target_ip FROM custom_dns_records WHERE domain = ?", (domain,)).fetchone()
    conn.close()
    return row["target_ip"] if row else None


def is_domain_blocked_db(domain: str) -> bool:
    conn = get_db()
    patterns = [r["pattern"].lower() for r in conn.execute("SELECT pattern FROM blocked_domains").fetchall()]
    cats = conn.execute("SELECT sample FROM block_categories WHERE enabled = 1").fetchall()
    conn.close()
    for p in patterns:
        if p.startswith("*."):
            suf = p[2:]
            if domain == suf or domain.endswith("." + suf):
                return True
        elif domain == p:
            return True
    for c in cats:
        s = c["sample"].lower()
        if domain == s or domain.endswith("." + s):
            return True
    return False


def is_ip_authorized_db(client_ip: str) -> bool:
    now_ts = int(time.time())
    conn = get_db()
    row = conn.execute(
        '''
        SELECT c.* FROM clients c
        JOIN inbounds i ON c.inbound_id = i.id
        WHERE i.protocol = 'Private DNS'
          AND i.enabled = 1
          AND c.enabled = 1
          AND c.registered_ip = ?
          AND (c.expires_at = 0 OR c.expires_at > ?)
          AND (c.total_gb <= 0 OR c.used_gb < c.total_gb)
        ''',
        (client_ip, now_ts),
    ).fetchone()
    if row:
        conn.execute("UPDATE clients SET used_gb = ROUND(used_gb + 0.000002, 6) WHERE id = ?", (row["id"],))
        conn.commit()
    conn.close()
    return row is not None


def build_dns_refused(query: bytes, rcode: int = 5) -> bytes:
    txid = query[:2]
    flags = (0x8180 | (rcode & 0x0F)).to_bytes(2, "big")
    qdcount = query[4:6]
    header = txid + flags + qdcount + b"\x00\x00\x00\x00\x00\x00"
    return header + query[12:]


def build_dns_a_response(query: bytes, ip_str: str) -> bytes:
    txid = query[:2]
    flags = (0x8180).to_bytes(2, "big")
    qdcount = query[4:6]
    ancount = (1).to_bytes(2, "big")
    header = txid + flags + qdcount + ancount + b"\x00\x00\x00\x00"
    question = query[12:]
    answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + socket.inet_aton(ip_str)
    return header + question + answer


def start_dns_udp_server():
    dns_port = int(CFG.get("dns_port", 5353))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("0.0.0.0", dns_port))
    except Exception as e:
        print(f"[DNS] Could not bind UDP port {dns_port}: {e}")
        return

    print(f"[DNS] VPN SOPR IP-Auth DNS Server listening on 0.0.0.0:{dns_port}")
    while True:
        try:
            data, addr = sock.recvfrom(2048)
            DNS_STATS["total_queries"] += 1
            client_ip = addr[0]
            qname = parse_dns_qname(data)
            if not is_ip_authorized_db(client_ip):
                DNS_STATS["rejected_unauth"] += 1
                sock.sendto(build_dns_refused(data, rcode=5), addr)
                continue
            if is_domain_blocked_db(qname):
                DNS_STATS["blocked_queries"] += 1
                sock.sendto(build_dns_refused(data, rcode=3), addr)
                continue
            custom_ip = get_custom_dns_ip(qname)
            if custom_ip:
                sock.sendto(build_dns_a_response(data, custom_ip), addr)
                continue
            upstream = CFG.get("dns_upstream", "1.1.1.1").strip() or "1.1.1.1"
            up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            up.settimeout(3.0)
            up.sendto(data, (upstream, 53))
            resp, _ = up.recvfrom(2048)
            up.close()
            sock.sendto(resp, addr)
        except Exception:
            pass


threading.Thread(target=start_dns_udp_server, daemon=True).start()


# ==============================================================================
# FASTAPI APP & SECRET WEB BASE PATH ROUTING (x-ui style)
# ==============================================================================
app = FastAPI(title="VPN SOPR Pro v5.3")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class LoginReq(BaseModel):
    username: str
    password: str


class InboundCreate(BaseModel):
    remark: str
    protocol: str
    port: int
    endpoint: str
    awg_params: Optional[str] = ""


class ClientCreate(BaseModel):
    name: str
    total_gb: float = 50
    days: int = 30
    ip_limit: int = 1
    registered_ip: Optional[str] = ""


class BulkClientCreate(BaseModel):
    prefix: str
    count: int = 5
    total_gb: float = 50
    days: int = 30
    ip_limit: int = 1


class ClientUpdate(BaseModel):
    name: str
    total_gb: float
    used_gb: float
    days: int
    ip_limit: int = 1
    enabled: bool = True
    registered_ip: Optional[str] = ""


class IpUpdateReq(BaseModel):
    ip: str


class DomainReq(BaseModel):
    pattern: str


class CustomRecordReq(BaseModel):
    domain: str
    target_ip: str


class SettingsUpdate(BaseModel):
    admin_user: str
    admin_pass: str
    web_base_path: Optional[str] = ""
    dns_upstream: Optional[str] = "1.1.1.1"
    domain: Optional[str] = ""
    sub_base_url: Optional[str] = ""
    tg_bot_token: Optional[str] = ""
    tg_admin_id: Optional[str] = ""
    tg_enabled: bool = False
    auto_backup_hours: int = 24


def render_panel_html() -> str:
    idx = FRONTEND_DIR / "index.html"
    if idx.exists():
        return idx.read_text(encoding="utf-8")
    return "<h1>VPN SOPR Pro v5.3 Active</h1>"


@app.get("/", response_class=HTMLResponse)
def serve_root():
    wpath = CFG.get("web_base_path", "").strip()
    if wpath and wpath != "/":
        return HTMLResponse("<h3>404 Not Found</h3>", status_code=404)
    return HTMLResponse(render_panel_html())


@app.get("/{secret_path}", response_class=HTMLResponse)
@app.get("/{secret_path}/", response_class=HTMLResponse)
def serve_secret_path(secret_path: str):
    wpath = CFG.get("web_base_path", "").strip().lstrip("/")
    if not wpath or secret_path != wpath:
        raise HTTPException(status_code=404, detail="Not Found")
    return HTMLResponse(render_panel_html())


@app.post("/api/login")
def api_login(body: LoginReq):
    if body.username == CFG["admin_user"] and body.password == CFG["admin_pass"]:
        return {"ok": True, "token": secrets.token_urlsafe(24)}
    raise HTTPException(status_code=401, detail="Invalid credentials")


@app.get("/api/stats")
def api_stats():
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    net = psutil.net_io_counters()
    return {
        "cpu_percent": psutil.cpu_percent(interval=0.1),
        "cpu_cores": psutil.cpu_count() or 1,
        "ram_used_gb": round(mem.used / (1024**3), 2),
        "ram_total_gb": round(mem.total / (1024**3), 2),
        "ram_percent": mem.percent,
        "disk_used_gb": round(disk.used / (1024**3), 1),
        "disk_total_gb": round(disk.total / (1024**3), 1),
        "disk_percent": disk.percent,
        "net_sent_gb": round(net.bytes_sent / (1024**3), 2),
        "net_recv_gb": round(net.bytes_recv / (1024**3), 2),
        "server_ip": CFG.get("server_ip", "127.0.0.1"),
        "panel_port": CFG.get("panel_port", 2053),
        "dns_port": CFG.get("dns_port", 5353),
        "dns_stats": DNS_STATS,
    }


@app.get("/api/state")
def api_get_state():
    now_ts = int(time.time())
    conn = get_db()
    inbs = [dict(r) for r in conn.execute("SELECT * FROM inbounds").fetchall()]
    for inb in inbs:
        inb["enabled"] = bool(inb["enabled"])
        cls = [dict(c) for c in conn.execute("SELECT * FROM clients WHERE inbound_id = ?", (inb["id"],)).fetchall()]
        for c in cls:
            c["enabled"] = bool(c["enabled"])
            c["remaining_days"] = max(0, round((c["expires_at"] - now_ts) / 86400, 1)) if (c["expires_at"] and c["expires_at"] > 0) else c["days"]
        inb["clients"] = cls
    cats = [dict(c) for c in conn.execute("SELECT * FROM block_categories").fetchall()]
    for c in cats:
        c["enabled"] = bool(c["enabled"])
    doms = [r["pattern"] for r in conn.execute("SELECT pattern FROM blocked_domains").fetchall()]
    custom_recs = [dict(r) for r in conn.execute("SELECT * FROM custom_dns_records").fetchall()]
    logs = [dict(l) for l in conn.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 40").fetchall()]
    conn.close()
    return {
        "inbounds": inbs,
        "blockCategories": cats,
        "blockedDomains": doms,
        "customRecords": custom_recs,
        "logs": logs,
        "config": CFG,
    }


@app.post("/api/inbounds")
def api_create_inbound(body: InboundCreate):
    priv, pub = gen_wg_keypair() if body.protocol in ("WireGuard", "AmneziaWG") else ("", "")
    conn = get_db()
    conn.execute(
        "INSERT INTO inbounds (enabled, remark, protocol, port, endpoint, server_privkey, server_pubkey, awg_params) VALUES (1, ?, ?, ?, ?, ?, ?, ?)",
        (body.remark, body.protocol, body.port, body.endpoint, priv, pub, body.awg_params or ""),
    )
    conn.commit()
    conn.close()
    add_audit_log("INBOUND", f"Inbound '{body.remark}' ({body.protocol}) created.")
    return {"ok": True}


@app.post("/api/inbounds/{inb_id}/toggle")
def api_toggle_inbound(inb_id: int):
    conn = get_db()
    conn.execute("UPDATE inbounds SET enabled = 1 - enabled WHERE id = ?", (inb_id,))
    conn.commit()
    conn.close()
    return {"ok": True}


@app.delete("/api/inbounds/{inb_id}")
def api_delete_inbound(inb_id: int):
    conn = get_db()
    conn.execute("DELETE FROM clients WHERE inbound_id = ?", (inb_id,))
    conn.execute("DELETE FROM inbounds WHERE id = ?", (inb_id,))
    conn.commit()
    conn.close()
    add_audit_log("INBOUND", f"Inbound #{inb_id} deleted.")
    return {"ok": True}


@app.post("/api/inbounds/{inb_id}/clients")
def api_create_client(inb_id: int, body: ClientCreate):
    conn = get_db()
    inb = conn.execute("SELECT * FROM inbounds WHERE id = ?", (inb_id,)).fetchone()
    if not inb:
        conn.close()
        raise HTTPException(status_code=404, detail="Inbound not found")
    cnt = conn.execute("SELECT COUNT(*) FROM clients WHERE inbound_id = ?", (inb_id,)).fetchone()[0]
    c_priv, c_pub = gen_wg_keypair() if inb["protocol"] in ("WireGuard", "AmneziaWG") else ("", "")
    allowed_ip = f"10.66.{inb_id}.{cnt + 2}/32"
    token = secrets.token_hex(6)
    expires_at = int(time.time()) + int(body.days) * 86400 if body.days > 0 else 0
    conn.execute(
        "INSERT INTO clients (inbound_id, name, enabled, used_gb, total_gb, days, expires_at, token, allowed_ip, privkey, pubkey, registered_ip, ip_limit) VALUES (?, ?, 1, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (inb_id, body.name, body.total_gb, body.days, expires_at, token, allowed_ip, c_priv, c_pub, (body.registered_ip or "").strip(), body.ip_limit),
    )
    conn.commit()
    conn.close()
    add_audit_log("CLIENT", f"Client '{body.name}' ({body.total_gb}GB / {body.days}d) created.")
    if CFG.get("tg_enabled"):
        tg_send_message(f"➕ <b>New Client Created</b>\n• Name: <code>{body.name}</code>\n• Protocol: {inb['protocol']}\n• Quota: {body.total_gb} GB | Duration: {body.days}d")
    return {"ok": True, "token": token}


@app.post("/api/inbounds/{inb_id}/clients/bulk")
def api_bulk_create_clients(inb_id: int, body: BulkClientCreate):
    conn = get_db()
    inb = conn.execute("SELECT * FROM inbounds WHERE id = ?", (inb_id,)).fetchone()
    if not inb:
        conn.close()
        raise HTTPException(status_code=404, detail="Inbound not found")
    cnt = conn.execute("SELECT COUNT(*) FROM clients WHERE inbound_id = ?", (inb_id,)).fetchone()[0]
    expires_at = int(time.time()) + int(body.days) * 86400 if body.days > 0 else 0
    count = max(1, min(100, int(body.count)))
    for i in range(1, count + 1):
        c_priv, c_pub = gen_wg_keypair() if inb["protocol"] in ("WireGuard", "AmneziaWG") else ("", "")
        allowed_ip = f"10.66.{inb_id}.{cnt + i + 1}/32"
        token = secrets.token_hex(6)
        cname = f"{body.prefix}_{i:02d}"
        conn.execute(
            "INSERT INTO clients (inbound_id, name, enabled, used_gb, total_gb, days, expires_at, token, allowed_ip, privkey, pubkey, registered_ip, ip_limit) VALUES (?, ?, 1, 0, ?, ?, ?, ?, ?, ?, ?, '', ?)",
            (inb_id, cname, body.total_gb, body.days, expires_at, token, allowed_ip, c_priv, c_pub, body.ip_limit),
        )
    conn.commit()
    conn.close()
    add_audit_log("CLIENT", f"Bulk created {count} clients with prefix '{body.prefix}'.")
    return {"ok": True}


@app.put("/api/clients/{client_id}")
def api_update_client(client_id: int, body: ClientUpdate):
    expires_at = int(time.time()) + int(body.days) * 86400 if body.days > 0 else 0
    conn = get_db()
    conn.execute(
        "UPDATE clients SET name = ?, total_gb = ?, used_gb = ?, days = ?, expires_at = ?, ip_limit = ?, enabled = ?, registered_ip = ? WHERE id = ?",
        (body.name.strip(), body.total_gb, body.used_gb, body.days, expires_at, body.ip_limit, 1 if body.enabled else 0, (body.registered_ip or "").strip(), client_id),
    )
    conn.commit()
    conn.close()
    add_audit_log("CLIENT", f"Client '{body.name}' quota/time updated.")
    return {"ok": True}


@app.post("/api/clients/{client_id}/reset")
def api_reset_client(client_id: int):
    conn = get_db()
    row = conn.execute("SELECT * FROM clients WHERE id = ?", (client_id,)).fetchone()
    if row:
        new_exp = int(time.time()) + int(row["days"]) * 86400 if row["days"] > 0 else 0
        conn.execute("UPDATE clients SET used_gb = 0, expires_at = ?, enabled = 1, notified_expired = 0 WHERE id = ?", (new_exp, client_id))
        conn.commit()
        add_audit_log("CLIENT", f"Client '{row['name']}' renewed & reset.")
    conn.close()
    return {"ok": True}


@app.delete("/api/clients/{client_id}")
def api_delete_client(client_id: int):
    conn = get_db()
    conn.execute("DELETE FROM clients WHERE id = ?", (client_id,))
    conn.commit()
    conn.close()
    return {"ok": True}


@app.post("/api/clients/{client_id}/ip")
def api_update_client_ip(client_id: int, body: IpUpdateReq):
    conn = get_db()
    conn.execute("UPDATE clients SET registered_ip = ? WHERE id = ?", (body.ip.strip(), client_id))
    conn.commit()
    conn.close()
    return {"ok": True}


@app.post("/api/dns/categories/{cat_id}/toggle")
def api_toggle_cat(cat_id: str):
    conn = get_db()
    conn.execute("UPDATE block_categories SET enabled = 1 - enabled WHERE id = ?", (cat_id,))
    conn.commit()
    conn.close()
    return {"ok": True}


@app.post("/api/dns/domains")
def api_add_domain(body: DomainReq):
    pat = body.pattern.strip().lower()
    if pat:
        conn = get_db()
        conn.execute("INSERT OR IGNORE INTO blocked_domains (pattern) VALUES (?)", (pat,))
        conn.commit()
        conn.close()
    return {"ok": True}


@app.delete("/api/dns/domains")
def api_del_domain(pattern: str):
    conn = get_db()
    conn.execute("DELETE FROM blocked_domains WHERE pattern = ?", (pattern,))
    conn.commit()
    conn.close()
    return {"ok": True}


@app.post("/api/dns/records")
def api_add_custom_record(body: CustomRecordReq):
    dom = body.domain.strip().lower()
    ip = body.target_ip.strip()
    if dom and ip:
        conn = get_db()
        conn.execute("INSERT OR REPLACE INTO custom_dns_records (domain, target_ip) VALUES (?, ?)", (dom, ip))
        conn.commit()
        conn.close()
    return {"ok": True}


@app.delete("/api/dns/records/{rec_id}")
def api_del_custom_record(rec_id: int):
    conn = get_db()
    conn.execute("DELETE FROM custom_dns_records WHERE id = ?", (rec_id,))
    conn.commit()
    conn.close()
    return {"ok": True}


# ==============================================================================
# SETTINGS, TELEGRAM, DOMAIN/SSL & BACKUP/RESTORE
# ==============================================================================
@app.post("/api/settings")
def api_save_settings(body: SettingsUpdate):
    CFG["admin_user"] = body.admin_user.strip() or "admin"
    CFG["admin_pass"] = body.admin_pass.strip() or "admin"
    wp = (body.web_base_path or "").strip()
    if wp and not wp.startswith("/"):
        wp = "/" + wp
    CFG["web_base_path"] = wp.rstrip("/")
    CFG["dns_upstream"] = (body.dns_upstream or "1.1.1.1").strip()
    CFG["domain"] = (body.domain or "").strip()
    if body.sub_base_url and body.sub_base_url.strip():
        CFG["sub_base_url"] = body.sub_base_url.strip().rstrip("/")
    elif CFG["domain"]:
        CFG["sub_base_url"] = f"https://{CFG['domain']}"
    CFG["tg_bot_token"] = (body.tg_bot_token or "").strip()
    CFG["tg_admin_id"] = (body.tg_admin_id or "").strip()
    CFG["tg_enabled"] = body.tg_enabled
    CFG["auto_backup_hours"] = max(1, int(body.auto_backup_hours))
    save_config(CFG)
    add_audit_log("SETTINGS", "System, Web Path, Domain & Telegram settings saved.")
    return {"ok": True, "config": CFG}


@app.post("/api/telegram/test")
def api_test_telegram():
    ok = tg_send_message("✅ <b>VPN SOPR Pro v5.3</b> Telegram Bot connection verified!")
    if not ok:
        raise HTTPException(status_code=400, detail="Failed to send test message. Check Bot Token and Admin Chat ID.")
    return {"ok": True}


@app.post("/api/domain/apply-ssl")
def api_apply_domain_ssl():
    domain = CFG.get("domain", "").strip()
    if not domain:
        raise HTTPException(status_code=400, detail="Please enter and save a domain name first.")
    try:
        subprocess.Popen(["/usr/local/bin/vpnsopr", "ssl", domain])
        add_audit_log("SSL", f"SSL certificate provisioning triggered for {domain}.")
        return {"ok": True, "message": f"SSL provisioning started for {domain}."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/backup/download")
def api_download_backup():
    zpath = create_backup_archive()
    add_audit_log("BACKUP", f"Downloaded backup archive {zpath.name}.")
    return FileResponse(path=zpath, filename=zpath.name, media_type="application/zip")


@app.post("/api/backup/telegram")
def api_send_backup_telegram():
    if not tg_send_backup():
        raise HTTPException(status_code=400, detail="Failed to send backup to Telegram.")
    add_audit_log("BACKUP", "Database backup sent to Telegram.")
    return {"ok": True}


@app.post("/api/backup/restore")
async def api_restore_backup(file: UploadFile = File(...)):
    content = await file.read()
    try:
        with zipfile.ZipFile(io.BytesIO(content), "r") as zf:
            names = zf.namelist()
            if "vpnsopr.db" not in names:
                raise HTTPException(status_code=400, detail="Invalid backup archive (vpnsopr.db missing).")
            zf.extract("vpnsopr.db", path=DATA_DIR)
            if "config.json" in names:
                zf.extract("config.json", path=DATA_DIR)
                global CFG
                CFG = load_config()
        add_audit_log("BACKUP", "Database restored from uploaded archive.")
        return {"ok": True}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Restore error: {e}")


# ==============================================================================
# SUBSCRIPTION PORTAL, RAW & BASE64 ENDPOINTS
# ==============================================================================
def render_client_config(inb: dict, client: dict) -> str:
    proto = inb["protocol"]
    if proto == "WireGuard":
        return f"""[Interface]
PrivateKey = {client['privkey']}
Address = {client['allowed_ip']}
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = {inb['server_pubkey']}
Endpoint = {inb['endpoint']}:{inb['port']}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25"""
    if proto == "AmneziaWG":
        return f"""[Interface]
PrivateKey = {client['privkey']}
Address = {client['allowed_ip']}
DNS = 1.1.1.1
Jc = 4
Jmin = 40
Jmax = 70
S1 = 32
S2 = 64
H1 = 102938475
H2 = 564738291
H3 = 918273645
H4 = 192837465

[Peer]
PublicKey = {inb['server_pubkey']}
Endpoint = {inb['endpoint']}:{inb['port']}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 20"""
    if proto == "OpenVPN":
        return f"""client
dev tun
proto tcp
remote {inb['endpoint']} {inb['port']}
resolv-retry infinite
nobind
persist-key
persist-tun
cipher AES-256-GCM
auth SHA256
verb 3
# VPN SOPR Client Token: {client['token']}"""
    status = (
        f"ACTIVE (Authorized IP: {client['registered_ip']})"
        if client["registered_ip"]
        else "BLOCKED (Register your IP on this subscription page to connect)"
    )
    return f"""# VPN SOPR Private DNS ({client['name']})
# Status: {status}
DNS Server IP : {inb['endpoint']}
DNS Port      : {inb['port']}
Client Token  : {client['token']}"""


@app.get("/sub/{proto}/{token}", response_class=HTMLResponse)
def customer_sub_portal(proto: str, token: str, request: Request):
    conn = get_db()
    row = conn.execute(
        "SELECT c.*, i.remark, i.protocol, i.port, i.endpoint, i.server_pubkey FROM clients c JOIN inbounds i ON c.inbound_id = i.id WHERE c.token = ?",
        (token,),
    ).fetchone()
    conn.close()
    if not row:
        return HTMLResponse("<h2>Subscription Not Found</h2>", status_code=404)
    data = dict(row)
    now_ts = int(time.time())
    rem_days = max(0, round((data["expires_at"] - now_ts) / 86400, 1)) if data["expires_at"] else data["days"]
    rem_gb = max(0, round(data["total_gb"] - data["used_gb"], 2))
    active_badge = "<span style='color:#52c41a'>Active</span>" if data["enabled"] else "<span style='color:#ff4d4f'>Disabled / Expired</span>"

    cfg_text = render_client_config(data, data)
    forwarded = request.headers.get("x-forwarded-for", "")
    visitor_ip = forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else "")
    is_dns = data["protocol"] == "Private DNS"
    ip_section = ""
    if is_dns:
        ip_section = f'''
        <div style="background:#2a2112;border:1px solid #faad14;padding:16px;border-radius:10px;margin:16px 0;">
          <div style="color:#faad14;font-weight:bold;margin-bottom:6px;">Mandatory IP Authentication for Private DNS</div>
          <div style="font-size:13px;margin-bottom:10px;">
            Registered IP: <b>{data['registered_ip'] or 'None (Blocked)'}</b> | Your Current IP: <code>{visitor_ip}</code>
          </div>
          <form method="post" action="/sub/{proto}/{token}/register-ip" style="display:flex;gap:8px;flex-wrap:wrap;">
            <input name="ip" value="{visitor_ip or data['registered_ip']}" placeholder="Enter your IPv4 address" style="flex:1;padding:9px;border-radius:6px;background:#141414;color:#fff;border:1px solid #444;" />
            <button type="submit" style="padding:9px 16px;border-radius:6px;background:#52c41a;color:#fff;border:none;font-weight:bold;cursor:pointer;">Register Current IP</button>
          </form>
        </div>
        '''
    return f'''<!DOCTYPE html>
<html lang="en" dir="ltr">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>VPN SOPR | {data['name']}</title></head>
<body style="background:#141414;color:#eee;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;padding:20px;max-width:680px;margin:auto;">
  <div style="background:#1f1f1f;border:1px solid #303030;border-radius:12px;padding:24px;">
    <h2 style="margin-top:0;color:#1677ff;">VPN SOPR — Client Subscription Portal</h2>
    <p style="font-size:14px;line-height:1.7;">
      Account: <b>{data['name']}</b> &bull; Status: <b>{active_badge}</b> &bull; Protocol: <b>{data['protocol']}</b><br/>
      Remaining Traffic: <b>{rem_gb} GB</b> / {data['total_gb']} GB &bull; Remaining Time: <b>{rem_days} Days</b>
    </p>
    {ip_section}
    <pre style="background:#111;color:#52c41a;padding:14px;border-radius:8px;overflow-x:auto;font-size:12px;">{cfg_text}</pre>
    <div style="display:flex;gap:10px;margin-top:12px;">
      <a href="/sub/{proto}/{token}/raw" style="padding:10px 16px;background:#1677ff;color:#fff;text-decoration:none;border-radius:8px;font-size:13px;font-weight:600;">Download Config File</a>
      <a href="/sub/{proto}/{token}/b64" style="padding:10px 16px;background:#303030;color:#fff;text-decoration:none;border-radius:8px;font-size:13px;">Raw Base64</a>
    </div>
  </div>
</body></html>'''


@app.post("/sub/{proto}/{token}/register-ip")
async def customer_register_ip_form(proto: str, token: str, request: Request):
    form = await request.form()
    ip_val = str(form.get("ip", "")).strip()
    conn = get_db()
    conn.execute("UPDATE clients SET registered_ip = ? WHERE token = ?", (ip_val, token))
    conn.commit()
    conn.close()
    return HTMLResponse(f'<script>window.location.href="/sub/{proto}/{token}";</script>')


@app.get("/sub/{proto}/{token}/raw", response_class=PlainTextResponse)
def customer_sub_raw(proto: str, token: str):
    conn = get_db()
    row = conn.execute(
        "SELECT c.*, i.remark, i.protocol, i.port, i.endpoint, i.server_pubkey FROM clients c JOIN inbounds i ON c.inbound_id = i.id WHERE c.token = ?",
        (token,),
    ).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Not found")
    data = dict(row)
    return render_client_config(data, data)


@app.get("/sub/{proto}/{token}/b64", response_class=PlainTextResponse)
def customer_sub_b64(proto: str, token: str):
    raw = customer_sub_raw(proto, token)
    return base64.b64encode(raw.encode("utf-8")).decode("utf-8")
