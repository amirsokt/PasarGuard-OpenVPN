#!/usr/bin/env bash
# =============================================================================
# OpenVPN for PasarGuard v2 — installer + user sync + dashboard
#
# What it does:
#   1. Installs OpenVPN and builds a small PKI (EC certs + tls-crypt key)
#   2. Authenticates clients with username/password (per-user derived password)
#   3. Runs the pg-ovpn daemon which:
#        - syncs users from the PasarGuard API (create / disable / delete / renew)
#        - enforces expiry, quota (panel usage + OpenVPN usage) and group access
#        - tracks online sessions, IPs, connect/disconnect history
#        - limits simultaneous connections per account (kicks the extras)
#        - serves per-user .ovpn download page + QR code + admin dashboard
#
# Usage (as root):
#   PANEL_URL=https://panel.example.com:8000 \
#   PANEL_USER=admin PANEL_PASS='secret' \
#   bash install_openvpn_pasarguard.sh
#
# Upgrading from v1: just run this script again (same PANEL_* values are
# remembered from /etc/pg-openvpn/sync.json). Existing .ovpn profiles keep working.
#
# Optional env:
#   PANEL_API_KEY, PANEL_INSECURE=1, OVPN_PORT=1194, OVPN_PROTO=udp|tcp,
#   OVPN_SUBNET=10.8.0.0, DNS1, DNS2, PUBLIC_HOST, SYNC_INTERVAL=30
#   MAX_CONN=2            default simultaneous connections per user (0 = unlimited)
#   LIMIT_POLICY=kick-oldest|kick-newest
#   OVPN_GROUPS="OpenVPN" panel group name(s)/id(s) allowed to use OpenVPN (empty = all)
#   WEB_PORT=8088 WEB_BIND=0.0.0.0 WEB_TLS_CERT=/path/fullchain.pem WEB_TLS_KEY=/path/key.pem
#   WEB_BASE_URL=https://vpn.example.com:8088   (public URL used in QR/links)
#   TICK=5 HISTORY_DAYS=90
# =============================================================================
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "Please run as root."; exit 1; }

BASE=/etc/pg-openvpn
VARDIR=/var/lib/pg-openvpn
PKI=$BASE/pki

# remember values from a previous install (v1 or v2) so upgrades are one command
if [ -f "$BASE/sync.json" ] && command -v python3 >/dev/null 2>&1; then
  eval "$(python3 - <<'PYEOF'
import json, shlex
try:
    c = json.load(open("/etc/pg-openvpn/sync.json"))
except Exception:
    c = {}
m = {"PANEL_URL": "panel_url", "PANEL_USER": "panel_user", "PANEL_PASS": "panel_pass",
     "PANEL_API_KEY": "api_key", "OVPN_PORT": "port", "OVPN_PROTO": "proto",
     "PUBLIC_HOST": "host", "SYNC_INTERVAL": "interval", "MAX_CONN": "max_conn",
     "LIMIT_POLICY": "limit_policy", "WEB_PORT": "web_port", "WEB_BIND": "web_bind",
     "WEB_TLS_CERT": "web_tls_cert", "WEB_TLS_KEY": "web_tls_key",
     "WEB_BASE_URL": "web_base_url", "TICK": "tick", "HISTORY_DAYS": "history_days"}
for env, key in m.items():
    v = c.get(key)
    if v not in (None, ""):
        print("export OLD_%s=%s" % (env, shlex.quote(str(v))))
if c.get("insecure"):
    print("export OLD_PANEL_INSECURE=1")
if c.get("groups"):
    print("export OLD_OVPN_GROUPS=%s" % shlex.quote(",".join(map(str, c["groups"]))))
PYEOF
)"
fi
pick() { local n=$1 d=$2 o="OLD_$1"; eval "echo \"\${$n:-\${$o:-$d}}\""; }

PANEL_URL="$(pick PANEL_URL '')"
PANEL_USER="$(pick PANEL_USER '')"
PANEL_PASS="$(pick PANEL_PASS '')"
PANEL_API_KEY="$(pick PANEL_API_KEY '')"
PANEL_INSECURE="$(pick PANEL_INSECURE 0)"
OVPN_PORT="$(pick OVPN_PORT 1194)"
OVPN_PROTO="$(pick OVPN_PROTO udp)"
OVPN_SUBNET="${OVPN_SUBNET:-10.8.0.0}"
DNS1="${DNS1:-1.1.1.1}"
DNS2="${DNS2:-8.8.8.8}"
SYNC_INTERVAL="$(pick SYNC_INTERVAL 30)"
PUBLIC_HOST="$(pick PUBLIC_HOST '')"
if [ -z "${MAX_CONN:-}" ] && [ -z "${OLD_MAX_CONN:-}" ] && [ "${ALLOW_MULTI:-1}" = "0" ]; then MAX_CONN=1; fi
MAX_CONN="$(pick MAX_CONN 2)"
LIMIT_POLICY="$(pick LIMIT_POLICY kick-oldest)"
OVPN_GROUPS="$(pick OVPN_GROUPS '')"
WEB_PORT="$(pick WEB_PORT 8088)"
WEB_BIND="$(pick WEB_BIND 0.0.0.0)"
WEB_TLS_CERT="$(pick WEB_TLS_CERT '')"
WEB_TLS_KEY="$(pick WEB_TLS_KEY '')"
WEB_BASE_URL="$(pick WEB_BASE_URL '')"
TICK="$(pick TICK 5)"
HISTORY_DAYS="$(pick HISTORY_DAYS 90)"
MGMT_PORT=7505

[ -n "$PANEL_URL" ] || read -rp "Panel URL (e.g. https://panel.example.com:8000): " PANEL_URL
if [ -z "$PANEL_API_KEY" ]; then
  [ -n "$PANEL_USER" ] || read -rp "Panel admin username: " PANEL_USER
  [ -n "$PANEL_PASS" ] || { read -rsp "Panel admin password: " PANEL_PASS; echo; }
fi
case "$OVPN_PROTO" in udp|tcp) ;; *) echo "OVPN_PROTO must be udp or tcp"; exit 1;; esac
case "$LIMIT_POLICY" in kick-oldest|kick-newest) ;; *) echo "LIMIT_POLICY must be kick-oldest or kick-newest"; exit 1;; esac
if [ -n "$WEB_TLS_CERT" ] && { [ ! -f "$WEB_TLS_CERT" ] || { [ -n "$WEB_TLS_KEY" ] && [ ! -f "$WEB_TLS_KEY" ]; }; }; then
  echo "WEB_TLS_CERT / WEB_TLS_KEY file not found."; exit 1
fi

# ---------------------------------------------------------------- packages --
echo "[1/7] Installing packages..."
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y openvpn openssl python3 iproute2 curl iptables qrencode
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y epel-release || true
  dnf install -y openvpn openssl python3 iproute curl iptables qrencode || \
    dnf install -y openvpn openssl python3 iproute curl iptables
elif command -v yum >/dev/null 2>&1; then
  yum install -y epel-release || true
  yum install -y openvpn openssl python3 iproute curl iptables qrencode || \
    yum install -y openvpn openssl python3 iproute curl iptables
else
  echo "Unsupported distro (need apt, dnf or yum)."; exit 1
fi
command -v qrencode >/dev/null 2>&1 || echo "WARNING: qrencode not installed - QR codes will be disabled."

NOGROUP=nobody
getent group nogroup >/dev/null 2>&1 && NOGROUP=nogroup

if [ -z "$PUBLIC_HOST" ]; then
  PUBLIC_HOST="$(curl -fsS --max-time 8 https://api.ipify.org 2>/dev/null || true)"
fi
[ -n "$PUBLIC_HOST" ] || read -rp "Server public IP/domain: " PUBLIC_HOST

# --------------------------------------------------------------------- PKI --
echo "[2/7] Generating certificates..."
install -d -m 750 -o root -g "$NOGROUP" "$BASE"
install -d -m 700 "$PKI"
install -d -m 700 "$VARDIR"
install -d -m 770 -o root -g "$NOGROUP" "$VARDIR/spool"
if [ ! -f "$PKI/ca.crt" ]; then
  cd "$PKI"
  openssl ecparam -name prime256v1 -genkey -noout -out ca.key
  openssl req -new -x509 -key ca.key -sha256 -days 3650 -subj "/CN=PG-OpenVPN-CA" -out ca.crt
  openssl ecparam -name prime256v1 -genkey -noout -out server.key
  openssl req -new -key server.key -subj "/CN=pg-openvpn-server" -out server.csr
  printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:pg-openvpn-server\n' > ext.cnf
  openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days 3650 -sha256 -extfile ext.cnf
  rm -f server.csr ext.cnf ca.srl
  openvpn --genkey secret tc.key 2>/dev/null || openvpn --genkey --secret tc.key
  chmod 600 ./*.key
  cd - >/dev/null
fi
[ -f "$BASE/mgmt.pass" ] || { openssl rand -hex 16 > "$BASE/mgmt.pass"; chmod 600 "$BASE/mgmt.pass"; }
[ -f "$BASE/internal.key" ] || { openssl rand -hex 24 > "$BASE/internal.key"; chmod 600 "$BASE/internal.key"; }

# ------------------------------------------------------------ sync config --
echo "[3/7] Writing configuration..."
export PANEL_URL PANEL_USER PANEL_PASS PANEL_API_KEY PANEL_INSECURE PUBLIC_HOST \
       OVPN_PORT OVPN_PROTO SYNC_INTERVAL MGMT_PORT NOGROUP BASE MAX_CONN LIMIT_POLICY \
       OVPN_GROUPS WEB_PORT WEB_BIND WEB_TLS_CERT WEB_TLS_KEY WEB_BASE_URL TICK HISTORY_DAYS
python3 - <<'PYEOF'
import json, os, secrets
E = os.environ
path = E["BASE"] + "/sync.json"
old = {}
if os.path.exists(path):
    old = json.load(open(path))
cfg = {
    "version": 2,
    "panel_url": E["PANEL_URL"], "panel_user": E["PANEL_USER"], "panel_pass": E["PANEL_PASS"],
    "api_key": E["PANEL_API_KEY"], "insecure": E["PANEL_INSECURE"] == "1",
    "host": E["PUBLIC_HOST"], "port": int(E["OVPN_PORT"]), "proto": E["OVPN_PROTO"],
    "interval": int(E["SYNC_INTERVAL"]), "tick": int(E["TICK"]), "mgmt_port": int(E["MGMT_PORT"]),
    "group": E["NOGROUP"],
    "max_conn": int(E["MAX_CONN"]), "limit_policy": E["LIMIT_POLICY"],
    "groups": [g.strip() for g in E["OVPN_GROUPS"].split(",") if g.strip()],
    "history_days": int(E["HISTORY_DAYS"]),
    "web_port": int(E["WEB_PORT"]), "web_bind": E["WEB_BIND"],
    "web_tls_cert": E["WEB_TLS_CERT"], "web_tls_key": E["WEB_TLS_KEY"],
    "web_base_url": E["WEB_BASE_URL"], "ovpn_path": old.get("ovpn_path", "/ovpn"),
    # keep the same secrets across re-runs so existing user passwords stay valid
    "secret": old.get("secret") or secrets.token_hex(32),
    "webhook_secret": old.get("webhook_secret") or secrets.token_hex(16),
    # v1 -> v2 upgrade: existing users keep their old password on first sync
    "legacy": bool(old.get("legacy")) or (bool(old) and "version" not in old),
}
with open(path, "w") as f:
    json.dump(cfg, f, indent=2)
os.chmod(path, 0o600)
PYEOF

SERVER_PROTO="$OVPN_PROTO"
EXTRA_UDP=""
[ "$OVPN_PROTO" = "udp" ] && EXTRA_UDP="explicit-exit-notify 1"

install -d /etc/openvpn/server
cat > /etc/openvpn/server/pg.conf <<EOF
port $OVPN_PORT
proto $SERVER_PROTO
dev tun
ca $PKI/ca.crt
cert $PKI/server.crt
key $PKI/server.key
dh none
ecdh-curve prime256v1
tls-crypt $PKI/tc.key
tls-version-min 1.2
topology subnet
server $OVPN_SUBNET 255.255.255.0
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS $DNS1"
push "dhcp-option DNS $DNS2"
keepalive 10 120
cipher AES-256-GCM
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
auth SHA256
user nobody
group $NOGROUP
persist-key
persist-tun
verb 3
$EXTRA_UDP

# several sessions per account are allowed at the TLS level; the pg-ovpn daemon
# enforces the per-user limit (MAX_CONN) and kicks the extra sessions
duplicate-cn

# username/password auth against the list synced from PasarGuard
verify-client-cert none
username-as-common-name
auth-user-pass-verify /usr/local/bin/pg-ovpn-auth via-file
client-disconnect /usr/local/bin/pg-ovpn-disconnect
script-security 2
management 127.0.0.1 $MGMT_PORT $BASE/mgmt.pass
EOF

# ------------------------------------------------------------ helper tools --
echo "[4/7] Installing helper tools..."
cat > /usr/local/bin/pg-ovpn-auth <<'PYEOF'
#!/usr/bin/env python3
# Called by OpenVPN (via-file): argv[1] is a temp file with username + password.
import hashlib, hmac, json, sys

try:
    with open(sys.argv[1]) as f:
        user = f.readline().rstrip("\n")
        pw = f.readline().rstrip("\n")
    with open("/etc/pg-openvpn/users.json") as f:
        db = json.load(f)
except Exception:
    sys.exit(1)

stored = db.get(user)
if stored and hmac.compare_digest(stored, hashlib.sha256(pw.encode()).hexdigest()):
    sys.exit(0)
sys.exit(1)
PYEOF
chmod 755 /usr/local/bin/pg-ovpn-auth

cat > /usr/local/bin/pg-ovpn-disconnect <<'PYEOF'
#!/usr/bin/env python3
# OpenVPN client-disconnect hook: spool final byte counters for the pg-ovpn daemon.
import json, os, time
env = os.environ
ev = {
    "user": env.get("common_name") or env.get("username") or "",
    "ip": env.get("trusted_ip") or env.get("trusted_ip6") or env.get("untrusted_ip") or "",
    "vip": env.get("ifconfig_pool_remote_ip", ""),
    "since": int(env.get("time_unix") or 0),
    "rx": int(env.get("bytes_received") or 0),
    "tx": int(env.get("bytes_sent") or 0),
    "ts": int(time.time()),
}
if ev["user"]:
    with open("/var/lib/pg-openvpn/spool/events.log", "a") as f:
        f.write(json.dumps(ev) + "\n")
PYEOF
chmod 755 /usr/local/bin/pg-ovpn-disconnect

cat > /usr/local/bin/pg-ovpn <<'PYEOF'
#!/usr/bin/env python3
"""pg-ovpn v2 - PasarGuard <-> OpenVPN bridge.

Daemon (systemd):   pg-ovpn run
One-shot sync:      pg-ovpn once
CLI (talks to the running daemon):
  pg-ovpn online | users | history [USER] [-n N]
  pg-ovpn kick USER [--ban MINUTES]
  pg-ovpn limit USER N|default        (max simultaneous connections)
  pg-ovpn reset USER                  (zero the OpenVPN usage counter)
  pg-ovpn rotate USER                 (new password -> old .ovpn stops working)
  pg-ovpn groups | set-groups NAME[,NAME...]|all
  pg-ovpn show USER [--no-embed]      (print the .ovpn profile)
  pg-ovpn link USER                   (print config / QR page URLs)
"""
import argparse, collections, grp, hashlib, hmac, html, http.server, json, logging
import os, re, secrets, socket, sqlite3, ssl, subprocess, sys, threading, time
import urllib.error, urllib.parse, urllib.request
from datetime import datetime, timezone

BASE = os.environ.get("PG_OVPN_BASE", "/etc/pg-openvpn")
VAR = os.environ.get("PG_OVPN_VAR", "/var/lib/pg-openvpn")
CONF = BASE + "/sync.json"
USERS = BASE + "/users.json"
DB_PATH = VAR + "/pg-ovpn.db"
SPOOL = VAR + "/spool"
log = logging.getLogger("pg-ovpn")

DEFAULTS = {
    "max_conn": 2, "limit_policy": "kick-oldest", "tick": 5, "interval": 30,
    "history_days": 90, "groups": [], "web_port": 8088, "web_bind": "0.0.0.0",
    "web_tls_cert": "", "web_tls_key": "", "web_base_url": "", "ovpn_path": "/ovpn",
    "webhook_secret": "",
}
NOTE_RE = re.compile(r"ovpn[_\- ]?(?:limit|conn|max)\s*[=:]\s*(\d+)", re.I)
STATUS_FA = {
    "ok": "فعال", "active": "فعال", "disabled": "غیرفعال", "limited": "حجم تمام شده",
    "expired": "منقضی", "on_hold": "در انتظار", "group": "بدون دسترسی OpenVPN",
    "banned": "مسدود موقت", "deleted": "حذف شده",
}


# ------------------------------------------------------------------ helpers --
def now():
    return int(time.time())


def load_cfg():
    with open(CONF) as f:
        cfg = json.load(f)
    for k, v in DEFAULTS.items():
        cfg.setdefault(k, v)
    return cfg


def write_atomic(path, text, mode=0o600, group=None):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(text)
    os.chmod(tmp, mode)
    if group:
        try:
            os.chown(tmp, 0, grp.getgrnam(group).gr_gid)
        except (KeyError, PermissionError):
            pass
    os.replace(tmp, path)


def save_cfg(cfg):
    write_atomic(CONF, json.dumps(cfg, indent=2), 0o600)


def derive_password(secret, username, salt=""):
    msg = username if not salt else username + ":" + salt
    return hmac.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest()[:24]


def pw_hash(password):
    return hashlib.sha256(password.encode()).hexdigest()


def parse_expire(v):
    if not v:
        return 0
    if isinstance(v, (int, float)):
        return int(v)
    try:
        dt = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp())
    except ValueError:
        try:
            return int(v)
        except (TypeError, ValueError):
            return 0


def hbytes(n):
    n = float(n or 0)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or u == "TB":
            return ("%d %s" % (n, u)) if u == "B" else ("%.2f %s" % (n, u))
        n /= 1024


def split_addr(addr):
    m = re.match(r"^(?:[a-z0-9-]+:)?\[?(.+?)\]?:(\d+)$", addr or "")
    return (m.group(1), m.group(2)) if m else (addr or "", "")


# -------------------------------------------------------------------- panel --
class Panel:
    def __init__(self, cfg):
        self.url = cfg["panel_url"].rstrip("/")
        self.api_key = cfg.get("api_key") or ""
        self.username = cfg.get("panel_user") or ""
        self.password = cfg.get("panel_pass") or ""
        self.token = None
        self.ctx = ssl._create_unverified_context() if cfg.get("insecure") else None

    def _request(self, method, path, params=None, form=None, auth=True, token=None):
        url = self.url + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        data = urllib.parse.urlencode(form).encode() if form else None
        req = urllib.request.Request(url, data=data, method=method)
        if form:
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
        if token:
            req.add_header("Authorization", "Bearer " + token)
        elif auth:
            if self.api_key:
                req.add_header("X-Api-Key", self.api_key)
            else:
                if not self.token:
                    self.login()
                req.add_header("Authorization", "Bearer " + self.token)
        with urllib.request.urlopen(req, timeout=30, context=self.ctx) as resp:
            return json.load(resp)

    def login(self):
        r = self._request("POST", "/api/admin/token",
                          form={"username": self.username, "password": self.password}, auth=False)
        self.token = r["access_token"]

    def get(self, path, params=None):
        try:
            return self._request("GET", path, params)
        except urllib.error.HTTPError as e:
            if e.code == 401 and not self.api_key:
                self.token = None
                return self._request("GET", path, params)
            raise

    def users(self):
        out, offset, limit = [], 0, 200
        while True:
            r = self.get("/api/users", {"offset": offset, "limit": limit})
            batch = r.get("users", [])
            out += batch
            offset += len(batch)
            if not batch or offset >= r.get("total", 0):
                return out

    def groups(self):
        r = self.get("/api/groups")
        items = r.get("groups", []) if isinstance(r, dict) else r
        return [{"id": g.get("id"), "name": g.get("name", "")} for g in items]

    def check_admin(self, username, password):
        """Validate panel admin credentials (dashboard login). Returns True/False."""
        try:
            r = self._request("POST", "/api/admin/token",
                              form={"username": username, "password": password}, auth=False)
        except Exception:
            return False
        tok = r.get("access_token")
        if not tok:
            return False
        try:
            me = self._request("GET", "/api/admin", auth=False, token=tok)
            if isinstance(me, dict) and me.get("is_sudo") is False:
                return False
        except Exception:
            pass
        return True


# ----------------------------------------------------------------------- db --
class DB:
    def __init__(self):
        os.makedirs(VAR, exist_ok=True)
        self.c = sqlite3.connect(DB_PATH, check_same_thread=False, isolation_level=None, timeout=15)
        self.c.row_factory = sqlite3.Row
        self.c.executescript("""
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS users(
          username TEXT PRIMARY KEY, salt TEXT NOT NULL,
          ovpn_bytes INTEGER NOT NULL DEFAULT 0, last_panel_used INTEGER NOT NULL DEFAULT 0,
          conn_limit INTEGER, ban_until INTEGER NOT NULL DEFAULT 0, created INTEGER);
        CREATE TABLE IF NOT EXISTS history(
          id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, ip TEXT, port TEXT, vip TEXT,
          cid TEXT, connected INTEGER, disconnected INTEGER,
          rx INTEGER DEFAULT 0, tx INTEGER DEFAULT 0, reason TEXT);
        CREATE INDEX IF NOT EXISTS h_user ON history(username, id);
        CREATE INDEX IF NOT EXISTS h_open ON history(disconnected);
        CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
        """)

    def q(self, sql, args=()):
        return self.c.execute(sql, args)

    def begin(self):
        self.c.execute("BEGIN")

    def commit(self):
        if self.c.in_transaction:
            self.c.execute("COMMIT")

    def meta(self, k):
        r = self.q("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
        return r["v"] if r else None

    def set_meta(self, k, v):
        self.q("INSERT OR REPLACE INTO meta(k,v) VALUES(?,?)", (k, v))

    def all_users(self):
        return {r["username"]: dict(r) for r in self.q("SELECT * FROM users")}

    def get_user(self, name):
        r = self.q("SELECT * FROM users WHERE username=?", (name,)).fetchone()
        return dict(r) if r else None


# ------------------------------------------------------------- management ---
class Mgmt:
    COLS = ["Common Name", "Real Address", "Virtual Address", "Virtual IPv6 Address",
            "Bytes Received", "Bytes Sent", "Connected Since", "Connected Since (time_t)",
            "Username", "Client ID", "Peer ID", "Data Channel Cipher"]

    def __init__(self, port):
        with open(BASE + "/mgmt.pass") as f:
            pw = f.read().strip()
        self.s = socket.create_connection(("127.0.0.1", port), timeout=5)
        self._read(lambda b: b"ENTER PASSWORD:" in b)
        self.s.sendall((pw + "\n").encode())
        out = self._read(lambda b: re.search(rb"(SUCCESS|FAILED)[^\n]*\n", b))
        if b"SUCCESS" not in out:
            raise OSError("management authentication failed")

    def _read(self, done, timeout=6):
        self.s.settimeout(timeout)
        buf, end = b"", time.time() + timeout
        while not done(buf):
            if time.time() > end:
                raise socket.timeout("management read timeout")
            chunk = self.s.recv(65536)
            if not chunk:
                raise OSError("management connection closed")
            buf += chunk
        return buf

    def status(self):
        self.s.sendall(b"status 3\n")
        out = self._read(lambda b: re.search(rb"(^|\n)END\r?\n", b)).decode(errors="replace")
        cols, rows = None, []
        for line in out.splitlines():
            p = line.split("\t")
            if p[0] == "HEADER" and len(p) > 1 and p[1] == "CLIENT_LIST":
                cols = p[2:]
            elif p[0] == "CLIENT_LIST":
                rows.append(dict(zip(cols or self.COLS, p[1:])))
        return rows

    def kill(self, cid):
        self.s.sendall(("client-kill %s\n" % cid).encode())
        out = self._read(lambda b: re.search(rb"(^|\n)(SUCCESS|ERROR)[^\n]*\n", b))
        return b"SUCCESS" in out

    def close(self):
        try:
            self.s.sendall(b"quit\n")
        except OSError:
            pass
        self.s.close()


# --------------------------------------------------------------------- core --
class Core:
    def __init__(self, cfg):
        self.cfg = cfg
        self.db = DB()
        self.lock = threading.RLock()
        self.wake = threading.Event()
        self.panel_users = {}
        self.token_map = {}
        self.group_list = []
        self.selected = None          # None = all users, else set of group ids
        self.allowed = {}             # username -> (ok, reason)
        self.sessions = {}            # key -> session dict
        self.missing = {}
        self.pending_events = []
        self.kill_reason = {}
        self.recent = collections.deque(maxlen=300)
        self.synced_once = False
        self.sync_error = ""
        self.last_sync = 0
        self.mgmt_up = False
        self._last_users = None
        self._last_prune = 0
        self._load_open_sessions()

    # ---- sessions persisted across daemon restarts (open history rows) ----
    def _load_open_sessions(self):
        for r in self.db.q("SELECT * FROM history WHERE disconnected IS NULL"):
            key = "%s|%s|%s" % (r["username"], r["cid"], r["connected"])
            self.sessions[key] = {
                "key": key, "user": r["username"], "ip": r["ip"], "port": r["port"],
                "vip": r["vip"], "since": r["connected"], "cid": r["cid"],
                "rx": r["rx"], "tx": r["tx"], "hid": r["id"], "killed": 0}

    # ---- credentials -------------------------------------------------------
    def password(self, username):
        row = self.db.get_user(username)
        return derive_password(self.cfg["secret"], username, row["salt"]) if row else None

    def max_conn(self, username):
        row = self.db.get_user(username)
        if row and row["conn_limit"] is not None:
            return int(row["conn_limit"])
        m = NOTE_RE.search((self.panel_users.get(username) or {}).get("note") or "")
        if m:
            return int(m.group(1))
        return int(self.cfg.get("max_conn", 2))

    # ---- panel sync --------------------------------------------------------
    def resolve_groups(self, groups):
        entries = [str(x).strip() for x in self.cfg.get("groups", []) if str(x).strip()]
        if not entries or any(e.lower() in ("all", "*") for e in entries):
            return None
        names = {g["name"].lower(): g["id"] for g in (groups or [])}
        ids = set()
        for e in entries:
            if e.isdigit():
                ids.add(int(e))
            elif e.lower() in names:
                ids.add(names[e.lower()])
            elif groups is not None:
                log.warning("group '%s' not found in panel", e)
        if groups is None and not ids:
            return self.selected  # groups API failed: keep last known selection
        return ids

    def sync(self):
        panel = Panel(self.cfg)
        users = panel.users()
        try:
            groups = panel.groups()
        except Exception as e:
            log.warning("could not read groups: %s", e)
            groups = None
        new, tokens = {}, {}
        for u in users:
            name = u.get("username")
            if not name:
                continue
            surl = u.get("subscription_url") or ""
            tok = urllib.parse.urlsplit(surl).path.rstrip("/").rsplit("/", 1)[-1] if surl else ""
            new[name] = {
                "status": u.get("status") or "", "used": int(u.get("used_traffic") or 0),
                "limit": int(u.get("data_limit") or 0), "expire": parse_expire(u.get("expire")),
                "groups": list(u.get("group_ids") or []), "note": u.get("note") or "",
                "token": tok, "sub_url": surl,
            }
            if tok:
                tokens[tok] = name
        with self.lock:
            existing = self.db.all_users()
            if not new and existing:
                raise RuntimeError("panel returned 0 users, keeping previous state")
            legacy = bool(self.cfg.get("legacy")) and not self.db.meta("migrated")
            self.db.begin()
            try:
                for name, info in new.items():
                    row = existing.get(name)
                    if not row:
                        salt = "" if legacy else secrets.token_hex(8)
                        self.db.q("INSERT INTO users(username,salt,last_panel_used,created) VALUES(?,?,?,?)",
                                  (name, salt, info["used"], now()))
                    else:
                        if info["used"] < row["last_panel_used"]:   # usage was reset / renewed
                            self.db.q("UPDATE users SET ovpn_bytes=0 WHERE username=?", (name,))
                            log.info("usage reset detected for %s -> OpenVPN counter cleared", name)
                        self.db.q("UPDATE users SET last_panel_used=? WHERE username=?", (info["used"], name))
                for gone in set(existing) - set(new):
                    self.db.q("DELETE FROM users WHERE username=?", (gone,))
                    log.info("user %s removed from panel", gone)
                if legacy:
                    self.db.set_meta("migrated", "1")
            finally:
                self.db.commit()
            self.panel_users, self.token_map = new, tokens
            if groups is not None:
                self.group_list = groups
            self.selected = self.resolve_groups(groups)
            self.synced_once, self.sync_error, self.last_sync = True, "", now()
            self.evaluate()
            self.write_users()
        return len([1 for v in self.allowed.values() if v[0]])

    def evaluate(self):
        t = now()
        rows = self.db.all_users()
        res = {}
        for name, info in self.panel_users.items():
            row = rows.get(name)
            if not row:
                continue
            if info["status"] != "active":
                res[name] = (False, info["status"] or "disabled")
            elif self.selected is not None and not (set(info["groups"]) & self.selected):
                res[name] = (False, "group")
            elif info["expire"] and info["expire"] <= t:
                res[name] = (False, "expired")
            elif info["limit"] and info["used"] + row["ovpn_bytes"] >= info["limit"]:
                res[name] = (False, "limited")
            elif row["ban_until"] > t:
                res[name] = (False, "banned")
            else:
                res[name] = (True, "ok")
        self.allowed = res
        self._rows = rows

    def write_users(self):
        if not self.synced_once:
            return
        out = {}
        for name, (ok, _) in self.allowed.items():
            if ok:
                out[name] = pw_hash(self.password(name))
        if out != self._last_users:
            write_atomic(USERS, json.dumps(out), 0o640, self.cfg.get("group", "nogroup"))
            self._last_users = out

    # ---- tick: sessions, accounting, history, enforcement ------------------
    def read_spool(self):
        src, dst = SPOOL + "/events.log", SPOOL + "/events.proc"
        try:
            os.replace(src, dst)
        except OSError:
            return []
        evs = []
        try:
            with open(dst) as f:
                for line in f:
                    try:
                        evs.append(json.loads(line))
                    except ValueError:
                        pass
            os.unlink(dst)
        except OSError:
            pass
        return evs

    @staticmethod
    def _match(s, ev):
        return (ev["user"] == s["user"] and ev["ip"] == s["ip"]
                and abs(int(ev["since"]) - int(s["since"])) <= 3
                and (not ev.get("vip") or not s.get("vip") or ev["vip"] == s["vip"]))

    def _add_usage(self, user, n):
        if n > 0:
            self.db.q("UPDATE users SET ovpn_bytes=ovpn_bytes+? WHERE username=?", (n, user))

    def _finalize(self, key, ev=None):
        s = self.sessions.pop(key)
        self.missing.pop(key, None)
        rx, tx = s["rx"], s["tx"]
        if ev:
            nrx, ntx = int(ev.get("rx", 0)), int(ev.get("tx", 0))
            self._add_usage(s["user"], max(0, nrx - rx) + max(0, ntx - tx))
            rx, tx = max(rx, nrx), max(tx, ntx)
        disc = int(ev["ts"]) if ev else now()
        reason = self.kill_reason.pop(key, "disconnect")
        self.db.q("UPDATE history SET disconnected=?, rx=?, tx=?, reason=? WHERE id=?",
                  (disc, rx, tx, reason, s["hid"]))
        self.recent.append(dict(s, ts=now()))

    def tick(self):
        with self.lock:
            self.pending_events += self.read_spool()
            try:
                m = Mgmt(self.cfg["mgmt_port"])
            except (OSError, socket.timeout):
                self.mgmt_up = False
                return
            self.mgmt_up = True
            self.db.begin()
            try:
                self._process(m.status(), m)
            except (OSError, socket.timeout) as e:
                log.warning("management error: %s", e)
            finally:
                self.db.commit()
                m.close()
            self._prune()

    def _process(self, rows, m):
        t = now()
        cur = set()
        for r in rows:
            cn = r.get("Common Name", "")
            if cn in ("", "UNDEF"):
                continue
            ip, port = split_addr(r.get("Real Address", ""))
            since = int(r.get("Connected Since (time_t)") or t)
            cid = r.get("Client ID", "")
            key = "%s|%s|%s" % (cn, cid, since)
            rx, tx = int(r.get("Bytes Received") or 0), int(r.get("Bytes Sent") or 0)
            s = self.sessions.get(key)
            if not s:
                cur_id = self.db.q(
                    "INSERT INTO history(username,ip,port,vip,cid,connected,rx,tx) VALUES(?,?,?,?,?,?,0,0)",
                    (cn, ip, port, r.get("Virtual Address", ""), cid, since)).lastrowid
                s = {"key": key, "user": cn, "ip": ip, "port": port,
                     "vip": r.get("Virtual Address", ""), "since": since, "cid": cid,
                     "rx": 0, "tx": 0, "hid": cur_id, "killed": 0}
                self.sessions[key] = s
                log.info("connect: %s from %s", cn, ip)
            drx, dtx = max(0, rx - s["rx"]), max(0, tx - s["tx"])
            if drx or dtx:
                self._add_usage(cn, drx + dtx)
                s["rx"], s["tx"] = rx, tx
                self.db.q("UPDATE history SET rx=?, tx=? WHERE id=?", (rx, tx, s["hid"]))
            self.missing.pop(key, None)
            cur.add(key)

        # disconnect events written by the client-disconnect hook
        left = []
        for ev in self.pending_events:
            hit = next((k for k, s in self.sessions.items() if self._match(s, ev)), None)
            if hit and hit in cur:
                if t - int(ev["ts"]) < 60:
                    left.append(ev)            # still listed, retry next tick
            elif hit:
                self._finalize(hit, ev)
            elif any(self._match(s, ev) for s in self.recent):
                pass                           # already closed by fallback
            else:                              # very short session, never seen in status
                rx, tx = int(ev.get("rx", 0)), int(ev.get("tx", 0))
                self._add_usage(ev["user"], rx + tx)
                self.db.q("INSERT INTO history(username,ip,port,vip,cid,connected,disconnected,rx,tx,reason)"
                          " VALUES(?,?,?,?,?,?,?,?,?,?)",
                          (ev["user"], ev["ip"], "", ev.get("vip", ""), "", int(ev["since"]),
                           int(ev["ts"]), rx, tx, "disconnect"))
        self.pending_events = left

        for key in list(self.sessions):
            if key not in cur:
                n = self.missing.get(key, 0) + 1
                self.missing[key] = n
                if n >= 2:
                    self._finalize(key)

        self.evaluate()
        self.write_users()
        if not self.synced_once:
            return

        by_user = collections.defaultdict(list)
        for key in cur:
            if key in self.sessions:
                by_user[self.sessions[key]["user"]].append(self.sessions[key])
        for user, ss in by_user.items():
            ok, reason = self.allowed.get(user, (False, "deleted"))
            if not ok:
                for s in ss:
                    self._kill(m, s, reason)
                continue
            limit = self.max_conn(user)
            if limit > 0 and len(ss) > limit:
                ss.sort(key=lambda s: (s["since"], int(s["cid"] or 0)))
                extra = len(ss) - limit
                victims = ss[:extra] if self.cfg.get("limit_policy") == "kick-oldest" else ss[-extra:]
                for s in victims:
                    self._kill(m, s, "limit")

    def _kill(self, m, s, reason):
        if now() - s.get("killed", 0) < 15:
            return
        s["killed"] = now()
        self.kill_reason[s["key"]] = reason
        try:
            m.kill(s["cid"])
            log.info("kicked %s (%s) reason=%s", s["user"], s["ip"], reason)
        except (OSError, socket.timeout) as e:
            log.warning("kill failed: %s", e)

    def _prune(self):
        if now() - self._last_prune < 3600:
            return
        self._last_prune = now()
        cutoff = now() - int(self.cfg.get("history_days", 90)) * 86400
        self.db.q("DELETE FROM history WHERE disconnected IS NOT NULL AND disconnected < ?", (cutoff,))

    # ---- admin actions -----------------------------------------------------
    def kick(self, user, ban_minutes=0, reason="admin-kick"):
        with self.lock:
            if ban_minutes > 0:
                self.db.q("UPDATE users SET ban_until=? WHERE username=?", (now() + ban_minutes * 60, user))
                self.evaluate()
                self.write_users()
            try:
                m = Mgmt(self.cfg["mgmt_port"])
            except (OSError, socket.timeout):
                return 0
            n = 0
            try:
                for s in [s for s in self.sessions.values() if s["user"] == user]:
                    s["killed"] = 0
                    self._kill(m, s, reason)
                    n += 1
            finally:
                m.close()
            return n

    def set_limit(self, user, value):
        with self.lock:
            self.db.q("UPDATE users SET conn_limit=? WHERE username=?", (value, user))

    def reset_usage(self, user):
        with self.lock:
            self.db.q("UPDATE users SET ovpn_bytes=0 WHERE username=?", (user,))
            self.evaluate()
            self.write_users()

    def rotate(self, user):
        with self.lock:
            self.db.q("UPDATE users SET salt=? WHERE username=?", (secrets.token_hex(8), user))
            self.write_users()
        self.kick(user, reason="rotated")

    def set_settings(self, data):
        with self.lock:
            if "groups" in data:
                self.cfg["groups"] = [str(x) for x in data["groups"]]
            if "max_conn" in data:
                self.cfg["max_conn"] = max(0, int(data["max_conn"]))
            if data.get("limit_policy") in ("kick-oldest", "kick-newest"):
                self.cfg["limit_policy"] = data["limit_policy"]
            save_cfg(self.cfg)
            self.selected = self.resolve_groups(self.group_list or None)
            self.evaluate()
            self.write_users()
        self.wake.set()

    # ---- views -------------------------------------------------------------
    def online_view(self):
        with self.lock:
            t = now()
            out = []
            for s in self.sessions.values():
                if self.missing.get(s["key"]):
                    continue
                out.append({"user": s["user"], "ip": s["ip"], "vip": s["vip"], "since": s["since"],
                            "duration": t - s["since"], "rx": s["rx"], "tx": s["tx"]})
            out.sort(key=lambda x: (x["user"], x["since"]))
            cnt = collections.Counter(o["user"] for o in out)
            for o in out:
                o["count"], o["max"] = cnt[o["user"]], self.max_conn(o["user"])
            return out

    def users_view(self, base):
        with self.lock:
            rows = self.db.all_users()
            online = collections.Counter(s["user"] for s in self.sessions.values())
            out = []
            for name, info in sorted(self.panel_users.items()):
                row = rows.get(name)
                if not row:
                    continue
                ok, reason = self.allowed.get(name, (False, "deleted"))
                out.append({
                    "user": name, "ok": ok, "reason": reason, "reason_fa": STATUS_FA.get(reason, reason),
                    "panel_used": info["used"], "ovpn_used": row["ovpn_bytes"], "limit": info["limit"],
                    "expire": info["expire"], "online": online.get(name, 0), "max": self.max_conn(name),
                    "override": row["conn_limit"],
                    "link": self.config_url(base, info["token"]) if info["token"] else ""})
            return out

    def config_url(self, base, token, tail=""):
        b = (self.cfg.get("web_base_url") or base).rstrip("/")
        return "%s%s/%s%s" % (b, self.cfg["ovpn_path"], urllib.parse.quote(token, safe=""), tail)

    def history_view(self, user=None, limit=200, offset=0):
        with self.lock:
            sql, args = "SELECT * FROM history", []
            if user:
                sql += " WHERE username=?"
                args.append(user)
            sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
            args += [min(limit, 1000), offset]
            return [dict(r) for r in self.db.q(sql, args)]

    def profile(self, username):
        cfg = self.cfg
        pw = self.password(username)
        if pw is None:
            return None
        with open(BASE + "/pki/ca.crt") as f:
            ca = f.read().strip()
        with open(BASE + "/pki/tc.key") as f:
            tc = f.read().strip()
        lines = [
            "# PasarGuard OpenVPN profile for %s" % username,
            "client", "dev tun", "proto %s" % cfg["proto"],
            "remote %s %s" % (cfg["host"], cfg["port"]),
            "resolv-retry infinite", "nobind", "persist-key", "persist-tun",
            "remote-cert-tls server", "auth-user-pass", "auth-nocache", "auth SHA256",
            "cipher AES-256-GCM", "data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305",
            "verb 3"]
        if cfg["proto"] == "udp":
            lines.append("explicit-exit-notify 1")
        lines += ["<ca>", ca, "</ca>", "<tls-crypt>", tc, "</tls-crypt>",
                  "<auth-user-pass>", username, pw, "</auth-user-pass>"]
        return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------- web --
_qr_cache = {}


def make_qr(text):
    if text in _qr_cache:
        return _qr_cache[text]
    try:
        svg = subprocess.run(["qrencode", "-t", "SVG", "-m", "2", "-s", "6", "-o", "-", text],
                             capture_output=True, timeout=10, check=True).stdout.decode()
    except (OSError, subprocess.SubprocessError):
        return None
    if len(_qr_cache) > 200:
        _qr_cache.clear()
    _qr_cache[text] = svg
    return svg


class RateLimit:
    def __init__(self, limit, window):
        self.limit, self.window, self.hits = limit, window, collections.defaultdict(list)

    def allow(self, key, record=True):
        t = time.time()
        h = [x for x in self.hits[key] if t - x < self.window]
        self.hits[key] = h
        if len(h) >= self.limit:
            return False
        if record:
            h.append(t)
        return True


pub_rl = RateLimit(40, 60)
login_rl = RateLimit(6, 300)


def user_page(core, username, token, base):
    info = core.panel_users.get(username, {})
    ok, reason = core.allowed.get(username, (False, "deleted"))
    row = core.db.get_user(username) or {}
    used = info.get("used", 0) + row.get("ovpn_bytes", 0)
    limit = info.get("limit", 0)
    pct = min(100, int(used * 100 / limit)) if limit else 0
    exp = datetime.fromtimestamp(info["expire"]).strftime("%Y-%m-%d") if info.get("expire") else "نامحدود"
    cfg_url = core.config_url(base, token, "/config.ovpn")
    import_url = "openvpn://import-profile/" + cfg_url
    qr = make_qr(import_url)
    e = html.escape
    badge = "ok" if ok else "bad"
    return """<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>OpenVPN - %(u)s</title>
<style>
:root{--bg:#f4f6fb;--card:#fff;--tx:#1b2333;--mut:#6b7488;--ok:#1a9d5c;--bad:#d64545;--ac:#3b6cf6;--bd:#e3e7f0}
@media(prefers-color-scheme:dark){:root{--bg:#10131a;--card:#181d28;--tx:#e8ecf5;--mut:#8b93a7;--bd:#2a3142}}
body{margin:0;background:var(--bg);color:var(--tx);font-family:Tahoma,system-ui,sans-serif;padding:16px}
.c{max-width:440px;margin:0 auto;background:var(--card);border:1px solid var(--bd);border-radius:16px;padding:20px}
h1{font-size:18px;margin:0 0 4px}.m{color:var(--mut);font-size:13px}
.b{display:inline-block;padding:2px 10px;border-radius:99px;font-size:12px;color:#fff}
.b.ok{background:var(--ok)}.b.bad{background:var(--bad)}
.bar{height:8px;background:var(--bd);border-radius:9px;margin:12px 0 4px;overflow:hidden}
.bar i{display:block;height:100%%;width:%(pct)d%%;background:var(--ac)}
.r{display:flex;justify-content:space-between;font-size:14px;padding:6px 0}
a.btn,button{display:block;text-align:center;background:var(--ac);color:#fff;border:0;border-radius:10px;
padding:12px;margin-top:10px;text-decoration:none;font-size:15px;width:100%%;box-sizing:border-box;cursor:pointer}
a.btn.s,button.s{background:transparent;color:var(--ac);border:1px solid var(--ac)}
.qr{text-align:center;margin-top:14px}.qr svg{width:210px;height:210px;background:#fff;padding:6px;border-radius:10px}
</style></head><body><div class="c">
<h1>OpenVPN</h1><div class="m">%(u)s &nbsp;<span class="b %(badge)s">%(st)s</span></div>
<div class="bar"><i></i></div>
<div class="r"><span>مصرف</span><span dir="ltr">%(used)s / %(lim)s</span></div>
<div class="r"><span>انقضا</span><span>%(exp)s</span></div>
<a class="btn" href="%(cfg)s">دانلود کانفیگ (.ovpn)</a>
<a class="btn s" href="%(imp)s">باز کردن در OpenVPN Connect</a>
%(qr)s
<button class="s" onclick="navigator.clipboard.writeText('%(cfg)s');this.textContent='کپی شد ✓'">کپی لینک کانفیگ</button>
<p class="m" style="text-align:center;margin-top:14px">برنامه OpenVPN Connect را نصب کنید، سپس QR را اسکن یا فایل را وارد کنید.</p>
</div></body></html>""" % {
        "u": e(username), "badge": badge, "st": e(STATUS_FA.get(reason, reason)), "pct": pct,
        "used": hbytes(used), "lim": hbytes(limit) if limit else "نامحدود", "exp": exp,
        "cfg": e(cfg_url, quote=True), "imp": e(import_url, quote=True),
        "qr": ('<div class="qr">%s</div>' % qr) if qr else ""}


class Handler(http.server.BaseHTTPRequestHandler):
    core = None
    server_version = "pg-ovpn"

    def log_message(self, fmt, *a):
        log.debug("web: " + fmt, *a)

    # -- plumbing
    def _send(self, code, body=b"", ctype="text/plain; charset=utf-8", headers=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code=200, headers=None):
        self._send(code, json.dumps(obj, ensure_ascii=False), "application/json; charset=utf-8", headers)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > 65536:
            return {}
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            return {}

    def _base(self):
        proto = self.headers.get("X-Forwarded-Proto") or ("https" if self.core.cfg.get("web_tls_cert") else "http")
        return "%s://%s" % (proto, self.headers.get("Host") or "localhost")

    def _ip(self):
        return self.client_address[0]

    # -- admin session (cookie) or internal CLI key
    def _skey(self):
        return hashlib.sha256(("web" + self.core.cfg["secret"]).encode()).digest()

    def _make_cookie(self, user):
        exp = now() + 12 * 3600
        msg = "%s.%d" % (user, exp)
        sig = hmac.new(self._skey(), msg.encode(), hashlib.sha256).hexdigest()
        return "pgs=%s.%s; Path=/; HttpOnly; SameSite=Strict; Max-Age=43200%s" % (
            urllib.parse.quote(msg), sig, "; Secure" if self._base().startswith("https") else "")

    def _authed(self):
        key = self.headers.get("X-Internal-Key")
        if key and self._ip() in ("127.0.0.1", "::1"):
            try:
                with open(BASE + "/internal.key") as f:
                    if hmac.compare_digest(key, f.read().strip()):
                        return "cli"
            except OSError:
                pass
        for part in (self.headers.get("Cookie") or "").split(";"):
            part = part.strip()
            if part.startswith("pgs="):
                val = urllib.parse.unquote(part[4:])
                try:
                    msg, sig = val.rsplit(".", 1)
                    user, exp = msg.rsplit(".", 1)
                except ValueError:
                    return None
                good = hmac.new(self._skey(), msg.encode(), hashlib.sha256).hexdigest()
                if hmac.compare_digest(sig, good) and int(exp) > now():
                    return user
        return None

    # -- routing
    def do_GET(self):
        self._route("GET")

    def do_POST(self):
        self._route("POST")

    def _route(self, method):
        core = self.core
        u = urllib.parse.urlsplit(self.path)
        path, qs = u.path, urllib.parse.parse_qs(u.query)
        try:
            if path in ("/", "/admin"):
                return self._send(200, DASHBOARD, "text/html; charset=utf-8")
            if path == "/healthz":
                return self._json({"ok": True})
            if path.startswith("/webhook"):
                return self._webhook(path)
            prefix = core.cfg["ovpn_path"]
            if path.startswith(prefix + "/"):
                return self._public(path[len(prefix) + 1:])
            if path.startswith("/api/"):
                return self._api(method, path, qs)
            self._send(404, "not found")
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:  # never kill the server thread
            log.exception("web error: %s", e)
            self._send(500, "internal error")

    def _webhook(self, path):
        cfg = self.core.cfg
        given = self.headers.get("x-webhook-secret") or path[len("/webhook"):].strip("/")
        if not cfg.get("webhook_secret") or not hmac.compare_digest(given, cfg["webhook_secret"]):
            return self._send(403, "forbidden")
        self._body()
        self.core.wake.set()
        self._send(200, "ok")

    def _public(self, rest):
        core = self.core
        if not pub_rl.allow(self._ip()):
            return self._send(429, "too many requests")
        parts = rest.split("/")
        token, action = urllib.parse.unquote(parts[0]), (parts[1] if len(parts) > 1 else "")
        if not action and token.endswith(".ovpn"):
            token, action = token[:-5], "config.ovpn"
        resp = None
        with core.lock:
            name = core.token_map.get(token)
            if name:
                base = self._base()
                if action == "":
                    resp = (200, user_page(core, name, token, base), "text/html; charset=utf-8", None)
                elif action == "qr.svg":
                    svg = make_qr("openvpn://import-profile/" + core.config_url(base, token, "/config.ovpn"))
                    resp = (200, svg, "image/svg+xml", None) if svg else (404, "qrencode missing", "text/plain", None)
                elif action == "config.ovpn":
                    text = core.profile(name)
                    if text is not None:
                        info = core.panel_users.get(name, {})
                        row = core.db.get_user(name) or {}
                        h = {"Content-Disposition": 'attachment; filename="%s.ovpn"' % name,
                             "subscription-userinfo": "upload=0; download=%d; total=%d; expire=%d" % (
                                 info.get("used", 0) + row.get("ovpn_bytes", 0), info.get("limit", 0), info.get("expire", 0)),
                             "profile-title": "OpenVPN-" + name, "profile-update-interval": "12"}
                        resp = (200, text, "application/x-openvpn-profile", h)
        if resp:
            return self._send(resp[0], resp[1], resp[2], resp[3])
        self._send(404, "not found")

    def _api(self, method, path, qs):
        core = self.core
        if path == "/api/login" and method == "POST":
            ip = self._ip()
            if not login_rl.allow(ip, record=False):
                return self._json({"error": "too many attempts"}, 429)
            d = self._body()
            if Panel(core.cfg).check_admin(str(d.get("username", "")), str(d.get("password", ""))):
                return self._json({"ok": True}, headers={"Set-Cookie": self._make_cookie(d["username"])})
            login_rl.allow(ip)
            return self._json({"error": "invalid credentials"}, 401)
        if path == "/api/logout":
            return self._json({"ok": True}, headers={"Set-Cookie": "pgs=; Path=/; Max-Age=0"})
        if not self._authed():
            return self._json({"error": "unauthorized"}, 401)
        q1 = lambda k, d="": (qs.get(k) or [d])[0]
        base = self._base()
        if method == "GET":
            if path == "/api/state":
                with core.lock:
                    on = core.online_view()
                    return self._json({
                        "mgmt_up": core.mgmt_up, "synced": core.synced_once, "sync_error": core.sync_error,
                        "last_sync": core.last_sync, "online": len(on),
                        "online_users": len({o["user"] for o in on}), "users": len(core.panel_users),
                        "allowed": len([1 for v in core.allowed.values() if v[0]])})
            if path == "/api/online":
                return self._json(core.online_view())
            if path == "/api/users":
                return self._json(core.users_view(base))
            if path == "/api/history":
                return self._json(core.history_view(q1("user") or None, int(q1("limit", "200")), int(q1("offset", "0"))))
            if path == "/api/groups":
                with core.lock:
                    return self._json({"groups": core.group_list, "selected": core.cfg.get("groups", []),
                                       "max_conn": core.cfg.get("max_conn"), "limit_policy": core.cfg.get("limit_policy")})
            if path == "/api/links":
                with core.lock:
                    name = q1("user")
                    tok = (core.panel_users.get(name) or {}).get("token")
                    if not tok:
                        return self._json({"error": "user not found"}, 404)
                    return self._json({"page": core.config_url(base, tok), "config": core.config_url(base, tok, "/config.ovpn"),
                                       "qr": core.config_url(base, tok, "/qr.svg")})
        if method == "POST":
            d = self._body()
            user = str(d.get("user", ""))
            if path == "/api/kick":
                return self._json({"kicked": core.kick(user, int(d.get("ban") or 0))})
            if path == "/api/limit":
                v = d.get("limit")
                core.set_limit(user, None if v in (None, "", "default") else max(0, int(v)))
                return self._json({"ok": True})
            if path == "/api/reset":
                core.reset_usage(user)
                return self._json({"ok": True})
            if path == "/api/rotate":
                core.rotate(user)
                return self._json({"ok": True})
            if path == "/api/settings":
                core.set_settings(d)
                return self._json({"ok": True})
            if path == "/api/sync":
                core.wake.set()
                return self._json({"ok": True})
        self._json({"error": "not found"}, 404)


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64


def start_web(core):
    cfg = core.cfg
    Handler.core = core
    srv = Server((cfg["web_bind"], int(cfg["web_port"])), Handler)
    if cfg.get("web_tls_cert"):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cfg["web_tls_cert"], cfg.get("web_tls_key") or None)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    log.info("web service on %s:%s (%s)", cfg["web_bind"], cfg["web_port"], "https" if cfg.get("web_tls_cert") else "http")
    return srv


# ---------------------------------------------------------------- dashboard --
DASHBOARD = r"""<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>PasarGuard OpenVPN</title>
<style>
:root{--bg:#f4f6fb;--card:#fff;--tx:#1b2333;--mut:#6b7488;--ok:#1a9d5c;--bad:#d64545;--ac:#3b6cf6;--bd:#e3e7f0}
@media(prefers-color-scheme:dark){:root{--bg:#10131a;--card:#181d28;--tx:#e8ecf5;--mut:#8b93a7;--bd:#2a3142}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);font-family:Tahoma,system-ui,sans-serif;font-size:14px}
header{display:flex;gap:12px;align-items:center;justify-content:space-between;padding:12px 16px;background:var(--card);border-bottom:1px solid var(--bd);flex-wrap:wrap}
h1{font-size:16px;margin:0}main{padding:16px;max-width:1100px;margin:0 auto}
.tabs{display:flex;gap:6px;margin-bottom:12px;flex-wrap:wrap}
.tabs button,.btn{background:var(--card);color:var(--tx);border:1px solid var(--bd);border-radius:8px;padding:7px 14px;cursor:pointer;font:inherit}
.tabs button.on,.btn.p{background:var(--ac);color:#fff;border-color:var(--ac)}.btn.d{color:var(--bad);border-color:var(--bad)}
.btn.s{padding:3px 9px;font-size:12px;margin:1px}
.card{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:12px;overflow-x:auto}
table{width:100%;border-collapse:collapse;white-space:nowrap}th,td{text-align:right;padding:8px;border-bottom:1px solid var(--bd)}
th{color:var(--mut);font-weight:normal;font-size:12px}.stats{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px}
.stat{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:10px 16px}.stat b{display:block;font-size:20px}
.b{padding:2px 9px;border-radius:99px;color:#fff;font-size:12px}.b.ok{background:var(--ok)}.b.bad{background:var(--bad)}
input,select{background:var(--bg);color:var(--tx);border:1px solid var(--bd);border-radius:8px;padding:7px;font:inherit}
.ltr{direction:ltr;unicode-bidi:embed}.mut{color:var(--mut)}#login{max-width:320px;margin:80px auto}
#login input{width:100%;margin-bottom:8px}.row{display:flex;gap:8px;margin:8px 0;align-items:center;flex-wrap:wrap}
</style></head><body>
<div id="login" class="card" style="display:none"><h1>ورود مدیر (اکانت ادمین پاسارگارد)</h1><br>
<input id="lu" placeholder="نام کاربری" autocomplete="username"><input id="lp" type="password" placeholder="رمز عبور" autocomplete="current-password">
<button class="btn p" style="width:100%" onclick="login()">ورود</button><p id="le" class="mut"></p></div>
<div id="app" style="display:none">
<header><h1>OpenVPN · PasarGuard</h1><span id="hs" class="mut"></span><button class="btn s" onclick="logout()">خروج</button></header>
<main><div class="stats" id="stats"></div>
<div class="tabs"><button data-t="online" class="on">آنلاین</button><button data-t="users">کاربران</button><button data-t="history">تاریخچه</button><button data-t="settings">تنظیمات</button></div>
<div id="t_online" class="card"></div><div id="t_users" class="card" style="display:none"></div>
<div id="t_history" class="card" style="display:none"></div><div id="t_settings" class="card" style="display:none"></div></main></div>
<script>
const $=id=>document.getElementById(id);
const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const hb=n=>{n=+n||0;for(const u of['B','KB','MB','GB','TB']){if(n<1024||u=='TB')return(u=='B'?n:n.toFixed(2))+' '+u;n/=1024}};
const dt=t=>t?new Date(t*1000).toLocaleString('fa-IR'):'-';
const dur=s=>{s=+s;const h=Math.floor(s/3600),m=Math.floor(s%3600/60);return(h?h+'س ':'')+m+'د'};
let tab='online',timer=null;
async function api(m,p,b){const r=await fetch(p,{method:m,headers:{'Content-Type':'application/json'},body:b?JSON.stringify(b):undefined});
 if(r.status==401){showLogin();throw 0}return r.json()}
function showLogin(){$('app').style.display='none';$('login').style.display='block';clearInterval(timer)}
async function login(){const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:$('lu').value,password:$('lp').value})});
 if(r.ok){init()}else{$('le').textContent='ورود ناموفق بود'}}
async function logout(){await fetch('/api/logout',{method:'POST'});showLogin()}
document.querySelectorAll('.tabs button').forEach(b=>b.onclick=()=>{tab=b.dataset.t;
 document.querySelectorAll('.tabs button').forEach(x=>x.classList.toggle('on',x==b));
 ['online','users','history','settings'].forEach(t=>$('t_'+t).style.display=t==tab?'':'none');refresh()});
async function refresh(){try{
 const s=await api('GET','/api/state');
 $('stats').innerHTML=[['اتصال فعال',s.online],['کاربر آنلاین',s.online_users],['کاربران مجاز',s.allowed+' / '+s.users]].map(x=>'<div class="stat"><span class="mut">'+x[0]+'</span><b>'+x[1]+'</b></div>').join('');
 $('hs').textContent=(s.mgmt_up?'OpenVPN ✓':'OpenVPN ✗ (قطع)')+' · همگام‌سازی: '+dt(s.last_sync)+(s.sync_error?' ⚠ '+s.sync_error:'');
 if(tab=='online')await rOnline();else if(tab=='users')await rUsers();else if(tab=='history')await rHistory();else await rSettings()}catch(e){}}
async function rOnline(){const d=await api('GET','/api/online');
 $('t_online').innerHTML='<table><tr><th>کاربر</th><th>IP متصل</th><th>IP داخلی</th><th>شروع اتصال</th><th>مدت</th><th>دریافت</th><th>ارسال</th><th>هم‌زمان</th><th></th></tr>'+
 (d.map(o=>'<tr><td>'+esc(o.user)+'</td><td class="ltr">'+esc(o.ip)+'</td><td class="ltr">'+esc(o.vip)+'</td><td>'+dt(o.since)+'</td><td>'+dur(o.duration)+'</td><td class="ltr">'+hb(o.rx)+'</td><td class="ltr">'+hb(o.tx)+'</td><td>'+o.count+'/'+(o.max||'∞')+'</td><td><button class="btn s d" data-k="'+esc(o.user)+'">قطع</button> <button class="btn s d" data-b="'+esc(o.user)+'">قطع+بن ۳۰د</button></td></tr>').join('')||'<tr><td colspan=9 class="mut">کسی آنلاین نیست</td></tr>')+'</table>';
 $('t_online').querySelectorAll('[data-k]').forEach(b=>b.onclick=async()=>{await api('POST','/api/kick',{user:b.dataset.k});setTimeout(refresh,1200)});
 $('t_online').querySelectorAll('[data-b]').forEach(b=>b.onclick=async()=>{await api('POST','/api/kick',{user:b.dataset.b,ban:30});setTimeout(refresh,1200)})}
async function rUsers(){const d=await api('GET','/api/users');
 $('t_users').innerHTML='<table><tr><th>کاربر</th><th>وضعیت</th><th>مصرف (پنل + OpenVPN)</th><th>حجم</th><th>انقضا</th><th>اتصال</th><th></th></tr>'+
 d.map(u=>'<tr><td>'+esc(u.user)+'</td><td><span class="b '+(u.ok?'ok':'bad')+'">'+esc(u.reason_fa)+'</span></td><td class="ltr">'+hb(u.panel_used)+' + '+hb(u.ovpn_used)+'</td><td class="ltr">'+(u.limit?hb(u.limit):'∞')+'</td><td>'+(u.expire?dt(u.expire):'∞')+'</td><td>'+u.online+'/'+(u.max||'∞')+(u.override!=null?' *':'')+'</td><td>'+
 '<button class="btn s" data-a="limit" data-u="'+esc(u.user)+'">حد اتصال</button><button class="btn s" data-a="reset" data-u="'+esc(u.user)+'">ریست مصرف OVPN</button><button class="btn s" data-a="rotate" data-u="'+esc(u.user)+'">رمز جدید</button>'+(u.link?'<a class="btn s" target="_blank" href="'+esc(u.link)+'">صفحه کانفیگ/QR</a>':'')+'</td></tr>').join('')+'</table>';
 $('t_users').querySelectorAll('[data-a]').forEach(b=>b.onclick=async()=>{const u=b.dataset.u,a=b.dataset.a;
  if(a=='limit'){const v=prompt('حداکثر اتصال هم‌زمان برای '+u+' (عدد، 0=نامحدود، خالی=پیش‌فرض)');if(v===null)return;await api('POST','/api/limit',{user:u,limit:v})}
  else if(a=='reset'){if(!confirm('شمارنده مصرف OpenVPN صفر شود؟'))return;await api('POST','/api/reset',{user:u})}
  else if(a=='rotate'){if(!confirm('رمز عوض و کانفیگ قبلی باطل شود؟'))return;await api('POST','/api/rotate',{user:u})}
  refresh()})}
let hu='';
async function rHistory(){const d=await api('GET','/api/history?limit=300'+(hu?'&user='+encodeURIComponent(hu):''));
 $('t_history').innerHTML='<div class="row"><input id="hf" placeholder="فیلتر کاربر" value="'+esc(hu)+'"><button class="btn" onclick="hu=$(\'hf\').value;refresh()">اعمال</button></div><table><tr><th>کاربر</th><th>IP</th><th>اتصال</th><th>قطع</th><th>مدت</th><th>دریافت/ارسال</th><th>علت</th></tr>'+
 d.map(h=>'<tr><td>'+esc(h.username)+'</td><td class="ltr">'+esc(h.ip)+'</td><td>'+dt(h.connected)+'</td><td>'+(h.disconnected?dt(h.disconnected):'<b style="color:var(--ok)">آنلاین</b>')+'</td><td>'+dur((h.disconnected||Date.now()/1000)-h.connected)+'</td><td class="ltr">'+hb(h.rx)+' / '+hb(h.tx)+'</td><td>'+esc(h.reason||'')+'</td></tr>').join('')+'</table>'}
async function rSettings(){if($('t_settings').dataset.f)return;const g=await api('GET','/api/groups');
 const all=!g.selected.length||g.selected.some(x=>String(x).toLowerCase()=='all');
 $('t_settings').dataset.f=1;
 $('t_settings').innerHTML='<h3>گروه OpenVPN</h3><p class="mut">فقط کاربرانی که عضو گروه‌های انتخابی هستند اجازه اتصال دارند.</p><div class="row"><label><input type="checkbox" id="g_all" '+(all?'checked':'')+'> همه کاربران</label></div><div class="row">'+
 g.groups.map(x=>'<label><input type="checkbox" class="g" value="'+esc(x.id)+'" '+(!all&&(g.selected.map(String).includes(String(x.id))||g.selected.map(s=>String(s).toLowerCase()).includes(String(x.name).toLowerCase()))?'checked':'')+'> '+esc(x.name)+'</label>').join('')+'</div>'+
 '<h3>محدودیت اتصال هم‌زمان</h3><div class="row"><input id="mc" type="number" min="0" value="'+esc(g.max_conn)+'" style="width:90px"> <span class="mut">(0 = نامحدود)</span>'+
 '<select id="lp2"><option value="kick-oldest">قطع قدیمی‌ترین اتصال</option><option value="kick-newest">قطع اتصال جدید</option></select></div><button class="btn p" onclick="saveS()">ذخیره</button> <span id="sv" class="mut"></span>';
 $('lp2').value=g.limit_policy}
async function saveS(){const all=$('g_all').checked;const gs=all?[]:[...document.querySelectorAll('.g:checked')].map(x=>x.value);
 await api('POST','/api/settings',{groups:gs,max_conn:+$('mc').value,limit_policy:$('lp2').value});$('sv').textContent='ذخیره شد ✓'}
async function init(){$('login').style.display='none';$('app').style.display='block';await refresh();clearInterval(timer);timer=setInterval(refresh,5000)}
fetch('/api/state').then(r=>r.status==401?showLogin():init());
</script></body></html>"""


# ---------------------------------------------------------------------- run --
def sync_thread(core):
    while True:
        try:
            n = core.sync()
            log.info("synced: %d users allowed", n)
        except Exception as e:
            core.sync_error = str(e)[:160]
            log.error("sync failed: %s", e)
        core.wake.wait(int(core.cfg.get("interval", 30)))
        core.wake.clear()


def run_daemon(cfg):
    os.makedirs(SPOOL, exist_ok=True)
    core = Core(cfg)
    start_web(core)
    threading.Thread(target=sync_thread, args=(core,), daemon=True).start()
    tick = max(2, int(cfg.get("tick", 5)))
    while True:
        try:
            core.tick()
        except Exception as e:
            log.exception("tick failed: %s", e)
        time.sleep(tick)


# ---------------------------------------------------------------------- cli --
def cli_api(cfg, method, path, data=None):
    scheme = "https" if cfg.get("web_tls_cert") else "http"
    try:
        with open(BASE + "/internal.key") as f:
            key = f.read().strip()
        req = urllib.request.Request(
            "%s://127.0.0.1:%s%s" % (scheme, cfg["web_port"], path),
            data=json.dumps(data).encode() if data is not None else None, method=method,
            headers={"X-Internal-Key": key, "Content-Type": "application/json"})
        ctx = ssl._create_unverified_context() if scheme == "https" else None
        with urllib.request.urlopen(req, timeout=20, context=ctx) as r:
            return json.load(r)
    except (OSError, urllib.error.URLError) as e:
        sys.exit("cannot reach pg-ovpn daemon (is pg-ovpn-sync running?): %s" % e)


def table(rows, head):
    rows = [[str(c) for c in r] for r in rows]
    w = [max(len(h), *(len(r[i]) for r in rows)) if rows else len(h) for i, h in enumerate(head)]
    print("  ".join(h.ljust(w[i]) for i, h in enumerate(head)))
    for r in rows:
        print("  ".join(c.ljust(w[i]) for i, c in enumerate(r)))


def ts(t):
    return datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S") if t else "-"


def main():
    ap = argparse.ArgumentParser(prog="pg-ovpn")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for c in ("run", "once", "online", "users", "groups"):
        sub.add_parser(c)
    p = sub.add_parser("history"); p.add_argument("username", nargs="?"); p.add_argument("-n", type=int, default=30)
    p = sub.add_parser("kick"); p.add_argument("username"); p.add_argument("--ban", type=int, default=0, metavar="MINUTES")
    p = sub.add_parser("limit"); p.add_argument("username"); p.add_argument("value")
    for c in ("reset", "rotate", "link"):
        p = sub.add_parser(c); p.add_argument("username")
    p = sub.add_parser("set-groups"); p.add_argument("groups")
    p = sub.add_parser("show"); p.add_argument("username"); p.add_argument("--no-embed", action="store_true")
    args = ap.parse_args()

    cfg = load_cfg()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    if args.cmd == "run":
        run_daemon(cfg)
    elif args.cmd == "once":
        os.makedirs(SPOOL, exist_ok=True)
        core = Core(cfg)
        print("OK: %d users allowed" % core.sync())
    elif args.cmd == "show":
        core = Core(cfg)
        text = core.profile(args.username)
        if text is None:
            sys.exit("user '%s' not found (run: pg-ovpn once)" % args.username)
        if args.no_embed:
            text = re.sub(r"<auth-user-pass>.*?</auth-user-pass>\n", "", text, flags=re.S)
            print("password: %s" % core.password(args.username), file=sys.stderr)
        sys.stdout.write(text)
    elif args.cmd == "online":
        d = cli_api(cfg, "GET", "/api/online")
        table([(o["user"], o["ip"], o["vip"], ts(o["since"]), "%d/%s" % (o["count"], o["max"] or "inf"),
                hbytes_pair(o)) for o in d], ["USER", "IP", "VPN-IP", "SINCE", "CONN", "RX/TX"])
    elif args.cmd == "users":
        d = cli_api(cfg, "GET", "/api/users")
        table([(u["user"], u["reason"], hbytes(u["panel_used"]), hbytes(u["ovpn_used"]),
                hbytes(u["limit"]) if u["limit"] else "inf", ts(u["expire"]) if u["expire"] else "inf",
                "%d/%s" % (u["online"], u["max"] or "inf")) for u in d],
              ["USER", "STATE", "PANEL", "OVPN", "LIMIT", "EXPIRE", "CONN"])
    elif args.cmd == "history":
        d = cli_api(cfg, "GET", "/api/history?limit=%d%s" % (args.n, "&user=" + urllib.parse.quote(args.username) if args.username else ""))
        table([(h["username"], h["ip"], ts(h["connected"]), ts(h["disconnected"]) if h["disconnected"] else "ONLINE",
                hbytes(h["rx"]) + "/" + hbytes(h["tx"]), h["reason"] or "") for h in d],
              ["USER", "IP", "CONNECTED", "DISCONNECTED", "RX/TX", "REASON"])
    elif args.cmd == "kick":
        r = cli_api(cfg, "POST", "/api/kick", {"user": args.username, "ban": args.ban})
        print("disconnected %d session(s)" % r.get("kicked", 0))
    elif args.cmd == "limit":
        cli_api(cfg, "POST", "/api/limit", {"user": args.username, "limit": args.value})
        print("ok")
    elif args.cmd in ("reset", "rotate"):
        cli_api(cfg, "POST", "/api/" + args.cmd, {"user": args.username})
        print("ok")
    elif args.cmd == "groups":
        r = cli_api(cfg, "GET", "/api/groups")
        print("selected:", ", ".join(map(str, r["selected"])) or "all users")
        for g in r["groups"]:
            print("  [%s] %s" % (g["id"], g["name"]))
    elif args.cmd == "set-groups":
        gs = [] if args.groups.strip().lower() == "all" else [x.strip() for x in args.groups.split(",") if x.strip()]
        cli_api(cfg, "POST", "/api/settings", {"groups": gs})
        print("ok")
    elif args.cmd == "link":
        r = cli_api(cfg, "GET", "/api/links?user=" + urllib.parse.quote(args.username))
        for k in ("page", "config", "qr"):
            print("%-7s %s" % (k, r[k]))


def hbytes_pair(o):
    return hbytes(o["rx"]) + "/" + hbytes(o["tx"])



if __name__ == "__main__":
    main()
PYEOF
chmod 755 /usr/local/bin/pg-ovpn

# ---------------------------------------------------------------- firewall --
cat > /usr/local/bin/pg-ovpn-fw <<'FWEOF'
#!/bin/sh
# usage: pg-ovpn-fw up|down
SUBNET="@SUBNET@/24"; PORT="@PORT@"; PROTO="@PROTO@"; WEBPORT="@WEBPORT@"; WEBBIND="@WEBBIND@"
IFACE=$(ip -4 route show default | awk '{print $5; exit}')
ensure() { t=$1; c=$2; shift 2; iptables -t "$t" -C "$c" "$@" 2>/dev/null || iptables -t "$t" -I "$c" "$@"; }
remove() { t=$1; c=$2; shift 2; iptables -t "$t" -D "$c" "$@" 2>/dev/null || true; }
rules() {
  $1 nat POSTROUTING -s "$SUBNET" -o "$IFACE" -j MASQUERADE
  $1 filter INPUT -p "$PROTO" --dport "$PORT" -j ACCEPT
  [ "$WEBBIND" = "127.0.0.1" ] || $1 filter INPUT -p tcp --dport "$WEBPORT" -j ACCEPT
  $1 filter FORWARD -s "$SUBNET" -j ACCEPT
  $1 filter FORWARD -d "$SUBNET" -m state --state RELATED,ESTABLISHED -j ACCEPT
}
case "$1" in
  up) rules ensure ;;
  down) rules remove ;;
  *) echo "usage: $0 up|down"; exit 1 ;;
esac
FWEOF
sed -i "s|@SUBNET@|$OVPN_SUBNET|; s|@PORT@|$OVPN_PORT|; s|@PROTO@|$OVPN_PROTO|; s|@WEBPORT@|$WEB_PORT|; s|@WEBBIND@|$WEB_BIND|" /usr/local/bin/pg-ovpn-fw
chmod 755 /usr/local/bin/pg-ovpn-fw

echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-pg-openvpn.conf
sysctl -p /etc/sysctl.d/99-pg-openvpn.conf >/dev/null

# ----------------------------------------------------------------- systemd --
echo "[5/7] Creating services..."
cat > /etc/systemd/system/pg-ovpn-fw.service <<'EOF'
[Unit]
Description=PasarGuard OpenVPN firewall/NAT rules
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/pg-ovpn-fw up
ExecStop=/usr/local/bin/pg-ovpn-fw down

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/pg-ovpn-sync.service <<'EOF'
[Unit]
Description=PasarGuard <-> OpenVPN daemon (sync, accounting, dashboard)
After=network-online.target
Wants=network-online.target
Before=openvpn-server@pg.service

[Service]
ExecStart=/usr/local/bin/pg-ovpn run
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# the stock unit limits processes to 10, which can starve the auth/disconnect scripts
install -d /etc/systemd/system/openvpn-server@pg.service.d
printf '[Service]\nLimitNPROC=100\n' > /etc/systemd/system/openvpn-server@pg.service.d/override.conf

# first sync must succeed before we start accepting connections
echo "Testing panel connection..."
if ! /usr/local/bin/pg-ovpn once; then
  echo "ERROR: could not fetch users from the panel. Check PANEL_URL / credentials."
  echo "(Config saved in $BASE/sync.json; fix it and run: pg-ovpn once)"
  exit 1
fi

# --------------------------------------------------------- nginx sub snippet --
cat > "$BASE/nginx-sub-snippet.conf" <<EOF
# Add inside the server{} block that serves your PasarGuard subscription domain.
# Then   https://YOUR-SUB-DOMAIN/sub/<token>/ovpn   downloads that user's .ovpn
# and    https://YOUR-SUB-DOMAIN/sub/<token>/ovpn/page   shows the page with QR code.
EOF
SCHEME=http; [ -n "$WEB_TLS_CERT" ] && SCHEME=https
cat >> "$BASE/nginx-sub-snippet.conf" <<EOF
location ~ ^/sub/([^/]+)/ovpn\$ {
    proxy_pass $SCHEME://127.0.0.1:$WEB_PORT/ovpn/\$1/config.ovpn;
    proxy_set_header Host \$host;
    proxy_set_header X-Forwarded-Proto \$scheme;
}
location ~ ^/sub/([^/]+)/ovpn/page\$ {
    proxy_pass $SCHEME://127.0.0.1:$WEB_PORT/ovpn/\$1;
    proxy_set_header Host \$host;
    proxy_set_header X-Forwarded-Proto \$scheme;
}
EOF

systemctl daemon-reload
systemctl enable pg-ovpn-fw.service pg-ovpn-sync.service
systemctl restart pg-ovpn-fw.service pg-ovpn-sync.service
systemctl enable openvpn-server@pg.service
systemctl restart openvpn-server@pg.service

# --------------------------------------------------------------------- done --
echo "[6/7] Verifying services..."
sleep 3
systemctl is-active --quiet openvpn-server@pg.service && echo "  openvpn: running" || echo "  openvpn: NOT running (journalctl -u openvpn-server@pg)"
systemctl is-active --quiet pg-ovpn-sync.service && echo "  pg-ovpn: running" || echo "  pg-ovpn: NOT running (journalctl -u pg-ovpn-sync)"

echo "[7/7] Done."
WEB_URL="${WEB_BASE_URL:-$SCHEME://$PUBLIC_HOST:$WEB_PORT}"
WEBHOOK_SECRET="$(python3 -c 'import json;print(json.load(open("/etc/pg-openvpn/sync.json"))["webhook_secret"])')"
cat <<EOF

OpenVPN is running on $PUBLIC_HOST:$OVPN_PORT/$OVPN_PROTO
Panel sync every ${SYNC_INTERVAL}s · max simultaneous connections per user: $MAX_CONN ($LIMIT_POLICY)
Allowed panel group(s): ${OVPN_GROUPS:-all users}

Admin dashboard (login = your PasarGuard admin account):
  $WEB_URL/admin
Per-user config page / direct .ovpn / QR (token = the last part of the user's sub link):
  $WEB_URL/ovpn/<token>   ·   $WEB_URL/ovpn/<token>/config.ovpn
  pg-ovpn link USERNAME   # prints the three URLs for one user
Sub-link style URLs (optional, needs nginx):  see $BASE/nginx-sub-snippet.conf
Instant sync on user create/edit (optional): add a webhook in PasarGuard:
  URL    $WEB_URL/webhook
  secret $WEBHOOK_SECRET

CLI:
  pg-ovpn online | users | history [USER] | kick USER [--ban MIN] | limit USER N
  pg-ovpn reset USER | rotate USER | groups | set-groups NAME[,NAME]|all
  pg-ovpn show USERNAME > USERNAME.ovpn
  pg-ovpn once        # force a sync now

Useful:
  systemctl status openvpn-server@pg pg-ovpn-sync
  journalctl -u pg-ovpn-sync -f

Per-user connection limit can also be set from the panel: put  ovpn_limit=3  in the user's note.
Remember to open port $OVPN_PORT/$OVPN_PROTO and $WEB_PORT/tcp in your cloud firewall.
EOF
[ -z "$WEB_TLS_CERT" ] && echo "NOTE: the web service is plain HTTP. Set WEB_TLS_CERT/WEB_TLS_KEY or put it behind nginx/HTTPS (configs contain the user's password)."
exit 0
