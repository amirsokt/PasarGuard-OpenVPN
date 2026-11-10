#!/usr/bin/env bash
# =============================================================================
# OpenVPN for PasarGuard — installer + user sync
#
# What it does:
#   1. Installs OpenVPN and builds a small PKI (EC certs + tls-crypt key)
#   2. Authenticates clients with username/password (no per-user certs)
#   3. Runs a sync service that pulls users from the PasarGuard panel API:
#        - status "active"            -> allowed to connect
#        - disabled/limited/expired   -> denied, and kicked if connected
#   4. Gives you `pg-ovpn show <username>` to print a ready-to-import .ovpn
#
# Usage (as root):
#   PANEL_URL=https://panel.example.com:8000 \
#   PANEL_USER=admin PANEL_PASS='secret' \
#   bash install_openvpn_pasarguard.sh
#
# Optional env: PANEL_API_KEY, PANEL_INSECURE=1, OVPN_PORT=1194, OVPN_PROTO=udp|tcp,
#   OVPN_SUBNET=10.8.0.0, DNS1, DNS2, PUBLIC_HOST, SYNC_INTERVAL=60, ALLOW_MULTI=1
# =============================================================================
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "Please run as root."; exit 1; }

PANEL_URL="${PANEL_URL:-}"
PANEL_USER="${PANEL_USER:-}"
PANEL_PASS="${PANEL_PASS:-}"
PANEL_API_KEY="${PANEL_API_KEY:-}"
PANEL_INSECURE="${PANEL_INSECURE:-0}"
OVPN_PORT="${OVPN_PORT:-1194}"
OVPN_PROTO="${OVPN_PROTO:-udp}"
OVPN_SUBNET="${OVPN_SUBNET:-10.8.0.0}"
DNS1="${DNS1:-1.1.1.1}"
DNS2="${DNS2:-8.8.8.8}"
SYNC_INTERVAL="${SYNC_INTERVAL:-60}"
ALLOW_MULTI="${ALLOW_MULTI:-1}"
PUBLIC_HOST="${PUBLIC_HOST:-}"
MGMT_PORT=7505

[ -n "$PANEL_URL" ] || read -rp "Panel URL (e.g. https://panel.example.com:8000): " PANEL_URL
if [ -z "$PANEL_API_KEY" ]; then
  [ -n "$PANEL_USER" ] || read -rp "Panel admin username: " PANEL_USER
  [ -n "$PANEL_PASS" ] || { read -rsp "Panel admin password: " PANEL_PASS; echo; }
fi
case "$OVPN_PROTO" in udp|tcp) ;; *) echo "OVPN_PROTO must be udp or tcp"; exit 1;; esac

BASE=/etc/pg-openvpn
PKI=$BASE/pki

# ---------------------------------------------------------------- packages --
echo "[1/6] Installing packages..."
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y openvpn openssl python3 iproute2 curl iptables
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y epel-release || true
  dnf install -y openvpn openssl python3 iproute curl iptables
elif command -v yum >/dev/null 2>&1; then
  yum install -y epel-release || true
  yum install -y openvpn openssl python3 iproute curl iptables
else
  echo "Unsupported distro (need apt, dnf or yum)."; exit 1
fi

NOGROUP=nobody
getent group nogroup >/dev/null 2>&1 && NOGROUP=nogroup

if [ -z "$PUBLIC_HOST" ]; then
  PUBLIC_HOST="$(curl -fsS --max-time 8 https://api.ipify.org 2>/dev/null || true)"
fi
[ -n "$PUBLIC_HOST" ] || read -rp "Server public IP/domain: " PUBLIC_HOST

# --------------------------------------------------------------------- PKI --
echo "[2/6] Generating certificates..."
install -d -m 750 -o root -g "$NOGROUP" "$BASE"
install -d -m 700 "$PKI"
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

# ------------------------------------------------------------ sync config --
echo "[3/6] Writing configuration..."
export PANEL_URL PANEL_USER PANEL_PASS PANEL_API_KEY PANEL_INSECURE PUBLIC_HOST \
       OVPN_PORT OVPN_PROTO SYNC_INTERVAL MGMT_PORT NOGROUP BASE
python3 - <<'PYEOF'
import json, os, secrets
path = os.environ["BASE"] + "/sync.json"
old = {}
if os.path.exists(path):
    old = json.load(open(path))
cfg = {
    "panel_url": os.environ["PANEL_URL"],
    "panel_user": os.environ["PANEL_USER"],
    "panel_pass": os.environ["PANEL_PASS"],
    "api_key": os.environ["PANEL_API_KEY"],
    "insecure": os.environ["PANEL_INSECURE"] == "1",
    "host": os.environ["PUBLIC_HOST"],
    "port": int(os.environ["OVPN_PORT"]),
    "proto": os.environ["OVPN_PROTO"],
    "interval": int(os.environ["SYNC_INTERVAL"]),
    "mgmt_port": int(os.environ["MGMT_PORT"]),
    "group": os.environ["NOGROUP"],
    # keep the same secret across re-runs so existing user passwords stay valid
    "secret": old.get("secret") or secrets.token_hex(32),
}
with open(path, "w") as f:
    json.dump(cfg, f, indent=2)
os.chmod(path, 0o600)
PYEOF

MULTI_LINE=""
[ "$ALLOW_MULTI" = "1" ] && MULTI_LINE="duplicate-cn"
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
$MULTI_LINE

# username/password auth against the list synced from PasarGuard
verify-client-cert none
username-as-common-name
auth-user-pass-verify /usr/local/bin/pg-ovpn-auth via-file
script-security 2
management 127.0.0.1 $MGMT_PORT $BASE/mgmt.pass
EOF

# ------------------------------------------------------------ helper tools --
echo "[4/6] Installing helper tools..."
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

cat > /usr/local/bin/pg-ovpn <<'PYEOF'
#!/usr/bin/env python3
"""pg-ovpn: sync PasarGuard users into OpenVPN.

  pg-ovpn run             # daemon loop (used by systemd)
  pg-ovpn once            # single sync, prints how many users are active
  pg-ovpn show USERNAME   # print .ovpn profile (credentials embedded)
"""
import argparse, grp, hashlib, hmac, json, logging, os, socket, ssl, sys, time
import urllib.error, urllib.parse, urllib.request

BASE = "/etc/pg-openvpn"
CONF = BASE + "/sync.json"
USERS = BASE + "/users.json"
log = logging.getLogger("pg-ovpn")


def load_cfg():
    with open(CONF) as f:
        return json.load(f)


def derive_password(secret, username):
    return hmac.new(secret.encode(), username.encode(), hashlib.sha256).hexdigest()[:24]


def pw_hash(password):
    return hashlib.sha256(password.encode()).hexdigest()


class Panel:
    def __init__(self, cfg):
        self.url = cfg["panel_url"].rstrip("/")
        self.api_key = cfg.get("api_key") or ""
        self.username = cfg.get("panel_user") or ""
        self.password = cfg.get("panel_pass") or ""
        self.token = None
        self.ctx = ssl._create_unverified_context() if cfg.get("insecure") else None

    def _request(self, method, path, params=None, form=None, auth=True):
        url = self.url + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        data = urllib.parse.urlencode(form).encode() if form else None
        req = urllib.request.Request(url, data=data, method=method)
        if form:
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
        if auth:
            if self.api_key:
                req.add_header("X-Api-Key", self.api_key)
            else:
                if not self.token:
                    self.login()
                req.add_header("Authorization", "Bearer " + self.token)
        with urllib.request.urlopen(req, timeout=30, context=self.ctx) as resp:
            return json.load(resp)

    def login(self):
        r = self._request(
            "POST", "/api/admin/token",
            form={"username": self.username, "password": self.password}, auth=False,
        )
        self.token = r["access_token"]

    def get(self, path, params=None):
        try:
            return self._request("GET", path, params)
        except urllib.error.HTTPError as e:
            if e.code == 401 and not self.api_key:
                self.token = None  # token expired: log in again once
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


def write_db(cfg, db):
    tmp = USERS + ".tmp"
    with open(tmp, "w") as f:
        json.dump(db, f)
    os.chmod(tmp, 0o640)
    try:
        os.chown(tmp, 0, grp.getgrnam(cfg.get("group", "nogroup")).gr_gid)
    except (KeyError, PermissionError):
        pass
    os.replace(tmp, USERS)


def sync_once(cfg):
    users = Panel(cfg).users()
    active = {u["username"] for u in users if u.get("status") == "active"}
    write_db(cfg, {n: pw_hash(derive_password(cfg["secret"], n)) for n in active})
    return active


def _read_until(sock, marker, timeout=5):
    sock.settimeout(timeout)
    buf = b""
    try:
        while marker not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
    except socket.timeout:
        pass
    return buf.decode(errors="replace")


def kick_inactive(cfg, active):
    """Disconnect connected clients whose panel user is no longer active."""
    try:
        with open(BASE + "/mgmt.pass") as f:
            mgmt_pw = f.read().strip()
        s = socket.create_connection(("127.0.0.1", cfg["mgmt_port"]), timeout=5)
    except OSError:
        return  # OpenVPN not running yet
    try:
        _read_until(s, b"ENTER PASSWORD:")
        s.sendall((mgmt_pw + "\n").encode())
        _read_until(s, b"SUCCESS")
        s.sendall(b"status 3\n")
        status = _read_until(s, b"\nEND")
        names = set()
        for line in status.splitlines():
            if line.startswith("CLIENT_LIST\t"):
                name = line.split("\t")[1]
                if name and name != "UNDEF":
                    names.add(name)
        for name in names - active:
            log.info("kicking %s (no longer active)", name)
            s.sendall(("kill %s\n" % name).encode())
        s.sendall(b"quit\n")
    finally:
        s.close()


def profile(cfg, username, embed=True):
    with open(BASE + "/pki/ca.crt") as f:
        ca = f.read().strip()
    with open(BASE + "/pki/tc.key") as f:
        tc = f.read().strip()
    lines = [
        "client", "dev tun", "proto %s" % cfg["proto"],
        "remote %s %s" % (cfg["host"], cfg["port"]),
        "resolv-retry infinite", "nobind", "persist-key", "persist-tun",
        "remote-cert-tls server", "auth-user-pass", "auth SHA256",
        "cipher AES-256-GCM", "data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305",
        "verb 3",
    ]
    if cfg["proto"] == "udp":
        lines.append("explicit-exit-notify 1")
    lines += ["<ca>", ca, "</ca>", "<tls-crypt>", tc, "</tls-crypt>"]
    if embed:
        lines += ["<auth-user-pass>", username,
                  derive_password(cfg["secret"], username), "</auth-user-pass>"]
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser(prog="pg-ovpn")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("run")
    sub.add_parser("once")
    sp = sub.add_parser("show")
    sp.add_argument("username")
    sp.add_argument("--no-embed", action="store_true", help="don't embed credentials")
    args = ap.parse_args()

    cfg = load_cfg()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    if args.cmd == "once":
        active = sync_once(cfg)
        print("OK: %d active users synced" % len(active))
    elif args.cmd == "show":
        users = {u["username"]: u for u in Panel(cfg).users()}
        u = users.get(args.username)
        if not u:
            sys.exit("user '%s' not found in panel" % args.username)
        if u.get("status") != "active":
            print("warning: user status is '%s' - login will be denied" % u.get("status"), file=sys.stderr)
        sys.stdout.write(profile(cfg, args.username, embed=not args.no_embed))
        if args.no_embed:
            print("password: %s" % derive_password(cfg["secret"], args.username), file=sys.stderr)
    else:
        while True:
            try:
                active = sync_once(cfg)
                kick_inactive(cfg, active)
                log.info("synced: %d active users", len(active))
            except Exception as e:  # keep last good list on panel/network errors
                log.error("sync failed: %s", e)
            time.sleep(int(cfg.get("interval", 60)))


if __name__ == "__main__":
    main()
PYEOF
chmod 755 /usr/local/bin/pg-ovpn

# ---------------------------------------------------------------- firewall --
cat > /usr/local/bin/pg-ovpn-fw <<'FWEOF'
#!/bin/sh
# usage: pg-ovpn-fw up|down
SUBNET="@SUBNET@/24"; PORT="@PORT@"; PROTO="@PROTO@"
IFACE=$(ip -4 route show default | awk '{print $5; exit}')
ensure() { t=$1; c=$2; shift 2; iptables -t "$t" -C "$c" "$@" 2>/dev/null || iptables -t "$t" -I "$c" "$@"; }
remove() { t=$1; c=$2; shift 2; iptables -t "$t" -D "$c" "$@" 2>/dev/null || true; }
rules() {
  $1 nat POSTROUTING -s "$SUBNET" -o "$IFACE" -j MASQUERADE
  $1 filter INPUT -p "$PROTO" --dport "$PORT" -j ACCEPT
  $1 filter FORWARD -s "$SUBNET" -j ACCEPT
  $1 filter FORWARD -d "$SUBNET" -m state --state RELATED,ESTABLISHED -j ACCEPT
}
case "$1" in
  up) rules ensure ;;
  down) rules remove ;;
  *) echo "usage: $0 up|down"; exit 1 ;;
esac
FWEOF
sed -i "s|@SUBNET@|$OVPN_SUBNET|; s|@PORT@|$OVPN_PORT|; s|@PROTO@|$OVPN_PROTO|" /usr/local/bin/pg-ovpn-fw
chmod 755 /usr/local/bin/pg-ovpn-fw

echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-pg-openvpn.conf
sysctl -p /etc/sysctl.d/99-pg-openvpn.conf >/dev/null

# ----------------------------------------------------------------- systemd --
echo "[5/6] Creating services..."
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
Description=PasarGuard -> OpenVPN user sync
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

# the stock unit limits processes to 10, which can starve the auth script
install -d /etc/systemd/system/openvpn-server@pg.service.d
printf '[Service]\nLimitNPROC=100\n' > /etc/systemd/system/openvpn-server@pg.service.d/override.conf

# first sync must succeed before we start accepting connections
echo "Testing panel connection..."
if ! /usr/local/bin/pg-ovpn once; then
  echo "ERROR: could not fetch users from the panel. Check PANEL_URL / credentials."
  echo "(Config saved in $BASE/sync.json; fix it and run: pg-ovpn once)"
  exit 1
fi

systemctl daemon-reload
systemctl enable --now pg-ovpn-fw.service pg-ovpn-sync.service
systemctl enable openvpn-server@pg.service
systemctl restart openvpn-server@pg.service

# --------------------------------------------------------------------- done --
echo "[6/6] Done."
cat <<EOF

OpenVPN is running on $PUBLIC_HOST:$OVPN_PORT/$OVPN_PROTO
Users are synced from the panel every ${SYNC_INTERVAL}s.

Get a client profile for a panel user:
  pg-ovpn show USERNAME > USERNAME.ovpn

Useful:
  systemctl status openvpn-server@pg pg-ovpn-sync
  journalctl -u pg-ovpn-sync -f
  pg-ovpn once        # force a sync now

Remember to open port $OVPN_PORT/$OVPN_PROTO in your cloud firewall.
EOF
