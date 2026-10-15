#!/usr/bin/env bash
# NetPush installer - run as root:  sudo bash install.sh [gui_password]
set -e
[ "$EUID" -ne 0 ] && { echo "Run as root (sudo)"; exit 1; }
DIR=/opt/netpush; SRC="$(cd "$(dirname "$0")" && pwd)"
PW="${1:-$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 14)}"
echo "[1/5] Installing system packages"
if command -v apt-get >/dev/null; then apt-get update -y && apt-get install -y python3 python3-venv python3-pip iputils-ping iproute2 libffi-dev libssl-dev
elif command -v dnf >/dev/null; then dnf install -y python3 python3-pip iputils iproute libffi-devel openssl-devel
elif command -v yum >/dev/null; then yum install -y python3 python3-pip iputils iproute
else echo "Unsupported distro - install python3, pip, ping manually"; fi
echo "[2/5] Copying files to $DIR"
mkdir -p $DIR; cp "$SRC/app.py" "$SRC/requirements.txt" $DIR/
echo "[3/5] Creating virtualenv"
python3 -m venv $DIR/venv && $DIR/venv/bin/pip install -q --upgrade pip && $DIR/venv/bin/pip install -q -r $DIR/requirements.txt
echo "[4/5] Creating service"
cat > /etc/netpush.env <<E2
NETPUSH_USER=admin
NETPUSH_PASS=$PW
NETPUSH_PORT=5050
E2
chmod 600 /etc/netpush.env
cat > /etc/systemd/system/netpush.service <<E3
[Unit]
Description=NetPush network config tool
After=network-online.target
[Service]
EnvironmentFile=/etc/netpush.env
WorkingDirectory=$DIR
ExecStart=$DIR/venv/bin/python $DIR/app.py
Restart=always
[Install]
WantedBy=multi-user.target
E3
systemctl daemon-reload; systemctl enable --now netpush
echo "[5/5] Firewall"
command -v ufw >/dev/null && ufw status | grep -q active && ufw allow 5050/tcp || true
command -v firewall-cmd >/dev/null && systemctl is-active -q firewalld && { firewall-cmd --permanent --add-port=5050/tcp; firewall-cmd --reload; } || true
IP=$(hostname -I | awk '{print $1}')
echo; echo "=========================================="
echo " NetPush is running:  http://$IP:5050"
echo " Username: admin     Password: $PW"
echo " (change password in /etc/netpush.env then: systemctl restart netpush)"
echo "=========================================="
