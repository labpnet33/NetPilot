# NetPush
1. Upload & unzip:  `unzip netpush.zip && cd netpush`
2. Install:         `sudo bash install.sh`  (or `sudo bash install.sh MyPassword`)
3. Open:            `http://SERVER_IP:5050`

Manage: `systemctl status|restart|stop netpush` · logs: `journalctl -u netpush -f`
Data (devices, history, encryption key): `/opt/netpush/data/` — device passwords are stored encrypted (Fernet).
Targets need SSH enabled. Add more vendor scripts in the TEMPLATES dict in app.py.
