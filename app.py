#!/usr/bin/env python3
"""NetPush - discover network devices, check SSH reachability, push bulk config. GUI on :5050"""
import os, json, socket, sqlite3, subprocess, ipaddress, threading, time, re, shlex
from concurrent.futures import ThreadPoolExecutor
from flask import Flask, request, jsonify, Response
from cryptography.fernet import Fernet
import paramiko

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(BASE, "data"); os.makedirs(DATA, exist_ok=True)
DB = os.path.join(DATA, "netpush.db"); KEYF = os.path.join(DATA, "secret.key")
if not os.path.exists(KEYF):
    open(KEYF, "wb").write(Fernet.generate_key()); os.chmod(KEYF, 0o600)
FER = Fernet(open(KEYF, "rb").read())
USER = os.environ.get("NETPUSH_USER", "admin")
PASS = os.environ.get("NETPUSH_PASS", "admin")
PORT = int(os.environ.get("NETPUSH_PORT", "5050"))
app = Flask(__name__)

def db():
    c = sqlite3.connect(DB, timeout=20); c.row_factory = sqlite3.Row; return c
with db() as c:
    c.execute("""CREATE TABLE IF NOT EXISTS devices(id INTEGER PRIMARY KEY, name TEXT, ip TEXT UNIQUE,
      port INTEGER DEFAULT 22, type TEXT, username TEXT, password TEXT, status TEXT DEFAULT 'unknown',
      msg TEXT DEFAULT '', checked TEXT DEFAULT '')""")
    c.execute("CREATE TABLE IF NOT EXISTS jobs(id INTEGER PRIMARY KEY, created TEXT, commands TEXT, results TEXT, done INTEGER DEFAULT 0)")

@app.before_request
def auth():
    a = request.authorization
    if not a or a.username != USER or a.password != PASS:
        return Response("Login required", 401, {"WWW-Authenticate": 'Basic realm="NetPush"'})

# ---------- predefined scripts ----------
CISCO_LIKE = lambda cfg_in, cfg_out, save: {
    "Show version / uptime": "show version",
    "Show interface status": "show ip interface brief",
    "Show running config": "show running-config",
    "Set NTP server": cfg_in + "\nntp server pool.ntp.org\n" + cfg_out,
    "Set syslog server": cfg_in + "\nlogging host 192.168.1.10\n" + cfg_out,
    "Set login banner": cfg_in + "\nbanner motd #Authorized access only#\n" + cfg_out,
    "Create VLAN 100": cfg_in + "\nvlan 100\nname USERS\n" + cfg_out,
    "Save configuration": save}
TEMPLATES = {
    "cisco_ios": CISCO_LIKE("configure terminal", "end", "write memory"),
    "huawei": {"Show version": "display version", "Show interfaces": "display ip interface brief",
               "Show current config": "display current-configuration",
               "Set NTP server": "system-view\nntp-service unicast-server pool.ntp.org\nquit", "Save config": "save\ny"},
    "mikrotik": {"Show resource": "/system resource print", "Show interfaces": "/interface print",
                 "Set NTP client": "/system ntp client set enabled=yes servers=pool.ntp.org",
                 "Set identity": "/system identity set name=MyRouter", "Export config": "/export"},
    "juniper": {"Show version": "show version", "Show interfaces": "show interfaces terse",
                "Set NTP": "configure\nset system ntp server 162.159.200.1\ncommit and-quit"},
    "fortigate": {"System status": "get system status", "Interface list": "get system interface",
                  "Set NTP": "config system ntp\nset ntpsync enable\nset type fortiguard\nend"},
    "linux": {"System info": "uname -a; uptime; cat /etc/os-release",
              "Disk & memory": "df -h; free -m", "Listening ports": "ss -tulpn",
              "Update packages (apt)": "apt-get update && apt-get -y upgrade",
              "Restart SSH": "systemctl restart ssh || systemctl restart sshd",
              "Set DNS": "echo 'nameserver 1.1.1.1' > /etc/resolv.conf"},
    "other": {"Show version": "show version"}}
SHELL_TYPES = {"cisco_ios", "huawei", "mikrotik", "juniper", "fortigate", "other"}
BAD = re.compile(r"% ?Invalid|Invalid input|Incorrect command|Unknown command|Unrecognized command|syntax error|bad command|Error:|ambiguous|failure|expected end of command|no such command", re.I)

# ---------- SSH ----------
def enc(p): return FER.encrypt(p.encode()).decode()
def dec(p): return FER.decrypt(p.encode()).decode()

def connect(d, t=8):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(d["ip"], port=d["port"], username=d["username"], password=dec(d["password"]), timeout=t,
              banner_timeout=t, auth_timeout=t, look_for_keys=False, allow_agent=False)
    return c

def check(d):
    try:
        c = connect(d); c.close(); return "online", "SSH session established"
    except paramiko.AuthenticationException: return "auth_failed", "Login failed - check username/password"
    except Exception as e: return "offline", str(e)[:150]

def check_and_save(did):
    with db() as c:
        d = c.execute("SELECT * FROM devices WHERE id=?", (did,)).fetchone()
        if not d: return
    s, m = check(dict(d))
    with db() as c:
        c.execute("UPDATE devices SET status=?,msg=?,checked=? WHERE id=?", (s, m, time.strftime("%H:%M:%S"), did))

def read_shell(sh, idle=1.2, maxw=25):
    out, last, start = "", time.time(), time.time()
    while time.time() - last < idle and time.time() - start < maxw:
        if sh.recv_ready(): out += sh.recv(65535).decode(errors="ignore"); last = time.time()
        else: time.sleep(0.1)
    return out

def run_device(d, cmds, sudo):
    try: c = connect(d, 10)
    except paramiko.AuthenticationException: return {"ok": False, "output": "Authentication failed"}
    except Exception as e: return {"ok": False, "output": f"Connection failed: {e}"}
    out, ok = "", True
    try:
        if d["type"] == "linux":
            pw = dec(d["password"])
            for cmd in cmds:
                full = f"echo {shlex.quote(pw)} | sudo -S -p '' bash -c {shlex.quote(cmd)}" if sudo and d["username"] != "root" else f"bash -c {shlex.quote(cmd)}"
                _, so, se = c.exec_command(full, timeout=300)
                o, e, rc = so.read().decode(errors="ignore"), se.read().decode(errors="ignore"), so.channel.recv_exit_status()
                out += f"$ {cmd}\n{o}{e}[exit {rc}]\n\n"
                if rc != 0: ok = False
        else:
            sh = c.invoke_shell(width=250, height=1000); read_shell(sh, 1.5)
            if d["type"] == "cisco_ios": sh.send("terminal length 0\n"); read_shell(sh, 0.8)
            for cmd in cmds:
                sh.send(cmd + "\n"); o = read_shell(sh)
                out += f"> {cmd}\n{o}\n"
                if BAD.search(o): ok = False
    except Exception as e: out += f"\nError: {e}"; ok = False
    finally: c.close()
    return {"ok": ok, "output": out}

def run_job(jid, ids, cmds, sudo):
    with db() as c:
        devs = [dict(r) for r in c.execute(f"SELECT * FROM devices WHERE id IN ({','.join('?'*len(ids))})", ids)]
    res = {str(d["id"]): {"name": d["name"], "ip": d["ip"], "state": "running", "output": ""} for d in devs}
    def save(done=0):
        with db() as c: c.execute("UPDATE jobs SET results=?,done=? WHERE id=?", (json.dumps(res), done, jid))
    save()
    def work(d):
        r = run_device(d, cmds, sudo)
        res[str(d["id"])].update(state="success" if r["ok"] else "failed", output=r["output"]); save()
    with ThreadPoolExecutor(10) as ex: list(ex.map(work, devs))
    save(1)

# ---------- discovery ----------
def default_subnet():
    try:
        o = subprocess.check_output(["ip", "-o", "-4", "addr", "show", "scope", "global"], text=True)
        m = re.search(r"inet (\S+)", o)
        if m: return str(ipaddress.ip_interface(m.group(1)).network)
    except Exception: pass
    return "192.168.1.0/24"

def probe(ip):
    up = subprocess.call(["ping", "-c1", "-W1", ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
    ports = []
    for p in (22, 23, 80, 443, 8291):
        try: socket.create_connection((ip, p), 0.6).close(); ports.append(p); up = True
        except Exception: pass
    if not up: return None
    try: host = socket.gethostbyaddr(ip)[0]
    except Exception: host = ""
    return {"ip": ip, "host": host, "ports": ports}

@app.post("/api/discover")
def discover():
    try: net = ipaddress.ip_network(request.json.get("subnet", "").strip(), strict=False)
    except Exception: return jsonify(error="Invalid subnet"), 400
    if net.num_addresses > 1024: return jsonify(error="Max /22 (1024 hosts) per scan"), 400
    with ThreadPoolExecutor(100) as ex: found = [r for r in ex.map(probe, [str(i) for i in net.hosts()]) if r]
    mac = {}
    try:
        for l in subprocess.check_output(["ip", "neigh"], text=True).splitlines():
            p = l.split()
            if "lladdr" in p: mac[p[0]] = p[p.index("lladdr") + 1]
    except Exception: pass
    with db() as c: known = {r["ip"] for r in c.execute("SELECT ip FROM devices")}
    for f in found: f["mac"] = mac.get(f["ip"], ""); f["added"] = f["ip"] in known
    return jsonify(sorted(found, key=lambda x: ipaddress.ip_address(x["ip"])))

# ---------- API ----------
@app.get("/api/meta")
def meta(): return jsonify(templates=TEMPLATES, subnet=default_subnet())

@app.get("/api/devices")
def devices():
    with db() as c:
        return jsonify([{k: r[k] for k in r.keys() if k != "password"} for r in c.execute("SELECT * FROM devices ORDER BY ip")])

@app.post("/api/devices")
def add_device():
    j = request.json
    try:
        with db() as c:
            cur = c.execute("INSERT INTO devices(name,ip,port,type,username,password) VALUES(?,?,?,?,?,?)",
                (j["name"] or j["ip"], j["ip"].strip(), int(j.get("port") or 22), j["type"], j["username"], enc(j["password"])))
        threading.Thread(target=check_and_save, args=(cur.lastrowid,)).start()
        return jsonify(ok=True)
    except sqlite3.IntegrityError: return jsonify(error="IP already exists"), 400
    except Exception as e: return jsonify(error=str(e)), 400

@app.put("/api/devices/<int:i>")
def edit_device(i):
    j = request.json
    with db() as c:
        c.execute("UPDATE devices SET name=?,ip=?,port=?,type=?,username=? WHERE id=?",
                  (j["name"], j["ip"], int(j.get("port") or 22), j["type"], j["username"], i))
        if j.get("password"): c.execute("UPDATE devices SET password=? WHERE id=?", (enc(j["password"]), i))
    threading.Thread(target=check_and_save, args=(i,)).start()
    return jsonify(ok=True)

@app.delete("/api/devices/<int:i>")
def del_device(i):
    with db() as c: c.execute("DELETE FROM devices WHERE id=?", (i,))
    return jsonify(ok=True)

@app.post("/api/check")
def check_api():
    ids = request.json.get("ids")
    if not ids:
        with db() as c: ids = [r["id"] for r in c.execute("SELECT id FROM devices")]
    with ThreadPoolExecutor(20) as ex: list(ex.map(check_and_save, ids))
    return jsonify(ok=True)

@app.post("/api/push")
def push():
    j = request.json; ids = j.get("ids") or []
    cmds = [l.strip() for l in j.get("commands", "").splitlines() if l.strip()]
    if not ids or not cmds: return jsonify(error="Select devices and enter commands"), 400
    with db() as c:
        cur = c.execute("INSERT INTO jobs(created,commands,results) VALUES(?,?,?)", (time.strftime("%Y-%m-%d %H:%M:%S"), "\n".join(cmds), "{}"))
    threading.Thread(target=run_job, args=(cur.lastrowid, ids, cmds, bool(j.get("sudo")))).start()
    return jsonify(job=cur.lastrowid)

@app.get("/api/jobs")
def jobs():
    with db() as c: return jsonify([dict(id=r["id"], created=r["created"], commands=r["commands"][:80], done=r["done"]) for r in c.execute("SELECT * FROM jobs ORDER BY id DESC LIMIT 50")])

@app.get("/api/jobs/<int:i>")
def job(i):
    with db() as c: r = c.execute("SELECT * FROM jobs WHERE id=?", (i,)).fetchone()
    return jsonify(id=i, done=r["done"], commands=r["commands"], results=json.loads(r["results"]))

def monitor():
    while True:
        time.sleep(120)
        try:
            with db() as c: ids = [r["id"] for r in c.execute("SELECT id FROM devices")]
            with ThreadPoolExecutor(20) as ex: list(ex.map(check_and_save, ids))
        except Exception: pass

@app.get("/")
def index(): return Response(HTML, mimetype="text/html")

HTML = r"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetPush</title><style>
:root{--bg:#f5f7fa;--card:#fff;--tx:#1c2333;--mu:#6b7385;--bd:#e3e7ee;--ac:#2563eb;--ok:#16a34a;--er:#dc2626;--wa:#d97706}
@media(prefers-color-scheme:dark){:root{--bg:#0f141c;--card:#171e29;--tx:#e6eaf2;--mu:#8b95a8;--bd:#263042;--ac:#4f8cff}}
*{box-sizing:border-box}body{margin:0;font:14px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--tx)}
header{display:flex;align-items:center;gap:24px;padding:0 24px;background:var(--card);border-bottom:1px solid var(--bd);position:sticky;top:0;z-index:5}
header h1{font-size:17px;margin:0;padding:14px 0}header h1 b{color:var(--ac)}
nav button{background:none;border:0;padding:16px 14px;color:var(--mu);font:inherit;cursor:pointer;border-bottom:2px solid transparent}
nav button.on{color:var(--ac);border-color:var(--ac);font-weight:600}
main{max-width:1150px;margin:24px auto;padding:0 20px}.card{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:18px;margin-bottom:18px}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:12px}.row h2{margin:0;font-size:16px;flex:1}
button.b{background:var(--ac);color:#fff;border:0;border-radius:7px;padding:7px 14px;font:inherit;cursor:pointer}button.g{background:none;color:var(--tx);border:1px solid var(--bd)}button.b:disabled{opacity:.5}
input,select,textarea{font:inherit;padding:7px 10px;border:1px solid var(--bd);border-radius:7px;background:var(--bg);color:var(--tx);width:100%}textarea{font-family:ui-monospace,monospace;min-height:170px}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:9px 8px;border-bottom:1px solid var(--bd)}th{color:var(--mu);font-weight:500;font-size:12px;text-transform:uppercase}
.pill{padding:2px 9px;border-radius:99px;font-size:12px;font-weight:600}.online,.success{background:#16a34a22;color:var(--ok)}.offline,.failed{background:#dc262622;color:var(--er)}.auth_failed{background:#d9770622;color:var(--wa)}.unknown,.running{background:#6b738522;color:var(--mu)}
dialog{border:1px solid var(--bd);border-radius:12px;background:var(--card);color:var(--tx);width:420px;padding:22px}dialog::backdrop{background:#0006}dialog label{display:block;margin:10px 0 3px;color:var(--mu);font-size:12px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}@media(max-width:800px){.grid{grid-template-columns:1fr}}
pre{background:#0b1020;color:#cfe3ff;padding:12px;border-radius:8px;overflow:auto;max-height:320px;font-size:12px;margin:8px 0 0}
.res{border:1px solid var(--bd);border-radius:8px;padding:10px 14px;margin-bottom:10px}.res summary{cursor:pointer;display:flex;gap:12px;align-items:center}
.mu{color:var(--mu)}.hide{display:none}.dev{display:flex;gap:8px;align-items:center;padding:6px 0;border-bottom:1px solid var(--bd)}.dev input{width:auto}
</style></head><body>
<header><h1>Net<b>Push</b></h1><nav>
<button data-t="dev" class="on">Devices</button><button data-t="disc">Discovery</button><button data-t="push">Push Config</button><button data-t="hist">History</button></nav></header>
<main>
<section id="dev"><div class="card"><div class="row"><h2>Managed devices</h2><button class="b g" onclick="checkAll()">Re-check all</button><button class="b" onclick="openForm()">+ Add device</button></div>
<table><thead><tr><th>Name</th><th>IP:Port</th><th>Type</th><th>Status</th><th>Checked</th><th></th></tr></thead><tbody id="dt"></tbody></table></div></section>
<section id="disc" class="hide"><div class="card"><div class="row"><h2>Network discovery</h2><input id="sub" style="width:200px"><button class="b" id="scanb" onclick="scan()">Scan</button></div>
<p class="mu" id="sm">Scans for hosts via ping and common ports (22, 23, 80, 443, 8291).</p>
<table><thead><tr><th>IP</th><th>Hostname</th><th>MAC</th><th>Open ports</th><th></th></tr></thead><tbody id="st"></tbody></table></div></section>
<section id="push" class="hide"><div class="grid"><div class="card"><div class="row"><h2>1. Select devices</h2><button class="b g" onclick="selAll()">Select all online</button></div><div id="pd"></div></div>
<div class="card"><div class="row"><h2>2. Commands</h2></div>
<div class="row"><select id="ptype" onchange="fillT()"></select><select id="ptpl" onchange="fillC()"></select></div>
<textarea id="cmds" placeholder="One command per line. Pick a template or type your own."></textarea>
<div class="row" style="margin-top:12px"><label><input type="checkbox" id="sudo" style="width:auto"> Linux: run with sudo</label><span style="flex:1"></span><button class="b" id="runb" onclick="run()">Run on selected</button></div></div></div>
<div class="card hide" id="rc"><div class="row"><h2 id="rt">Results</h2></div><div id="rs"></div></div></section>
<section id="hist" class="hide"><div class="card"><div class="row"><h2>Job history</h2></div><table><thead><tr><th>#</th><th>Time</th><th>Commands</th><th></th></tr></thead><tbody id="ht"></tbody></table></div><div class="card hide" id="hc"><div id="hr"></div></div></section>
</main>
<dialog id="dlg"><h3 id="dt2" style="margin:0">Add device</h3><input type="hidden" id="f_id">
<label>Name</label><input id="f_name"><label>IP address</label><input id="f_ip"><label>SSH port</label><input id="f_port" value="22">
<label>Device type</label><select id="f_type"></select><label>Username</label><input id="f_user"><label>Password</label><input id="f_pw" type="password">
<div class="row" style="margin-top:16px;justify-content:flex-end"><button class="b g" onclick="dlg.close()">Cancel</button><button class="b" onclick="saveDev()">Save &amp; test</button></div></dialog>
<script>
const $=s=>document.querySelector(s),api=async(u,m='GET',b)=>{const r=await fetch(u,{method:m,headers:{'Content-Type':'application/json'},body:b?JSON.stringify(b):void 0});const j=await r.json();if(j.error)alert(j.error);return j};
const NAMES={cisco_ios:'Cisco IOS / similar',huawei:'Huawei VRP',mikrotik:'MikroTik',juniper:'Juniper',fortigate:'FortiGate firewall',linux:'Linux / open-source',other:'Other (SSH shell)'};
let devs=[],meta={};
const esc=s=>String(s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
document.querySelectorAll('nav button').forEach(b=>b.onclick=()=>{document.querySelectorAll('nav button').forEach(x=>x.classList.toggle('on',x==b));document.querySelectorAll('main section').forEach(s=>s.classList.toggle('hide',s.id!=b.dataset.t));if(b.dataset.t=='hist')loadHist();if(b.dataset.t=='push')renderPush()});
async function init(){meta=await api('/api/meta');$('#sub').value=meta.subnet;const o=Object.entries(NAMES).map(([k,v])=>`<option value="${k}">${v}</option>`).join('');$('#f_type').innerHTML=o;$('#ptype').innerHTML=o;fillT();load();setInterval(load,15000)}
async function load(){devs=await api('/api/devices');$('#dt').innerHTML=devs.map(d=>`<tr><td><b>${esc(d.name)}</b></td><td>${d.ip}:${d.port}</td><td>${NAMES[d.type]||d.type}</td><td><span class="pill ${d.status}" title="${esc(d.msg)}">${d.status=='online'?'Online · established':d.status.replace('_',' ')}</span></td><td class="mu">${d.checked||'-'}</td><td style="text-align:right"><button class="b g" onclick="chk(${d.id})">Test</button> <button class="b g" onclick='openForm(${JSON.stringify(d)})'>Edit</button> <button class="b g" onclick="del(${d.id})">✕</button></td></tr>`).join('')||'<tr><td colspan=6 class="mu">No devices yet. Use Discovery or Add device.</td></tr>';if(!$('#push').classList.contains('hide')&&!window.running)renderPush()}
function openForm(d){d=d||{};$('#dt2').textContent=d.id?'Edit device':'Add device';$('#f_id').value=d.id||'';$('#f_name').value=d.name||'';$('#f_ip').value=d.ip||'';$('#f_port').value=d.port||22;$('#f_type').value=d.type||'cisco_ios';$('#f_user').value=d.username||'';$('#f_pw').value='';$('#f_pw').placeholder=d.id?'(unchanged)':'';dlg.showModal()}
async function saveDev(){const id=$('#f_id').value,b={name:$('#f_name').value,ip:$('#f_ip').value,port:$('#f_port').value,type:$('#f_type').value,username:$('#f_user').value,password:$('#f_pw').value};const r=await api(id?'/api/devices/'+id:'/api/devices',id?'PUT':'POST',b);if(!r.error){dlg.close();setTimeout(load,300);setTimeout(load,3000)}}
async function del(i){if(confirm('Remove device?')){await api('/api/devices/'+i,'DELETE');load()}}
async function chk(i){await api('/api/check','POST',{ids:[i]});load()}
async function checkAll(){await api('/api/check','POST',{});load()}
async function scan(){$('#scanb').disabled=true;$('#sm').textContent='Scanning… this can take up to a minute.';const r=await api('/api/discover','POST',{subnet:$('#sub').value});$('#scanb').disabled=false;if(r.error)return;$('#sm').textContent=r.length+' hosts found';
$('#st').innerHTML=r.map(h=>`<tr><td>${h.ip}</td><td>${esc(h.host)||'-'}</td><td class="mu">${h.mac||'-'}</td><td>${h.ports.join(', ')||'ping only'}</td><td style="text-align:right">${h.added?'<span class="mu">Added</span>':`<button class="b g" onclick='openForm({ip:"${h.ip}",name:"${esc(h.host)||h.ip}",port:${h.ports.includes(22)?22:22}})'>Add</button>`}</td></tr>`).join('')}
function fillT(){const t=$('#ptype').value;$('#ptpl').innerHTML='<option value="">— custom / pick template —</option>'+Object.keys(meta.templates[t]||{}).map(k=>`<option>${k}</option>`).join('')}
function fillC(){const v=$('#ptpl').value;if(v)$('#cmds').value=meta.templates[$('#ptype').value][v]}
function renderPush(){const sel=new Set([...document.querySelectorAll('.pc:checked')].map(x=>x.value));$('#pd').innerHTML=devs.map(d=>`<label class="dev"><input type="checkbox" class="pc" value="${d.id}" ${d.status!='online'?'disabled':''} ${sel.has(String(d.id))?'checked':''}><span style="flex:1"><b>${esc(d.name)}</b> <span class="mu">${d.ip} · ${NAMES[d.type]}</span></span><span class="pill ${d.status}">${d.status.replace('_',' ')}</span></label>`).join('')||'<span class="mu">No devices</span>'}
function selAll(){document.querySelectorAll('.pc:not(:disabled)').forEach(c=>c.checked=true)}
function showRes(j,el){el.innerHTML=Object.values(j.results).map(r=>`<details class="res"><summary><b>${esc(r.name)}</b><span class="mu">${r.ip}</span><span class="pill ${r.state}">${r.state=='success'?'✔ Success':r.state=='failed'?'✘ Failed':'Running…'}</span></summary><pre>${esc(r.output||'waiting…')}</pre></details>`).join('')}
async function run(){const ids=[...document.querySelectorAll('.pc:checked')].map(c=>+c.value);if(!ids.length)return alert('Select at least one online device');if(!confirm('Run commands on '+ids.length+' device(s)?'))return;
const r=await api('/api/push','POST',{ids,commands:$('#cmds').value,sudo:$('#sudo').checked});if(r.error)return;window.running=1;$('#runb').disabled=true;$('#rc').classList.remove('hide');
const t=setInterval(async()=>{const j=await api('/api/jobs/'+r.job);$('#rt').textContent='Results – job #'+r.job+(j.done?' (finished)':' (running…)');showRes(j,$('#rs'));if(j.done){clearInterval(t);window.running=0;$('#runb').disabled=false}},1000)}
async function loadHist(){const h=await api('/api/jobs');$('#ht').innerHTML=h.map(j=>`<tr><td>${j.id}</td><td>${j.created}</td><td class="mu">${esc(j.commands)}</td><td><button class="b g" onclick="viewJ(${j.id})">View</button></td></tr>`).join('')}
async function viewJ(i){const j=await api('/api/jobs/'+i);$('#hc').classList.remove('hide');showRes(j,$('#hr'))}
init();
</script></body></html>"""

if __name__ == "__main__":
    threading.Thread(target=monitor, daemon=True).start()
    app.run(host="0.0.0.0", port=PORT, threaded=True)
