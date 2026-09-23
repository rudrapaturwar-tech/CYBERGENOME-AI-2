import os, re, shutil, hashlib
from datetime import datetime

try:
    import psutil
except ImportError:
    psutil = None

QUARANTINE = os.path.join("quarantine")
os.makedirs(QUARANTINE, exist_ok=True)

SUSPICIOUS_NAME_RE = re.compile(r"(keygen|crack|miner|mimikatz|payload|backdoor|trojan|ransomware)", re.I)

def list_processes(limit=50):
    if psutil is None: return []
    out = []
    for p in psutil.process_iter(["pid", "name", "exe", "cpu_percent", "memory_percent"]):
        try:
            info = p.info
            name = info.get("name") or ""
            exe = info.get("exe") or ""
            cpu = float(info.get("cpu_percent") or 0)
            mem = float(info.get("memory_percent") or 0)
            risk = 1
            reasons = []
            if SUSPICIOUS_NAME_RE.search(name):
                risk = 4; reasons.append("Suspicious process name")
            if cpu >= 80:
                risk = max(risk, 3); reasons.append("Very High CPU Usage")
            out.append({"pid": info.get("pid"), "name": name, "exe": exe, "cpu": round(cpu, 1), "mem": round(mem, 1), "risk": risk, "reasons": reasons})
        except: continue
    out.sort(key=lambda x: (-x["risk"], -x["cpu"]))
    return out[:limit]

def kill_process(pid):
    if psutil is None: return {"ok": False, "msg": "psutil missing"}
    try:
        p = psutil.Process(int(pid))
        name = p.name()
        p.kill()
        return {"ok": True, "msg": f"Terminated PID {pid} ({name})"}
    except Exception as e:
        return {"ok": False, "msg": str(e)}

def quarantine_file(path):
    path = os.path.abspath(path)
    if not os.path.isfile(path): return {"ok": False, "msg": "File not found"}
    base = os.path.basename(path)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    dest = os.path.join(QUARANTINE, f"{ts}__{base}")
    try:
        shutil.move(path, dest)
        return {"ok": True, "msg": "Quarantined successfully", "dest": dest}
    except Exception as e:
        return {"ok": False, "msg": str(e)}

def list_quarantine():
    items = []
    for fn in sorted(os.listdir(QUARANTINE), reverse=True):
        fp = os.path.join(QUARANTINE, fn)
        if os.path.isfile(fp):
            items.append({"name": fn, "size": os.path.getsize(fp), "path": fp})
    return items[:30]

def startup_entries():
    entries = []
    startup = os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup")
    if os.path.isdir(startup):
        for fn in os.listdir(startup):
            entries.append({"name": fn, "path": os.path.join(startup, fn), "risk": 1, "reasons": ["User startup folder entry"]})
    return entries
