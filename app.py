"""
CYBERGENOME AI 2.0 - Full Enterprise SOC Platform
RBAC + IOC + Telegram Alerts + Domain Age WHOIS + PDF Reports
Default admin: admin / cybergenome2025
"""

import os
import re
import math
import hashlib
import sqlite3
import socket
import subprocess
import threading
from datetime import datetime
from functools import wraps

from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash

try:
    import joblib
    from sklearn.tree import DecisionTreeClassifier
except ImportError:
    joblib = None
    DecisionTreeClassifier = None

try:
    from ai_assistant import answer as assistant_answer
except Exception:
    def assistant_answer(msg, ctx=None):
        return {"reply": f"AI Copilot online. You asked: {msg}", "ts": datetime.now().strftime("%H:%M:%S")}

try:
    from behavior_ai import init_behavior_db, start_observer, observe_once, daily_summary
except Exception:
    def init_behavior_db():
        pass

    def start_observer(interval_sec=45):
        pass

    def observe_once(learn_procs=True):
        return {
            "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "features": {"cpu": 10, "mem": 35, "proc_count": 50, "conn_count": 10, "bytes_sent_delta": 0, "new_procs": 0},
            "score": 5, "level": 1, "label": "NORMAL", "reasons": [], "ai_note": "Observer ready",
        }

    def daily_summary():
        return {"date": datetime.now().strftime("%Y-%m-%d"), "samples": 0, "anomalies": 0, "avg_score": 0, "alerts": [], "model_meta": {}}

try:
    from endpoint_guard import list_processes, kill_process, quarantine_file, list_quarantine, startup_entries
except Exception:
    def list_processes(limit=50):
        return [{"pid": 100, "name": "system", "exe": "", "cpu": 1, "mem": 1, "risk": 1, "reasons": []}]

    def kill_process(pid):
        return {"ok": False, "msg": "Endpoint module unavailable"}

    def quarantine_file(path):
        return {"ok": False, "msg": "Endpoint module unavailable"}

    def list_quarantine():
        return []

    def startup_entries():
        return []

try:
    from threat_intel import check_url_ioc, check_hash_ioc, refresh_urlhaus_recent, intel_status
except Exception:
    def check_url_ioc(url):
        return {"matched": False, "source": None, "host": "", "message": "IOC offline", "risk_boost": 0, "tags": []}

    def check_hash_ioc(h):
        return {"matched": False, "source": None, "message": "Hash intel offline", "risk_boost": 0}

    def refresh_urlhaus_recent(force=True):
        return {"ok": False, "count": 0}

    def intel_status():
        return {"requests_installed": False, "feed_hosts": 0, "feed_fetched_at": None}

try:
    from upgrades import alert_high_threat, check_domain_age, telegram_configured
except Exception:
    def alert_high_threat(kind, target, score, analyst="SOC"):
        return False

    def check_domain_age(domain):
        return "N/A", 0, 0, ""

    def telegram_configured():
        return False

app = Flask(__name__)
app.secret_key = os.environ.get("CG_SECRET", "cybergenome_rbac_secret_2025")
app.config["UPLOAD_FOLDER"] = "uploads"
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

os.makedirs("uploads", exist_ok=True)
os.makedirs("database", exist_ok=True)
os.makedirs("models", exist_ok=True)
os.makedirs("quarantine", exist_ok=True)

DB = os.path.join("database", "cybergenome.db")

ACTIVE_DEVICES = []
REMOTE_AGENTS = {}
ISOLATED_DEVICES = set()
SCANNING_ACTIVE = False

KW = ["login", "verify", "account", "password", "secure", "update", "bank", "confirm", "signin", "wallet"]
EXT = [".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".scr", ".msi"]


def get_db():
    c = sqlite3.connect(DB, timeout=20)
    c.row_factory = sqlite3.Row
    return c


def ensure_column(cursor, table, col_name, col_type):
    try:
        cursor.execute(f"PRAGMA table_info({table})")
        cols = [row[1] for row in cursor.fetchall()]
        if col_name not in cols:
            cursor.execute(f"ALTER TABLE {table} ADD COLUMN {col_name} {col_type}")
    except Exception:
        pass


def init_db():
    c = get_db()
    cur = c.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'analyst',
            full_name TEXT DEFAULT '',
            email TEXT DEFAULT '',
            created_at TEXT
        )
    """)
    ensure_column(cur, "users", "full_name", "TEXT DEFAULT ''")
    ensure_column(cur, "users", "email", "TEXT DEFAULT ''")
    ensure_column(cur, "users", "role", "TEXT DEFAULT 'analyst'")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS url_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT, url TEXT, domain TEXT,
            has_https INTEGER, url_length INTEGER, subdomains INTEGER,
            suspicious_keywords INTEGER, has_at_symbol INTEGER,
            risk_score INTEGER, risk_classification TEXT, ai_prediction TEXT
        )
    """)
    ensure_column(cur, "url_scans", "mitre_id", "TEXT DEFAULT ''")
    ensure_column(cur, "url_scans", "ioc_matched", "INTEGER DEFAULT 0")
    ensure_column(cur, "url_scans", "ioc_source", "TEXT DEFAULT ''")
    ensure_column(cur, "url_scans", "scanned_by", "TEXT DEFAULT ''")
    ensure_column(cur, "url_scans", "domain_age", "TEXT DEFAULT ''")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS file_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT, filename TEXT, file_size INTEGER, file_extension TEXT,
            sha256_hash TEXT, entropy REAL, risk_score INTEGER, risk_classification TEXT
        )
    """)
    ensure_column(cur, "file_scans", "yara_matches", "TEXT DEFAULT ''")
    ensure_column(cur, "file_scans", "mitre_id", "TEXT DEFAULT ''")
    ensure_column(cur, "file_scans", "ioc_matched", "INTEGER DEFAULT 0")
    ensure_column(cur, "file_scans", "scanned_by", "TEXT DEFAULT ''")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS activity_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT, event_type TEXT, target TEXT, risk TEXT, message TEXT
        )
    """)

    if not cur.execute("SELECT id FROM users WHERE username=?", ("admin",)).fetchone():
        cur.execute(
            "INSERT INTO users (username, password, role, full_name, email, created_at) VALUES (?,?,?,?,?,?)",
            (
                "admin",
                generate_password_hash("cybergenome2025"),
                "admin",
                "SOC Administrator",
                "admin@cybergenome.local",
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ),
        )

    c.commit()
    c.close()


def add_log(etype, target="", risk="", msg=""):
    try:
        c = get_db()
        c.execute(
            "INSERT INTO activity_log (timestamp, event_type, target, risk, message) VALUES (?,?,?,?,?)",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), etype, target, risk, msg),
        )
        c.commit()
        c.close()
    except Exception:
        pass


def ctx_user():
    return {
        "current_user": session.get("user") or "Guest",
        "current_role": session.get("role") or "analyst",
        "is_admin": session.get("role") == "admin",
        "full_name": session.get("full_name") or session.get("user") or "Guest",
    }


def login_required(f):
    @wraps(f)
    def wrap(*a, **kw):
        if not session.get("logged_in"):
            return redirect(url_for("login_page"))
        return f(*a, **kw)
    return wrap


def admin_required(f):
    @wraps(f)
    def wrap(*a, **kw):
        if not session.get("logged_in"):
            return redirect(url_for("login_page"))
        if session.get("role") != "admin":
            add_log("ACCESS_DENIED", session.get("user", "?"), "HIGH", f"Blocked {request.path}")
            return render_template("access_denied.html", **ctx_user()), 403
        return f(*a, **kw)
    return wrap


def get_windows_security_events():
    events = []
    try:
        c = get_db()
        rows = c.execute(
            "SELECT timestamp, event_type, target, risk, message FROM activity_log ORDER BY id DESC LIMIT 12"
        ).fetchall()
        c.close()
        for r in rows:
            events.append({
                "id": f"CG-{r['event_type']}",
                "type": r["risk"] or "INFO",
                "msg": f"{r['target'] or '-'} | {r['message'] or ''}",
                "time": r["timestamp"] or "",
            })
    except Exception:
        pass
    if not events:
        events = [{
            "id": "CG-SYSTEM", "type": "INFO", "msg": "SIEM online",
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }]
    return events[:12]


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def ping_host(ip):
    param = "-n" if os.name == "nt" else "-c"
    try:
        r = subprocess.run(
            ["ping", param, "1", "-w", "300", ip],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=1.0,
        )
        return r.returncode == 0
    except Exception:
        return False


def scan_network_worker(subnet):
    global ACTIVE_DEVICES, SCANNING_ACTIVE
    SCANNING_ACTIVE = True
    my_ip = get_local_ip()
    discovered = [{
        "ip": my_ip, "hostname": "Host Workstation", "ports": [80, 443, 5000],
        "risk": 5 if my_ip in ISOLATED_DEVICES else 1,
        "status": "isolated" if my_ip in ISOLATED_DEVICES else "safe", "type": "LOCAL",
    }]
    results = {}

    def worker(ip):
        if ping_host(ip):
            results[ip] = True

    threads = []
    for i in range(2, 12):
        tip = f"{subnet}{i}"
        if tip == my_ip:
            continue
        t = threading.Thread(target=worker, args=(tip,))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    for ip in results:
        discovered.append({
            "ip": ip, "hostname": "Subnet Endpoint", "ports": [80],
            "risk": 5 if ip in ISOLATED_DEVICES else 1,
            "status": "isolated" if ip in ISOLATED_DEVICES else "safe", "type": "LOCAL",
        })
    ACTIVE_DEVICES = discovered
    SCANNING_ACTIVE = False


def run_network_scan():
    global SCANNING_ACTIVE
    if SCANNING_ACTIVE:
        return
    my_ip = get_local_ip()
    subnet = "192.168.1." if my_ip == "127.0.0.1" else ".".join(my_ip.split(".")[:3]) + "."
    threading.Thread(target=scan_network_worker, args=(subnet,), daemon=True).start()


def train_model():
    if not joblib or not DecisionTreeClassifier:
        return None
    X = [[1, 20, 0, 0, 0], [1, 25, 0, 0, 0], [1, 55, 1, 1, 0], [0, 40, 1, 0, 0], [0, 100, 3, 2, 1], [0, 120, 4, 3, 1]]
    y = [0, 0, 1, 1, 2, 2]
    m = DecisionTreeClassifier(random_state=42)
    m.fit(X, y)
    joblib.dump(m, os.path.join("models", "threat_model.pkl"))
    return m


def load_model():
    if not joblib:
        return None
    p = os.path.join("models", "threat_model.pkl")
    return joblib.load(p) if os.path.exists(p) else train_model()


def predict(model, feats):
    if not model:
        return "LOW"
    try:
        return {0: "LOW", 1: "MEDIUM", 2: "HIGH"}.get(int(model.predict([feats])[0]), "LOW")
    except Exception:
        return "LOW"


ai_model = load_model()


def analyze_url(url):
    https = 1 if url.lower().startswith("https://") else 0
    d = url.lower().strip()
    if "://" in d:
        d = d.split("://", 1)[1]
    if "/" in d:
        d = d.split("/", 1)[0]
    if ":" in d:
        d = d.split(":", 1)[0]
    sub = max(0, len(d.split(".")) - 2)
    kw = sum(1 for k in KW if k in url.lower())
    at = 1 if "@" in url else 0

    s, r = 0, []
    if not https:
        s += 20
        r.append("HTTPS missing (+20)")
    if len(url) > 75:
        s += 15
        r.append("Long URL (+15)")
    if at:
        s += 20
        r.append("@ symbol (+20)")
    if sub >= 2:
        s += 10
        r.append("Multiple subdomains (+10)")
    if kw:
        s += 15
        r.append("Suspicious keywords (+15)")

    # Domain Age / WHOIS
    age_str, age_days, age_boost, age_reason = check_domain_age(d)
    if age_boost:
        s = min(100, s + age_boost)
        r.append(age_reason)

    s = min(100, s)
    if not r:
        r.append("No suspicious local indicators")

    # Global IOC
    ioc = check_url_ioc(url)
    if ioc.get("matched"):
        boost = int(ioc.get("risk_boost") or 40)
        s = min(100, s + boost)
        r.append(f"GLOBAL IOC MATCH (+{boost}) source={ioc.get('source')}")
        tags = ioc.get("tags") or []
        if tags:
            r.append("IOC tags: " + ", ".join(str(t) for t in tags[:6]))

    cl = "HIGH" if s >= 60 else ("MEDIUM" if s >= 30 else "LOW")
    return {
        "url": url,
        "domain": d,
        "has_https": https,
        "url_length": len(url),
        "subdomains": sub,
        "suspicious_keywords": kw,
        "has_at_symbol": at,
        "risk_score": s,
        "risk_classification": cl,
        "reasons": r,
        "domain_age": age_str,
        "mitre_id": "T1566.002 (Phishing Link)" if s >= 30 else "T1071 (Web Traffic)",
        "cyber_dna": {
            "https": "YES" if https else "NO",
            "url_length": len(url),
            "subdomains": sub,
            "suspicious_keywords": kw,
            "at_symbol": "YES" if at else "NO",
            "domain": d,
            "domain_age": age_str,
        },
        "ioc": ioc,
    }


def analyze_file(fp, fn):
    try:
        with open(fp, "rb") as f:
            data = f.read()
        sz = len(data)
        ext = os.path.splitext(fn)[1].lower()
        h = hashlib.sha256(data).hexdigest()
        ent = 0.0
        if sz:
            ent = round(
                -sum((data.count(x) / sz) * math.log2(data.count(x) / sz) for x in range(256) if data.count(x)),
                2,
            )
        s, r = 0, []
        if ext in EXT:
            s += 30
            r.append(f"Suspicious extension {ext} (+30)")
        if ent > 6:
            s += 20
            r.append("High entropy (+20)")
        ioc = check_hash_ioc(h)
        if ioc.get("matched"):
            boost = int(ioc.get("risk_boost") or 50)
            s = min(100, s + boost)
            r.append(str(ioc.get("message") or "Hash IOC match"))
        s = min(100, s)
        cl = "HIGH" if s >= 60 else ("MEDIUM" if s >= 30 else "LOW")
        if not r:
            r.append("No suspicious indicators")
        sd = f"{sz} B" if sz < 1024 else f"{sz / 1024:.1f} KB"
        return {
            "filename": fn,
            "file_size": sz,
            "file_size_display": sd,
            "file_extension": ext or "none",
            "sha256_hash": h,
            "entropy": ent,
            "risk_score": s,
            "risk_classification": cl,
            "reasons": r,
            "yara_matches": [],
            "mitre_id": "T1027 (Obfuscated)" if ent > 6 else "T1059 (Scripting)",
            "ioc": ioc,
        }
    except Exception as e:
        return {
            "filename": fn, "file_size": 0, "file_size_display": "0 B", "file_extension": "",
            "sha256_hash": "", "entropy": 0, "risk_score": 0, "risk_classification": "UNKNOWN",
            "reasons": [str(e)], "yara_matches": [], "mitre_id": "N/A",
            "ioc": {"matched": False, "message": "not checked"},
        }


def get_stats():
    c = get_db()
    try:
        ut = c.execute("SELECT COUNT(*) FROM url_scans WHERE risk_classification='HIGH'").fetchone()[0]
        ft = c.execute("SELECT COUNT(*) FROM file_scans WHERE risk_classification='HIGH'").fetchone()[0]
        lr = c.execute("SELECT risk_classification FROM url_scans ORDER BY id DESC LIMIT 1").fetchone()
        tu = c.execute("SELECT COUNT(*) FROM url_scans").fetchone()[0]
        tf = c.execute("SELECT COUNT(*) FROM file_scans").fetchone()[0]
        us = [dict(r) for r in c.execute("SELECT * FROM url_scans ORDER BY id DESC LIMIT 10").fetchall()]
        fs = [dict(r) for r in c.execute("SELECT * FROM file_scans ORDER BY id DESC LIMIT 10").fetchall()]
        al = [dict(r) for r in c.execute("SELECT * FROM activity_log ORDER BY id DESC LIMIT 20").fetchall()]
        cr = c.execute("SELECT domain, risk_score FROM url_scans ORDER BY id DESC LIMIT 10").fetchall()
        cl = [r[0][:20] for r in reversed(cr)]
        cd = [r[1] for r in reversed(cr)]
    except Exception:
        ut = ft = tu = tf = 0
        lr = ("NONE",)
        us = fs = al = cl = cd = []
    c.close()
    return ut + ft, (lr[0] if lr else "NONE"), tu, tf, us, fs, al, cl, cd


# ================= AUTH =================
@app.route("/register", methods=["GET", "POST"])
def register():
    if session.get("logged_in"):
        return redirect(url_for("home"))
    error = success = None
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "").strip()
        full_name = request.form.get("full_name", "").strip() or username
        email = request.form.get("email", "").strip()
        if len(username) < 3:
            error = "Username min 3 characters"
        elif not re.match(r"^[a-z0-9_]+$", username):
            error = "Username: only letters, numbers, underscore"
        elif len(password) < 6:
            error = "Password min 6 characters"
        else:
            c = get_db()
            if c.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone():
                error = f"Username '{username}' already exists"
            else:
                c.execute(
                    "INSERT INTO users (username,password,role,full_name,email,created_at) VALUES (?,?,?,?,?,?)",
                    (username, generate_password_hash(password), "analyst", full_name, email,
                     datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                )
                c.commit()
                add_log("USER_REGISTRATION", username, "SAFE", "New Analyst account")
                success = f"Account '{username}' created as Analyst. Please login."
            c.close()
    return render_template("register.html", error=error, success=success)


@app.route("/login", methods=["GET", "POST"])
def login_page():
    if session.get("logged_in"):
        return redirect(url_for("home"))
    error = None
    if request.method == "POST":
        user = request.form.get("username", "").strip().lower()
        pwd = request.form.get("password", "").strip()
        c = get_db()
        try:
            row = c.execute("SELECT * FROM users WHERE username=?", (user,)).fetchone()
        except Exception:
            init_db()
            row = c.execute("SELECT * FROM users WHERE username=?", (user,)).fetchone()
        c.close()
        if row and check_password_hash(row["password"], pwd):
            session.clear()
            session["logged_in"] = True
            session["user"] = row["username"]
            session["role"] = row["role"]
            session["user_id"] = row["id"]
            session["full_name"] = row["full_name"] or row["username"]
            add_log("LOGIN", user, "SAFE", f"role={row['role']}")
            return redirect(url_for("home"))
        error = "Invalid username or password"
        add_log("LOGIN_FAILED", user, "HIGH", "Bad credentials")
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    u = session.get("user", "")
    session.clear()
    if u:
        add_log("LOGOUT", u, "SAFE", "User logged out")
    return redirect(url_for("login_page"))


@app.route("/profile")
@login_required
def profile():
    c = get_db()
    u = c.execute(
        "SELECT id,username,role,full_name,email,created_at FROM users WHERE id=?",
        (session.get("user_id"),),
    ).fetchone()
    c.close()
    return render_template("profile.html", user=dict(u) if u else {}, **ctx_user())


@app.route("/admin/users")
@admin_required
def admin_users():
    c = get_db()
    users = [dict(r) for r in c.execute(
        "SELECT id,username,role,full_name,email,created_at FROM users ORDER BY id"
    ).fetchall()]
    c.close()
    return render_template("admin_users.html", users=users, msg=request.args.get("msg"), **ctx_user())


@app.route("/admin/users/<int:uid>/set-role", methods=["POST"])
@admin_required
def admin_set_role(uid):
    new_role = request.form.get("role", "").strip().lower()
    if new_role not in ("admin", "analyst"):
        return redirect(url_for("admin_users", msg="Invalid role"))
    c = get_db()
    target = c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not target:
        c.close()
        return redirect(url_for("admin_users", msg="User not found"))
    if target["role"] == "admin" and new_role == "analyst":
        admins = c.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0]
        if admins <= 1:
            c.close()
            return redirect(url_for("admin_users", msg="Cannot demote last admin"))
    c.execute("UPDATE users SET role=? WHERE id=?", (new_role, uid))
    c.commit()
    c.close()
    add_log("ACCESS_CHANGE", target["username"], "HIGH" if new_role == "admin" else "SAFE",
            f"{session.get('user')} set {target['username']} -> {new_role}")
    if target["username"] == session.get("user"):
        session["role"] = new_role
    return redirect(url_for("admin_users", msg=f"{target['username']} is now {new_role.upper()}"))


@app.route("/admin/users/<int:uid>/delete", methods=["POST"])
@admin_required
def admin_delete_user(uid):
    c = get_db()
    target = c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not target:
        c.close()
        return redirect(url_for("admin_users", msg="Not found"))
    if target["username"] == session.get("user"):
        c.close()
        return redirect(url_for("admin_users", msg="Cannot delete yourself"))
    if target["role"] == "admin":
        admins = c.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0]
        if admins <= 1:
            c.close()
            return redirect(url_for("admin_users", msg="Cannot delete last admin"))
    c.execute("DELETE FROM users WHERE id=?", (uid,))
    c.commit()
    c.close()
    add_log("USER_DELETED", target["username"], "HIGH", f"by {session.get('user')}")
    return redirect(url_for("admin_users", msg=f"Deleted {target['username']}"))


# ================= DASHBOARD =================
@app.route("/")
@login_required
def home():
    td, lr, tu, tf, us, fs, al, cl, cd = get_stats()
    return render_template(
        "index.html",
        threats_detected=td, latest_risk=lr, total_url_scans=tu, total_file_scans=tf,
        result=None, ai_prediction=None, cyber_dna=None, file_result=None, file_error=None,
        recent_url_scans=us, recent_file_scans=fs, activity_logs=al,
        chart_labels=cl, chart_data=cd, win_events=get_windows_security_events(),
        **ctx_user(),
    )


@app.route("/scan-url", methods=["POST"])
@login_required
def scan_url():
    url = request.form.get("url", "").strip()
    if not url:
        return redirect(url_for("home"))
    if not url.startswith("http"):
        url = "http://" + url

    r = analyze_url(url)
    ai = predict(ai_model, [r["has_https"], r["url_length"], r["subdomains"], r["suspicious_keywords"], r["has_at_symbol"]])
    who = session.get("user", "")
    ioc_m = 1 if r.get("ioc", {}).get("matched") else 0
    ioc_s = str(r.get("ioc", {}).get("source") or "")

    c = get_db()
    c.execute(
        """INSERT INTO url_scans
        (timestamp,url,domain,has_https,url_length,subdomains,suspicious_keywords,has_at_symbol,
         risk_score,risk_classification,ai_prediction,mitre_id,ioc_matched,ioc_source,scanned_by,domain_age)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"), r["url"], r["domain"], r["has_https"],
            r["url_length"], r["subdomains"], r["suspicious_keywords"], r["has_at_symbol"],
            r["risk_score"], r["risk_classification"], ai, r["mitre_id"], ioc_m, ioc_s, who,
            r.get("domain_age", ""),
        ),
    )
    scan_id = c.lastrowid
    c.commit()
    c.close()

    r["id"] = scan_id
    r["scanned_by"] = who
    add_log("URL_SCAN", r["domain"], r["risk_classification"], f"by {who} score={r['risk_score']}")

    # Telegram HIGH alert
    if r["risk_classification"] == "HIGH":
        alert_high_threat("URL/Phishing", r["domain"], r["risk_score"], who)

    td, lr, tu, tf, us, fs, al, cl, cd = get_stats()
    return render_template(
        "index.html",
        threats_detected=td, latest_risk=r["risk_classification"], total_url_scans=tu, total_file_scans=tf,
        result=r, ai_prediction=ai, cyber_dna=r["cyber_dna"], file_result=None, file_error=None,
        recent_url_scans=us, recent_file_scans=fs, activity_logs=al,
        chart_labels=cl, chart_data=cd, win_events=get_windows_security_events(),
        **ctx_user(),
    )


@app.route("/scan-file", methods=["POST"])
@login_required
def scan_file():
    if "file" not in request.files:
        return redirect(url_for("home"))
    f = request.files["file"]
    if not f.filename:
        return redirect(url_for("home"))
    safe = "".join(ch for ch in f.filename if ch.isalnum() or ch in "._-") or "upload.bin"
    fp = os.path.join(app.config["UPLOAD_FOLDER"], safe)
    f.save(fp)
    fr = analyze_file(fp, f.filename)
    who = session.get("user", "")
    ioc_m = 1 if fr.get("ioc", {}).get("matched") else 0

    c = get_db()
    c.execute(
        """INSERT INTO file_scans
        (timestamp,filename,file_size,file_extension,sha256_hash,entropy,risk_score,risk_classification,yara_matches,mitre_id,ioc_matched,scanned_by)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"), fr["filename"], fr.get("file_size", 0),
            fr["file_extension"], fr["sha256_hash"], fr["entropy"], fr["risk_score"],
            fr["risk_classification"], "None", fr["mitre_id"], ioc_m, who,
        ),
    )
    scan_id = c.lastrowid
    c.commit()
    c.close()

    fr["id"] = scan_id
    fr["scanned_by"] = who
    add_log("FILE_SCAN", f.filename, fr["risk_classification"], f"by {who}")

    if fr["risk_classification"] == "HIGH":
        alert_high_threat("Malware File", fr["filename"], fr["risk_score"], who)

    try:
        os.remove(fp)
    except Exception:
        pass

    td, lr, tu, tf, us, fs, al, cl, cd = get_stats()
    return render_template(
        "index.html",
        threats_detected=td, latest_risk=lr, total_url_scans=tu, total_file_scans=tf,
        result=None, ai_prediction=None, cyber_dna=None, file_result=fr, file_error=None,
        recent_url_scans=us, recent_file_scans=fs, activity_logs=al,
        chart_labels=cl, chart_data=cd, win_events=get_windows_security_events(),
        **ctx_user(),
    )


# ================= PDF / PRINT REPORT =================
@app.route("/report/<scan_type>/<int:scan_id>")
@login_required
def report_page(scan_type, scan_id):
    c = get_db()
    if scan_type.lower() == "url":
        row = c.execute("SELECT * FROM url_scans WHERE id=?", (scan_id,)).fetchone()
        st = "URL"
    else:
        row = c.execute("SELECT * FROM file_scans WHERE id=?", (scan_id,)).fetchone()
        st = "FILE"
    c.close()
    if not row:
        return "Report not found", 404
    scan = dict(row)
    if st == "URL" and not scan.get("domain_age"):
        age_str, _, _, _ = check_domain_age(scan.get("domain") or "")
        scan["domain_age"] = age_str
    return render_template("report.html", scan=scan, scan_type=st, **ctx_user())


@app.route("/endpoint")
@login_required
def endpoint_page():
    return render_template(
        "endpoint.html",
        procs=list_processes(),
        startups=startup_entries(),
        quarantine=list_quarantine(),
        summary=daily_summary(),
        live=observe_once(learn_procs=True),
        **ctx_user(),
    )


@app.route("/network")
@login_required
def network_page():
    run_network_scan()
    return render_template("network.html", **ctx_user())


@app.route("/tools/encode", methods=["GET", "POST"])
@login_required
def encode_tool():
    result = error = None
    if request.method == "POST":
        text = request.form.get("text", "")
        tool = request.form.get("tool", "base64")
        mode = request.form.get("mode", "encode")
        try:
            if tool == "base64":
                import base64
                result = base64.b64encode(text.encode()).decode() if mode == "encode" else base64.b64decode(text).decode()
            elif tool == "hex":
                result = text.encode().hex() if mode == "encode" else bytes.fromhex(text).decode()
            elif tool == "url":
                import urllib.parse
                result = urllib.parse.quote(text) if mode == "encode" else urllib.parse.unquote(text)
            elif tool == "rot13":
                import codecs
                result = codecs.encode(text, "rot_13")
            elif tool == "binary":
                if mode == "encode":
                    result = " ".join(format(b, "08b") for b in text.encode())
                else:
                    result = "".join(chr(int(b, 2)) for b in text.split())
        except Exception as e:
            error = str(e)
    return render_template("encode.html", result=result, error=error, **ctx_user())


# ================= APIs =================
@app.route("/api/assistant", methods=["POST"])
@login_required
def api_assistant():
    data = request.get_json(force=True, silent=True) or {}
    td, lr, *_ = get_stats()
    return jsonify(assistant_answer(data.get("message", ""), {"threats_detected": td, "latest_risk": lr}))


@app.route("/api/endpoint/kill", methods=["POST"])
@admin_required
def api_kill():
    data = request.get_json(force=True, silent=True) or {}
    if not data.get("confirm"):
        return jsonify({"ok": False, "msg": "confirm=true required"})
    res = kill_process(data.get("pid"))
    if res.get("ok"):
        add_log("KILL", str(data.get("pid")), "HIGH", f"by {session.get('user')}")
    return jsonify(res)


@app.route("/api/endpoint/quarantine", methods=["POST"])
@admin_required
def api_quar():
    data = request.get_json(force=True, silent=True) or {}
    res = quarantine_file(data.get("path", ""))
    if res.get("ok"):
        add_log("QUARANTINE", data.get("path", ""), "HIGH", f"by {session.get('user')}")
    return jsonify(res)


@app.route("/api/network")
@login_required
def api_net():
    if not ACTIVE_DEVICES:
        run_network_scan()
    return jsonify({
        "local_devices": ACTIVE_DEVICES,
        "remote_agents": list(REMOTE_AGENTS.values()),
        "scanning": SCANNING_ACTIVE,
        "my_ip": get_local_ip(),
        "is_admin": session.get("role") == "admin",
    })


@app.route("/api/attack", methods=["POST"])
@admin_required
def api_attack():
    data = request.get_json(force=True, silent=True) or {}
    target = data.get("target", "")
    if not target:
        return jsonify({"ok": False})
    ISOLATED_DEVICES.add(target)
    for d in ACTIVE_DEVICES:
        if d.get("ip") == target or d.get("hostname") == target:
            d["status"] = "isolated"
            d["risk"] = 5
    add_log("ISOLATION", target, "CRITICAL", f"by {session.get('user')}")
    return jsonify({"ok": True, "target": target, "predictions": {x["ip"]: 60 for x in ACTIVE_DEVICES if x.get("ip") != target}})


@app.route("/api/reset")
@admin_required
def api_reset():
    ISOLATED_DEVICES.clear()
    ACTIVE_DEVICES.clear()
    REMOTE_AGENTS.clear()
    run_network_scan()
    return jsonify({"ok": True})


@app.route("/api/agent/report", methods=["POST"])
def agent_report():
    data = request.get_json(force=True, silent=True) or {}
    agent_id = data.get("agent_id", "Remote-PC")
    REMOTE_AGENTS[agent_id] = {
        "hostname": agent_id,
        "os": data.get("os", "Unknown"),
        "public_ip": request.remote_addr,
        "cpu": data.get("cpu", 0),
        "ram": data.get("ram", 0),
        "last_seen": datetime.now().strftime("%H:%M:%S"),
        "risk": 5 if agent_id in ISOLATED_DEVICES or data.get("threat_detected") else 1,
        "status": "isolated" if agent_id in ISOLATED_DEVICES else ("threat" if data.get("threat_detected") else "safe"),
        "type": "REMOTE_CLOUD",
    }
    return jsonify({"status": "received", "command": "ISOLATE" if agent_id in ISOLATED_DEVICES else "MONITOR"})


@app.route("/api/intel/status")
@login_required
def api_intel_status():
    st = intel_status()
    st["telegram_configured"] = telegram_configured()
    return jsonify(st)


@app.route("/api/intel/refresh", methods=["GET", "POST"])
@admin_required
def api_intel_refresh():
    return jsonify({"refresh": refresh_urlhaus_recent(force=True), "status": intel_status()})


@app.route("/api/stats")
@login_required
def api_stats():
    td, lr, tu, tf, *_ = get_stats()
    return jsonify({"threats_detected": td, "latest_risk": lr, "total_url_scans": tu, "total_file_scans": tf})


# boot
init_db()
try:
    init_behavior_db()
    start_observer(interval_sec=45)
except Exception:
    pass

if __name__ == "__main__":
    add_log("SYSTEM", "CYBERGENOME", "NONE", "Server started with Telegram+WHOIS+PDF upgrades")
    print("Login: admin / cybergenome2025")
    print("Telegram configured:", telegram_configured())
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, host="0.0.0.0", port=port)