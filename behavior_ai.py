import os, json, sqlite3, threading, time
from datetime import datetime, date
from collections import Counter

try:
    import psutil
except ImportError:
    psutil = None

try:
    import joblib, numpy as np
    from sklearn.ensemble import IsolationForest
except ImportError:
    joblib, np, IsolationForest = None, None, None

DB = os.path.join("database", "cybergenome.db")
MODEL_PATH = os.path.join("models", "behavior_iforest.pkl")
META_PATH = os.path.join("models", "behavior_meta.json")

_lock = threading.Lock()
_observer_started = False
_last_net = None

def _conn():
    c = sqlite3.connect(DB, check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c

def init_behavior_db():
    c = _conn()
    c.execute("CREATE TABLE IF NOT EXISTS behavior_samples (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, cpu REAL, mem REAL, proc_count INTEGER, conn_count INTEGER, bytes_sent_delta REAL, new_procs INTEGER, score REAL, label TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS behavior_alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, level INTEGER, title TEXT, detail TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS known_procs (name TEXT PRIMARY KEY, first_seen TEXT, hits INTEGER)")
    c.commit(); c.close()

def snapshot_features():
    global _last_net
    if psutil is None:
        return {"cpu": 0, "mem": 0, "proc_count": 0, "conn_count": 0, "bytes_sent_delta": 0, "new_procs": 0, "proc_names": []}
    cpu = float(psutil.cpu_percent(interval=0.2))
    mem = float(psutil.virtual_memory().percent)
    procs = list(psutil.process_iter(["name"]))
    names = [p.info.get("name").lower() for p in procs if p.info.get("name")]
    proc_count = len(names)
    try: conn_count = len(psutil.net_connections(kind="inet"))
    except: conn_count = 0
    try:
        sent = float(psutil.net_io_counters().bytes_sent)
        delta = max(0.0, sent - _last_net) if _last_net is not None else 0.0
        _last_net = sent
    except: delta = 0.0
    c = _conn()
    known = {r[0] for r in c.execute("SELECT name FROM known_procs").fetchall()}
    c.close()
    new_procs = len([n for n in set(names) if n not in known]) if known else 0
    return {"cpu": cpu, "mem": mem, "proc_count": proc_count, "conn_count": conn_count, "bytes_sent_delta": delta, "new_procs": new_procs, "proc_names": names}

def _update_known_procs(names):
    c = _conn()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for n, hits in Counter(names).items():
        if not n: continue
        row = c.execute("SELECT hits FROM known_procs WHERE name=?", (n,)).fetchone()
        if row: c.execute("UPDATE known_procs SET hits=? WHERE name=?", (row[0] + hits, n))
        else: c.execute("INSERT INTO known_procs(name, first_seen, hits) VALUES (?,?,?)", (n, now, hits))
    c.commit(); c.close()

def rule_anomaly_score(feat):
    score, reasons = 0, []
    if feat["cpu"] >= 85: score += 25; reasons.append("CPU spike >= 85%")
    if feat["mem"] >= 85: score += 20; reasons.append("RAM usage >= 85%")
    if feat["conn_count"] >= 150: score += 20; reasons.append("High Network Connections")
    if feat["bytes_sent_delta"] >= 10 * 1024 * 1024: score += 25; reasons.append("High Data Transfer")
    if feat["new_procs"] >= 5: score += 20; reasons.append("New processes vs baseline")
    return min(100, score), reasons

def train_self():
    if not joblib or not IsolationForest or not np: return {"ok": False, "msg": "Libraries missing"}
    c = _conn()
    rows = c.execute("SELECT cpu, mem, proc_count, conn_count, bytes_sent_delta, new_procs FROM behavior_samples ORDER BY id DESC LIMIT 300").fetchall()
    c.close()
    if len(rows) < 20: return {"ok": False, "msg": f"Need >=20 samples, have {len(rows)}"}
    X = np.array([[r[0], r[1], r[2], r[3], r[4], r[5]] for r in rows], dtype=float)
    model = IsolationForest(n_estimators=50, contamination=0.08, random_state=42)
    model.fit(X)
    os.makedirs("models", exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    meta = {"trained_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "samples": len(rows)}
    with open(META_PATH, "w") as f: json.dump(meta, f)
    return {"ok": True, "msg": f"AI Trained on {len(rows)} samples", "meta": meta}

def ml_anomaly(feat):
    if not joblib or not os.path.exists(MODEL_PATH): return None, "NO_MODEL"
    try:
        model = joblib.load(MODEL_PATH)
        x = [[feat["cpu"], feat["mem"], feat["proc_count"], feat["conn_count"], feat["bytes_sent_delta"], feat["new_procs"]]]
        pred = int(model.predict(x)[0])
        dec = float(model.decision_function(x)[0])
        return pred, dec
    except: return None, "ERR"

def observe_once(learn_procs=True):
    init_behavior_db()
    feat = snapshot_features()
    if learn_procs and feat.get("proc_names"): _update_known_procs(feat["proc_names"])
    rule_score, reasons = rule_anomaly_score(feat)
    ml_pred, ml_info = ml_anomaly(feat)
    final = rule_score
    ai_note = "Rule Engine Baseline"
    if ml_pred == -1:
        final = min(100, rule_score + 25)
        ai_note = "Self-Trained AI: ANOMALY DETECTED"
        reasons.append("AI IsolationForest flagged anomaly")
    elif ml_pred == 1:
        ai_note = "Self-Trained AI: NORMAL PATTERN"

    level = 5 if final >= 70 else (4 if final >= 50 else (3 if final >= 30 else 1))
    label = "ANOMALY" if final >= 30 else "NORMAL"
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    c = _conn()
    c.execute("INSERT INTO behavior_samples (ts, cpu, mem, proc_count, conn_count, bytes_sent_delta, new_procs, score, label) VALUES (?,?,?,?,?,?,?,?,?)",
              (ts, feat["cpu"], feat["mem"], feat["proc_count"], feat["conn_count"], feat["bytes_sent_delta"], feat["new_procs"], final, label))
    if final >= 35:
        c.execute("INSERT INTO behavior_alerts(ts, level, title, detail) VALUES (?,?,?,?)", (ts, level, "Behavioral Anomaly", ai_note))
    c.commit(); c.close()

    return {"ts": ts, "features": {k: feat[k] for k in feat if k != "proc_names"}, "score": final, "level": level, "label": label, "reasons": reasons, "ai_note": ai_note}

def daily_summary():
    init_behavior_db()
    today = date.today().isoformat()
    c = _conn()
    rows = c.execute("SELECT score, label FROM behavior_samples WHERE ts LIKE ?", (today + "%",)).fetchall()
    alerts = c.execute("SELECT ts, level, title, detail FROM behavior_alerts WHERE ts LIKE ? ORDER BY id DESC LIMIT 10", (today + "%",)).fetchall()
    c.close()
    meta = {}
    if os.path.exists(META_PATH):
        try: meta = json.load(open(META_PATH))
        except: pass
    return {"date": today, "samples": len(rows), "anomalies": sum(1 for r in rows if r[1] == "ANOMALY"), "avg_score": round(sum(r[0] for r in rows)/len(rows), 1) if rows else 0, "alerts": [dict(ts=a[0], level=a[1], title=a[2], detail=a[3]) for a in alerts], "model_meta": meta}

def start_observer(interval_sec=45):
    global _observer_started
    with _lock:
        if _observer_started: return
        _observer_started = True
    def loop():
        init_behavior_db()
        while True:
            try: observe_once(learn_procs=True)
            except: pass
            time.sleep(interval_sec)
    threading.Thread(target=loop, daemon=True).start()
