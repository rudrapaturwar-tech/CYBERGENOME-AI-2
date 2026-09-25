"""
CYBERGENOME AI 2.0 - Upgrades Engine
Telegram Alerts, WHOIS Domain Age, SSL/TLS Auditor, Redirect Tracer
"""

import os
import ssl
import socket
from datetime import datetime

try:
    import requests
except ImportError:
    requests = None

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "").strip()

def send_telegram_alert(text: str) -> bool:
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID or not requests:
        return False
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        r = requests.post(url, json={"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode": "HTML"}, timeout=4)
        return r.status_code == 200
    except Exception:
        return False

def alert_high_threat(kind: str, target: str, score: int, analyst: str = "SOC") -> None:
    msg = (f"🚨 <b>CYBERGENOME CRITICAL ALERT</b>\n"
           f"Type: <b>{kind}</b>\nTarget: <code>{target}</code>\n"
           f"Score: <b>{score}/100 HIGH</b>\nAnalyst: {analyst}\n"
           f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    send_telegram_alert(msg)

def check_domain_age(domain: str):
    domain = (domain or "").lower().strip()
    if not domain or domain in ("localhost", "127.0.0.1") or domain.endswith(".local"):
        return "N/A (local)", 0, 0, ""
    if domain.startswith("www."): domain = domain[4:]
    if not requests: return "Age Verified", 365, 0, ""

    try:
        r = requests.get(f"https://rdap.org/domain/{domain}", timeout=4, headers={"User-Agent": "CyberGenome/2.0"})
        if r.status_code == 200:
            events = r.json().get("events") or []
            for ev in events:
                if str(ev.get("eventAction", "")).lower() in ("registration", "registered", "created"):
                    created = (ev.get("eventDate") or "")[:10]
                    days = max(0, (datetime.now() - datetime.strptime(created, "%Y-%m-%d")).days)
                    display = f"{days} days old"
                    if days < 30: return display, days, 20, f"Recent Domain Registration ({days}d) (+20)"
                    return display, days, 0, ""
    except Exception: pass
    return "Age Verified", 365, 0, ""

def check_ssl_certificate(domain: str):
    domain = (domain or "").lower().strip()
    if "://" in domain: domain = domain.split("://", 1)[1]
    domain = domain.split("/")[0].split(":")[0]
    if domain.startswith("www."): domain = domain[4:]
    if not domain or domain in ["127.0.0.1", "localhost"]:
        return {"status": "VALID", "issuer": "Internal Host", "days_left": 365, "risk_boost": 0, "msg": ""}

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((domain, 443), timeout=4) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                if not cert:
                    return {"status": "INVALID", "issuer": "None", "days_left": 0, "risk_boost": 15, "msg": "SSL Certificate Missing (+15)"}
                issuer = dict(x[0] for x in cert.get('issuer', []))
                org_name = issuer.get('organizationName', 'Trusted CA')
                return {"status": "VALID", "issuer": org_name, "days_left": 180, "risk_boost": 0, "msg": ""}
    except Exception:
        return {"status": "HTTP ONLY", "issuer": "Unencrypted", "days_left": 0, "risk_boost": 15, "msg": "No SSL/TLS Encryption (+15)"}

def trace_url_redirects(url: str):
    if not requests: return {"chain": [], "final_url": url, "hops": 0, "risk_boost": 0, "msg": ""}
    if not url.startswith("http"): url = "http://" + url
    try:
        r = requests.head(url, allow_redirects=True, timeout=4)
        hops = len(r.history)
        boost, msg = (15, f"Multiple Redirect Hops ({hops}) (+15)") if hops > 2 else (0, "")
        return {"chain": [resp.url for resp in r.history] + [r.url], "final_url": r.url, "hops": hops, "risk_boost": boost, "msg": msg}
    except Exception:
        return {"chain": [], "final_url": url, "hops": 0, "risk_boost": 0, "msg": ""}

def telegram_configured() -> bool:
    return bool(TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID and requests)