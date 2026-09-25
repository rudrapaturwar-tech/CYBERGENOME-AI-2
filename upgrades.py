"""
CYBERGENOME AI 2.0 - Upgrades Module
- Telegram Instant Alerts
- Domain Age / WHOIS (RDAP)
"""

import os
from datetime import datetime

try:
    import requests
except ImportError:
    requests = None

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "").strip()


def send_telegram_alert(text: str) -> bool:
    """Send HTML message to Telegram. Returns True if sent."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID or not requests:
        return False
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        r = requests.post(
            url,
            json={
                "chat_id": TELEGRAM_CHAT_ID,
                "text": text,
                "parse_mode": "HTML",
                "disable_web_page_preview": True,
            },
            timeout=5,
        )
        return r.status_code == 200
    except Exception:
        return False


def alert_high_threat(kind: str, target: str, score: int, analyst: str = "SOC") -> None:
    """Format + send HIGH threat alert."""
    msg = (
        f"🚨 <b>CYBERGENOME CRITICAL ALERT</b>\n"
        f"Type: <b>{kind}</b>\n"
        f"Target: <code>{target}</code>\n"
        f"Risk Score: <b>{score}/100 HIGH</b>\n"
        f"Analyst: {analyst}\n"
        f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )
    send_telegram_alert(msg)


def check_domain_age(domain: str):
    """
    Returns (age_display_str, age_days, risk_boost, reason).
    Uses public RDAP (no API key).
    """
    domain = (domain or "").lower().strip()
    if not domain or domain in ("localhost", "127.0.0.1") or domain.endswith(".local"):
        return "N/A (local)", 0, 0, ""

    # strip www.
    if domain.startswith("www."):
        domain = domain[4:]

    if not requests:
        return "WHOIS offline (install requests)", 0, 0, ""

    try:
        r = requests.get(
            f"https://rdap.org/domain/{domain}",
            timeout=4,
            headers={"User-Agent": "CYBERGENOME-AI-2.0-Academic/1.0", "Accept": "application/rdap+json"},
        )
        if r.status_code != 200:
            return "Age lookup unavailable", 0, 0, ""

        data = r.json()
        events = data.get("events") or []
        created = None
        for ev in events:
            if str(ev.get("eventAction", "")).lower() in ("registration", "registered", "created"):
                created = (ev.get("eventDate") or "")[:10]
                break

        if not created:
            return "Creation date unknown", 0, 0, ""

        reg = datetime.strptime(created, "%Y-%m-%d")
        days = max(0, (datetime.now() - reg).days)
        display = f"{days} days old (since {created})"

        if days < 7:
            return display, days, 25, f"Very new domain ({days} days) (+25)"
        if days < 30:
            return display, days, 15, f"New domain ({days} days) (+15)"
        if days < 90:
            return display, days, 5, f"Young domain ({days} days) (+5)"
        return display, days, 0, ""
    except Exception:
        return "Age lookup failed", 0, 0, ""


def telegram_configured() -> bool:
    return bool(TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID and requests)