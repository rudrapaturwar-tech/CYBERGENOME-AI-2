"""
CYBERGENOME AI 2.0 - ChatGPT / Claude Style Security Copilot
------------------------------------------------------------
Intelligent Conversational Security Assistant for SOC / EDR Platform
"""

import os
import re
import sqlite3
from datetime import datetime

# Internet Search Libraries
try:
    import wikipedia
    from duckduckgo_search import DDGS
except ImportError:
    wikipedia = None
    DDGS = None

DB = os.path.join("database", "cybergenome.db")

def _now():
    return datetime.now().strftime("%H:%M:%S")

# ============================================================
# Rich Security Knowledge Base (30+ Topics)
# ============================================================
KNOWLEDGE_BASE = {
    "phishing": (
        "<b>🎣 Phishing Attacks:</b><br>"
        "Phishing ek social engineering attack hai jisme attackers fake websites, emails, ya links ke zariye user ke credentials (passwords, OTP, banking details) churate hain.<br><br>"
        "<b>How CYBERGENOME protects against Phishing:</b><br>"
        "• <b>HTTPS Inspection:</b> Missing SSL certificates detect karta hai.<br>"
        "• <b>Domain Spoofing Detection:</b> URL mein `@` symbol aur excessive subdomains pakadta hai.<br>"
        "• <b>Keyword Analysis:</b> 'login', 'verify', 'bank', 'secure' jaise keywords analyze karta hai.<br>"
        "• <b>MITRE ATT&CK Mapping:</b> Technique <code>T1566.002</code> tag karta hai."
    ),
    "ransomware": (
        "<b>🦠 Ransomware Malware:</b><br>"
        "Ransomware ek dangerous malware hai jo user ke PC ki saari important files ko encrypt (lock) kar deta hai aur unhe unlock karne ke liye ransom (paise) maangta hai.<br><br>"
        "<b>Defensive Measures:</b><br>"
        "• <b>Endpoint Guard:</b> Suspicious executable scripts/processes ko detect aur kill karta hai.<br>"
        "• <b>Auto Quarantine:</b> High entropy files ko <code>quarantine/</code> folder mein safely move karta hai.<br>"
        "• <b>Behavior AI:</b> File system/memory changes ka anomaly score calculate karta hai."
    ),
    "mitre": (
        "<b>🎯 MITRE ATT&CK Framework:</b><br>"
        "MITRE ATT&CK ek globally recognized knowledge base hai jo real-world cyber attacks ke tactics aur techniques ko categorize karta hai.<br><br>"
        "<b>Mapped Techniques in System:</b><br>"
        "• <code>T1566.002</code>: Phishing via malicious URLs.<br>"
        "• <code>T1027</code>: Obfuscated/Encrypted file payloads (High Entropy).<br>"
        "• <code>T1059</code>: Command and Scripting Execution (PowerShell/CMD).<br>"
        "• <code>T1071</code>: Web application protocol communications."
    ),
    "edr": (
        "<b>🛡️ EDR (Endpoint Detection and Response):</b><br>"
        "EDR endpoints (laptops/servers) ko continuously monitor karta hai taaki malicious behavior detect ho sake.<br><br>"
        "<b>CYBERGENOME EDR Features:</b><br>"
        "• <b>Process Inspector:</b> Live running PIDs aur CPU/RAM usage display karta hai.<br>"
        "• <b>Confirmed Kill:</b> Suspicious PID ko terminate karta hai.<br>"
        "• <b>Safe Quarantine:</b> Files ko execute kiye bina isolate karta hai."
    ),
    "ueba": (
        "<b>🧠 UEBA (User & Entity Behavior Analytics):</b><br>"
        "UEBA system Machine Learning se host ke normal behavior (CPU, RAM, network connections, data transfer) ka baseline seekhta hai.<br><br>"
        "<b>AI Model:</b> Hum <code>IsolationForest</code> (Unsupervised ML) use karte hain jo abnormal resource spikes par automated security alerts generate karta hai."
    ),
    "cyber dna": (
        "<b>🧬 Cyber DNA Profiling:</b><br>"
        "Jaise human DNA se identity pata chalti hai, waise hi Cyber DNA har URL aur file ki security characteristics ka profile hai.<br><br>"
        "<b>DNA Parameters:</b> HTTPS Usage, URL Length, Subdomain Count, Suspicious Keyword Count, and `@` Symbol Presence."
    ),
    "yara": (
        "<b>🔍 YARA Rule Inspection:</b><br>"
        "YARA static malware inspection ke liye use hota hai. CYBERGENOME files ke binary content mein binary strings scan karta hai jaise <code>VirtualAlloc</code>, <code>CreateRemoteThread</code>, <code>mimikatz</code>, aur <code>powershell -enc</code>."
    ),
    "siem": (
        "<b>📊 SIEM (Security Information & Event Management):</b><br>"
        "SIEM centralized security event logging karta hai. CYBERGENOME Windows Event Log (Event ID 4624/4625) ko directly query karke live authentication stream dikhata hai."
    )
}

def auto_analyze_system():
    """Queries live database to generate a ChatGPT-style health audit report."""
    try:
        c = sqlite3.connect(DB)
        url_high = c.execute("SELECT COUNT(*) FROM url_scans WHERE risk_classification='HIGH'").fetchone()[0]
        file_high = c.execute("SELECT COUNT(*) FROM file_scans WHERE risk_classification='HIGH'").fetchone()[0]
        total_urls = c.execute("SELECT COUNT(*) FROM url_scans").fetchone()[0]
        total_files = c.execute("SELECT COUNT(*) FROM file_scans").fetchone()[0]
        last_url = c.execute("SELECT domain, risk_score, risk_classification FROM url_scans ORDER BY id DESC LIMIT 1").fetchone()
        c.close()

        report = f"🤖 <b>SOC Copilot System Audit ({_now()}):</b><br><br>"
        report += f"• <b>Total URLs Scanned:</b> {total_urls}<br>"
        report += f"• <b>Total Files Analyzed:</b> {total_files}<br>"
        report += f"• <b>High Risk Threats Detected:</b> {url_high + file_high}<br><br>"

        if last_url:
            report += f"📍 <b>Latest URL Inspection:</b> <code>{last_url[0]}</code> — Score: <b>{last_url[1]}/100</b> ({last_url[2]})<br><br>"

        if (url_high + file_high) == 0:
            report += "<b>✅ Security Posture:</b> EXCELLENT. All endpoints and scanned assets are clean. No critical threat vectors identified."
        else:
            report += "<b>🚨 Security Posture:</b> ACTION REQUIRED. High-risk threat vectors found. Please review Endpoint Guard and Network Command Center."

        return report
    except Exception as e:
        return f"System Analysis Error: {str(e)}"

def search_web_smart(query):
    """Smart targeted search that prevents irrelevant biographical results."""
    clean_query = query.strip()
    
    # Force cybersecurity context on web search
    search_term = f"cybersecurity {clean_query}"
    
    if DDGS:
        try:
            results = list(DDGS().text(search_term, max_results=1))
            if results and len(results) > 0:
                body = results[0].get('body', '')
                if body:
                    return f"<b>🌍 Cyber Intelligence Search:</b><br>{body}"
        except Exception:
            pass

    if wikipedia:
        try:
            wikipedia.set_lang("en")
            summary = wikipedia.summary(clean_query, sentences=2)
            # Check if summary is relevant
            if any(w in summary.lower() for w in ["security", "computer", "network", "data", "attack", "software", "system", "web", "internet", "code"]):
                return f"<b>🌍 Global Knowledge Base:</b><br>{summary}"
        except Exception:
            pass

    return f"I couldn't find a direct cybersecurity match for <i>'{clean_query}'</i>. Try asking about <b>phishing, ransomware, EDR, UEBA, MITRE, or type 'analyze system'</b>."

def answer(message, context=None):
    """
    Main ChatGPT / Claude style Conversational Engine.
    Handles Hinglish, English, System Commands, and Security Concepts cleanly.
    """
    text = (message or "").strip()
    if not text:
        return {"reply": "Hello! I am your <b>CYBERGENOME AI Copilot</b>. How can I help secure your network today?", "ts": _now()}

    lower = text.lower()

    # --- Conversational & Greetings ---
    if re.search(r"\b(hi|hello|hey|namaste|hii|hlo|helo|kaise ho|greetings)\b", lower):
        return {
            "reply": "Namaste! Main aapka <b>CYBERGENOME Security Copilot</b> hoon. 🤖<br><br>Main aapki kis cheez mein help karoon?<br>• <i>'analyze system'</i> — Full security health audit<br>• <i>'kya chal rha hai'</i> — Live status check<br>• Ask about <b>Phishing, Ransomware, EDR, MITRE, YARA</b>",
            "ts": _now()
        }

    # --- Status / "Kya chal rha" intents ---
    if any(k in lower for k in ["kya chal", "status", "haal chal", "report", "system check", "what's up", "what is happening"]):
        return {"reply": auto_analyze_system(), "ts": _now()}

    # --- System Analysis Intent ---
    if "analyze" in lower or "analysis" in lower or "audit" in lower:
        return {"reply": auto_analyze_system(), "ts": _now()}

    # --- Help / Command Menu ---
    if lower in ["help", "menu", "commands", "?", "options"]:
        return {
            "reply": (
                "<b>🤖 CYBERGENOME AI Copilot Assistance Guide:</b><br><br>"
                "• <b>analyze system</b> — Executes an automated audit of all database logs and threats.<br>"
                "• <b>what is phishing / ransomware / mitre / edr / ueba / yara / siem</b> — Deep-dive security concept explanations.<br>"
                "• <b>search [query]</b> — Fetches live threat intelligence from the web.<br>"
                "• <b>explain risk</b> — Details the scoring methodology (0-100)."
            ),
            "ts": _now()
        }

    # --- Risk Explanation Intent ---
    if "risk" in lower or "scoring" in lower:
        return {
            "reply": (
                "<b>📊 Risk Scoring Methodology:</b><br><br>"
                "🟢 <b>LOW RISK (0-29):</b> Asset exhibits standard security configurations.<br>"
                "🟡 <b>MEDIUM RISK (30-59):</b> Suspicious characteristics detected (e.g. missing HTTPS, long URL).<br>"
                "🔴 <b>HIGH RISK (60-100):</b> Critical indicators present (Domain spoofing, High Entropy, Malicious Extensions). Action required!"
            ),
            "ts": _now()
        }

    # --- Knowledge Base Matching ---
    for key, content in KNOWLEDGE_BASE.items():
        if key in lower or (key == "cyber dna" and "dna" in lower):
            return {"reply": content, "ts": _now()}

    # --- Live Web Search Trigger (explicit or fallback) ---
    if lower.startswith("search ") or lower.startswith("google "):
        query = re.sub(r"^(search|google)\s+", "", lower)
        return {"reply": search_web_smart(query), "ts": _now()}

    # Default Smart Fallback
    if len(text) > 3:
        return {"reply": search_web_smart(text), "ts": _now()}

    return {"reply": "Type <b>'help'</b> to see available security commands or ask me any question!", "ts": _now()}