from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_file
import socket, ssl, json, datetime, hashlib, re, io
import urllib.request, urllib.parse

app = Flask(__name__)
app.secret_key = "intelrecon_secret_2024"

# ── Users ─────────────────────────────────────────────────────────────────
USERS = {
    "admin":   hashlib.sha256("admin123".encode()).hexdigest(),
    "analyst": hashlib.sha256("analyst123".encode()).hexdigest(),
}

# In-memory history store per user  { username: [entry, ...] }
HISTORY = {}

# ── Curated domain database ───────────────────────────────────────────────
SAFE_DOMAINS = {
    "google.com", "github.com", "cloudflare.com", "microsoft.com",
    "amazon.com", "apple.com", "meta.com", "wikipedia.org", "stackoverflow.com",
    "mozilla.org", "python.org", "linux.org", "ubuntu.com", "debian.org",
    "nginx.com", "apache.org", "nodejs.org", "reactjs.org", "vuejs.org",
}

RISKY_DOMAINS = {
    "free-v-bucks-generator.xyz": {"reason": "Game currency scam", "type": "Scam"},
    "login-paypal-secure.tk":     {"reason": "PayPal phishing site", "type": "Phishing"},
    "win-iphone-prize.gq":        {"reason": "Prize scam / adware", "type": "Scam"},
    "bitcoin-doubler-now.top":    {"reason": "Crypto fraud scheme", "type": "Fraud"},
    "update-adobe-flash.click":   {"reason": "Malware delivery via fake update", "type": "Malware"},
    "amazon-security-alert.xyz":  {"reason": "Amazon credential phishing", "type": "Phishing"},
    "netflix-account-verify.tk":  {"reason": "Netflix phishing kit", "type": "Phishing"},
    "bank0famerica-login.com":     {"reason": "Typosquatting — bank phishing", "type": "Phishing"},
    "google-security-check.gq":   {"reason": "Google account harvesting", "type": "Phishing"},
    "download-free-antivirus.xyz": {"reason": "Fake AV / ransomware dropper", "type": "Malware"},
    "steam-free-games.top":        {"reason": "Steam credential stealer", "type": "Phishing"},
    "paypal-refund-service.click": {"reason": "Financial fraud", "type": "Fraud"},
    "covid19-relief-fund.tk":      {"reason": "Pandemic relief scam", "type": "Scam"},
    "microsoftsupport-helpdesk.xyz": {"reason": "Tech support scam", "type": "Scam"},
    "instagram-followers-free.gq": {"reason": "Credential harvesting via social bait", "type": "Phishing"},
}

# ── Helpers ───────────────────────────────────────────────────────────────
def safe_get(url, timeout=6):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "IntelRecon/2.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except Exception:
        return None

def resolve_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None

def get_dns_records(domain):
    records = {}
    try:
        import subprocess
        for rtype in ["A", "MX", "TXT", "NS", "AAAA"]:
            res = subprocess.run(["nslookup", f"-type={rtype}", domain],
                                 capture_output=True, text=True, timeout=5)
            lines = [l.strip() for l in res.stdout.splitlines()
                     if domain.lower() in l.lower() or ("=" in l and "Server" not in l)]
            records[rtype] = lines[:5] if lines else []
    except Exception:
        pass
    return records

def get_ssl_info(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            exp = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            days_left = (exp - datetime.datetime.utcnow()).days
            issuer = dict(x[0] for x in cert["issuer"])
            subject = dict(x[0] for x in cert["subject"])
            return {"valid": True, "issuer": issuer.get("organizationName", "Unknown"),
                    "subject": subject.get("commonName", domain),
                    "expires": cert["notAfter"], "days_left": days_left,
                    "status": "Valid" if days_left > 0 else "Expired"}
    except ssl.SSLCertVerificationError:
        return {"valid": False, "status": "Invalid / Self-signed", "issuer": "N/A",
                "expires": "N/A", "days_left": 0, "subject": domain}
    except Exception:
        return {"valid": False, "status": "No SSL / Unreachable", "issuer": "N/A",
                "expires": "N/A", "days_left": 0, "subject": domain}

def get_ip_info(ip):
    data = safe_get(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,lat,lon,query")
    if data and data.get("status") == "success":
        return data
    return {"country": "Unknown", "city": "Unknown", "isp": "Unknown",
            "org": "Unknown", "as": "Unknown", "lat": 0, "lon": 0}

def get_whois_info(domain):
    result = {"registrar": "N/A", "created": "N/A", "expires": "N/A",
              "updated": "N/A", "status": "N/A"}
    try:
        rdap = safe_get(f"https://rdap.org/domain/{domain}")
        if rdap:
            result["status"] = ", ".join(rdap.get("status", ["N/A"]))
            for ev in rdap.get("events", []):
                if ev.get("eventAction") == "registration":
                    result["created"] = ev.get("eventDate", "N/A")[:10]
                if ev.get("eventAction") == "expiration":
                    result["expires"] = ev.get("eventDate", "N/A")[:10]
                if ev.get("eventAction") == "last changed":
                    result["updated"] = ev.get("eventDate", "N/A")[:10]
            for entity in rdap.get("entities", []):
                if "registrar" in entity.get("roles", []):
                    vcard = entity.get("vcardArray", [])
                    if vcard and len(vcard) > 1:
                        for v in vcard[1]:
                            if v[0] == "fn":
                                result["registrar"] = v[3]
    except Exception:
        pass
    return result

def get_subdomains(domain):
    subs = []
    try:
        req = urllib.request.Request(
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            headers={"User-Agent": "IntelRecon/2.0"})
        with urllib.request.urlopen(req, timeout=8) as r:
            text = r.read().decode()
        for line in text.splitlines()[:15]:
            if "," in line:
                subs.append(line.split(",")[0].strip())
    except Exception:
        pass
    return subs[:12]

def check_reputation(domain):
    """Check against our curated risky domain list and heuristics."""
    rep = {"verdict": "Clean", "risk_type": "None", "reason": "No threats detected", "color": "green"}
    if domain in RISKY_DOMAINS:
        info = RISKY_DOMAINS[domain]
        rep["verdict"]   = "MALICIOUS"
        rep["risk_type"] = info["type"]
        rep["reason"]    = info["reason"]
        rep["color"]     = "red"
    elif domain in SAFE_DOMAINS:
        rep["verdict"]   = "Trusted"
        rep["risk_type"] = "None"
        rep["reason"]    = "Well-known trusted domain"
        rep["color"]     = "green"
    else:
        # Heuristic checks
        suspicious_tlds = [".xyz", ".top", ".click", ".loan", ".win", ".gq", ".tk", ".ml", ".cf"]
        if any(domain.endswith(t) for t in suspicious_tlds):
            rep["verdict"]   = "Suspicious"
            rep["risk_type"] = "Heuristic"
            rep["reason"]    = f"High-risk TLD detected: {domain.rsplit('.',1)[-1]}"
            rep["color"]     = "yellow"
        elif len(domain) > 35:
            rep["verdict"]   = "Suspicious"
            rep["risk_type"] = "Heuristic"
            rep["reason"]    = "Unusually long domain name"
            rep["color"]     = "yellow"
        elif sum(c.isdigit() for c in domain.split(".")[0]) > 4:
            rep["verdict"]   = "Suspicious"
            rep["risk_type"] = "Heuristic"
            rep["reason"]    = "Excessive digits in domain label"
            rep["color"]     = "yellow"
    return rep

def calc_risk_score(ssl_info, domain, reputation):
    score = 0
    if not ssl_info.get("valid"):
        score += 30
    elif ssl_info.get("days_left", 999) < 30:
        score += 15
    if reputation["color"] == "red":
        score += 60
    elif reputation["color"] == "yellow":
        score += 25
    suspicious_tlds = [".xyz", ".top", ".click", ".loan", ".win", ".gq", ".tk", ".ml", ".cf"]
    if any(domain.endswith(t) for t in suspicious_tlds):
        score += 20
    if len(domain) > 35:
        score += 10
    return min(score, 100)

# ── Routes ────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html", user=session["user"])

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        pw_hash  = hashlib.sha256(password.encode()).hexdigest()
        if username in USERS and USERS[username] == pw_hash:
            session["user"] = username
            return redirect(url_for("index"))
        error = "Invalid credentials. Try admin / admin123"
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))

@app.route("/investigate", methods=["POST"])
def investigate():
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    data   = request.get_json()
    target = re.sub(r"^https?://", "", data.get("target", "").strip().lower()).split("/")[0]
    if not target:
        return jsonify({"error": "No target provided"}), 400

    is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target))
    result = {"target": target, "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")}

    if is_ip:
        result["type"]    = "ip"
        result["ip"]      = target
        result["ip_info"] = get_ip_info(target)
        result["ssl"]     = get_ssl_info(target)
        result["reputation"] = {"verdict": "N/A (IP)", "risk_type": "None",
                                 "reason": "IP address — no domain reputation", "color": "blue"}
        result["risk_score"] = 10
    else:
        ip = resolve_ip(target)
        result["type"]       = "domain"
        result["ip"]         = ip or "Unresolved"
        result["whois"]      = get_whois_info(target)
        result["dns"]        = get_dns_records(target)
        result["ssl"]        = get_ssl_info(target)
        result["ip_info"]    = get_ip_info(ip) if ip else {}
        result["subdomains"] = get_subdomains(target)
        result["reputation"] = check_reputation(target)
        result["risk_score"] = calc_risk_score(result["ssl"], target, result["reputation"])

    # Save to history
    user = session["user"]
    if user not in HISTORY:
        HISTORY[user] = []
    entry = {
        "id":         len(HISTORY[user]) + 1,
        "target":     result["target"],
        "type":       result["type"],
        "ip":         result["ip"],
        "risk_score": result["risk_score"],
        "verdict":    result["reputation"]["verdict"],
        "timestamp":  result["timestamp"],
        "data":       result,
    }
    HISTORY[user].insert(0, entry)
    HISTORY[user] = HISTORY[user][:50]  # keep last 50

    return jsonify(result)

@app.route("/history", methods=["GET"])
def get_history():
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    user = session["user"]
    entries = HISTORY.get(user, [])
    return jsonify({"history": [{k: v for k, v in e.items() if k != "data"} for e in entries]})

@app.route("/history/<int:entry_id>", methods=["GET"])
def get_history_entry(entry_id):
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    user = session["user"]
    for entry in HISTORY.get(user, []):
        if entry["id"] == entry_id:
            return jsonify(entry["data"])
    return jsonify({"error": "Not found"}), 404

@app.route("/history/clear", methods=["POST"])
def clear_history():
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    HISTORY[session["user"]] = []
    return jsonify({"ok": True})

@app.route("/report/pdf", methods=["POST"])
def generate_pdf():
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                    Table, TableStyle, HRFlowable)
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT

    d = request.get_json()
    target = d.get("target", "Unknown")

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            leftMargin=20*mm, rightMargin=20*mm,
                            topMargin=20*mm, bottomMargin=20*mm)

    # ── Color palette
    C_BG     = colors.HexColor("#050c10")
    C_ACCENT = colors.HexColor("#00ffe0")
    C_DARK   = colors.HexColor("#0a141a")
    C_BORDER = colors.HexColor("#0d2a30")
    C_TEXT   = colors.HexColor("#c8e6ea")
    C_MUTED  = colors.HexColor("#4a7880")
    C_RED    = colors.HexColor("#ff4560")
    C_GREEN  = colors.HexColor("#00e676")
    C_YELLOW = colors.HexColor("#f5a623")
    C_WHITE  = colors.white

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TitleStyle", parent=styles["Normal"],
        fontSize=22, textColor=C_ACCENT, fontName="Helvetica-Bold",
        spaceAfter=4, alignment=TA_LEFT)
    sub_style = ParagraphStyle("SubStyle", parent=styles["Normal"],
        fontSize=9, textColor=C_MUTED, fontName="Helvetica", spaceAfter=2)
    section_style = ParagraphStyle("SectionStyle", parent=styles["Normal"],
        fontSize=11, textColor=C_ACCENT, fontName="Helvetica-Bold",
        spaceBefore=10, spaceAfter=6)
    label_style = ParagraphStyle("LabelStyle", parent=styles["Normal"],
        fontSize=8, textColor=C_MUTED, fontName="Helvetica")
    value_style = ParagraphStyle("ValueStyle", parent=styles["Normal"],
        fontSize=9, textColor=C_TEXT, fontName="Helvetica")
    body_style  = ParagraphStyle("BodyStyle", parent=styles["Normal"],
        fontSize=9, textColor=C_TEXT, fontName="Helvetica", leading=14)

    def section(title):
        return [Paragraph(title.upper(), section_style),
                HRFlowable(width="100%", thickness=0.5, color=C_BORDER)]

    def kv_table(rows, col_widths=None):
        if col_widths is None:
            col_widths = [55*mm, 110*mm]
        data = [[Paragraph(k, label_style), Paragraph(str(v), value_style)] for k, v in rows]
        t = Table(data, colWidths=col_widths)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,-1), C_DARK),
            ("ROWBACKGROUNDS", (0,0), (-1,-1), [C_DARK, colors.HexColor("#0d1e26")]),
            ("TEXTCOLOR",  (0,0), (-1,-1), C_TEXT),
            ("FONTNAME",   (0,0), (-1,-1), "Helvetica"),
            ("FONTSIZE",   (0,0), (-1,-1), 9),
            ("GRID",       (0,0), (-1,-1), 0.5, C_BORDER),
            ("LEFTPADDING",(0,0), (-1,-1), 8),
            ("RIGHTPADDING",(0,0),(-1,-1), 8),
            ("TOPPADDING", (0,0), (-1,-1), 5),
            ("BOTTOMPADDING",(0,0),(-1,-1), 5),
        ]))
        return t

    # ── Verdict color helper
    verdict = d.get("reputation", {}).get("verdict", "Unknown")
    v_color = C_GREEN if verdict in ("Clean", "Trusted") else (C_RED if verdict == "MALICIOUS" else C_YELLOW)
    risk    = d.get("risk_score", 0)
    r_color = C_GREEN if risk < 30 else (C_RED if risk >= 70 else C_YELLOW)

    story = []

    # ── Header banner
    header_data = [[
        Paragraph("INTELRECON TOOLKIT", ParagraphStyle("H", parent=styles["Normal"],
            fontSize=18, textColor=C_ACCENT, fontName="Helvetica-Bold")),
        Paragraph("OSINT Intelligence Report", ParagraphStyle("H2", parent=styles["Normal"],
            fontSize=10, textColor=C_MUTED, fontName="Helvetica", alignment=TA_RIGHT)),
    ]]
    header_tbl = Table(header_data, colWidths=[100*mm, 65*mm])
    header_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), C_BG),
        ("VALIGN",     (0,0), (-1,-1), "MIDDLE"),
        ("LEFTPADDING",(0,0), (-1,-1), 10),
        ("RIGHTPADDING",(0,0),(-1,-1), 10),
        ("TOPPADDING", (0,0), (-1,-1), 10),
        ("BOTTOMPADDING",(0,0),(-1,-1), 10),
        ("LINEBELOW",  (0,0), (-1,0), 1.5, C_ACCENT),
    ]))
    story.append(header_tbl)
    story.append(Spacer(1, 8*mm))

    # ── Summary banner
    sum_data = [[
        Paragraph(f"TARGET: {target}", ParagraphStyle("T", parent=styles["Normal"],
            fontSize=13, textColor=C_WHITE, fontName="Helvetica-Bold")),
        Paragraph(f"IP: {d.get('ip','N/A')}", ParagraphStyle("T2", parent=styles["Normal"],
            fontSize=10, textColor=C_TEXT, fontName="Helvetica")),
        Paragraph(f"RISK: {risk}%", ParagraphStyle("T3", parent=styles["Normal"],
            fontSize=13, textColor=r_color, fontName="Helvetica-Bold")),
        Paragraph(f"VERDICT: {verdict}", ParagraphStyle("T4", parent=styles["Normal"],
            fontSize=11, textColor=v_color, fontName="Helvetica-Bold")),
    ]]
    sum_tbl = Table(sum_data, colWidths=[60*mm, 40*mm, 30*mm, 35*mm])
    sum_tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,-1), C_DARK),
        ("LINEBELOW",    (0,0), (-1,-1), 0.5, C_BORDER),
        ("LEFTPADDING",  (0,0), (-1,-1), 8),
        ("RIGHTPADDING", (0,0), (-1,-1), 8),
        ("TOPPADDING",   (0,0), (-1,-1), 8),
        ("BOTTOMPADDING",(0,0), (-1,-1), 8),
        ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
    ]))
    story.append(sum_tbl)
    story.append(Spacer(1, 6*mm))

    # ── Timestamp / generated by
    story.append(Paragraph(
        f"Generated: {d.get('timestamp','N/A')}  |  Analyst: {session['user']}  |  Tool: IntelRecon v2.0",
        ParagraphStyle("TS", parent=styles["Normal"],
            fontSize=8, textColor=C_MUTED, fontName="Helvetica")))
    story.append(Spacer(1, 6*mm))

    # ── Reputation
    rep = d.get("reputation", {})
    story += section("Reputation & Threat Intelligence")
    story.append(Spacer(1, 2*mm))
    story.append(kv_table([
        ("Verdict",   rep.get("verdict",   "N/A")),
        ("Risk Type", rep.get("risk_type", "N/A")),
        ("Reason",    rep.get("reason",    "N/A")),
    ]))
    story.append(Spacer(1, 5*mm))

    # ── Whois
    if d.get("whois"):
        w = d["whois"]
        story += section("Whois / Registry Information")
        story.append(Spacer(1, 2*mm))
        story.append(kv_table([
            ("Registrar",    w.get("registrar", "N/A")),
            ("Created",      w.get("created",   "N/A")),
            ("Expires",      w.get("expires",   "N/A")),
            ("Last Updated", w.get("updated",   "N/A")),
            ("Status",       w.get("status",    "N/A")),
        ]))
        story.append(Spacer(1, 5*mm))

    # ── SSL
    ssl_d = d.get("ssl", {})
    story += section("SSL Certificate Analysis")
    story.append(Spacer(1, 2*mm))
    story.append(kv_table([
        ("Status",    ssl_d.get("status",    "N/A")),
        ("Issuer",    ssl_d.get("issuer",    "N/A")),
        ("Subject",   ssl_d.get("subject",   "N/A")),
        ("Expires",   ssl_d.get("expires",   "N/A")),
        ("Days Left", str(ssl_d.get("days_left", "N/A"))),
    ]))
    story.append(Spacer(1, 5*mm))

    # ── IP Intelligence
    ip_d = d.get("ip_info", {})
    if ip_d:
        story += section("IP & Geolocation Intelligence")
        story.append(Spacer(1, 2*mm))
        story.append(kv_table([
            ("IP Address", d.get("ip",            "N/A")),
            ("Country",    ip_d.get("country",    "N/A")),
            ("Region",     ip_d.get("regionName", "N/A")),
            ("City",       ip_d.get("city",       "N/A")),
            ("ISP",        ip_d.get("isp",        "N/A")),
            ("Org",        ip_d.get("org",        "N/A")),
            ("ASN",        ip_d.get("as",         "N/A")),
        ]))
        story.append(Spacer(1, 5*mm))

    # ── DNS
    dns = d.get("dns", {})
    if dns:
        story += section("DNS Records")
        story.append(Spacer(1, 2*mm))
        dns_rows = []
        for rtype in ["A", "MX", "NS", "TXT", "AAAA"]:
            records = dns.get(rtype, [])
            dns_rows.append((rtype, "\n".join(records) if records else "No records"))
        story.append(kv_table(dns_rows))
        story.append(Spacer(1, 5*mm))

    # ── Subdomains
    subs = d.get("subdomains", [])
    story += section("Subdomain Enumeration")
    story.append(Spacer(1, 2*mm))
    if subs:
        sub_text = "   |   ".join(subs)
        story.append(Paragraph(sub_text, body_style))
    else:
        story.append(Paragraph("No subdomains discovered.", body_style))
    story.append(Spacer(1, 8*mm))

    # ── Footer
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER))
    story.append(Spacer(1, 3*mm))
    story.append(Paragraph(
        "CONFIDENTIAL — IntelRecon Toolkit | For authorized security research only.",
        ParagraphStyle("Footer", parent=styles["Normal"],
            fontSize=7.5, textColor=C_MUTED, fontName="Helvetica", alignment=TA_CENTER)))

    doc.build(story)
    buf.seek(0)

    safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", target)
    filename  = f"IntelRecon_{safe_name}_{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
    return send_file(buf, mimetype="application/pdf",
                     as_attachment=True, download_name=filename)

@app.route("/tools-list", methods=["GET"])
def tools_list():
    return jsonify({"safe_domains": sorted(SAFE_DOMAINS),
                    "risky_domains": [{"domain": k, **v} for k, v in RISKY_DOMAINS.items()]})

if __name__ == "__main__":
    app.run(debug=True, port=5000)
