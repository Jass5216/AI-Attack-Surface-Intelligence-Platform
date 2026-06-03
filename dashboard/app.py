import os
import sys
import json
import socket
import random
from datetime import datetime, timedelta

import pandas as pd
import streamlit as st
import validators

# =====================================================
# PROJECT PATH
# =====================================================

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(BASE_DIR)

from modules.realtime_scanner import run_realtime_scan

DATA_DIR = os.path.join(BASE_DIR, "data")

USERS_FILE = os.path.join(DATA_DIR, "users.json")
RESULT_FILE = os.path.join(DATA_DIR, "scan_results.json")
HISTORY_FILE = os.path.join(DATA_DIR, "scan_history.json")
AUDIT_FILE = os.path.join(DATA_DIR, "audit_logs.json")

os.makedirs(DATA_DIR, exist_ok=True)

# =====================================================
# PAGE CONFIG
# =====================================================

st.set_page_config(
    page_title="Attack Surface Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# =====================================================
# CSS
# =====================================================

st.markdown(
    """
    <style>
    .stApp {
        background: #f4f7fb;
        color: #111827;
        font-family: "Segoe UI", Arial, sans-serif;
    }

    .block-container {
        max-width: 1280px;
        padding-top: 1.5rem;
        padding-bottom: 3rem;
    }

    header[data-testid="stHeader"] {
        background: transparent;
    }

    [data-testid="stToolbar"],
    [data-testid="stDecoration"],
    [data-testid="stStatusWidget"] {
        display: none;
    }

    section[data-testid="stSidebar"] {
        background: #0f172a;
        border-right: 1px solid #1e293b;
    }

    .auth-card {
        background: #ffffff;
        border: 1px solid #e5e7eb;
        border-radius: 24px;
        padding: 34px;
        max-width: 520px;
        margin: 40px auto 26px auto;
        box-shadow: 0 14px 34px rgba(15, 23, 42, 0.10);
        text-align: center;
    }

    .auth-title {
        font-size: 34px;
        font-weight: 850;
        color: #0f172a;
    }

    .auth-subtitle {
        color: #64748b;
        margin-top: 8px;
        font-size: 15px;
        line-height: 1.6;
    }

    .hero {
        background: #ffffff;
        border: 1px solid #e5e7eb;
        border-radius: 24px;
        padding: 34px;
        margin-bottom: 24px;
        box-shadow: 0 12px 30px rgba(15, 23, 42, 0.08);
    }

    .hero-top {
        display: flex;
        align-items: center;
        gap: 16px;
    }

    .hero-icon {
        width: 54px;
        height: 54px;
        border-radius: 16px;
        background: linear-gradient(135deg, #2563eb, #06b6d4);
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 30px;
    }

    .hero-title {
        font-size: 40px;
        font-weight: 850;
        color: #0f172a;
        margin: 0;
        letter-spacing: -0.8px;
    }

    .hero-subtitle {
        color: #475569;
        margin-top: 16px;
        max-width: 980px;
        font-size: 16px;
        line-height: 1.7;
    }

    .panel {
        background: #ffffff;
        border: 1px solid #e5e7eb;
        border-radius: 20px;
        padding: 24px;
        margin-bottom: 20px;
        box-shadow: 0 8px 22px rgba(15, 23, 42, 0.06);
    }

    .section-title {
        color: #0f172a;
        font-size: 24px;
        font-weight: 800;
        margin-bottom: 16px;
    }

    .metric-card {
        background: #f8fafc;
        border: 1px solid #e5e7eb;
        border-radius: 18px;
        padding: 22px;
        min-height: 120px;
    }

    .metric-label {
        color: #64748b;
        font-size: 12px;
        text-transform: uppercase;
        margin-bottom: 12px;
        font-weight: 800;
        letter-spacing: 0.5px;
    }

    .metric-value {
        color: #0f172a;
        font-size: 34px;
        font-weight: 850;
    }

    .low { color: #16a34a; }
    .medium { color: #ca8a04; }
    .high { color: #dc2626; }

    .status-good {
        background: #dcfce7;
        border-left: 5px solid #22c55e;
        color: #166534;
        padding: 14px;
        border-radius: 14px;
        font-weight: 700;
    }

    .status-warn {
        background: #fef3c7;
        border-left: 5px solid #f59e0b;
        color: #92400e;
        padding: 14px;
        border-radius: 14px;
        font-weight: 700;
    }

    .status-danger {
        background: #fee2e2;
        border-left: 5px solid #ef4444;
        color: #991b1b;
        padding: 14px;
        border-radius: 14px;
        font-weight: 700;
    }

    .badge {
        display: inline-block;
        background: #e0f2fe;
        color: #075985;
        padding: 8px 13px;
        border-radius: 999px;
        margin: 4px;
        font-weight: 700;
        font-size: 14px;
    }

    .port {
        background: #eef2ff;
        color: #3730a3;
    }

    .stTextInput input {
        background: #ffffff !important;
        color: #0f172a !important;
        border: 1px solid #cbd5e1 !important;
        border-radius: 12px !important;
        height: 48px !important;
    }

    .stTextInput input:focus {
        border: 1px solid #2563eb !important;
        box-shadow: 0 0 0 1px #2563eb !important;
    }

    label {
        color: #0f172a !important;
        font-weight: 650 !important;
    }

    .stRadio label,
    .stRadio label span,
    .stRadio div,
    .stRadio p {
        color: #0f172a !important;
        opacity: 1 !important;
        font-weight: 700 !important;
    }

    /* =====================================================
       CHECKBOX FIX
       This fixes invisible text beside permission and Ollama checkboxes
    ===================================================== */

    .stCheckbox {
        margin-top: 10px;
        margin-bottom: 10px;
    }

    .stCheckbox label {
        color: #111827 !important;
        font-size: 15px !important;
        font-weight: 700 !important;
        opacity: 1 !important;
    }

    .stCheckbox label span {
        color: #111827 !important;
        opacity: 1 !important;
        font-weight: 700 !important;
    }

    .stCheckbox p {
        color: #111827 !important;
        opacity: 1 !important;
        font-weight: 700 !important;
    }

    .stCheckbox div {
        color: #111827 !important;
        opacity: 1 !important;
    }

    .stButton > button {
        background: #2563eb;
        color: white;
        border: none;
        border-radius: 12px;
        height: 46px;
        padding: 0 24px;
        font-weight: 750;
    }

    .stButton > button:hover {
        background: #1d4ed8;
        color: white;
    }

    .stDownloadButton > button {
        background: #16a34a;
        color: white;
        border: none;
        border-radius: 12px;
        height: 46px;
        padding: 0 24px;
        font-weight: 750;
    }

    div[data-testid="stDataFrame"] {
        border-radius: 14px;
        overflow: hidden;
        border: 1px solid #e5e7eb;
    }
    </style>
    """,
    unsafe_allow_html=True
)

# =====================================================
# JSON HELPERS
# =====================================================

def read_json(path, default):
    if not os.path.exists(path):
        with open(path, "w") as file:
            json.dump(default, file, indent=4)
        return default

    try:
        with open(path, "r") as file:
            return json.load(file)
    except Exception:
        return default


def write_json(path, data):
    with open(path, "w") as file:
        json.dump(data, file, indent=4)


# =====================================================
# USER SYSTEM
# =====================================================

def load_users():
    default_users = {
        "admin": {
            "password": "admin123",
            "role": "admin"
        }
    }

    return read_json(USERS_FILE, default_users)


def save_users(users):
    write_json(USERS_FILE, users)


def auth_page():
    users = load_users()

    st.markdown(
        """
        <div class="auth-card">
            <div class="auth-title">🔐 Secure Access</div>
            <div class="auth-subtitle">
                Login or create a temporary local account for project demonstration.
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    left, center, right = st.columns([1, 1.25, 1])

    with center:
        mode = st.radio(
            "Choose Access Option",
            ["Login", "Create Account"],
            horizontal=True,
            label_visibility="visible"
        )

        if mode == "Login":
            username = st.text_input(
                "Username",
                placeholder="Enter username",
                key="login_username"
            )

            password = st.text_input(
                "Password",
                type="password",
                placeholder="Enter password",
                key="login_password"
            )

            if st.button("Login", width="stretch"):
                if username in users and users[username]["password"] == password:
                    st.session_state.logged_in = True
                    st.session_state.username = username
                    st.session_state.role = users[username]["role"]
                    st.rerun()
                else:
                    st.error("Invalid username or password.")

        else:
            new_username = st.text_input(
                "New Username",
                placeholder="Create username",
                key="new_username"
            )

            new_password = st.text_input(
                "New Password",
                type="password",
                placeholder="Create password",
                key="new_password"
            )

            confirm_password = st.text_input(
                "Confirm Password",
                type="password",
                placeholder="Confirm password",
                key="confirm_password"
            )

            if st.button("Create Account", width="stretch"):
                new_username = new_username.strip()

                if not new_username:
                    st.error("Username cannot be empty.")
                elif new_username in users:
                    st.error("Username already exists.")
                elif len(new_password) < 4:
                    st.error("Password must be at least 4 characters.")
                elif new_password != confirm_password:
                    st.error("Passwords do not match.")
                else:
                    users[new_username] = {
                        "password": new_password,
                        "role": "user"
                    }

                    save_users(users)
                    st.success("Account created successfully. Please login now.")


if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if "username" not in st.session_state:
    st.session_state.username = ""

if "role" not in st.session_state:
    st.session_state.role = ""

if not st.session_state.logged_in:
    auth_page()
    st.stop()

is_admin = st.session_state.role == "admin"

# =====================================================
# SIDEBAR
# =====================================================

st.sidebar.title("🛡️ Control Panel")
st.sidebar.success(f"Logged in: {st.session_state.username}")
st.sidebar.info(f"Role: {st.session_state.role}")

if st.sidebar.button("Logout"):
    st.session_state.logged_in = False
    st.session_state.username = ""
    st.session_state.role = ""
    st.rerun()

st.sidebar.markdown("---")

if is_admin:
    st.sidebar.warning("Admin access enabled")
else:
    st.sidebar.info("User access enabled")

# =====================================================
# SECURITY FEATURES
# =====================================================

def get_scan_log():
    return read_json(HISTORY_FILE, [])


def get_audit_logs():
    return read_json(AUDIT_FILE, [])


def save_scan_history(entry):
    history = get_scan_log()
    history.insert(0, entry)
    history = history[:20]
    write_json(HISTORY_FILE, history)


def save_audit_log(action, domain=""):
    logs = get_audit_logs()

    logs.insert(
        0,
        {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "username": st.session_state.username,
            "role": st.session_state.role,
            "action": action,
            "domain": domain
        }
    )

    logs = logs[:100]
    write_json(AUDIT_FILE, logs)


def check_rate_limit():
    history = get_scan_log()
    now = datetime.now()
    recent_count = 0

    for item in history:
        if item.get("username") != st.session_state.username:
            continue

        try:
            item_time = datetime.strptime(
                item.get("time", ""),
                "%Y-%m-%d %H:%M:%S"
            )

            if now - item_time <= timedelta(minutes=1):
                recent_count += 1
        except Exception:
            pass

    return recent_count < 3


def generate_captcha():
    if "captcha_a" not in st.session_state:
        st.session_state.captcha_a = random.randint(2, 9)
        st.session_state.captcha_b = random.randint(2, 9)

    return st.session_state.captcha_a, st.session_state.captcha_b


def reset_captcha():
    st.session_state.captcha_a = random.randint(2, 9)
    st.session_state.captcha_b = random.randint(2, 9)


# =====================================================
# HELPERS
# =====================================================

def clean_domain(domain):
    return (
        domain.replace("https://", "")
        .replace("http://", "")
        .replace("/", "")
        .strip()
        .lower()
    )


def validate_domain(domain):
    blocked = [
        "abc.com",
        "xyz.com",
        "example.com",
        "test.com",
        "demo.com",
        "localhost"
    ]

    if domain in blocked:
        return False

    try:
        if not validators.domain(domain):
            return False

        socket.gethostbyname(domain)
        return True
    except Exception:
        return False


def load_results():
    return read_json(RESULT_FILE, {})


def sev_class(severity):
    severity = str(severity).upper()

    if severity in ["HIGH", "CRITICAL"]:
        return "high"

    if severity == "MEDIUM":
        return "medium"

    return "low"


def status_class(severity):
    severity = str(severity).upper()

    if severity in ["HIGH", "CRITICAL"]:
        return "status-danger"

    if severity == "MEDIUM":
        return "status-warn"

    return "status-good"


def build_observations(subdomains, ports, paths, technologies):
    return pd.DataFrame(
        [
            ["Subdomains", f"{len(subdomains)} DNS-resolvable subdomains found"],
            ["Open Ports", f"{len(ports)} open ports detected"],
            ["Paths", f"{len(paths)} restricted/access paths found"],
            ["Technologies", f"{len(technologies)} technologies detected"],
        ],
        columns=["Category", "Observation"]
    )


def build_actions(ports, paths, technologies):
    actions = []

    if 22 in ports:
        actions.append(["High", "Restrict SSH access using firewall or IP allowlist."])

    if paths:
        actions.append(["High", "Review restricted paths and check for sensitive exposure."])

    if not technologies:
        actions.append(["Medium", "Improve fingerprinting using headers and metadata."])

    actions.append(["Medium", "Verify WAF and rate limiting protection."])
    actions.append(["Low", "Schedule periodic monitoring."])

    return pd.DataFrame(
        actions,
        columns=["Priority", "Recommended Action"]
    )


def make_report_html(data, role):
    ai = data.get("ai_results", {})

    domain = data.get("domain", "N/A")
    severity = ai.get("Severity", "N/A")
    risk_score = ai.get("Risk Score", "N/A")
    confidence = ai.get("Confidence", "N/A")
    last_updated = data.get("last_updated", "N/A")

    subdomains = data.get("subdomains", [])
    ports = data.get("ports", [])
    paths = data.get("directories", [])
    technologies = data.get("technologies", [])
    llm_summary = data.get("llm_summary", "")

    if role == "user":
        subdomain_section = "<p>Detailed subdomain intelligence is restricted for user role.</p>"
        path_section = "<p>Restricted path intelligence is admin-only.</p>"
        tech_section = f"<p>Total technologies detected: {len(technologies)}</p>"
        ai_section = "<p>AI analyst intelligence is admin-only.</p>"
    else:
        subdomain_section = "".join(
            [f"<li>{item}</li>" for item in subdomains]
        ) or "<li>No subdomains found.</li>"

        path_section = "".join(
            [
                f"<li>{item.get('url', 'N/A')} - Status {item.get('status', 'N/A')}</li>"
                for item in paths
            ]
        ) or "<li>No notable paths found.</li>"

        tech_section = "".join(
            [f"<li>{item}</li>" for item in technologies]
        ) or "<li>No technologies detected.</li>"

        ai_section = f"<pre>{llm_summary}</pre>" if llm_summary else "<p>No AI summary generated.</p>"

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Attack Surface Report</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                background: #f8fafc;
                color: #111827;
                padding: 30px;
            }}

            .header {{
                background: #0f172a;
                color: white;
                padding: 28px;
                border-radius: 16px;
                margin-bottom: 24px;
            }}

            .card {{
                background: white;
                border: 1px solid #e5e7eb;
                border-radius: 14px;
                padding: 20px;
                margin-bottom: 18px;
            }}

            table {{
                width: 100%;
                border-collapse: collapse;
            }}

            td, th {{
                border: 1px solid #e5e7eb;
                padding: 10px;
                text-align: left;
            }}

            th {{
                background: #f1f5f9;
            }}

            pre {{
                white-space: pre-wrap;
                background: #f1f5f9;
                padding: 14px;
                border-radius: 10px;
            }}
        </style>
    </head>

    <body>
        <div class="header">
            <h1>Attack Surface Intelligence Report</h1>
            <p>Generated for role: {role.upper()}</p>
            <p>Generated at: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>

        <div class="card">
            <h2>Executive Summary</h2>
            <table>
                <tr><th>Metric</th><th>Value</th></tr>
                <tr><td>Target Domain</td><td>{domain}</td></tr>
                <tr><td>Threat Level</td><td>{severity}</td></tr>
                <tr><td>Risk Score</td><td>{risk_score}</td></tr>
                <tr><td>AI Confidence</td><td>{confidence}</td></tr>
                <tr><td>Last Updated</td><td>{last_updated}</td></tr>
            </table>
        </div>

        <div class="card">
            <h2>Key Signals</h2>
            <table>
                <tr><th>Signal</th><th>Count</th></tr>
                <tr><td>Subdomains</td><td>{len(subdomains)}</td></tr>
                <tr><td>Open Ports</td><td>{len(ports)}</td></tr>
                <tr><td>Restricted / Accessible Paths</td><td>{len(paths)}</td></tr>
                <tr><td>Technologies</td><td>{len(technologies)}</td></tr>
            </table>
        </div>

        <div class="card">
            <h2>Open Ports</h2>
            <ul>
                {"".join([f"<li>Port {port}</li>" for port in ports]) or "<li>No common open ports detected.</li>"}
            </ul>
        </div>

        <div class="card">
            <h2>Subdomain Intelligence</h2>
            <ul>{subdomain_section}</ul>
        </div>

        <div class="card">
            <h2>Restricted / Accessible Paths</h2>
            <ul>{path_section}</ul>
        </div>

        <div class="card">
            <h2>Technology Fingerprint</h2>
            <ul>{tech_section}</ul>
        </div>

        <div class="card">
            <h2>Recommended Actions</h2>
            <ul>
                <li>Review exposed services and remove unnecessary public access.</li>
                <li>Verify Web Application Firewall and rate limiting protection.</li>
                <li>Review restricted paths for sensitive exposure.</li>
                <li>Schedule periodic attack surface monitoring.</li>
            </ul>
        </div>

        <div class="card">
            <h2>AI Analyst Summary</h2>
            {ai_section}
        </div>
    </body>
    </html>
    """


# =====================================================
# HERO
# =====================================================

st.markdown(
    """
    <div class="hero">
        <div class="hero-top">
            <div class="hero-icon">🛡️</div>
            <div>
                <div class="hero-title">Attack Surface Intelligence Dashboard</div>
            </div>
        </div>
        <div class="hero-subtitle">
            A role-based cybersecurity reconnaissance platform for authorized assessments.
            Includes login, scan history, audit logs, captcha, rate limiting, report generation,
            and machine-learning powered risk analysis.
        </div>
    </div>
    """,
    unsafe_allow_html=True
)

# =====================================================
# SCAN INPUT
# =====================================================

st.markdown("<div class='panel'>", unsafe_allow_html=True)
st.markdown("<div class='section-title'>🎯 Start Authorized Scan</div>", unsafe_allow_html=True)

domain = st.text_input(
    "Target Domain",
    placeholder=""
)

authorized = st.checkbox(
    "I confirm that I own this domain or have authorized permission to scan it.",
    key="authorized_permission"
)

captcha_a, captcha_b = generate_captcha()

captcha_answer = st.text_input(
    f"Captcha: What is {captcha_a} + {captcha_b}?"
)

col1, col2, col3 = st.columns([1, 1, 1])

with col1:
    start_scan = st.button("Start Scan")

with col2:
    if is_admin:
        load_last = st.button("Load Last Result")
    else:
        load_last = False
        st.info("Load last result is admin-only.")

with col3:
    if is_admin:
        use_ollama = st.checkbox(
            "Use Ollama AI Threat Intelligence",
            key="ollama_checkbox"
        )
    else:
        use_ollama = False
        st.info("Ollama summary is admin-only.")

st.markdown("</div>", unsafe_allow_html=True)

# =====================================================
# SCAN FLOW
# =====================================================

data = None

if start_scan:
    domain = clean_domain(domain)

    if not authorized:
        st.error("Permission confirmation is required.")
        st.stop()

    try:
        if int(captcha_answer) != captcha_a + captcha_b:
            st.error("Captcha is incorrect.")
            reset_captcha()
            st.stop()
    except Exception:
        st.error("Please solve the captcha.")
        st.stop()

    if not check_rate_limit():
        st.error("Rate limit reached. You can run only 3 scans per minute.")
        st.stop()

    if not domain:
        st.error("Please enter a domain.")
        st.stop()

    if not validate_domain(domain):
        st.error("Invalid, blocked, or non-resolvable domain.")
        st.stop()

    progress = st.progress(0)
    status = st.empty()

    steps = [
        "Validating target",
        "Enumerating subdomains",
        "Scanning common ports",
        "Checking exposed paths",
        "Detecting technologies",
        "Calculating ML risk score",
        "Saving history and audit logs"
    ]

    for index, step in enumerate(steps):
        status.info(step)
        progress.progress(int(((index + 1) / len(steps)) * 100))

    try:
        data = run_realtime_scan(
            domain,
            use_ollama=use_ollama
        )

        ai = data.get("ai_results", {})

        save_scan_history(
            {
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "username": st.session_state.username,
                "role": st.session_state.role,
                "domain": domain,
                "severity": ai.get("Severity", "N/A"),
                "risk_score": ai.get("Risk Score", "N/A")
            }
        )

        save_audit_log("scan_completed", domain)

        status.success("Scan completed successfully.")
        reset_captcha()

    except Exception as error:
        save_audit_log("scan_failed", domain)
        st.error(f"Scan failed: {error}")
        st.stop()

elif load_last:
    data = load_results()
    save_audit_log("loaded_previous_report")

if not data:
    st.info("Enter a domain, confirm permission, solve captcha, and start a scan.")
    st.stop()

# =====================================================
# DATA EXTRACTION
# =====================================================

ai = data.get("ai_results", {})

severity = ai.get("Severity", "N/A")
risk_score = ai.get("Risk Score", "N/A")
confidence = ai.get("Confidence", "N/A")
last_updated = data.get("last_updated", "N/A")

subdomains = data.get("subdomains", [])
ports = data.get("ports", [])
paths = data.get("directories", [])
technologies = data.get("technologies", [])
llm_summary = data.get("llm_summary", "")

# =====================================================
# EXECUTIVE SUMMARY
# =====================================================

st.markdown("<div class='panel'>", unsafe_allow_html=True)
st.markdown("<div class='section-title'>📊 Executive Summary</div>", unsafe_allow_html=True)

m1, m2, m3, m4 = st.columns(4)

with m1:
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">Threat Level</div>
            <div class="metric-value {sev_class(severity)}">{severity}</div>
        </div>
        """,
        unsafe_allow_html=True
    )

with m2:
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">Risk Score</div>
            <div class="metric-value">{risk_score}</div>
        </div>
        """,
        unsafe_allow_html=True
    )

with m3:
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">Confidence</div>
            <div class="metric-value">{confidence}</div>
        </div>
        """,
        unsafe_allow_html=True
    )

with m4:
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">Last Updated</div>
            <div class="metric-value" style="font-size:16px;">{last_updated}</div>
        </div>
        """,
        unsafe_allow_html=True
    )

st.markdown(
    f"""
    <div class="{status_class(severity)}">
        Current assessment: {severity} risk based on verified scan signals.
    </div>
    """,
    unsafe_allow_html=True
)

st.markdown("</div>", unsafe_allow_html=True)

# =====================================================
# KEY SIGNALS
# =====================================================

st.markdown("<div class='panel'>", unsafe_allow_html=True)
st.markdown("<div class='section-title'>📡 Key Exposure Signals</div>", unsafe_allow_html=True)

k1, k2, k3, k4 = st.columns(4)

k1.metric("Subdomains", len(subdomains))
k2.metric("Open Ports", len(ports))
k3.metric("Paths", len(paths))
k4.metric("Technologies", len(technologies))

st.markdown("</div>", unsafe_allow_html=True)

# =====================================================
# USER LIMITED VIEW
# =====================================================

if not is_admin:
    st.markdown("<div class='panel'>", unsafe_allow_html=True)
    st.markdown("<div class='section-title'>👤 User Report View</div>", unsafe_allow_html=True)

    user_df = pd.DataFrame(
        [
            ["Threat Level", severity],
            ["Risk Score", risk_score],
            ["Open Ports Count", len(ports)],
            ["Technology Count", len(technologies)],
            ["Last Updated", last_updated],
        ],
        columns=["Metric", "Value"]
    )

    st.dataframe(user_df, width="stretch", hide_index=True)

    st.warning(
        "Detailed reconnaissance data such as subdomains, restricted paths, and full AI summary is admin-only."
    )

    st.markdown("</div>", unsafe_allow_html=True)

# =====================================================
# ADMIN FULL VIEW
# =====================================================

if is_admin:
    st.markdown("<div class='panel'>", unsafe_allow_html=True)
    st.markdown("<div class='section-title'>🧠 Important Observations</div>", unsafe_allow_html=True)

    st.dataframe(
        build_observations(subdomains, ports, paths, technologies),
        width="stretch",
        hide_index=True
    )

    st.markdown("</div>", unsafe_allow_html=True)

    left, right = st.columns([1.5, 1])

    with left:
        st.markdown("<div class='panel'>", unsafe_allow_html=True)
        st.markdown("<div class='section-title'>🌐 Discovered Subdomains</div>", unsafe_allow_html=True)

        if subdomains:
            st.dataframe(
                pd.DataFrame({"Subdomain": subdomains}),
                width="stretch",
                hide_index=True
            )
        else:
            st.info("No DNS-resolvable subdomains found.")

        st.markdown("</div>", unsafe_allow_html=True)

        st.markdown("<div class='panel'>", unsafe_allow_html=True)
        st.markdown("<div class='section-title'>📂 Restricted / Accessible Paths</div>", unsafe_allow_html=True)

        if paths:
            st.dataframe(
                pd.DataFrame(paths),
                width="stretch",
                hide_index=True
            )
        else:
            st.info("No notable paths found.")

        st.markdown("</div>", unsafe_allow_html=True)

    with right:
        st.markdown("<div class='panel'>", unsafe_allow_html=True)
        st.markdown("<div class='section-title'>🔌 Open Ports</div>", unsafe_allow_html=True)

        if ports:
            for port in ports:
                st.markdown(
                    f"<span class='badge port'>Port {port}</span>",
                    unsafe_allow_html=True
                )
        else:
            st.info("No common open ports detected.")

        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown("<div class='section-title'>⚙️ Technologies</div>", unsafe_allow_html=True)

        if technologies:
            for tech in technologies:
                st.markdown(
                    f"<span class='badge'>{tech}</span>",
                    unsafe_allow_html=True
                )
        else:
            st.info("No technologies detected.")

        st.markdown("</div>", unsafe_allow_html=True)

# =====================================================
# ACTIONS
# =====================================================

st.markdown("<div class='panel'>", unsafe_allow_html=True)
st.markdown("<div class='section-title'>🛡️ Recommended Actions</div>", unsafe_allow_html=True)

st.dataframe(
    build_actions(ports, paths, technologies),
    width="stretch",
    hide_index=True
)

st.markdown("</div>", unsafe_allow_html=True)

# =====================================================
# AI SUMMARY ADMIN ONLY
# =====================================================

if is_admin and llm_summary:
    st.markdown("<div class='panel'>", unsafe_allow_html=True)
    st.markdown("<div class='section-title'>🤖 AI Analyst Summary</div>", unsafe_allow_html=True)
    st.write(llm_summary)
    st.markdown("</div>", unsafe_allow_html=True)

# =====================================================
# REPORT DOWNLOAD
# =====================================================

st.markdown("<div class='panel'>", unsafe_allow_html=True)
st.markdown("<div class='section-title'>📄 Generate Report</div>", unsafe_allow_html=True)

report_html = make_report_html(data, st.session_state.role)
filename_domain = clean_domain(data.get("domain", "scan_report")).replace(".", "_")

st.download_button(
    label="Download HTML Report",
    data=report_html.encode("utf-8"),
    file_name=f"{filename_domain}_{st.session_state.role}_report.html",
    mime="text/html"
)

st.markdown("</div>", unsafe_allow_html=True)

# =====================================================
# ADMIN HISTORY + AUDIT
# =====================================================

if is_admin:
    st.markdown("<div class='panel'>", unsafe_allow_html=True)
    st.markdown("<div class='section-title'>📜 Scan History</div>", unsafe_allow_html=True)

    history = get_scan_log()

    if history:
        st.dataframe(
            pd.DataFrame(history),
            width="stretch",
            hide_index=True
        )
    else:
        st.info("No scan history available.")

    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("<div class='panel'>", unsafe_allow_html=True)
    st.markdown("<div class='section-title'>🧾 Audit Logs</div>", unsafe_allow_html=True)

    logs = get_audit_logs()

    if logs:
        st.dataframe(
            pd.DataFrame(logs),
            width="stretch",
            hide_index=True
        )
    else:
        st.info("No audit logs available.")

    st.markdown("</div>", unsafe_allow_html=True)