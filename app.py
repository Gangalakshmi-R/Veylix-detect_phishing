import time

import streamlit as st

from run_investigation import investigate_message


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="Veylix",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# ============================================================
# SESSION STATE
# ============================================================
# `result` holds the last completed investigation so it survives
# reruns triggered by tabs / expanders / any other widget click —
# without this the results panel disappears the moment the user
# interacts with anything after analyzing.

if "result" not in st.session_state:
    st.session_state.result = None

if "message_input" not in st.session_state:
    st.session_state.message_input = ""


# ============================================================
# THEME — RUST / ORANGE (flat, solid surfaces — no translucency)
# ============================================================

st.markdown(
    """
    <style>

    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap');

    :root {
        --rust: #B7410E;
        --rust-dark: #7C2D12;
        --orange: #F97316;
        --amber: #C2660D;
        --cream: #FFF8F3;
        --paper: #FFFFFF;
        --ink: #2B1B12;
        --muted: #8A6F5C;
        --border: #F0DFCF;
        --good: #16A34A;
        --good-bg: #F0FBF4;
    }

    html, body, [class*="css"] {
        font-family: 'Inter', -apple-system, sans-serif;
    }

    .stApp {
        background: var(--cream);
    }

    /* Force light-theme text everywhere in the main content area.
       Without this, a visitor's OS/browser dark-mode preference makes
       Streamlit default plain text (st.write, tab labels, captions)
       render white-on-cream and disappear — only elements with their
       own explicit color survive. Sidebar keeps its own rule below. */
    section[data-testid="stMain"] {
        color: var(--ink);
    }

    section[data-testid="stMain"] * {
        color: var(--ink);
    }

    .block-container {
        max-width: 1300px;
        padding-top: 1.6rem;
        padding-bottom: 4rem;
    }

    #MainMenu { visibility: hidden; }
    footer { visibility: hidden; }
    header { visibility: hidden; }

    

  
    /* ---------------- TOP BAR ---------------- */

    .brand {
        font-size: 1.9rem;
        font-weight: 900;
        color: var(--ink);
        letter-spacing: -0.02em;
        margin-bottom: 0;
    }

    .subtitle {
        color: var(--muted);
        font-size: 0.9rem;
        font-weight: 500;
        margin-top: -2px;
    }

    .status-pill {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 8px 15px;
        border-radius: 8px;
        background: var(--good-bg);
        border: 1px solid #CBEFD6;
        color: var(--good);
        font-size: 0.72rem;
        font-weight: 800;
        letter-spacing: 0.05em;
    }

    .status-dot {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background: var(--good);
    }

    /* ---------------- HERO ---------------- */

    .hero {
        padding: 30px 42px;
        border-radius: 14px;
        background: var(--rust-dark);
        margin-bottom: 30px;
    }

    .hero h1 {
        margin-bottom: 8px;
        color: white;
        font-size: 2.1rem;
        font-weight: 850;
        letter-spacing: -0.02em;
    }

    .hero p {
        color: #FBD9C4;
        font-size: 0.96rem;
        max-width: 760px;
        line-height: 1.6;
    }

    /* ---------------- SECTION TITLES ---------------- */

    .section-kicker {
        color: var(--rust);
        font-size: 0.68rem;
        font-weight: 850;
        letter-spacing: 0.14em;
        text-transform: uppercase;
        margin-top: 8px;
    }

    .section-title {
        font-size: 1.3rem;
        font-weight: 800;
        color: var(--ink);
        margin-top: 2px;
        margin-bottom: 4px;
    }

    .section-rule {
        width: 46px;
        height: 3px;
        background: var(--rust);
        border-radius: 3px;
        margin-bottom: 18px;
    }

    /* ---------------- INPUT ---------------- */

    .stTextArea label {
        font-weight: 700 !important;
        color: var(--ink) !important;
    }

    .stTextArea textarea {
        background: var(--paper) !important;
        color: var(--ink) !important;
        border: 1.5px solid var(--border) !important;
        border-radius: 10px !important;
        font-size: 0.92rem !important;
        line-height: 1.6 !important;
        padding: 16px !important;
    }

    .stTextArea textarea:focus {
        border: 1.5px solid var(--rust) !important;
        box-shadow: 0 0 0 3px rgba(183,65,14,0.12) !important;
    }

    /* ---------------- BUTTONS ---------------- */

    div[data-testid="stButton"] button {
        min-height: 46px;
        border-radius: 8px;
        font-weight: 750;
        border: 1.5px solid var(--border);
        color: var(--ink);
        background: var(--paper);
    }

    div[data-testid="stButton"] button[kind="primary"] {
        background: var(--rust);
        border: none;
        color: white;
    }

    div[data-testid="stButton"] button[kind="primary"]:hover {
        background: var(--rust-dark);
    }

    /* ---------------- VERDICT CARD ---------------- */

    .verdict-card {
        padding: 26px 30px;
        border-radius: 12px;
        margin: 22px 0 28px 0;
        border: 1px solid var(--border);
        background: var(--paper);
    }

    .verdict-card.critical { border-left: 6px solid var(--rust-dark); background: #FFF3EC; }
    .verdict-card.high     { border-left: 6px solid var(--rust); background: #FFF6EE; }
    .verdict-card.medium   { border-left: 6px solid var(--amber); background: #FFFAEF; }
    .verdict-card.low      { border-left: 6px solid var(--good); background: var(--good-bg); }

    .verdict-eyebrow {
        color: var(--muted);
        font-size: 0.72rem;
        font-weight: 800;
        letter-spacing: 0.1em;
    }

    .verdict {
        font-size: 2rem;
        font-weight: 900;
        margin: 2px 0 6px 0;
        color: var(--ink);
    }

    .verdict-level {
        font-weight: 700;
        color: var(--muted);
        font-size: 0.9rem;
    }

    .risk-score {
        font-size: 2.7rem;
        font-weight: 900;
        color: var(--rust);
        text-align: right;
    }

    /* ---------------- METRIC CARDS ---------------- */

    [data-testid="stMetric"] {
        background: var(--paper);
        border: 1px solid var(--border);
        border-radius: 10px;
        padding: 14px 16px;
    }

    [data-testid="stMetricLabel"] {
        color: var(--muted) !important;
        font-size: 0.68rem !important;
        font-weight: 800 !important;
        letter-spacing: 0.07em !important;
        text-transform: uppercase;
    }

    [data-testid="stMetricValue"] {
        color: var(--ink) !important;
        font-weight: 850 !important;
    }

    .metric-card {
        background: var(--paper);
        padding: 18px;
        border-radius: 10px;
        border: 1px solid var(--border);
        text-align: center;
        min-height: 110px;
    }

    .metric-title {
        color: var(--muted);
        font-size: 0.68rem;
        font-weight: 800;
        letter-spacing: 0.07em;
        text-transform: uppercase;
    }

    .metric-value {
        font-size: 1.8rem;
        font-weight: 850;
        color: var(--ink);
        margin-top: 8px;
    }

    .metric-value.accent-rust { color: var(--rust); }
    .metric-value.accent-good { color: var(--good); }
    .metric-value.accent-orange { color: var(--orange); }

    /* ---------------- ALERTS ---------------- */

    .alert {
        border-radius: 8px;
        padding: 13px 16px;
        font-size: 0.88rem;
        font-weight: 600;
        margin-bottom: 12px;
        border: 1px solid transparent;
    }

    .alert-danger  { background: #FFF1EC; color: var(--rust-dark); border-color: #F7C7AE; }
    .alert-warning { background: #FFF8E9; color: var(--amber); border-color: #F5DFAF; }
    .alert-success { background: var(--good-bg); color: #146534; border-color: #CBEFD6; }
    .alert-info    { background: #FDF3EC; color: var(--rust); border-color: var(--border); }

    /* ---------------- REASON CARDS ---------------- */

    .reason-card {
        background: var(--paper);
        border: 1px solid var(--border);
        border-radius: 10px;
        padding: 18px 20px;
        margin-bottom: 12px;
    }

    .reason-title {
        font-weight: 800;
        font-size: 0.98rem;
        color: var(--ink);
    }

    .reason-category {
        color: var(--muted);
        font-size: 0.72rem;
        font-weight: 700;
        letter-spacing: 0.04em;
        margin-top: 4px;
        text-transform: uppercase;
    }

    .reason-description {
        color: #5A493D;
        margin-top: 8px;
        font-size: 0.86rem;
        line-height: 1.55;
    }

    .evidence {
        background: #FBF1E8;
        border-left: 3px solid var(--orange);
        padding: 9px 12px;
        border-radius: 6px;
        margin-top: 9px;
        font-family: 'SFMono-Regular', Consolas, monospace;
        font-size: 0.8rem;
        color: var(--rust-dark);
        word-break: break-word;
    }

    /* ---------------- URL CARDS ---------------- */

    .url-card {
        background: var(--paper);
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 22px;
        margin-bottom: 16px;
    }

    .url-card h4 {
        margin: 0 0 8px 0;
        color: var(--rust);
        font-size: 0.78rem;
        font-weight: 850;
        letter-spacing: 0.1em;
        text-transform: uppercase;
    }

    .url-text {
        word-break: break-all;
        font-family: 'SFMono-Regular', Consolas, monospace;
        font-size: 0.88rem;
        color: var(--ink);
        background: #FBF1E8;
        padding: 11px 13px;
        border-radius: 8px;
    }

    /* ---------------- TABS ---------------- */

    button[data-baseweb="tab"] {
        font-weight: 700 !important;
    }

    button[data-baseweb="tab"] p {
        color: var(--muted) !important;
    }

    button[data-baseweb="tab"][aria-selected="true"] p {
        color: var(--rust) !important;
    }

    div[data-baseweb="tab-highlight"] {
        background-color: var(--rust) !important;
    }

    /* st.code renders inside Streamlit's own dark code-block chrome
       by default. Force it to a light, on-brand style instead of
       leaving it dark — dark text inheriting onto a dark background
       is what made hostnames/domains unreadable. */
    section[data-testid="stMain"] .stCodeBlock,
    section[data-testid="stMain"] .stCodeBlock pre,
    section[data-testid="stMain"] .stCodeBlock code,
    section[data-testid="stMain"] .stCodeBlock span {
        background: #FBF1E8 !important;
        color: var(--rust-dark) !important;
        border: 1px solid var(--border) !important;
        border-radius: 8px !important;
    }

    [data-testid="stMetricValue"],
    [data-testid="stMetricValue"] * {
        color: var(--ink) !important;
    }

    [data-testid="stMetricLabel"],
    [data-testid="stMetricLabel"] * {
        color: var(--muted) !important;
    }

    /* ---------------- EXPANDER ---------------- */

    details[data-testid="stExpander"] {
        border: 1px solid var(--border) !important;
        border-radius: 10px !important;
        background: var(--paper) !important;
    }

    /* ---------------- FOOTER ---------------- */

    .footer {
        text-align: center;
        color: var(--muted);
        font-size: 0.75rem;
        margin-top: 50px;
        padding-top: 20px;
        border-top: 1px solid var(--border);
        letter-spacing: 0.03em;
    }

    </style>
    """,
    unsafe_allow_html=True
)


# ============================================================
# ALERT HELPER (keeps the custom theme instead of default st.* colors)
# ============================================================

def alert(message, kind="info"):
    st.markdown(
        f'<div class="alert alert-{kind}">{message}</div>',
        unsafe_allow_html=True
    )

# ============================================================
# TOP BAR
# ============================================================

topcol1, topcol2 = st.columns([4, 1])

with topcol1:
    st.markdown('<div class="brand">🛡️ Veylix</div>', unsafe_allow_html=True)
 

with topcol2:
    st.markdown(
        """
        <div style="display:flex; justify-content:flex-end; padding-top:15px;">
            <div class="status-pill">
                <span class="status-dot"></span>
                SYSTEM ONLINE
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )


# ============================================================
# HERO
# ============================================================

st.markdown(
    """
    <div class="hero">
        <h1>Detect phishing</h1>
        <p>
        Analyze emails, SMS, WhatsApp and Telegram messages
        using machine learning, URL analysis, DNS investigation,
        domain intelligence and threat intelligence — with a
        transparent, evidence-backed verdict every time.
        </p>
    </div>
    """,
    unsafe_allow_html=True
)


# ============================================================
# MESSAGE INPUT
# ============================================================

st.markdown('<div class="section-kicker">INPUT</div>', unsafe_allow_html=True)
st.markdown('<div class="section-title">Message Investigation</div>', unsafe_allow_html=True)
st.markdown('<div class="section-rule"></div>', unsafe_allow_html=True)

message = st.text_area(
    "Paste the complete message",
    height=260,
    key="message_input",
    placeholder="""Example:

URGENT! Your account has been suspended.

Please verify your password immediately.

Click here:
https://example.com/login

Failure to verify within 24 hours will result
in permanent account closure.""",
    label_visibility="visible"
)


# ============================================================
# BUTTONS
# ============================================================

col1, col2, col3 = st.columns([1, 1, 4])

with col1:
    analyze = st.button(
        "🔍 Analyze Message",
        type="primary",
        use_container_width=True
    )

def _clear_message():
    # Runs BEFORE the script reruns and the text_area widget is
    # re-instantiated, so it's safe to reset its bound state here —
    # doing this after instantiation (later in the script body) is
    # what raises StreamlitAPIException.
    st.session_state.message_input = ""
    st.session_state.result = None

with col2:
    st.button(
        "🗑️ Clear",
        use_container_width=True,
        on_click=_clear_message
    )


# ============================================================
# RUN INVESTIGATION
# ============================================================
# The underlying investigate_message() call is a single blocking
# operation, so a staged status log is used to surface real progress
# feedback instead of one flat spinner — each stage label is shown as
# soon as that piece of work is either about to start or has been
# confirmed complete, giving a lazy-loading feel without stalling the
# rest of the app on every rerun.

if analyze:

    if not message.strip():
        alert("Please enter a message before starting the investigation.", "warning")
        st.stop()

    try:
        with st.status("Starting investigation...", expanded=True) as status:

            status.write("Parsing message content...")
            time.sleep(0.25)

            status.write("Scoring message with the ML model...")
            time.sleep(0.25)

            status.write("Extracting URLs and resolving DNS...")
            time.sleep(0.25)

            status.write("Checking domain and threat intelligence...")
            result = investigate_message(message)

            status.update(
                label="Investigation complete",
                state="complete",
                expanded=False
            )

    except Exception as exc:
        alert(f"Investigation failed: {exc}", "danger")
        st.stop()

    st.session_state.result = result


# ============================================================
# RESULTS
# ============================================================
# Read from session_state — NOT the `analyze` button flag — so the
# results panel stays on screen across reruns caused by tabs,
# expanders, or any other widget interaction on the page.

result = st.session_state.result

if result:

    st.markdown('<div class="section-kicker">ANALYSIS</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-title">Investigation Results</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-rule"></div>', unsafe_allow_html=True)

    # --------------------------------------------------------
    # VERDICT
    # --------------------------------------------------------

    verdict = str(result.get("verdict", "UNKNOWN")).upper()
    risk_level = str(result.get("risk_level", "UNKNOWN")).upper()
    risk_score = float(result.get("risk_score", result.get("final_risk_score", 0)))

    risk_class = (
        "critical" if risk_level == "CRITICAL"
        else "high" if risk_level == "HIGH"
        else "medium" if risk_level == "MEDIUM"
        else "low"
    )

    icon = (
        "🚨" if verdict == "PHISHING"
        else "⚠️" if verdict == "SUSPICIOUS"
        else "🛡️" if verdict in ["LEGITIMATE", "LIKELY LEGITIMATE"]
        else "🔎"
    )

    st.markdown(
        f"""
        <div class="verdict-card {risk_class}">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <div>
                    <div class="verdict-eyebrow">FINAL VERDICT</div>
                    <div class="verdict">{icon} {verdict}</div>
                    <div class="verdict-level">Risk Level: {risk_level}</div>
                </div>
                <div style="text-align:right;">
                    <div class="verdict-eyebrow">FINAL RISK SCORE</div>
                    <div class="risk-score">{risk_score:.1f}%</div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # --------------------------------------------------------
    # MODEL PROBABILITIES
    # --------------------------------------------------------

    st.markdown('<div class="section-kicker">MACHINE LEARNING</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-title">Model Analysis</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-rule"></div>', unsafe_allow_html=True)

    message_model = result.get("message_model", {})
    message_phishing = float(message_model.get("phishing_probability", 0))
    message_legitimate = float(message_model.get("legitimate_probability", 0))

    urls = result.get("urls", [])

    url_scores = [
        float(item.get("machine_learning", {}).get("phishing_probability", 0))
        for item in urls
    ]

    highest_url_score = max(url_scores) if url_scores else 0

    c1, c2, c3, c4 = st.columns(4)

    with c1:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-title">MESSAGE PHISHING</div>
                <div class="metric-value accent-rust">{message_phishing:.2f}%</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with c2:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-title">MESSAGE LEGITIMATE</div>
                <div class="metric-value accent-good">{message_legitimate:.2f}%</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with c3:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-title">HIGHEST URL RISK</div>
                <div class="metric-value accent-orange">{highest_url_score:.2f}%</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with c4:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-title">URLs DETECTED</div>
                <div class="metric-value">{len(urls)}</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    # --------------------------------------------------------
    # MESSAGE ANALYSIS
    # --------------------------------------------------------

    analysis = result.get("message_analysis", {})

    st.markdown('<div class="section-kicker">MESSAGE</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-title">Message Analysis</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-rule"></div>', unsafe_allow_html=True)

    c1, c2, c3, c4, c5 = st.columns(5)

    with c1:
        st.metric("Message Length", f"{analysis.get('message_length', 0):,}")

    with c2:
        st.metric("URLs", analysis.get("url_count", 0))

    with c3:
        st.metric("Urgency Signals", len(analysis.get("urgency_terms", [])))

    with c4:
        st.metric("Credential Signals", len(analysis.get("credential_terms", [])))

    with c5:
        st.metric("Financial Signals", len(analysis.get("money_terms", [])))

    # --------------------------------------------------------
    # SIGNALS
    # --------------------------------------------------------

    st.markdown('<div class="section-kicker">INDICATORS</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-title">Detected Signals</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-rule"></div>', unsafe_allow_html=True)

    urgency = analysis.get("urgency_terms", [])
    credentials = analysis.get("credential_terms", [])
    money = analysis.get("money_terms", [])

    if urgency:
        alert("⏱️ Urgency: " + ", ".join(map(str, urgency)), "warning")

    if credentials:
        alert("🔑 Credential-related terms: " + ", ".join(map(str, credentials)), "danger")

    if money:
        alert("💰 Financial terms: " + ", ".join(map(str, money)), "warning")

    if not urgency and not credentials and not money:
        alert("No predefined message-level warning signals detected.", "success")

    # --------------------------------------------------------
    # WHY FLAGGED
    # --------------------------------------------------------

    reasons = result.get("reasons", [])

    st.markdown('<div class="section-kicker">EVIDENCE</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-title">Why Was It Flagged?</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-rule"></div>', unsafe_allow_html=True)

    if not reasons:
        alert("No specific investigation reasons were generated.", "info")

    for index, reason in enumerate(reasons, start=1):

        impact = str(reason.get("impact", "INFO")).upper()
        category = str(reason.get("category", "UNKNOWN"))
        factor = str(reason.get("factor", "Unknown"))
        explanation = str(reason.get("explanation", ""))
        evidence_value = reason.get("evidence")

        st.markdown(
            f"""
            <div class="reason-card">
                <div class="reason-title">{index}. [{impact}] {factor}</div>
                <div class="reason-category">Category · {category}</div>
                <div class="reason-description">{explanation}</div>
            </div>
            """,
            unsafe_allow_html=True
        )

        if evidence_value is not None:

            if isinstance(evidence_value, list):
                evidence_text = ", ".join(map(str, evidence_value))
            else:
                evidence_text = str(evidence_value)

            st.markdown(
                f'<div class="evidence">Evidence: {evidence_text}</div>',
                unsafe_allow_html=True
            )

    # --------------------------------------------------------
    # URL INVESTIGATION
    # --------------------------------------------------------

    st.markdown('<div class="section-kicker">NETWORK INTELLIGENCE</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-title">URL Investigation</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-rule"></div>', unsafe_allow_html=True)

    if not urls:
        alert("No URLs were found in this message.", "info")

    for index, item in enumerate(urls, start=1):

        url = item.get("url", "")
        ml = item.get("machine_learning", {})
        url_analysis = ml.get("analysis", {})
        metadata = url_analysis.get("metadata", {})
        dns = item.get("dns", {})
        threat = item.get("threat_intelligence", {})

        url_probability = float(ml.get("phishing_probability", 0))
        prediction = ml.get("prediction", "UNKNOWN")

        st.markdown(
            f"""
            <div class="url-card">
                <h4>URL #{index}</h4>
                <div class="url-text">{url}</div>
            </div>
            """,
            unsafe_allow_html=True
        )

        c1, c2, c3, c4 = st.columns(4)

        with c1:
            st.metric("ML Prediction", prediction)

        with c2:
            st.metric("Phishing Probability", f"{url_probability:.2f}%")

        with c3:
            st.metric("HTTPS", "YES" if metadata.get("is_https") else "NO")

        with c4:
            st.metric("IP Address URL", "YES" if metadata.get("is_ip") else "NO")






#===================

# import os
# from flask import Flask, render_template, request

# from run_investigation import investigate_message


# app = Flask(__name__)


# @app.route("/", methods=["GET", "POST"])
# def home():

#     result = None
#     message = ""
#     error = None

#     if request.method == "POST":

#         message = request.form.get("message", "").strip()

#         if not message:
#             error = "Please enter a message to analyze."

#         else:
#             try:
#                 result = investigate_message(message)

#             except Exception as e:
#                 error = f"Investigation failed: {str(e)}"

#     return render_template(
#         "index.html",
#         result=result,
#         message=message,
#         error=error
#     )


# if __name__ == "__main__":

#     port = int(os.environ.get("PORT", 5000))

#     app.run(
#         host="0.0.0.0",
#         port=port,
#         debug=True
#     )