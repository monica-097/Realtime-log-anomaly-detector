
from pathlib import Path
import subprocess
import sys
import tempfile

import pandas as pd
import plotly.express as px
import streamlit as st


# --------------------------------------------------
# PROJECT FILES
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
DETECTOR_FILE = BASE_DIR / "detector.py"
SAMPLE_LOG_FILE = BASE_DIR / "sample_access.log"
ALERTS_FILE = BASE_DIR / "alerts.csv"


# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------

st.set_page_config(
    page_title="Sentinel SOC | Log Anomaly Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# --------------------------------------------------
# DARK SOC THEME
# --------------------------------------------------

st.markdown(
    """
    <style>
    .stApp {
        background-color: #0b1120;
        color: #e5e7eb;
    }

    [data-testid="stSidebar"] {
        background-color: #101a2b;
        border-right: 1px solid #293950;
    }

    h1, h2, h3 {
        color: #f8fafc;
    }

    p, label, li {
        color: #cbd5e1;
    }

    div[data-testid="stMetric"] {
        background: #141f31;
        border: 1px solid #293950;
        padding: 18px;
        border-radius: 12px;
    }

    div[data-testid="stMetricLabel"] {
        color: #94a3b8;
    }

    div[data-testid="stMetricValue"] {
        color: #f8fafc;
    }

    .soc-card {
        background: #141f31;
        border: 1px solid #293950;
        border-radius: 12px;
        padding: 18px;
        margin-bottom: 12px;
    }

    .muted {
        color: #94a3b8;
        font-size: 14px;
    }

    .status-good {
        color: #22c55e;
        font-weight: 600;
    }

    .status-warning {
        color: #f97316;
        font-weight: 600;
    }

    div.stButton > button {
        border-radius: 8px;
        border: 1px solid #334155;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# --------------------------------------------------
# HELPER FUNCTIONS
# --------------------------------------------------

def read_alerts():
    """Read alerts.csv safely."""
    if not ALERTS_FILE.exists():
        return pd.DataFrame()

    try:
        return pd.read_csv(ALERTS_FILE)
    except (pd.errors.EmptyDataError, pd.errors.ParserError, OSError):
        return pd.DataFrame()


def count_log_lines(file_path):
    """Count non-empty lines in a log file."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as file:
            return sum(1 for line in file if line.strip())
    except (OSError, TypeError):
        return 0


def find_column(df, possible_names):
    """Find a column even if its name uses different capitalization."""
    if df.empty:
        return None

    lookup = {str(column).strip().lower(): column for column in df.columns}

    for name in possible_names:
        if name.lower() in lookup:
            return lookup[name.lower()]

    for column in df.columns:
        normalized = str(column).strip().lower().replace("_", " ").replace("-", " ")
        if any(name.lower().replace("_", " ") in normalized for name in possible_names):
            return column

    return None


def severity_column(df):
    return find_column(
        df,
        ["severity", "level", "priority", "risk_level", "alert_severity"],
    )


def alert_name_column(df):
    return find_column(
        df,
        ["alert_type", "alert_name", "rule", "detection", "type", "name", "description"],
    )


def normalize_severity(value):
    """Convert severity labels into consistent chart categories."""
    value = str(value).strip().upper()

    if "CRITICAL" in value:
        return "CRITICAL"
    if "HIGH" in value:
        return "HIGH"
    if "MEDIUM" in value or "MODERATE" in value:
        return "MEDIUM"
    if "LOW" in value or "INFO" in value:
        return "LOW"

    return "OTHER"


def severity_counts(df):
    """Count alerts by severity."""
    if df.empty:
        return pd.DataFrame(columns=["Severity", "Count"])

    col = severity_column(df)

    if col is None:
        return pd.DataFrame(
            {"Severity": ["Unclassified"], "Count": [len(df)]}
        )

    labels = df[col].fillna("Unclassified").apply(normalize_severity)

    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "OTHER"]
    counts = labels.value_counts()

    result = [
        {"Severity": severity, "Count": int(counts[severity])}
        for severity in order
        if severity in counts.index
    ]

    if "UNCLASSIFIED" in counts.index:
        result.append(
            {"Severity": "Unclassified", "Count": int(counts["UNCLASSIFIED"])}
        )

    return pd.DataFrame(result)


def count_severity(df, wanted):
    """Count alerts matching a severity."""
    col = severity_column(df)

    if df.empty or col is None:
        return 0

    return int(
        df[col]
        .fillna("")
        .apply(normalize_severity)
        .isin(wanted)
        .sum()
    )


def run_detector(log_path):
    """Run the existing Python detector."""
    if not DETECTOR_FILE.exists():
        return False, "detector.py was not found in the project folder."

    command = [
        sys.executable,
        str(DETECTOR_FILE),
        str(log_path),
        "--alerts",
        str(ALERTS_FILE),
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=120,
            cwd=str(BASE_DIR),
        )

        output = result.stdout.strip()
        errors = result.stderr.strip()

        if result.returncode == 0:
            message = output or "The detector finished running."
            return True, message

        message = errors or output or "The detector exited with an error."
        return False, message

    except subprocess.TimeoutExpired:
        return False, "The detector took too long and was stopped."
    except OSError as error:
        return False, str(error)


def display_scan_result(success, message):
    """Show the detector's output."""
    if success:
        st.success("Scan completed.")
    else:
        st.error("The scan did not complete successfully.")

    st.code(message or "No output was returned.", language="text")


def show_alert_table(df):
    if df.empty:
        st.info(
            "No alert records are available yet. Run a scan to generate alerts."
        )
    else:
        st.dataframe(df, use_container_width=True, hide_index=True)


def run_scan_and_refresh(log_path):
    success, message = run_detector(log_path)
    st.session_state["last_scan_success"] = success
    st.session_state["last_scan_message"] = message
    st.session_state["last_scan_log_entries"] = count_log_lines(log_path)


# --------------------------------------------------
# SIDEBAR NAVIGATION
# --------------------------------------------------

with st.sidebar:
    st.markdown("# 🛡️ Sentinel SOC")
    st.caption("Web Log Anomaly Detection")
    st.divider()

    page = st.radio(
        "Navigation",
        [
            "Overview",
            "Detection Engine",
            "Alert Investigation",
            "Alert Documentation",
            "Testing & Documentation",
        ],
        label_visibility="collapsed",
    )

    st.divider()
    st.markdown("### System status")

    if DETECTOR_FILE.exists():
        st.markdown(
            '<p class="status-good">● Detector file found</p>',
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            '<p class="status-warning">● Detector file missing</p>',
            unsafe_allow_html=True,
        )

    if SAMPLE_LOG_FILE.exists():
        st.markdown(
            '<p class="status-good">● Sample log found</p>',
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            '<p class="status-warning">● Sample log missing</p>',
            unsafe_allow_html=True,
        )

    st.caption("Local log analysis · Rule-based detection")


# --------------------------------------------------
# OVERVIEW
# --------------------------------------------------

if page == "Overview":

    st.title("Security Operations Center")
    st.markdown(
        "Monitor web access logs, identify suspicious activity, "
        "and investigate potential security events."
    )

    alerts = read_alerts()

    log_entries = 0
    if SAMPLE_LOG_FILE.exists():
        log_entries = count_log_lines(SAMPLE_LOG_FILE)

    total_alerts = len(alerts)
    critical_high = count_severity(alerts, ["CRITICAL", "HIGH"])
    medium_alerts = count_severity(alerts, ["MEDIUM"])
    low_alerts = count_severity(alerts, ["LOW"])

    # Top metric cards
    metric1, metric2, metric3, metric4 = st.columns(4)

    metric1.metric("Total Alerts", total_alerts)
    metric2.metric("High / Critical", critical_high)
    metric3.metric("Medium Alerts", medium_alerts)
    metric4.metric("Sample Log Entries", log_entries)

    st.divider()

    # Graphs
    left_chart, right_chart = st.columns(2)

    severity_colors = {
        "CRITICAL": "#ef4444",
        "HIGH": "#f97316",
        "MEDIUM": "#3b82f6",
        "LOW": "#22c55e",
        "OTHER": "#94a3b8",
        "Unclassified": "#94a3b8",
    }

    with left_chart:
        st.subheader("Alert Severity Distribution")

        chart_data = severity_counts(alerts)

        if not chart_data.empty and chart_data["Count"].sum() > 0:
            fig = px.pie(
                chart_data,
                names="Severity",
                values="Count",
                hole=0.62,
                color="Severity",
                color_discrete_map=severity_colors,
            )

            fig.update_traces(
                textposition="inside",
                textinfo="label+value",
                marker=dict(line=dict(color="#0b1120", width=3)),
            )

            fig.update_layout(
                paper_bgcolor="#0b1120",
                plot_bgcolor="#0b1120",
                font=dict(color="#e5e7eb"),
                showlegend=True,
                legend=dict(orientation="h", y=-0.15),
                margin=dict(l=10, r=10, t=20, b=35),
            )

            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Run a scan to display the severity distribution.")

    with right_chart:
        st.subheader("Alerts by Severity")

        if not chart_data.empty and chart_data["Count"].sum() > 0:
            bar_data = chart_data.copy()

            fig = px.bar(
                bar_data,
                x="Severity",
                y="Count",
                color="Severity",
                color_discrete_map=severity_colors,
                text="Count",
                category_orders={
                    "Severity": [
                        "CRITICAL",
                        "HIGH",
                        "MEDIUM",
                        "LOW",
                        "OTHER",
                        "Unclassified",
                    ]
                },
            )

            fig.update_traces(
                textposition="outside",
                cliponaxis=False,
            )

            fig.update_layout(
                paper_bgcolor="#0b1120",
                plot_bgcolor="#0b1120",
                font=dict(color="#e5e7eb"),
                showlegend=False,
                xaxis_title="Severity",
                yaxis_title="Number of alerts",
                yaxis=dict(gridcolor="#293950", rangemode="tozero"),
                xaxis=dict(showgrid=False),
                margin=dict(l=10, r=20, t=25, b=10),
            )

            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Your alert graph will appear here after a scan.")

    st.divider()

    st.subheader("Recent Alerts")

    if not alerts.empty:
        st.dataframe(
            alerts.tail(10).iloc[::-1],
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No alerts.csv records found. Start by scanning the sample log.")

    st.subheader("Quick Scan")

    st.write("Run your detector against the sample access log.")

    if st.button("▶ Run Sample Log Scan", type="primary"):
        if not SAMPLE_LOG_FILE.exists():
            st.error("sample_access.log is missing from the project folder.")
        else:
            with st.spinner("Analyzing sample log..."):
                run_scan_and_refresh(SAMPLE_LOG_FILE)

            display_scan_result(
                st.session_state["last_scan_success"],
                st.session_state["last_scan_message"],
            )

            st.rerun()


# --------------------------------------------------
# DETECTION ENGINE
# --------------------------------------------------

elif page == "Detection Engine":

    st.title("Detection Engine")
    st.write(
        "Run the detector on the included sample log or upload a web server "
        "log file for analysis."
    )

    st.info(
        "Only analyze logs you own or have permission to inspect. "
        "Uploaded logs are passed to your local detector."
    )

    tab_sample, tab_upload = st.tabs(
        ["Sample Log", "Upload a Log"]
    )

    with tab_sample:
        st.subheader("Analyze the included sample")

        if SAMPLE_LOG_FILE.exists():
            st.write(
                f"Sample log: `{SAMPLE_LOG_FILE.name}`"
            )
            st.metric(
                "Non-empty log lines",
                count_log_lines(SAMPLE_LOG_FILE),
            )

            with st.expander("Preview sample log"):
                try:
                    with open(
                        SAMPLE_LOG_FILE,
                        "r",
                        encoding="utf-8",
                        errors="replace",
                    ) as file:
                        st.code(file.read()[:12000], language="text")
                except OSError as error:
                    st.error(str(error))

            if st.button("Run Detector on Sample", type="primary"):
                with st.spinner("Running detector..."):
                    success, message = run_detector(SAMPLE_LOG_FILE)

                st.session_state["last_scan_success"] = success
                st.session_state["last_scan_message"] = message
                st.session_state["last_scan_log_entries"] = count_log_lines(
                    SAMPLE_LOG_FILE
                )

                display_scan_result(success, message)

                if success:
                    st.subheader("Generated Alerts")
                    show_alert_table(read_alerts())
        else:
            st.error("sample_access.log was not found beside dashboard.py.")

    with tab_upload:
        st.subheader("Upload a web access log")

        uploaded_file = st.file_uploader(
            "Choose a .log or .txt file",
            type=["log", "txt"],
            help="The file will be analyzed by your local detector.",
        )

        if uploaded_file is not None:
            st.write(f"Selected file: `{uploaded_file.name}`")

            if st.button("Analyze Uploaded Log", type="primary"):
                suffix = Path(uploaded_file.name).suffix or ".log"

                try:
                    with tempfile.NamedTemporaryFile(
                        mode="wb",
                        suffix=suffix,
                        delete=False,
                    ) as temp_file:
                        temp_file.write(uploaded_file.getvalue())
                        temp_path = Path(temp_file.name)

                    try:
                        with st.spinner("Analyzing uploaded log..."):
                            success, message = run_detector(temp_path)

                        st.session_state["last_scan_success"] = success
                        st.session_state["last_scan_message"] = message
                        st.session_state["last_scan_log_entries"] = count_log_lines(
                            temp_path
                        )

                        display_scan_result(success, message)

                        if success:
                            st.subheader("Generated Alerts")
                            show_alert_table(read_alerts())
                    finally:
                        temp_path.unlink(missing_ok=True)

                except OSError as error:
                    st.error(f"Could not process the uploaded file: {error}")

    st.divider()
    st.subheader("Last Scan Result")

    if "last_scan_success" in st.session_state:
        display_scan_result(
            st.session_state["last_scan_success"],
            st.session_state.get("last_scan_message", ""),
        )
    else:
        st.caption("No scan has been run during this dashboard session.")


# --------------------------------------------------
# ALERT INVESTIGATION
# --------------------------------------------------

elif page == "Alert Investigation":

    st.title("Alert Investigation")
    st.write(
        "Review generated alerts and follow a structured investigation process."
    )

    alerts = read_alerts()

    if alerts.empty:
        st.info(
            "No alert records are available. Go to Detection Engine and run a scan."
        )
    else:
        st.subheader("Alert Records")
        show_alert_table(alerts)

        st.divider()
        st.subheader("Investigate an Alert")

        selected_index = st.selectbox(
            "Select an alert record",
            options=list(range(len(alerts))),
            format_func=lambda index: (
                f"Alert {index + 1} — "
                + str(
                    alerts.iloc[index].get(
                        alert_name_column(alerts),
                        "Detected event",
                    )
                )
            ),
        )

        selected_alert = alerts.iloc[selected_index]

        st.markdown("### Selected Alert")
        st.dataframe(
            selected_alert.to_frame(name="Value"),
            use_container_width=True,
        )

        st.markdown("### Investigation Checklist")

        checks = [
            "Confirm the source IP address and timestamps.",
            "Identify the requested URL or endpoint.",
            "Review HTTP status codes and nearby log entries.",
            "Check whether the activity repeated across multiple requests.",
            "Look for any successful requests after repeated failures.",
            "Determine whether the behavior is legitimate or suspicious.",
            "Record evidence and escalate if necessary.",
        ]

        for check in checks:
            st.checkbox(check, key=f"investigation_{selected_index}_{check}")

        st.warning(
            "An alert is a signal for investigation, not proof that an attack "
            "succeeded. Validate it against the surrounding logs and server evidence."
        )


# --------------------------------------------------
# ALERT DOCUMENTATION
# --------------------------------------------------

elif page == "Alert Documentation":

    st.title("Alert Documentation")
    st.write(
        "Reference guide for understanding the detection rules and responding "
        "to the events they identify."
    )

    with st.expander(
        "1. Repeated authentication failures",
        expanded=True,
    ):
        st.markdown("**Severity:** High, when configured by the detector")
        st.markdown(
            "**What it means:** Multiple HTTP 401 or 403 responses from the "
            "same IP within a short time may indicate repeated login attempts."
        )
        st.markdown(
            "**Potential risk:** Password guessing or attempts to access "
            "restricted resources."
        )
        st.markdown(
            "**Investigate:** Check the source IP, timestamps, login endpoint, "
            "number of failures, and whether a successful login followed."
        )
        st.markdown(
            "**Possible false positives:** A user entering the wrong password "
            "repeatedly, expired credentials, or an automated health check."
        )

    with st.expander("2. Sensitive-path requests"):
        st.markdown("**Severity:** Medium, when configured by the detector")
        st.markdown(
            "**What it means:** A request targets a path such as `/.env`, "
            "`/.git`, `/wp-admin`, `/admin`, or `/phpmyadmin`."
        )
        st.markdown(
            "**Potential risk:** Reconnaissance or attempts to locate exposed "
            "configuration files and administrative interfaces."
        )
        st.markdown(
            "**Investigate:** Review the requested path, source IP, response "
            "status, web server configuration, and whether sensitive content "
            "was actually returned."
        )
        st.markdown(
            "**Possible false positives:** Authorized security testing, "
            "automated scanners, or legitimate administrative requests."
        )

    with st.expander("3. Repeated HTTP 404 responses"):
        st.markdown("**Severity:** Medium, if this rule is enabled")
        st.markdown(
            "**What it means:** Many requests return HTTP 404 (Not Found). "
            "This may indicate directory or endpoint scanning."
        )
        st.markdown(
            "**Investigate:** Review the number of requests, requested paths, "
            "source IP, timestamps, and whether the paths resemble common "
            "administrative or vulnerable endpoints."
        )
        st.markdown(
            "**Possible false positives:** Broken links, mistyped URLs, "
            "missing website resources, or normal crawling."
        )

    st.divider()

    st.subheader("Suggested Response Workflow")

    st.markdown(
        """
        1. Validate the alert against the original access logs.
        2. Determine the source, target endpoint, frequency, and time range.
        3. Check server and authentication logs for additional evidence.
        4. Decide whether the activity is benign, suspicious, or confirmed malicious.
        5. Escalate or contain the activity according to your organization's policy.
        6. Document the evidence, decision, and follow-up actions.
        """
    )

    st.caption(
        "Severity labels depend on your detector's actual rules and output. "
        "Confirm the implemented thresholds in detector.py."
    )


# --------------------------------------------------
# TESTING AND DOCUMENTATION
# --------------------------------------------------

elif page == "Testing & Documentation":

    st.title("Testing & Documentation")
    st.write(
        "Check the project files, run a smoke test, and review the current "
        "detection capabilities and limitations."
    )

    st.subheader("Project File Status")

    files_to_check = [
        ("detector.py", DETECTOR_FILE),
        ("sample_access.log", SAMPLE_LOG_FILE),
        ("alerts.csv", ALERTS_FILE),
    ]

    for file_name, file_path in files_to_check:
        if file_path.exists():
            st.success(f"{file_name} — found")
        else:
            if file_name == "alerts.csv":
                st.info(
                    "alerts.csv — not created yet. Run the detector to generate it."
                )
            else:
                st.error(f"{file_name} — missing")

    st.divider()
    st.subheader("Run a Smoke Test")

    st.write(
        "This test checks whether the detector runs on the sample log. "
        "It does not independently measure detection accuracy."
    )

    if st.button("Run Project Smoke Test", type="primary"):
        if not DETECTOR_FILE.exists():
            st.error("Cannot test: detector.py is missing.")
        elif not SAMPLE_LOG_FILE.exists():
            st.error("Cannot test: sample_access.log is missing.")
        else:
            with st.spinner("Running smoke test..."):
                success, message = run_detector(SAMPLE_LOG_FILE)

            st.session_state["last_scan_success"] = success
            st.session_state["last_scan_message"] = message
            st.session_state["last_scan_log_entries"] = count_log_lines(
                SAMPLE_LOG_FILE
            )

            if success:
                st.success("Smoke test passed: the detector exited successfully.")
            else:
                st.error("Smoke test failed: the detector reported an error.")

            display_scan_result(success, message)

            st.subheader("Resulting Alert Records")
            show_alert_table(read_alerts())

    st.divider()
    st.subheader("Detection Capabilities")

    rules = pd.DataFrame(
        [
            {
                "Detection scenario": "Repeated authentication failures",
                "Typical evidence": "Repeated HTTP 401/403 responses",
                "Purpose": "Identify possible brute-force behavior",
            },
            {
                "Detection scenario": "Sensitive-path access",
                "Typical evidence": "Requests to paths such as /.env or /.git",
                "Purpose": "Identify possible reconnaissance",
            },
            {
                "Detection scenario": "Repeated HTTP 404 responses",
                "Typical evidence": "Many missing-page responses",
                "Purpose": "Identify possible endpoint scanning",
            },
        ]
    )

    st.dataframe(rules, use_container_width=True, hide_index=True)

    st.caption(
        "This table describes intended detection scenarios. It is not a guarantee "
        "that every rule is implemented in detector.py."
    )

    st.subheader("Project Limitations")

    st.markdown(
        """
        - The current project uses rule-based detection, not a trained AI model.
        - Normal user behavior may sometimes trigger alerts.
        - An HTTP response code alone does not prove that an attack succeeded.
        - Detection accuracy requires labeled test cases and measured results.
        - Real-world use needs log protection, access controls, and further testing.
        """
    )

    st.subheader("Useful Project Commands")

    st.code(
        "py detector.py sample_access.log --alerts alerts.csv\n"
        "py -m streamlit run dashboard.py",
        language="powershell",
    )


# --------------------------------------------------
# FOOTER
# --------------------------------------------------

st.divider()

st.caption(
    "Sentinel SOC | Educational cybersecurity project | "
    "Rule-based web log anomaly detection"
)
