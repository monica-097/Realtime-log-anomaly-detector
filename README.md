
# Real-Time Web Log Anomaly Detector

A Python-based cybersecurity project for analyzing web server access logs, identifying potentially suspicious activity through rule-based detection, and presenting security alerts through an interactive Security Operations Center (SOC) dashboard.

The project combines a Python detection engine with a Streamlit web interface to support log analysis, alert visualization, and investigation workflows.

## Project Overview

Web server access logs contain valuable information about requests, response codes, source IP addresses, and access patterns. Reviewing these logs manually can make it difficult to identify suspicious behavior efficiently.

This project automates selected detection tasks by analyzing access logs against configurable rules and displaying the resulting alerts in a centralized dashboard.

It is intended as an educational cybersecurity project demonstrating log analysis, basic threat detection, security monitoring, and alert investigation.

## Key Features

### 1. Web Log Analysis
- Parses supported web server access log entries.
- Analyzes request patterns and HTTP response codes.
- Processes sample logs for testing and demonstration.

### 2. Rule-Based Anomaly Detection
- Identifies repeated HTTP 401/403 responses when the corresponding authentication-failure rule is configured.
- Flags requests to potentially sensitive paths, such as `/.env`, `/.git`, `/admin`, and `/phpmyadmin`, when supported by the detection engine.
- Supports additional detection scenarios implemented in `detector.py`.
- Produces alerts for further investigation rather than treating every suspicious request as a confirmed attack.

### 3. Interactive SOC Dashboard
- Built with Streamlit.
- Displays summary metrics for total alerts, high/critical alerts, medium alerts, and sample log entries.
- Provides severity-distribution and alert-count charts using Plotly.
- Uses color-coded severity categories to improve readability.
- Displays recent alert records.

### 4. Alert Investigation
- Presents generated alerts in a tabular format.
- Allows individual alert records to be selected and reviewed.
- Provides an investigation checklist covering source IPs, timestamps, endpoints, HTTP responses, and surrounding activity.

### 5. Alert Documentation
- Explains the purpose and potential significance of supported detection scenarios.
- Describes investigation steps and possible false positives.
- Provides a suggested workflow for validating and documenting alerts.

### 6. Testing and Project Documentation
- Includes a smoke test that runs the detector against the sample log.
- Checks the presence of important project files.
- Documents intended detection scenarios, limitations, and execution commands.

### 7. CSV Alert Reporting
- Writes generated alert records to `alerts.csv`.
- Allows detection results to be reviewed outside the dashboard using a spreadsheet or CSV viewer.

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Log processing and detection logic |
| Streamlit | Interactive SOC dashboard |
| Pandas | Tabular alert data processing |
| Plotly | Interactive alert visualizations |
| CSV | Alert output and reporting |
| Git and GitHub | Version control and project hosting |

## Project Structure

```text
realtime-log-anomaly-detector/
│
├── detector.py
├── dashboard.py
├── sample_access.log
├── alerts.csv
├── requirements.txt
├── README.md
└── .gitignore
```

**File descriptions**

- `detector.py` — Processes access logs and applies the implemented detection rules.
- `dashboard.py` — Provides the Streamlit interface, visualizations, alert review, documentation, and smoke-test functionality.
- `sample_access.log` — Contains sample access-log entries for demonstration and testing.
- `alerts.csv` — Stores generated detection results. This file is created or updated when the detector runs.
- `requirements.txt` — Lists the Python packages required by the project.
- `.gitignore` — Excludes selected local and sensitive files from Git version control.

## Prerequisites

- Python 3 installed on your system.
- Git, if you plan to clone or contribute to the repository.
- A terminal such as PowerShell, Command Prompt, or a Unix shell.
- An internet connection for installing dependencies.

## Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/monica-097/realtime-log-anomaly-detector.git
cd realtime-log-anomaly-detector
```

### 2. Install dependencies

```bash
py -m pip install -r requirements.txt
```

If your system uses `python` instead of the Windows `py` launcher, use the appropriate Python command for your environment.

### 3. Run the detection engine

```bash
py detector.py sample_access.log --alerts alerts.csv
```

The detector processes the sample log and writes its generated results to `alerts.csv`, provided execution completes successfully.

### 4. Launch the dashboard

```bash
py -m streamlit run dashboard.py
```

Open the local address printed in the terminal. The default address is usually:

http://localhost:8501

## Using the Dashboard

### Overview
View summary metrics, alert severity charts, recent alert records, and a shortcut to run the sample-log scan.

### Detection Engine
Run the detector on the included sample log or upload a supported `.log` or `.txt` file for analysis.

### Alert Investigation
Review the generated alert records and use the investigation checklist to organize follow-up analysis.

### Alert Documentation
Read descriptions of detection scenarios, potential risks, investigation steps, and possible false positives.

### Testing & Documentation
Check project-file availability, run a smoke test, and review the detection scenarios and project limitations.

## Detection and Investigation Approach

The detection engine is rule-based. It flags patterns that match the rules implemented in `detector.py`.

Examples of suspicious behavior that such rules may identify include:

- Repeated authentication failures.
- Requests targeting sensitive files or administrative paths.
- Repeated HTTP 404 responses, if a corresponding rule is implemented.

These patterns may indicate reconnaissance or other suspicious activity, but they can also occur during legitimate use. Each alert should be validated using the original logs, surrounding requests, timestamps, server configuration, and other available evidence.

The dashboard's documentation describes intended detection scenarios. The exact implemented rules, thresholds, and output fields are determined by the current contents of `detector.py`.

## Testing

Use `sample_access.log` to exercise the detection workflow.

Recommended manual checks:

1. Run the detector and confirm that it completes successfully.
2. Review the generated `alerts.csv`.
3. Launch the Streamlit dashboard.
4. Confirm that summary metrics and charts reflect the generated alert data.
5. Review an alert using the investigation checklist.
6. Test a separate log file containing known test cases and compare the output with the expected results.

The built-in smoke test verifies execution against the sample log. It does not independently establish detection accuracy, precision, recall, or false-positive rate. Those measurements require labeled test data and a separate evaluation process.

## Security Considerations

- Analyze only logs that you own or are authorized to inspect.
- Use synthetic or sanitized logs in public repositories.
- Do not commit credentials, API tokens, private logs, or other sensitive information.
- Treat generated alerts as investigation leads, not definitive proof of malicious activity.
- Review uploaded log data and access controls before deploying the application for shared use.

## Limitations and Future Improvements

Current limitations include dependence on predefined rules, the possibility of false positives, and the absence of a validated detection-accuracy benchmark.

Potential future enhancements include:

- Configurable detection thresholds.
- Timestamp-based alert trends and filtering.
- Additional detection rules for suspicious request patterns.
- Structured logging and improved error handling.
- Automated tests with expected alert outcomes.
- Precision, recall, and false-positive evaluation using labeled datasets.
- Optional machine-learning-based anomaly detection.
- Persistent alert storage and richer incident investigation features.

These are potential enhancements and should not be interpreted as features already implemented.

## Disclaimer

This project was developed for educational cybersecurity practice and portfolio demonstration. It is not a replacement for a production SIEM or a complete incident-response platform. Detection results require human validation and appropriate supporting evidence.

## Author

**Monica Navelu**

Cybersecurity Student

GitHub: https://github.com/monica-097

## License

No license has been specified yet. If you intend to allow others to reuse or modify this project, consider adding an appropriate open-source license.
