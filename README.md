
# Real-Time Web Log Anomaly Detector

A Python-based application that analyzes web server access logs, identifies potentially suspicious request patterns using rule-based detection, and presents results through an interactive web dashboard.

The project combines log processing, rule-based analysis, automated testing, CSV reporting, and data visualization to demonstrate practical software development skills.

## Project Overview

Web server access logs contain useful information about HTTP requests, response codes, timestamps, and source IP addresses. Manually reviewing log entries can be time-consuming and make unusual patterns difficult to identify.

This project automates selected log analysis tasks by processing access-log entries, applying predefined detection rules, and presenting the results through an interactive dashboard.

The application demonstrates Python programming, file handling, data processing, application development, testing, debugging, data visualization, and structured problem-solving.

## Key Features

### 1. Log Processing and Analysis

- Parses supported web server access-log entries.
- Extracts relevant information, including source IP addresses, request paths, timestamps, and HTTP response codes.
- Processes sample log data for testing and demonstration.
- Handles invalid log entries according to the implemented parsing logic.

### 2. Rule-Based Anomaly Detection

- Detects repeated HTTP 401/403 authentication failures from a single IP address within a defined time window.
- Identifies repeated HTTP 404 responses that may indicate path scanning.
- Flags requests to potentially sensitive paths, such as `/.env`.
- Tracks activity from different source IP addresses independently.
- Applies alert cooldown logic to reduce duplicate alerts.
- Generates structured detection results for further investigation.

Detection thresholds and time windows depend on the implemented rules and available command-line options.

### 3. Interactive Web Dashboard

- Built using Streamlit.
- Displays summary metrics and recent alert records.
- Visualizes alert severity and counts using Plotly.
- Organizes results into separate sections for easier navigation.
- Provides an interface for reviewing detection results.

### 4. Alert Review and Investigation

- Displays generated alerts in a tabular format.
- Supports reviewing individual alert records.
- Provides an investigation checklist covering timestamps, source IP addresses, request paths, and HTTP response codes.
- Helps organize follow-up analysis of potentially unusual activity.

### 5. CSV Reporting

- Exports detection results to `alerts.csv`.
- Stores structured output for further analysis.
- Supports reviewing results using spreadsheet software or other CSV-compatible tools.

### 6. Automated Testing

- Includes unit tests written with pytest.
- Tests valid and invalid log parsing.
- Verifies authentication-failure detection thresholds.
- Tests time-window handling.
- Tests repeated HTTP 404 responses and sensitive-path detection.
- Checks alert cooldown behavior.
- Verifies independent tracking of source IP addresses.

The test suite is intended to validate specific behaviors of the detection engine.

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Application logic, log processing, and detection rules |
| Streamlit | Interactive web dashboard |
| Pandas | Tabular data processing and analysis |
| Plotly | Interactive data visualization |
| pytest | Automated unit testing |
| CSV | Structured output and reporting |
| Git and GitHub | Version control and source code hosting |

## Project Structure

```text
realtime-log-anomaly-detector/
├── detector.py
├── test_detector.py
├── dashboard.py
├── sample_access.log
├── requirements.txt
├── alerts.csv
├── README.md
└── .gitignore
```

## File Descriptions

- `detector.py` — Processes access logs and applies the implemented detection rules.
- `test_detector.py` — Contains automated unit tests for the detection engine.
- `dashboard.py` — Provides the web interface, visualizations, alert review, and supporting documentation.
- `sample_access.log` — Contains sample log entries for testing and demonstration.
- `requirements.txt` — Lists the Python packages required by the project.
- `alerts.csv` — Stores generated detection results when the detector runs.
- `README.md` — Contains project documentation and setup instructions.
- `.gitignore` — Specifies files that should be excluded from version control.

## Prerequisites

- Python 3
- pip for installing Python packages
- Git, for cloning or contributing to the repository
- A terminal such as PowerShell, Command Prompt, or a Unix shell

## Installation and Setup

### 1. Clone the Repository

```bash
git clone https://github.com/monica-097/realtime-log-anomaly-detector.git
cd realtime-log-anomaly-detector
```

### 2. Install Dependencies

On Windows:

```powershell
py -m pip install -r requirements.txt
```

Alternatively, on systems where the `python` command is configured:

```bash
python -m pip install -r requirements.txt
```

### 3. Run the Detection Engine

On Windows:

```powershell
py detector.py sample_access.log --alerts alerts.csv
```

The detector processes the sample log and writes the resulting detection records to `alerts.csv` if execution completes successfully.

### 4. Run the Unit Tests

Execute the test suite using:

```powershell
py -m pytest -v
```

Pytest displays the individual test results and reports the total number of passed or failed tests.

### 5. Launch the Dashboard

```powershell
py -m streamlit run dashboard.py
```

Open the local URL displayed in the terminal. The default address is usually:

http://localhost:8501

## Application Workflow

1. Input — Load the supplied sample log or a supported log file.
2. Processing — Parse log entries and extract relevant request information.
3. Analysis — Apply the detection rules implemented in the Python engine.
4. Output — Generate structured detection results and save them to a CSV file.
5. Visualization — Display summary metrics, charts, and records through the dashboard.
6. Review — Examine selected records and investigate potentially unusual patterns.
7. Testing — Run automated tests to verify supported behaviors of the detection engine.

## Detection and Investigation Approach

The detection engine uses rule-based logic to identify patterns that match the rules implemented in `detector.py`.

The intended detection scenarios include repeated authentication failures, repeated HTTP 404 responses, and requests targeting potentially sensitive paths.

Thresholds, time windows, alert severity, cooldown behavior, and output fields depend on the current implementation and its configuration.

These patterns may indicate suspicious activity, but they are not definitive proof of an attack. Legitimate users and automated services can also generate unusual request patterns. Detection results should be validated using the original logs and other available evidence.

## Testing

The project includes a pytest-based unit test suite.

Run all tests using:

```powershell
py -m pytest -v
```

The test suite covers:

- Parsing valid log entries and rejecting invalid entries.
- Detecting authentication failures at the configured threshold.
- Avoiding an alert when the number of failures is below the threshold.
- Handling failures that occur outside the configured time window.
- Detecting repeated HTTP 404 responses.
- Identifying requests to sensitive paths such as `/.env`.
- Suppressing duplicate alerts through cooldown logic.
- Tracking different source IP addresses independently.

If the test suite contains nine tests, pytest should report nine test results. The actual outcome must be confirmed by running the tests against the current implementation.

Passing unit tests validates the behaviors covered by those tests. It does not independently establish overall detection accuracy, precision, recall, or false-positive rate.

## Skills Demonstrated

- Python programming and application logic.
- File handling and text processing.
- Data parsing and transformation.
- Rule-based analysis and conditional logic.
- Web application development.
- Interactive data visualization.
- CSV reporting and output validation.
- Automated testing with pytest.
- Debugging and functional verification.
- Git-based version control.
- Technical documentation.

## Limitations and Future Improvements

The application depends on predefined detection rules and may produce false positives or miss patterns that are not covered by those rules.

Potential improvements include:

- Support for additional log formats.
- Configurable detection thresholds.
- Improved filtering and search options.
- More robust error handling.
- Additional automated tests with expected outcomes.
- Performance improvements for large log files.
- Time-based trends and enhanced visualizations.
- Evaluation using labeled test data.
- Optional machine-learning-based anomaly detection.
- Persistent storage and enhanced reporting features.

These are potential future enhancements, not claims about existing functionality.

## Security Considerations

- Analyze only logs that you own or are authorized to inspect.
- Use synthetic or sanitized log data in public repositories.
- Do not commit credentials, API tokens, private logs, or other sensitive information.
- Treat generated alerts as indicators for investigation rather than definitive proof of malicious activity.
- Review data handling and access controls before deploying the application for shared use.

## Disclaimer

This project was developed for educational purposes and portfolio demonstration. It is not a replacement for a production monitoring or incident-response platform. Detection results require appropriate validation before being used to make operational decisions.

## Author

**Monica**  
Cybersecurity Student

GitHub: [monica-097](https://github.com/monica-097)
