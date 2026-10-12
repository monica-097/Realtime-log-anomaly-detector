
# Real-Time Web Log Anomaly Detector

A Python-based application that analyzes web server access logs, identifies potentially unusual request patterns using rule-based detection, and displays results through an interactive web dashboard.

The project combines data processing, rule-based logic, CSV reporting, and a Streamlit interface to demonstrate practical software development skills.

## Project Overview

Applications generate logs that contain useful information about requests, response codes, timestamps, and source IP addresses. Manually reviewing large numbers of log entries can be time-consuming and make unusual patterns difficult to identify.

This project automates selected log analysis tasks by processing access-log entries, applying predefined detection rules, and presenting the results in an interactive dashboard.

The project demonstrates practical concepts in Python programming, data processing, application development, debugging, data visualization, and structured problem-solving.

## Key Features

### 1. Log Processing and Analysis
- Reads supported web server access-log files.
- Extracts relevant information from log entries.
- Analyzes HTTP requests and response codes.
- Processes sample data for testing and demonstration.

### 2. Rule-Based Pattern Detection
- Identifies repeated authentication failures when supported by the implemented detection rules.
- Flags requests targeting potentially sensitive paths when supported by the detection engine.
- Generates structured alerts for further review.
- Uses configurable or predefined conditions to identify selected patterns, depending on the implementation.

### 3. Interactive Web Dashboard
- Built using Streamlit.
- Displays summary metrics and recent alert records.
- Visualizes alert severity and counts using Plotly.
- Organizes results into separate sections for easier navigation.
- Provides an interface for reviewing analysis results.

### 4. Alert Review and Investigation
- Displays generated results in a tabular format.
- Supports selecting and reviewing individual alert records.
- Provides a checklist to organize the review of timestamps, source IP addresses, endpoints, and HTTP response codes.

### 5. CSV Reporting
- Exports detection results to `alerts.csv`.
- Makes results available for further analysis using spreadsheet software or other CSV-compatible tools.
- Separates analysis output from the dashboard interface.

### 6. Testing and Documentation
- Includes sample log data for demonstration.
- Provides a workflow for running the detection engine and reviewing its output.
- Documents setup instructions, supported functionality, limitations, and potential improvements.

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Application logic, log processing, and rule-based analysis |
| Streamlit | Interactive web application and dashboard |
| Pandas | Tabular data processing and analysis |
| Plotly | Interactive data visualization |
| CSV | Structured output and reporting |
| Git and GitHub | Version control and source code hosting |

## Project Structure

```text
realtime-log-anomaly-detector/
├── detector.py
├── dashboard.py
├── sample_access.log
├── alerts.csv
├── requirements.txt
├── README.md
└── .gitignore
```

## File Descriptions

- `detector.py` — Processes access logs and applies the implemented detection rules.
- `dashboard.py` — Provides the web interface, visualizations, result review, and supporting documentation.
- `sample_access.log` — Contains sample data for testing and demonstration.
- `alerts.csv` — Stores generated detection results when the detection engine runs.
- `requirements.txt` — Lists the Python packages required by the application.
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

Alternatively, if Python is available through the `python` command:

```bash
python -m pip install -r requirements.txt
```

### 3. Run the Analysis

On Windows:

```powershell
py detector.py sample_access.log --alerts alerts.csv
```

The application processes the sample log and writes the resulting detection records to `alerts.csv` if execution completes successfully.

### 4. Launch the Web Dashboard

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

## Testing

Use `sample_access.log` to test the application workflow.

Recommended checks:

1. Run the detection engine and confirm successful execution.
2. Verify that `alerts.csv` is generated or updated.
3. Review the generated records.
4. Launch the dashboard and check whether the displayed metrics match the available data.
5. Test additional log files containing known patterns.
6. Compare the results against expected outputs to identify incorrect detections or missed cases.

A successful execution confirms that the tested workflow runs; it does not, by itself, establish detection accuracy or performance.

## Skills Demonstrated

- Python programming and application logic
- File handling and text processing
- Data transformation and tabular data analysis
- Rule-based logic and conditional processing
- Web application development
- Interactive data visualization
- CSV reporting and output validation
- Debugging and functional testing
- Git-based version control
- Technical documentation

## Limitations and Future Improvements

The current application depends on predefined detection rules and may produce false positives or miss patterns that are not covered by those rules.

Potential improvements include:

- Support for additional log formats.
- Configurable detection thresholds.
- More filtering and search options.
- Improved error handling and automated testing.
- Performance improvements for large log files.
- Additional visualizations and time-based trend analysis.
- Evaluation using labeled test data.
- Optional machine-learning-based anomaly detection.
- Persistent storage and enhanced reporting features.

These items are potential future enhancements, not claims about existing functionality.

## Disclaimer

This project was developed for educational purposes and portfolio demonstration. Detection results should be reviewed and validated before being used to make operational decisions.

## Author

**Monica**  
Cybersecurity Student

GitHub: [monica-097](https://github.com/monica-097)
