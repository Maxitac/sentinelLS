# SentinelLog

**Author:** [Ian Ignatius]  
**Date:** [28/04/2025]  

## Description
SentinelLS is a Python-based log monitoring tool designed for computer security projects.  
It continuously generates logs (simulated), reads only new logs from a growing log file, formats them for security analysis, and appends them to a separate formatted log file.

## Key Features
- Continuous log generation with randomized events.
- Smart log reading using file position tracking (avoids duplicate processing).
- Log formatting to mark security events clearly.
- Automatic reading every 10 seconds for live monitoring.
- Designed to scale efficiently with growing log files.
- Structured for future integration with alert systems or cloud storage (e.g., AWS S3).

## Next Steps
- Detect log rotation or file replacement.
- Integrate with a local LLM for anomaly detection.
- Add cloud storage upload functionality.
- Build a simple web interface to alert security administrators.

## Requirements
- Python 3.x
- Loguru (for log formatting and management)
- `boto3` (for AWS S3 integration - optional, if cloud storage is planned)

## Installation
1. Clone the repository:
    ```bash
    git clone https://github.com/yourusername/sentinellog.git
    cd sentinellog
    ```

2. Install required dependencies:
    ```bash
    pip install -r requirements.txt
    ```

## Usage
1. **Start log generation (simulated)**:
    ```bash
    python3 log_generator.py
    ```

2. **Start log reading and formatting**:
    ```bash
    python3 log_reader.py
    ```

Logs will be generated in the `generated_logs.log` file, and the formatted logs will be appended to `formatted_logs.log`.

## Future Enhancements
- Integration with machine learning models for log anomaly detection.
- Web interface to show real-time alerts for security administrators.

## License
This project is not yet licensed.
