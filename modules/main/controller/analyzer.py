import sqlite3
import requests
import json
from datetime import datetime

DB_FILE = "logs.db"
OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama3.2:3B"

def init_db():
    """Create analysis_results table if not exists."""
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS analysis_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            normalized_log_id INTEGER,
            agent_id TEXT,
            source_type TEXT,
            log_timestamp TEXT,
            event TEXT,
            llm_analysis TEXT,
            severity TEXT,
            anomaly_score REAL,
            analyzed_at TEXT,
            FOREIGN KEY (normalized_log_id) REFERENCES normalized_logs(id)
        )
    """)
    conn.commit()
    conn.close()


def get_unanalyzed_logs():
    """Fetch normalized logs not yet analyzed."""
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        SELECT id, agent_id, source_type, timestamp, event, hostname, ip, username
        FROM normalized_logs
        WHERE id NOT IN (SELECT normalized_log_id FROM analysis_results)
    """)
    rows = cur.fetchall()
    conn.close()
    return rows


def send_to_llm(log_data):
    """Send log data to Ollama LLM and return its response."""
    prompt = f"""
    You are a cybersecurity log analysis assistant.
    Analyze the following normalized log and determine if it indicates suspicious or anomalous activity.

    Provide your answer strictly in JSON format with the following fields:
    {{
      "anomalous": true or false,
      "reason": "brief explanation of your reasoning",
      "severity": "low" or "medium" or "high" or "critical",
      "anomaly_score": number between 0.0 and 1.0,
      "recommendation": "optional security advice"
    }}

    Log details:
    Source: {log_data['source_type']}
    Host: {log_data['hostname']}
    IP: {log_data['ip']}
    User: {log_data['username']}
    Event: {log_data['event']}
    Timestamp: {log_data['timestamp']}
    """

    try:
        response = requests.post(
            OLLAMA_URL,
            json={"model": MODEL, 
                  "prompt": prompt,
                  "stream": False},
            timeout=120
        )
        response.raise_for_status()
        return response.json().get("response", "").strip()
    except Exception as e:
        print(f"[!] LLM request failed: {e}")
        return None


def parse_llm_output(llm_output):
    """Safely parse the LLM output as JSON."""
    try:
        data = json.loads(llm_output)
        return {
            "severity": data.get("severity", "unknown"),
            "anomaly_score": float(data.get("anomaly_score", 0.0)),
            "llm_analysis": json.dumps(data, indent=2)
        }
    except json.JSONDecodeError:
        # In case LLM output is not valid JSON
        return {
            "severity": "unknown",
            "anomaly_score": 0.0,
            "llm_analysis": llm_output
        }


def save_analysis(log_id, agent_id, source_type, timestamp, event, parsed):
    """Save analysis results to the database."""
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO analysis_results (
            normalized_log_id, agent_id, source_type,
            log_timestamp, event, llm_analysis,
            severity, anomaly_score, analyzed_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        log_id, agent_id, source_type, timestamp, event,
        parsed["llm_analysis"], parsed["severity"], parsed["anomaly_score"],
        datetime.now().isoformat()
    ))
    conn.commit()
    conn.close()


def analyze_new_logs():
    """Main routine: get unanalyzed logs, send to LLM, save results."""
    logs = get_unanalyzed_logs()

    if not logs:
        print("[*] No new logs to analyze.")
        return

    for row in logs:
        log_id, agent_id, source_type, timestamp, event, hostname, ip, username = row
        log_data = {
            "source_type": source_type,
            "hostname": hostname,
            "ip": ip,
            "username": username,
            "event": event,
            "timestamp": timestamp
        }

        print(f"[*] Analyzing log {log_id} from {source_type} ({hostname})...")
        llm_output = send_to_llm(log_data)

        if not llm_output:
            print(f"[!] Skipping log {log_id} — no response from LLM.")
            continue

        #Debug: print raw LLM output
        print("\n--- LLM Output Start ---")
        print(llm_output)
        print("--- LLM Output End ---\n")

        parsed = parse_llm_output(llm_output)
        save_analysis(log_id, agent_id, source_type, timestamp, event, parsed)
        print(f"[+] Saved analysis for log {log_id} (Severity: {parsed['severity']})")


if __name__ == "__main__":
    init_db()
    analyze_new_logs()
