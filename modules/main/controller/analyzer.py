import sqlite3
import json
import requests
from datetime import datetime, timedelta, timezone
import time

# --- Configuration Constants ---
DB_FILE = "logs.db"
OLLAMA_URL = "http://localhost:11434/api/generate"  # default Ollama endpoint
MODEL = "SentinelAIv1"  # replace with your model name
ANALYSIS_MODES_FILE = "analysis_modes.json"
SLEEP_INTERVAL_SECONDS = 60

def load_analysis_modes():
    """Loads analysis configurations from a JSON file."""
    with open(ANALYSIS_MODES_FILE, "r") as f:
        return json.load(f)

def get_prompt_template(mode):
    """Returns the prompt string for a given analysis mode."""
    templates = {
        "single": (
            "You are a SOC analyst. Analyze this log entry for potential security issues. "
            "Return a JSON object with fields: anomaly_type, severity, confidence, summary.\n\nLog:\n{logs}"
        ),
        "batch": (
            "You are a SOC analyst. Analyze the following group of logs for any correlated security events, "
            "patterns, or anomalies. Return a JSON object describing any suspicious activity.\n\nLogs:\n{logs}"
        ),
        "contextual": (
            "You are a SOC analyst. Analyze these logs collected within a short time window from the same "
            "IP or username. Identify possible coordinated or repeated attack behavior such as brute force or scanning. "
            "Return a JSON object with anomaly_type, severity, confidence, summary.\n\nLogs:\n{logs}"
        )
    }
    return templates.get(mode)

def send_to_llm(prompt):
    """Sends the prompt to the local Ollama LLM and returns parsed JSON output."""
    try:
        response = requests.post(OLLAMA_URL, json={"model": MODEL, "prompt": prompt}, stream=True)
        response.raise_for_status()
        
        output_text = ""
        for line in response.iter_lines():
            if line:
                data = json.loads(line.decode("utf-8"))
                if "response" in data:
                    output_text += data["response"]

        try:
            json_start = output_text.find("{")
            json_end = output_text.rfind("}")
            if json_start != -1 and json_end != -1:
                structured_output = json.loads(output_text[json_start:json_end + 1])
                return structured_output
            else:
                raise json.JSONDecodeError("No JSON object found", output_text, 0)
        except json.JSONDecodeError:
            print(f"[!] LLM returned unstructured output: {output_text[:150]}...")
            return None

    except requests.RequestException as e:
        print(f"[!] LLM request failed: {e}")
        return None
    except Exception as e:
        print(f"[!] An unexpected error occurred in send_to_llm: {e}")
        return None

def init_db():
    """Initializes the database and creates the analysis_results table if it doesn't exist."""
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS analysis_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT, log_ids TEXT, source_type TEXT,
            anomaly_type TEXT, severity TEXT, confidence REAL, summary TEXT, analyzed_at TEXT
        )
    """)
    conn.commit()
    conn.close()

def process_single_log(conn, source_type, log, prompt_template):
    """Analyzes a single log, saves the result, and marks it as analyzed."""
    log_text = json.dumps(log, indent=2)
    prompt = prompt_template.format(logs=log_text)
    result = send_to_llm(prompt)

    if result:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO analysis_results (log_ids, source_type, anomaly_type, severity, confidence, summary, analyzed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            json.dumps([log["id"]]),
            source_type,
            result.get("anomaly_type"),
            result.get("severity"),
            result.get("confidence"),
            result.get("summary"),
            datetime.now(timezone.utc).isoformat()
        ))
        conn.commit()
        mark_logs_as_analyzed(conn, [log["id"]])
        print(f"[+] Analyzed single log {log['id']} ({source_type}) -> {result.get('anomaly_type')}")
    else:
        print(f"[!] Skipping log {log['id']} — no valid response from LLM.")

def analyze_single_logs(conn, source_type, logs):
    """Analyzes logs one by one using the helper function."""
    print(f"[*] Analyzing {len(logs)} logs (single mode) for {source_type}...")
    prompt_template = get_prompt_template("single")
    for log in logs:
        process_single_log(conn, source_type, log, prompt_template)

def analyze_batch_logs(conn, source_type, logs, batch_size):
    """Analyzes logs in fixed-size batches."""
    print(f"[*] Analyzing {len(logs)} logs (batch mode, size={batch_size}) for {source_type}...")
    prompt_template = get_prompt_template("batch")

    for i in range(0, len(logs), batch_size):
        batch = logs[i:i + batch_size]
        batch_text = "\n".join([json.dumps(l, indent=2) for l in batch])
        prompt = prompt_template.format(logs=batch_text)
        result = send_to_llm(prompt)

        if result:
            log_ids = [l["id"] for l in batch]
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO analysis_results (log_ids, source_type, anomaly_type, severity, confidence, summary, analyzed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                json.dumps(log_ids),
                source_type,
                result.get("anomaly_type"),
                result.get("severity"),
                result.get("confidence"),
                result.get("summary"),
                datetime.now(timezone.utc).isoformat()
            ))
            conn.commit()
            mark_logs_as_analyzed(conn, log_ids)
            print(f"[+] Analyzed logs {log_ids} ({source_type}) -> {result.get('anomaly_type')}")
        else:
            print(f"[!] Skipping batch starting with log {batch[0]['id']} — no valid response.")

def analyze_contextual_logs(conn, source_type, logs, window_minutes):
    """Groups logs and analyzes them contextually, with a fallback to single analysis for isolated logs."""
    print(f"[*] Analyzing {len(logs)} logs (contextual mode, window={window_minutes} min) for {source_type}...")
    
    contextual_prompt_template = get_prompt_template("contextual")
    single_prompt_template = get_prompt_template("single")

    grouped = {}
    for log in logs:
        key = log.get("ip") or log.get("username")
        if key:
            grouped.setdefault(key, []).append(log)

    for key, group in grouped.items():
        if len(group) == 1:
            print(f"[*] Found single log for group '{key}'. Analyzing individually.")
            process_single_log(conn, source_type, group[0], single_prompt_template)
            continue

        group_sorted = sorted(group, key=lambda l: l["timestamp"])
        
        try:
            first_log_time = datetime.strptime(group_sorted[0]["timestamp"], "%b %d %H:%M:%S")
        except (ValueError, TypeError):
            print(f"[!] Could not parse timestamp for group '{key}'. Skipping.")
            continue

        time_window = timedelta(minutes=window_minutes)
        logs_in_window = []
        for l in group_sorted:
            try:
                current_log_time = datetime.strptime(l["timestamp"], "%b %d %H:%M:%S")
                if (current_log_time - first_log_time) <= time_window:
                    logs_in_window.append(l)
            except (ValueError, TypeError):
                continue

        if len(logs_in_window) < 2:
            continue

        context_text = "\n".join([json.dumps(l, indent=2) for l in logs_in_window])
        prompt = contextual_prompt_template.format(logs=context_text)
        result = send_to_llm(prompt)

        if result:
            log_ids = [l["id"] for l in logs_in_window]
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO analysis_results (log_ids, source_type, anomaly_type, severity, confidence, summary, analyzed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                json.dumps(log_ids),
                source_type,
                result.get("anomaly_type"),
                result.get("severity"),
                result.get("confidence"),
                result.get("summary"),
                datetime.now(timezone.utc).isoformat()
            ))
            conn.commit()
            mark_logs_as_analyzed(conn, log_ids)
            print(f"[+] Analyzed contextual group '{key}' ({len(log_ids)} logs) -> {result.get('anomaly_type')}")

def mark_logs_as_analyzed(conn, log_ids):
    """Updates the normalized_logs table to mark logs as analyzed."""
    if not log_ids:
        return
    cur = conn.cursor()
    placeholders = ', '.join('?' for _ in log_ids)
    query = f"UPDATE normalized_logs SET analyzed = 1 WHERE id IN ({placeholders})"
    try:
        cur.execute(query, log_ids)
        conn.commit()
        print(f"[*] Marked {len(log_ids)} logs as analyzed.")
    except sqlite3.Error as e:
        print(f"[!] Database error while marking logs as analyzed: {e}")

def main():
    """Main function to run the analysis process in a continuous loop."""
    init_db()
    modes = load_analysis_modes()
    
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row

    print("[*] Starting continuous log analysis process... Press Ctrl+C to exit.")
    
    try:
        while True:
            logs_processed_in_cycle = 0
            
            for source_type, cfg in modes.items():
                mode = cfg["mode"]
                print(f"\n=== Checking for new '{source_type.upper()}' logs ({mode.upper()} mode) ===")
                
                cur = conn.cursor()
                cur.execute("SELECT * FROM normalized_logs WHERE source_type=? AND analyzed = 0", (source_type,))
                logs = [dict(row) for row in cur.fetchall()]

                if not logs:
                    print(f"[-] No new logs found for source_type: {source_type}")
                    continue

                logs_processed_in_cycle += len(logs)

                if mode == "single":
                    analyze_single_logs(conn, source_type, logs)
                elif mode == "batch":
                    analyze_batch_logs(conn, source_type, logs, cfg.get("batch_size", 10))
                elif mode == "contextual":
                    analyze_contextual_logs(conn, source_type, logs, cfg.get("window_minutes", 5))
                else:
                    print(f"[!] Unknown mode: {mode}")

            if logs_processed_in_cycle == 0:
                print(f"\n[+] No new logs found in this cycle. Sleeping for {SLEEP_INTERVAL_SECONDS} seconds...")
                time.sleep(SLEEP_INTERVAL_SECONDS)

    except KeyboardInterrupt:
        print("\n[!] Shutdown signal received. Exiting.")
    finally:
        if conn:
            conn.close()
            print("[*] Database connection closed.")

if __name__ == "__main__":
    main()