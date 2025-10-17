#!/usr/bin/env python3
"""
pipeline_tester.py

Usage:
  - Configure CONFIG below (agent hosts, log path, DB_FILE)
  - Ensure SSH key auth works (ssh user@host <command>)
  - Run: python3 pipeline_tester.py
"""

import sqlite3
import subprocess
import uuid
import time
import json
import os
import psutil
from datetime import datetime, timezone

# -----------------------
# CONFIGURATION (edit)
# -----------------------
CONFIG = {
    "agents": [
        {"host": "agent1.example.local", "user": "netadmin", "log_path": "/var/log/auth.log"},
        {"host": "agent2.example.local", "user": "netadmin", "log_path": "/var/log/auth.log"}
    ],
    # Path to controller SQLite DB accessible to this script
    "DB_FILE": "logs.db",
    "LOGS_TABLE": "logs",  # raw logs table (adjust if different)
    "NORMALIZED_TABLE": "normalized_logs",  # normalized table if relevant
    "ANALYSIS_TABLE": "analysis_results",
    "poll_interval": 2.0,
    "timeout_seconds": 180,
    # resource sampling
    "resource_sample_interval": 1.0,
    "resource_sample_duration": 180,
    # where to write results
    "OUTPUT_FILE": "pipeline_test_results.json"
}
# -----------------------

# helper: run command over ssh
def run_ssh_cmd(user, host, command):
    ssh_cmd = ["ssh", f"{user}@{host}", command]
    try:
        out = subprocess.check_output(ssh_cmd, stderr=subprocess.STDOUT, timeout=30)
        return out.decode("utf-8", errors="ignore")
    except subprocess.CalledProcessError as e:
        print(f"[ssh] cmd failed on {host}: {e.output.decode()}")
        raise
    except Exception as e:
        print(f"[ssh] exception: {e}")
        raise

# inject a log line into remote host using logger (safe)
def inject_log_via_logger(agent, message):
    # use 'logger' to send to syslog; choose facility auth or authpriv
    cmd = f"logger -t sentinells_test -p auth.info \"{message}\""
    return run_ssh_cmd(agent["user"], agent["host"], cmd)

# direct append to monitored file (needs permission)
def append_line_to_file(agent, path, line):
    safe_line = line.replace('"', '\\"')
    cmd = f"sudo sh -c 'echo \"{safe_line}\" >> {path}'"
    return run_ssh_cmd(agent["user"], agent["host"], cmd)

# query DB for raw logs matching token
def query_logs_by_token(db_file, token):
    conn = sqlite3.connect(db_file)
    cur = conn.cursor()
    # try 'logs' raw table first
    rows = []
    try:
        cur.execute(f"SELECT id, agent_id, source_type, timestamp, rawlog FROM {CONFIG['LOGS_TABLE']} WHERE rawlog LIKE ?", (f"%{token}%",))
        rows = cur.fetchall()
    except sqlite3.OperationalError:
        # table not found; attempt normalized table raw column
        try:
            cur.execute(f"SELECT id, agent_id, source_type, timestamp, event FROM {CONFIG['NORMALIZED_TABLE']} WHERE event LIKE ?", (f"%{token}%",))
            rows = cur.fetchall()
        except Exception:
            rows = []
    conn.close()
    return rows

# query analysis_results for entries referencing a given normalized log id
def query_analysis_by_log_id(db_file, log_id):
    conn = sqlite3.connect(db_file)
    cur = conn.cursor()
    try:
        # log_ids stored as JSON array string; search for substring
        cur.execute(f"SELECT id, log_ids, source_type, anomaly_type, severity, confidence, summary, analyzed_at FROM {CONFIG['ANALYSIS_TABLE']} WHERE log_ids LIKE ?", (f'%{log_id}%',))
        rows = cur.fetchall()
    except Exception as e:
        print("DB query error:", e)
        rows = []
    conn.close()
    return rows

# sample system resource usage for a duration (returns list of samples)
def sample_resources(duration_seconds, sample_interval=1.0):
    samples = []
    start = time.time()
    while time.time() - start < duration_seconds:
        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory()._asdict()
        # optionally monitor a process like 'ollama' or 'python' by name
        # collect top process memory/cpu if available
        procs = [(p.info['name'], p.info['cpu_percent'], p.info['memory_info'].rss) for p in psutil.process_iter(['name','cpu_percent','memory_info'])]
        samples.append({
            "ts": datetime.now(timezone.utc).isoformat(),
            "cpu_percent": cpu,
            "mem": mem,
            "process_snapshot": procs[:10]
        })
        time.sleep(sample_interval)
    return samples

# main test action: inject N logs (attack or benign) to an agent and wait for analysis
def run_injection_test(agent, lines, expected_label, db_file, use_logger=True, timeout=180):
    """
    lines: list of strings (raw log lines)
    expected_label: "attack" or "benign"
    returns: dict with timings and results per log
    """
    results = []
    token = str(uuid.uuid4())[:8]
    # include token and expected label inside each line so we can correlate
    tagged_lines = []
    for i, l in enumerate(lines):
        tag = f"SENTINELLS_TEST={token}"
        line = f"{l} {tag} type={expected_label}"
        tagged_lines.append(line)
    print(f"[test] injecting {len(tagged_lines)} lines to {agent['host']} (token={token})")

    # record injection timestamps and try to inject
    injection_times = []
    for line in tagged_lines:
        try:
            if use_logger:
                inject_log_via_logger(agent, line)
            else:
                append_line_to_file(agent, agent["log_path"], line)
            injection_times.append(datetime.now(timezone.utc).isoformat())
            time.sleep(0.05)  # small gap
        except Exception as e:
            print(f"[!] injection failed: {e}")
            injection_times.append(None)

    # now poll DB for raw rows with token
    start_ts = time.time()
    found_rows = []
    while time.time() - start_ts < timeout:
        rows = query_logs_by_token(db_file, token)
        if rows:
            found_rows = rows
            break
        time.sleep(CONFIG["poll_interval"])

    if not found_rows:
        print("[!] No normalized/raw logs found for token within timeout")
        return {"token": token, "injections": injection_times, "found_rows": [], "analysis": []}

    # for each found raw/normalized log, poll analysis_results for its id
    analyses = []
    for row in found_rows:
        log_id = row[0]
        print(f"[test] Found log id={log_id}, then polling analysis_results for it...")
        start_log_poll = time.time()
        found_analysis = []
        while time.time() - start_log_poll < timeout:
            rows = query_analysis_by_log_id(db_file, log_id)
            if rows:
                found_analysis = rows
                break
            time.sleep(CONFIG["poll_interval"])
        analyses.append({
            "log_id": log_id,
            "raw_row": row,
            "analysis_rows": found_analysis
        })

    return {
        "token": token,
        "injections": injection_times,
        "found_rows": found_rows,
        "analysis": analyses
    }

# run a test scenario: inject attacks and benign, measure latency/throughput/accuracy
def run_test_scenario():
    db_file = CONFIG["DB_FILE"]
    out = {
        "start_time": datetime.now(timezone.utc).isoformat(),
        "scenarios": [],
        "resource_samples": []
    }

    # start resource sampling in background (non-blocking simplistic)
    print("[*] Starting resource sampling in background ...")
    # we'll sample synchronously later to keep code simple

    # Example: run on the first agent a short bruteforce-like burst (using ssh-like messages)
    agent = CONFIG["agents"][0]
    # sample ssh failure lines similar to OpenSSH logs (make sure your normalizer patterns match)
    attack_lines = [
        'Oct 10 20:26:15 host sshd[9999]: Failed password for invalid user testuser from 192.0.2.5 port 55555 ssh2',
        'Oct 10 20:26:16 host sshd[9999]: Failed password for invalid user testuser from 192.0.2.5 port 55555 ssh2',
        'Oct 10 20:26:17 host sshd[9999]: Failed password for invalid user testuser from 192.0.2.5 port 55555 ssh2',
        'Oct 10 20:26:18 host sshd[9999]: error: maximum authentication attempts exceeded for invalid user testuser from 192.0.2.5 port 55555 ssh2 [preauth]'
    ]

    benign_lines = [
        'Oct 10 20:30:01 host CRON[2656]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)',
        'Oct 10 20:30:01 host CRON[2656]: pam_unix(cron:session): session closed for user root'
    ]

    # inject attack
    attack_result = run_injection_test(agent, attack_lines, expected_label="attack", db_file=db_file, use_logger=True, timeout=CONFIG["timeout_seconds"])
    out["scenarios"].append({"agent": agent["host"], "type": "attack", "result": attack_result})

    # small wait
    time.sleep(2)

    # inject benign
    benign_result = run_injection_test(agent, benign_lines, expected_label="benign", db_file=db_file, use_logger=True, timeout=CONFIG["timeout_seconds"])
    out["scenarios"].append({"agent": agent["host"], "type": "benign", "result": benign_result})

    # sample resources for a short time
    print("[*] Sampling resources for 10 seconds ...")
    resource_samples = sample_resources(duration_seconds=10, sample_interval=1.0)
    out["resource_samples"] = resource_samples

    out["end_time"] = datetime.now(timezone.utc).isoformat()

    # write JSON
    with open(CONFIG["OUTPUT_FILE"], "w") as f:
        json.dump(out, f, indent=2)

    print(f"[*] Test finished, results written to {CONFIG['OUTPUT_FILE']}")
    return out

if __name__ == "__main__":
    # sanity checks
    if not os.path.exists(CONFIG["DB_FILE"]):
        print(f"[!] DB file {CONFIG['DB_FILE']} not found. Please run from controller or provide DB access.")
    else:
        results = run_test_scenario()
        print(json.dumps(results, indent=2))
