import os
import time
import requests

LOG_FILE = "/home/netadmin/project-env/sentinelLS/python-scripts/formatted_logs.log"
OFFSET_FILE = ".llm_offset"
OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "qwen3:1.7b_Analysisbot"  # Change if using a different model

def get_last_position():
    if os.path.exists(OFFSET_FILE):
        with open(OFFSET_FILE, "r") as f:
            return int(f.read())
    return 0

def save_position(pos):
    with open(OFFSET_FILE, "w") as f:
        f.write(str(pos))

def read_new_logs():
    position = get_last_position()
    new_logs = []

    with open(LOG_FILE, "r") as f:
        f.seek(position)
        for line in f:
            new_logs.append(line.strip())
        current_pos = f.tell()

    save_position(current_pos)
    return new_logs

def build_prompt(log_lines):
    if not log_lines:
        return None

    log_block = "\n".join(log_lines)
    prompt = f"""--- LOG BATCH START ---
{log_block}
--- LOG BATCH END ---

Analyze the logs above for any suspicious or abnormal activity."""
    return prompt

def send_to_ollama(prompt):
    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": False
    }
    response = requests.post(OLLAMA_URL, json=payload)
    if response.status_code == 200:
        return response.json()["response"]
    else:
        print(f"[ERROR] Ollama API returned {response.status_code}: {response.text}")
        return None

def main():
    while True:
        log_lines = read_new_logs()
        if log_lines:
            prompt = build_prompt(log_lines)
            if prompt:
                print("\n[INFO] Sending logs to LLM for analysis...")
                analysis = send_to_ollama(prompt)
                if analysis:
                    print("\n[LLM Analysis Result]")
                    print(analysis)
        else:
            print("[INFO] No new logs to process.")

        time.sleep(30)  # wait before next check

if __name__ == "__main__":
    main()
