import time
from loguru import logger

# Configure Loguru to append formatted logs to another file
logger.add("formatted_logs.log", format="{time} {level} {message}", level="INFO", mode="a")

log_file = "generated_logs.log"

sleep_interval = 10
last_read_position = 0

def read_new_logs(file_path):
    """Reads only new files"""
    global last_read_position
    new_logs = []

    try:
        with open(file_path, "r") as file:
            file.seek(last_read_position)  # Move to last position
            new_logs = file.readlines()
            last_read_position = file.tell()  # Update file position to end
    except FileNotFoundError:
        logger.error("Log file not found!")
    return new_logs

def process_logs():
    """ Reads, formats, and saves logs """
    logs = read_new_logs(log_file)

    if logs:
        logger.info("Processing {len(logs)} new logs...")
        for log in logs:
            formatted_log = log.strip().replace("INFO", "[SECURITY EVENT]")  # Example: Format logs
            logger.info(f"Formatted Log: {formatted_log}")

        logger.info("Logs processed successfully!\n")
    else:
        logger.info("No new logs to process.")

if __name__ == "__main__":
    while True:
        process_logs()
        time.sleep(sleep_interval)