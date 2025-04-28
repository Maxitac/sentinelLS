import time
import random
from loguru import logger

# Configure Loguru to write logs to a file
logger.add("generated_logs.log", format="{time} {level} {message}", level="INFO")

# Sample log messages
log_messages = [
	"User login successful",
	"Failed login attempt",
	"Firewall detached unusual traffic",
	"User logged out",
	"Security scan completed",
	"New SSH connection established",
]

# Continuously generate logs
while True:
	message = random.choice(log_messages)
	logger.info(message)
	time.sleep(2) #2 seconds wait
