import time
from pygtail import Pygtail

log_file = "test.log"

print(f"Monitoring {log_file} for new entries...\n")

while True:
	for line in Pygtail(log_file):
		print(line.strip()) # Print new log lines without extra spaces

	time.sleep(2) # Waiit for 2 seconds
