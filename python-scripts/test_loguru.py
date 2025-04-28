from loguru import logger

# Save logs to a file
logger.add("app.log", format="{time} {level} {message}", level="INFO")
logger.add("app.log", rotation="500 KB") # Create a new file when it exceeds 500 KB
logger.info("Logging with rotation enabled!")

logger.debug("This is a debug message.") #Won't be logged (level is INFO)
logger.info("This is an info message.")
logger.warning("This is a warning message.")
logger.error("This is an error message.")
logger.critical("This is a critical error!")
