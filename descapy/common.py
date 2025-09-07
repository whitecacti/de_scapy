from datetime import datetime, timezone
import logging
import sys

def get_curr_time():
    return datetime.now(timezone.utc).isoformat()

def setup_logger(name=__name__, level=logging.INFO):
    """Set up logger with consistent formatting"""

    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Avoid adding multiple handlers
    if logger.handlers:
        return logger

    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)

    # File handler (optional)
    file_handler = logging.FileHandler('app.log')
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)

    # Add handlers to logger
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    return logger

# Create default logger
logger = setup_logger()