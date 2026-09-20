# utils/logger.py

from datetime import datetime

def log(message: str) -> None:
    """
    Standardized framework application logger. 
    Injects high-precision timing parameters to support runtime event sequence sorting.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}")
