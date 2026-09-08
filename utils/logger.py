from datetime import datetime

def log(msg):
"""Simple timestamped logger."""
ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
print(f"[{ts}] {msg}")