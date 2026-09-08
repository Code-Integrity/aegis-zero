import json
import os

def load_json(path):
"""Load JSON file safely."""
if not os.path.exists(path):
print(f"[WARN] File not found: {path}")
return None
with open(path, "r", encoding="utf-8") as f:
return json.load(f)

def save_json(path, data):
"""Save JSON with directory auto-create."""
os.makedirs(os.path.dirname(path), exist_ok=True)
with open(path, "w", encoding="utf-8") as f:
json.dump(data, f, indent=2)

def save_text(path, text):
"""Save plain text."""
os.makedirs(os.path.dirname(path), exist_ok=True)
with open(path, "w", encoding="utf-8") as f:
f.write(text)