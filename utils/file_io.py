# utils/file_io.py

import os
import json
from typing import Dict, Any, List, Optional
from utils.logger import log

def load_json(file_path: str) -> Optional[Any]:
    """
    Safely ingests and parses a targeted JSON resource file.
    Defensively intercepts file absence or character encoding syntax corruptions.
    """
    if not file_path or not os.path.exists(file_path):
        log(f"[WARNING] Requested payload file matrix absent at location: {file_path}")
        return None
        
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as parse_err:
        log(f"[ERROR] Serialization error. Invalid JSON structural syntax format in {file_path}: {str(parse_err)}")
        return None
    except Exception as e:
        log(f"[ERROR] Unexpected I/O reading fault encountered inside {file_path}: {str(e)}")
        return None

def save_json(file_path: str, data: Any) -> bool:
    """
    Serializes application state payloads cleanly into target file targets.
    Auto-validates data availability and encapsulates pipeline errors.
    """
    if data is None:
        log(f"[WARNING] Aborting write pipeline for {file_path}: Inbound data reference is null.")
        return False
        
    try:
        # Parent directory existence is already enforced by run_analysis.py step 1.5,
        # but standard defensive fallback is preserved here.
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        log(f"[ERROR] Failed to serialize and dump dynamic JSON data matrices to {file_path}: {str(e)}")
        return False

def save_text(file_path: str, content: str) -> bool:
    """
    Writes raw textual analytics stream reports (e.g., AI output logs) to local workspace locations.
    """
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)
        return True
    except Exception as e:
        log(f"[ERROR] Standard file text pipeline export crash recorded at {file_path}: {str(e)}")
        return False
