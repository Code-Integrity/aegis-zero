import json
import os

# ---------------------------------------------------------
# Utils
# ---------------------------------------------------------
from utils.file_io import load_json, save_json, save_text
from utils.logger import log
from utils.formatter import format_depth4_tree, format_llama_payload

# ---------------------------------------------------------
# Recon Modules
# ---------------------------------------------------------
from recon.devtools_extract import extract_all
from recon.depth4_tree import preprocess_devtools_logs_depth4
from recon.scoring import score_vulnerability_node

# ---------------------------------------------------------
# LLaMA Inference Backend
# ---------------------------------------------------------
from models.llama3.inference import run_llama_inference


# ---------------------------------------------------------
# CONFIG LOADER
# ---------------------------------------------------------
def load_config():
 config_dir = "config"

 def load(name):
 return load_json(os.path.join(config_dir, name)) or {}

 return {
 "model": load("model.json"),
 "paths": load("paths.json"),
 "settings": load("settings.json")
 }


# ---------------------------------------------------------
# MAIN PROCESS
# ---------------------------------------------------------
def main():
 log("=== AEGIS-ZERO Recon Engine (Optimized Auto-Inference Mode) ===")

 # 1. Load config
 log("[1] Loading config...")
 cfg = load_config()
 model_cfg = cfg["model"]
 paths = cfg["paths"]
 settings = cfg["settings"]

 # 2. Load DevTools logs
 log("[2] Loading DevTools logs...")
 network_logs = load_json(paths.get("network_file"))
 console_logs = load_json(paths.get("console_file"))
 storage_logs = load_json(paths.get("storage_file"))
 sources_logs = load_json(paths.get("sources_file"))

 # 3. Extract key items
 log("[3] Extracting key items...")
 extracted = extract_all(network_logs, console_logs, storage_logs, sources_logs)

 # 4. Generate Depth4 tree
 log("[4] Generating Depth4 binary tree...")
 depth4_tree_json = preprocess_devtools_logs_depth4(
 network_logs, console_logs, storage_logs, sources_logs
 )
 depth4_tree = json.loads(depth4_tree_json)

 formatted_tree = format_depth4_tree(depth4_tree)
 save_json(paths.get("depth4_output"), formatted_tree)
 log(f"[OK] Depth4 tree saved → {paths.get('depth4_output')}")

 # 5. Scoring
 scoring_results = []
 if settings.get("enable_scoring", True):
 log("[5] Running vulnerability scoring...")
 scoring_results = [score_vulnerability_node(node) for node in depth4_tree]
 save_json(paths.get("scoring_output"), scoring_results)
 log(f"[OK] Scoring results saved → {paths.get('scoring_output')}")

 # 6. Prepare LLaMA payload
 if settings.get("enable_llama_payload", True):
 log("[6] Preparing LLaMA payload...")
 llama_payload = format_llama_payload(
 model_cfg.get("prompt_file"),
 model_cfg.get("llama_model_path"),
 depth4_tree,
 scoring_results
 )
 save_json(paths.get("llama_payload"), llama_payload)
 log(f"[OK] LLaMA payload saved → {paths.get('llama_payload')}")

 # 7. Auto-inference
 if settings.get("enable_llama_inference", True):
 log("[7] Running LLaMA inference automatically...")
 llama_output = run_llama_inference()
 save_text(paths.get("llama_output"), llama_output)
 log(f"[OK] LLaMA output saved → {paths.get('llama_output')}")

 log("=== Completed: AEGIS-ZERO Auto-Inference Mode ===")


if __name__ == "__main__":
 main()
