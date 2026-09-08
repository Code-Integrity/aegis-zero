# auditors/js_domxss_auditor.py

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import subprocess
import os

from utils.logger import log


SINK_KEYWORDS = [
"document.write",
"innerHTML",
"eval(",
"location.href",
]


PROMPT_PATH = "prompts/js_domxss_prompt.txt"


def load_prompt_template():
"""prompts/js_domxss_prompt.txt を読み込む"""
if not os.path.exists(PROMPT_PATH):
raise FileNotFoundError(f"Prompt file not found: {PROMPT_PATH}")
with open(PROMPT_PATH, "r", encoding="utf-8") as f:
return f.read()


def build_prompt(template: str, js_code: str, source_type: str) -> str:
"""テンプレート内のプレースホルダに JS コードを埋め込む"""
return template.format(
source_type=source_type,
js_code=js_code,
)


def call_llama_with_prompt(prompt: str) -> str:
"""Ollama (LLaMA3) を使って解析を実行する"""
try:
result = subprocess.run(
["ollama", "run", "llama3.2"],
input=prompt,
capture_output=True,
text=True,
encoding="utf-8",
timeout=60,
)
return result.stdout or "[INFO] No output from model."
except Exception as e:
return f"[AI召喚エラー] {e}"


def aegis_js_scan(target_url: str):
"""対象URLのインラインJavaScriptを走査し、DOMベースXSSの疑いをAIに解析させる"""
log(f"--- 🏹 Aegis-Zero JS Auditor: バグハント開始 [{target_url}] ---")

try:
response = requests.get(
target_url,
timeout=10,
headers={"User-Agent": "Mozilla/5.0"},
)
except Exception as e:
log(f"[解析エラー] HTMLの取得に失敗しました: {e}")
return

soup = BeautifulSoup(response.text, "html.parser")
scripts = soup.find_all("script")
log(f"[インラインJS] {len(scripts)}個のスクリプトブロックを検出")

try:
template = load_prompt_template()
except Exception as e:
log(f"[プロンプト読み込みエラー] {e}")
return

for i, script in enumerate(scripts, 1):
js_code = script.string
if not js_code or not js_code.strip():
continue

sinks = [s for s in SINK_KEYWORDS if s in js_code]
if not sinks:
continue

log(f"🚨 Block {i}: 危険なSink {sinks} を検知、AIに精密解析を依頼します…")

prompt = build_prompt(template, js_code=js_code, source_type="Inline-Script")
ai_report = call_llama_with_prompt(prompt)

print("\n" + "-" * 60)
print(f"[Block {i} AI Report]")
print(ai_report)
print("-" * 60)


if __name__ == "__main__":
# 手動テスト用
test_url = "https://example.com"
aegis_js_scan(test_url)
