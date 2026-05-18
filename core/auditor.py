import ollama
import os

class Auditor:
    def __init__(self, model='llama3.2'):
        self.model = model

    def audit_code(self, file_path, code):
        # 憲法（ルール）を読み込む
        rules_path = 'rules/php_rules.txt'
        if os.path.exists(rules_path):
            with open(rules_path, 'r', encoding='utf-8') as f:
                rules = f.read()
        else:
            rules = "ゼロトラストに基づき、厳格にセキュリティ監査を行え。"

        # ルールを冒頭に据えたプロンプト
        prompt = f"""
{rules}

---
上記の「監査憲法」に基づき、以下のファイルを冷徹に監査せよ。
存在しないコードの捏造（ハルシネーション）は厳禁とする。

【対象ファイル】: {file_path}
【コード】:
{code}
"""
        response = ollama.chat(model=self.model, messages=[
            {'role': 'user', 'content': prompt},
        ])
        return response['message']['content']

