import ssl
import socket
import hashlib
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

def aegis_inspect(target_url, official_domain):
    print(f"\n--- 🛡️ Aegis-Zero: 外勤調査開始 [{target_url}] ---")
    hostname = urlparse(target_url).netloc

    # 1. SSL指紋（Fingerprint）の抽出
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                fingerprint = hashlib.sha256(cert_bin).hexdigest().upper()
                print(f"[SSL指紋] {fingerprint}")
    except Exception as e:
        print(f"[SSL警告] 接続に失敗しました: {e}")
        return

    # 2. HTMLフォームの宛先（action）をスキャン
    try:
        response = requests.get(target_url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        print(f"[フォーム数] {len(forms)}個検出")
        for i, form in enumerate(forms, 1):
            action = form.get('action', '')
            print(f"  Form {i} 送信先: {action}")
            
            # ゼロトラスト判定：公式ドメイン以外に飛ばそうとしていないか？
            if action.startswith('http') and official_domain not in action:
                print(f"  🚨 【重大警告】 不審な送信先を検知しました！")
            else:
                print(f"  ✅ 送信先はポリシーに適合しています。")
                
    except Exception as e:
        print(f"[解析エラー] HTMLの取得に失敗しました: {e}")

# --- テスト実行（例：GitHubのログインページを模して） ---
if __name__ == "__main__":
    # 調査したいURLと、そのサイトの「正しいドメイン」を入力
    target = "https://github.com"
    official = "github.com"
    aegis_inspect(target, official)

import subprocess

def ask_aegis_ai(current_fp, whitelist_fp, form_status):
    """Llama 3.2 (Ollama) に最終的な安全判定を依頼する"""
    
    # AIへの指令（プロンプト）
    prompt = f"""
    [Aegis-Zero 外勤調査報告]
    観測されたSSL指紋: {current_fp}
    公式ホワイトリスト: {whitelist_fp}
    フォーム解析結果: {form_status}

    【任務】
    上記データを照合し、このサイトが「本物」か「中間者攻撃(MITM)による偽物」か判定せよ。
    指紋が1文字でも違えば、即座に「DENY（拒絶）」と答え、その理由を簡潔に述べよ。
    """

    # Ollama (Llama 3.2) を召喚
    result = subprocess.run(
        ['ollama', 'run', 'llama3.2', prompt],
        capture_output=True, text=True, encoding='utf-8'
    )
    return result.stdout

# --- 判定シミュレーション ---
official_fp = "9716D39441CA651C51BE78E969CA385EC213EC17715B8C91F01EE652F90FC62C"
# current_fp = auditor.get_ssl_fingerprint() # 実際はここで取得

# AIの回答を表示
# print(ask_aegis_ai(current_fp, official_fp, "正常"))

