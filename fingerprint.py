import requests # Ollamaと喋るために必要

def tell_ollama_warning(current_fp, saved_fp):
    url = "http://127.0.0"
    # AIへの「叫び」の命令文
    prompt = f"警告：GitHubのSSL指紋が不一致です！記録済み: {saved_fp}, 現在: {current_fp}。偽サイトや通信傍受の危険性を分析し、短く警告してください。"
    
    data = {
        "model": "llama3", # あなたが使っているモデル名に変えてください
        "prompt": prompt,
        "stream": False
    }
    
    response = requests.post(url, json=data)
    print("【AIからの緊急分析】:", response.json().get('response'))

# ここに、さっきの指紋比較ロジックを入れます
import ssl
import socket
import hashlib

def get_github_fingerprint():
    hostname = 'github.com'
    port = 443
    
    # 1. 相手のサーバーから「身分証（証明書）」を直接もらう
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert_bin = ssock.getpeercert(binary_form=True)
            
            # 2. 身分証から「指紋」を作成（SHA-256）
            fingerprint = hashlib.sha256(cert_bin).hexdigest()
            return fingerprint

# 実行して表示
current_fingerprint = get_github_fingerprint()
print(f"【検証対象】: github.com")
print(f"【現在の指紋】: {current_fingerprint}")

