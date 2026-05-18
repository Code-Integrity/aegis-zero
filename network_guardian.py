import ssl
import socket
import hashlib
import os
import platform
import subprocess
import requests
import time

# --- 設定：守りたいサイトと「本物の指紋」 ---
TARGET_SITES = {
    "github.com": "9716d39441ca651c51be78e969ca385ec213ec17715b8c91f01ee652f90fc62c",
    "laravel.com": "2f893af634024740e7b39404ee14d72d78312c944f6b47844c9a0089b0d24e40",
    #"school-domain.jp": "9aaf1c481ad38eb8d8628b6e9152e191e6485b41b49276898ef6da1dfc5f6952",#
    "google.com": "d223496393f995e9eb7b4941976cee7f568bb0fe46e920fdf608865fcfe897f8",
    "updates.signal.org": "9eda1eaf0f8121d6e1f50b7788d52abf2a40558750af20849d33c5c24ffd29ed",
    "visualstudio.com": "55de24beb6da578a822fd253afb83b7bface8eee1e58d1d286a2399af9e23c35",
    "registry-1.docker.io": "af74d8d5f18c5e46ef2e7aaf319da90e6d1168d6b7389f106a8ae453c3a35593",
    "youtube.com": "d223496393f995e9eb7b4941976cee7f568bb0fe46e920fdf608865fcfe897f8",
    "www.amazon.co.jp": "0c9bb8b79352603f0fafc5a670e0e094a42b7f8b260753fbfe3222b6b29b668e"
}

def play_alert_sound():
    """異常時に警告音を鳴らす（WSLからWindowsを叩く設定）"""
    try:
        for _ in range(3):
            # Windowsのビープ音を鳴らす
            subprocess.run(["powershell.exe", "-Command", "[Console]::Beep(2000, 500)"], capture_output=True)
            time.sleep(0.1)
    except:
        pass

def kill_browser():
    """ブラウザを強制終了して通信を遮断する"""
    current_os = platform.system()
    try:
        if current_os == "Windows":
            subprocess.run(["taskkill", "/F", "/IM", "chrome.exe", "/T"], capture_output=True)
            subprocess.run(["taskkill", "/F", "/IM", "msedge.exe", "/T"], capture_output=True)
        else:
            # WSL上のLinux側ブラウザも想定
            subprocess.run(["pkill", "-9", "chrome"], capture_output=True)
            subprocess.run(["pkill", "-9", "google-chrome"], capture_output=True)
        print("🛡️ [Guardian] 緊急防御：ブラウザを強制終了しました。")
    except Exception as e:
        print(f"⚠️ 強制終了失敗: {e}")

def get_fingerprint(hostname):
    """サイトの「指紋」を取得する"""
    try:
        context = ssl.create_default_context()
        # タイムアウトを短めに設定して全体の流れを止めないようにする
        with socket.create_connection((hostname, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                return hashlib.sha256(cert_bin).hexdigest()
    except:
        return None

def ask_ollama(host, current_fp, saved_fp):
    """Ollamaに分析を依頼する"""
    url = "http://127.0.0"
    prompt = f"警告：{host}のSSL指紋が不一致です！記録:{saved_fp}, 現在:{current_fp}。攻撃の危険性を分析し、日本語で短く叫んで！"
    try:
        res = requests.post(url, json={"model": "llama3", "prompt": prompt, "stream": False}, timeout=10)
        print(f"\n🚨 【AI警告】: {res.json().get('response')}")
    except:
        print("\n🚨 【緊急】指紋不一致！AI通信に失敗しましたが、直ちにネットを切断してください！")

def monitor():
    """監視ループ：1分おきに全サイトをチェック"""
    print("📡 [Guardian] 外部サイトの監視を開始しました（1分おき）...")
    while True:
        for host, saved_fp in TARGET_SITES.items():
            current_fp = get_fingerprint(host)
            
            # 1. 接続に失敗した場合はエラーにせずスキップ（重要）
            if current_fp is None:
                print(f"⚠️ {host}: 接続失敗（スキップします）")
                continue

            # 2. 指紋が一致しない（異常検知）場合
            if current_fp != saved_fp:
                print(f"‼️ {host} で異常検知！指紋が異なります。")
                play_alert_sound()  # 音
                kill_browser()      # 遮断
                ask_ollama(host, current_fp, saved_fp) # 分析
                return # 攻撃を検知したら安全のためループを停止

            # 3. 正常な場合
            print(f"✅ {host}: 正常 (FP: {current_fp[:10]}...)")
        
        # 次のチェックまで1分待機
        time.sleep(60)

if __name__ == "__main__":
    monitor()

