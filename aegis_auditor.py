import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import subprocess

def aegis_js_scan(target_url):
    print(f"\n--- 🏹 Aegis-Zero: バグハント開始 [{target_url}] ---")
    
    try:
        response = requests.get(target_url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # 1. ページ内に直接書かれているインラインJavaScriptを抽出
        scripts = soup.find_all('script')
        print(f"[インラインJS] {len(scripts)}個のスクリプトブロックを検出")
        
        for i, script in enumerate(scripts, 1):
            js_code = script.string
            if js_code and len(js_code).strip() > 0:
                # 危険なキーワード（Sink）が1つでも含まれているか簡易スクリーニング
                sinks = [s for s in ['document.write', 'innerHTML', 'eval(', 'location.href'] if s in js_code]
                if sinks:
                    print(f"  🚨 Block {i}: 危険なSink {sinks} を検知！AIに精密解析を依頼します...")
                    # Ollamaを召喚して解析
                    ai_report = ask_aegis_ai_hunter(js_code, "Inline-Script")
                    print(ai_report)
                    print("-" * 40)

    except Exception as e:
        print(f"[解析エラー] HTMLの取得に失敗しました: {e}")

def ask_aegis_ai_hunter(js_code, source_type):
    """Llama 3.2 (Ollama) にハッカーとしてコードの脆弱性解析を依頼する"""
    
    # バグバウンティ専用の「ハッカー仕様プロンプト」
    prompt = f"""
    あなたはHackerOneで賞金を狙うエリートハッカーです。
    提供されたJavaScriptコード（種類: {source_type}）を静的解析し、外部からの入力値（URLパラメータやlocation.searchなど）が、安全に処理されずに危険な関数（document.write, innerHTML, eval, location.hrefなど）へ流れ込んでいる『DOMベースXSS』の脆弱性があるか判定してください。

    【解析対象のコード】
    {js_code}

    【任務】
    1. 脆弱性（DOMベースXSS）が「ある（VULNERABLE）」か「ない（SAFE）」かを明確に答えてください。
    2. 脆弱性がある場合、危険な関数（Sink）の名前と、外部からのデータの入り口（Source）を特定してください。
    3. このバグを実際に発動（PoC）させるための、具体的な攻撃ペイロード（例：<script>alert(1)</script> などを用いた具体的なURLや入力値の例）を提示してください。
    """

    # Ollama (Llama 3.2) を召喚
    try:
        result = subprocess.run(
            ['ollama', 'run', 'llama3.2', prompt],
            capture_output=True, text=True, encoding='utf-8', timeout=30
        )
        return result.stdout
    except Exception as e:
        return f"[AI召喚エラー] {e}"

# --- 実戦テスト（例：PortSwiggerのアカデミーで今見つけたバグのコードを模して） ---
if __name__ == "__main__":
    # ターゲットURLの指定（実戦時はここを変える）
    # target = "https://example.com"
    # aegis_js_scan(target)
    
    # テスト用：さっきPortSwiggerで見つけた実際のdocument.writeのコードを直接流し込んでみる
    test_code = """
    var query = (new URLSearchParams(window.location.search)).get('search');
    if (query) {
        document.write('<img src="/resources/images/tracker.gif?searchTerms='+query+'">');
    }
    """
    print("[テスト] さっきのPortSwiggerのバグコードをAIチェッカーに投げてみます...")
    report = ask_aegis_ai_hunter(test_code, "PortSwigger-Lab1")
    print(report)
