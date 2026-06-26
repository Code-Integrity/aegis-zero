import os
import subprocess

def ask_aegis_ai_vdp_static_analyzer(target_code):
    """通信を一切発生させず、剥ぎ取られたコードのみを安全に100%静的解析する"""
    prompt = f"""
    あなたはHackerOneのVDP（脆弱性開示プログラム）で活動する、規約と安全性を最優先するエリート・ホワイトハッカーです。
    実在する企業のWebサイトから手動で剥ぎ取ってきた、以下のコード（HTML/JavaScript/通信パラメータなど）を『完全オフライン』で静的解析してください。

    【解析対象のコード】
    {target_code}

    【任務（HackerOne VDP仕様）】
    1. 脆弱性の有無（VULNERABLE / SAFE）を冷徹に判定してください。
    2. 脆弱性がある場合、その『危険性（インパクト）』と、外部からのデータの入り口（Source）および危険な処理（Sink）を正確に特定してください。
    3. 【超重要】HackerOneのVDP規約に完全準拠し、企業側のデータを破壊・改ざんしない『100%安全な概念実証（PoC）』の手順を示してください。
       - XSSであれば、クッキー強奪ではなく `alert(document.domain)` や `console.log(1)` を使用。
       - SSRFであれば、内部データの破壊ではなく `http://localhost/` などの安全な応答サイズ確認に留める。
       - CSRFであれば、実際のメールを上書きせず、手動で検証可能な安全なダミーフォームの構造を示す。
    4. 企業のセキュリティチームへそのまま提出（コピペ）できる形式の『HackerOne 脆弱性報告書テンプレート（英語または日本語）』を自動生成してください。
    5. 開発者がこのバグを安全に修正するための、具体的な防御コード例（サニタイズ、トークン実装、ホワイトリストなど）を提示してください。
    """

    print("\n[Aegis-Zero] 🛡️ 外部通信: 遮断状態（完全ステルス）")
    print("[Aegis-Zero] 🧠 ローカルOllama(Llama 3.2)で静的解析を実行中...")
    try:
        result = subprocess.run(
            ['/usr/bin/ollama', 'run', 'llama3.2', prompt],
            capture_output=True, text=True, encoding='utf-8', timeout=90
        )
        return result.stdout
    except Exception as e:
        return f"[AI召喚エラー] {e}"

if __name__ == "__main__":
    print("==========================================================")
    print("🦅 Aegis-Zero: HackerOne VDP ステルス静的解析システム v3.0")
    print("==========================================================")
    
    # ⚠️ 【使い方】
    # 実際のWebサイトのF12（検証）から、怪しいと思ったHTMLやJavaScriptの塊を
    # コピーして、以下のトリプルクォーテーション（\"\"\"）の間にペタッと貼り付けてください。
    
    captured_code = """
    <form class="login-form" name="change-email-form" action="/my-account/change-email" method="POST">
        <label>Email</label>
        <input required type="email" name="email" value="">
        <button class="button" type="submit">Update email</button>
    </form>
    """
    
    # 完全隔離された安全な脳内でスキャンを実行
    report = ask_aegis_ai_vdp_static_analyzer(captured_code)
    print("\n==========================================================")
    print("🎯 【Aegis-Zero VDPステルス静的解析報告書】")
    print("==========================================================")
    print(report)
