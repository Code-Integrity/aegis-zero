import json
import os
import datetime
import argparse
import subprocess
import sys
from core.scanner import FileScanner
from core.auditor import Auditor

# 設定ファイル (Aegis-Zero内のパスを維持するため絶対パス化を推奨)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, "config/settings.json")
LOG_FILE = os.path.join(BASE_DIR, "logs/audit_results.log")

def load_config():
    with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)

def get_staged_files(project_path):
    """指定されたディレクトリのGit変更ファイル名を取得"""
    result = subprocess.run(
        ['git', 'diff', '--name-only', 'HEAD'],
        capture_output=True, text=True,
        cwd=project_path
    )
    return result.stdout.splitlines()

def main():
    # 引数の解析
    parser = argparse.ArgumentParser(description="Aegis-Zero: AI Security Auditor")
    parser.add_argument('--git-check', action='store_true', help='Gitプッシュ前監査モード')
    parser.add_argument('--project-path', type=str, help='監査対象のプロジェクトディレクトリ')
    args = parser.parse_args()

    config = load_config()
    auditor = Auditor()

    # 1. 監査対象ファイルのリストアップ
    if args.git_check:
        p_path = args.project_path if args.project_path else os.getcwd()
        print(f"🛡️ [Aegis-Zero] 迎撃対象: {p_path}")

        raw_files = get_staged_files(p_path)
        files = []
        
        # --- 🛡️ 監視対象ファイルの定義強化 ---
        # プロセスの邪魔をしないよう、チェックすべき重要ファイル名をリスト化
        critical_keywords = ['.env', '.git', 'robots.txt', 'docker-compose.yml', 'Dockerfile']
        
        for f in raw_files:
            full_path = os.path.join(p_path, f)
            
            # PHPファイル、または機密キーワードが含まれるファイルを抽出
            is_php = f.endswith('.php')
            is_critical = any(keyword in f for keyword in critical_keywords)
            
            if is_php or is_critical:
                files.append(full_path)
    else:
        target_path = config['target_path']
        exclude_dirs = set(config['exclude_dirs'])
        if not os.path.exists(target_path):
            print(f"❌ パスが見つかりません: {target_path}")
            return
        scanner = FileScanner(target_path, exclude_dirs)
        print(f"🚀 Aegis-Zero 全件迎撃開始: {target_path}")
        files = scanner.get_php_files()

    if not files:
        print("✨ 監査対象のファイルは見つかりませんでした。")
        sys.exit(0)

    has_critical_error = False

    # 2. 監査の実行とログ記録
    with open(LOG_FILE, "a", encoding="utf-8") as log:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        mode_name = "Git監査" if args.git_check else "全件監査"
        log.write(f"\n--- {mode_name}開始: {timestamp} ---\n")

        for file_path in files:
            # .git自体はディレクトリなので、ファイルの存在チェックで弾かれないよう配慮
            if not os.path.exists(file_path) and '.git' not in file_path:
                continue

            print(f"🔍 監査中: {file_path}")
            
            # ディレクトリ（.git等）そのものを見つけた場合の特別処理
            if os.path.isdir(file_path) and '.git' in file_path:
                result = "一発アウト: 公開ディレクトリに.gitが存在します。全ソースコード漏洩の恐れがあります。"
            else:
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        code = f.read()
                    result = auditor.audit_code(file_path, code)
                except Exception as e:
                    result = f"⚠️ 読み込みエラー: {e}"

            log.write(f"【ファイル】: {file_path}\n{result}\n" + "-"*30 + "\n")

            if "一発アウト" in result:
                print(f"❌ 警告: {file_path} は極めて危険です。")
                has_critical_error = True
            else:
                print(f"✅ {file_path}: 合格")

    # 3. 判定
    if args.git_check and has_critical_error:
        print("\n🚨 深刻な脆弱性、または機密ファイルの露出を検知したため、プッシュを阻止します。")
        sys.exit(1)

    print("\n✅ 全てのプロセスが正常に完了しました。")
    sys.exit(0)

if __name__ == "__main__":
    main()
