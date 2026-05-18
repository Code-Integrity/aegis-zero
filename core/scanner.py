import os

class FileScanner:
    def __init__(self, target_dir, exclude_dirs=None):
        self.target_dir = target_dir
        self.exclude_dirs = exclude_dirs or {'.venv', 'vendor', 'node_modules', '.git', 'storage'}

    def get_php_files(self):
        php_files = []
        for root, dirs, files in os.walk(self.target_dir):
            # 除外リストにあるディレクトリをスキップ
            dirs[:] = [d for d in dirs if d not in self.exclude_dirs]
            for file in files:
                if file.endswith('.php'):
                    php_files.append(os.path.join(root, file))
        return php_files
