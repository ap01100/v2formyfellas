"""
Точка входа для запуска модуля download_configs как пакета.
"""

import sys
import os
from pathlib import Path

# Добавляем родительскую директорию в sys.path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

# Импортируем и запускаем download_configs.py
from filter import download_configs

if __name__ == "__main__":
    sys.exit(download_configs.main()) 