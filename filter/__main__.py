"""
Точка входа для запуска модуля filter как пакета.
"""

import sys
import os
from pathlib import Path

# Добавляем родительскую директорию в sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Импортируем и запускаем main.py
from filter import main

if __name__ == "__main__":
    sys.exit(main.main()) 