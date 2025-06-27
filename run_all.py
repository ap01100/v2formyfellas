#!/usr/bin/env python3
"""
Единый скрипт для запуска всех операций v2formyfellas:
1. Скачивание конфигураций
2. Базовое URL-тестирование
3. Расширенное тестирование
"""

import os
import sys
import argparse
import logging
import datetime
import platform
import subprocess
from pathlib import Path

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def ensure_directory(directory):
    """Создает директорию, если она не существует."""
    os.makedirs(directory, exist_ok=True)
    
def get_singbox_path():
    """Определяет путь к исполняемому файлу sing-box."""
    system = platform.system()
    if system == "Windows":
        singbox_path = os.path.join("bin", "sing-box.exe")
    else:
        singbox_path = os.path.join("bin", "sing-box")
    
    if not os.path.exists(singbox_path):
        logging.error(f"sing-box не найден по пути: {singbox_path}")
        logging.info("Установите sing-box в директорию bin/ или укажите путь с помощью --singbox-path")
        return None
        
    return singbox_path

def main():
    parser = argparse.ArgumentParser(
        description="v2formyfellas - Скачивание и тестирование прокси-конфигураций"
    )
    
    parser.add_argument(
        "-s", "--sources", 
        default="filter/sources.txt",
        help="Файл со списком источников конфигураций (по умолчанию: filter/sources.txt)"
    )
    parser.add_argument(
        "-w", "--workers", 
        type=int, 
        default=30,
        help="Количество параллельных потоков для тестирования (по умолчанию: 30)"
    )
    parser.add_argument(
        "--singbox-path", 
        help="Путь к исполняемому файлу sing-box"
    )
    parser.add_argument(
        "--skip-download", 
        action="store_true",
        help="Пропустить этап скачивания конфигураций"
    )
    parser.add_argument(
        "--skip-url-test", 
        action="store_true",
        help="Пропустить этап URL-тестирования"
    )
    parser.add_argument(
        "--skip-advanced-test", 
        action="store_true",
        help="Пропустить этап расширенного тестирования"
    )
    parser.add_argument(
        "-v", "--verbose", 
        action="store_true",
        help="Подробный вывод"
    )
    
    args = parser.parse_args()
    
    # Настройка уровня логирования
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Создаем директорию для результатов, если она не существует
    ensure_directory("results")
    
    # Получаем текущую дату и время для имен файлов
    now = datetime.datetime.now()
    datestamp = now.strftime("%Y%m%d")
    timestamp = now.strftime("%H%M%S")
    
    # Формируем имена файлов
    configs_file = f"results/configs_{datestamp}_{timestamp}.txt"
    url_working_file = f"results/working_url_{datestamp}.txt"
    advanced_working_file = f"results/working_advanced_{datestamp}.txt"
    
    # Определяем путь к sing-box
    singbox_path = args.singbox_path or get_singbox_path()
    if not singbox_path and not (args.skip_url_test and args.skip_advanced_test):
        return 1
    
    # 1. Скачивание конфигураций
    if not args.skip_download:
        logging.info("=== Скачивание конфигураций ===")
        download_cmd = [
            sys.executable, "-m", "filter", "download",
            "-s", args.sources, "-o", configs_file
        ]
        
        if args.verbose:
            download_cmd.append("-v")
            
        logging.debug(f"Выполняется команда: {' '.join(download_cmd)}")
        download_result = subprocess.run(download_cmd)
        
        if download_result.returncode != 0:
            logging.error("Ошибка при скачивании конфигураций!")
            return 1
    else:
        logging.info("Этап скачивания конфигураций пропущен.")
        # Проверяем существование файла только если нужны последующие этапы
        if not (args.skip_url_test and args.skip_advanced_test) and not os.path.exists(configs_file):
            logging.error(f"Файл конфигураций {configs_file} не существует!")
            return 1
    
    # 2. Базовое URL-тестирование
    if not args.skip_url_test:
        logging.info("=== Запуск базового URL-тестирования ===")
        url_test_cmd = [
            sys.executable, "-m", "filter", "test",
            configs_file, "-o", url_working_file,
            "-w", str(args.workers), "--singbox-path", singbox_path
        ]
        
        if args.verbose:
            url_test_cmd.append("-v")
            
        logging.debug(f"Выполняется команда: {' '.join(url_test_cmd)}")
        url_test_result = subprocess.run(url_test_cmd)
        
        if url_test_result.returncode != 0:
            logging.warning("Внимание: URL-тестирование не нашло рабочих конфигураций.")
    else:
        logging.info("Этап базового URL-тестирования пропущен.")
    
    # 3. Расширенное тестирование
    if not args.skip_advanced_test:
        logging.info("=== Запуск расширенного тестирования ===")
        
        # Определяем входной файл для расширенного тестирования
        input_file = url_working_file if not args.skip_url_test else configs_file
        
        if not os.path.exists(input_file):
            logging.error(f"Файл {input_file} не существует!")
            return 1
            
        advanced_test_cmd = [
            sys.executable, "-m", "filter", "test",
            input_file, "-o", advanced_working_file, "-a",
            "-w", str(args.workers), "--singbox-path", singbox_path
        ]
        
        if args.verbose:
            advanced_test_cmd.append("-v")
            
        logging.debug(f"Выполняется команда: {' '.join(advanced_test_cmd)}")
        advanced_test_result = subprocess.run(advanced_test_cmd)
        
        if advanced_test_result.returncode != 0:
            logging.warning("Внимание: Расширенное тестирование не нашло рабочих конфигураций.")
    else:
        logging.info("Этап расширенного тестирования пропущен.")
    
    # Выводим итоговую информацию
    logging.info("=== Готово! ===")
    logging.info(f"Все конфигурации: {configs_file}")
    
    if not args.skip_url_test and os.path.exists(url_working_file):
        logging.info(f"Рабочие URL-конфигурации: {url_working_file}")
        
    if not args.skip_advanced_test and os.path.exists(advanced_working_file):
        logging.info(f"Рабочие расширенные конфигурации: {advanced_working_file}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 