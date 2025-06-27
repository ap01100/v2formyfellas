#!/usr/bin/env python3
"""
Тестовый скрипт для проверки работы SingBoxProcessManager.
Запускает тестирование с использованием нового менеджера процессов.
"""

import os
import sys
import time
import logging
import argparse
from typing import List

# Настраиваем логирование
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Импортируем необходимые модули
from filter.url_tester import get_process_manager, shutdown_process_manager
from filter.utils import find_singbox_executable, cleanup_all_temp_files
from filter.config import SINGBOX_EXECUTABLE
from filter.main import test_configs

def read_configs_from_file(file_path: str, limit: int = None) -> List[str]:
    """
    Чтение конфигураций из файла.
    
    Args:
        file_path: Путь к файлу с конфигурациями
        limit: Ограничение количества конфигураций для тестирования
        
    Returns:
        Список строк конфигураций
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            # Читаем непустые строки, которые не начинаются с #
            configs = [line.strip() for line in f.readlines() if line.strip() and not line.strip().startswith('#')]
        
        if limit and limit > 0:
            configs = configs[:limit]
            
        logging.info(f"Прочитано {len(configs)} конфигураций из {file_path}")
        return configs
    except FileNotFoundError:
        logging.error(f"Файл не найден: {file_path}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Ошибка чтения файла {file_path}: {e}")
        sys.exit(1)

def main():
    """Основная функция."""
    parser = argparse.ArgumentParser(
        description="Тестирование SingBoxProcessManager",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument("input_file", help="Файл с конфигурациями для тестирования")
    parser.add_argument("-o", "--output-file", help="Файл для сохранения рабочих конфигураций")
    parser.add_argument("-w", "--workers", type=int, default=28, help="Количество параллельных потоков")
    parser.add_argument("-l", "--limit", type=int, help="Ограничить количество тестируемых конфигураций")
    parser.add_argument("-v", "--verbose", action="store_true", help="Подробный вывод")
    parser.add_argument("-a", "--advanced", action="store_true", help="Использовать расширенное тестирование")
    
    args = parser.parse_args()
    
    # Настраиваем уровень логирования
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Находим путь к sing-box
    singbox_path = find_singbox_executable() or SINGBOX_EXECUTABLE
    if not os.path.isfile(singbox_path):
        logging.error(f"sing-box не найден по пути: {singbox_path}")
        return 1
    
    logging.info(f"Используется sing-box: {singbox_path}")
    
    # Читаем конфигурации из файла
    configs = read_configs_from_file(args.input_file, args.limit)
    
    try:
        # Получаем менеджер процессов для логирования статистики
        process_manager = get_process_manager(singbox_path, args.verbose)
        
        # Запускаем тестирование
        start_time = time.time()
        
        test_urls = ["http://cp.cloudflare.com", "https://gemini.google.com"]
        
        logging.info(f"Запуск тестирования {len(configs)} конфигураций с {args.workers} потоками")
        
        results = test_configs(
            configs=configs,
            singbox_path=singbox_path,
            test_url=test_urls,
            timeout=5,
            workers=args.workers,
            verbose=args.verbose,
            advanced_test=args.advanced
        )
        
        end_time = time.time()
        elapsed = end_time - start_time
        
        # Выводим результаты
        logging.info(f"Тестирование завершено за {elapsed:.2f} секунд")
        logging.info(f"Найдено {len(results['working'])} рабочих конфигураций из {len(configs)}")
        
        # Выводим статистику менеджера процессов
        stats = process_manager.get_stats()
        logging.info(f"Статистика менеджера процессов:")
        logging.info(f"  Всего процессов: {stats['total_processes']}")
        logging.info(f"  Активные процессы: {stats['active_processes']}")
        logging.info(f"  Простаивающие процессы: {stats['idle_processes']}")
        logging.info(f"  Порты в использовании: {stats['ports_in_use']}")
        logging.info(f"  Среднее время работы: {stats['avg_uptime']:.2f} сек")
        
        # Сохраняем результаты, если указан выходной файл
        if args.output_file:
            try:
                with open(args.output_file, 'w', encoding='utf-8') as f:
                    for config in results["working"]:
                        f.write(f"{config}\n")
                logging.info(f"Сохранено {len(results['working'])} конфигураций в {args.output_file}")
            except Exception as e:
                logging.error(f"Ошибка сохранения результатов: {e}")
        
        return 0
    
    except KeyboardInterrupt:
        logging.info("Тестирование прервано пользователем")
        return 130
    except Exception as e:
        logging.error(f"Ошибка при тестировании: {e}", exc_info=True)
        return 1
    finally:
        # Очищаем ресурсы
        cleanup_all_temp_files()
        shutdown_process_manager()

if __name__ == "__main__":
    sys.exit(main()) 