"""
Точка входа для запуска модуля filter как пакета.
Поддерживает несколько команд: test (тестирование), download (скачивание).
"""

import sys
import os
import argparse
from pathlib import Path

# Добавляем родительскую директорию в sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Импортируем модули
from filter import main, download

def main_cli():
    """Основная функция CLI с поддержкой нескольких команд."""
    parser = argparse.ArgumentParser(
        description="v2formyfellas - инструмент для работы с прокси-конфигурациями"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Доступные команды")
    
    # Команда test (тестирование)
    test_parser = subparsers.add_parser("test", 
                                       help="Тестирование конфигураций",
                                       epilog="Примечание: Тестирование можно прервать в любой момент, нажав Ctrl+C. Все временные файлы будут очищены.",
                                       formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    test_parser.add_argument("input_file", help="Файл с конфигурациями для тестирования")
    test_parser.add_argument("-o", "--output-file", help="Файл для сохранения рабочих конфигураций")
    test_parser.add_argument("-ao", "--append-output", help="Добавить рабочие конфигурации в этот файл")
    test_parser.add_argument("-u", "--url", action="append", help="URL для тестирования (можно указать несколько раз)")
    test_parser.add_argument("--urls-file", help="Файл со списком URL для тестирования")
    test_parser.add_argument("--url-mode", choices=["all", "any"], default="all", help="Режим тестирования URL")
    test_parser.add_argument("-t", "--timeout", type=float, default=10.0, help="Таймаут запроса в секундах")
    test_parser.add_argument("-w", "--workers", type=int, default=10, help="Количество параллельных потоков")
    test_parser.add_argument("-a", "--advanced", action="store_true", help="Выполнить расширенное тестирование")
    test_parser.add_argument("--tcp-host", help="Хост для TCP-тестов в расширенном режиме")
    test_parser.add_argument("--tcp-port", type=int, help="Порт для TCP-тестов в расширенном режиме")
    test_parser.add_argument("--tcp-timeout", type=float, help="Таймаут для TCP-тестов в расширенном режиме")
    test_parser.add_argument("--ip-service-url", help="URL для определения IP в расширенном режиме")
    test_parser.add_argument("--ip-service-timeout", type=float, help="Таймаут для запросов к IP-сервису в расширенном режиме")
    test_parser.add_argument("--advanced-workers", type=int, help="Количество параллельных потоков для расширенного тестирования")
    test_parser.add_argument("--singbox-path", help="Путь к исполняемому файлу sing-box")
    test_parser.add_argument("-v", "--verbose", action="store_true", help="Подробный вывод")
    test_parser.add_argument("--no-dedup", action="store_true", help="Пропустить дедупликацию конфигураций")
    test_parser.add_argument("--advanced-dedup", action="store_true", help="Использовать расширенную дедупликацию")
    test_parser.add_argument("--url-then-advanced", action="store_true", help="Сначала URL-тестирование, затем расширенное")
    test_parser.add_argument("--temp-file", help="Временный файл для промежуточных результатов URL-тестирования")
    test_parser.add_argument("--use-http-proxy", action="store_true", help="Использовать HTTP-прокси вместо SOCKS5")
    
    # Команда download (скачивание)
    download_parser = subparsers.add_parser("download", help="Скачивание конфигураций")
    download_parser.add_argument('-u', '--url', help="URL для скачивания конфигураций")
    download_parser.add_argument('-f', '--file', help="Локальный файл с конфигурациями")
    download_parser.add_argument('-s', '--sources', help="Файл со списком источников (URLs или пути к файлам)")
    download_parser.add_argument('-o', '--output', required=True, help="Выходной файл для сохранения конфигураций")
    download_parser.add_argument('-a', '--append', action='store_true', help="Добавить к существующему файлу вместо перезаписи")
    download_parser.add_argument('-v', '--verbose', action='store_true', help="Подробный вывод")
    
    args = parser.parse_args()
    
    if args.command == "test" or args.command is None:
        # По умолчанию используем команду test
        # Передаем sys.argv напрямую в main.main()
        sys.argv = [sys.argv[0]] + sys.argv[2:]
        return main.main()
    elif args.command == "download":
        # Передаем sys.argv напрямую в download.main()
        sys.argv = [sys.argv[0]] + sys.argv[2:]
        return download.main()
    else:
        parser.print_help()
        return 1

if __name__ == "__main__":
    sys.exit(main_cli()) 