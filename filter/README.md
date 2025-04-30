# Proxy Configuration Tester

Инструмент для тестирования и фильтрации работоспособных прокси-конфигураций для различных протоколов (Shadowsocks, Trojan, VMess, VLESS).

## Особенности

- Тестирование URL: проверка способности прокси-соединения загружать заданный URL
- Расширенное тестирование: проверка TCP-соединения и определение исходящего IP-адреса
- Параллельное выполнение тестов для повышения скорости
- Поддержка нескольких протоколов прокси (SS, Trojan, VMess, VLESS)
- Консолидированный интерфейс командной строки для всех видов тестирования

## Требования

- Python 3.6+
- sing-box (https://github.com/SagerNet/sing-box)
- netcat (nc) для расширенного TCP-тестирования
- Python-зависимости: requests

## Установка

1. Клонируйте репозиторий:
```bash
git clone https://github.com/yourusername/proxy-config-tester.git
cd proxy-config-tester
```

2. Установите Python-зависимости:
```bash
pip install requests
```

3. Убедитесь, что sing-box установлен и доступен в PATH или укажите путь к нему при запуске.

4. Для расширенного тестирования установите netcat:
```bash
# Ubuntu/Debian
sudo apt install netcat-traditional
# или
sudo apt install netcat-openbsd
```

## Использование

### Базовое тестирование URL

```bash
python main.py input.txt -o working.txt
```

### Расширенное тестирование

```bash
python main.py input.txt -o working.txt -a
```

### Комбинированное тестирование (URL, затем расширенное)

```bash
python main.py input.txt -o advanced_working.txt --url-then-advanced --temp-file url_working.txt
```

### Параметры командной строки

```
usage: main.py [-h] [-o OUTPUT_FILE] [-ao APPEND_OUTPUT] [-u URL] [-t TIMEOUT] [-w WORKERS] [-a]
               [--tcp-host TCP_HOST] [--tcp-port TCP_PORT] [--tcp-timeout TCP_TIMEOUT]
               [--ip-service-url IP_SERVICE_URL] [--ip-service-timeout IP_SERVICE_TIMEOUT]
               [--advanced-workers ADVANCED_WORKERS] [--singbox-path SINGBOX_PATH] [-v]
               [--no-dedup] [--url-then-advanced] [--temp-file TEMP_FILE]
               input_file

Тестирование конфигураций прокси с помощью URL-тестирования и расширенного тестирования.

positional arguments:
  input_file            Файл, содержащий конфигурации прокси для тестирования

options:
  -h, --help            показать это справочное сообщение и выйти
  -o OUTPUT_FILE, --output-file OUTPUT_FILE
                        Файл для сохранения рабочих конфигураций
  -ao APPEND_OUTPUT, --append-output APPEND_OUTPUT
                        Добавлять рабочие конфигурации в этот файл вместо перезаписи
  -u URL, --url URL     URL для тестирования прокси
  -t TIMEOUT, --timeout TIMEOUT
                        Тайм-аут запроса в секундах
  -w WORKERS, --workers WORKERS
                        Количество параллельных потоков тестирования
  -a, --advanced        Выполнение расширенных тестов (TCP, IP) для конфигураций
  --tcp-host TCP_HOST   Хост для TCP-тестов в расширенном режиме
  --tcp-port TCP_PORT   Порт для TCP-тестов в расширенном режиме
  --tcp-timeout TCP_TIMEOUT
                        Тайм-аут для TCP-тестов в расширенном режиме
  --ip-service-url IP_SERVICE_URL
                        URL сервиса определения IP в расширенном режиме
  --ip-service-timeout IP_SERVICE_TIMEOUT
                        Тайм-аут для запросов IP-сервиса в расширенном режиме
  --advanced-workers ADVANCED_WORKERS
                        Количество параллельных потоков для расширенного тестирования
  --singbox-path SINGBOX_PATH
                        Путь к исполняемому файлу sing-box
  -v, --verbose         Включить подробное логирование (уровень DEBUG)
  --no-dedup            Пропустить дедупликацию входных конфигураций
  --url-then-advanced   Сначала запустить URL-тестирование, затем расширенное тестирование на рабочих конфигурациях
  --temp-file TEMP_FILE Временный файл для сохранения промежуточных результатов URL-тестирования
```

## Структура проекта

- `main.py` - основной скрипт для запуска тестирования
- `config.py` - конфигурационные константы
- `utils.py` - общие утилиты
- `parsers.py` - парсеры конфигураций для разных протоколов
- `url_tester.py` - модуль тестирования URL
- `advanced_tester.py` - модуль расширенного тестирования (TCP, IP)
- `parallel.py` - утилиты для параллельного выполнения

## Расширение

Для добавления поддержки новых протоколов прокси:

1. Добавьте функцию парсера в `parsers.py`
2. Обновите словарь `parser_map` в функции `convert_to_singbox_config`

## Лицензия

MIT 