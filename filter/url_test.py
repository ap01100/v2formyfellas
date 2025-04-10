import time
import socket
import subprocess
import json
import base64
import urllib.parse
import concurrent.futures
import tempfile
import os
import argparse
import logging
import re
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Any

# --- Logging Setup ---
# Устанавливаем базовый уровень INFO, чтобы видеть прогресс без -v
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Constants ---
DEFAULT_TEST_URL = "https://www.google.com/generate_204"
DEFAULT_TIMEOUT = 10
DEFAULT_WORKERS = 5
SINGBOX_EXECUTABLE = "sing-box" # Предполагаем, что sing-box в PATH или указываем полный путь

# --- Вспомогательные функции ---

def find_free_port() -> int:
    """Находит свободный TCP порт."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def cleanup_process(process: Optional[subprocess.Popen], verbose: bool = False):
    """Аккуратно завершает процесс и читает его вывод."""
    if process and process.poll() is None: # Проверяем, что процесс еще жив
        logging.debug(f"Завершение процесса {process.pid}...")
        try:
            process.terminate()
            process.wait(timeout=2) # Даем время на завершение
            logging.debug(f"Процесс {process.pid} завершен через terminate.")
        except subprocess.TimeoutExpired:
            logging.warning(f"Процесс {process.pid} не завершился за 2 сек, отправка kill...")
            process.kill()
            process.wait()
            logging.debug(f"Процесс {process.pid} завершен через kill.")
        except Exception as e:
            logging.error(f"Ошибка при попытке завершить процесс {process.pid}: {e}")

    # Попытка прочитать остатки вывода, чтобы избежать блокировок
    if process:
        stdout, stderr = "", ""
        try:
            # Используем communicate для безопасного чтения без блокировок
            stdout, stderr = process.communicate(timeout=1)
            if verbose and (stdout or stderr):
                 logging.debug(f"Вывод процесса {process.pid} при завершении:\nSTDOUT:\n{stdout[:500]}\nSTDERR:\n{stderr[:500]}")
        except subprocess.TimeoutExpired:
             logging.warning(f"Таймаут при чтении вывода завершенного процесса {process.pid}")
        except Exception as e:
             logging.error(f"Ошибка при чтении вывода процесса {process.pid}: {e}")


def cleanup_file(filepath: Optional[str]):
    """Удаляет временный файл."""
    if filepath and os.path.exists(filepath):
        try:
            os.remove(filepath)
            logging.debug(f"Временный файл удален: {filepath}")
        except Exception as e:
            logging.error(f"Ошибка при удалении файла {filepath}: {e}")

# --- Парсеры конфигураций (оставлены без изменений из вашего кода) ---

def parse_ss_config(config_str: str) -> Dict[str, Any]:
    """Парсит конфигурацию Shadowsocks (ss://)."""
    parsed = urllib.parse.urlparse(config_str)
    user_info_part = parsed.netloc.split('@')[0]
    server_part = parsed.netloc.split('@')[1]
    host, port_str = server_part.split(':')
    port = int(port_str)

    method = None # Инициализация
    password = None # Инициализация

    try:
        # Попытка декодировать user_info как base64 (старый формат)
        decoded_user_info = base64.urlsafe_b64decode(user_info_part + '===').decode('utf-8')
        method, password = decoded_user_info.split(':', 1)
    except (base64.binascii.Error, ValueError, UnicodeDecodeError):
        # Если не base64, считаем, что формат method:password
        # Это может быть неверно для некоторых URI, где только пароль в base64
        logging.warning(f"Не удалось декодировать user_info '{user_info_part}' как base64 для SS, предполагается формат method:password или только пароль base64")
        try:
            # Простой вариант: если нет ':' предполагаем только пароль (декодируя)
            password = base64.urlsafe_b64decode(user_info_part + '===').decode('utf-8')
            # Метод нужно будет указать по умолчанию или извлечь иначе
            method = "aes-256-gcm" # Пример! Установите здесь ваш дефолтный метод
            logging.warning(f"Метод не найден явно, использован метод по умолчанию: {method}")
        except Exception as inner_e:
             logging.error(f"Не удалось определить метод/пароль SS из '{user_info_part}'. Ошибка: {inner_e}")
             raise ValueError(f"Не удалось определить метод/пароль SS из '{user_info_part}'")

    if not method or not password:
         raise ValueError("Не удалось извлечь метод или пароль SS")

    remark = parsed.fragment if parsed.fragment else host

    return {
        "type": "shadowsocks",
        "tag": f"ss-out-{remark[:10]}",
        "server": host,
        "server_port": port,
        "method": method,
        "password": password,
    }

def parse_trojan_config(config_str: str) -> Dict[str, Any]:
    """Парсит конфигурацию Trojan (trojan://)."""
    parsed = urllib.parse.urlparse(config_str)
    password = parsed.username if parsed.username else parsed.netloc.split('@')[0] # Пароль может быть до @
    server_part = parsed.netloc.split('@')[1] if '@' in parsed.netloc else parsed.netloc
    host, port_str = server_part.split(':')
    port = int(port_str)
    remark = parsed.fragment if parsed.fragment else host
    query_params = urllib.parse.parse_qs(parsed.query)

    outbound = {
        "type": "trojan",
        "tag": f"trojan-out-{remark[:10]}",
        "server": host,
        "server_port": port,
        "password": password,
        "tls": { # Trojan обычно требует TLS
            "enabled": True,
            "server_name": query_params.get('sni', [host])[0],
            "insecure": query_params.get('allowInsecure', ['0'])[0] == '1',
            # Дополнительные параметры TLS (alpn, fingerprint) могут быть в query_params
            "alpn": query_params.get('alpn', [None])[0].split(',') if query_params.get('alpn', [None])[0] else None,
        }
    }
    # Обработка транспорта WS
    transport_type = query_params.get('type', ['tcp'])[0]
    if transport_type == 'ws':
        ws_settings = {
             "type": "ws",
             "path": query_params.get('path', ['/'])[0],
             "headers": {"Host": query_params.get('host', [host])[0]}
        }
        # В sing-box транспорт указывается внутри основного объекта
        outbound["transport"] = ws_settings
    elif transport_type != 'tcp':
        logging.warning(f"Тип транспорта '{transport_type}' для Trojan пока не полностью поддерживается в этом парсере.")


    return outbound

def parse_vmess_config(config_str: str) -> Dict[str, Any]:
    """Парсит конфигурацию VMess (vmess://)."""
    try:
        encoded_json = config_str.replace("vmess://", "")
        padding = "=" * (4 - len(encoded_json) % 4)
        decoded_json = base64.b64decode(encoded_json + padding).decode('utf-8')
        vmess_params = json.loads(decoded_json)
    except Exception as e:
        raise ValueError(f"Ошибка декодирования VMess JSON: {e}")

    remark = vmess_params.get("ps", vmess_params.get("add", "vmess"))

    outbound = {
        "type": "vmess",
        "tag": f"vmess-out-{remark[:10]}",
        "server": vmess_params.get("add"),
        "server_port": int(vmess_params.get("port", 443)),
        "uuid": vmess_params.get("id"),
        "security": vmess_params.get("scy", vmess_params.get("security", "auto")), # Добавил синоним "security"
        "alter_id": int(vmess_params.get("aid", 0)),
    }

    tls_enabled = vmess_params.get("tls", "") == "tls"
    if tls_enabled:
        outbound["tls"] = {
            "enabled": True,
            "server_name": vmess_params.get("sni", vmess_params.get("host", vmess_params.get("add"))),
            "insecure": str(vmess_params.get("allowInsecure", vmess_params.get("allow_insecure", "false"))).lower() == "true", # Добавил синоним и проверку строки
            "alpn": vmess_params.get('alpn', '').split(',') if vmess_params.get('alpn') else None,
        }

    net_type = vmess_params.get("net", "tcp")
    if net_type != "tcp":
         transport = {"type": net_type}
         if net_type == "ws":
             transport["path"] = vmess_params.get("path", "/")
             # В VMess JSON поле для Host хедера обычно "host"
             ws_host = vmess_params.get("host", vmess_params.get("add"))
             if ws_host:
                 transport["headers"] = {"Host": ws_host}
         elif net_type == "grpc":
             # В sing-box поле называется 'service_name'
             transport["service_name"] = vmess_params.get("path", vmess_params.get("serviceName", ""))
         # Другие типы транспорта (h2, quic) можно добавить здесь
         outbound["transport"] = transport

    return outbound

def parse_vless_config(config_str: str) -> Dict[str, Any]:
    """Парсит конфигурацию VLESS (vless://)."""
    parsed = urllib.parse.urlparse(config_str)
    uuid = parsed.username if parsed.username else parsed.netloc.split('@')[0]
    server_part = parsed.netloc.split('@')[1] if '@' in parsed.netloc else parsed.netloc
    host, port_str = server_part.split(':')
    port = int(port_str)
    remark = parsed.fragment if parsed.fragment else host
    query_params = urllib.parse.parse_qs(parsed.query)

    outbound = {
        "type": "vless",
        "tag": f"vless-out-{remark[:10]}",
        "server": host,
        "server_port": port,
        "uuid": uuid,
        "flow": query_params.get('flow', [None])[0],
    }

    security = query_params.get('security', ['none'])[0]
    if security == 'tls' or security == 'reality':
        tls_settings = {
            "enabled": True,
            "server_name": query_params.get('sni', [host])[0],
            "insecure": query_params.get('allowInsecure', ['0'])[0] == '1',
             "alpn": query_params.get('alpn', [None])[0].split(',') if query_params.get('alpn', [None])[0] else None,
        }
        if security == 'reality':
            reality_opts = {
                 "enabled": True,
                 "public_key": query_params.get('pbk', [None])[0],
                 "short_id": query_params.get('sid', [None])[0],
             }
            # Уточняем параметр fingerprint для sing-box
            fp = query_params.get('fp', [None])[0]
            if fp:
                 reality_opts["fingerprint"] = fp
            tls_settings["reality"] = reality_opts

            # Важно: для Reality часто нужен явный server_name (куда пойдут 'реальные' пакеты)
            # Если sni не указан, он может быть равен host
            tls_settings["server_name"] = query_params.get('sni', [host])[0]

        else: # Просто TLS
            fp = query_params.get('fp', [None])[0]
            if fp:
                 tls_settings["utls"] = {"enabled": True, "fingerprint": fp} # или просто "fingerprint" в зависимости от версии sing-box

        outbound["tls"] = tls_settings

    transport_type = query_params.get('type', ['tcp'])[0]
    if transport_type != 'tcp':
        transport = {"type": transport_type}
        if transport_type == 'ws':
            transport["path"] = query_params.get('path', ['/'])[0]
            transport["headers"] = {"Host": query_params.get('host', [host])[0]}
        elif transport_type == 'grpc':
            transport["service_name"] = query_params.get('serviceName', [''])[0]
        # Другие транспорты: h2, quic
        outbound["transport"] = transport

    return outbound

def convert_to_singbox_config(config_str: str, socks_port: int) -> Dict[str, Any]:
    """Конвертирует строку конфигурации в формат JSON для sing-box."""
    base_config = {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [{
            "type": "socks",
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "listen_port": socks_port,
            "sniff": True,
             "sniff_override_destination": True, # Полезно для VLESS/Trojan с domain-based routing
             "users": []
        }],
        "outbounds": []
    }

    parser_map = {
        "ss://": parse_ss_config,
        "trojan://": parse_trojan_config,
        "vmess://": parse_vmess_config,
        "vless://": parse_vless_config,
    }

    parsed_outbound = None
    protocol_parsed = "unknown"
    for prefix, parser in parser_map.items():
        if config_str.startswith(prefix):
            protocol_parsed = prefix.replace("://","")
            try:
                parsed_outbound = parser(config_str)
                logging.debug(f"Успешно распарсен как {protocol_parsed}: {config_str[:40]}...")
                break
            except Exception as e:
                logging.error(f"Ошибка парсинга '{config_str[:40]}...' как {protocol_parsed}: {e}", exc_info=False) # Убрал полный трейсбек по умолчанию
                raise ValueError(f"Ошибка парсинга {protocol_parsed} конфигурации") from e

    if not parsed_outbound:
        raise ValueError(f"Неподдерживаемый или некорректный протокол: {config_str[:40]}...")

    # Добавляем основной outbound и прямой/блочный для полноты
    base_config["outbounds"].append(parsed_outbound)

    # Добавляем простое правило маршрутизации: все через наш outbound
    base_config["route"] = {
        "rules": [
            {
                 # Правило для DNS, чтобы он тоже шел через прокси
                 "protocol": ["dns"],
                 "outbound": parsed_outbound["tag"]
            },
            {
                "outbound": parsed_outbound["tag"] # Основное правило
            }
        ],
        "final": parsed_outbound["tag"] # Явно указываем final outbound
    }
    # Добавляем DNS сервер для разрешения через прокси
    base_config["dns"] = {
        "servers": [
            {"tag": "proxy-dns", "address": "1.1.1.1", "detour": parsed_outbound["tag"]}, # Направляем DNS через наш outbound
            {"tag": "local-dns", "address": "local"}, # Fallback на локальный DNS
            {"tag": "block-dns", "address": "rcode://success"} # Для блокировки
        ],
        "rules": [
             {"server": "proxy-dns"} # Использовать DNS через прокси по умолчанию
        ],
        "strategy": "prefer_ipv4"
    }

    return base_config

# --- Функция теста ---

def perform_url_test(config_str: str, test_url: str, timeout: float, singbox_path: str, verbose: bool) -> Dict[str, Any]:
    """
    Выполняет URL-тест для одной конфигурации, используя sing-box.
    Запускает sing-box на свободном порту.
    Возвращает словарь с результатами.
    """
    # Используем более короткий префикс для логов
    log_prefix = f"Тест [{config_str[:25]}...]"
    logging.info(f"{log_prefix} Запуск...")

    result = {
        "config": config_str, # Сохраняем полный конфиг для возврата в случае успеха
        "success": False,
        "latency_ms": float('inf'),
        "status_code": None,
        "error": None,
    }
    socks_port: Optional[int] = None
    config_file: Optional[str] = None
    proxy_process: Optional[subprocess.Popen] = None
    session = None

    try:
        # 1. Найти свободный порт
        socks_port = find_free_port()
        local_proxy = f"socks5h://127.0.0.1:{socks_port}" # socks5h для DNS через прокси
        logging.debug(f"{log_prefix} Назначен порт {socks_port}")

        # 2. Сгенерировать конфиг sing-box
        try:
            singbox_config = convert_to_singbox_config(config_str, socks_port)
            if verbose: # Выводим конфиг только в verbose режиме
                 logging.debug(f"{log_prefix} Сгенерированный конфиг sing-box:\n{json.dumps(singbox_config, indent=2)}")
        except ValueError as e:
            result["error"] = f"Ошибка конфигурации: {e}"
            logging.error(f"{log_prefix} {result['error']}")
            return result # Возвращаем ошибку, дальше не идем

        # 3. Записать конфиг во временный файл
        # Используем try-finally для гарантии удаления файла
        try:
             # Создаем файл в контекстном менеджере, но нам нужно имя файла вне его
             f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
             config_file = f.name
             json.dump(singbox_config, f, indent=2)
             f.close() # Закрываем файл, чтобы sing-box мог его прочитать
             logging.debug(f"{log_prefix} Конфиг записан в {config_file}")
        except Exception as e:
             result["error"] = f"Ошибка записи временного конфига: {e}"
             logging.error(f"{log_prefix} {result['error']}")
             # cleanup_file(config_file) # Файл может еще не существовать
             return result

        # 4. Запустить sing-box
        cmd = [singbox_path, "run", "-c", config_file]
        logging.debug(f"{log_prefix} Запуск команды: {' '.join(cmd)}")
        try:
             proxy_process = subprocess.Popen(
                 cmd,
                 stdout=subprocess.PIPE,
                 stderr=subprocess.PIPE,
                 text=True,
                 encoding='utf-8', # Явно указываем кодировку
                 errors='replace' # Заменяем ошибки декодирования
             )
        except FileNotFoundError:
             result["error"] = f"Исполняемый файл sing-box не найден по пути: {singbox_path}"
             logging.error(f"{log_prefix} {result['error']}")
             cleanup_file(config_file)
             return result
        except Exception as e:
             result["error"] = f"Не удалось запустить sing-box: {e}"
             logging.error(f"{log_prefix} {result['error']}")
             cleanup_file(config_file)
             return result


        # 5. Дождаться запуска sing-box (проверка порта)
        start_wait = time.time()
        port_ready = False
        singbox_error_output = ""
        logging.debug(f"{log_prefix} Ожидание доступности порта {socks_port}...")
        while time.time() - start_wait < 10: # Ждем до 10 секунд
            # Проверяем, не завершился ли процесс с ошибкой
            if proxy_process.poll() is not None:
                logging.error(f"{log_prefix} Процесс sing-box ({proxy_process.pid}) неожиданно завершился с кодом {proxy_process.returncode} во время ожидания порта.")
                # Читаем stderr для диагностики
                try:
                    _, stderr_output = proxy_process.communicate(timeout=1)
                    singbox_error_output = stderr_output[:1000] # Ограничиваем объем
                    logging.error(f"{log_prefix} STDERR sing-box:\n{singbox_error_output}")
                except Exception as e:
                    logging.error(f"{log_prefix} Не удалось прочитать stderr sing-box после ошибки: {e}")
                result["error"] = f"Sing-box не запустился (код {proxy_process.returncode}). См. логи для STDERR."
                # cleanup_process не нужен, т.к. он уже завершился
                cleanup_file(config_file)
                return result

            try:
                with socket.create_connection(("127.0.0.1", socks_port), timeout=0.2):
                    port_ready = True
                    logging.debug(f"{log_prefix} Порт {socks_port} готов за {time.time() - start_wait:.2f} сек.")
                    break
            except (socket.timeout, ConnectionRefusedError):
                time.sleep(0.3) # Небольшая пауза перед следующей проверкой
            except Exception as e:
                 logging.error(f"{log_prefix} Неожиданная ошибка при проверке порта {socks_port}: {e}")
                 time.sleep(0.5)


        if not port_ready:
            logging.error(f"{log_prefix} Таймаут ожидания sing-box на порту {socks_port}.")
            result["error"] = f"Таймаут ожидания sing-box ({socks_port})"
            # Завершаем процесс и читаем вывод для диагностики
            cleanup_process(proxy_process, verbose)
            cleanup_file(config_file)
            return result

        # 6. Выполнить HTTP-запрос через прокси
        try:
            # Импортируем requests здесь, т.к. он проверяется в main
            import requests
            session = requests.Session()
            session.proxies = {
                "http": local_proxy,
                "https": local_proxy
            }

            logging.debug(f"{log_prefix} Выполнение GET запроса к {test_url} через {local_proxy}...")
            start_time = time.time()
            response = session.get(test_url, timeout=timeout)
            latency = (time.time() - start_time) * 1000 # в мс

            result["success"] = True
            result["latency_ms"] = round(latency)
            result["status_code"] = response.status_code
            # Логируем успех на уровне INFO
            logging.info(f"{log_prefix} УСПЕХ - Задержка: {result['latency_ms']}ms, Статус: {result['status_code']}")

        except requests.exceptions.Timeout:
             result["error"] = f"Ошибка теста URL: Таймаут ({timeout} сек)"
             logging.warning(f"{log_prefix} {result['error']}")
        except requests.exceptions.ProxyError as e:
             result["error"] = f"Ошибка теста URL: Ошибка прокси - {str(e)[:200]}"
             logging.warning(f"{log_prefix} {result['error']}")
        except requests.exceptions.RequestException as e:
             result["error"] = f"Ошибка теста URL: {type(e).__name__} - {str(e)[:200]}"
             logging.warning(f"{log_prefix} {result['error']}")
        except Exception as e: # Ловим прочие возможные ошибки
             result["error"] = f"Неожиданная ошибка теста URL: {type(e).__name__}: {str(e)[:200]}"
             logging.error(f"{log_prefix} {result['error']}", exc_info=verbose) # Показывать traceback в verbose

    except Exception as e:
        # Ловим ошибки этапов 1-5 (поиск порта, генерация/запись конфига, запуск/ожидание sing-box)
        result["error"] = f"Общая ошибка подготовки теста: {type(e).__name__}: {str(e)[:200]}"
        logging.error(f"{log_prefix} {result['error']}", exc_info=verbose) # Показывать traceback в verbose

    finally:
        # 7. Закрыть сессию requests
        if session:
             session.close()
             logging.debug(f"{log_prefix} Сессия requests закрыта.")
        # 8. Остановить sing-box и удалить файл
        logging.debug(f"{log_prefix} Очистка ресурсов...")
        cleanup_process(proxy_process, verbose)
        cleanup_file(config_file)
        logging.debug(f"{log_prefix} Очистка завершена.")

    return result

# --- Основная функция ---

def main():
    parser = argparse.ArgumentParser(
        description="Параллельное тестирование VPN/Proxy конфигураций (ss, vmess, vless, trojan) с использованием sing-box.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
        )
    parser.add_argument(
        "input_file",
        type=Path,
        help="Путь к текстовому файлу со списком конфигураций URI (по одной на строку)."
        )
    parser.add_argument(
        "-o", "--output_file",
        type=Path,
        required=True,
        # Изменено описание выходного файла
        help="Путь к текстовому файлу для сохранения РАБОЧИХ конфигураций URI (по одной на строку)."
        )
    parser.add_argument(
        "-w", "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help="Количество параллельных потоков для тестирования."
        )
    parser.add_argument(
        "-u", "--url",
        type=str,
        default=DEFAULT_TEST_URL,
        help="URL для выполнения теста доступности через прокси."
        )
    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help="Таймаут для URL теста в секундах."
        )
    parser.add_argument(
        "-s", "--singbox-path",
        type=str,
        default=SINGBOX_EXECUTABLE,
        help="Путь к исполняемому файлу sing-box."
        )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Включить подробное логирование (уровень DEBUG)."
        )

    args = parser.parse_args()

    # Устанавливаем уровень логирования DEBUG, если указан флаг -v
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Включен режим подробного логирования (DEBUG).")

    # Обновляем глобальную переменную пути к sing-box (хотя лучше передавать как параметр)
    # Но для простоты пока оставим так, раз perform_url_test его принимает
    effective_singbox_path = args.singbox_path

    # Проверка наличия sing-box
    try:
        logging.debug(f"Проверка sing-box по пути: {effective_singbox_path}")
        # Используем capture_output=True чтобы скрыть вывод версии
        process_result = subprocess.run([effective_singbox_path, "version"], check=True, capture_output=True, text=True, timeout=5)
        logging.info(f"Используется sing-box: {effective_singbox_path} (Версия: {process_result.stdout.strip()})")
    except FileNotFoundError:
        logging.error(f"КРИТИЧЕСКАЯ ОШИБКА: Исполняемый файл sing-box НЕ НАЙДЕН по пути: '{effective_singbox_path}'")
        logging.error("Убедитесь, что sing-box установлен, имеет права на выполнение (chmod +x) и путь указан верно (через --singbox-path или он есть в $PATH).")
        return # Выходим, если sing-box не найден
    except subprocess.CalledProcessError as e:
        logging.error(f"Ошибка при вызове '{effective_singbox_path} version': {e}")
        logging.error(f"Вывод ошибки sing-box: {e.stderr}")
        return
    except subprocess.TimeoutExpired:
         logging.error(f"Таймаут при проверке версии sing-box: {effective_singbox_path}")
         return
    except Exception as e:
        logging.error(f"Неожиданная ошибка при проверке sing-box ('{effective_singbox_path}'): {e}")
        return

    # Проверка наличия requests
    try:
        import requests
        logging.debug(f"Модуль 'requests' успешно импортирован.")
    except ImportError:
        logging.error("КРИТИЧЕСКАЯ ОШИБКА: Модуль 'requests' не найден.")
        logging.error("Пожалуйста, установите его командой: pip install requests")
        return # Выходим, если requests не найден


    # Чтение конфигураций
    configs = []
    try:
        logging.info(f"Чтение конфигураций из файла: {args.input_file}")
        with open(args.input_file, 'r', encoding='utf-8') as f:
            # Фильтруем пустые строки и строки, начинающиеся с # (комментарии)
            configs = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
        if not configs:
             logging.warning(f"Файл '{args.input_file}' пуст или содержит только комментарии/пустые строки. Тестировать нечего.")
             return
        logging.info(f"Загружено {len(configs)} конфигураций для тестирования.")
    except FileNotFoundError:
        logging.error(f"КРИТИЧЕСКАЯ ОШИБКА: Файл не найден: {args.input_file}")
        return
    except Exception as e:
        logging.error(f"Ошибка чтения файла {args.input_file}: {e}")
        return

    # Список для хранения рабочих конфигураций
    working_configs = []
    start_time_total = time.time()
    total_configs = len(configs)

    logging.info(f"Начало параллельного тестирования ({args.workers} потоков)...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        # Создаем задачи, передавая необходимые аргументы в perform_url_test
        future_to_config = {
            executor.submit(perform_url_test, config, args.url, args.timeout, effective_singbox_path, args.verbose): config
            for config in configs
        }

        # Собираем результаты по мере выполнения
        for i, future in enumerate(concurrent.futures.as_completed(future_to_config), 1):
            original_config_str = future_to_config[future]
            try:
                # Получаем результат из функции perform_url_test
                result_dict = future.result()

                # Логируем общий прогресс
                status_msg = "УСПЕХ" if result_dict['success'] else "НЕУДАЧА"
                error_msg = f" Ошибка: {result_dict['error']}" if not result_dict['success'] and result_dict['error'] else ""
                # Не выводим latency для неудачных тестов
                latency_msg = f" Задержка: {result_dict['latency_ms']}ms" if result_dict['success'] else ""

                logging.info(f"({i}/{total_configs}) [{original_config_str[:25]}...] -> {status_msg}{latency_msg}{error_msg}")

                # Если тест успешен, добавляем оригинальную строку конфига в список
                if result_dict['success']:
                    working_configs.append(original_config_str)

            except Exception as e:
                # Ловим ошибки, возникшие при выполнении future.result() (маловероятно, т.к. ловим внутри perform_url_test)
                logging.error(f"({i}/{total_configs}) КРИТИЧЕСКАЯ ОШИБКА обработки результата для {original_config_str[:30]}...: {e}", exc_info=args.verbose)


    end_time_total = time.time()
    duration = end_time_total - start_time_total
    num_successful = len(working_configs)
    num_failed = total_configs - num_successful

    logging.info(f"Тестирование завершено за {duration:.2f} секунд.")
    logging.info(f"Итог: {num_successful} конфигураций работают, {num_failed} не работают.")

    # Запись РАБОЧИХ конфигураций в текстовый файл
    if working_configs:
        logging.info(f"Сохранение {num_successful} рабочих конфигураций в файл: {args.output_file}")
        try:
            # Создаем родительские директории, если их нет
            args.output_file.parent.mkdir(parents=True, exist_ok=True)
            with open(args.output_file, 'w', encoding='utf-8') as f:
                for config_uri in working_configs:
                    f.write(config_uri + '\n') # Добавляем перенос строки после каждой URI
            logging.info(f"Рабочие конфигурации успешно сохранены.")
        except Exception as e:
            logging.error(f"Ошибка записи результатов в файл {args.output_file}: {e}")
    else:
        logging.warning(f"Рабочих конфигураций для сохранения в {args.output_file} не найдено.")
        # Можно опционально создать пустой файл или не создавать его вообще
        # Создадим пустой для консистентности
        try:
             args.output_file.parent.mkdir(parents=True, exist_ok=True)
             with open(args.output_file, 'w', encoding='utf-8') as f:
                 pass # Создаем пустой файл
             logging.info(f"Создан пустой файл результатов: {args.output_file}")
        except Exception as e:
             logging.error(f"Ошибка создания пустого файла результатов {args.output_file}: {e}")


if __name__ == "__main__":
    main()
