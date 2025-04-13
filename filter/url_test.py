# [Source 1]
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
import sys # Добавлен импорт sys
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Any

# --- Logging Setup ---
# Устанавливаем базовый уровень INFO, чтобы видеть прогресс без -v
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Constants ---
DEFAULT_TEST_URL = "http://cp.cloudflare.com"
DEFAULT_TIMEOUT = 10
DEFAULT_WORKERS = 5
SINGBOX_EXECUTABLE = "sing-box" # Предполагаем, что sing-box в PATH или указываем полный путь
# [Source 88] Добавляем путь к скрипту advanced_test.py
ADVANCED_TEST_SCRIPT = "advanced_test.py" # Предполагаем, что он в той же директории

# --- Вспомогательные функции ---

def find_free_port() -> int:
    """Находит свободный TCP порт."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        # [Source 2]
        return s.getsockname()[1]

def cleanup_process(process: Optional[subprocess.Popen], verbose: bool = False):
    """Аккуратно завершает процесс и читает его вывод."""
    if process and process.poll() is None:
        logging.debug(f"Завершение процесса {process.pid}...")
        try:
            process.terminate()
            process.wait(timeout=2)
            logging.debug(f"Процесс {process.pid} завершен через terminate.")
        except subprocess.TimeoutExpired:
            logging.warning(f"Процесс {process.pid} не завершился за 2 сек, отправка kill...")
            process.kill()
            process.wait()
            logging.debug(f"Процесс {process.pid} завершен через kill.")
        except Exception as e:
            logging.error(f"Ошибка при попытке завершить процесс {process.pid}: {e}")

    if process:
        try:
            # Без text=True вывод уже является строкой
            stdout, stderr = process.communicate(timeout=2)
            stdout = stdout if stdout else ""
            stderr = stderr if stderr else ""
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
            # [Source 6]
            logging.debug(f"Временный файл удален: {filepath}")
        except Exception as e:
            logging.error(f"Ошибка при удалении файла {filepath}: {e}")

# --- Парсеры конфигураций (оставлены без изменений) ---

# [Source 6]
def parse_ss_config(config_str: str) -> Dict[str, Any]:
    """Парсит конфигурацию Shadowsocks (ss://)."""
    parsed = urllib.parse.urlparse(config_str)
    user_info_part = parsed.netloc.split('@')[0]
    server_part = parsed.netloc.split('@')[1]
    host, port_str = server_part.split(':')
    port = int(port_str)

    # [Source 7]
    method = None # Инициализация
    password = None # Инициализация

    try:
        # Попытка декодировать user_info как base64 (старый формат)
        decoded_user_info = base64.urlsafe_b64decode(user_info_part + '===').decode('utf-8')
        method, password = decoded_user_info.split(':', 1)
    except (base64.binascii.Error, ValueError, UnicodeDecodeError):
        # Если не base64, считаем, что формат method:password
        # Это может быть неверно для некоторых URI, где только пароль в base64
        # [Source 8]
        logging.warning(f"Не удалось декодировать user_info '{user_info_part}' как base64 для SS, предполагается формат method:password или только пароль base64")
        try:
            # Простой вариант: если нет ':' предполагаем только пароль (декодируя)
            password = base64.urlsafe_b64decode(user_info_part + '===').decode('utf-8')
            # Метод нужно будет указать по умолчанию или извлечь иначе
            # [Source 9]
            method = "aes-256-gcm" # Пример! Установите здесь ваш дефолтный метод
            logging.warning(f"Метод не найден явно, использован метод по умолчанию: {method}")
        except Exception as inner_e:
             logging.error(f"Не удалось определить метод/пароль SS из '{user_info_part}'. Ошибка: {inner_e}")
             raise ValueError(f"Не удалось определить метод/пароль SS из '{user_info_part}'")

    if not method or not password:
         # [Source 10]
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

# [Source 10]
def parse_trojan_config(config_str: str) -> Dict[str, Any]:
    """Парсит конфигурацию Trojan (trojan://)."""
    parsed = urllib.parse.urlparse(config_str)
    # [Source 11]
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
        # [Source 12]
        "password": password,
        "tls": { # Trojan обычно требует TLS
            "enabled": True,
            "server_name": query_params.get('sni', [host])[0],
            "insecure": query_params.get('allowInsecure', ['0'])[0] == '1',
            # Дополнительные параметры TLS (alpn, fingerprint) могут быть в query_params
            "alpn": query_params.get('alpn', [None])[0].split(',') if query_params.get('alpn', [None])[0] else None,
        # [Source 13]
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
        # [Source 14] # В sing-box транспорт указывается внутри основного объекта
        outbound["transport"] = ws_settings
    elif transport_type != 'tcp':
        logging.warning(f"Тип транспорта '{transport_type}' для Trojan пока не полностью поддерживается в этом парсере.")

    return outbound

# [Source 14]
def parse_vmess_config(config_str: str) -> Dict[str, Any]:
    """Парсит конфигурацию VMess (vmess://)."""
    try:
        encoded_json = config_str.replace("vmess://", "")
        # Добавим обработку возможного отсутствия паддинга
        encoded_json = encoded_json.strip()
        padding = "=" * (4 - len(encoded_json) % 4)
        # [Source 15]
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
        # [Source 16]
        "security": vmess_params.get("scy", vmess_params.get("security", "auto")), # Добавил синоним "security"
        "alter_id": int(vmess_params.get("aid", 0)),
    }

    tls_enabled = vmess_params.get("tls", "") == "tls"
    if tls_enabled:
        outbound["tls"] = {
            "enabled": True,
            "server_name": vmess_params.get("sni", vmess_params.get("host", vmess_params.get("add"))),
            "insecure": str(vmess_params.get("allowInsecure", vmess_params.get("allow_insecure", "false"))).lower() == "true", # Добавил синоним и проверку строки
            # [Source 17]
            "alpn": vmess_params.get('alpn', '').split(',') if vmess_params.get('alpn') else None,
        }

    net_type = vmess_params.get("net", "tcp")
    if net_type != "tcp":
         transport = {"type": net_type}
         if net_type == "ws":
             transport["path"] = vmess_params.get("path", "/")
             # [Source 18] В VMess JSON поле для Host хедера обычно "host"
             ws_host = vmess_params.get("host", vmess_params.get("add"))
             if ws_host:
                 transport["headers"] = {"Host": ws_host}
         elif net_type == "grpc":
             # В sing-box поле называется 'service_name'
             transport["service_name"] = vmess_params.get("path", vmess_params.get("serviceName", ""))
             # [Source 19] Другие типы транспорта (h2, quic) можно добавить здесь
         outbound["transport"] = transport

    return outbound

# [Source 19]
def parse_vless_config(config_str: str) -> Dict[str, Any]:
    """Парсит конфигурацию VLESS (vless://)."""
    parsed = urllib.parse.urlparse(config_str)
    uuid = parsed.username if parsed.username else parsed.netloc.split('@')[0]
    server_part = parsed.netloc.split('@')[1] if '@' in parsed.netloc else parsed.netloc
    host, port_str = server_part.split(':')
    port = int(port_str)
    remark = parsed.fragment if parsed.fragment else host
    query_params = urllib.parse.parse_qs(parsed.query)

    # [Source 20]
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
            # [Source 21]
            "enabled": True,
            "server_name": query_params.get('sni', [host])[0],
            "insecure": query_params.get('allowInsecure', ['0'])[0] == '1',
             "alpn": query_params.get('alpn', [None])[0].split(',') if query_params.get('alpn', [None])[0] else None,
        }
        if security == 'reality':
            reality_opts = {
                # [Source 22]
                 "enabled": True,
                 "public_key": query_params.get('pbk', [None])[0],
                 "short_id": query_params.get('sid', [None])[0],
             }
            # Уточняем параметр fingerprint для sing-box
            fp = query_params.get('fp', [None])[0]
            # [Source 23]
            if fp:
                 reality_opts["fingerprint"] = fp
            tls_settings["reality"] = reality_opts

            # Важно: для Reality часто нужен явный server_name (куда пойдут 'реальные' пакеты)
            # Если sni не указан, он может быть равен host
            tls_settings["server_name"] = query_params.get('sni', [host])[0]

        # [Source 24]
        else: # Просто TLS
            fp = query_params.get('fp', [None])[0]
            if fp:
                 # В новых версиях sing-box может быть просто "fingerprint" внутри "tls"
                 # Проверяем документацию sing-box для вашей версии
                 tls_settings["utls"] = {"enabled": True, "fingerprint": fp}
                 # или tls_settings["fingerprint"] = fp

        outbound["tls"] = tls_settings

    transport_type = query_params.get('type', ['tcp'])[0]
    if transport_type != 'tcp':
        transport = {"type": transport_type}
        # [Source 25]
        if transport_type == 'ws':
            transport["path"] = query_params.get('path', ['/'])[0]
            transport["headers"] = {"Host": query_params.get('host', [host])[0]}
        elif transport_type == 'grpc':
            transport["service_name"] = query_params.get('serviceName', [''])[0]
        # Другие транспорты: h2, quic
        outbound["transport"] = transport

    return outbound

# [Source 25]
def convert_to_singbox_config(config_str: str, socks_port: int) -> Dict[str, Any]:
    """Конвертирует строку конфигурации в формат JSON для sing-box."""
    # [Source 26]
    base_config = {
        # Уровень warn по умолчанию, debug при verbose флаге? Можно настроить позже.
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [{
            "type": "socks",
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "listen_port": socks_port,
            # [Source 27]
            "sniff": True,
             "sniff_override_destination": True, # Полезно для VLESS/Trojan с domain-based routing
             "users": [] # Если нужна аутентификация на SOCKS
        }],
        "outbounds": []
    }

    parser_map = {
        "ss://": parse_ss_config,
        "trojan://": parse_trojan_config,
        "vmess://": parse_vmess_config,
        # [Source 28]
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
                # [Source 29]
                break
            except Exception as e:
                # Логируем ошибку парсинга, но не прерываем всю программу, а возвращаем ошибку в perform_url_test
                logging.error(f"Ошибка парсинга '{config_str[:40]}...' как {protocol_parsed}: {e}", exc_info=False)
                raise ValueError(f"Ошибка парсинга {protocol_parsed} конфигурации: {e}") from e # Добавляем исходную ошибку

    if not parsed_outbound:
        raise ValueError(f"Неподдерживаемый или некорректный протокол: {config_str[:40]}...")

    # [Source 30] Добавляем основной outbound и direct
    base_config["outbounds"].append(parsed_outbound)
    # "direct" нужен для DNS detour, даже если его определение считается устаревшим
    base_config["outbounds"].append({"type": "direct", "tag": "direct"})
    # "block" пока оставляем закомментированным, т.к. он не вызывал фатальной ошибки
    # base_config["outbounds"].append({"type": "block", "tag":
# [Source 84] # "block"})


    # Добавляем простое правило маршрутизации: все через наш outbound
    base_config["route"] = {
        "rules": [
            {
                 # Правило для DNS, чтобы он тоже шел через прокси
                 "protocol": ["dns"],
                 # [Source 31]
                 "outbound": parsed_outbound["tag"]
            },
            {
                # Маршрутизируем все остальное через наш outbound
                "outbound": parsed_outbound["tag"]
            }
        ],
        # "final" указывает, куда направлять трафик, не соответствующий ни одному правилу
        # В нашем случае, так как последнее правило ловит все, final можно оставить как есть или указать direct/block
        "final": parsed_outbound["tag"] # Явно указываем final outbound
    }

    # [Source 32] Добавляем DNS сервер для разрешения через прокси
    base_config["dns"] = {
        "servers": [
            # DNS сервер, который будет запрашиваться через основной outbound
            {"tag": "proxy-dns", "address": "1.1.1.1", "detour": parsed_outbound["tag"]},
             # Резервный DNS сервер (например, локальный или Google)
            {"tag": "local-dns", "address": "8.8.8.8", "detour": "direct"}, # Идет напрямую
            # {"tag": "local-dns", "address": "local"}, # Или используем системный DNS
            {"tag": "block-dns", "address": "rcode://success"} # Для блокировки запросов
        ],
        # [Source 33]
        "rules": [
             # Можно добавить правила для маршрутизации DNS запросов (например, для обхода блокировок)
             # По умолчанию используем DNS через прокси
             {"server": "proxy-dns"}
        ],
        "strategy": "prefer_ipv4" # или "use_first"
    }

    return base_config

# --- Функция теста ---

# [Source 33]
def perform_url_test(config_str: str, test_url: str, timeout: float, singbox_path: str, verbose: bool) -> Dict[str, Any]:
    """
    Выполняет URL-тест для одной конфигурации, используя sing-box.
    Запускает sing-box на свободном порту. # [Source 34]
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
    # [Source 35]
    socks_port: Optional[int] = None
    config_file: Optional[str] = None
    proxy_process: Optional[subprocess.Popen] = None
    session = None # Инициализируем session здесь

    try:
        # 1. Найти свободный порт
        socks_port = find_free_port()
        local_proxy = f"socks5h://127.0.0.1:{socks_port}" # socks5h для DNS через прокси
        logging.debug(f"{log_prefix} Назначен порт {socks_port}")

        # 2. Сгенерировать конфиг sing-box
        try:
            # [Source 36]
            singbox_config = convert_to_singbox_config(config_str, socks_port)
            # Устанавливаем уровень логов sing-box в зависимости от verbose
            singbox_config["log"]["level"] = "debug" if verbose else "warn"
            if verbose: # Выводим конфиг только в verbose режиме
                 logging.debug(f"{log_prefix} Сгенерированный конфиг sing-box:\n{json.dumps(singbox_config, indent=2)}")
        except ValueError as e:
            result["error"] = f"Ошибка конфигурации: {e}"
            logging.error(f"{log_prefix} {result['error']}")
            # [Source 37]
            return result # Возвращаем ошибку, дальше не идем

        # 3. Записать конфиг во временный файл
        config_file_handle = None
        try:
             # Используем NamedTemporaryFile с delete=False, чтобы получить имя
             config_file_handle = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding='utf-8')
             # [Source 38]
             config_file = config_file_handle.name
             json.dump(singbox_config, config_file_handle, indent=2)
             config_file_handle.close() # Закрываем файл, чтобы sing-box мог его прочитать
             logging.debug(f"{log_prefix} Конфиг записан в {config_file}")
        except Exception as e:
             result["error"] = f"Ошибка записи временного конфига: {e}"
             # [Source 39]
             logging.error(f"{log_prefix} {result['error']}")
             if config_file_handle: # Пытаемся закрыть, если открыт
                 try: config_file_handle.close()
                 except: pass
             cleanup_file(config_file) # Пытаемся удалить, если создан
             return result

        # 4. Запустить sing-box
        cmd = [singbox_path, "run", "-c", config_file]
        logging.debug(f"{log_prefix} Запуск команды: {' '.join(cmd)}")
        try:
             # Используем Popen для асинхронного запуска
             proxy_process = subprocess.Popen(
                # [Source 40]
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True, # Лучше не использовать text=True при чтении stderr ниже
                # [Source 41]
                encoding='utf-8', # Явно указываем кодировку
                errors='replace' # Заменяем ошибки декодирования
                # bufsize=1 # Для более быстрого получения вывода (опционально)
             )
        except FileNotFoundError:
             result["error"] = f"Исполняемый файл sing-box не найден по пути: {singbox_path}"
             logging.error(f"{log_prefix} {result['error']}")
             cleanup_file(config_file)
             return result
        except Exception as e:
             # [Source 42]
             result["error"] = f"Не удалось запустить sing-box: {e}"
             logging.error(f"{log_prefix} {result['error']}")
             cleanup_file(config_file)
             return result


        # 5. Дождаться запуска sing-box (проверка порта и/или логов)
        start_wait = time.time()
        port_ready = False
        # [Source 43]
        singbox_error_output = "" # Собираем stderr на случай ошибки старта
        logging.debug(f"{log_prefix} Ожидание доступности порта {socks_port}...")
        max_wait_time = 15 # Увеличим время ожидания старта
        while time.time() - start_wait < max_wait_time:
            # Проверяем, не завершился ли процесс с ошибкой
            return_code = proxy_process.poll()
            if return_code is not None:
                logging.error(f"{log_prefix} Процесс sing-box ({proxy_process.pid}) неожиданно завершился с кодом {return_code} во время ожидания порта.")
                # [Source 44] Читаем stderr для диагностики
                try:
                     # Читаем остатки вывода (stdout и stderr уже строки из-за text=True)
                    stdout_str, stderr_str = proxy_process.communicate(timeout=1)
                    # Просто присваиваем строку stderr, декодирование не нужно
                    singbox_error_output = stderr_str[:1000] if stderr_str else "" # Ограничиваем объем
                    # [Source 45]
                    logging.error(f"{log_prefix} STDERR sing-box:\n{singbox_error_output}")
                except Exception as e:
                    # Сообщение об ошибке можно оставить тем же или уточнить
                    logging.error(f"{log_prefix} Ошибка при чтении вывода sing-box после его завершения: {e}")
                    # [Source 106] (строка изменена)
                result["error"] = f"Sing-box не запустился (код {return_code}). См. логи для STDERR." # [Source 46]
                cleanup_file(config_file) # Процесс уже завершен
                return result

            # Проверяем доступность порта
            try:
                with socket.create_connection(("127.0.0.1", socks_port), timeout=0.1):
                    # [Source 47]
                    port_ready = True
                    logging.debug(f"{log_prefix} Порт {socks_port} готов за {time.time() - start_wait:.2f} сек.")
                    break
            except (socket.timeout, ConnectionRefusedError):
                time.sleep(0.2) # Небольшая пауза перед следующей проверкой
            # [Source 48]
            except Exception as e:
                 logging.error(f"{log_prefix} Неожиданная ошибка при проверке порта {socks_port}: {e}")
                 time.sleep(0.3)

        if not port_ready:
            logging.error(f"{log_prefix} Таймаут ({max_wait_time} сек) ожидания sing-box на порту {socks_port}.")
            result["error"] = f"Таймаут ожидания sing-box ({socks_port})"
            # [Source 49] Завершаем процесс и читаем вывод для диагностики
            cleanup_process(proxy_process, verbose) # Завершаем принудительно
            cleanup_file(config_file)
            return result

        # 6. Выполнить HTTP-запрос через прокси
        try:
            # [Source 50] Импортируем requests здесь, т.к. он проверяется в main
            import requests
            session = requests.Session()
            session.proxies = {
                "http": local_proxy,
                "https": local_proxy
            }

            # [Source 51]
            logging.debug(f"{log_prefix} Выполнение GET запроса к {test_url} через {local_proxy}...")
            start_time = time.time()
            # Добавляем User-Agent для большей реалистичности
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36'}
            response = session.get(test_url, timeout=timeout, headers=headers, allow_redirects=True) # Добавили allow_redirects
            latency = (time.time() - start_time) * 1000 # в мс

            # Проверяем статус код (2xx считается успехом)
            if 200 <= response.status_code < 300:
                 result["success"] = True
                 result["latency_ms"] = round(latency)
                 result["status_code"] = response.status_code
                 # [Source 52] Логируем успех на уровне INFO
                 logging.info(f"{log_prefix} УСПЕХ - Задержка: {result['latency_ms']}ms, Статус: {result['status_code']}")
            else:
                result["error"] = f"Ошибка теста URL: Неожиданный статус-код {response.status_code}"
                logging.warning(f"{log_prefix} {result['error']}")
                result["status_code"] = response.status_code


        except requests.exceptions.Timeout:
             result["error"] = f"Ошибка теста URL: Таймаут ({timeout} сек)"
             logging.warning(f"{log_prefix} {result['error']}")
        except requests.exceptions.ProxyError as e:
            # [Source 53]
            result["error"] = f"Ошибка теста URL: Ошибка прокси - {str(e)[:200]}"
            logging.warning(f"{log_prefix} {result['error']}")
        except requests.exceptions.RequestException as e:
             result["error"] = f"Ошибка теста URL: {type(e).__name__} - {str(e)[:200]}"
             logging.warning(f"{log_prefix} {result['error']}")
        except Exception as e: # Ловим прочие возможные ошибки
             # [Source 54]
             result["error"] = f"Неожиданная ошибка теста URL: {type(e).__name__}: {str(e)[:200]}"
             logging.error(f"{log_prefix} {result['error']}", exc_info=verbose) # Показывать traceback в verbose

    except Exception as e:
        # Ловим ошибки этапов 1-5 (поиск порта, генерация/запись конфига, запуск/ожидание sing-box)
        result["error"] = f"Общая ошибка подготовки теста: {type(e).__name__}: {str(e)[:200]}"
        logging.error(f"{log_prefix} {result['error']}", exc_info=verbose) # Показывать traceback в verbose

    finally:
        # 7. Закрыть сессию requests
        # [Source 55]
        if session:
             try: session.close()
             except: pass
             logging.debug(f"{log_prefix} Сессия requests закрыта.")
        # 8. Остановить sing-box и удалить файл
        logging.debug(f"{log_prefix} Очистка ресурсов...")
        cleanup_process(proxy_process, verbose)
        cleanup_file(config_file)
        logging.debug(f"{log_prefix} Очистка завершена.")

    return result

# --- Основная функция ---

def main():
    # [Source 56]
    parser = argparse.ArgumentParser(
        description="Этап 1: Параллельное URL-тестирование прокси-конфигураций (ss, vmess, vless, trojan) с использованием sing-box.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
        )
    parser.add_argument(
        "input_file",
        type=Path,
        help="Путь к текстовому файлу со списком конфигураций URI (по одной на строку)."
        )
    # [Source 57] Удален аргумент -o / --output_file
    # parser.add_argument(
    #     "-o", "--output_file",
    #     type=Path,
    #     required=True,
    #     help="Путь к текстовому файлу для сохранения РАБОЧИХ конфигураций URI (по одной на строку)."
    #     )

    # [Source 114] Добавлен аргумент для указания финального выходного файла (передается в advanced_test.py)
    parser.add_argument(
        "-ao", "--advanced-output",
        type=Path,
        required=True,
        help="Путь к ФИНАЛЬНОМУ выходному файлу для сохранения окончательно рабочих конфигураций (будет создан advanced_test.py)."
    )
    parser.add_argument(
        "-w", "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help="Количество параллельных потоков для тестирования."
        ) # [Source 58]
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
        ) # [Source 59]
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

    # [Source 60] Устанавливаем уровень логирования DEBUG, если указан флаг -v
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Включен режим подробного логирования (DEBUG).")
        # Устанавливаем уровень логов sing-box (если нужно)
        # logging.getLogger('sing-box').setLevel(logging.DEBUG) # Пример, если бы был логгер sing-box

    # Обновляем глобальную переменную пути к sing-box
    effective_singbox_path = args.singbox_path

    # Проверка наличия sing-box
    try:
        logging.debug(f"Проверка sing-box по пути: {effective_singbox_path}")
        # [Source 61] Используем capture_output=True чтобы скрыть вывод версии
        process_result = subprocess.run([effective_singbox_path, "version"], check=True, capture_output=True, text=True, timeout=5, encoding='utf-8', errors='replace')
        logging.info(f"Используется sing-box: {effective_singbox_path} (Версия: {process_result.stdout.strip()})")
    except FileNotFoundError:
        logging.error(f"КРИТИЧЕСКАЯ ОШИБКА: Исполняемый файл sing-box НЕ НАЙДЕН по пути: '{effective_singbox_path}'")
        logging.error("Убедитесь, что sing-box установлен, имеет права на выполнение (chmod +x) и путь указан верно (через --singbox-path или он есть в $PATH).")
        sys.exit(1) # Выходим с кодом ошибки
    # [Source 62]
    except subprocess.CalledProcessError as e:
        logging.error(f"Ошибка при вызове '{effective_singbox_path} version': {e}")
        stderr_output = e.stderr.decode('utf-8', errors='replace') if isinstance(e.stderr, bytes) else e.stderr
        logging.error(f"Вывод ошибки sing-box: {stderr_output}")
        sys.exit(1)
    except subprocess.TimeoutExpired:
         logging.error(f"Таймаут при проверке версии sing-box: {effective_singbox_path}")
         sys.exit(1)
    except Exception as e:
        logging.error(f"Неожиданная ошибка при проверке sing-box ('{effective_singbox_path}'): {e}")
        sys.exit(1)

    # [Source 63] Проверка наличия requests
    try:
        import requests
        logging.debug(f"Модуль 'requests' успешно импортирован.")
    except ImportError:
        logging.error("КРИТИЧЕСКАЯ ОШИБКА: Модуль 'requests' не найден.")
        logging.error("Пожалуйста, установите его командой: pip install requests")
        sys.exit(1) # Выходим, если requests не найден

    # Чтение конфигураций
    configs = []
    try:
        logging.info(f"Чтение конфигураций из файла: {args.input_file}")
        # [Source 64]
        with open(args.input_file, 'r', encoding='utf-8') as f:
            # Фильтруем пустые строки и строки, начинающиеся с # (комментарии)
            configs = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
        if not configs:
             logging.warning(f"Файл '{args.input_file}' пуст или содержит только комментарии/пустые строки. Тестировать нечего.") # [Source 65]
             sys.exit(0) # Успешный выход, так как нет работы
        logging.info(f"Загружено {len(configs)} конфигураций для тестирования.")
    except FileNotFoundError:
        logging.error(f"КРИТИЧЕСКАЯ ОШИБКА: Файл не найден: {args.input_file}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Ошибка чтения файла {args.input_file}: {e}")
        sys.exit(1)

    # Список для хранения рабочих конфигураций
    working_configs = []
    # [Source 66]
    start_time_total = time.time()
    total_configs = len(configs)

    logging.info(f"Начало URL-тестирования ({args.workers} потоков)...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        # Создаем задачи, передавая необходимые аргументы в perform_url_test
        future_to_config = {
            executor.submit(perform_url_test, config, args.url, args.timeout, effective_singbox_path, args.verbose): config
            for config in configs
        }

        # [Source 67] Собираем результаты по мере выполнения
        for i, future in enumerate(concurrent.futures.as_completed(future_to_config), 1):
            original_config_str = future_to_config[future]
            try:
                # Получаем результат из функции perform_url_test
                result_dict = future.result()

                # [Source 68] Логируем общий прогресс
                status_msg = "УСПЕХ" if result_dict['success'] else "НЕУДАЧА"
                error_msg = f" Ошибка: {result_dict['error']}" if not result_dict['success'] and result_dict['error'] else ""
                # Не выводим latency для неудачных тестов
                latency_msg = f" Задержка: {result_dict['latency_ms']}ms" if result_dict['success'] else ""

                # [Source 69]
                logging.info(f"({i}/{total_configs}) [{original_config_str[:25]}...] -> {status_msg}{latency_msg}{error_msg}")

                # Если тест успешен, добавляем оригинальную строку конфига в список
                if result_dict['success']:
                    working_configs.append(original_config_str)

            except Exception as e:
                # [Source 70] Ловим ошибки, возникшие при выполнении future.result() (маловероятно)
                # [Source 71]
                logging.error(f"({i}/{total_configs}) КРИТИЧЕСКАЯ ОШИБКА обработки результата для {original_config_str[:30]}...: {e}", exc_info=args.verbose)


    end_time_total = time.time()
    duration = end_time_total - start_time_total
    num_successful = len(working_configs)
    num_failed = total_configs - num_successful

    logging.info(f"URL-тестирование завершено за {duration:.2f} секунд.")
    logging.info(f"Итог URL-теста: {num_successful} конфигураций прошли, {num_failed} не прошли.")

    # [Source 100] Удален блок записи working_configs в файл

    # --- Начало нового блока: Передача управления в advanced_test.py ---
    temp_file_path = None # Инициализация пути к временному файлу
    # [Source 95] Проверяем, есть ли рабочие конфигурации для передачи
    if working_configs:
        try:
            # Создаем временный файл для передачи рабочих конфигураций
            with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding='utf-8') as tmp_file:
                json.dump(working_configs, tmp_file)
                temp_file_path = tmp_file.name # Сохраняем путь к файлу # [Source 96]

            logging.info(f"Передача {len(working_configs)} рабочих конфигураций в {ADVANCED_TEST_SCRIPT}...")

            # Формируем команду для запуска advanced_test.py
            # Используем sys.executable для запуска скрипта тем же интерпретатором Python
            cmd = [
                sys.executable,
                ADVANCED_TEST_SCRIPT,
                "--input-file", temp_file_path,              # Передаем временный файл с конфигами
                "--output-file", str(args.advanced_output), # Передаем путь для финального вывода
                "--singbox-path", effective_singbox_path    # Передаем путь к sing-box
            ]
            if args.verbose:
                cmd.append("--verbose") # Передаем флаг verbose, если он был установлен

            logging.debug(f"Запуск команды: {' '.join(cmd)}")

            # Запускаем advanced_test.py
            # [Source 97]
            result = subprocess.run(cmd, check=False, capture_output=True, text=True, encoding='utf-8', errors='replace')

            # Логируем вывод advanced_test.py
            logging.info(f"--- Начало вывода {ADVANCED_TEST_SCRIPT} ---")
            if result.stdout:
                 logging.info(result.stdout.strip())
            if result.stderr:
                 # Логируем stderr как ошибку, если процесс завершился с ошибкой, иначе как warning
                 if result.returncode != 0:
                     logging.error(f"STDERR от {ADVANCED_TEST_SCRIPT}:\n{result.stderr.strip()}")
                 else:
                      logging.warning(f"STDERR от {ADVANCED_TEST_SCRIPT} (код возврата 0):\n{result.stderr.strip()}")
            logging.info(f"--- Конец вывода {ADVANCED_TEST_SCRIPT} ---")

            if result.returncode != 0:
                 logging.error(f"{ADVANCED_TEST_SCRIPT} завершился с кодом ошибки {result.returncode}.")
                 # Можно добавить sys.exit(1) здесь, если ошибка в advanced_test критична

        # [Source 98] Обрабатываем ошибки запуска subprocess
        except subprocess.CalledProcessError as e: # check=True не используется, эта ошибка не возникнет
             logging.error(f"Ошибка при запуске {ADVANCED_TEST_SCRIPT} (CalledProcessError): {e}")
             stderr_output = e.stderr.decode('utf-8', errors='replace') if isinstance(e.stderr, bytes) else e.stderr
             logging.error(f"Вывод ошибки:\n{stderr_output}")
        except FileNotFoundError:
             logging.error(f"КРИТИЧЕСКАЯ ОШИБКА: Скрипт {ADVANCED_TEST_SCRIPT} не найден.") # [Source 99]
             logging.error("Убедитесь, что файл advanced_test.py находится в той же директории или укажите правильный путь в константе ADVANCED_TEST_SCRIPT.")
        except Exception as e: # Ловим другие возможные ошибки
            logging.error(f"Неожиданная ошибка при запуске или обработке {ADVANCED_TEST_SCRIPT}: {e}", exc_info=args.verbose)

        # [Source 99] Очищаем временный файл в блоке finally
        finally:
             if temp_file_path:
                 cleanup_file(temp_file_path)

    else: # Если working_configs пуст
        # [Source 99]
        logging.info("После URL-теста не осталось рабочих конфигураций. Запуск advanced_test.py пропущен.")
        # Создаем пустой финальный файл, если он не существует, чтобы показать, что процесс завершился без ошибок, но без результата
        try:
             # [Source 74]
             args.advanced_output.parent.mkdir(parents=True, exist_ok=True)
             with open(args.advanced_output, 'w', encoding='utf-8') as f:
                 pass # Создаем пустой файл
             logging.info(f"Создан пустой финальный файл результатов: {args.advanced_output}")
        except Exception as e:
             # [Source 75]
             logging.error(f"Ошибка создания пустого финального файла результатов {args.advanced_output}: {e}")


if __name__ == "__main__":
    main()
