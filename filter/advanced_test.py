# -*- coding: utf-8 -*-
# advanced_test.py
# Этап 2: Углубленное тестирование прокси-конфигураций

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
import sys
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Any

# --- Logging Setup ---
# Уровень INFO по умолчанию, DEBUG при --verbose
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [AdvTest] %(message)s')

# --- Constants ---
DEFAULT_TCP_TEST_HOST = "8.8.8.8"  # Хост для TCP Ping/Latency тестов (например, Google DNS)
DEFAULT_TCP_TEST_PORT = 53        # Порт для TCP Ping/Latency тестов
DEFAULT_TCP_TIMEOUT = 5           # Таймаут для TCP тестов в секундах
DEFAULT_IP_SERVICE_URL = "https://api.ipify.org?format=json" # Сервис для определения внешнего IP
DEFAULT_IP_SERVICE_TIMEOUT = 10 # Таймаут для запроса к IP сервису
DEFAULT_WORKERS_ADVANCED = 5      # Количество потоков для углубленного тестирования

# --- Вспомогательные функции (Скопированы/Адаптированы из url_test.py) ---

def find_free_port() -> int:
    """Находит свободный TCP порт."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
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
        stdout, stderr = "", ""
        try:
            # Пытаемся прочитать остатки вывода после завершения
            stdout_bytes, stderr_bytes = process.communicate(timeout=1)
            stdout = stdout_bytes.decode('utf-8', errors='replace') if stdout_bytes else ""
            stderr = stderr_bytes.decode('utf-8', errors='replace') if stderr_bytes else ""
            if verbose and (stdout or stderr):
                 logging.debug(f"Вывод процесса {process.pid} при завершении:\nSTDOUT:\n{stdout[:200]}\nSTDERR:\n{stderr[:200]}")
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

# --- Парсеры конфигураций (Скопированы из url_test.py) ---
# ... (код парсеров остается без изменений) ...
def parse_ss_config(config_str: str) -> Dict[str, Any]:
    """Парсит конфигурацию Shadowsocks (ss://)."""
    parsed = urllib.parse.urlparse(config_str)
    user_info_part = parsed.netloc.split('@')[0]
    server_part = parsed.netloc.split('@')[1]
    host, port_str = server_part.split(':')
    port = int(port_str)
    method = None
    password = None
    try:
        decoded_user_info = base64.urlsafe_b64decode(user_info_part + '===').decode('utf-8')
        method, password = decoded_user_info.split(':', 1)
    except (base64.binascii.Error, ValueError, UnicodeDecodeError):
        logging.warning(f"Не удалось декодировать user_info '{user_info_part}' как base64 для SS, пробуем другие варианты")
        try:
            # Пробуем формат method:password без base64
            if ':' in user_info_part:
                 method, password = user_info_part.split(':', 1)
            else:
                 # Если нет ':', пробуем декодировать как пароль base64
                 password = base64.urlsafe_b64decode(user_info_part + '===').decode('utf-8')
                 method = "aes-256-gcm" # Пример дефолтного метода
                 logging.warning(f"Метод SS не найден, использован по умолчанию: {method}")
        except Exception as inner_e:
             logging.error(f"Не удалось определить метод/пароль SS из '{user_info_part}'. Ошибка: {inner_e}")
             raise ValueError(f"Не удалось определить метод/пароль SS из '{user_info_part}'")

    if not method or not password:
         raise ValueError("Не удалось извлечь метод или пароль SS")

    remark = urllib.parse.unquote(parsed.fragment) if parsed.fragment else host
    return {
        "type": "shadowsocks", "tag": f"ss-out-{remark[:10]}", "server": host,
        "server_port": port, "method": method, "password": password,
    }

def parse_trojan_config(config_str: str) -> Dict[str, Any]:
    """Парсит конфигурацию Trojan (trojan://)."""
    parsed = urllib.parse.urlparse(config_str)
    password = parsed.username if parsed.username else parsed.netloc.split('@')[0]
    server_part = parsed.netloc.split('@')[1] if '@' in parsed.netloc else parsed.netloc
    host, port_str = server_part.split(':')
    port = int(port_str)
    remark = urllib.parse.unquote(parsed.fragment) if parsed.fragment else host
    query_params = urllib.parse.parse_qs(parsed.query)
    sni = query_params.get('sni', [query_params.get('peer', [host])[0]])[0] # Добавил 'peer' как синоним sni

    outbound = {
        "type": "trojan", "tag": f"trojan-out-{remark[:10]}", "server": host,
        "server_port": port, "password": password,
        "tls": {
            "enabled": True, "server_name": sni,
            "insecure": query_params.get('allowInsecure', ['0'])[0] == '1',
            "alpn": query_params.get('alpn', [None])[0].split(',') if query_params.get('alpn', [None])[0] else None,
        }
    }
    transport_type = query_params.get('type', ['tcp'])[0]
    if transport_type == 'ws':
        ws_settings = {
             "type": "ws",
             "path": query_params.get('path', ['/'])[0],
             "headers": {"Host": query_params.get('host', [sni])[0]} # Используем sni если host не задан
        }
        outbound["transport"] = ws_settings
    elif transport_type == 'grpc':
         grpc_settings = {
            "type": "grpc",
            "service_name": query_params.get('serviceName', [''])[0],
         }
         outbound["transport"] = grpc_settings
    elif transport_type != 'tcp':
        logging.warning(f"Тип транспорта '{transport_type}' для Trojan пока не полностью поддерживается в этом парсере.")
    return outbound

def parse_vmess_config(config_str: str) -> Dict[str, Any]:
   """Парсит конфигурацию VMess (vmess://)."""
   try:
        encoded_json = config_str.replace("vmess://", "").strip()
        padding = "=" * (4 - len(encoded_json) % 4)
        decoded_json = base64.b64decode(encoded_json + padding).decode('utf-8')
        vmess_params = json.loads(decoded_json)
   except Exception as e:
       raise ValueError(f"Ошибка декодирования VMess JSON: {e}")

   remark = vmess_params.get("ps", vmess_params.get("add", "vmess"))
   host = vmess_params.get("add")
   port = int(vmess_params.get("port", 443))

   outbound = {
        "type": "vmess", "tag": f"vmess-out-{remark[:10]}", "server": host,
        "server_port": port, "uuid": vmess_params.get("id"),
        "security": vmess_params.get("scy", vmess_params.get("security", "auto")),
        "alter_id": int(vmess_params.get("aid", 0)),
   }

   tls_enabled = vmess_params.get("tls", "") == "tls"
   if tls_enabled:
        sni = vmess_params.get("sni", vmess_params.get("host", host)) # SNI по умолчанию равен host или add
        outbound["tls"] = {
            "enabled": True, "server_name": sni,
            "insecure": str(vmess_params.get("allowInsecure", vmess_params.get("allow_insecure", "false"))).lower() == "true",
            "alpn": vmess_params.get('alpn', '').split(',') if vmess_params.get('alpn') else None,
        }

   net_type = vmess_params.get("net", "tcp")
   if net_type != "tcp":
         transport = {"type": net_type}
         if net_type == "ws":
             transport["path"] = vmess_params.get("path", "/")
             ws_host = vmess_params.get("host", sni) # Используем host из vmess или sni
             if ws_host:
                 transport["headers"] = {"Host": ws_host}
         elif net_type == "grpc":
             transport["service_name"] = vmess_params.get("path", vmess_params.get("serviceName", ""))
         outbound["transport"] = transport
   return outbound

def parse_vless_config(config_str: str) -> Dict[str, Any]:
    """Парсит конфигурацию VLESS (vless://)."""
    parsed = urllib.parse.urlparse(config_str)
    uuid = parsed.username if parsed.username else parsed.netloc.split('@')[0]
    server_part = parsed.netloc.split('@')[1] if '@' in parsed.netloc else parsed.netloc
    host, port_str = server_part.split(':')
    port = int(port_str)
    remark = urllib.parse.unquote(parsed.fragment) if parsed.fragment else host
    query_params = urllib.parse.parse_qs(parsed.query)

    outbound = {
        "type": "vless", "tag": f"vless-out-{remark[:10]}", "server": host,
        "server_port": port, "uuid": uuid,
        "flow": query_params.get('flow', [None])[0],
    }

    security = query_params.get('security', ['none'])[0]
    sni = query_params.get('sni', [host])[0] # SNI по умолчанию host
    fp = query_params.get('fp', [None])[0] # Fingerprint

    if security == 'tls' or security == 'reality':
        tls_settings = {
            "enabled": True, "server_name": sni,
            "insecure": query_params.get('allowInsecure', ['0'])[0] == '1',
            "alpn": query_params.get('alpn', [None])[0].split(',') if query_params.get('alpn', [None])[0] else None,
        }
        if security == 'reality':
            reality_opts = {
                 "enabled": True,
                 "public_key": query_params.get('pbk', [None])[0],
                 "short_id": query_params.get('sid', [None])[0],
            }
            if fp: reality_opts["fingerprint"] = fp
            tls_settings["reality"] = reality_opts
        else: # Просто TLS
             if fp:
                 # Для sing-box fingerprint обычно внутри utls
                 tls_settings["utls"] = {"enabled": True, "fingerprint": fp}

        outbound["tls"] = tls_settings

    transport_type = query_params.get('type', ['tcp'])[0]
    if transport_type != 'tcp':
        transport = {"type": transport_type}
        if transport_type == 'ws':
            transport["path"] = query_params.get('path', ['/'])[0]
            # Host для WS используем из 'host' параметра или sni
            transport["headers"] = {"Host": query_params.get('host', [sni])[0]}
        elif transport_type == 'grpc':
             transport["service_name"] = query_params.get('serviceName', [''])[0]
        # Другие транспорты (h2, quic) можно добавить аналогично
        outbound["transport"] = transport

    return outbound

# --- Конвертер Конфигурации (Скопирован из url_test.py) ---
# ... (код конвертера остается без изменений) ...
def convert_to_singbox_config(config_str: str, socks_port: int, log_level: str = "warn") -> Dict[str, Any]:
    """Конвертирует строку конфигурации в формат JSON для sing-box."""
    base_config = {
        "log": {"level": log_level, "timestamp": True},
        "inbounds": [{
            "type": "socks", "tag": "socks-in", "listen": "127.0.0.1",
            "listen_port": socks_port, "sniff": True,
            "sniff_override_destination": True, "users": []
        }],
        "outbounds": []
    }
    parser_map = {
        "ss://": parse_ss_config, "trojan://": parse_trojan_config,
        "vmess://": parse_vmess_config, "vless://": parse_vless_config,
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
                logging.error(f"Ошибка парсинга '{config_str[:40]}...' как {protocol_parsed}: {e}", exc_info=False)
                raise ValueError(f"Ошибка парсинга {protocol_parsed} конфигурации: {e}") from e
    if not parsed_outbound:
        raise ValueError(f"Неподдерживаемый или некорректный протокол: {config_str[:40]}...")

    base_config["outbounds"].append(parsed_outbound)
    base_config["outbounds"].append({"type": "direct", "tag": "direct"}) # Оставляем direct
    # base_config["outbounds"].append({"type": "block", "tag": "block"}) # Убрали block
    base_config["route"] = {
        "rules": [{"protocol": ["dns"], "outbound": parsed_outbound["tag"]}, {"outbound": parsed_outbound["tag"]}],
        "final": parsed_outbound["tag"]
    }
    base_config["dns"] = {
        "servers": [
            {"tag": "proxy-dns", "address": "1.1.1.1", "detour": parsed_outbound["tag"]},
            {"tag": "local-dns", "address": "8.8.8.8", "detour": "direct"},
            {"tag": "block-dns", "address": "rcode://success"}
        ],
        "rules": [{"server": "proxy-dns"}], "strategy": "prefer_ipv4"
    }
    return base_config

# --- Функции Углубленного Тестирования ---

def tcp_ping_latency_test(
    config_str: str,
    target_host: str,
    target_port: int,
    singbox_path: str,
    timeout: float,
    verbose: bool
) -> Tuple[bool, Optional[float], Optional[str]]:
    """
    Выполняет TCP-пинг и измеряет задержку до target_host:target_port через прокси.
    Использует netcat (nc) для теста.
    Возвращает (success, latency_ms, error_message).
    """
    log_prefix = f"TCP [{config_str[:25]}... -> {target_host}:{target_port}]"
    logging.debug(f"{log_prefix} Запуск...")

    socks_port: Optional[int] = None
    config_file: Optional[str] = None
    proxy_process: Optional[subprocess.Popen] = None

    try:
        # 1. Найти порт и сгенерировать конфиг sing-box
        socks_port = find_free_port()
        log_level = "debug" if verbose else "warn"
        singbox_config = convert_to_singbox_config(config_str, socks_port, log_level)

        # 2. Записать конфиг во временный файл
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding='utf-8') as tmp_f:
            json.dump(singbox_config, tmp_f)
            config_file = tmp_f.name
        logging.debug(f"{log_prefix} Конфиг sing-box записан в {config_file}")

        # 3. Запустить sing-box
        cmd = [singbox_path, "run", "-c", config_file]
        # Используем Popen для асинхронного запуска
        proxy_process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
        )

        # 4. Дождаться запуска sing-box (проверка порта)
        start_wait = time.time()
        port_ready = False
        max_wait_time = 10 # Время ожидания запуска sing-box
        while time.time() - start_wait < max_wait_time:
            if proxy_process.poll() is not None: # Процесс завершился
                 stderr_output = ""
                 try:
                     # Читаем вывод завершенного процесса
                     _, stderr_bytes = proxy_process.communicate(timeout=1)
                     stderr_output = stderr_bytes.decode('utf-8', errors='replace')[:500] # Ограничиваем длину
                 except Exception: pass # Игнорируем ошибки чтения, т.к. процесс уже упал
                 error_msg = f"Sing-box не запустился (код {proxy_process.poll()}). Stderr: {stderr_output}"
                 logging.warning(f"{log_prefix} {error_msg}")
                 return False, None, error_msg
            try:
                # Проверяем, слушается ли порт
                with socket.create_connection(("127.0.0.1", socks_port), timeout=0.1):
                    port_ready = True
                    logging.debug(f"{log_prefix} Порт {socks_port} готов за {time.time() - start_wait:.2f} сек.")
                    break
            except (socket.timeout, ConnectionRefusedError):
                time.sleep(0.2) # Ждем немного перед следующей проверкой
            except Exception as e:
                 logging.warning(f"{log_prefix} Ошибка проверки порта {socks_port}: {e}")
                 time.sleep(0.3)

        if not port_ready:
            error_msg = f"Таймаут ({max_wait_time} сек) ожидания sing-box на порту {socks_port}"
            logging.warning(f"{log_prefix} {error_msg}")
            # Попытаемся завершить процесс, если он еще работает
            cleanup_process(proxy_process, verbose)
            return False, None, error_msg

        # 5. Попытка TCP-соединения через прокси с помощью netcat (nc)
        start_time = time.time()
        try:
            # Конвертируем таймаут в целое число секунд для nc -w
            nc_timeout_sec = max(1, int(timeout))
            # Команда netcat для проверки TCP соединения через SOCKS5
            # -z : Режим сканирования (только проверка соединения)
            # -X 5 : Использовать SOCKS версии 5
            # -x proxy_addr:port : Адрес SOCKS прокси
            # -w timeout : Таймаут соединения в секундах
            nc_cmd = [
                "nc", "-z",
                "-X", "5",
                "-x", f"127.0.0.1:{socks_port}",
                "-w", str(nc_timeout_sec),
                target_host,
                str(target_port)
            ]

            logging.debug(f"{log_prefix} Запуск nc для TCP теста: {' '.join(nc_cmd)}")
            # Используем subprocess.run, т.к. nc -z быстро завершается
            ping_process = subprocess.run(
                nc_cmd,
                capture_output=True,
                timeout=nc_timeout_sec + 2 # Добавляем запас времени на выполнение самой команды nc
            )
            end_time = time.time()
            latency = (end_time - start_time) * 1000 # в мс

            if ping_process.returncode == 0:
                logging.debug(f"{log_prefix} Успешное соединение (через nc -z), задержка (прибл.): {latency:.0f}ms")
                return True, round(latency), None
            else:
                 # Анализируем ошибку nc
                 nc_error = ping_process.stderr.decode('utf-8', errors='replace').strip()
                 # Часто nc не пишет много в stderr при ошибках -z, код возврата важнее
                 error_msg = f"TCP Тест через nc не удался (код {ping_process.returncode}). Ошибка: {nc_error[:100]}"
                 logging.warning(f"{log_prefix} {error_msg}")
                 return False, None, error_msg

        except subprocess.TimeoutExpired:
            error_msg = f"Таймаут ({nc_timeout_sec + 2} сек) выполнения команды nc"
            logging.warning(f"{log_prefix} {error_msg}")
            return False, None, error_msg
        except FileNotFoundError:
            error_msg = "Команда 'nc' (netcat) не найдена. TCP тест не выполнен."
            logging.error(f"{log_prefix} {error_msg}") # Это критическая ошибка для функции
            return False, None, error_msg
        except Exception as e:
            error_msg = f"Ошибка выполнения nc или TCP соединения: {type(e).__name__}: {str(e)[:100]}"
            logging.warning(f"{log_prefix} {error_msg}")
            return False, None, error_msg
        # finally для nc не нужен, т.к. nc -z сам закрывает соединение

    except ValueError as e: # Ошибка парсинга/конвертации
        error_msg = f"Ошибка подготовки: {e}"
        logging.error(f"{log_prefix} {error_msg}")
        return False, None, error_msg
    except Exception as e: # Общие ошибки (запуск sing-box, запись файла)
        error_msg = f"Общая ошибка TCP теста: {type(e).__name__}: {str(e)[:100]}"
        logging.error(f"{log_prefix} {error_msg}", exc_info=verbose)
        return False, None, error_msg
    finally:
        # Очистка: завершить sing-box и удалить временный конфиг
        logging.debug(f"{log_prefix} Очистка ресурсов TCP теста...")
        cleanup_process(proxy_process, verbose)
        cleanup_file(config_file)
        logging.debug(f"{log_prefix} Очистка TCP теста завершена.")


def get_inbound_ip(config_str: str) -> Optional[str]:
    """Извлекает IP-адрес сервера (inbound) из строки конфигурации."""
    log_prefix = f"InIP [{config_str[:25]}...]"
    logging.debug(f"{log_prefix} Получение IP...")
    parser_map = {
        "ss://": parse_ss_config, "trojan://": parse_trojan_config,
        "vmess://": parse_vmess_config, "vless://": parse_vless_config,
    }
    try:
        for prefix, parser in parser_map.items():
            if config_str.startswith(prefix):
                parsed_config = parser(config_str)
                in_ip = parsed_config.get("server")
                if in_ip:
                    logging.debug(f"{log_prefix} Найден Inbound IP: {in_ip}")
                    return str(in_ip) # Убедимся, что это строка
                else:
                     logging.warning(f"{log_prefix} Поле 'server' не найдено в распарсенном конфиге.")
                     return None
        logging.warning(f"{log_prefix} Не удалось распознать протокол для извлечения IP.")
        return None
    except Exception as e:
        logging.error(f"{log_prefix} Ошибка при парсинге для получения Inbound IP: {e}")
        return None


def get_outbound_ip(
    config_str: str,
    singbox_path: str,
    ip_service_url: str,
    timeout: float,
    verbose: bool
) -> Tuple[Optional[str], Optional[str]]:
    """
    Определяет исходящий IP-адрес, используя прокси и внешний сервис.
    Возвращает (outbound_ip, error_message).
    """
    log_prefix = f"OutIP[{config_str[:25]}...]"
    logging.debug(f"{log_prefix} Запрос к {ip_service_url}...")

    socks_port: Optional[int] = None
    config_file: Optional[str] = None
    proxy_process: Optional[subprocess.Popen] = None
    session = None # Для requests

    try:
        # 1. Подготовка: порт, конфиг, запуск sing-box (аналогично TCP тесту)
        socks_port = find_free_port()
        local_proxy = f"socks5h://127.0.0.1:{socks_port}" # Используем socks5h для DNS через прокси
        log_level = "debug" if verbose else "warn"
        singbox_config = convert_to_singbox_config(config_str, socks_port, log_level)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding='utf-8') as tmp_f:
            json.dump(singbox_config, tmp_f)
            config_file = tmp_f.name
        logging.debug(f"{log_prefix} Конфиг sing-box записан в {config_file}")

        cmd = [singbox_path, "run", "-c", config_file]
        proxy_process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
        )

        # Ожидание запуска sing-box
        start_wait = time.time()
        port_ready = False
        max_wait_time = 10
        while time.time() - start_wait < max_wait_time:
             if proxy_process.poll() is not None:
                 stderr_output = ""
                 try: _, stderr_bytes = proxy_process.communicate(timeout=1); stderr_output = stderr_bytes.decode('utf-8', errors='replace')[:500]
                 except Exception: pass
                 error_msg = f"Sing-box не запустился (код {proxy_process.poll()}). Stderr: {stderr_output}"
                 logging.warning(f"{log_prefix} {error_msg}")
                 return None, error_msg
             try:
                 with socket.create_connection(("127.0.0.1", socks_port), timeout=0.1):
                    port_ready = True
                    logging.debug(f"{log_prefix} Порт {socks_port} готов за {time.time() - start_wait:.2f} сек.")
                    break
             except (socket.timeout, ConnectionRefusedError): time.sleep(0.2)
             except Exception as e: logging.warning(f"{log_prefix} Ошибка проверки порта {socks_port}: {e}"); time.sleep(0.3)

        if not port_ready:
            error_msg = f"Таймаут ({max_wait_time} сек) ожидания sing-box на порту {socks_port}"
            logging.warning(f"{log_prefix} {error_msg}")
            cleanup_process(proxy_process, verbose) # Завершаем процесс
            return None, error_msg

        # 2. Выполнить запрос к IP-сервису через прокси
        try:
            # Импортируем requests здесь, чтобы ошибка импорта была обработана ниже
            import requests
            session = requests.Session()
            session.proxies = {"http": local_proxy, "https": local_proxy}
            # Добавляем User-Agent, некоторые сервисы могут его требовать
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36'}

            logging.debug(f"{log_prefix} Выполнение GET запроса к {ip_service_url} через {local_proxy}...")
            response = session.get(ip_service_url, timeout=timeout, headers=headers)
            response.raise_for_status() # Проверка на HTTP ошибки (4xx, 5xx)

            ip_data = response.json()
            outbound_ip = ip_data.get("ip")

            if outbound_ip and isinstance(outbound_ip, str):
                logging.debug(f"{log_prefix} Успешно получен Outbound IP: {outbound_ip}")
                return outbound_ip, None
            else:
                error_msg = f"Не удалось извлечь IP из ответа сервиса: {str(ip_data)[:100]}"
                logging.warning(f"{log_prefix} {error_msg}")
                return None, error_msg

        except ImportError:
             error_msg = "Модуль 'requests' не найден. Невозможно определить Outbound IP."
             logging.error(error_msg) # Критическая ошибка для этой функции
             # Возвращаем ошибку, но не прерываем весь скрипт
             return None, error_msg
        except requests.exceptions.Timeout:
             error_msg = f"Таймаут ({timeout} сек) запроса к IP сервису"
             logging.warning(f"{log_prefix} {error_msg}")
             return None, error_msg
        except requests.exceptions.ProxyError as e:
            # Ошибка SOCKS (например, sing-box упал или не может подключиться дальше)
            error_msg = f"Ошибка прокси при запросе к IP сервису: {str(e)[:150]}"
            logging.warning(f"{log_prefix} {error_msg}")
            return None, error_msg
        except requests.exceptions.RequestException as e:
             # Другие ошибки requests (DNS, Connection Error и т.д.)
             error_msg = f"Ошибка запроса к IP сервису: {type(e).__name__} - {str(e)[:150]}"
             logging.warning(f"{log_prefix} {error_msg}")
             return None, error_msg
        except json.JSONDecodeError:
            # Сервис вернул не JSON
            error_msg = f"Ошибка декодирования JSON ответа от IP сервиса: {response.text[:100]}"
            logging.warning(f"{log_prefix} {error_msg}")
            return None, error_msg
        except Exception as e:
            # Неожиданная ошибка
            error_msg = f"Неожиданная ошибка при запросе к IP сервису: {type(e).__name__}: {str(e)[:100]}"
            logging.error(f"{log_prefix} {error_msg}", exc_info=verbose)
            return None, error_msg
        finally:
            if session:
                try: session.close() # Закрываем сессию requests
                except Exception: pass

    except ValueError as e: # Ошибка парсинга/конвертации
        error_msg = f"Ошибка подготовки: {e}"
        logging.error(f"{log_prefix} {error_msg}")
        return None, error_msg
    except Exception as e: # Общие ошибки (запуск sing-box, запись файла)
        error_msg = f"Общая ошибка Outbound IP теста: {type(e).__name__}: {str(e)[:100]}"
        logging.error(f"{log_prefix} {error_msg}", exc_info=verbose)
        return None, error_msg
    finally:
        # Очистка: завершить sing-box и удалить временный конфиг
        logging.debug(f"{log_prefix} Очистка ресурсов Outbound IP теста...")
        cleanup_process(proxy_process, verbose)
        cleanup_file(config_file)
        logging.debug(f"{log_prefix} Очистка Outbound IP теста завершена.")


def perform_advanced_test(
    config_str: str,
    singbox_path: str,
    tcp_host: str,
    tcp_port: int,
    tcp_timeout: float,
    ip_service_url: str,
    ip_service_timeout: float,
    verbose: bool
) -> Dict[str, Any]:
    """
    Выполняет все углубленные тесты для одной конфигурации.
    Возвращает словарь с результатами.
    """
    log_prefix = f"AdvTest[{config_str[:25]}...]"
    logging.info(f"{log_prefix} Начало углубленных тестов...")

    results = {
        "config": config_str,
        "inbound_ip": None,
        "tcp_success": False,
        "tcp_latency_ms": None,
        "outbound_ip": None,
        "overall_success": False, # Прошла ли все тесты
        "error": None # Общая ошибка, если что-то пошло не так
    }

    # 1. Получить Inbound IP (это не влияет на overall_success)
    results["inbound_ip"] = get_inbound_ip(config_str)
    if not results["inbound_ip"]:
         logging.warning(f"{log_prefix} Не удалось получить Inbound IP.")
         # Не прерываем тест, Inbound IP - информационное поле

    # 2. Выполнить TCP Ping/Latency тест
    tcp_success, tcp_latency, tcp_error = tcp_ping_latency_test(
        config_str, tcp_host, tcp_port, singbox_path, tcp_timeout, verbose
    )
    results["tcp_success"] = tcp_success
    results["tcp_latency_ms"] = tcp_latency
    if not tcp_success:
        results["error"] = f"TCP Тест: {tcp_error or 'Неизвестная ошибка'}"
        logging.warning(f"{log_prefix} {results['error']}")
        # Если TCP тест не прошел, нет смысла делать Outbound IP тест
        logging.info(f"{log_prefix} -> Финальный статус: НЕУДАЧА ({results['error']})")
        return results # Возвращаем результат без Outbound IP теста

    # 3. Определить Outbound IP
    outbound_ip, ip_error = get_outbound_ip(
        config_str, singbox_path, ip_service_url, ip_service_timeout, verbose
    )
    results["outbound_ip"] = outbound_ip
    if not outbound_ip:
        results["error"] = f"Outbound IP Тест: {ip_error or 'Неизвестная ошибка'}"
        logging.warning(f"{log_prefix} {results['error']}")
        # Если Outbound IP не получен, считаем тест неудачным
        logging.info(f"{log_prefix} -> Финальный статус: НЕУДАЧА ({results['error']})")
        return results

    # 4. Если все тесты пройдены
    results["overall_success"] = True
    logging.info(f"{log_prefix} -> Финальный статус: УСПЕХ (TCP Latency: {tcp_latency}ms, Outbound IP: {outbound_ip})")
    return results

# --- Основная функция ---

def main():
    parser = argparse.ArgumentParser(
        description="Этап 2: Углубленное тестирование (TCP, IP) прокси-конфигураций, прошедших URL-тест.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "--input-file",
        type=Path,
        required=True,
        help="Путь к временному JSON-файлу со списком рабочих конфигураций от url_test.py."
    )
    parser.add_argument(
        "--output-file",
        type=Path,
        required=True,
        help="Путь к ФИНАЛЬНОМУ выходному файлу для сохранения окончательно рабочих конфигураций."
    )
    parser.add_argument(
        "--singbox-path",
        type=str,
        required=True, # Должен передаваться из url_test.py
        help="Путь к исполняемому файлу sing-box."
    )
    parser.add_argument(
        "-w", "--workers",
        type=int,
        default=DEFAULT_WORKERS_ADVANCED,
        help="Количество параллельных потоков для углубленного тестирования."
    )
    parser.add_argument(
        "--tcp-host",
        type=str,
        default=DEFAULT_TCP_TEST_HOST,
        help="Хост для TCP Ping/Latency тестов."
    )
    parser.add_argument(
        "--tcp-port",
        type=int,
        default=DEFAULT_TCP_TEST_PORT,
        help="Порт для TCP Ping/Latency тестов."
    )
    parser.add_argument(
        "--tcp-timeout",
        type=float,
        default=DEFAULT_TCP_TIMEOUT,
        help="Таймаут для TCP тестов в секундах."
    )
    parser.add_argument(
        "--ip-service-url",
        type=str,
        default=DEFAULT_IP_SERVICE_URL,
        help="URL сервиса для определения исходящего IP-адреса."
    )
    parser.add_argument(
        "--ip-service-timeout",
        type=float,
        default=DEFAULT_IP_SERVICE_TIMEOUT,
        help="Таймаут для запроса к IP сервису в секундах."
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Включить подробное логирование (уровень DEBUG)."
    )

    args = parser.parse_args()

    # Установка уровня логирования
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Включен режим подробного логирования (DEBUG).")

    # Проверка наличия requests (необходим для get_outbound_ip)
    try:
        import requests
        logging.debug("Модуль 'requests' успешно импортирован.")
    except ImportError:
        logging.error("КРИТИЧЕСКАЯ ОШИБКА: Модуль 'requests' не найден.")
        logging.error("Пожалуйста, установите его командой: pip install requests")
        sys.exit(1)

    # --- ИЗМЕНЕНО: Проверка наличия nc (netcat) ---
    try:
        # Пытаемся запустить nc с опцией -h (help), чтобы проверить его наличие и работоспособность
        # Используем check=True, чтобы вызвать исключение при ошибке
        process = subprocess.run(["nc", "-h"], check=True, capture_output=True, timeout=5)
        # Некоторые версии nc могут выводить help в stderr
        output = (process.stdout or b'') + (process.stderr or b'')
        if b'usage:' in output.lower() or b'openssl' in output.lower() or b'proxy' in output.lower():
             logging.debug("Команда 'nc' (netcat) найдена и работает.")
        else:
             # Если вывод help не похож на стандартный, возможно это не та утилита
             logging.warning("Команда 'nc' найдена, но вывод '-h' выглядит необычно. Убедитесь, что это netcat.")
    except FileNotFoundError:
        logging.error("КРИТИЧЕСКАЯ ОШИБКА: Команда 'nc' (netcat) не найдена.")
        logging.error("Установите netcat (например, 'sudo apt update && sudo apt install netcat-traditional' или 'netcat-openbsd' на Debian/Ubuntu, или 'nmap-ncat' если используете ncat).")
        sys.exit(1)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        logging.error(f"КРИТИЧЕСКАЯ ОШИБКА: Команда 'nc' найдена, но не работает корректно: {e}")
        sys.exit(1)
    except Exception as e:
         logging.error(f"КРИТИЧЕСКАЯ ОШИБКА: Неожиданная ошибка при проверке 'nc': {e}")
         sys.exit(1)
    # --- КОНЕЦ ИЗМЕНЕНИЯ ---

    # Чтение конфигураций из временного файла
    configs_to_test = []
    try:
        logging.info(f"Чтение конфигураций из JSON файла: {args.input_file}")
        with open(args.input_file, 'r', encoding='utf-8') as f:
            # Используем json.load для чтения списка из файла
            configs_to_test = json.load(f)

        # Проверка, что прочитан именно список
        if not isinstance(configs_to_test, list):
             raise ValueError("Формат JSON некорректен, ожидался список (массив) строк.")

        # Дополнительная проверка и очистка: оставляем только непустые строки
        original_count = len(configs_to_test)
        configs_to_test = [str(config).strip() for config in configs_to_test if isinstance(config, str) and str(config).strip()]
        if len(configs_to_test) != original_count:
            logging.warning(f"Обнаружены и удалены некорректные или пустые записи из входного файла {args.input_file}.")

        if not configs_to_test:
             logging.warning(f"Входной файл '{args.input_file}' пуст или не содержит валидных конфигураций после очистки.")
             # Создаем пустой выходной файл и выходим
             args.output_file.parent.mkdir(parents=True, exist_ok=True)
             with open(args.output_file, 'w', encoding='utf-8') as f_out:
                 pass # Просто создаем/очищаем файл
             logging.info(f"Создан пустой финальный файл результатов: {args.output_file}")
             sys.exit(0)

        logging.info(f"Загружено {len(configs_to_test)} конфигураций для углубленного тестирования из {args.input_file}.")

    except FileNotFoundError:
        logging.error(f"КРИТИЧЕСКАЯ ОШИБКА: Входной файл не найден: {args.input_file}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        logging.error(f"КРИТИЧЕСКАЯ ОШИБКА: Ошибка декодирования JSON из файла {args.input_file}: {e}")
        # Попробуем прочитать первые несколько строк для диагностики
        try:
            with open(args.input_file, 'r', encoding='utf-8') as f_err:
                lines = [f_err.readline().strip() for _ in range(5)]
            logging.error(f"Начало файла:\n" + "\n".join(lines))
        except Exception:
            pass # Не удалось прочитать начало файла
        sys.exit(1)
    except ValueError as e: # Ошибка типа данных после json.load
        logging.error(f"КРИТИЧЕСКАЯ ОШИБКА: Некорректные данные в JSON файле {args.input_file}: {e}")
        sys.exit(1)
    except Exception as e: # Другие возможные ошибки чтения файла
        logging.error(f"Неожиданная ошибка чтения или обработки входного файла {args.input_file}: {e}")
        sys.exit(1)


    # Список для окончательно рабочих конфигураций
    final_working_configs = []
    start_time_total = time.time()
    total_configs = len(configs_to_test)

    logging.info(f"Начало углубленного тестирования ({args.workers} потоков)...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        # Создаем задачи для каждой конфигурации
        future_to_config = {
            executor.submit(
                perform_advanced_test,
                config,
                args.singbox_path,
                args.tcp_host,
                args.tcp_port,
                args.tcp_timeout,
                args.ip_service_url,
                args.ip_service_timeout,
                args.verbose
            ): config
            for config in configs_to_test
        }

        # Обрабатываем результаты по мере их поступления
        processed_count = 0
        for future in concurrent.futures.as_completed(future_to_config):
            original_config_str = future_to_config[future]
            processed_count += 1
            try:
                result_dict = future.result() # Получаем результат выполнения perform_advanced_test

                # Логирование уже происходит внутри perform_advanced_test
                # Просто добавляем рабочую конфигурацию в список
                if result_dict['overall_success']:
                    final_working_configs.append(original_config_str)
                # Логируем прогресс (опционально, т.к. детали уже залогированы)
                # status_msg = "УСПЕХ" if result_dict['overall_success'] else "НЕУДАЧА"
                # logging.info(f"({processed_count}/{total_configs}) [{original_config_str[:25]}...] -> Обработан: {status_msg}")

            except Exception as e:
                # Эта ошибка ловит исключения, возникшие *внутри* ThreadPoolExecutor
                # или при получении результата future.result()
                logging.error(f"({processed_count}/{total_configs}) КРИТИЧЕСКАЯ ОШИБКА обработки результата для {original_config_str[:30]}...: {e}", exc_info=args.verbose)

    end_time_total = time.time()
    duration = end_time_total - start_time_total
    num_successful = len(final_working_configs)
    num_failed = total_configs - num_successful

    logging.info("-" * 30)
    logging.info(f"Углубленное тестирование завершено за {duration:.2f} секунд.")
    logging.info(f"Итог: {num_successful} прошли | {num_failed} не прошли | Всего: {total_configs}")
    logging.info("-" * 30)

    # Запись окончательно рабочих конфигураций в выходной файл
    try:
        logging.info(f"Запись {num_successful} окончательно рабочих конфигураций в {args.output_file}...")
        # Создаем директорию, если она не существует
        args.output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(args.output_file, 'w', encoding='utf-8') as f_out:
            if final_working_configs:
                for config in final_working_configs:
                     f_out.write(config + '\n')
            else:
                 # Если список пуст, все равно создаем/перезаписываем файл как пустой
                 pass # Файл будет создан/очищен при открытии 'w'
        logging.info(f"Файл '{args.output_file}' успешно записан ({num_successful} строк).")
    except Exception as e:
        logging.error(f"Ошибка записи в выходной файл {args.output_file}: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
