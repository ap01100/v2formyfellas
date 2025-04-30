# 
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
from contextlib import contextmanager
import select

# --- Logging Setup ---
# Устанавливаем базовый уровень INFO, чтобы видеть прогресс без -v
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Constants ---
DEFAULT_TEST_URL = "http://cp.cloudflare.com"
DEFAULT_TIMEOUT = 10
DEFAULT_WORKERS = 5
SINGBOX_EXECUTABLE = "sing-box" # Предполагаем, что sing-box в PATH или указываем полный путь
#  Добавляем путь к скрипту advanced_test.py
ADVANCED_TEST_SCRIPT = "advanced_test.py" # Предполагаем, что он в той же директории
DEFAULT_SS_METHOD = "aes-256-gcm"  # Default method for Shadowsocks
MAX_WAIT_TIME = 15  # Maximum time to wait for sing-box to start
MAX_ERROR_OUTPUT_LEN = 1000  # Maximum length of error output to log
SOCKET_CHECK_INTERVAL = 0.2  # Interval between socket connection checks
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36'

# --- Вспомогательные функции ---

def check_ubuntu_compatibility():
    """Проверяет совместимость с Ubuntu 22.04."""
    try:
        with open('/etc/os-release', 'r') as f:
            os_info = f.read()
            if 'Ubuntu' in os_info:
                if '22.04' in os_info:
                    logging.debug("Detected Ubuntu 22.04 - compatible environment")
                    return True
                else:
                    logging.warning("Running on Ubuntu, but not version 22.04. Some features may not work as expected.")
                    return True
    except Exception:
        # Если не удается определить ОС, продолжаем выполнение
        pass
    
    # Если это не Ubuntu, выводим предупреждение
    logging.warning("Not running on Ubuntu 22.04. This script is optimized for Ubuntu 22.04, some features may not work as expected.")
    return False

def ensure_executable_permissions(file_path):
    """Ensures the file has executable permissions (chmod +x)."""
    if not os.path.exists(file_path):
        return False
    
    try:
        # Check if file is executable
        if not os.access(file_path, os.X_OK):
            logging.warning(f"File {file_path} is not executable. Attempting to add execute permission.")
            os.chmod(file_path, os.stat(file_path).st_mode | 0o111)  # Add execute permission
            if os.access(file_path, os.X_OK):
                logging.info(f"Successfully added execute permission to {file_path}")
                return True
            else:
                logging.error(f"Failed to make {file_path} executable")
                return False
        return True
    except Exception as e:
        logging.error(f"Error checking/setting permissions on {file_path}: {e}")
        return False

@contextmanager
def create_temp_file(suffix=".json"):
    """Creates a temporary file and ensures it's deleted after use."""
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False, encoding='utf-8') as tmp_file:
            temp_path = tmp_file.name
            yield tmp_file
    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
                logging.debug(f"Temporary file removed: {temp_path}")
            except Exception as e:
                logging.error(f"Error deleting temporary file {temp_path}: {e}")

def find_free_port() -> int:
    """Находит свободный TCP порт."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        # 
        return s.getsockname()[1]

def cleanup_process(process: Optional[subprocess.Popen], verbose: bool = False):
    """Аккуратно завершает процесс и читает его вывод."""
    if not process:
        return
        
    if process.poll() is None:
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
            # 
            logging.debug(f"Временный файл удален: {filepath}")
        except Exception as e:
            logging.error(f"Ошибка при удалении файла {filepath}: {e}")

def wait_for_port(host: str, port: int, timeout: float = MAX_WAIT_TIME) -> bool:
    """Ожидает доступности порта синхронно."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            with socket.create_connection((host, port), timeout=0.1):
                logging.debug(f"Порт {port} готов за {time.time() - start_time:.2f} сек.")
                return True
        except (socket.timeout, ConnectionRefusedError):
            time.sleep(SOCKET_CHECK_INTERVAL)
        except Exception as e:
            logging.error(f"Неожиданная ошибка при проверке порта {port}: {e}")
            time.sleep(SOCKET_CHECK_INTERVAL * 1.5)
    return False

def is_process_running(process: Optional[subprocess.Popen]) -> bool:
    """Проверяет, запущен ли процесс."""
    if not process:
        return False
    return process.poll() is None

# --- Функции удаления дубликатов ---

def get_config_type(config_str: str) -> str:
    """Определяет тип конфигурации по её URI."""
    if config_str.startswith("ss://"):
        return "shadowsocks"
    elif config_str.startswith("trojan://"):
        return "trojan"
    elif config_str.startswith("vmess://"):
        return "vmess"
    elif config_str.startswith("vless://"):
        return "vless"
    else:
        return "unknown"

def extract_functional_params(config_str: str) -> Dict[str, Any]:
    """
    Извлекает функционально значимые параметры из конфигурации,
    используя существующие парсеры конфигураций.
    """
    config_type = get_config_type(config_str)
    
    try:
        if config_type == "shadowsocks":
            params = parse_ss_config(config_str)
            return {
                "type": "shadowsocks",
                "server": params.get("server", ""),
                "server_port": params.get("server_port", 0),
                "method": params.get("method", ""),
                "password": params.get("password", "")
            }
        elif config_type == "trojan":
            params = parse_trojan_config(config_str)
            result = {
                "type": "trojan",
                "server": params.get("server", ""),
                "server_port": params.get("server_port", 0),
                "password": params.get("password", "")
            }
            if "tls" in params:
                result["tls"] = {
                    "server_name": params["tls"].get("server_name", ""),
                    "insecure": params["tls"].get("insecure", False),
                    "alpn": params["tls"].get("alpn")
                }
            if "transport" in params:
                result["transport"] = {
                    "type": params["transport"].get("type", "tcp"),
                    "path": params["transport"].get("path", "/")
                }
            return result
        elif config_type == "vmess":
            params = parse_vmess_config(config_str)
            result = {
                "type": "vmess",
                "server": params.get("server", ""),
                "server_port": params.get("server_port", 0),
                "uuid": params.get("uuid", ""),
                "security": params.get("security", "auto"),
                "alter_id": params.get("alter_id", 0)
            }
            if "tls" in params:
                result["tls"] = {
                    "enabled": True,
                    "server_name": params["tls"].get("server_name", ""),
                    "insecure": params["tls"].get("insecure", False),
                    "alpn": params["tls"].get("alpn")
                }
            if "transport" in params:
                result["transport"] = {
                    "type": params["transport"].get("type", "tcp"),
                    "path": params["transport"].get("path", "/"),
                    "service_name": params["transport"].get("service_name", "")
                }
            return result
        elif config_type == "vless":
            params = parse_vless_config(config_str)
            result = {
                "type": "vless",
                "server": params.get("server", ""),
                "server_port": params.get("server_port", 0),
                "uuid": params.get("uuid", ""),
                "flow": params.get("flow")
            }
            if "tls" in params:
                result["tls"] = {
                    "enabled": True,
                    "server_name": params["tls"].get("server_name", ""),
                    "insecure": params["tls"].get("insecure", False),
                    "alpn": params["tls"].get("alpn")
                }
                if "reality" in params["tls"]:
                    result["tls"]["reality"] = {
                        "enabled": True,
                        "public_key": params["tls"]["reality"].get("public_key", ""),
                        "short_id": params["tls"]["reality"].get("short_id", "")
                    }
            if "transport" in params:
                result["transport"] = {
                    "type": params["transport"].get("type", "tcp"),
                    "path": params["transport"].get("path", "/"),
                    "service_name": params["transport"].get("service_name", "")
                }
            return result
        else:
            return {"type": "unknown", "config": config_str}
    except Exception as e:
        logging.debug(f"Ошибка извлечения параметров из {config_str[:30]}...: {e}")
        return {"type": "error", "config": config_str, "error": str(e)}

def is_functional_duplicate(config1: str, config2: str) -> bool:
    """
    Проверяет, являются ли две конфигурации функциональными дубликатами.
    """
    try:
        params1 = extract_functional_params(config1)
        params2 = extract_functional_params(config2)
        
        # Если типы разные, это не дубликаты
        if params1.get("type") != params2.get("type"):
            return False
        
        # Если при разборе возникла ошибка, не считаем дубликатами
        if params1.get("type") == "error" or params2.get("type") == "error":
            return False
        
        # Удаляем поле "type" перед сравнением остальных параметров
        if "type" in params1:
            del params1["type"]
        if "type" in params2:
            del params2["type"]
        
        # Сравниваем оставшиеся параметры
        return params1 == params2
    except Exception as e:
        logging.debug(f"Ошибка при сравнении конфигураций: {e}")
        return False

def remove_functional_duplicates(configs: List[str]) -> List[str]:
    """
    Удаляет функциональные дубликаты из списка конфигураций.
    Сохраняет первое вхождение уникальной конфигурации.
    """
    if not configs:
        return []
    
    logging.info(f"Начало удаления дубликатов из {len(configs)} конфигураций...")
    unique_configs = []
    duplicates_count = 0
    duplicate_types = {"shadowsocks": 0, "trojan": 0, "vmess": 0, "vless": 0, "unknown": 0}
    
    for config in configs:
        is_duplicate = False
        config_type = get_config_type(config)
        
        for unique_config in unique_configs:
            if is_functional_duplicate(config, unique_config):
                is_duplicate = True
                duplicates_count += 1
                duplicate_types[config_type] += 1
                
                if logging.getLogger().isEnabledFor(logging.DEBUG):
                    logging.debug(f"Найден дубликат [{config_type}]: {config[:50]}... дублирует {unique_config[:50]}...")
                break
        
        if not is_duplicate:
            unique_configs.append(config)
    
    if duplicates_count > 0:
        logging.info(f"Удалено {duplicates_count} дубликатов. Осталось {len(unique_configs)} уникальных конфигураций.")
        logging.info(f"Распределение дубликатов по типам: {', '.join([f'{k}: {v}' for k, v in duplicate_types.items() if v > 0])}")
    else:
        logging.info("Дубликаты не найдены.")
    
    return unique_configs

# --- Парсеры конфигураций (оставлены без изменений) ---

# 
def parse_ss_config(config_str: str) -> Dict[str, Any]:
    """Парсит конфигурацию Shadowsocks (ss://)."""
    parsed = urllib.parse.urlparse(config_str)
    user_info_part = parsed.netloc.split('@')[0]
    server_part = parsed.netloc.split('@')[1]
    host, port_str = server_part.split(':')
    port = int(port_str)

    # 
    method = None # Инициализация
    password = None # Инициализация

    try:
        # Попытка декодировать user_info как base64 (старый формат)
        decoded_user_info = base64.urlsafe_b64decode(user_info_part + '===').decode('utf-8')
        method, password = decoded_user_info.split(':', 1)
    except (base64.binascii.Error, ValueError, UnicodeDecodeError):
        # Если не base64, считаем, что формат method:password
        # Это может быть неверно для некоторых URI, где только пароль в base64
        # 
        logging.warning(f"Не удалось декодировать user_info '{user_info_part}' как base64 для SS, предполагается формат method:password или только пароль base64")
        try:
            # Простой вариант: если нет ':' предполагаем только пароль (декодируя)
            password = base64.urlsafe_b64decode(user_info_part + '===').decode('utf-8')
            # Метод нужно будет указать по умолчанию или извлечь иначе
            # 
            method = DEFAULT_SS_METHOD # Пример! Установите здесь ваш дефолтный метод
            logging.warning(f"Метод не найден явно, использован метод по умолчанию: {method}")
        except Exception as inner_e:
             logging.error(f"Не удалось определить метод/пароль SS из '{user_info_part}'. Ошибка: {inner_e}")
             raise ValueError(f"Не удалось определить метод/пароль SS из '{user_info_part}'")

    if not method or not password:
         # 
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

# 
def parse_trojan_config(config_str: str) -> Dict[str, Any]:
    """Парсит конфигурацию Trojan (trojan://)."""
    parsed = urllib.parse.urlparse(config_str)
    # 
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
        # 
        "password": password,
        "tls": { # Trojan обычно требует TLS
            "enabled": True,
            "server_name": query_params.get('sni', [host])[0],
            "insecure": query_params.get('allowInsecure', ['0'])[0] == '1',
            # Дополнительные параметры TLS (alpn, fingerprint) могут быть в query_params
            "alpn": query_params.get('alpn', [None])[0].split(',') if query_params.get('alpn', [None])[0] else None,
        # 
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
        #  # В sing-box транспорт указывается внутри основного объекта
        outbound["transport"] = ws_settings
    elif transport_type != 'tcp':
        logging.warning(f"Тип транспорта '{transport_type}' для Trojan пока не полностью поддерживается в этом парсере.")

    return outbound

# 
def parse_vmess_config(config_str: str) -> Dict[str, Any]:
    """Парсит конфигурацию VMess (vmess://)."""
    try:
        encoded_json = config_str.replace("vmess://", "")
        # Добавим обработку возможного отсутствия паддинга
        encoded_json = encoded_json.strip()
        padding = "=" * (4 - len(encoded_json) % 4)
        # 
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
        # 
        "security": vmess_params.get("scy", vmess_params.get("security", "auto")), # Добавил синоним "security"
        "alter_id": int(vmess_params.get("aid", 0)),
    }

    tls_enabled = vmess_params.get("tls", "") == "tls"
    if tls_enabled:
        outbound["tls"] = {
            "enabled": True,
            "server_name": vmess_params.get("sni", vmess_params.get("host", vmess_params.get("add"))),
            "insecure": str(vmess_params.get("allowInsecure", vmess_params.get("allow_insecure", "false"))).lower() == "true", # Добавил синоним и проверку строки
            # 
            "alpn": vmess_params.get('alpn', '').split(',') if vmess_params.get('alpn') else None,
        }

    net_type = vmess_params.get("net", "tcp")
    if net_type != "tcp":
         transport = {"type": net_type}
         if net_type == "ws":
             transport["path"] = vmess_params.get("path", "/")
             #  В VMess JSON поле для Host хедера обычно "host"
             ws_host = vmess_params.get("host", vmess_params.get("add"))
             if ws_host:
                 transport["headers"] = {"Host": ws_host}
         elif net_type == "grpc":
             # В sing-box поле называется 'service_name'
             transport["service_name"] = vmess_params.get("path", vmess_params.get("serviceName", ""))
             #  Другие типы транспорта (h2, quic) можно добавить здесь
         outbound["transport"] = transport

    return outbound

# 
def parse_vless_config(config_str: str) -> Dict[str, Any]:
    """Парсит конфигурацию VLESS (vless://)."""
    parsed = urllib.parse.urlparse(config_str)
    uuid = parsed.username if parsed.username else parsed.netloc.split('@')[0]
    server_part = parsed.netloc.split('@')[1] if '@' in parsed.netloc else parsed.netloc
    host, port_str = server_part.split(':')
    port = int(port_str)
    remark = parsed.fragment if parsed.fragment else host
    query_params = urllib.parse.parse_qs(parsed.query)

    # 
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
            # 
            "enabled": True,
            "server_name": query_params.get('sni', [host])[0],
            "insecure": query_params.get('allowInsecure', ['0'])[0] == '1',
             "alpn": query_params.get('alpn', [None])[0].split(',') if query_params.get('alpn', [None])[0] else None,
        }
        if security == 'reality':
            reality_opts = {
                # 
                 "enabled": True,
                 "public_key": query_params.get('pbk', [None])[0],
                 "short_id": query_params.get('sid', [None])[0],
             }
            # Уточняем параметр fingerprint для sing-box
            fp = query_params.get('fp', [None])[0]
            # 
            if fp:
                 reality_opts["fingerprint"] = fp
            tls_settings["reality"] = reality_opts

            # Важно: для Reality часто нужен явный server_name (куда пойдут 'реальные' пакеты)
            # Если sni не указан, он может быть равен host
            tls_settings["server_name"] = query_params.get('sni', [host])[0]

        # 
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
        # 
        if transport_type == 'ws':
            transport["path"] = query_params.get('path', ['/'])[0]
            transport["headers"] = {"Host": query_params.get('host', [host])[0]}
        elif transport_type == 'grpc':
            transport["service_name"] = query_params.get('serviceName', [''])[0]
        # Другие транспорты: h2, quic
        outbound["transport"] = transport

    return outbound

# 
def convert_to_singbox_config(config_str: str, socks_port: int) -> Dict[str, Any]:
    """Конвертирует строку конфигурации в формат JSON для sing-box."""
    # 
    base_config = {
        # Уровень warn по умолчанию, debug при verbose флаге? Можно настроить позже.
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [{
            "type": "socks",
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "listen_port": socks_port,
            # 
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
        # 
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
                # 
                break
            except Exception as e:
                # Логируем ошибку парсинга, но не прерываем всю программу, а возвращаем ошибку в perform_url_test
                logging.error(f"Ошибка парсинга '{config_str[:40]}...' как {protocol_parsed}: {e}", exc_info=False)
                raise ValueError(f"Ошибка парсинга {protocol_parsed} конфигурации: {e}") from e # Добавляем исходную ошибку

    if not parsed_outbound:
        raise ValueError(f"Неподдерживаемый или некорректный протокол: {config_str[:40]}...")

    #  Добавляем основной outbound и direct
    base_config["outbounds"].append(parsed_outbound)
    # "direct" нужен для DNS detour, даже если его определение считается устаревшим
    base_config["outbounds"].append({"type": "direct", "tag": "direct"})
    # "block" пока оставляем закомментированным, т.к. он не вызывал фатальной ошибки
    # base_config["outbounds"].append({"type": "block", "tag":
#  # "block"})


    # Добавляем простое правило маршрутизации: все через наш outbound
    base_config["route"] = {
        "rules": [
            {
                 # Правило для DNS, чтобы он тоже шел через прокси
                 "protocol": ["dns"],
                 # 
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

    #  Добавляем DNS сервер для разрешения через прокси
    base_config["dns"] = {
        "servers": [
            # DNS сервер, который будет запрашиваться через основной outbound
            {"tag": "proxy-dns", "address": "1.1.1.1", "detour": parsed_outbound["tag"]},
             # Резервный DNS сервер (например, локальный или Google)
            {"tag": "local-dns", "address": "8.8.8.8", "detour": "direct"}, # Идет напрямую
            # {"tag": "local-dns", "address": "local"}, # Или используем системный DNS
            {"tag": "block-dns", "address": "rcode://success"} # Для блокировки запросов
        ],
        # 
        "rules": [
             # Можно добавить правила для маршрутизации DNS запросов (например, для обхода блокировок)
             # По умолчанию используем DNS через прокси
             {"server": "proxy-dns"}
        ],
        "strategy": "prefer_ipv4" # или "use_first"
    }

    return base_config

# --- Функция теста ---

# 
def perform_url_test(config_str: str, test_url: str, timeout: float, singbox_path: str, verbose: bool) -> Dict[str, Any]:
    """
    Выполняет URL-тест для одной конфигурации, используя sing-box.
    Запускает sing-box на свободном порту. # 
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
    
    socks_port = None
    config_file = None
    proxy_process = None
    session = None
    
    try:
        # 1. Найти свободный порт
        socks_port = find_free_port()
        local_proxy = f"socks5h://127.0.0.1:{socks_port}" # socks5h для DNS через прокси
        logging.debug(f"{log_prefix} Назначен порт {socks_port}")

        # 2. Сгенерировать конфиг sing-box
        try:
            singbox_config = convert_to_singbox_config(config_str, socks_port)
            singbox_config["log"]["level"] = "debug" if verbose else "warn"
            if verbose:
                logging.debug(f"{log_prefix} Сгенерированный конфиг sing-box:\n{json.dumps(singbox_config, indent=2)}")
        except ValueError as e:
            result["error"] = f"Ошибка конфигурации: {e}"
            logging.error(f"{log_prefix} {result['error']}")
            return result

        # 3. Записать конфиг во временный файл с использованием контекстного менеджера
        with create_temp_file() as config_file_handle:
            config_file = config_file_handle.name
            json.dump(singbox_config, config_file_handle, indent=2)
            config_file_handle.flush()  # Явно сбрасываем буфер
            logging.debug(f"{log_prefix} Конфиг записан в {config_file}")
            
            # Проверяем, что файл конфигурации действительно существует и читаем
            if not os.path.exists(config_file):
                result["error"] = "Ошибка создания файла конфигурации sing-box"
                logging.error(f"{log_prefix} {result['error']}")
                return result
                
            if not os.access(config_file, os.R_OK):
                result["error"] = f"Нет прав на чтение файла конфигурации: {config_file}"
                logging.error(f"{log_prefix} {result['error']}")
                return result
            
            # 4. Запустить sing-box
            cmd = [singbox_path, "run", "-c", config_file]
            logging.debug(f"{log_prefix} Запуск команды: {' '.join(cmd)}")
            
            try:
                # Проверяем существование и исполняемость sing-box перед запуском
                if not os.path.exists(singbox_path):
                    result["error"] = f"Исполняемый файл sing-box не найден по пути: {singbox_path}"
                    logging.error(f"{log_prefix} {result['error']}")
                    return result
                
                if not os.access(singbox_path, os.X_OK):
                    result["error"] = f"Исполняемый файл sing-box не имеет прав на выполнение: {singbox_path}"
                    logging.error(f"{log_prefix} {result['error']}")
                    return result
                
                # Запускаем процесс с перенаправлением вывода для более подробного логирования
                proxy_process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding='utf-8',
                    errors='replace',
                    bufsize=1  # Построчная буферизация для быстрого получения вывода
                )
                
                if not proxy_process or proxy_process.poll() is not None:
                    result["error"] = "Процесс sing-box не был запущен или сразу завершился"
                    logging.error(f"{log_prefix} {result['error']}")
                    return result
                    
                logging.debug(f"{log_prefix} Процесс sing-box запущен, PID: {proxy_process.pid}")
                
            except FileNotFoundError:
                result["error"] = f"Исполняемый файл sing-box не найден по пути: {singbox_path}"
                logging.error(f"{log_prefix} {result['error']}")
                return result
            except PermissionError:
                result["error"] = f"Нет прав на запуск sing-box: {singbox_path}"
                logging.error(f"{log_prefix} {result['error']}")
                return result
            except Exception as e:
                result["error"] = f"Не удалось запустить sing-box: {e}"
                logging.error(f"{log_prefix} {result['error']}")
                return result

            # Небольшая задержка после запуска для инициализации sing-box
            time.sleep(0.5)
            
            # 5. Дождаться запуска sing-box и доступности порта
            logging.debug(f"{log_prefix} Ожидание доступности порта {socks_port}...")
            
            # Проверяем вывод процесса сразу после запуска
            output_logs = ""
            error_logs = ""
            
            if proxy_process.stdout:
                try:
                    # Проверяем, есть ли данные на stdout без блокировки
                    readable, _, _ = select.select([proxy_process.stdout], [], [], 0.1)
                    if readable:
                        output_lines = proxy_process.stdout.readlines(10)  # Читаем максимум 10 строк
                        output_logs = "".join(output_lines)
                        if output_logs.strip():
                            logging.debug(f"{log_prefix} Вывод sing-box при запуске:\n{output_logs}")
                except Exception as e:
                    logging.debug(f"{log_prefix} Ошибка при чтении stdout: {e}")
            
            if proxy_process.stderr:
                try:
                    readable, _, _ = select.select([proxy_process.stderr], [], [], 0.1)
                    if readable:
                        error_lines = proxy_process.stderr.readlines(10)
                        error_logs = "".join(error_lines)
                        if error_logs.strip():
                            logging.debug(f"{log_prefix} Ошибки sing-box при запуске:\n{error_logs}")
                except Exception as e:
                    logging.debug(f"{log_prefix} Ошибка при чтении stderr: {e}")
            
            # Проверяем, не завершился ли процесс с ошибкой
            return_code = proxy_process.poll()
            if return_code is not None:
                logging.error(f"{log_prefix} Процесс sing-box ({proxy_process.pid}) неожиданно завершился с кодом {return_code}.")
                
                try:
                    # Пытаемся получить оставшийся вывод
                    remaining_stdout, remaining_stderr = proxy_process.communicate(timeout=1)
                    if remaining_stdout:
                        output_logs += remaining_stdout
                    if remaining_stderr:
                        error_logs += remaining_stderr
                        
                    # Логируем полный вывод ошибки
                    if error_logs:
                        logging.error(f"{log_prefix} STDERR sing-box:\n{error_logs[:MAX_ERROR_OUTPUT_LEN]}")
                    if output_logs:
                        logging.debug(f"{log_prefix} STDOUT sing-box:\n{output_logs[:MAX_ERROR_OUTPUT_LEN]}")
                except Exception as e:
                    logging.error(f"{log_prefix} Ошибка при чтении вывода sing-box после его завершения: {e}")
                
                result["error"] = f"Sing-box не запустился (код {return_code}). См. логи для STDERR."
                
                # Добавляем текст ошибки в сообщение, если он есть
                if error_logs:
                    result["error"] += f" Ошибка: {error_logs.strip()[:200]}"
                    
                return result
            
            # Ожидаем доступности порта
            port_ready = wait_for_port("127.0.0.1", socks_port, MAX_WAIT_TIME)
            
            # Если порт не стал доступен, но процесс все еще запущен, попробуем получить больше информации
            if not port_ready and is_process_running(proxy_process):
                logging.warning(f"{log_prefix} Порт {socks_port} не стал доступным, но процесс sing-box ({proxy_process.pid}) все еще запущен.")
                
                # Получаем дополнительную информацию о состоянии сетевых подключений
                try:
                    # Проверяем открытые TCP-соединения с помощью системных команд
                    netstat_cmd = ["ss", "-tnlp"]
                    netstat_output = subprocess.check_output(netstat_cmd, universal_newlines=True, stderr=subprocess.DEVNULL)
                    logging.debug(f"{log_prefix} Открытые TCP-соединения (ss -tnlp):\n{netstat_output}")
                    
                    # Проверяем, есть ли в выводе наш порт
                    if f":{socks_port}" in netstat_output:
                        logging.info(f"{log_prefix} Порт {socks_port} найден в списке открытых портов, но не отвечает на подключения.")
                        # Портал найден, но подключение не удаётся. Попробуем предположить, что порт всё-таки готов
                        port_ready = True
                    else:
                        logging.warning(f"{log_prefix} Порт {socks_port} НЕ найден в списке открытых портов.")
                except Exception as e:
                    logging.debug(f"{log_prefix} Ошибка при проверке сетевых подключений: {e}")
                
                # Если не удалось получить информацию о портах, пытаемся продолжить с тестом, если процесс запущен
                if is_process_running(proxy_process):
                    logging.warning(f"{log_prefix} Продолжаем тестирование, несмотря на проблемы с портом {socks_port}.")
                    port_ready = True
            
            if not port_ready:
                logging.error(f"{log_prefix} Таймаут ({MAX_WAIT_TIME} сек) ожидания sing-box на порту {socks_port}.")
                result["error"] = f"Таймаут ожидания sing-box ({socks_port})"
                cleanup_process(proxy_process, verbose)
                return result

            # 6. Выполнить HTTP-запрос через прокси
            try:
                import requests
                session = requests.Session()
                session.proxies = {
                    "http": local_proxy,
                    "https": local_proxy
                }

                logging.debug(f"{log_prefix} Выполнение GET запроса к {test_url} через {local_proxy}...")
                start_time = time.time()
                headers = {'User-Agent': USER_AGENT}
                
                try:
                    response = session.get(test_url, timeout=timeout, headers=headers, allow_redirects=True)
                    latency = (time.time() - start_time) * 1000 # в мс

                    # Проверяем статус код (2xx считается успехом)
                    if 200 <= response.status_code < 300:
                        result["success"] = True
                        result["latency_ms"] = round(latency)
                        result["status_code"] = response.status_code
                        logging.info(f"{log_prefix} УСПЕХ - Задержка: {result['latency_ms']}ms, Статус: {result['status_code']}")
                    else:
                        result["error"] = f"Ошибка теста URL: Неожиданный статус-код {response.status_code}"
                        logging.warning(f"{log_prefix} {result['error']}")
                        result["status_code"] = response.status_code
                except requests.exceptions.Timeout:
                    result["error"] = f"Ошибка теста URL: Таймаут ({timeout} сек)"
                    logging.warning(f"{log_prefix} {result['error']}")
                except requests.exceptions.ProxyError as e:
                    result["error"] = f"Ошибка теста URL: Ошибка прокси - {str(e)[:200]}"
                    logging.warning(f"{log_prefix} {result['error']}")
                except requests.exceptions.RequestException as e:
                    result["error"] = f"Ошибка теста URL: {type(e).__name__} - {str(e)[:200]}"
                    logging.warning(f"{log_prefix} {result['error']}")

            except Exception as e:
                result["error"] = f"Неожиданная ошибка теста URL: {type(e).__name__}: {str(e)[:200]}"
                logging.error(f"{log_prefix} {result['error']}", exc_info=verbose)

    except Exception as e:
        result["error"] = f"Общая ошибка подготовки теста: {type(e).__name__}: {str(e)[:200]}"
        logging.error(f"{log_prefix} {result['error']}", exc_info=verbose)

    finally:
        # 7. Закрыть сессию requests
        if session:
            try:
                session.close()
            except:
                pass
            logging.debug(f"{log_prefix} Сессия requests закрыта.")
        
        # 8. Остановить sing-box
        logging.debug(f"{log_prefix} Очистка ресурсов...")
        cleanup_process(proxy_process, verbose)
        logging.debug(f"{log_prefix} Очистка завершена.")

    return result

# --- Основная функция ---

def main():
    parser = argparse.ArgumentParser(
        description="Этап 1: Параллельное URL-тестирование прокси-конфигураций (ss, vmess, vless, trojan) с использованием sing-box.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "input_file",
        type=Path,
        help="Путь к текстовому файлу со списком конфигураций URI (по одной на строку)."
    )
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
    parser.add_argument(
        "--no-deduplicate",
        action="store_true",
        help="Отключить удаление функциональных дубликатов конфигураций."
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Включен режим подробного логирования (DEBUG).")

    # Проверка совместимости с Ubuntu 22.04
    check_ubuntu_compatibility()

    effective_singbox_path = args.singbox_path

    # Проверка наличия и исполняемости sing-box
    if not os.path.isabs(effective_singbox_path):
        # Если путь не абсолютный, попробуем найти в PATH
        from shutil import which
        resolved_path = which(effective_singbox_path)
        if resolved_path:
            effective_singbox_path = resolved_path
            logging.debug(f"Resolved sing-box path: {effective_singbox_path}")

    # Проверка исполняемых прав
    if os.path.exists(effective_singbox_path) and not ensure_executable_permissions(effective_singbox_path):
        logging.warning(f"Could not set execute permissions on {effective_singbox_path}. You may need to run 'chmod +x {effective_singbox_path}' manually.")

    # Проверка наличия sing-box
    try:
        logging.debug(f"Проверка sing-box по пути: {effective_singbox_path}")
        process_result = subprocess.run(
            [effective_singbox_path, "version"], 
            check=True, 
            capture_output=True, 
            text=True, 
            timeout=5, 
            encoding='utf-8', 
            errors='replace'
        )
        logging.info(f"Используется sing-box: {effective_singbox_path} (Версия: {process_result.stdout.strip()})")
    except FileNotFoundError:
        logging.error(f"КРИТИЧЕСКАЯ ОШИБКА: Исполняемый файл sing-box НЕ НАЙДЕН по пути: '{effective_singbox_path}'")
        logging.error("Убедитесь, что sing-box установлен, имеет права на выполнение (chmod +x) и путь указан верно (через --singbox-path или он есть в $PATH).")
        sys.exit(1)
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

    # Проверка наличия и исполняемости advanced_test.py
    advanced_script_path = ADVANCED_TEST_SCRIPT
    if not os.path.isabs(advanced_script_path):
        # Если указан относительный путь, преобразуем его в абсолютный
        script_dir = os.path.dirname(os.path.abspath(__file__))
        advanced_script_path = os.path.join(script_dir, advanced_script_path)
    
    if not os.path.exists(advanced_script_path):
        logging.warning(f"Скрипт {advanced_script_path} не найден. Будет использовано значение константы.")
    else:
        ensure_executable_permissions(advanced_script_path)
        logging.debug(f"Найден скрипт advanced_test.py: {advanced_script_path}")

    # Проверка наличия requests
    try:
        import requests
        logging.debug(f"Модуль 'requests' успешно импортирован.")
    except ImportError:
        logging.error("КРИТИЧЕСКАЯ ОШИБКА: Модуль 'requests' не найден.")
        logging.error("Пожалуйста, установите его командой: pip install requests")
        sys.exit(1)

    # Проверка доступа к файлу ввода
    input_file_path = args.input_file
    if not os.path.exists(input_file_path):
        logging.error(f"КРИТИЧЕСКАЯ ОШИБКА: Файл не найден: {input_file_path}")
        sys.exit(1)
    
    if not os.access(input_file_path, os.R_OK):
        logging.error(f"КРИТИЧЕСКАЯ ОШИБКА: Нет прав на чтение файла: {input_file_path}")
        sys.exit(1)

    # Проверка возможности записи в выходной файл
    try:
        output_dir = args.advanced_output.parent
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Проверим, можем ли мы создать тестовый файл в этой директории
        test_file = output_dir / f"test_write_{int(time.time())}.tmp"
        try:
            with open(test_file, 'w') as f:
                f.write("test")
            os.remove(test_file)
        except (PermissionError, IOError) as e:
            logging.error(f"КРИТИЧЕСКАЯ ОШИБКА: Нет прав на запись в директорию {output_dir}: {e}")
            sys.exit(1)
    except Exception as e:
        logging.error(f"КРИТИЧЕСКАЯ ОШИБКА: Проблема с проверкой прав на запись: {e}")
        sys.exit(1)

    # Чтение конфигураций
    configs = []
    try:
        logging.info(f"Чтение конфигураций из файла: {args.input_file}")
        with open(args.input_file, 'r', encoding='utf-8') as f:
            configs = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
        if not configs:
            logging.warning(f"Файл '{args.input_file}' пуст или содержит только комментарии/пустые строки. Тестировать нечего.")
            sys.exit(0)
        logging.info(f"Загружено {len(configs)} конфигураций для тестирования.")
        
        # Удаление функциональных дубликатов перед тестированием
        if not args.no_deduplicate:
            configs = remove_functional_duplicates(configs)
            logging.info("Удаление дубликатов выполнено успешно.")
        else:
            logging.info("Удаление дубликатов отключено через аргумент --no-deduplicate.")
        
    except FileNotFoundError:
        logging.error(f"КРИТИЧЕСКАЯ ОШИБКА: Файл не найден: {args.input_file}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Ошибка чтения файла {args.input_file}: {e}")
        sys.exit(1)

    # Определяем оптимальное количество потоков
    workers = args.workers
    try:
        import multiprocessing
        cpu_count = multiprocessing.cpu_count()
        if workers > cpu_count * 2:
            logging.warning(f"Указано большое количество потоков ({workers}). Это может вызвать проблемы с производительностью.")
            logging.warning(f"Рекомендуемое значение для вашей системы: {cpu_count} - {cpu_count * 2} потоков.")
    except:
        pass

    # Список для хранения рабочих конфигураций
    working_configs = []
    start_time_total = time.time()
    total_configs = len(configs)

    logging.info(f"Начало URL-тестирования ({workers} потоков)...")

    # Основная логика тестирования
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        # Создаем задачи для пакетной обработки
        futures = []
        for config in configs:
            future = executor.submit(
                perform_url_test, 
                config, 
                args.url, 
                args.timeout, 
                effective_singbox_path, 
                args.verbose
            )
            futures.append((future, config))
        
        # Собираем результаты по мере выполнения
        for i, (future, original_config_str) in enumerate(futures, 1):
            try:
                result_dict = future.result()
                
                status_msg = "УСПЕХ" if result_dict['success'] else "НЕУДАЧА"
                error_msg = f" Ошибка: {result_dict['error']}" if not result_dict['success'] and result_dict['error'] else ""
                latency_msg = f" Задержка: {result_dict['latency_ms']}ms" if result_dict['success'] else ""
                
                logging.info(f"({i}/{total_configs}) [{original_config_str[:25]}...] -> {status_msg}{latency_msg}{error_msg}")
                
                if result_dict['success']:
                    working_configs.append(original_config_str)
                    
            except Exception as e:
                logging.error(f"({i}/{total_configs}) КРИТИЧЕСКАЯ ОШИБКА обработки результата для {original_config_str[:30]}...: {e}", exc_info=args.verbose)

    end_time_total = time.time()
    duration = end_time_total - start_time_total
    num_successful = len(working_configs)
    num_failed = total_configs - num_successful

    logging.info(f"URL-тестирование завершено за {duration:.2f} секунд.")
    logging.info(f"Итог URL-теста: {num_successful} конфигураций прошли, {num_failed} не прошли.")

    # Передача управления в advanced_test.py
    if working_configs:
        with create_temp_file() as tmp_file:
            # Очищаем конфигурации от потенциально проблемных символов
            cleaned_configs = []
            for config in working_configs:
                try:
                    # Экранируем или удаляем потенциально проблемные символы
                    cleaned_config = config
                    # Заменяем обратные кавычки (`) на обычные одинарные (')
                    cleaned_config = cleaned_config.replace('`', "'")
                    # Удаляем символы управления, которые могут нарушить формат JSON
                    cleaned_config = ''.join(c for c in cleaned_config if ord(c) >= 32 or c in '\n\r\t')
                    # Заменяем эмодзи и другие специальные символы на безопасные представления
                    cleaned_config = cleaned_config.encode('ascii', errors='backslashreplace').decode('ascii')
                    cleaned_configs.append(cleaned_config)
                except Exception as e:
                    logging.warning(f"Не удалось очистить конфигурацию: {config[:30]}... Ошибка: {e}")
                    # Включаем исходную конфигурацию, если очистка не удалась
                    cleaned_configs.append(config)
            
            try:
                # Используем ensure_ascii=True для безопасного кодирования всех символов
                json.dump(cleaned_configs, tmp_file, ensure_ascii=True)
                tmp_file.flush()
                temp_file_path = tmp_file.name
                
                # Проверяем созданный JSON на валидность перед передачей в advanced_test.py
                with open(temp_file_path, 'r') as check_file:
                    try:
                        json.load(check_file)
                        logging.debug(f"Проверка JSON перед передачей в advanced_test.py прошла успешно")
                    except json.JSONDecodeError as e:
                        logging.error(f"Созданный JSON невалиден: {e}")
                        logging.error(f"Создаём JSON заново с дополнительной обработкой...")
                        # Если проверка не удалась, создаем JSON построчно
                        with open(temp_file_path, 'w') as retry_file:
                            retry_file.write('[\n')
                            for i, config in enumerate(cleaned_configs):
                                if i > 0:
                                    retry_file.write(',\n')
                                # Используем repr() для гарантированного экранирования всех спецсимволов
                                retry_file.write(json.dumps(config, ensure_ascii=True))
                            retry_file.write('\n]')
                
                logging.info(f"Передача {len(cleaned_configs)} рабочих конфигураций в {ADVANCED_TEST_SCRIPT}...")
                
                # Формируем команду для запуска advanced_test.py
                cmd = [
                    sys.executable,
                    advanced_script_path,
                    "--input-file", temp_file_path,
                    "--output-file", str(args.advanced_output),
                    "--singbox-path", effective_singbox_path
                ]
                if args.verbose:
                    cmd.append("--verbose")
                    
                logging.debug(f"Запуск команды: {' '.join(cmd)}")
                
                try:
                    result = subprocess.run(
                        cmd, 
                        check=False, 
                        capture_output=True, 
                        text=True, 
                        encoding='utf-8', 
                        errors='replace'
                    )
                    
                    # Логируем вывод advanced_test.py
                    logging.info(f"--- Начало вывода {ADVANCED_TEST_SCRIPT} ---")
                    if result.stdout:
                        logging.info(result.stdout.strip())
                    if result.stderr:
                        if result.returncode != 0:
                            logging.error(f"STDERR от {ADVANCED_TEST_SCRIPT}:\n{result.stderr.strip()}")
                        else:
                            logging.warning(f"STDERR от {ADVANCED_TEST_SCRIPT} (код возврата 0):\n{result.stderr.strip()}")
                    logging.info(f"--- Конец вывода {ADVANCED_TEST_SCRIPT} ---")
                    
                    if result.returncode != 0:
                        logging.error(f"{ADVANCED_TEST_SCRIPT} завершился с кодом ошибки {result.returncode}.")
                        
                except FileNotFoundError:
                    logging.error(f"КРИТИЧЕСКАЯ ОШИБКА: Скрипт {ADVANCED_TEST_SCRIPT} не найден.")
                    logging.error("Убедитесь, что файл advanced_test.py находится в той же директории или укажите правильный путь в константе ADVANCED_TEST_SCRIPT.")
                except Exception as e:
                    logging.error(f"Неожиданная ошибка при запуске или обработке {ADVANCED_TEST_SCRIPT}: {e}", exc_info=args.verbose)
            except Exception as json_error:
                logging.error(f"Ошибка при создании или обработке JSON: {json_error}")
                # Если не удалось создать JSON, записываем конфигурации в обычный текстовый файл
                with open(args.advanced_output, 'w', encoding='utf-8') as direct_output:
                    for config in cleaned_configs:
                        direct_output.write(f"{config}\n")
                logging.info(f"Рабочие конфигурации ({len(cleaned_configs)}) сохранены напрямую в {args.advanced_output}")
    else:
        logging.info("После URL-теста не осталось рабочих конфигураций. Запуск advanced_test.py пропущен.")


if __name__ == "__main__":
    main()