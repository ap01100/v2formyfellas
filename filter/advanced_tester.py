"""
Advanced testing module for proxy configurations.
Performs TCP ping/latency tests and determines inbound/outbound IP addresses.
"""

import os
import time
import json
import subprocess
import socket
import logging
import sys
import requests
import socks  # Добавляем импорт PySocks для прямой работы с SOCKS-прокси
from typing import Dict, Any, Optional, Tuple, List

from filter.config import (
    DEFAULT_TCP_TEST_HOST, DEFAULT_TCP_TEST_PORT, DEFAULT_TCP_TIMEOUT,
    DEFAULT_IP_SERVICE_URL, DEFAULT_IP_SERVICE_TIMEOUT,
    MAX_WAIT_TIME, SOCKET_CHECK_INTERVAL, USER_AGENT
)
from filter.utils import find_free_port, cleanup_process, cleanup_file, wait_for_port, get_temp_file_path
from filter.parsers import convert_to_singbox_config, parse_ss_config, parse_trojan_config, parse_vmess_config, parse_vless_config
from filter.process_manager import SingBoxProcessManager
from filter.url_tester import get_process_manager

def get_inbound_ip(config_str: str) -> Optional[str]:
    """Extracts the server (inbound) IP address from a configuration string."""
    log_prefix = f"InIP [{config_str[:25]}...]"
    logging.debug(f"{log_prefix} Getting IP...")
    
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
                    logging.debug(f"{log_prefix} Found Inbound IP: {in_ip}")
                    return str(in_ip)  # Ensure it's a string
                else:
                    logging.warning(f"{log_prefix} 'server' field not found in parsed config.")
                    return None
        
        logging.warning(f"{log_prefix} Could not recognize protocol for IP extraction.")
        return None
    except Exception as e:
        logging.error(f"{log_prefix} Error parsing to get Inbound IP: {e}")
        return None

def tcp_ping_with_python(host: str, port: int, proxy_port: int, timeout: float) -> Tuple[bool, Optional[float], Optional[str]]:
    """
    Выполняет TCP-пинг с использованием чистого Python и библиотеки PySocks.
    Эта функция является альтернативой для Windows, где netcat может быть недоступен.
    """
    start_time = time.time()
    sock = None
    
    try:
        # Создаем SOCKS5-прокси сокет
        sock = socks.socksocket()
        sock.set_proxy(socks.SOCKS5, "127.0.0.1", proxy_port)
        sock.settimeout(timeout)
        
        # Пытаемся подключиться к целевому хосту
        sock.connect((host, port))
        end_time = time.time()
        latency = (end_time - start_time) * 1000  # в мс
        
        return True, round(latency), None
    except socks.ProxyConnectionError as e:
        return False, None, f"Ошибка подключения к прокси: {str(e)}"
    except socks.GeneralProxyError as e:
        return False, None, f"Общая ошибка прокси: {str(e)}"
    except socket.timeout:
        return False, None, f"Таймаут подключения к {host}:{port}"
    except socket.error as e:
        return False, None, f"Ошибка сокета: {str(e)}"
    except Exception as e:
        return False, None, f"Непредвиденная ошибка: {type(e).__name__}: {str(e)}"
    finally:
        if sock:
            sock.close()

def tcp_ping_latency_test(
    config_str: str,
    target_host: str,
    target_port: int,
    singbox_path: str,
    timeout: float,
    verbose: bool
) -> Tuple[bool, Optional[float], Optional[str]]:
    """
    Performs a TCP ping and measures latency to target_host:target_port through the proxy.
    Uses netcat (nc) for testing on Unix-like systems and pure Python on Windows.
    Returns (success, latency_ms, error_message).
    """
    log_prefix = f"TCP [{config_str[:25]}... -> {target_host}:{target_port}]"
    logging.debug(f"{log_prefix} Starting...")

    socks_port: Optional[int] = None
    config_file: Optional[str] = None
    proxy_process: Optional[subprocess.Popen] = None

    try:
        # 1. Find port and generate sing-box config
        socks_port = find_free_port()
        log_level = "debug" if verbose else "warn"
        singbox_config = convert_to_singbox_config(config_str, socks_port, log_level)

        # 2. Write config to temp file in workfiles directory
        config_file = get_temp_file_path("temp_tcp", socks_port)
        with open(config_file, "w", encoding="utf-8") as tmp:
            json.dump(singbox_config, tmp)
        logging.debug(f"{log_prefix} sing-box config written to {config_file}")

        # 3. Start sing-box
        cmd = [singbox_path, "run", "-c", config_file]
        proxy_process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
        )

        # 4. Wait for sing-box to start
        start_wait = time.time()
        port_ready = False
        max_wait_time = 10  # Time to wait for sing-box to start
        
        while time.time() - start_wait < max_wait_time:
            if proxy_process.poll() is not None:  # Process ended
                stderr_output = ""
                try:
                    # Read output from terminated process
                    _, stderr_bytes = proxy_process.communicate(timeout=1)
                    stderr_output = stderr_bytes.decode('utf-8', errors='replace')[:500]  # Limit length
                    
                    # Проверяем наличие конкретных ошибок
                    if "Only one usage of each socket address" in stderr_output:
                        error_msg = f"sing-box failed to start: порт {socks_port} уже используется. Попробуйте запустить тест позже или с меньшим количеством потоков."
                    else:
                        error_msg = f"sing-box failed to start (code {proxy_process.poll()}). Stderr: {stderr_output}"
                except Exception as e:
                    error_msg = f"sing-box failed to start (code {proxy_process.poll()}). Error reading stderr: {str(e)}"
                    
                logging.warning(f"{log_prefix} {error_msg}")
                return False, None, error_msg
            
            try:
                # Check if port is listening
                with socket.create_connection(("127.0.0.1", socks_port), timeout=0.1):
                    port_ready = True
                    logging.debug(f"{log_prefix} Port {socks_port} ready after {time.time() - start_wait:.2f} sec.")
                    break
            except (socket.timeout, ConnectionRefusedError):
                time.sleep(0.2)  # Wait a bit before next check
            except Exception as e:
                logging.warning(f"{log_prefix} Error checking port {socks_port}: {e}")
                time.sleep(0.3)

        if not port_ready:
            error_msg = f"Timeout ({max_wait_time} sec) waiting for sing-box on port {socks_port}"
            logging.warning(f"{log_prefix} {error_msg}")
            cleanup_process(proxy_process, verbose)
            return False, None, error_msg

        # 5. TCP connection attempt through proxy
        # Выбираем метод в зависимости от ОС
        if sys.platform == 'win32':
            # Используем чистый Python для Windows
            return tcp_ping_with_python(target_host, target_port, socks_port, timeout)
        else:
            # Используем netcat для Unix-подобных систем
            start_time = time.time()
            try:
                # Convert timeout to integer seconds for nc -w
                nc_timeout_sec = max(1, int(timeout))
                # Netcat command for TCP connection check through SOCKS5
                nc_cmd = [
                    "nc", "-z",
                    "-X", "5",
                    "-x", f"127.0.0.1:{socks_port}",
                    "-w", str(nc_timeout_sec),
                    target_host,
                    str(target_port)
                ]

                logging.debug(f"{log_prefix} Running nc for TCP test: {' '.join(nc_cmd)}")
                ping_process = subprocess.run(
                    nc_cmd,
                    capture_output=True,
                    timeout=nc_timeout_sec + 2  # Add extra time for nc command execution
                )
                end_time = time.time()
                latency = (end_time - start_time) * 1000  # in ms

                if ping_process.returncode == 0:
                    logging.debug(f"{log_prefix} Successful connection (via nc -z), latency (approx.): {latency:.0f}ms")
                    return True, round(latency), None
                else:
                    # Analyze nc error
                    nc_error = ping_process.stderr.decode('utf-8', errors='replace').strip()
                    error_msg = f"TCP Test via nc failed (code {ping_process.returncode}). Error: {nc_error[:100]}"
                    logging.warning(f"{log_prefix} {error_msg}")
                    return False, None, error_msg

            except subprocess.TimeoutExpired:
                error_msg = f"Timeout ({nc_timeout_sec + 2} sec) executing nc command"
                logging.warning(f"{log_prefix} {error_msg}")
                return False, None, error_msg
            except FileNotFoundError:
                # Если netcat не найден, попробуем использовать Python-метод как запасной вариант
                logging.warning(f"{log_prefix} Command 'nc' (netcat) not found. Falling back to Python implementation.")
                return tcp_ping_with_python(target_host, target_port, socks_port, timeout)
            except Exception as e:
                error_msg = f"Error executing nc or TCP connection: {type(e).__name__}: {str(e)[:100]}"
                logging.warning(f"{log_prefix} {error_msg}")
                return False, None, error_msg

    except ValueError as e:  # Parsing/conversion error
        error_msg = f"Preparation error: {e}"
        logging.error(f"{log_prefix} {error_msg}")
        return False, None, error_msg
    except Exception as e:  # General errors (starting sing-box, writing file)
        error_msg = f"General TCP test error: {type(e).__name__}: {str(e)[:100]}"
        logging.error(f"{log_prefix} {error_msg}", exc_info=verbose)
        return False, None, error_msg
    finally:
        # Cleanup: terminate sing-box and remove temp config
        logging.debug(f"{log_prefix} Cleaning up TCP test resources...")
        cleanup_process(proxy_process, verbose)
        cleanup_file(config_file)
        logging.debug(f"{log_prefix} TCP test cleanup completed.")

def get_outbound_ip_with_requests(
    proxy_url: str,
    ip_service_url: str,
    timeout: float,
    verbose: bool
) -> Tuple[Optional[str], Optional[str]]:
    """
    Get outbound IP address using requests library.
    
    Args:
        proxy_url: Proxy URL in format socks5h://host:port
        ip_service_url: URL of IP detection service
        timeout: Request timeout in seconds
        verbose: Enable verbose logging
        
    Returns:
        Tuple of (IP address or None, error message or None)
    """
    log_prefix = f"IPTest[{proxy_url}]"
    
    if verbose:
        logging.debug(f"{log_prefix} Getting outbound IP via {ip_service_url}")
    
    try:
        session = requests.Session()
        session.proxies = {"http": proxy_url, "https": proxy_url}
        session.headers.update({"User-Agent": USER_AGENT})
        
        response = session.get(ip_service_url, timeout=timeout)
        response.raise_for_status()
        
        ip_data = response.json()
        outbound_ip = ip_data.get("ip")
        
        if outbound_ip and isinstance(outbound_ip, str):
            if verbose:
                logging.debug(f"{log_prefix} Successfully got Outbound IP: {outbound_ip}")
            return outbound_ip, None
        else:
            error_msg = f"Could not extract IP from service response: {str(ip_data)[:100]}"
            if verbose:
                logging.debug(f"{log_prefix} {error_msg}")
            return None, error_msg
            
    except requests.exceptions.RequestException as e:
        error_msg = f"Request error: {type(e).__name__}: {str(e)}"
        if verbose:
            logging.debug(f"{log_prefix} {error_msg}")
        return None, error_msg
        
    except Exception as e:
        error_msg = f"Unknown error: {type(e).__name__}: {str(e)}"
        if verbose:
            logging.debug(f"{log_prefix} {error_msg}")
        return None, error_msg

def perform_advanced_test(
    config_str: str,
    singbox_path: str,
    tcp_host: str = DEFAULT_TCP_TEST_HOST,
    tcp_port: int = DEFAULT_TCP_TEST_PORT,
    tcp_timeout: float = DEFAULT_TCP_TIMEOUT,
    ip_service_url: str = DEFAULT_IP_SERVICE_URL,
    ip_service_timeout: float = DEFAULT_IP_SERVICE_TIMEOUT,
    verbose: bool = False
) -> Dict[str, Any]:
    """
    Performs advanced testing for a proxy configuration.
    Tests TCP connectivity and determines outbound IP address.
    
    Args:
        config_str: Строка конфигурации прокси
        singbox_path: Путь к исполняемому файлу sing-box
        tcp_host: Хост для TCP-теста
        tcp_port: Порт для TCP-теста
        tcp_timeout: Таймаут для TCP-теста в секундах
        ip_service_url: URL сервиса для определения IP-адреса
        ip_service_timeout: Таймаут для запроса к сервису IP в секундах
        verbose: Подробный вывод логов
        
    Returns:
        Dict with test results
    """
    log_prefix = f"AdvTest[{config_str[:20]}...]"
    
    if verbose:
        logging.debug(f"{log_prefix} Starting advanced test")
    
    # Initialize test result dictionary
    result = {
        "success": False,
        "config": config_str,
        "tcp_latency_ms": None,
        "outbound_ip": None,
        "error": None
    }
    
    # Получаем менеджер процессов
    process_manager = get_process_manager(singbox_path, verbose)
    
    # Получаем или создаем процесс для этой конфигурации
    sing_process = process_manager.get_process(config_str)
    
    if not sing_process:
        result["error"] = "Failed to start sing-box process"
        if verbose:
            logging.debug(f"{log_prefix} {result['error']}")
        return result
    
    try:
        # Получаем порт прокси
        socks_port = sing_process.socks_port
        
        if verbose:
            logging.debug(f"{log_prefix} Using proxy on port {socks_port}")
        
        # 1. Perform TCP test
        tcp_latency, tcp_error = test_tcp_connection(
            "127.0.0.1", socks_port, tcp_host, tcp_port, tcp_timeout, verbose
        )
        
        if tcp_error:
            result["error"] = f"TCP test failed: {tcp_error}"
            if verbose:
                logging.debug(f"{log_prefix} {result['error']}")
            return result
        
        result["tcp_latency_ms"] = tcp_latency
        
        if verbose:
            logging.debug(f"{log_prefix} TCP test successful, latency: {tcp_latency}ms")
        
        # 2. Get outbound IP
        proxy_url = f"socks5h://127.0.0.1:{socks_port}"
        outbound_ip, ip_error = get_outbound_ip_with_requests(
            proxy_url, ip_service_url, ip_service_timeout, verbose
        )
        
        if ip_error:
            result["error"] = f"IP detection failed: {ip_error}"
            if verbose:
                logging.debug(f"{log_prefix} {result['error']}")
            # Не возвращаем сразу, так как TCP-тест прошел успешно
        
        result["outbound_ip"] = outbound_ip
        
        # If both tests passed, mark as successful
        result["success"] = tcp_latency is not None and outbound_ip is not None
        
        if verbose:
            if result["success"]:
                logging.debug(f"{log_prefix} Advanced test successful: "
                             f"TCP latency: {tcp_latency}ms, Outbound IP: {outbound_ip}")
            else:
                logging.debug(f"{log_prefix} Advanced test partially failed: "
                             f"TCP latency: {tcp_latency}ms, Outbound IP: {outbound_ip or 'Failed'}")
        
    except Exception as e:
        result["error"] = f"Unknown error: {type(e).__name__}: {str(e)}"
        if verbose:
            logging.debug(f"{log_prefix} Failed: {result['error']}")
    finally:
        # Отмечаем процесс как неиспользуемый
        process_manager.release_process(config_str)
    
    return result

def test_tcp_connection(
    proxy_host: str,
    proxy_port: int,
    target_host: str,
    target_port: int,
    timeout: float,
    verbose: bool
) -> Tuple[Optional[int], Optional[str]]:
    """
    Test TCP connection through a SOCKS5 proxy.
    
    Args:
        proxy_host: SOCKS5 proxy host
        proxy_port: SOCKS5 proxy port
        target_host: Target host to connect to
        target_port: Target port to connect to
        timeout: Connection timeout in seconds
        verbose: Enable verbose logging
        
    Returns:
        Tuple of (latency in ms, error message or None)
    """
    log_prefix = f"TCPTest[{proxy_host}:{proxy_port}]"
    
    if verbose:
        logging.debug(f"{log_prefix} Testing TCP connection to {target_host}:{target_port}")
    
    try:
        # Create a SOCKS5 socket
        s = socks.socksocket()
        s.set_proxy(socks.SOCKS5, proxy_host, proxy_port)
        s.settimeout(timeout)
        
        # Measure connection time
        start_time = time.time()
        s.connect((target_host, target_port))
        end_time = time.time()
        
        # Calculate latency
        latency_ms = round((end_time - start_time) * 1000)
        
        # Close the socket
        s.close()
        
        if verbose:
            logging.debug(f"{log_prefix} TCP connection successful, latency: {latency_ms}ms")
        
        return latency_ms, None
        
    except socks.ProxyConnectionError as e:
        error_msg = f"Cannot connect to proxy: {str(e)}"
        if verbose:
            logging.debug(f"{log_prefix} {error_msg}")
        return None, error_msg
        
    except socks.GeneralProxyError as e:
        error_msg = f"Proxy error: {str(e)}"
        if verbose:
            logging.debug(f"{log_prefix} {error_msg}")
        return None, error_msg
        
    except socket.timeout:
        error_msg = f"Connection timeout after {timeout}s"
        if verbose:
            logging.debug(f"{log_prefix} {error_msg}")
        return None, error_msg
        
    except Exception as e:
        error_msg = f"Unknown error: {type(e).__name__}: {str(e)}"
        if verbose:
            logging.debug(f"{log_prefix} {error_msg}")
        return None, error_msg

def get_outbound_ip(
    config_str: str,
    singbox_path: str,
    ip_service_url: str,
    timeout: float,
    verbose: bool
) -> Tuple[Optional[str], Optional[str]]:
    """
    Get outbound IP address using a proxy.
    
    Args:
        config_str: Proxy configuration string
        singbox_path: Path to sing-box executable
        ip_service_url: URL of IP detection service
        timeout: Request timeout in seconds
        verbose: Enable verbose logging
        
    Returns:
        Tuple of (IP address or None, error message or None)
    """
    log_prefix = f"IPTest[{config_str[:20]}...]"
    
    # Получаем менеджер процессов
    process_manager = get_process_manager(singbox_path, verbose)
    
    # Получаем или создаем процесс для этой конфигурации
    sing_process = process_manager.get_process(config_str)
    
    if not sing_process:
        return None, "Failed to start sing-box process"
    
    try:
        # Получаем URL прокси
        proxy_url = sing_process.get_proxy_url()
        
        # Получаем IP через прокси
        outbound_ip, error = get_outbound_ip_with_requests(
            proxy_url, ip_service_url, timeout, verbose
        )
        
        return outbound_ip, error
        
    finally:
        # Отмечаем процесс как неиспользуемый
        process_manager.release_process(config_str)

def perform_batch_advanced_tests(
    configs: List[str],
    singbox_path: str,
    tcp_host: str = DEFAULT_TCP_TEST_HOST,
    tcp_port: int = DEFAULT_TCP_TEST_PORT,
    tcp_timeout: float = DEFAULT_TCP_TIMEOUT,
    ip_service_url: str = DEFAULT_IP_SERVICE_URL,
    ip_service_timeout: float = DEFAULT_IP_SERVICE_TIMEOUT,
    verbose: bool = False
) -> Dict[str, List[str]]:
    """
    Performs advanced tests on a batch of configurations.
    Returns a dictionary with 'working' and 'failed' config lists.
    """
    result = {
        "working": [],
        "failed": []
    }
    
    total = len(configs)
    for i, config in enumerate(configs, 1):
        logging.info(f"Advanced testing config {i}/{total}: {config[:30]}...")
        test_result = perform_advanced_test(
            config, singbox_path, tcp_host, tcp_port, tcp_timeout,
            ip_service_url, ip_service_timeout, verbose
        )
        
        if test_result["success"]:
            result["working"].append(config)
            tcp_latency = test_result.get("tcp_latency_ms", "N/A")
            outbound_ip = test_result.get("outbound_ip", "N/A")
            logging.info(f"✓ Config {i}/{total} ADVANCED SUCCESS, TCP latency: {tcp_latency}ms, IP: {outbound_ip}")
        else:
            result["failed"].append(config)
            error = test_result.get("error", "Unknown error")
            logging.info(f"✗ Config {i}/{total} ADVANCED FAILED: {error[:100]}")
    
    success_rate = len(result["working"]) / total * 100 if total > 0 else 0
    logging.info(f"Advanced testing completed: {len(result['working'])}/{total} working ({success_rate:.1f}%)")
    
    return result 