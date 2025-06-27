"""
URL Tester module.
Handles testing of proxy configurations using HTTP requests.
"""

import os
import time
import json
import subprocess
import requests
import logging
from typing import Dict, Any, Optional, List, Union

from filter.config import (
    DEFAULT_TEST_URLS, DEFAULT_TIMEOUT, USER_AGENT, 
    MULTIPLE_URL_MODE, MAX_RETRY_COUNT, RETRY_DELAY
)
from filter.utils import find_free_port, cleanup_process, cleanup_file, wait_for_port, get_temp_file_path
from filter.parsers import convert_to_singbox_config

def perform_url_test(
    config_str: str, 
    test_url: Union[str, List[str]], 
    timeout: float, 
    singbox_path: str, 
    verbose: bool, 
    use_http_proxy: bool = False
) -> Dict[str, Any]:
    """
    Performs a URL test for a single proxy configuration.
    Sets up sing-box, makes an HTTP request through the proxy, and measures success and latency.
    If test_url is a list, tests all URLs in the list.
    Returns a dict with test results.
    
    Args:
        config_str: Строка конфигурации прокси
        test_url: URL или список URL для тестирования
        timeout: Таймаут в секундах
        singbox_path: Путь к исполняемому файлу sing-box
        verbose: Подробный вывод логов
        use_http_proxy: Использовать HTTP прокси вместо SOCKS5
    """
    # Добавляем префикс для логов
    log_prefix = f"URLTest[{config_str[:20]}...]"
    
    if verbose:
        logging.debug(f"{log_prefix} Starting test with {singbox_path}")
    
    # Handle single URL case
    if isinstance(test_url, str):
        test_urls = [test_url]
    else:
        test_urls = test_url
    
    # Initialize test result dictionary
    result = {
        "success": False,
        "url_results": [],  # Will contain results for each URL
        "error": None,
        "config": config_str,
        "latency_ms": None  # Will be average of successful URLs
    }
    
    socks_port = None
    config_file = None
    proxy_process = None
    
    try:
        # 1. Find free port and generate sing-box config
        socks_port = find_free_port()
        if verbose:
            logging.debug(f"{log_prefix} Using port {socks_port}")
            
        log_level = "debug" if verbose else "warn"
        singbox_config = convert_to_singbox_config(config_str, socks_port, log_level, use_http_proxy)
        
        # 2. Write config to temp file in workfiles directory
        config_file = get_temp_file_path("temp", socks_port)
        with open(config_file, "w", encoding="utf-8") as tmp:
            json.dump(singbox_config, tmp)
            
        if verbose:
            logging.debug(f"{log_prefix} Config written to {config_file}")
            
        # 3. Start sing-box
        cmd = [singbox_path, "run", "-c", config_file]
        if verbose:
            logging.debug(f"{log_prefix} Running command: {' '.join(cmd)}")
            
        proxy_process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
        )
        
        # 4. Wait for sing-box to start
        if verbose:
            logging.debug(f"{log_prefix} Waiting for port {socks_port} to be ready...")
            
        if not wait_for_port("127.0.0.1", socks_port):
            error_msg = f"Timeout waiting for sing-box to start on port {socks_port}"
            if verbose:
                logging.debug(f"{log_prefix} {error_msg}")
            result["error"] = error_msg
            return result
        
        if verbose:
            logging.debug(f"{log_prefix} sing-box started successfully on port {socks_port}")
            
        # 5. Setup proxies and headers for requests
        if use_http_proxy:
            proxies = {
                "http": f"http://127.0.0.1:{socks_port}",
                "https": f"http://127.0.0.1:{socks_port}"
            }
        else:
            proxies = {
                "http": f"socks5h://127.0.0.1:{socks_port}",
                "https": f"socks5h://127.0.0.1:{socks_port}"
            }
        headers = {"User-Agent": USER_AGENT}
        
        # 6. Test each URL
        successful_tests = 0
        total_latency = 0
        
        for current_url in test_urls:
            url_result = {
                "url": current_url,
                "success": False,
                "latency_ms": None,
                "error": None
            }
            
            if verbose:
                logging.debug(f"{log_prefix} Testing URL: {current_url}")
            
            # Добавляем повторные попытки
            retry_count = 0
            while retry_count <= MAX_RETRY_COUNT:
                try:
                    # Measure request time
                    start_time = time.time()
                    response = requests.get(current_url, proxies=proxies, headers=headers, timeout=timeout, verify=True)
                    end_time = time.time()
                    
                    # Calculate latency
                    latency_ms = round((end_time - start_time) * 1000)
                    
                    # Check if request was successful
                    response.raise_for_status()  # Raises exception for 4XX/5XX responses
                    
                    # Update URL result with success data
                    url_result["success"] = True
                    url_result["latency_ms"] = latency_ms
                    successful_tests += 1
                    total_latency += latency_ms
                    
                    if verbose:
                        logging.debug(f"{log_prefix} URL test successful: {current_url}, latency: {latency_ms}ms")
                    
                    # Если успешно, прерываем цикл повторных попыток
                    break
                    
                except requests.exceptions.ConnectTimeout as e:
                    # Тайм-аут соединения, можно повторить
                    error_desc = f"Connection timeout after {timeout}s"
                    
                    if retry_count < MAX_RETRY_COUNT:
                        if verbose:
                            logging.debug(f"{log_prefix} URL test timeout, retrying ({retry_count+1}/{MAX_RETRY_COUNT}): {current_url}")
                        retry_count += 1
                        time.sleep(RETRY_DELAY)
                        continue
                    
                    url_result["error"] = f"Request error: {error_desc}"
                    if verbose:
                        logging.debug(f"{log_prefix} URL test failed after {retry_count} retries: {current_url}: {url_result['error']}")
                    
                except requests.exceptions.ReadTimeout as e:
                    # Тайм-аут чтения, можно повторить
                    error_desc = f"Read timeout after {timeout}s"
                    
                    if retry_count < MAX_RETRY_COUNT:
                        if verbose:
                            logging.debug(f"{log_prefix} URL test read timeout, retrying ({retry_count+1}/{MAX_RETRY_COUNT}): {current_url}")
                        retry_count += 1
                        time.sleep(RETRY_DELAY)
                        continue
                    
                    url_result["error"] = f"Request error: {error_desc}"
                    if verbose:
                        logging.debug(f"{log_prefix} URL test failed after {retry_count} retries: {current_url}: {url_result['error']}")
                
                except requests.exceptions.RequestException as e:
                    # Handle request errors
                    error_desc = str(e)
                    if hasattr(e, 'response') and e.response:
                        error_desc = f"HTTP {e.response.status_code}: {error_desc[:100]}"
                    
                    # Определим, следует ли повторить запрос для других типов ошибок
                    retriable_error = isinstance(e, (
                        requests.exceptions.ProxyError,
                        requests.exceptions.ConnectionError
                    ))
                    
                    if retriable_error and retry_count < MAX_RETRY_COUNT:
                        if verbose:
                            logging.debug(f"{log_prefix} URL test error, retrying ({retry_count+1}/{MAX_RETRY_COUNT}): {current_url}: {error_desc}")
                        retry_count += 1
                        time.sleep(RETRY_DELAY)
                        continue
                    
                    url_result["error"] = f"Request error: {error_desc}"
                    if verbose:
                        logging.debug(f"{log_prefix} URL test failed: {current_url}: {url_result['error']}")
                
                except Exception as e:
                    # Handle other errors
                    url_result["error"] = f"Unknown error: {type(e).__name__}: {str(e)}"
                    if verbose:
                        logging.debug(f"{log_prefix} URL test failed: {current_url}: {url_result['error']}")
                
                # Если попали сюда, значит произошла ошибка и повторные попытки не помогли
                break
            
            # Add result for this URL to the list
            result["url_results"].append(url_result)
        
        # Determine overall success based on multiple URL test mode
        if MULTIPLE_URL_MODE == "all":
            # All URLs must have succeeded
            result["success"] = successful_tests == len(test_urls)
        else:  # "any" mode
            # At least one URL must have succeeded
            result["success"] = successful_tests > 0
        
        # Calculate average latency for successful tests
        if successful_tests > 0:
            result["latency_ms"] = round(total_latency / successful_tests)
        
        if verbose:
            if result["success"]:
                logging.debug(f"{log_prefix} Overall URL testing successful: "
                             f"{successful_tests}/{len(test_urls)} URLs passed, avg latency: {result.get('latency_ms', 'N/A')}ms")
            else:
                logging.debug(f"{log_prefix} Overall URL testing failed: "
                             f"only {successful_tests}/{len(test_urls)} URLs passed")
            
    except ValueError as e:
        # Handle parsing/conversion errors
        result["error"] = f"Configuration error: {str(e)}"
        if verbose:
            logging.debug(f"{log_prefix} Failed: {result['error']}")
    except Exception as e:
        # Handle other errors
        result["error"] = f"Unknown error: {type(e).__name__}: {str(e)}"
        if verbose:
            logging.debug(f"{log_prefix} Failed: {result['error']}")
    finally:
        # Cleanup regardless of success or failure
        if proxy_process:
            cleanup_process(proxy_process, verbose)
        if config_file and os.path.exists(config_file):
            cleanup_file(config_file, verbose)
            
    return result

def perform_batch_url_tests(
    configs: List[str],
    test_url: Union[str, List[str]] = DEFAULT_TEST_URLS,
    timeout: float = DEFAULT_TIMEOUT,
    singbox_path: str = "sing-box",
    verbose: bool = False,
    use_http_proxy: bool = False
) -> Dict[str, List[str]]:
    """
    Performs URL tests on a batch of configurations.
    Returns a dictionary with 'working' and 'failed' config lists.
    """
    result = {
        "working": [],
        "failed": []
    }
    
    total = len(configs)
    for i, config in enumerate(configs, 1):
        logging.info(f"Testing config {i}/{total}: {config[:30]}...")
        test_result = perform_url_test(config, test_url, timeout, singbox_path, verbose, use_http_proxy)
        
        if test_result["success"]:
            result["working"].append(config)
            latency = test_result.get("latency_ms", "N/A")
            success_count = sum(1 for ur in test_result.get("url_results", []) if ur.get("success", False))
            total_urls = len(test_result.get("url_results", []))
            logging.info(f"✓ Config {i}/{total} SUCCESS ({success_count}/{total_urls} URLs), avg latency: {latency}ms")
        else:
            result["failed"].append(config)
            success_count = sum(1 for ur in test_result.get("url_results", []) if ur.get("success", False))
            total_urls = len(test_result.get("url_results", []))
            error = test_result.get("error", "Failed URLs")
            logging.info(f"✗ Config {i}/{total} FAILED: ({success_count}/{total_urls} URLs): {error[:100]}")
    
    success_rate = len(result["working"]) / total * 100 if total > 0 else 0
    logging.info(f"URL testing completed: {len(result['working'])}/{total} working ({success_rate:.1f}%)")
    
    return result 