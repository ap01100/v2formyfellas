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
from filter.process_manager import SingBoxProcessManager

# Глобальный экземпляр менеджера процессов
_process_manager = None

def get_process_manager(singbox_path: str, verbose: bool = False) -> SingBoxProcessManager:
    """
    Получить или создать глобальный экземпляр менеджера процессов
    
    Args:
        singbox_path: Путь к исполняемому файлу sing-box
        verbose: Подробный вывод логов
        
    Returns:
        Экземпляр SingBoxProcessManager
    """
    global _process_manager
    if _process_manager is None:
        # Определяем оптимальное количество процессов на основе доступных ресурсов
        import multiprocessing
        max_processes = max(50, multiprocessing.cpu_count() * 5)  # Минимум 50, но может быть больше в зависимости от CPU
        
        _process_manager = SingBoxProcessManager(
            singbox_path=singbox_path,
            max_processes=max_processes,
            idle_timeout=60,  # 1 минута таймаут для неиспользуемых процессов
            verbose=verbose
        )
    return _process_manager

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
    
    # Получаем менеджер процессов
    process_manager = get_process_manager(singbox_path, verbose)
    
    # Получаем или создаем процесс для этой конфигурации
    sing_process = process_manager.get_process(config_str, use_http_proxy)
    
    if not sing_process:
        result["error"] = "Failed to start sing-box process"
        if verbose:
            logging.debug(f"{log_prefix} {result['error']}")
        return result
    
    try:
        # Получаем URL прокси для requests
        proxy_url = sing_process.get_proxy_url(use_http_proxy)
        
        if verbose:
            logging.debug(f"{log_prefix} Using proxy {proxy_url}")
        
        # Настраиваем сессию requests с прокси
        session = requests.Session()
        session.proxies = {
            "http": proxy_url,
            "https": proxy_url
        }
        session.headers.update({"User-Agent": USER_AGENT})
        
        # Тестируем все URL
        successful_tests = 0
        total_latency = 0
        
        for url in test_urls:
            url_result = {
                "url": url,
                "success": False,
                "latency_ms": None,
                "error": None
            }
            
            # Выполняем запрос с повторными попытками
            for retry in range(MAX_RETRY_COUNT + 1):
                try:
                    if verbose and retry > 0:
                        logging.debug(f"{log_prefix} Retry {retry} for {url}")
                    
                    start_time = time.time()
                    response = session.get(url, timeout=timeout, allow_redirects=True)
                    end_time = time.time()
                    
                    # Проверяем успешность запроса
                    response.raise_for_status()
                    
                    # Запрос успешен
                    latency_ms = round((end_time - start_time) * 1000)
                    url_result["success"] = True
                    url_result["latency_ms"] = latency_ms
                    
                    if verbose:
                        logging.debug(f"{log_prefix} Successfully tested {url} in {latency_ms}ms")
                    
                    successful_tests += 1
                    total_latency += latency_ms
                    break
                    
                except requests.exceptions.RequestException as e:
                    # Обрабатываем ошибки запроса
                    error_type = type(e).__name__
                    error_msg = str(e)
                    
                    # Сокращаем сообщение об ошибке, если оно слишком длинное
                    if len(error_msg) > 100:
                        error_msg = error_msg[:100] + "..."
                    
                    url_result["error"] = f"{error_type}: {error_msg}"
                    
                    if verbose:
                        logging.debug(f"{log_prefix} Error testing {url}: {url_result['error']}")
                    
                    # Если это не последняя попытка, ждем перед повторной попыткой
                    if retry < MAX_RETRY_COUNT:
                        time.sleep(RETRY_DELAY)
                    else:
                        if verbose:
                            logging.debug(f"{log_prefix} Max retries reached for {url}")
            
            # Добавляем результат для этого URL
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
        # Отмечаем процесс как неиспользуемый (он будет завершен автоматически через idle_timeout)
        process_manager.release_process(config_str)
            
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

def shutdown_process_manager():
    """
    Завершить работу менеджера процессов.
    Должно быть вызвано перед завершением программы.
    """
    global _process_manager
    if _process_manager:
        _process_manager.shutdown()
        _process_manager = None 