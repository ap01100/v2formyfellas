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

from config import DEFAULT_TEST_URLS, DEFAULT_TIMEOUT, USER_AGENT, MULTIPLE_URL_MODE
from utils import find_free_port, cleanup_process, cleanup_file, wait_for_port, get_temp_file_path
from parsers import convert_to_singbox_config

def perform_url_test(config_str: str, test_url: Union[str, List[str]], timeout: float, singbox_path: str, verbose: bool) -> Dict[str, Any]:
    """
    Performs a URL test for a single proxy configuration.
    Sets up sing-box, makes an HTTP request through the proxy, and measures success and latency.
    If test_url is a list, tests all URLs in the list.
    Returns a dict with test results.
    """
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
        log_level = "debug" if verbose else "warn"
        singbox_config = convert_to_singbox_config(config_str, socks_port, log_level)
        
        # 2. Write config to temp file in workfiles directory
        config_file = get_temp_file_path("temp", socks_port)
        with open(config_file, "w", encoding="utf-8") as tmp:
            json.dump(singbox_config, tmp)
            
        # 3. Start sing-box
        cmd = [singbox_path, "run", "-c", config_file]
        proxy_process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
        )
        
        # 4. Wait for sing-box to start
        if not wait_for_port("127.0.0.1", socks_port):
            result["error"] = f"Timeout waiting for sing-box to start on port {socks_port}"
            return result
        
        # 5. Setup proxies and headers for requests
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
                    logging.debug(f"URL test successful: {config_str[:30]}... -> {current_url}, latency: {latency_ms}ms")
                    
            except requests.exceptions.RequestException as e:
                # Handle request errors
                error_desc = str(e)
                if hasattr(e, 'response') and e.response:
                    error_desc = f"HTTP {e.response.status_code}: {error_desc[:100]}"
                url_result["error"] = f"Request error: {error_desc}"
                if verbose:
                    logging.debug(f"URL test failed: {config_str[:30]}... -> {current_url}: {url_result['error']}")
            except Exception as e:
                # Handle other errors
                url_result["error"] = f"Unknown error: {type(e).__name__}: {str(e)}"
                if verbose:
                    logging.debug(f"URL test failed: {config_str[:30]}... -> {current_url}: {url_result['error']}")
            
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
                logging.debug(f"Overall URL testing successful: {config_str[:30]}..., "
                             f"{successful_tests}/{len(test_urls)} URLs passed, avg latency: {result['latency_ms']}ms")
            else:
                logging.debug(f"Overall URL testing failed: {config_str[:30]}..., "
                             f"only {successful_tests}/{len(test_urls)} URLs passed")
            
    except ValueError as e:
        # Handle parsing/conversion errors
        result["error"] = f"Configuration error: {str(e)}"
        logging.debug(f"URL test failed: {config_str[:30]}... -> {result['error']}")
    except Exception as e:
        # Handle other errors
        result["error"] = f"Unknown error: {type(e).__name__}: {str(e)}"
        logging.debug(f"URL test failed: {config_str[:30]}... -> {result['error']}")
    finally:
        # Clean up
        cleanup_process(proxy_process, verbose)
        cleanup_file(config_file)
        
    return result

def perform_batch_url_tests(
    configs: List[str],
    test_url: Union[str, List[str]] = DEFAULT_TEST_URLS,
    timeout: float = DEFAULT_TIMEOUT,
    singbox_path: str = "sing-box",
    verbose: bool = False
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
        test_result = perform_url_test(config, test_url, timeout, singbox_path, verbose)
        
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