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
from typing import Dict, Any, Optional, List

from config import DEFAULT_TEST_URL, DEFAULT_TIMEOUT, USER_AGENT
from utils import find_free_port, cleanup_process, cleanup_file, wait_for_port
from parsers import convert_to_singbox_config

def perform_url_test(config_str: str, test_url: str, timeout: float, singbox_path: str, verbose: bool) -> Dict[str, Any]:
    """
    Performs a URL test for a single proxy configuration.
    Sets up sing-box, makes an HTTP request through the proxy, and measures success and latency.
    Returns a dict with test results.
    """
    # Initialize test result dictionary
    result = {
        "success": False,
        "latency_ms": None,
        "error": None,
        "config": config_str
    }
    
    socks_port = None
    config_file = None
    proxy_process = None
    
    try:
        # 1. Find free port and generate sing-box config
        socks_port = find_free_port()
        log_level = "debug" if verbose else "warn"
        singbox_config = convert_to_singbox_config(config_str, socks_port, log_level)
        
        # 2. Write config to temp file
        with open(f"temp_{socks_port}.json", "w", encoding="utf-8") as tmp:
            json.dump(singbox_config, tmp)
            config_file = tmp.name
            
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
        
        # 5. Make HTTP request through proxy
        proxies = {
            "http": f"socks5h://127.0.0.1:{socks_port}",
            "https": f"socks5h://127.0.0.1:{socks_port}"
        }
        headers = {"User-Agent": USER_AGENT}
        
        # Measure request time
        start_time = time.time()
        response = requests.get(test_url, proxies=proxies, headers=headers, timeout=timeout, verify=True)
        end_time = time.time()
        
        # Calculate latency
        latency_ms = round((end_time - start_time) * 1000)
        
        # Check if request was successful
        response.raise_for_status()  # Raises exception for 4XX/5XX responses
        
        # Update result with success data
        result["success"] = True
        result["latency_ms"] = latency_ms
        
        if verbose:
            logging.debug(f"URL test successful: {config_str[:30]}... -> {test_url}, latency: {latency_ms}ms")
            
    except requests.exceptions.RequestException as e:
        # Handle request errors
        error_desc = str(e)
        if hasattr(e, 'response') and e.response:
            error_desc = f"HTTP {e.response.status_code}: {error_desc[:100]}"
        result["error"] = f"Request error: {error_desc}"
        logging.debug(f"URL test failed: {config_str[:30]}... -> {result['error']}")
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
    test_url: str = DEFAULT_TEST_URL,
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
            logging.info(f"✓ Config {i}/{total} SUCCESS, latency: {latency}ms")
        else:
            result["failed"].append(config)
            error = test_result.get("error", "Unknown error")
            logging.info(f"✗ Config {i}/{total} FAILED: {error[:100]}")
    
    success_rate = len(result["working"]) / total * 100 if total > 0 else 0
    logging.info(f"URL testing completed: {len(result['working'])}/{total} working ({success_rate:.1f}%)")
    
    return result 