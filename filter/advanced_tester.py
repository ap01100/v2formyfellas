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
from typing import Dict, Any, Optional, Tuple, List

from config import (
    DEFAULT_TCP_TEST_HOST, DEFAULT_TCP_TEST_PORT, DEFAULT_TCP_TIMEOUT,
    DEFAULT_IP_SERVICE_URL, DEFAULT_IP_SERVICE_TIMEOUT
)
from utils import find_free_port, cleanup_process, cleanup_file, wait_for_port, get_temp_file_path
from parsers import convert_to_singbox_config, parse_ss_config, parse_trojan_config, parse_vmess_config, parse_vless_config

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
    Uses netcat (nc) for testing.
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
                except Exception:
                    pass  # Ignore read errors as process already crashed
                
                error_msg = f"sing-box failed to start (code {proxy_process.poll()}). Stderr: {stderr_output}"
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

        # 5. TCP connection attempt through proxy using netcat
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
            error_msg = "Command 'nc' (netcat) not found. TCP test failed."
            logging.error(f"{log_prefix} {error_msg}")  # Critical error for this function
            return False, None, error_msg
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

def get_outbound_ip(
    config_str: str,
    singbox_path: str,
    ip_service_url: str,
    timeout: float,
    verbose: bool
) -> Tuple[Optional[str], Optional[str]]:
    """
    Determines the outbound IP address using the proxy and an external service.
    Returns (outbound_ip, error_message).
    """
    log_prefix = f"OutIP[{config_str[:25]}...]"
    logging.debug(f"{log_prefix} Requesting {ip_service_url}...")

    socks_port: Optional[int] = None
    config_file: Optional[str] = None
    proxy_process: Optional[subprocess.Popen] = None
    session = None  # For requests

    try:
        # 1. Preparation: port, config, start sing-box (similar to TCP test)
        socks_port = find_free_port()
        local_proxy = f"socks5h://127.0.0.1:{socks_port}"  # Use socks5h for DNS via proxy
        log_level = "debug" if verbose else "warn"
        singbox_config = convert_to_singbox_config(config_str, socks_port, log_level)

        # Write config to temp file in workfiles directory
        config_file = get_temp_file_path("temp_ip", socks_port)
        with open(config_file, "w", encoding="utf-8") as tmp:
            json.dump(singbox_config, tmp)
        logging.debug(f"{log_prefix} sing-box config written to {config_file}")

        cmd = [singbox_path, "run", "-c", config_file]
        proxy_process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
        )

        # Wait for sing-box to start
        if not wait_for_port("127.0.0.1", socks_port, timeout=10):
            error_msg = f"Timeout waiting for sing-box to start on port {socks_port}"
            logging.warning(f"{log_prefix} {error_msg}")
            cleanup_process(proxy_process, verbose)
            return None, error_msg

        # 2. Make request to IP service through proxy
        try:
            # Import requests here so import error is handled below
            import requests
            session = requests.Session()
            session.proxies = {"http": local_proxy, "https": local_proxy}
            # Add User-Agent, some services might require it
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36'}

            logging.debug(f"{log_prefix} Performing GET request to {ip_service_url} via {local_proxy}...")
            response = session.get(ip_service_url, timeout=timeout, headers=headers)
            response.raise_for_status()  # Check for HTTP errors (4xx, 5xx)

            ip_data = response.json()
            outbound_ip = ip_data.get("ip")

            if outbound_ip and isinstance(outbound_ip, str):
                logging.debug(f"{log_prefix} Successfully got Outbound IP: {outbound_ip}")
                return outbound_ip, None
            else:
                error_msg = f"Could not extract IP from service response: {str(ip_data)[:100]}"
                logging.warning(f"{log_prefix} {error_msg}")
                return None, error_msg

        except ImportError:
            error_msg = "Module 'requests' not found. Unable to determine Outbound IP."
            logging.error(error_msg)  # Critical error for this function
            return None, error_msg
        except requests.exceptions.Timeout:
            error_msg = f"Timeout ({timeout} sec) requesting IP service"
            logging.warning(f"{log_prefix} {error_msg}")
            return None, error_msg
        except requests.exceptions.ProxyError as e:
            # SOCKS error (e.g., sing-box crashed or can't connect further)
            error_msg = f"Proxy error requesting IP service: {str(e)[:150]}"
            logging.warning(f"{log_prefix} {error_msg}")
            return None, error_msg
        except requests.exceptions.RequestException as e:
            # Other requests errors (DNS, Connection Error, etc.)
            error_msg = f"Error requesting IP service: {type(e).__name__} - {str(e)[:150]}"
            logging.warning(f"{log_prefix} {error_msg}")
            return None, error_msg
        except json.JSONDecodeError:
            # Service returned non-JSON
            error_msg = f"Error decoding JSON from IP service: {response.text[:100]}"
            logging.warning(f"{log_prefix} {error_msg}")
            return None, error_msg
        except Exception as e:
            # Unexpected error
            error_msg = f"Unexpected error requesting IP service: {type(e).__name__}: {str(e)[:100]}"
            logging.error(f"{log_prefix} {error_msg}", exc_info=verbose)
            return None, error_msg
        finally:
            if session:
                try:
                    session.close()  # Close requests session
                except Exception:
                    pass

    except ValueError as e:  # Parsing/conversion error
        error_msg = f"Preparation error: {e}"
        logging.error(f"{log_prefix} {error_msg}")
        return None, error_msg
    except Exception as e:  # General errors (starting sing-box, writing file)
        error_msg = f"General Outbound IP test error: {type(e).__name__}: {str(e)[:100]}"
        logging.error(f"{log_prefix} {error_msg}", exc_info=verbose)
        return None, error_msg
    finally:
        # Cleanup: terminate sing-box and remove temp config
        logging.debug(f"{log_prefix} Cleaning up Outbound IP test resources...")
        cleanup_process(proxy_process, verbose)
        cleanup_file(config_file)
        logging.debug(f"{log_prefix} Outbound IP test cleanup completed.")

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
    Performs all advanced tests for a single configuration.
    Returns a dictionary with test results.
    """
    log_prefix = f"AdvTest[{config_str[:25]}...]"
    logging.info(f"{log_prefix} Starting advanced tests...")

    results = {
        "config": config_str,
        "inbound_ip": None,
        "tcp_success": False,
        "tcp_latency_ms": None,
        "outbound_ip": None,
        "overall_success": False,  # Whether all tests passed
        "error": None  # General error if something went wrong
    }

    # 1. Get Inbound IP (this doesn't affect overall_success)
    results["inbound_ip"] = get_inbound_ip(config_str)
    if not results["inbound_ip"]:
        logging.warning(f"{log_prefix} Could not get Inbound IP.")
        # Don't break test, Inbound IP is informational

    # 2. Perform TCP Ping/Latency test
    tcp_success, tcp_latency, tcp_error = tcp_ping_latency_test(
        config_str, tcp_host, tcp_port, singbox_path, tcp_timeout, verbose
    )
    results["tcp_success"] = tcp_success
    results["tcp_latency_ms"] = tcp_latency
    if not tcp_success:
        results["error"] = f"TCP Test: {tcp_error or 'Unknown error'}"
        logging.warning(f"{log_prefix} {results['error']}")
        # If TCP test failed, no point doing Outbound IP test
        logging.info(f"{log_prefix} -> Final status: FAILED ({results['error']})")
        return results  # Return result without Outbound IP test

    # 3. Determine Outbound IP
    outbound_ip, ip_error = get_outbound_ip(
        config_str, singbox_path, ip_service_url, ip_service_timeout, verbose
    )
    results["outbound_ip"] = outbound_ip
    if not outbound_ip:
        results["error"] = f"Outbound IP Test: {ip_error or 'Unknown error'}"
        logging.warning(f"{log_prefix} {results['error']}")
        # If Outbound IP not obtained, consider test failed
        logging.info(f"{log_prefix} -> Final status: FAILED ({results['error']})")
        return results

    # 4. If all tests passed
    results["overall_success"] = True
    logging.info(f"{log_prefix} -> Final status: SUCCESS (TCP Latency: {tcp_latency}ms, Outbound IP: {outbound_ip})")
    return results

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
        
        if test_result["overall_success"]:
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