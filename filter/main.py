#!/usr/bin/env python3
"""
Main script for proxy configuration testing.
Combines functionality of both url_test.py and advanced_test.py.
"""

import os
import sys
import json
import logging
import argparse
from pathlib import Path
from typing import List, Dict, Any, Union

# Import modules
from config import (
    DEFAULT_TEST_URLS, DEFAULT_TIMEOUT, DEFAULT_WORKERS,
    DEFAULT_TCP_TEST_HOST, DEFAULT_TCP_TEST_PORT, DEFAULT_TCP_TIMEOUT,
    DEFAULT_IP_SERVICE_URL, DEFAULT_IP_SERVICE_TIMEOUT, DEFAULT_WORKERS_ADVANCED,
    SINGBOX_EXECUTABLE, MULTIPLE_URL_MODE
)
from utils import (
    check_ubuntu_compatibility, ensure_executable_permissions, remove_duplicates,
    ensure_workfiles_dir, cleanup_all_temp_files, remove_duplicates_advanced
)
from url_tester import perform_url_test
from advanced_tester import perform_advanced_test
from parallel import run_url_tests_parallel, run_advanced_tests_parallel

def setup_logging(verbose: bool = False):
    """Configure logging based on verbosity."""
    log_level = logging.DEBUG if verbose else logging.INFO
    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    logging.basicConfig(level=log_level, format=log_format)

def read_configs_from_file(file_path: str) -> List[str]:
    """Read proxy configurations from a file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            # Read non-empty lines that don't start with #
            configs = [line.strip() for line in f.readlines() if line.strip() and not line.strip().startswith('#')]
        logging.info(f"Read {len(configs)} configurations from {file_path}")
        return configs
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Error reading file {file_path}: {e}")
        sys.exit(1)

def read_urls_from_file(file_path: str) -> List[str]:
    """Read URLs from a file, one URL per line."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            # Read non-empty lines that don't start with #
            urls = [line.strip() for line in f.readlines() if line.strip() and not line.strip().startswith('#')]
        logging.info(f"Read {len(urls)} URLs from {file_path}")
        return urls
    except FileNotFoundError:
        logging.error(f"URL file not found: {file_path}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Error reading URL file {file_path}: {e}")
        sys.exit(1)

def write_configs_to_file(configs: List[str], file_path: str):
    """Write proxy configurations to a file."""
    try:
        os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
        with open(file_path, 'w', encoding='utf-8') as f:
            for config in configs:
                f.write(f"{config}\n")
        logging.info(f"Wrote {len(configs)} configurations to {file_path}")
    except Exception as e:
        logging.error(f"Error writing to file {file_path}: {e}")
        sys.exit(1)

def test_configs(
    configs: List[str],
    singbox_path: str,
    test_url: Union[str, List[str]],
    timeout: float,
    workers: int,
    verbose: bool,
    advanced_test: bool = False,
    tcp_host: str = DEFAULT_TCP_TEST_HOST,
    tcp_port: int = DEFAULT_TCP_TEST_PORT,
    tcp_timeout: float = DEFAULT_TCP_TIMEOUT,
    ip_service_url: str = DEFAULT_IP_SERVICE_URL,
    ip_service_timeout: float = DEFAULT_IP_SERVICE_TIMEOUT
) -> Dict[str, List[str]]:
    """
    Test configurations using either basic URL testing or advanced testing.
    
    Args:
        configs: List of proxy configuration strings
        singbox_path: Path to sing-box executable
        test_url: URL or list of URLs to test with
        timeout: Test timeout in seconds
        workers: Number of parallel workers
        verbose: Enable verbose logging
        advanced_test: Use advanced testing (TCP, IP) instead of URL testing
        tcp_host: Host for TCP tests (advanced only)
        tcp_port: Port for TCP tests (advanced only)
        tcp_timeout: Timeout for TCP tests (advanced only)
        ip_service_url: URL for IP service (advanced only)
        ip_service_timeout: Timeout for IP service (advanced only)
        
    Returns:
        Dict with 'working' and 'failed' lists
    """
    if advanced_test:
        return run_advanced_tests_parallel(
            configs,
            perform_advanced_test,
            max_workers=workers,
            singbox_path=singbox_path,
            tcp_host=tcp_host,
            tcp_port=tcp_port,
            tcp_timeout=tcp_timeout,
            ip_service_url=ip_service_url,
            ip_service_timeout=ip_service_timeout,
            verbose=verbose
        )
    else:
        return run_url_tests_parallel(
            configs,
            perform_url_test,
            max_workers=workers,
            test_url=test_url,
            timeout=timeout,
            singbox_path=singbox_path,
            verbose=verbose
        )

def main():
    parser = argparse.ArgumentParser(
        description="Test proxy configurations using URL testing and advanced testing.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # Input/output arguments
    parser.add_argument(
        "input_file",
        help="File containing proxy configurations to test"
    )
    parser.add_argument(
        "-o", "--output-file",
        help="File to save working configurations"
    )
    parser.add_argument(
        "-ao", "--append-output",
        help="Append working configurations to this file instead of overwriting"
    )
    
    # Testing options
    parser.add_argument(
        "-u", "--url",
        action="append",
        help="URL to test proxies against (can be specified multiple times)"
    )
    parser.add_argument(
        "--urls-file",
        help="Path to a file containing URLs to test, one URL per line"
    )
    parser.add_argument(
        "--url-mode",
        choices=["all", "any"],
        default=MULTIPLE_URL_MODE,
        help="URL testing mode: 'all' means all URLs must work, 'any' means at least one URL must work"
    )
    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help="Request timeout in seconds"
    )
    parser.add_argument(
        "-w", "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help="Number of concurrent testing workers"
    )
    
    # Advanced testing options
    parser.add_argument(
        "-a", "--advanced",
        action="store_true",
        help="Perform advanced tests (TCP, IP) on configurations"
    )
    parser.add_argument(
        "--tcp-host",
        default=DEFAULT_TCP_TEST_HOST,
        help="Host for TCP tests in advanced mode"
    )
    parser.add_argument(
        "--tcp-port",
        type=int,
        default=DEFAULT_TCP_TEST_PORT,
        help="Port for TCP tests in advanced mode"
    )
    parser.add_argument(
        "--tcp-timeout",
        type=float,
        default=DEFAULT_TCP_TIMEOUT,
        help="Timeout for TCP tests in advanced mode"
    )
    parser.add_argument(
        "--ip-service-url",
        default=DEFAULT_IP_SERVICE_URL,
        help="URL for IP detection service in advanced mode"
    )
    parser.add_argument(
        "--ip-service-timeout",
        type=float,
        default=DEFAULT_IP_SERVICE_TIMEOUT,
        help="Timeout for IP service requests in advanced mode"
    )
    parser.add_argument(
        "--advanced-workers",
        type=int,
        default=DEFAULT_WORKERS_ADVANCED,
        help="Number of concurrent workers for advanced testing"
    )
    
    # System options
    parser.add_argument(
        "--singbox-path",
        default=SINGBOX_EXECUTABLE,
        help="Path to sing-box executable"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging (DEBUG level)"
    )
    parser.add_argument(
        "--no-dedup",
        action="store_true",
        help="Skip deduplication of input configurations"
    )
    
    parser.add_argument(
        "--advanced-dedup",
        action="store_true",
        help="Use advanced deduplication (ignores configuration names during comparison)"
    )
    
    # Pipeline options
    parser.add_argument(
        "--url-then-advanced",
        action="store_true",
        help="Run URL testing first, then advanced testing on working configs"
    )
    parser.add_argument(
        "--temp-file",
        help="Temporary file to store intermediate results from URL testing"
    )
    
    # Parse arguments
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.verbose)
    
    # Create workfiles directory if it doesn't exist
    ensure_workfiles_dir()
    
    # Set testing URLs
    test_urls = []
    
    # Read URLs from file if specified
    if args.urls_file:
        file_urls = read_urls_from_file(args.urls_file)
        if file_urls:
            test_urls.extend(file_urls)
            logging.info(f"Loaded {len(file_urls)} URLs from {args.urls_file}")
    
    # Add URLs specified directly in command line
    if args.url:
        test_urls.extend(args.url)
    
    # If no URLs were specified, use default
    if not test_urls:
        test_urls = DEFAULT_TEST_URLS
    
    # If URL mode is different from default, set it in the config module
    if args.url_mode != MULTIPLE_URL_MODE:
        import config
        config.MULTIPLE_URL_MODE = args.url_mode
        logging.info(f"URL testing mode set to: {args.url_mode}")
    
    logging.info(f"Testing URLs: {', '.join(test_urls)}")
    
    # Find sing-box executable
    singbox_path = args.singbox_path or SINGBOX_EXECUTABLE
    ensure_executable_permissions(singbox_path)
    
    # Check system compatibility
    # Only on Linux systems
    if sys.platform.startswith('linux'):
        check_ubuntu_compatibility()
    
    # Read configs from file
    configs = read_configs_from_file(args.input_file)
    logging.info(f"Loaded {len(configs)} configurations from {args.input_file}")
    
    # Remove duplicates
    old_count = len(configs)
    configs = remove_duplicates(configs)
    if old_count != len(configs):
        logging.info(f"Removed {old_count - len(configs)} duplicate configurations, {len(configs)} remain")
    
    # Choose the appropriate number of workers
    workers = args.workers
    if args.advanced:
        workers = args.advanced_workers
    
    # Run the tests
    if args.advanced:
        logging.info(f"Starting advanced testing using {workers} workers")
        results = test_configs(
            configs=configs,
            singbox_path=singbox_path,
            test_url=test_urls,  # Changed from test_url to test_urls
            timeout=args.timeout,
            workers=workers,
            verbose=args.verbose,
            advanced_test=True,
            tcp_host=args.tcp_host,
            tcp_port=args.tcp_port,
            tcp_timeout=args.tcp_timeout,
            ip_service_url=args.ip_service_url,
            ip_service_timeout=args.ip_service_timeout
        )
    else:
        logging.info(f"Starting URL testing using {workers} workers")
        results = test_configs(
            configs=configs,
            singbox_path=singbox_path,
            test_url=test_urls,  # Changed from test_url to test_urls
            timeout=args.timeout,
            workers=workers,
            verbose=args.verbose
        )
    
    # Calculate and display results
    working_configs = results["working"]
    failed_configs = results["failed"]
    
    logging.info(f"Results: {len(working_configs)} working, {len(failed_configs)} failed")
    
    # If there are working configs and output file specified, save them
    if working_configs and args.output_file:
        write_configs_to_file(working_configs, args.output_file)
        
    # If append output option specified, append working configs
    if working_configs and args.append_output:
        # First try to read existing configs
        try:
            existing_configs = read_configs_from_file(args.append_output)
        except:
            existing_configs = []
            
        # Combine and deduplicate
        combined = existing_configs + working_configs
        combined = remove_duplicates(combined)
        
        # Write back
        write_configs_to_file(combined, args.append_output)
        logging.info(f"Appended {len(working_configs)} working configs to {args.append_output}, now contains {len(combined)} configs")
    
    # Clean up temporary files
    cleanup_all_temp_files()
    
    # Return success if at least one config worked
    return 0 if working_configs else 1

if __name__ == "__main__":
    sys.exit(main())