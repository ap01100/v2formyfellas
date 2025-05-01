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
from typing import List, Dict, Any

# Import modules
from config import (
    DEFAULT_TEST_URL, DEFAULT_TIMEOUT, DEFAULT_WORKERS,
    DEFAULT_TCP_TEST_HOST, DEFAULT_TCP_TEST_PORT, DEFAULT_TCP_TIMEOUT,
    DEFAULT_IP_SERVICE_URL, DEFAULT_IP_SERVICE_TIMEOUT, DEFAULT_WORKERS_ADVANCED,
    SINGBOX_EXECUTABLE
)
from utils import (
    check_ubuntu_compatibility, ensure_executable_permissions, remove_duplicates,
    ensure_workfiles_dir, cleanup_all_temp_files
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
    test_url: str,
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
        test_url: URL to test with
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
        default=DEFAULT_TEST_URL,
        help="URL to test proxies against"
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
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.verbose)
    
    # Create workfiles directory
    ensure_workfiles_dir()
    logging.info("Initialized workfiles directory for temporary files")
    
    # Check compatibility and sing-box
    check_ubuntu_compatibility()
    if not ensure_executable_permissions(args.singbox_path):
        logging.error(f"Cannot ensure executable permissions for sing-box at {args.singbox_path}")
        sys.exit(1)
    
    # Read configurations
    configs = read_configs_from_file(args.input_file)
    
    # Deduplicate configurations
    if not args.no_dedup:
        configs = remove_duplicates(configs)
    
    # Determine test mode and workers
    if args.url_then_advanced:
        # Run URL testing first
        logging.info(f"Running URL testing on {len(configs)} configurations...")
        url_results = test_configs(
            configs,
            args.singbox_path,
            args.url,
            args.timeout,
            args.workers,
            args.verbose,
            advanced_test=False
        )
        
        # Save intermediate results if temp_file specified
        if args.temp_file:
            write_configs_to_file(url_results["working"], args.temp_file)
            logging.info(f"Saved {len(url_results['working'])} working configurations from URL testing to {args.temp_file}")
        
        # Run advanced testing on working configs
        logging.info(f"Running advanced testing on {len(url_results['working'])} configurations that passed URL testing...")
        workers = args.advanced_workers if args.advanced_workers else args.workers
        final_results = test_configs(
            url_results["working"],
            args.singbox_path,
            args.url,
            args.timeout,
            workers,
            args.verbose,
            advanced_test=True,
            tcp_host=args.tcp_host,
            tcp_port=args.tcp_port,
            tcp_timeout=args.tcp_timeout,
            ip_service_url=args.ip_service_url,
            ip_service_timeout=args.ip_service_timeout
        )
        working_configs = final_results["working"]
        
    elif args.advanced:
        # Run advanced testing only
        logging.info(f"Running advanced testing on {len(configs)} configurations...")
        workers = args.advanced_workers if args.advanced_workers else args.workers
        results = test_configs(
            configs,
            args.singbox_path,
            args.url,
            args.timeout,
            workers,
            args.verbose,
            advanced_test=True,
            tcp_host=args.tcp_host,
            tcp_port=args.tcp_port,
            tcp_timeout=args.tcp_timeout,
            ip_service_url=args.ip_service_url,
            ip_service_timeout=args.ip_service_timeout
        )
        working_configs = results["working"]
        
    else:
        # Run URL testing only
        logging.info(f"Running URL testing on {len(configs)} configurations...")
        results = test_configs(
            configs,
            args.singbox_path,
            args.url,
            args.timeout,
            args.workers,
            args.verbose,
            advanced_test=False
        )
        working_configs = results["working"]
    
    # Save results
    if args.output_file:
        write_configs_to_file(working_configs, args.output_file)
        
    if args.append_output:
        # Read existing configs first if file exists
        existing_configs = []
        if os.path.exists(args.append_output):
            try:
                with open(args.append_output, 'r', encoding='utf-8') as f:
                    existing_configs = [line.strip() for line in f.readlines() if line.strip()]
            except Exception as e:
                logging.error(f"Error reading {args.append_output} for appending: {e}")
        
        # Combine and deduplicate
        combined = existing_configs + working_configs
        unique_combined = remove_duplicates(combined)
        
        # Write back
        write_configs_to_file(unique_combined, args.append_output)
        
        added_count = len(unique_combined) - len(existing_configs)
        logging.info(f"Added {added_count} new working configurations to {args.append_output}")
    
    # Print summary
    success_rate = len(working_configs) / len(configs) * 100 if configs else 0
    logging.info(f"Testing completed: {len(working_configs)}/{len(configs)} working configurations ({success_rate:.1f}%)")
    
    # Clean up any remaining temp files
    cleanup_all_temp_files()
    logging.debug("Cleaned up all temporary files")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())