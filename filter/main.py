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
import signal
from pathlib import Path
from typing import List, Dict, Any, Union

# Import modules
from filter.config import (
    DEFAULT_TEST_URLS, DEFAULT_TIMEOUT, DEFAULT_WORKERS,
    DEFAULT_TCP_TEST_HOST, DEFAULT_TCP_TEST_PORT, DEFAULT_TCP_TIMEOUT,
    DEFAULT_IP_SERVICE_URL, DEFAULT_IP_SERVICE_TIMEOUT, DEFAULT_WORKERS_ADVANCED,
    SINGBOX_EXECUTABLE, MULTIPLE_URL_MODE
)
from filter.utils import (
    check_ubuntu_compatibility, ensure_executable_permissions, remove_duplicates,
    ensure_workfiles_dir, cleanup_all_temp_files, remove_duplicates_advanced,
    find_singbox_executable, ensure_directory
)
from filter.url_tester import perform_url_test, shutdown_process_manager
from filter.advanced_tester import perform_advanced_test
from filter.parallel import run_url_tests_parallel, run_advanced_tests_parallel

def setup_logging(verbose: bool = False):
    """Configure logging based on verbosity."""
    log_level = logging.DEBUG if verbose else logging.INFO
    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    
    # Сбрасываем предыдущие настройки логирования
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)
        
    # Настраиваем вывод в консоль
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_handler.setFormatter(logging.Formatter(log_format))
    
    # Настраиваем корневой логгер
    logging.root.setLevel(log_level)
    logging.root.addHandler(console_handler)
    
    if verbose:
        logging.debug("Debug logging enabled")

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
    ip_service_timeout: float = DEFAULT_IP_SERVICE_TIMEOUT,
    use_http_proxy: bool = False
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
        use_http_proxy: Use HTTP proxy instead of SOCKS5 proxy
        
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
            verbose=verbose,
            use_http_proxy=use_http_proxy
        )

def save_configs(configs: List[str], output_file: str, append: bool = False):
    """Save configurations to a file."""
    mode = 'a' if append else 'w'
    try:
        with open(output_file, mode, encoding='utf-8') as f:
            for config in configs:
                f.write(f"{config}\n")
        logging.info(f"Saved {len(configs)} configurations to {output_file}")
    except Exception as e:
        logging.error(f"Error saving configurations to {output_file}: {e}")
        sys.exit(1)

def setup_signal_handlers():
    """Setup signal handlers for graceful shutdown."""
    def signal_handler(sig, frame):
        logging.info("Interrupted by user. Cleaning up...")
        cleanup_all_temp_files()
        shutdown_process_manager()  # Завершаем работу менеджера процессов
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

def main():
    """Main function."""
    # Setup signal handlers
    setup_signal_handlers()
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="Test proxy configurations",
        epilog="Note: Testing can be interrupted at any time by pressing Ctrl+C. All temporary files will be cleaned up.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # Required arguments
    parser.add_argument("input_file", help="File with proxy configurations to test")
    
    # Output options
    parser.add_argument("-o", "--output-file", help="File to save working configurations to")
    parser.add_argument("-ao", "--append-output", help="Append working configurations to this file")
    
    # URL testing options
    parser.add_argument("-u", "--url", action="append", help="URL to test (can be specified multiple times)")
    parser.add_argument("--urls-file", help="File with URLs to test, one URL per line")
    parser.add_argument("--url-mode", choices=["all", "any"], default=MULTIPLE_URL_MODE,
                        help="URL testing mode: 'all' requires all URLs to be accessible, 'any' requires at least one")
    parser.add_argument("-t", "--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help="Timeout for URL tests in seconds")
    
    # Advanced testing options
    parser.add_argument("-a", "--advanced", action="store_true",
                        help="Perform advanced testing (TCP, IP) instead of URL testing")
    parser.add_argument("--tcp-host", default=DEFAULT_TCP_TEST_HOST,
                        help="Host for TCP tests (advanced only)")
    parser.add_argument("--tcp-port", type=int, default=DEFAULT_TCP_TEST_PORT,
                        help="Port for TCP tests (advanced only)")
    parser.add_argument("--tcp-timeout", type=float, default=DEFAULT_TCP_TIMEOUT,
                        help="Timeout for TCP tests in seconds (advanced only)")
    parser.add_argument("--ip-service-url", default=DEFAULT_IP_SERVICE_URL,
                        help="URL for IP service (advanced only)")
    parser.add_argument("--ip-service-timeout", type=float, default=DEFAULT_IP_SERVICE_TIMEOUT,
                        help="Timeout for IP service in seconds (advanced only)")
    
    # Performance options
    parser.add_argument("-w", "--workers", type=int, default=DEFAULT_WORKERS,
                        help="Number of parallel workers for URL testing")
    parser.add_argument("--advanced-workers", type=int, default=DEFAULT_WORKERS_ADVANCED,
                        help="Number of parallel workers for advanced testing")
    
    # System options
    parser.add_argument("--singbox-path", help="Path to sing-box executable")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    # Additional options
    parser.add_argument(
        "--no-dedup",
        action="store_true",
        help="Skip deduplication of configurations"
    )
    parser.add_argument(
        "--advanced-dedup",
        action="store_true",
        help="Use advanced deduplication (slower but more accurate)"
    )
    parser.add_argument(
        "--url-then-advanced",
        action="store_true",
        help="First perform URL testing, then advanced testing on working configs"
    )
    parser.add_argument(
        "--temp-file",
        help="Temporary file for URL testing results when using --url-then-advanced"
    )
    parser.add_argument(
        "--use-http-proxy", 
        action="store_true",
        help="Use HTTP proxy instead of SOCKS5 proxy"
    )
    
    args = parser.parse_args()
    
    # Configure logging
    setup_logging(args.verbose)
    
    # Create workfiles directory if it doesn't exist
    ensure_workfiles_dir()
    
    # Auto-detect sing-box executable if not specified
    singbox_path = args.singbox_path or find_singbox_executable() or SINGBOX_EXECUTABLE
    if not os.path.isfile(singbox_path):
        logging.error(f"sing-box executable not found at {singbox_path}")
        logging.error("Please specify the correct path with --singbox-path or install sing-box")
        return 1
    
    # Ensure sing-box is executable (on Unix)
    ensure_executable_permissions(singbox_path)
    logging.info(f"Using sing-box executable: {singbox_path}")
    
    # Read configurations from input file
    configs = read_configs_from_file(args.input_file)
    
    # Deduplicate configurations if needed
    if not args.no_dedup:
        original_count = len(configs)
        if args.advanced_dedup:
            configs = remove_duplicates_advanced(configs)
        else:
            configs = remove_duplicates(configs)
        logging.info(f"Removed {original_count - len(configs)} duplicate configurations, {len(configs)} remaining")
    
    # Determine URLs to test
    test_urls = DEFAULT_TEST_URLS
    if args.url:
        test_urls = args.url
    elif args.urls_file:
        test_urls = read_urls_from_file(args.urls_file)
    
    logging.info(f"Using {len(test_urls)} URLs for testing: {', '.join(test_urls)}")
    
    try:
        # Perform testing
        if args.url_then_advanced:
            # First do URL testing
            logging.info(f"Performing URL testing on {len(configs)} configurations...")
            url_results = test_configs(
                configs, singbox_path, test_urls, args.timeout, args.workers, args.verbose,
                advanced_test=False, use_http_proxy=args.use_http_proxy
            )
            
            # Save intermediate results if temp file specified
            if args.temp_file:
                save_configs(url_results["working"], args.temp_file)
                logging.info(f"Saved {len(url_results['working'])} working configurations from URL test to {args.temp_file}")
            
            # Then do advanced testing on working configs
            logging.info(f"Performing advanced testing on {len(url_results['working'])} configurations that passed URL test...")
            advanced_results = test_configs(
                url_results["working"], singbox_path, test_urls, args.timeout, args.advanced_workers, args.verbose,
                advanced_test=True, tcp_host=args.tcp_host, tcp_port=args.tcp_port, tcp_timeout=args.tcp_timeout,
                ip_service_url=args.ip_service_url, ip_service_timeout=args.ip_service_timeout
            )
            
            # Final results are from advanced testing
            results = advanced_results
            logging.info(f"URL testing found {len(url_results['working'])} working configurations")
            logging.info(f"Advanced testing found {len(results['working'])} working configurations")
            
        else:
            # Do either URL testing or advanced testing
            logging.info(f"Performing {'advanced' if args.advanced else 'URL'} testing on {len(configs)} configurations...")
            results = test_configs(
                configs, singbox_path, test_urls, args.timeout, 
                args.advanced_workers if args.advanced else args.workers, 
                args.verbose, advanced_test=args.advanced,
                tcp_host=args.tcp_host, tcp_port=args.tcp_port, tcp_timeout=args.tcp_timeout,
                ip_service_url=args.ip_service_url, ip_service_timeout=args.ip_service_timeout,
                use_http_proxy=args.use_http_proxy
            )
            
            logging.info(f"Testing found {len(results['working'])} working configurations")
        
        # Save results
        if args.output_file:
            save_configs(results["working"], args.output_file)
        if args.append_output:
            save_configs(results["working"], args.append_output, append=True)
            
        if not args.output_file and not args.append_output:
            logging.warning("No output file specified. Results will not be saved.")
            
        logging.info("Testing completed successfully")
        
    except Exception as e:
        logging.error(f"Error during testing: {e}", exc_info=args.verbose)
        return 1
    finally:
        # Cleanup
        cleanup_all_temp_files()
        shutdown_process_manager()  # Завершаем работу менеджера процессов
    
    return 0

if __name__ == "__main__":
    sys.exit(main())