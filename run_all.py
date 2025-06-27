#!/usr/bin/env python3
"""
Unified script for downloading and testing proxy configurations.
Combines functionality of download.py and main.py.
"""

import os
import sys
import time
import logging
import argparse
import signal
from typing import List, Dict, Any

# Import modules
from filter.download import process_subscription, process_sources_file
from filter.main import test_configs, setup_logging
from filter.url_tester import shutdown_process_manager
from filter.utils import (
    find_singbox_executable, ensure_executable_permissions, remove_duplicates,
    ensure_workfiles_dir, cleanup_all_temp_files, remove_duplicates_advanced
)
from filter.config import (
    DEFAULT_TEST_URLS, DEFAULT_TIMEOUT, DEFAULT_WORKERS,
    DEFAULT_TCP_TEST_HOST, DEFAULT_TCP_TEST_PORT, DEFAULT_TCP_TIMEOUT,
    DEFAULT_IP_SERVICE_URL, DEFAULT_IP_SERVICE_TIMEOUT, DEFAULT_WORKERS_ADVANCED,
    SINGBOX_EXECUTABLE
)

def setup_signal_handlers():
    """Setup signal handlers for graceful shutdown."""
    def signal_handler(sig, frame):
        logging.info("Interrupted by user. Cleaning up...")
        cleanup_all_temp_files()
        shutdown_process_manager()  # Завершаем работу менеджера процессов
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

def download_configs(sources_file: str, output_file: str, verbose: bool = False) -> List[str]:
    """
    Download configurations from sources and save them to output file.
    
    Args:
        sources_file: File with list of sources
        output_file: File to save downloaded configurations
        verbose: Enable verbose logging
        
    Returns:
        List of downloaded configurations
    """
    logging.info(f"Downloading configurations from sources in {sources_file}...")
    configs = process_sources_file(sources_file)
    
    # Deduplicate
    original_count = len(configs)
    configs = remove_duplicates(configs)
    logging.info(f"Removed {original_count - len(configs)} duplicate configurations, {len(configs)} remaining")
    
    # Save to file
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            for config in configs:
                f.write(f"{config}\n")
        logging.info(f"Saved {len(configs)} configurations to {output_file}")
    except Exception as e:
        logging.error(f"Error saving configurations to {output_file}: {e}")
        sys.exit(1)
    
    return configs

def save_configs(configs: List[str], output_file: str):
    """
    Save configurations to a file.
    
    Args:
        configs: List of configurations
        output_file: File to save configurations
    """
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            for config in configs:
                f.write(f"{config}\n")
        logging.info(f"Saved {len(configs)} configurations to {output_file}")
    except Exception as e:
        logging.error(f"Error saving configurations to {output_file}: {e}")
        sys.exit(1)

def main():
    """Main function."""
    # Setup signal handlers
    setup_signal_handlers()
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="Download and test proxy configurations",
        epilog="Note: Testing can be interrupted at any time by pressing Ctrl+C. All temporary files will be cleaned up.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # Sources and output
    parser.add_argument("-s", "--sources", default="sources.txt",
                        help="File with list of configuration sources")
    parser.add_argument("-o", "--output", default="working.txt",
                        help="File to save working configurations")
    parser.add_argument("-c", "--configs", default="configs.txt",
                        help="File to save downloaded configurations")
    
    # Performance options
    parser.add_argument("-w", "--workers", type=int, default=DEFAULT_WORKERS,
                        help="Number of parallel workers for testing")
    
    # System options
    parser.add_argument("--singbox-path", help="Path to sing-box executable")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    # Flow control
    parser.add_argument("--skip-download", action="store_true",
                        help="Skip configuration download step")
    parser.add_argument("--skip-url-test", action="store_true",
                        help="Skip URL testing step")
    parser.add_argument("--skip-advanced-test", action="store_true",
                        help="Skip advanced testing step")
    parser.add_argument("--temp-file", default="url_working.txt",
                        help="Temporary file for URL testing results")
    
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
    
    try:
        # Step 1: Download configurations
        if not args.skip_download:
            if not os.path.isfile(args.sources):
                logging.error(f"Sources file not found: {args.sources}")
                return 1
            
            configs = download_configs(args.sources, args.configs, args.verbose)
            logging.info(f"Downloaded {len(configs)} configurations")
        else:
            logging.info("Skipping download step")
            # Read configurations from file
            try:
                with open(args.configs, 'r', encoding='utf-8') as f:
                    configs = [line.strip() for line in f.readlines() if line.strip() and not line.strip().startswith('#')]
                logging.info(f"Read {len(configs)} configurations from {args.configs}")
            except FileNotFoundError:
                logging.error(f"Configurations file not found: {args.configs}")
                return 1
            except Exception as e:
                logging.error(f"Error reading configurations file: {e}")
                return 1
        
        # Step 2: URL Testing
        if not args.skip_url_test:
            logging.info(f"Performing URL testing on {len(configs)} configurations...")
            url_results = test_configs(
                configs, singbox_path, DEFAULT_TEST_URLS, DEFAULT_TIMEOUT, args.workers, args.verbose,
                advanced_test=False
            )
            
            # Save intermediate results
            save_configs(url_results["working"], args.temp_file)
            logging.info(f"URL testing found {len(url_results['working'])} working configurations")
            
            # Use URL results for advanced testing
            configs = url_results["working"]
        else:
            logging.info("Skipping URL testing step")
        
        # Step 3: Advanced Testing
        if not args.skip_advanced_test:
            logging.info(f"Performing advanced testing on {len(configs)} configurations...")
            advanced_results = test_configs(
                configs, singbox_path, DEFAULT_TEST_URLS, DEFAULT_TIMEOUT, args.workers, args.verbose,
                advanced_test=True, tcp_host=DEFAULT_TCP_TEST_HOST, tcp_port=DEFAULT_TCP_TEST_PORT,
                tcp_timeout=DEFAULT_TCP_TIMEOUT, ip_service_url=DEFAULT_IP_SERVICE_URL,
                ip_service_timeout=DEFAULT_IP_SERVICE_TIMEOUT
            )
            
            # Save final results
            save_configs(advanced_results["working"], args.output)
            logging.info(f"Advanced testing found {len(advanced_results['working'])} working configurations")
        else:
            logging.info("Skipping advanced testing step")
            # If URL testing was done but advanced testing skipped, save URL results as final
            if not args.skip_url_test:
                save_configs(configs, args.output)
        
        logging.info("All steps completed successfully")
        
    except Exception as e:
        logging.error(f"Error during execution: {e}", exc_info=args.verbose)
        return 1
    finally:
        # Cleanup
        cleanup_all_temp_files()
        shutdown_process_manager()  # Завершаем работу менеджера процессов
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 