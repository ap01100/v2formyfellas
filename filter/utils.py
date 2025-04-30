"""
Utility functions for proxy testing project.
Contains common utility functions used across the project.
"""

import os
import socket
import time
import subprocess
import logging
import tempfile
from typing import Optional, List
from contextlib import contextmanager
from config import MAX_WAIT_TIME, SOCKET_CHECK_INTERVAL, MAX_ERROR_OUTPUT_LEN

def check_ubuntu_compatibility():
    """Checks compatibility with Ubuntu 22.04."""
    try:
        with open('/etc/os-release', 'r') as f:
            os_info = f.read()
            if 'Ubuntu' in os_info:
                if '22.04' in os_info:
                    logging.debug("Detected Ubuntu 22.04 - compatible environment")
                    return True
                else:
                    logging.warning("Running on Ubuntu, but not version 22.04. Some features may not work as expected.")
                    return True
    except Exception:
        # If OS can't be determined, continue
        pass
    
    # If not Ubuntu, show warning
    logging.warning("Not running on Ubuntu 22.04. This script is optimized for Ubuntu 22.04, some features may not work as expected.")
    return False

def ensure_executable_permissions(file_path):
    """Ensures the file has executable permissions (chmod +x)."""
    if not os.path.exists(file_path):
        return False
    
    try:
        # Check if file is executable
        if not os.access(file_path, os.X_OK):
            logging.warning(f"File {file_path} is not executable. Attempting to add execute permission.")
            os.chmod(file_path, os.stat(file_path).st_mode | 0o111)  # Add execute permission
            if os.access(file_path, os.X_OK):
                logging.info(f"Successfully added execute permission to {file_path}")
                return True
            else:
                logging.error(f"Failed to make {file_path} executable")
                return False
        return True
    except Exception as e:
        logging.error(f"Error checking/setting permissions on {file_path}: {e}")
        return False

@contextmanager
def create_temp_file(suffix=".json"):
    """Creates a temporary file and ensures it's deleted after use."""
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False, encoding='utf-8') as tmp_file:
            temp_path = tmp_file.name
            yield tmp_file
    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
                logging.debug(f"Temporary file removed: {temp_path}")
            except Exception as e:
                logging.error(f"Error deleting temporary file {temp_path}: {e}")

def find_free_port() -> int:
    """Finds a free TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def cleanup_process(process: Optional[subprocess.Popen], verbose: bool = False):
    """Gracefully terminates a process and captures its output."""
    if not process:
        return
        
    if process.poll() is None:
        logging.debug(f"Terminating process {process.pid}...")
        try:
            process.terminate()
            process.wait(timeout=2)
            logging.debug(f"Process {process.pid} terminated.")
        except subprocess.TimeoutExpired:
            logging.warning(f"Process {process.pid} did not terminate in 2 sec, sending kill...")
            process.kill()
            process.wait()
            logging.debug(f"Process {process.pid} killed.")
        except Exception as e:
            logging.error(f"Error terminating process {process.pid}: {e}")

    try:
        stdout, stderr = process.communicate(timeout=2)
        stdout_str = stdout.decode('utf-8', errors='replace') if stdout else ""
        stderr_str = stderr.decode('utf-8', errors='replace') if stderr else ""
        if verbose and (stdout_str or stderr_str):
            output_len = MAX_ERROR_OUTPUT_LEN
            logging.debug(f"Process {process.pid} output on termination:"
                          f"\nSTDOUT:\n{stdout_str[:output_len]}"
                          f"\nSTDERR:\n{stderr_str[:output_len]}")
    except subprocess.TimeoutExpired:
        logging.warning(f"Timeout reading output from terminated process {process.pid}")
    except Exception as e:
        logging.error(f"Error reading output from process {process.pid}: {e}")

def cleanup_file(filepath: Optional[str]):
    """Deletes a temporary file."""
    if filepath and os.path.exists(filepath):
        try:
            os.remove(filepath)
            logging.debug(f"Temporary file deleted: {filepath}")
        except Exception as e:
            logging.error(f"Error deleting file {filepath}: {e}")

def wait_for_port(host: str, port: int, timeout: float = MAX_WAIT_TIME) -> bool:
    """Waits for a port to become available (synchronously)."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            with socket.create_connection((host, port), timeout=0.1):
                logging.debug(f"Port {port} ready after {time.time() - start_time:.2f} sec.")
                return True
        except (socket.timeout, ConnectionRefusedError):
            time.sleep(SOCKET_CHECK_INTERVAL)
        except Exception as e:
            logging.error(f"Unexpected error checking port {port}: {e}")
            time.sleep(SOCKET_CHECK_INTERVAL * 1.5)
    return False

def is_process_running(process: Optional[subprocess.Popen]) -> bool:
    """Checks if a process is running."""
    if not process:
        return False
    return process.poll() is None

def remove_duplicates(configs: List[str]) -> List[str]:
    """
    Removes duplicates from a list of configurations.
    Uses simple string comparison for fast processing.
    """
    if not configs:
        return []
    
    logging.info(f"Removing duplicates from {len(configs)} configurations...")
    unique_configs = []
    seen_configs = set()
    duplicates_count = 0
    
    for config in configs:
        if config in seen_configs:
            duplicates_count += 1
            continue
        
        seen_configs.add(config)
        unique_configs.append(config)
    
    if duplicates_count > 0:
        logging.info(f"Removed {duplicates_count} duplicates. {len(unique_configs)} unique configs remain.")
    else:
        logging.info("No duplicates found.")
    
    return unique_configs 