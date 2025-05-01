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

# Define workfiles directory path
WORKFILES_DIR = "workfiles"

def ensure_workfiles_dir():
    """Ensures the workfiles directory exists."""
    os.makedirs(WORKFILES_DIR, exist_ok=True)
    logging.debug(f"Ensured workfiles directory exists at: {WORKFILES_DIR}")
    return WORKFILES_DIR

def get_temp_file_path(prefix="temp", port=None, suffix=".json"):
    """
    Generates a path for a temporary file in the workfiles directory.
    
    Args:
        prefix: Prefix for the filename
        port: Optional port number to include in the filename
        suffix: File extension
        
    Returns:
        Path to the temporary file
    """
    ensure_workfiles_dir()
    if port:
        filename = f"{prefix}_{port}{suffix}"
    else:
        filename = f"{prefix}_{int(time.time())}{suffix}"
    return os.path.join(WORKFILES_DIR, filename)

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
    """Creates a temporary file in the workfiles directory and ensures it's deleted after use."""
    temp_path = None
    try:
        ensure_workfiles_dir()
        temp_path = os.path.join(WORKFILES_DIR, f"temp_{int(time.time())}{suffix}")
        with open(temp_path, "w", encoding="utf-8") as tmp_file:
            yield tmp_file
    finally:
        cleanup_file(temp_path)

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

def remove_duplicates_advanced(configs: List[str]) -> List[str]:
    """
    Advanced duplicate removal for proxy configurations.
    
    Considers configurations as duplicates if all parameters except name are identical.
    This implementation parses each configuration to extract its parameters and then
    compares them, ignoring the name/remark field.
    
    Args:
        configs: List of configuration strings to deduplicate
        
    Returns:
        List of unique configurations
    """
    if not configs:
        return []
    
    from parsers import parse_ss_config, parse_trojan_config, parse_vmess_config, parse_vless_config
    
    logging.info(f"Removing duplicates (advanced mode) from {len(configs)} configurations...")
    unique_configs = []
    seen_fingerprints = set()
    duplicates_count = 0
    
    # Map of protocol prefixes to their corresponding parser functions
    parser_map = {
        "ss://": parse_ss_config,
        "trojan://": parse_trojan_config,
        "vmess://": parse_vmess_config,
        "vless://": parse_vless_config,
    }
    
    def get_config_fingerprint(config_str: str) -> str:
        """
        Generate a fingerprint for a configuration by extracting and 
        normalizing its parameters (excluding name/tag).
        
        Returns an empty string if parsing fails.
        """
        protocol = None
        for prefix in parser_map:
            if config_str.startswith(prefix):
                protocol = prefix
                break
        
        if not protocol:
            # Unknown protocol, can't deduplicate
            return ""
        
        try:
            # Parse the configuration
            parser = parser_map[protocol]
            parsed = parser(config_str)
            
            # Create a normalized copy without tag field
            fingerprint = dict(parsed)
            if "tag" in fingerprint:
                del fingerprint["tag"]
            
            # Convert to a string representation for hashing
            import json
            return protocol + json.dumps(fingerprint, sort_keys=True)
        except Exception as e:
            # Log the error but don't halt the process
            logging.debug(f"Failed to parse configuration for deduplication: {str(e)}")
            # Use a simplified fingerprint based on the raw string
            # This prevents complete failure but may not catch all duplicates
            import hashlib
            simplified_hash = hashlib.md5(config_str.encode('utf-8')).hexdigest()
            return f"{protocol}_unparseable_{simplified_hash}"
    
    for config in configs:
        fingerprint = get_config_fingerprint(config)
        
        if not fingerprint:
            # If we couldn't parse the config, keep it as is
            unique_configs.append(config)
            continue
        
        if fingerprint in seen_fingerprints:
            duplicates_count += 1
            continue
        
        seen_fingerprints.add(fingerprint)
        unique_configs.append(config)
    
    if duplicates_count > 0:
        logging.info(f"Removed {duplicates_count} duplicates (advanced mode). {len(unique_configs)} unique configs remain.")
    else:
        logging.info("No duplicates found (advanced mode).")
    
    return unique_configs

def cleanup_all_temp_files():
    """Cleans up all temporary files in the workfiles directory."""
    if not os.path.exists(WORKFILES_DIR):
        return
        
    for filename in os.listdir(WORKFILES_DIR):
        if filename.startswith("temp_") and filename.endswith(".json"):
            filepath = os.path.join(WORKFILES_DIR, filename)
            cleanup_file(filepath) 