"""
Utility functions for the filter package.
"""

import os
import sys
import socket
import time
import logging
import subprocess
import re
import platform
import hashlib
import json
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Union
from contextlib import contextmanager
from filter.config import MAX_WAIT_TIME, SOCKET_CHECK_INTERVAL, MAX_ERROR_OUTPUT_LEN
from filter.parsers import parse_ss_config, parse_trojan_config, parse_vmess_config, parse_vless_config

# Define workfiles directory path
WORKFILES_DIR = "workfiles"

# Добавляем глобальную переменную для отслеживания использованных портов
_used_ports = set()

def ensure_workfiles_dir():
    """Ensures the workfiles directory exists."""
    ensure_directory(WORKFILES_DIR)
    # Также создаем директорию filter/workfiles
    ensure_directory(os.path.join("filter", WORKFILES_DIR))
    logging.debug(f"Ensured workfiles directory exists at: {WORKFILES_DIR}")
    return WORKFILES_DIR

def ensure_directory(directory):
    """Safely creates a directory if it doesn't exist."""
    try:
        os.makedirs(directory, exist_ok=True)
    except Exception as e:
        logging.debug(f"Error creating directory {directory}: {e}")

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

def find_singbox_executable() -> Optional[str]:
    """
    Finds the sing-box executable in common locations.
    
    Returns:
        Path to sing-box executable if found, None otherwise
    """
    # Check in bin directory first
    bin_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bin")
    
    if os.name == 'nt':  # Windows
        singbox_path = os.path.join(bin_dir, "sing-box.exe")
        if os.path.exists(singbox_path):
            return singbox_path
            
        # Check in PATH
        for path in os.environ["PATH"].split(os.pathsep):
            exe_path = os.path.join(path, "sing-box.exe")
            if os.path.exists(exe_path):
                return exe_path
    else:  # Unix-like
        singbox_path = os.path.join(bin_dir, "sing-box")
        if os.path.exists(singbox_path):
            return singbox_path
            
        # Check in PATH
        for path in os.environ["PATH"].split(os.pathsep):
            exe_path = os.path.join(path, "sing-box")
            if os.path.exists(exe_path):
                return exe_path
    
    return None

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

def find_free_port(start_port: int = 10000, max_attempts: int = 1000) -> int:
    """
    Finds a free port on the local machine.
    
    Args:
        start_port: Starting port number to check
        max_attempts: Maximum number of ports to check
        
    Returns:
        A free port number
        
    Raises:
        RuntimeError: If no free port is found after max_attempts
    """
    global _used_ports
    
    # Если начальный порт уже был использован, увеличиваем его
    if start_port in _used_ports:
        start_port = max(_used_ports) + 1
    
    for port in range(start_port, start_port + max_attempts):
        # Пропускаем порты, которые уже были использованы
        if port in _used_ports:
            continue
            
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('127.0.0.1', port))
                # Добавляем порт в список использованных
                _used_ports.add(port)
                return port
        except OSError:
            continue
    
    raise RuntimeError(f"Could not find a free port after {max_attempts} attempts")

def cleanup_process(process: Optional[subprocess.Popen], verbose: bool = False):
    """Gracefully terminates a process and captures its output."""
    if not process:
        return
        
    try:
        # Проверяем, завершен ли процесс
        if process.poll() is None:
            # Процесс еще работает, пытаемся завершить его
            logging.debug(f"Terminating process {process.pid}...")
            try:
                # Сначала пробуем graceful termination
                process.terminate()
                try:
                    # Ждем завершения с таймаутом
                    process.wait(timeout=2)
                    logging.debug(f"Process {process.pid} terminated.")
                except subprocess.TimeoutExpired:
                    # Если процесс не завершился, убиваем его
                    logging.debug(f"Process {process.pid} did not terminate in 2 sec, sending kill...")
                    process.kill()
                    process.wait(timeout=1)
                    logging.debug(f"Process {process.pid} killed.")
            except Exception as e:
                # Игнорируем ошибки при попытке завершить процесс
                logging.debug(f"Error terminating process {process.pid}: {e}")
        else:
            # Процесс уже завершен
            logging.debug(f"Process {process.pid} already terminated with code {process.returncode}")
    except Exception as e:
        # Игнорируем любые другие ошибки
        logging.debug(f"Error in cleanup_process: {e}")
    
    # Пытаемся прочитать вывод процесса, если это возможно
    try:
        stdout, stderr = process.communicate(timeout=1)
        if verbose:
            stdout_str = stdout.decode('utf-8', errors='replace') if stdout else ""
            stderr_str = stderr.decode('utf-8', errors='replace') if stderr else ""
            if stdout_str or stderr_str:
                logging.debug(f"Process {process.pid} output:"
                            f"\nSTDOUT: {stdout_str[:200]}"
                            f"\nSTDERR: {stderr_str[:200]}")
    except Exception:
        # Игнорируем ошибки при чтении вывода
        pass

def cleanup_file(filepath: Optional[str], verbose: bool = False):
    """Deletes a temporary file."""
    if filepath and os.path.exists(filepath):
        try:
            os.remove(filepath)
            logging.debug(f"Temporary file deleted: {filepath}")
        except FileNotFoundError:
            # Файл уже удален, игнорируем
            pass
        except PermissionError:
            # Файл занят другим процессом, пробуем позже
            logging.debug(f"File {filepath} is locked, will try to delete later")
        except Exception as e:
            # Только для отладки, не для обычного режима
            logging.debug(f"Error deleting file {filepath}: {e}")

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
            return protocol + json.dumps(fingerprint, sort_keys=True)
        except Exception as e:
            # Log the error but don't halt the process
            logging.debug(f"Failed to parse configuration for deduplication: {str(e)}")
            # Use a simplified fingerprint based on the raw string
            # This prevents complete failure but may not catch all duplicates
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
    # Список процессов sing-box для завершения
    sing_box_processes = []
    
    # Поиск процессов sing-box в Windows
    if os.name == 'nt':
        try:
            import psutil
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    if proc.info['name'] == 'sing-box.exe' or (proc.info['cmdline'] and 'sing-box' in ' '.join(proc.info['cmdline'])):
                        sing_box_processes.append(proc)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
        except ImportError:
            logging.debug("Модуль psutil не установлен, не удается найти процессы sing-box")
    
    # Очистка временных файлов
    if not os.path.exists(WORKFILES_DIR):
        return
        
    for filename in os.listdir(WORKFILES_DIR):
        if filename.startswith("temp_") and filename.endswith(".json"):
            filepath = os.path.join(WORKFILES_DIR, filename)
            cleanup_file(filepath)
    
    # Также очищаем директорию filter/workfiles
    filter_workfiles = os.path.join("filter", WORKFILES_DIR)
    if os.path.exists(filter_workfiles):
        for filename in os.listdir(filter_workfiles):
            if filename.startswith("temp_") and filename.endswith(".json"):
                try:
                    os.remove(os.path.join(filter_workfiles, filename))
                except FileNotFoundError:
                    # Файл уже удален, игнорируем
                    pass
                except PermissionError:
                    # Файл занят другим процессом, пробуем позже
                    logging.debug(f"File {os.path.join(filter_workfiles, filename)} is locked, will try to delete later")
                except Exception as e:
                    # Только для отладки, не для обычного режима
                    logging.debug(f"Error deleting file {os.path.join(filter_workfiles, filename)}: {e}")
    
    # Завершаем процессы sing-box
    if sing_box_processes:
        logging.info(f"Завершение {len(sing_box_processes)} процессов sing-box...")
        for proc in sing_box_processes:
            try:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except:
                    proc.kill()
            except:
                pass

def check_netcat_traditional() -> bool:
    """Checks if netcat-traditional is installed and selected on Ubuntu."""
    try:
        result = subprocess.run(
            ["nc", "-h"],
            capture_output=True,
            text=True,
            timeout=2
        )
        return "BusyBox" not in result.stderr and "OpenBSD" not in result.stderr
    except Exception:
        return False

def remove_duplicates(configs: List[str]) -> List[str]:
    """
    Removes duplicate configurations from a list.
    
    Args:
        configs: List of configuration strings
        
    Returns:
        List with duplicates removed
    """
    unique_configs = []
    seen = set()
    
    for config in configs:
        if config not in seen:
            seen.add(config)
            unique_configs.append(config)
    
    return unique_configs

def remove_duplicates_advanced(configs: List[str]) -> List[str]:
    """
    Removes duplicate configurations using a more advanced method.
    Ignores configuration names and other metadata, focusing on core connection details.
    
    Args:
        configs: List of configuration strings
        
    Returns:
        List with duplicates removed
    """
    unique_configs = []
    seen_hashes = set()
    
    for config in configs:
        # Extract core connection details using regex
        server_match = re.search(r'@([^:]+):', config)
        if not server_match:
            # If we can't extract server, just use the whole config
            unique_configs.append(config)
            continue
            
        server = server_match.group(1)
        port_match = re.search(r':(\d+)(\?|#|$)', config)
        port = port_match.group(1) if port_match else ""
        
        # Create a hash of the core details
        core_hash = hashlib.md5(f"{server}:{port}".encode()).hexdigest()
        
        if core_hash not in seen_hashes:
            seen_hashes.add(core_hash)
            unique_configs.append(config)
    
    return unique_configs 