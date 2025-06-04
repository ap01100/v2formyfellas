#!/usr/bin/env python3
"""
Setup script for v2formyfellas project.
Installs dependencies and checks for sing-box executable.
"""

import os
import sys
import subprocess
import platform
import tempfile
import shutil
import zipfile
import tarfile
import urllib.request
import logging

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def install_dependencies():
    """Устанавливает необходимые зависимости Python."""
    logging.info("Installing Python dependencies...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        logging.info("Dependencies installed successfully.")
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to install dependencies: {e}")
        return False

def check_singbox():
    """Проверяет наличие sing-box в системе."""
    logging.info("Checking for sing-box...")
    
    # Импортируем функцию поиска sing-box из utils.py
    sys.path.append(os.path.join(os.path.dirname(__file__), "filter"))
    try:
        from utils import find_singbox_executable
        singbox_path = find_singbox_executable()
        if singbox_path:
            logging.info(f"Found sing-box at: {singbox_path}")
            return True, singbox_path
        else:
            logging.warning("sing-box not found in system.")
            return False, None
    except ImportError:
        logging.error("Could not import find_singbox_executable from utils.py")
        return False, None

def download_singbox():
    """Скачивает и устанавливает sing-box."""
    logging.info("Attempting to download sing-box...")
    
    # Определяем архитектуру и ОС
    system = platform.system().lower()
    machine = platform.machine().lower()
    
    # Преобразуем архитектуру в формат, используемый в релизах sing-box
    arch_map = {
        'x86_64': 'amd64',
        'amd64': 'amd64',
        'i386': '386',
        'i686': '386',
        'armv7l': 'armv7',
        'armv6l': 'armv6',
        'aarch64': 'arm64',
        'arm64': 'arm64'
    }
    
    arch = arch_map.get(machine, machine)
    
    # Определяем URL для скачивания
    version = "1.8.0"  # Можно обновить на более новую версию
    
    if system == 'windows':
        filename = f"sing-box-{version}-windows-{arch}.zip"
        executable = "sing-box.exe"
    elif system == 'linux':
        filename = f"sing-box-{version}-linux-{arch}.tar.gz"
        executable = "sing-box"
    elif system == 'darwin':  # macOS
        filename = f"sing-box-{version}-darwin-{arch}.tar.gz"
        executable = "sing-box"
    else:
        logging.error(f"Unsupported system: {system}")
        return False, None
    
    url = f"https://github.com/SagerNet/sing-box/releases/download/v{version}/{filename}"
    
    # Создаем временную директорию для скачивания
    temp_dir = tempfile.mkdtemp()
    archive_path = os.path.join(temp_dir, filename)
    
    try:
        # Скачиваем архив
        logging.info(f"Downloading sing-box from {url}...")
        urllib.request.urlretrieve(url, archive_path)
        
        # Распаковываем архив
        logging.info("Extracting sing-box...")
        if system == 'windows':
            with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)
        else:
            with tarfile.open(archive_path, 'r:gz') as tar_ref:
                tar_ref.extractall(temp_dir)
        
        # Находим исполняемый файл в распакованных файлах
        for root, dirs, files in os.walk(temp_dir):
            if executable in files:
                extracted_path = os.path.join(root, executable)
                break
        else:
            logging.error(f"Could not find {executable} in extracted files")
            return False, None
        
        # Создаем директорию для установки
        install_dir = os.path.join(os.path.dirname(__file__), "bin")
        os.makedirs(install_dir, exist_ok=True)
        
        # Копируем исполняемый файл
        install_path = os.path.join(install_dir, executable)
        shutil.copy2(extracted_path, install_path)
        
        # Делаем файл исполняемым на Unix-системах
        if system != 'windows':
            os.chmod(install_path, 0o755)
        
        logging.info(f"sing-box installed to {install_path}")
        return True, install_path
        
    except Exception as e:
        logging.error(f"Failed to download and install sing-box: {e}")
        return False, None
    finally:
        # Удаляем временную директорию
        shutil.rmtree(temp_dir, ignore_errors=True)

def update_config(singbox_path):
    """Обновляет конфигурационный файл с путем к sing-box."""
    config_file = os.path.join(os.path.dirname(__file__), "filter", "config.py")
    
    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Заменяем значение SINGBOX_EXECUTABLE
        if "SINGBOX_EXECUTABLE =" in content:
            lines = content.split('\n')
            for i, line in enumerate(lines):
                if line.strip().startswith("SINGBOX_EXECUTABLE ="):
                    lines[i] = f'SINGBOX_EXECUTABLE = "{singbox_path}"  # Auto-updated by setup.py'
                    break
            
            updated_content = '\n'.join(lines)
            
            with open(config_file, 'w', encoding='utf-8') as f:
                f.write(updated_content)
                
            logging.info(f"Updated {config_file} with sing-box path: {singbox_path}")
            return True
        else:
            logging.error(f"Could not find SINGBOX_EXECUTABLE in {config_file}")
            return False
    except Exception as e:
        logging.error(f"Failed to update config file: {e}")
        return False

def main():
    """Основная функция настройки."""
    logging.info("Starting setup for v2formyfellas...")
    
    # Устанавливаем зависимости
    if not install_dependencies():
        logging.error("Failed to install dependencies. Setup incomplete.")
        return 1
    
    # Проверяем наличие sing-box
    found, singbox_path = check_singbox()
    
    # Если sing-box не найден, пытаемся скачать
    if not found:
        logging.info("sing-box not found, attempting to download...")
        success, singbox_path = download_singbox()
        if not success:
            logging.error("Failed to download sing-box. You need to install it manually.")
            logging.info("You can download it from: https://github.com/SagerNet/sing-box/releases")
            return 1
    
    # Обновляем конфигурацию с путем к sing-box
    if not update_config(singbox_path):
        logging.warning("Failed to update config with sing-box path.")
        logging.info(f"Please manually set SINGBOX_EXECUTABLE in filter/config.py to: {singbox_path}")
    
    logging.info("Setup completed successfully!")
    logging.info("You can now run the tool with: python filter/main.py")
    return 0

if __name__ == "__main__":
    sys.exit(main()) 