"""
Модуль управления процессами sing-box.
Предоставляет централизованный механизм для запуска, мониторинга и завершения sing-box процессов.
"""

import os
import time
import json
import logging
import subprocess
import threading
import queue
from typing import Dict, Any, Optional, List, Tuple, Set, Union
from pathlib import Path

from filter.utils import find_free_port, wait_for_port, get_temp_file_path, cleanup_file
from filter.parsers import convert_to_singbox_config
from filter.config import MAX_WAIT_TIME, SOCKET_CHECK_INTERVAL

class SingBoxProcess:
    """Класс, представляющий отдельный процесс sing-box"""
    
    def __init__(self, process: subprocess.Popen, config_file: str, socks_port: int, 
                 config_str: str, start_time: float):
        """
        Инициализация объекта процесса sing-box
        
        Args:
            process: Объект subprocess.Popen запущенного процесса
            config_file: Путь к файлу конфигурации
            socks_port: Порт, на котором запущен прокси
            config_str: Строка конфигурации прокси
            start_time: Время запуска процесса
        """
        self.process = process
        self.config_file = config_file
        self.socks_port = socks_port
        self.config_str = config_str
        self.start_time = start_time
        self.last_used = start_time
        self.is_ready = False
        
    def mark_as_used(self):
        """Отметить процесс как использованный (обновить время последнего использования)"""
        self.last_used = time.time()
        
    def uptime(self) -> float:
        """Получить время работы процесса в секундах"""
        return time.time() - self.start_time
    
    def idle_time(self) -> float:
        """Получить время простоя процесса в секундах"""
        return time.time() - self.last_used
    
    def get_proxy_url(self, use_http: bool = False) -> str:
        """
        Получить URL прокси для использования в requests
        
        Args:
            use_http: Использовать HTTP прокси вместо SOCKS5
            
        Returns:
            URL прокси в формате для requests
        """
        protocol = "http" if use_http else "socks5"
        return f"{protocol}://127.0.0.1:{self.socks_port}"
    
    def is_running(self) -> bool:
        """Проверить, запущен ли процесс"""
        if self.process is None:
            return False
        return self.process.poll() is None
    
    def cleanup(self, verbose: bool = False):
        """
        Очистить ресурсы процесса
        
        Args:
            verbose: Подробный вывод логов
        """
        try:
            if self.is_running():
                if verbose:
                    logging.debug(f"Terminating sing-box process on port {self.socks_port}")
                try:
                    self.process.terminate()
                    try:
                        self.process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        if verbose:
                            logging.debug(f"Process on port {self.socks_port} did not terminate, killing")
                        self.process.kill()
                        self.process.wait(timeout=1)
                except Exception as e:
                    if verbose:
                        logging.debug(f"Error terminating process on port {self.socks_port}: {e}")
            
            # Удаляем файл конфигурации
            if self.config_file and os.path.exists(self.config_file):
                cleanup_file(self.config_file, verbose)
                
        except Exception as e:
            if verbose:
                logging.debug(f"Error during cleanup of process on port {self.socks_port}: {e}")


class SingBoxProcessManager:
    """
    Менеджер процессов sing-box.
    Управляет пулом процессов, их созданием, мониторингом и завершением.
    """
    
    def __init__(self, singbox_path: str, max_processes: int = 100, 
                 idle_timeout: int = 60, verbose: bool = False):
        """
        Инициализация менеджера процессов
        
        Args:
            singbox_path: Путь к исполняемому файлу sing-box
            max_processes: Максимальное количество одновременно запущенных процессов
            idle_timeout: Время в секундах, после которого неиспользуемый процесс будет завершен
            verbose: Подробный вывод логов
        """
        self.singbox_path = singbox_path
        self.max_processes = max_processes
        self.idle_timeout = idle_timeout
        self.verbose = verbose
        self.processes: Dict[str, SingBoxProcess] = {}  # config_str -> SingBoxProcess
        self.ports_in_use: Set[int] = set()
        self.lock = threading.RLock()
        self.cleanup_thread = None
        self.stop_cleanup = False
        self._start_cleanup_thread()
        
        logging.info(f"SingBoxProcessManager initialized with max {max_processes} processes")
        
    def _start_cleanup_thread(self):
        """Запустить поток для периодической очистки неиспользуемых процессов"""
        def cleanup_worker():
            while not self.stop_cleanup:
                try:
                    self._cleanup_idle_processes()
                except Exception as e:
                    if self.verbose:
                        logging.debug(f"Error in cleanup thread: {e}")
                time.sleep(10)  # Проверка каждые 10 секунд
                
        self.cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
        self.cleanup_thread.start()
        if self.verbose:
            logging.debug("Cleanup thread started")
    
    def _cleanup_idle_processes(self):
        """Очистить неиспользуемые процессы"""
        with self.lock:
            current_time = time.time()
            to_remove = []
            
            for config_str, process in self.processes.items():
                # Проверяем, запущен ли процесс и не используется ли слишком долго
                if not process.is_running():
                    to_remove.append(config_str)
                    if self.verbose:
                        logging.debug(f"Process for {config_str[:20]}... is not running, marking for removal")
                elif process.idle_time() > self.idle_timeout:
                    to_remove.append(config_str)
                    if self.verbose:
                        logging.debug(f"Process for {config_str[:20]}... idle for {process.idle_time():.1f}s, marking for removal")
            
            # Удаляем процессы, помеченные для удаления
            for config_str in to_remove:
                self._remove_process(config_str)
                
            if to_remove and self.verbose:
                logging.debug(f"Cleaned up {len(to_remove)} idle processes, {len(self.processes)} remaining")
    
    def _remove_process(self, config_str: str):
        """
        Удалить процесс из пула и освободить ресурсы
        
        Args:
            config_str: Строка конфигурации прокси
        """
        if config_str in self.processes:
            process = self.processes[config_str]
            
            # Освобождаем порт
            if process.socks_port in self.ports_in_use:
                self.ports_in_use.remove(process.socks_port)
                
            # Очищаем ресурсы процесса
            process.cleanup(self.verbose)
            
            # Удаляем из словаря
            del self.processes[config_str]
            
            if self.verbose:
                logging.debug(f"Removed process for {config_str[:20]}...")
    
    def get_process(self, config_str: str, use_http_proxy: bool = False) -> Optional[SingBoxProcess]:
        """
        Получить или создать процесс для заданной конфигурации
        
        Args:
            config_str: Строка конфигурации прокси
            use_http_proxy: Использовать HTTP прокси вместо SOCKS5
            
        Returns:
            Объект процесса или None в случае ошибки
        """
        with self.lock:
            # Проверяем, есть ли уже запущенный процесс для этой конфигурации
            if config_str in self.processes:
                process = self.processes[config_str]
                
                # Проверяем, запущен ли процесс
                if process.is_running():
                    process.mark_as_used()
                    return process
                else:
                    # Процесс завершился, удаляем его
                    self._remove_process(config_str)
            
            # Проверяем, не превышен ли лимит процессов
            if len(self.processes) >= self.max_processes:
                # Находим самый старый неиспользуемый процесс
                oldest_process = None
                oldest_idle_time = -1
                
                for proc_config, proc in self.processes.items():
                    if proc.idle_time() > oldest_idle_time:
                        oldest_process = proc_config
                        oldest_idle_time = proc.idle_time()
                
                # Удаляем самый старый процесс
                if oldest_process:
                    if self.verbose:
                        logging.debug(f"Max processes reached, removing oldest idle process")
                    self._remove_process(oldest_process)
                else:
                    logging.warning("Max processes reached and no idle processes to remove")
                    return None
            
            # Создаем новый процесс
            try:
                return self._create_process(config_str, use_http_proxy)
            except Exception as e:
                logging.error(f"Error creating process for {config_str[:20]}...: {e}")
                return None
    
    def _create_process(self, config_str: str, use_http_proxy: bool = False) -> Optional[SingBoxProcess]:
        """
        Создать новый процесс sing-box
        
        Args:
            config_str: Строка конфигурации прокси
            use_http_proxy: Использовать HTTP прокси вместо SOCKS5
            
        Returns:
            Объект процесса или None в случае ошибки
        """
        log_prefix = f"Process[{config_str[:15]}...]"
        
        try:
            # Находим свободный порт
            while True:
                socks_port = find_free_port()
                if socks_port not in self.ports_in_use:
                    self.ports_in_use.add(socks_port)
                    break
            
            if self.verbose:
                logging.debug(f"{log_prefix} Using port {socks_port}")
                
            # Создаем конфигурацию sing-box
            log_level = "debug" if self.verbose else "warn"
            singbox_config = convert_to_singbox_config(config_str, socks_port, log_level, use_http_proxy)
            
            # Записываем конфигурацию во временный файл
            config_file = get_temp_file_path("temp", socks_port)
            with open(config_file, "w", encoding="utf-8") as tmp:
                json.dump(singbox_config, tmp)
                
            if self.verbose:
                logging.debug(f"{log_prefix} Config written to {config_file}")
                
            # Запускаем sing-box
            cmd = [self.singbox_path, "run", "-c", config_file]
            if self.verbose:
                logging.debug(f"{log_prefix} Running command: {' '.join(cmd)}")
                
            # Создаем процесс
            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            
            start_time = time.time()
            
            # Создаем объект процесса
            sing_process = SingBoxProcess(
                process=process,
                config_file=config_file,
                socks_port=socks_port,
                config_str=config_str,
                start_time=start_time
            )
            
            # Ждем, пока порт будет доступен
            if self.verbose:
                logging.debug(f"{log_prefix} Waiting for port {socks_port} to be ready...")
                
            if not wait_for_port("127.0.0.1", socks_port):
                error_msg = f"Timeout waiting for sing-box to start on port {socks_port}"
                logging.error(f"{log_prefix} {error_msg}")
                sing_process.cleanup(self.verbose)
                if socks_port in self.ports_in_use:
                    self.ports_in_use.remove(socks_port)
                return None
            
            # Процесс успешно запущен
            sing_process.is_ready = True
            self.processes[config_str] = sing_process
            
            if self.verbose:
                logging.debug(f"{log_prefix} Process started successfully on port {socks_port}")
            
            return sing_process
            
        except Exception as e:
            logging.error(f"{log_prefix} Error creating process: {e}")
            # Очищаем ресурсы в случае ошибки
            if 'socks_port' in locals() and socks_port in self.ports_in_use:
                self.ports_in_use.remove(socks_port)
            if 'config_file' in locals() and os.path.exists(config_file):
                cleanup_file(config_file, self.verbose)
            return None
    
    def release_process(self, config_str: str):
        """
        Отметить процесс как неиспользуемый
        
        Args:
            config_str: Строка конфигурации прокси
        """
        with self.lock:
            if config_str in self.processes:
                # Просто обновляем время последнего использования
                # Процесс будет завершен автоматически, если не будет использован в течение idle_timeout
                self.processes[config_str].mark_as_used()
    
    def shutdown(self):
        """Завершить все процессы и освободить ресурсы"""
        logging.info("Shutting down SingBoxProcessManager")
        
        # Останавливаем поток очистки
        self.stop_cleanup = True
        if self.cleanup_thread and self.cleanup_thread.is_alive():
            self.cleanup_thread.join(timeout=2)
        
        with self.lock:
            # Завершаем все процессы
            for config_str in list(self.processes.keys()):
                self._remove_process(config_str)
            
            self.processes.clear()
            self.ports_in_use.clear()
        
        logging.info("SingBoxProcessManager shutdown complete")
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Получить статистику по процессам
        
        Returns:
            Словарь со статистикой
        """
        with self.lock:
            active_count = 0
            idle_count = 0
            total_uptime = 0
            
            for process in self.processes.values():
                if process.is_running():
                    active_count += 1
                    total_uptime += process.uptime()
                    if process.idle_time() > 5:  # Считаем процесс простаивающим, если он не использовался более 5 секунд
                        idle_count += 1
            
            avg_uptime = total_uptime / active_count if active_count > 0 else 0
            
            return {
                "total_processes": len(self.processes),
                "active_processes": active_count,
                "idle_processes": idle_count,
                "ports_in_use": len(self.ports_in_use),
                "avg_uptime": avg_uptime
            } 