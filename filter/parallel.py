"""
Parallel execution module for proxy tests.
Handles concurrent testing of multiple proxy configurations.
"""

import concurrent.futures
import logging
import time
import os
import sys
import signal
from typing import List, Dict, Any, Callable, TypeVar, Generic, Union

T = TypeVar('T')
R = TypeVar('R')

class ParallelExecutor(Generic[T, R]):
    """
    Generic class for parallel execution of tasks.
    Executes a given function on a list of items using a thread pool.
    """
    
    def __init__(self, worker_func: Callable[[T], R], items: List[T], max_workers: int = 5):
        """
        Initialize the parallel executor.
        
        Args:
            worker_func: Function to execute on each item
            items: List of items to process
            max_workers: Maximum number of concurrent threads
        """
        self.worker_func = worker_func
        self.items = items
        self.executor = None
        self.futures = []
        self.interrupted = False
        
        # Автоматически определяем оптимальное количество потоков, если не указано
        if max_workers <= 0:
            # Используем количество CPU + 1 для I/O-bound задач, но не более 16
            suggested_workers = min(os.cpu_count() + 1, 16) if os.cpu_count() else 5
            self.max_workers = suggested_workers
            logging.info(f"Auto-detected optimal worker count: {self.max_workers}")
        else:
            self.max_workers = max_workers
        
        self.results = []  # List to store results
        
        # Регистрируем обработчик сигнала SIGINT
        self.original_sigint_handler = signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGINT, self._handle_interrupt)
        
    def _handle_interrupt(self, sig, frame):
        """Обрабатывает сигнал прерывания (Ctrl+C)."""
        if self.interrupted:
            # Если это второй Ctrl+C, восстанавливаем оригинальный обработчик и выходим
            logging.warning("\nПолучен повторный сигнал прерывания. Принудительное завершение...")
            signal.signal(signal.SIGINT, self.original_sigint_handler)
            return
            
        logging.warning("\nПолучен сигнал прерывания (Ctrl+C). Отмена выполняемых задач...")
        self.interrupted = True
        
        # Отменяем все запущенные задачи
        if self.executor and self.futures:
            for future in self.futures:
                future.cancel()
        
    def execute(self) -> List[R]:
        """
        Execute tasks in parallel and return results.
        
        Returns:
            List of results from worker_func applied to each item
        """
        start_time = time.time()
        total_items = len(self.items)
        
        if total_items == 0:
            logging.warning("No items to process")
            return []
        
        logging.info(f"Starting parallel execution of {total_items} items with {self.max_workers} workers")
        
        # Используем ProcessPoolExecutor для CPU-bound задач на Unix-системах
        # и ThreadPoolExecutor для всех остальных случаев
        executor_class = concurrent.futures.ThreadPoolExecutor
        
        try:
            with executor_class(max_workers=self.max_workers) as executor:
                self.executor = executor
                
                # Создаем словарь future -> item для отслеживания прогресса
                future_to_item = {executor.submit(self.worker_func, item): item for item in self.items}
                self.futures = list(future_to_item.keys())
                
                # Обрабатываем результаты по мере их завершения
                completed = 0
                start_time_progress = time.time()
                last_progress_time = start_time_progress
                
                for future in concurrent.futures.as_completed(future_to_item):
                    if self.interrupted:
                        logging.warning("Выполнение прервано пользователем.")
                        break
                        
                    completed += 1
                    item = future_to_item[future]
                    
                    try:
                        if not future.cancelled():
                            result = future.result()
                            self.results.append(result)
                        
                        # Логируем прогресс с ограничением частоты обновлений
                        current_time = time.time()
                        time_since_last = current_time - last_progress_time
                        
                        # Показываем прогресс каждые 10 элементов или каждые 5 секунд
                        if completed % 10 == 0 or time_since_last >= 5 or completed == total_items:
                            elapsed = current_time - start_time_progress
                            rate = completed / elapsed if elapsed > 0 else 0
                            eta = (total_items - completed) / rate if rate > 0 else 0
                            
                            logging.info(f"Progress: {completed}/{total_items} ({completed/total_items*100:.1f}%), "
                                        f"Rate: {rate:.2f} items/sec, ETA: {eta:.1f} sec")
                            last_progress_time = current_time
                            
                    except concurrent.futures.CancelledError:
                        logging.debug(f"Task for item {str(item)[:30]}... was cancelled")
                    except Exception as e:
                        logging.error(f"Error processing item: {str(item)[:30]}...: {type(e).__name__}: {str(e)}")
        finally:
            # Восстанавливаем оригинальный обработчик сигнала
            signal.signal(signal.SIGINT, self.original_sigint_handler)
        
        elapsed = time.time() - start_time
        if self.interrupted:
            logging.info(f"Parallel execution interrupted after {elapsed:.2f} seconds, processed {len(self.results)}/{total_items} items")
        else:
            logging.info(f"Parallel execution completed in {elapsed:.2f} seconds, processed {len(self.results)} items")
        
        return self.results

def run_parallel_tests(
    configs: List[str], 
    test_func: Callable, 
    max_workers: int = 5, 
    advanced_mode: bool = False,
    **kwargs
) -> Dict[str, List[str]]:
    """
    Универсальная функция для параллельного запуска тестов.
    Работает как для URL-тестов, так и для расширенных тестов.
    
    Args:
        configs: Список строк конфигурации прокси
        test_func: Функция тестирования одной конфигурации
        max_workers: Максимальное количество параллельных потоков
        advanced_mode: Режим расширенного тестирования (True) или URL-тестирования (False)
        **kwargs: Дополнительные аргументы для test_func
        
    Returns:
        Dict с 'working' и 'failed' списками
    """
    if not configs:
        logging.warning("No configurations to test")
        return {"working": [], "failed": []}
    
    # Создаем функцию-обертку, которая включает kwargs
    def test_wrapper(config):
        return test_func(config, **kwargs)
    
    # Выполняем тесты параллельно
    executor = ParallelExecutor(test_wrapper, configs, max_workers)
    results = executor.execute()
    
    # Сортируем результаты на рабочие и неудачные
    working = []
    failed = []
    
    success_key = "overall_success" if advanced_mode else "success"
    
    for result in results:
        if result.get(success_key, False):
            working.append(result["config"])
        else:
            failed.append(result["config"])
    
    success_rate = len(working) / len(configs) * 100 if configs else 0
    
    # Выводим статистику
    test_type = "Advanced" if advanced_mode else "URL"
    logging.info(f"{test_type} testing completed: {len(working)}/{len(configs)} working ({success_rate:.1f}%)")
    
    return {
        "working": working,
        "failed": failed
    }

# Для обратной совместимости оставляем старые функции, но реализуем их через общую
def run_url_tests_parallel(configs: List[str], test_func: Callable, max_workers: int = 5, **kwargs) -> Dict[str, List[str]]:
    """
    Run URL tests on multiple configurations in parallel.
    
    Args:
        configs: List of proxy configuration strings
        test_func: Function that tests a single configuration
        max_workers: Maximum number of concurrent threads
        **kwargs: Additional arguments to pass to test_func
            test_url: URL or list of URLs to test with
            timeout: Request timeout in seconds
            singbox_path: Path to sing-box executable
            verbose: Enable verbose logging
            use_http_proxy: Use HTTP proxy instead of SOCKS5
        
    Returns:
        Dict with 'working' and 'failed' lists
    """
    return run_parallel_tests(configs, test_func, max_workers, advanced_mode=False, **kwargs)

def run_advanced_tests_parallel(configs: List[str], test_func: Callable, max_workers: int = 5, **kwargs) -> Dict[str, List[str]]:
    """
    Run advanced tests on multiple configurations in parallel.
    
    Args:
        configs: List of proxy configuration strings
        test_func: Function that tests a single configuration
        max_workers: Maximum number of concurrent threads
        **kwargs: Additional arguments to pass to test_func
        
    Returns:
        Dict with 'working' and 'failed' lists
    """
    return run_parallel_tests(configs, test_func, max_workers, advanced_mode=True, **kwargs) 