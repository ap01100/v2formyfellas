"""
Parallel execution module for proxy tests.
Handles concurrent testing of multiple proxy configurations.
"""

import concurrent.futures
import logging
import time
from typing import List, Dict, Any, Callable, TypeVar, Generic

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
        self.max_workers = max_workers
        self.results = []  # List to store results
        
    def execute(self) -> List[R]:
        """
        Execute tasks in parallel and return results.
        
        Returns:
            List of results from worker_func applied to each item
        """
        start_time = time.time()
        total_items = len(self.items)
        
        logging.info(f"Starting parallel execution of {total_items} items with {self.max_workers} workers")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Create a future for each item
            future_to_item = {executor.submit(self.worker_func, item): item for item in self.items}
            
            # Process results as they complete
            completed = 0
            for future in concurrent.futures.as_completed(future_to_item):
                completed += 1
                item = future_to_item[future]
                
                try:
                    result = future.result()
                    self.results.append(result)
                    
                    # Log progress
                    if completed % 10 == 0 or completed == total_items:
                        elapsed = time.time() - start_time
                        rate = completed / elapsed if elapsed > 0 else 0
                        eta = (total_items - completed) / rate if rate > 0 else 0
                        logging.info(f"Progress: {completed}/{total_items} ({completed/total_items*100:.1f}%), "
                                     f"Rate: {rate:.2f} items/sec, ETA: {eta:.1f} sec")
                        
                except Exception as e:
                    logging.error(f"Error processing item: {item}: {type(e).__name__}: {str(e)}")
        
        elapsed = time.time() - start_time
        logging.info(f"Parallel execution completed in {elapsed:.2f} seconds, processed {len(self.results)} items")
        return self.results

def run_url_tests_parallel(configs: List[str], test_func: Callable, max_workers: int = 5, **kwargs) -> Dict[str, List[str]]:
    """
    Run URL tests on multiple configurations in parallel.
    
    Args:
        configs: List of proxy configuration strings
        test_func: Function that tests a single configuration
        max_workers: Maximum number of concurrent threads
        **kwargs: Additional arguments to pass to test_func
        
    Returns:
        Dict with 'working' and 'failed' lists
    """
    if not configs:
        logging.warning("No configurations to test")
        return {"working": [], "failed": []}
    
    # Create a wrapper function that includes kwargs
    def test_wrapper(config):
        return test_func(config, **kwargs)
    
    # Execute tests in parallel
    executor = ParallelExecutor(test_wrapper, configs, max_workers)
    results = executor.execute()
    
    # Sort results into working and failed
    working = []
    failed = []
    
    for result in results:
        if result.get("success", False):
            working.append(result["config"])
        else:
            failed.append(result["config"])
    
    success_rate = len(working) / len(configs) * 100 if configs else 0
    logging.info(f"Testing completed: {len(working)}/{len(configs)} working ({success_rate:.1f}%)")
    
    return {
        "working": working,
        "failed": failed
    }

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
    if not configs:
        logging.warning("No configurations to test")
        return {"working": [], "failed": []}
    
    # Create a wrapper function that includes kwargs
    def test_wrapper(config):
        return test_func(config, **kwargs)
    
    # Execute tests in parallel
    executor = ParallelExecutor(test_wrapper, configs, max_workers)
    results = executor.execute()
    
    # Sort results into working and failed
    working = []
    failed = []
    
    for result in results:
        if result.get("overall_success", False):
            working.append(result["config"])
        else:
            failed.append(result["config"])
    
    success_rate = len(working) / len(configs) * 100 if configs else 0
    logging.info(f"Advanced testing completed: {len(working)}/{len(configs)} working ({success_rate:.1f}%)")
    
    return {
        "working": working,
        "failed": failed
    } 