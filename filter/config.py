"""
Configuration module for the proxy testing project.
Contains all constants and configuration settings.
"""

# Default settings
DEFAULT_TEST_URLS = ["http://cp.cloudflare.com", "https://gemini.google.com"]  # List of URLs to test
MULTIPLE_URL_MODE = "all"  # Options: "all" (all URLs must work), "any" (at least one must work)
DEFAULT_TIMEOUT = 5  # Уменьшен таймаут с 10 до 5 секунд
DEFAULT_WORKERS = 5
MAX_WAIT_TIME = 15  # Maximum time to wait for sing-box to start
MAX_ERROR_OUTPUT_LEN = 1000  # Maximum length of error output to log
SOCKET_CHECK_INTERVAL = 0.2  # Interval between socket connection checks
DEFAULT_SS_METHOD = "aes-256-gcm"  # Default method for Shadowsocks

# Retry settings
MAX_RETRY_COUNT = 2  # Количество повторных попыток при ошибке
RETRY_DELAY = 1  # Задержка между повторными попытками в секундах

# Advanced test settings
DEFAULT_TCP_TEST_HOST = "8.8.8.8"  # Host for TCP Ping/Latency tests
DEFAULT_TCP_TEST_PORT = 53  # Port for TCP Ping/Latency tests
DEFAULT_TCP_TIMEOUT = 5  # Timeout for TCP tests in seconds
DEFAULT_IP_SERVICE_URL = "https://api.ipify.org?format=json"  # Service for external IP detection
DEFAULT_IP_SERVICE_TIMEOUT = 10  # Timeout for IP service request
DEFAULT_WORKERS_ADVANCED = 5  # Number of threads for advanced testing

# System settings
SINGBOX_EXECUTABLE = "D:\nekoray\v2formyfellas\bin\sing-box.exe"  # Auto-updated by setup.py
ADVANCED_TEST_SCRIPT = "advanced_test.py"  # Assuming it's in the same directory

# User agent for HTTP requests
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36'