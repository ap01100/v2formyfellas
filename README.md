# v2formyfellas

## Subscription Link
**all in one**:
```bash
https://raw.githubusercontent.com/ap01100/v2formyfellas/refs/heads/main/configs.txt
```

And tool for testing and filtering working proxy configurations for various protocols (Shadowsocks, Trojan, VMess, VLESS).

## Features

- URL Testing: checks the ability of a proxy connection to load a specified URL
- Advanced Testing: tests TCP connections and determines the outbound IP address
- Parallel test execution for increased speed
- Support for multiple proxy protocols (SS, Trojan, VMess, VLESS)
- Consolidated command-line interface for all types of testing
- **Улучшенная поддержка Windows** - работает без netcat, автоматический поиск sing-box
- **Оптимизированное параллельное выполнение** - автоопределение оптимального числа потоков
- **Автоматическая установка** - скрипт setup.py для установки зависимостей и sing-box

## Requirements

- Python 3.6+
- sing-box (https://github.com/SagerNet/sing-box)
- Python dependencies: requests, PySocks

## Installation

### Automatic Installation (Recommended)

Run the setup script to install dependencies and configure sing-box:

```bash
python setup.py
```

### Manual Installation

1. Clone the repository:
```bash
git clone https://github.com/ap01100/v2formyfellas.git
cd v2formyfellas
```

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

3. Make sure sing-box is installed and available in PATH or specify its path when running.

4. For advanced testing on Unix systems, install netcat:
```bash
# Ubuntu/Debian
sudo apt install netcat-traditional
# or
sudo apt install netcat-openbsd
```

## Usage

### Basic URL Testing

```bash
python filter/main.py input.txt -o working.txt
```

### Advanced Testing

```bash
python filter/main.py input.txt -o working.txt -a
```

### Combined Testing (URL, then Advanced)

```bash
python filter/main.py input.txt -o advanced_working.txt --url-then-advanced --temp-file url_working.txt
```

### Windows Users

See [WINDOWS_README.md](WINDOWS_README.md) for detailed Windows-specific instructions.

### Command Line Parameters

```
usage: main.py [-h] [-o OUTPUT_FILE] [-ao APPEND_OUTPUT] [-u URL]
               [--urls-file URLS_FILE] [--url-mode {all,any}] [-t TIMEOUT]
               [-w WORKERS] [-a] [--tcp-host TCP_HOST] [--tcp-port TCP_PORT]
               [--tcp-timeout TCP_TIMEOUT] [--ip-service-url IP_SERVICE_URL]
               [--ip-service-timeout IP_SERVICE_TIMEOUT]
               [--advanced-workers ADVANCED_WORKERS] [--singbox-path SINGBOX_PATH]
               [-v] [--no-dedup] [--advanced-dedup] [--url-then-advanced]
               [--temp-file TEMP_FILE]
               input_file

Test proxy configurations using URL testing and advanced testing.

positional arguments:
  input_file            File containing proxy configurations to test

options:
  -h, --help            show this help message and exit
  -o OUTPUT_FILE, --output-file OUTPUT_FILE
                        File to save working configurations
  -ao APPEND_OUTPUT, --append-output APPEND_OUTPUT
                        Append working configurations to this file instead of overwriting
  -u URL, --url URL     URL to test proxies against (can be specified multiple times)
  --urls-file URLS_FILE
                        Path to a file containing URLs to test, one URL per line
  --url-mode {all,any}  URL testing mode: 'all' means all URLs must work, 'any' means at least one URL must work
  -t TIMEOUT, --timeout TIMEOUT
                        Request timeout in seconds
  -w WORKERS, --workers WORKERS
                        Number of concurrent testing workers
  -a, --advanced        Perform advanced tests (TCP, IP) on configurations
  --tcp-host TCP_HOST   Host for TCP tests in advanced mode
  --tcp-port TCP_PORT   Port for TCP tests in advanced mode
  --tcp-timeout TCP_TIMEOUT
                        Timeout for TCP tests in advanced mode
  --ip-service-url IP_SERVICE_URL
                        URL for IP detection service in advanced mode
  --ip-service-timeout IP_SERVICE_TIMEOUT
                        Timeout for IP service requests in advanced mode
  --advanced-workers ADVANCED_WORKERS
                        Number of concurrent workers for advanced testing
  --singbox-path SINGBOX_PATH
                        Path to sing-box executable
  -v, --verbose         Enable verbose logging (DEBUG level)
  --no-dedup            Skip deduplication of input configurations
  --advanced-dedup      Use advanced deduplication (ignores configuration names during comparison)
  --url-then-advanced   Run URL testing first, then advanced testing on working configurations
  --temp-file TEMP_FILE Temporary file to store intermediate results from URL testing
```

## Project Structure

- `main.py` - main script for running tests
- `config.py` - configuration constants
- `utils.py` - common utilities
- `parsers.py` - configuration parsers for different protocols
- `url_tester.py` - URL testing module
- `advanced_tester.py` - advanced testing module (TCP, IP)
- `parallel.py` - utilities for parallel execution
- `setup.py` - installation and setup script

## Extension

To add support for new proxy protocols:

1. Add a parser function in `parsers.py`
2. Update the `parser_map` dictionary in the `convert_to_singbox_config` function

# Visitors
![Visitors count](https://profile-counter.glitch.me/ap01100_v2rayformyfellas/count.svg)
