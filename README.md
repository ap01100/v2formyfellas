# v2formyfellas

A tool for testing and filtering working proxy configurations for various protocols (Shadowsocks, Trojan, VMess, VLESS).

## Subscription Link

**All-in-one**:
```bash
https://raw.githubusercontent.com/ap01100/v2formyfellas/refs/heads/main/configs.txt
```

## Features

- URL Testing: checks the ability of a proxy connection to load a specified URL
- Advanced Testing: tests TCP connections and determines the outbound IP address
- Parallel test execution for increased speed
- Support for multiple proxy protocols (SS, Trojan, VMess, VLESS)
- Consolidated command-line interface for all types of testing
- Windows support - works without netcat, automatic sing-box detection
- Optimized parallel execution - automatic determination of optimal thread count
- Automatic installation - setup.py script for installing dependencies and sing-box

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

### Running All Tests (Recommended)

Use the unified script to download configurations and run all tests:

```bash
python run_all.py
```

Options:
```
  -s SOURCES, --sources SOURCES
                        File with list of configuration sources
  -w WORKERS, --workers WORKERS
                        Number of parallel workers for testing
  --singbox-path SINGBOX_PATH
                        Path to sing-box executable
  --skip-download       Skip configuration download step
  --skip-url-test       Skip URL testing step
  --skip-advanced-test  Skip advanced testing step
  -v, --verbose         Verbose output
```

### Download Configurations

```bash
python -m filter download -s sources.txt -o configs.txt
```

### Basic URL Testing

```bash
python -m filter test configs.txt -o working.txt
```

### Advanced Testing

```bash
python -m filter test configs.txt -o working.txt -a
```

### Command Line Parameters

```
usage: filter test [-h] [-o OUTPUT_FILE] [-ao APPEND_OUTPUT] [-u URL]
               [--urls-file URLS_FILE] [--url-mode {all,any}] [-t TIMEOUT]
               [-w WORKERS] [-a] [--tcp-host TCP_HOST] [--tcp-port TCP_PORT]
               [--tcp-timeout TCP_TIMEOUT] [--ip-service-url IP_SERVICE_URL]
               [--ip-service-timeout IP_SERVICE_TIMEOUT]
               [--advanced-workers ADVANCED_WORKERS] [--singbox-path SINGBOX_PATH]
               [-v] [--no-dedup] [--advanced-dedup] [--url-then-advanced]
               [--temp-file TEMP_FILE]
               input_file
```

## Windows-specific Instructions

### Troubleshooting on Windows

#### "sing-box not found"
**Solution**: Specify the full path to sing-box.exe using the `--singbox-path` parameter:
```
python filter\main.py input.txt -o working.txt --singbox-path "C:\path\to\sing-box.exe"
```

#### "Port access error"
**Solution**: Run Command Prompt or PowerShell as administrator.

#### "Windows Firewall blocks connection"
**Solution**: Allow sing-box.exe in Windows Firewall.

#### "Antivirus blocks sing-box"
**Solution**: Add an exception for sing-box.exe in your antivirus.

### Performance Optimization on Windows

1. Increase the number of worker threads if you have a multi-core processor:
   ```
   python filter\main.py input.txt -o working.txt -w 8
   ```

2. Use "any" mode for URL testing so that a configuration is considered working if at least one URL is accessible:
   ```
   python filter\main.py input.txt -o working.txt --url-mode any
   ```

3. For large files, use advanced deduplication:
   ```
   python filter\main.py input.txt -o working.txt --advanced-dedup
   ```

## Project Structure

- `run_all.py` - unified script for running all operations
- `filter/` - main package
  - `__main__.py` - entry point with command-line interface
  - `main.py` - main testing script
  - `download.py` - configuration download script
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
