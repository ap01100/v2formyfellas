#!/usr/bin/env python3

import os
import re
import subprocess
import json
import base64
import time
import logging
import urllib.parse
import socket
import threading
import queue
import sys
import requests
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, parse_qs

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("v2ray_filter.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("v2ray_filter")

class V2RayConfig:
    def __init__(self, config_str):
        self.config_str = config_str.strip()
        self.protocol = self.config_str.split('://')[0] if '://' in self.config_str else None
        self.server = None
        self.port = None
        self.parsed = False
        self.tcp_ping_time = None
        self.in_ip = None
        self.out_ip = None
        self.parse_config()
    
    def parse_config(self):
        try:
            if self.protocol == 'vless' or self.protocol == 'trojan':
                # Extract server and port from vless/trojan URL
                match = re.search(r'@([^:]+):(\d+)', self.config_str)
                if match:
                    self.server = match.group(1)
                    self.port = int(match.group(2))
                    self.parsed = True
            elif self.protocol == 'vmess':
                # Extract and decode vmess config
                base64_part = self.config_str.split('://')[1]
                # Handle URL encoding in base64 string
                base64_part = urllib.parse.unquote(base64_part)
                # Remove any trailing remarks
                if '#' in base64_part:
                    base64_part = base64_part.split('#')[0]
                # Fix padding if needed
                padding = len(base64_part) % 4
                if padding:
                    base64_part += '=' * (4 - padding)
                
                try:
                    decoded = base64.b64decode(base64_part).decode('utf-8')
                    config_json = json.loads(decoded)
                    self.server = config_json.get('add')
                    self.port = int(config_json.get('port'))
                    self.parsed = True
                except Exception as e:
                    logger.error(f"Error decoding vmess config: {e}")
            elif self.protocol == 'ss':
                # Extract and decode shadowsocks config
                parts = self.config_str.split('://', 1)[1]
                if '#' in parts:
                    parts = parts.split('#')[0]
                
                if '@' in parts:
                    # Format: ss://base64(method:password)@server:port
                    server_part = parts.split('@')[1]
                    self.server = server_part.split(':')[0]
                    self.port = int(server_part.split(':')[1])
                else:
                    # Format: ss://base64(method:password@server:port)
                    try:
                        # Fix padding if needed
                        padding = len(parts) % 4
                        if padding:
                            parts += '=' * (4 - padding)
                        
                        decoded = base64.b64decode(parts).decode('utf-8')
                        if '@' in decoded:
                            server_part = decoded.split('@')[1]
                            self.server = server_part.split(':')[0]
                            self.port = int(server_part.split(':')[1])
                    except Exception as e:
                        logger.error(f"Error decoding ss config: {e}")
                
                self.parsed = bool(self.server and self.port)
        except Exception as e:
            logger.error(f"Error parsing config: {e}")
            self.parsed = False

    def __eq__(self, other):
        if not isinstance(other, V2RayConfig):
            return False
        return self.config_str == other.config_str

    def __hash__(self):
        return hash(self.config_str)


def remove_duplicates(configs):
    """Remove duplicate configurations while preserving original strings"""
    unique_configs = set()
    result = []
    
    for config in configs:
        v2ray_config = V2RayConfig(config)
        if v2ray_config.parsed and config not in unique_configs:
            unique_configs.add(config)
            result.append(config)
    
    logger.info(f"Removed duplicates: {len(configs) - len(result)} duplicates found")
    return result


def tcp_ping(host, port, timeout=3):
    """Test TCP connectivity to host:port and return connection time in ms or False on failure"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        start_time = time.time()
        result = sock.connect_ex((host, port))
        elapsed_time = (time.time() - start_time) * 1000  # Convert to ms
        sock.close()
        if result == 0:
            return elapsed_time
        return False
    except Exception as e:
        logger.debug(f"TCP ping error for {host}:{port} - {str(e)}")
        return False


def udp_ping(host, port, timeout=3):
    """
    Test UDP connectivity to host:port
    For different proxy protocols, we might need to send different packets
    """
    try:
        # Create a UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        
        # Send a more specific packet based on protocol standards
        # This is a generic message that might not be ideal for all protocols
        message = b'\x00\x01\x00\x00\x00\x01\x00\x00'  # Generic DNS-like query format
        sock.sendto(message, (host, port))
        
        # Try to receive a response
        try:
            data, addr = sock.recvfrom(1024)
            sock.close()
            return True
        except socket.timeout:
            # In UDP we can't know for sure if the port is open
            # We'll assume it's ok if we don't get an error from sending
            sock.close()
            return True
    except Exception as e:
        logger.debug(f"UDP ping error for {host}:{port} - {str(e)}")
        return False


def get_local_ip():
    """Get local IP address"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception as e:
        logger.error(f"Error getting local IP: {e}")
        return None


def get_public_ip_via_proxy(server, port, protocol, timeout=10):
    """Get public IP by routing through the proxy"""
    try:
        # Configure proxy based on protocol
        if protocol in ['http', 'https']:
            proxies = {
                'http': f'{protocol}://{server}:{port}',
                'https': f'{protocol}://{server}:{port}'
            }
        elif protocol == 'socks5':
            proxies = {
                'http': f'socks5://{server}:{port}',
                'https': f'socks5://{server}:{port}'
            }
        else:
            # For vmess, vless and other protocols,
            # we need external tools or libraries which is beyond this script
            # For now, we'll consider these protocols not supported for direct IP check
            logger.debug(f"Protocol {protocol} not directly supported for IP check via requests")
            return None
        
        # Make request through the proxy
        response = requests.get('https://api.ipify.org', proxies=proxies, timeout=timeout)
        if response.status_code == 200:
            return response.text.strip()
        return None
    except Exception as e:
        logger.debug(f"Error getting public IP via proxy {server}:{port}: {str(e)}")
        return None


def test_url_via_proxy(proxy_config, test_url="https://www.gstatic.com/generate_204", timeout=5):
    """
    Test if a URL is accessible through the proxy
    Returns True if connection successful and HTTP status is 200-299
    """
    protocol = proxy_config.protocol
    server = proxy_config.server
    port = proxy_config.port
    
    # For HTTP/HTTPS protocols we can use requests
    if protocol in ['http', 'https', 'socks5']:
        try:
            # Configure proxies
            if protocol in ['http', 'https']:
                proxies = {
                    'http': f'{protocol}://{server}:{port}',
                    'https': f'{protocol}://{server}:{port}'
                }
            else:  # socks5
                proxies = {
                    'http': f'socks5://{server}:{port}',
                    'https': f'socks5://{server}:{port}'
                }
            
            # Make request
            response = requests.get(test_url, proxies=proxies, timeout=timeout)
            # Check if status code is successful (2xx)
            return 200 <= response.status_code < 300
        except Exception as e:
            logger.debug(f"URL test via proxy error: {str(e)}")
            return False
    else:
        # For other protocols, we need to use external tools
        # Try to use curl with socks5 proxy as a fallback method
        try:
            # Prepare command: using curl with specified proxy
            # This is an approximation and may not work for all proxy types
            cmd = [
                "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                "--connect-timeout", str(timeout),
                "--socks5", f"{server}:{port}",
                test_url
            ]
            
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate(timeout=timeout+2)
            
            # Check if status code is successful (2xx)
            status_code = int(stdout.decode().strip())
            return 200 <= status_code < 300
        except Exception as e:
            logger.debug(f"Curl URL test error: {str(e)}")
            return False


def test_tcp_connectivity(configs, max_workers=10):
    """Test TCP connectivity for all configurations"""
    result = []
    total = len(configs)
    success = 0
    
    logger.info(f"Starting TCP connectivity test for {total} configurations")
    
    def worker(config):
        v2ray_config = V2RayConfig(config)
        if not v2ray_config.parsed:
            logger.warning(f"Skipping unparseable config: {config[:30]}...")
            return None
        
        ping_time = tcp_ping(v2ray_config.server, v2ray_config.port)
        if ping_time:
            v2ray_config.tcp_ping_time = ping_time
            # Return original config string with V2RayConfig object
            return config, v2ray_config
        return None
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(worker, config) for config in configs]
        for future in futures:
            try:
                res = future.result()
                if res:
                    result.append(res)
                    success += 1
            except Exception as e:
                logger.error(f"Error in TCP connectivity test: {e}")
    
    logger.info(f"TCP connectivity test completed: {success}/{total} configurations passed")
    return result


def test_url_connectivity(configs, max_workers=10):
    """Test URL connectivity for all configurations using the proper proxy method"""
    result = []
    total = len(configs)
    success = 0
    
    logger.info(f"Starting URL connectivity test for {total} configurations")
    
    def worker(config_tuple):
        config, v2ray_config = config_tuple
        
        # Test using standard URL that returns 204 (No Content) - mimicking sing-box behavior
        test_url = "https://www.gstatic.com/generate_204"
        
        # Try to test URL connectivity via proxy
        is_accessible = test_url_via_proxy(v2ray_config, test_url)
        
        if is_accessible:
            return config_tuple
        
        # Fallback: Try another test URL if the first one failed
        test_url = "https://www.google.com"
        is_accessible = test_url_via_proxy(v2ray_config, test_url)
        
        if is_accessible:
            return config_tuple
        return None
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(worker, config_tuple) for config_tuple in configs]
        for future in futures:
            try:
                res = future.result()
                if res:
                    result.append(res)
                    success += 1
            except Exception as e:
                logger.error(f"Error in URL connectivity test: {e}")
    
    logger.info(f"URL connectivity test completed: {success}/{total} configurations passed")
    return result


def final_test(configs, max_workers=10):
    """Perform final tests (TCP ping, UDP ping, and IP determination)"""
    result = []
    total = len(configs)
    success = 0
    
    logger.info(f"Starting final tests for {total} configurations")
    
    def worker(config_tuple):
        config, v2ray_config = config_tuple
        errors = 0
        
        # 1. TCP ping (again)
        tcp_ping_result = tcp_ping(v2ray_config.server, v2ray_config.port)
        if tcp_ping_result:
            v2ray_config.tcp_ping_time = tcp_ping_result  # Update ping time
        else:
            errors += 1
            logger.debug(f"TCP ping failed for {v2ray_config.server}:{v2ray_config.port}")
        
        # 2. UDP ping
        udp_ping_result = udp_ping(v2ray_config.server, v2ray_config.port)
        if not udp_ping_result:
            errors += 1
            logger.debug(f"UDP ping failed for {v2ray_config.server}:{v2ray_config.port}")
        
        # 3. Determine IN IP (local)
        v2ray_config.in_ip = get_local_ip()
        if not v2ray_config.in_ip:
            errors += 1
            logger.debug(f"Local IP determination failed")
        
        # 4. Try to get OUT IP (public) via proxy
        # This is just an attempt - we don't fail if it doesn't work
        # since direct proxy IP checks are complex for many proxy types
        public_ip = get_public_ip_via_proxy(
            v2ray_config.server, 
            v2ray_config.port, 
            v2ray_config.protocol
        )
        if public_ip:
            v2ray_config.out_ip = public_ip
        else:
            # We don't increment errors here as not all proxy types support direct IP checks
            v2ray_config.out_ip = "Unable to determine"
            logger.debug(f"Could not determine public IP via proxy")
        
        # 5. If critical errors, discard the configuration
        if errors > 0:
            return None
        
        return config, v2ray_config
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(worker, config_tuple) for config_tuple in configs]
        for future in futures:
            try:
                res = future.result()
                if res:
                    result.append(res)
                    success += 1
            except Exception as e:
                logger.error(f"Error in final test: {e}")
    
    logger.info(f"Final tests completed: {success}/{total} configurations passed")
    
    # 6. Sort by TCP ping time but keep original configs
    result.sort(key=lambda x: x[1].tcp_ping_time)
    
    # Return only the ORIGINAL config strings, preserving all details
    return [config for config, _ in result]


def main():
    input_file = "input_configs.txt"
    output_file = "output_configs.txt"
    
    logger.info("Starting V2Ray configuration filtering process")
    
    # Read configurations
    try:
        with open(input_file, 'r') as f:
            configs = [line.strip() for line in f if line.strip()]
        
        logger.info(f"Read {len(configs)} configurations from {input_file}")
        
        # Step 1: Remove duplicates
        configs = remove_duplicates(configs)
        logger.info(f"After removing duplicates: {len(configs)} configurations")
        
        # Step 2: TCP ping test with V2RayConfig objects
        configs = test_tcp_connectivity(configs)
        logger.info(f"After TCP ping test: {len(configs)} configurations")
        
        # Step 3: URL connectivity test - now properly testing through proxies
        configs = test_url_connectivity(configs)
        logger.info(f"After URL connectivity test: {len(configs)} configurations")
        
        # Step 4: Final test with sorting
        configs = final_test(configs)
        logger.info(f"After final tests: {len(configs)} configurations")
        
        # Write results to output file - original configurations only
        with open(output_file, 'w') as f:
            for config in configs:
                f.write(f"{config}\n")
        
        logger.info(f"Successfully wrote {len(configs)} valid configurations to {output_file}")
    
    except Exception as e:
        logger.error(f"An error occurred: {e}")


if __name__ == "__main__":
    main()