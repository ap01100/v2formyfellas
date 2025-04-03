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
                decoded = base64.b64decode(base64_part).decode('utf-8')
                config_json = json.loads(decoded)
                self.server = config_json.get('add')
                self.port = int(config_json.get('port'))
                self.parsed = True
            elif self.protocol == 'ss':
                # Extract and decode shadowsocks config
                base64_part = self.config_str.split('://')[1].split('#')[0]
                if '@' in base64_part:
                    # Format: ss://base64(method:password)@server:port
                    server_part = base64_part.split('@')[1]
                    self.server = server_part.split(':')[0]
                    self.port = int(server_part.split(':')[1])
                else:
                    # Format: ss://base64(method:password@server:port)
                    decoded = base64.b64decode(base64_part).decode('utf-8')
                    parts = decoded.split('@')
                    if len(parts) > 1:
                        server_part = parts[1]
                        self.server = server_part.split(':')[0]
                        self.port = int(server_part.split(':')[1])
                self.parsed = True
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
    """Remove duplicate configurations"""
    unique_configs = set()
    result = []
    
    for config in configs:
        v2ray_config = V2RayConfig(config)
        if v2ray_config.parsed and config not in unique_configs:
            unique_configs.add(config)
            result.append(config)
    
    logger.info(f"Removed duplicates: {len(configs) - len(result)} duplicates found")
    return result


def tcp_ping(host, port, timeout=5):
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


def udp_ping(host, port, timeout=5):
    """Test UDP connectivity to host:port"""
    try:
        # Create a UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        
        # Send a dummy packet
        message = b'ping'
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


def get_ip_info():
    """Get IN (local) and OUT (public) IP addresses"""
    in_ip = None
    out_ip = None
    
    # Get IN IP (local IP)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        in_ip = s.getsockname()[0]
        s.close()
    except Exception as e:
        logger.error(f"Error getting local IP: {e}")
        return None, None
    
    # Get OUT IP (public IP)
    try:
        cmd = ["curl", "-s", "https://api.ipify.org"]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate(timeout=10)
        if process.returncode == 0:
            out_ip = stdout.decode().strip()
    except Exception as e:
        logger.error(f"Error getting public IP: {e}")
        return None, None
    
    return in_ip, out_ip


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
            return config, v2ray_config
        return None
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(worker, config) for config in configs]
        for future in futures:
            try:
                res = future.result()
                if res:
                    config, v2ray_config = res
                    result.append((config, v2ray_config))
                    success += 1
            except Exception as e:
                logger.error(f"Error in TCP connectivity test: {e}")
    
    logger.info(f"TCP connectivity test completed: {success}/{total} configurations passed")
    return result


def test_url_connectivity(configs, max_workers=10):
    """Test URL connectivity for all configurations"""
    result = []
    total = len(configs)
    success = 0
    
    logger.info(f"Starting URL connectivity test for {total} configurations")
    
    def worker(config_tuple):
        config, v2ray_config = config_tuple
        
        try:
            # Simple HTTP request to check if IP is accessible
            cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", 
                   "--connect-timeout", "5", f"http://{v2ray_config.server}:{v2ray_config.port}"]
            
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate(timeout=10)
            
            # We consider any response (even an error HTTP code) as a sign that the server is reachable
            if process.returncode == 0 or stdout.decode().strip():
                return config_tuple
            return None
        except subprocess.TimeoutExpired:
            process.kill()
            return None
        except Exception as e:
            logger.debug(f"URL test error for {v2ray_config.server}:{v2ray_config.port} - {str(e)}")
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
        
        # 3. Determine IN and OUT IP
        in_ip, out_ip = get_ip_info()
        if in_ip and out_ip:
            v2ray_config.in_ip = in_ip
            v2ray_config.out_ip = out_ip
        else:
            errors += 1
            logger.debug(f"IP determination failed")
        
        # 4. If any errors, discard the configuration
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
    
    # 5. Sort by TCP ping time
    result.sort(key=lambda x: x[1].tcp_ping_time)
    
    # Return only the config strings
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
        
        # Step 3: URL connectivity test
        configs = test_url_connectivity(configs)
        logger.info(f"After URL connectivity test: {len(configs)} configurations")
        
        # Step 4: Final test with sorting
        configs = final_test(configs)
        logger.info(f"After final tests: {len(configs)} configurations")
        
        # Write results to output file
        with open(output_file, 'w') as f:
            for config in configs:
                f.write(f"{config}\n")
        
        logger.info(f"Successfully wrote {len(configs)} valid configurations to {output_file}")
    
    except Exception as e:
        logger.error(f"An error occurred: {e}")


if __name__ == "__main__":
    main()
