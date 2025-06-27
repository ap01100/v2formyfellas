#!/usr/bin/env python3
"""
Script for downloading and processing proxy configurations.
Supports downloading from URLs, decoding Base64, and processing subscriptions.
"""

import os
import sys
import argparse
import logging
import requests
import base64
import re
import time
from urllib.parse import urlparse
from typing import List, Set

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def is_base64(text: str) -> bool:
    """Checks if a string is Base64 encoded."""
    pattern = r'^[A-Za-z0-9+/]+={0,2}$'
    return bool(re.match(pattern, text)) and len(text) % 4 == 0

def decode_base64(encoded_text: str) -> str:
    """Decodes a Base64 string."""
    try:
        # Add missing padding if needed
        padding = 4 - len(encoded_text) % 4
        if padding != 4:
            encoded_text += '=' * padding
            
        decoded_bytes = base64.b64decode(encoded_text)
        return decoded_bytes.decode('utf-8')
    except Exception as e:
        logging.error(f"Base64 decoding error: {e}")
        return ""

def download_from_url(url: str) -> str:
    """Downloads content from a URL."""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        logging.error(f"Error downloading from {url}: {e}")
        return ""

def process_content(content: str) -> List[str]:
    """Processes content, extracting and decoding configurations."""
    configs = []
    
    # Split by lines
    lines = content.strip().split('\n')
    
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
            
        # Check if the line is a proxy configuration URL
        if line.startswith(('ss://', 'vmess://', 'trojan://', 'vless://')):
            configs.append(line)
        # Check if the line is Base64 encoded
        elif is_base64(line):
            decoded = decode_base64(line)
            if decoded:
                # Process decoded content recursively
                decoded_configs = process_content(decoded)
                configs.extend(decoded_configs)
    
    return configs

def process_subscription(url: str) -> List[str]:
    """Processes a subscription URL."""
    content = download_from_url(url)
    if not content:
        return []
    
    # Try to decode as Base64 if it's a subscription
    if is_base64(content):
        decoded_content = decode_base64(content)
        if decoded_content:
            content = decoded_content
    
    return process_content(content)

def save_configs(configs: List[str], output_file: str):
    """Saves configurations to a file."""
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            for config in configs:
                f.write(f"{config}\n")
        logging.info(f"Saved {len(configs)} configurations to {output_file}")
    except IOError as e:
        logging.error(f"Error saving to file {output_file}: {e}")

def process_sources_file(sources_file: str) -> List[str]:
    """Processes a file with sources (URLs or file paths)."""
    configs = []
    
    try:
        with open(sources_file, 'r', encoding='utf-8') as f:
            sources = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
        
        for source in sources:
            logging.info(f"Processing source: {source}")
            
            if source.startswith(('http://', 'https://')):
                # Process as URL
                source_configs = process_subscription(source)
                configs.extend(source_configs)
                logging.info(f"Retrieved {len(source_configs)} configurations from {source}")
            else:
                # Process as local file
                try:
                    with open(source, 'r', encoding='utf-8') as f:
                        content = f.read()
                    source_configs = process_content(content)
                    configs.extend(source_configs)
                    logging.info(f"Retrieved {len(source_configs)} configurations from file {source}")
                except IOError as e:
                    logging.error(f"Error reading file {source}: {e}")
    
    except IOError as e:
        logging.error(f"Error reading sources file {sources_file}: {e}")
    
    return configs

def remove_duplicates(configs: List[str]) -> List[str]:
    """Removes duplicate configurations."""
    unique_configs = []
    seen = set()
    
    for config in configs:
        if config not in seen:
            seen.add(config)
            unique_configs.append(config)
    
    logging.info(f"Removed {len(configs) - len(unique_configs)} duplicates")
    return unique_configs

def main():
    parser = argparse.ArgumentParser(description="Downloads and processes proxy configurations")
    
    # Source group (mutually exclusive)
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument('-u', '--url', help="URL to download configurations from")
    source_group.add_argument('-f', '--file', help="Local file with configurations")
    source_group.add_argument('-s', '--sources', help="File with a list of sources (URLs or file paths)")
    
    parser.add_argument('-o', '--output', required=True, help="Output file to save configurations to")
    parser.add_argument('-a', '--append', action='store_true', help="Append to existing file instead of overwriting")
    parser.add_argument('-v', '--verbose', action='store_true', help="Verbose output")
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Get configurations from the specified source
    configs = []
    
    if args.url:
        logging.info(f"Downloading configurations from URL: {args.url}")
        configs = process_subscription(args.url)
    elif args.file:
        logging.info(f"Reading configurations from file: {args.file}")
        try:
            with open(args.file, 'r', encoding='utf-8') as f:
                content = f.read()
            configs = process_content(content)
        except IOError as e:
            logging.error(f"Error reading file {args.file}: {e}")
            return 1
    elif args.sources:
        logging.info(f"Processing sources from file: {args.sources}")
        configs = process_sources_file(args.sources)
    
    # Remove duplicates
    configs = remove_duplicates(configs)
    logging.info(f"Total unique configurations: {len(configs)}")
    
    # If --append flag is specified and the file exists, append to existing configurations
    if args.append and os.path.exists(args.output):
        try:
            with open(args.output, 'r', encoding='utf-8') as f:
                existing_configs = [line.strip() for line in f if line.strip()]
            
            # Combine and remove duplicates
            combined = existing_configs + configs
            configs = remove_duplicates(combined)
            
            logging.info(f"Combined with existing file. Total: {len(configs)} configurations")
        except IOError as e:
            logging.error(f"Error reading existing file {args.output}: {e}")
    
    # Save results
    save_configs(configs, args.output)
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 