"""
Proxy configuration parsers module.
Contains parsers for different proxy protocols (SS, Trojan, VMess, VLESS).
"""

import json
import base64
import urllib.parse
import re
import logging
from typing import Dict, Any
from filter.config import DEFAULT_SS_METHOD

def parse_ss_config(config_str: str) -> Dict[str, Any]:
    """Parses Shadowsocks configuration (ss://)."""
    parsed = urllib.parse.urlparse(config_str)
    user_info_part = parsed.netloc.split('@')[0]
    server_part = parsed.netloc.split('@')[1] if '@' in parsed.netloc else parsed.netloc
    
    # Make sure server_part contains host:port format
    if ':' not in server_part:
        raise ValueError(f"Invalid server part in SS URL: {server_part}, missing port")
    
    host, port_str = server_part.split(':')
    port = int(port_str)
    method = None
    password = None
    
    # Check if user_info_part looks like a UUID
    uuid_pattern = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE)
    hex_pattern = re.compile(r'^[0-9a-f]+$', re.IGNORECASE)
    
    if uuid_pattern.match(user_info_part):
        # If it's a UUID, use it as the password and set default method
        logging.debug(f"UUID detected as password for SS: {user_info_part}")
        method = DEFAULT_SS_METHOD
        password = user_info_part
    elif hex_pattern.match(user_info_part) and len(user_info_part) >= 32:
        # If it's a hex string (common for some SS implementations)
        logging.debug(f"Hex string detected as password for SS: {user_info_part}")
        method = DEFAULT_SS_METHOD
        password = user_info_part
    else:
        try:
            # Add proper padding for base64 decoding
            padding_needed = len(user_info_part) % 4
            if padding_needed:
                user_info_part += '=' * (4 - padding_needed)
            
            decoded_user_info = base64.urlsafe_b64decode(user_info_part).decode('utf-8')
            
            # Check if decoded string is JSON
            if decoded_user_info.startswith('{') and decoded_user_info.endswith('}'):
                try:
                    json_config = json.loads(decoded_user_info)
                    # Process JSON configuration (in VMess format but passed via SS)
                    method = json_config.get("scy", DEFAULT_SS_METHOD)
                    password = json_config.get("id", "")
                    if json_config.get("add"):
                        host = json_config.get("add")
                    if json_config.get("port"):
                        port = int(json_config.get("port"))
                    remark = json_config.get("ps", host)
                    
                    return {
                        "type": "shadowsocks", "tag": f"ss-out-{remark[:10]}", "server": host,
                        "server_port": port, "method": method, "password": password,
                    }
                except json.JSONDecodeError as e:
                    raise ValueError(f"Failed to parse SS JSON configuration: {e}")
            else:
                # Standard method:password format
                if ':' in decoded_user_info:
                    method, password = decoded_user_info.split(':', 1)
                else:
                    # If no colon, assume it's just a password
                    password = decoded_user_info
                    method = DEFAULT_SS_METHOD
        except (base64.binascii.Error, ValueError, UnicodeDecodeError):
            logging.info(f"Failed to decode user_info '{user_info_part}' as base64 for SS, trying other formats")
            try:
                # Try method:password format without base64
                if ':' in user_info_part:
                    method, password = user_info_part.split(':', 1)
                else:
                    # If not UUID and no ':', assume it's just a password (not in base64)
                    password = user_info_part
                    method = DEFAULT_SS_METHOD
                    logging.info(f"SS method not found, using default: {method}")
            except Exception as inner_e:
                logging.error(f"Failed to determine SS method/password from '{user_info_part}'. Error: {inner_e}")
                raise ValueError(f"Failed to extract SS method/password from '{user_info_part}'")

    if not method or not password:
        raise ValueError("Failed to extract SS method or password")

    remark = urllib.parse.unquote(parsed.fragment) if parsed.fragment else host
    return {
        "type": "shadowsocks", "tag": f"ss-out-{remark[:10]}", "server": host,
        "server_port": port, "method": method, "password": password,
    }

def parse_trojan_config(config_str: str) -> Dict[str, Any]:
    """Parses Trojan configuration (trojan://)."""
    parsed = urllib.parse.urlparse(config_str)
    password = parsed.username if parsed.username else parsed.netloc.split('@')[0]
    server_part = parsed.netloc.split('@')[1] if '@' in parsed.netloc else parsed.netloc
    host, port_str = server_part.split(':')
    port = int(port_str)
    remark = urllib.parse.unquote(parsed.fragment) if parsed.fragment else host
    query_params = urllib.parse.parse_qs(parsed.query)
    sni = query_params.get('sni', [query_params.get('peer', [host])[0]])[0]  # 'peer' as synonym for sni

    outbound = {
        "type": "trojan", "tag": f"trojan-out-{remark[:10]}", "server": host,
        "server_port": port, "password": password,
        "tls": {
            "enabled": True, "server_name": sni,
            "insecure": query_params.get('allowInsecure', ['0'])[0] == '1',
            "alpn": query_params.get('alpn', [None])[0].split(',') if query_params.get('alpn', [None])[0] else None,
        }
    }
    transport_type = query_params.get('type', ['tcp'])[0]
    if transport_type == 'ws':
        ws_settings = {
             "type": "ws",
             "path": query_params.get('path', ['/'])[0],
             "headers": {"Host": query_params.get('host', [sni])[0]}  # Use sni if host not provided
        }
        outbound["transport"] = ws_settings
    elif transport_type == 'grpc':
         grpc_settings = {
            "type": "grpc",
            "service_name": query_params.get('serviceName', [''])[0],
         }
         outbound["transport"] = grpc_settings
    elif transport_type != 'tcp':
        logging.warning(f"Transport type '{transport_type}' for Trojan is not fully supported in this parser.")
    return outbound

def parse_vmess_config(config_str: str) -> Dict[str, Any]:
   """Parses VMess configuration (vmess://)."""
   try:
        encoded_json = config_str.replace("vmess://", "").strip()
        padding = "=" * (4 - len(encoded_json) % 4)
        decoded_json = base64.b64decode(encoded_json + padding).decode('utf-8')
        vmess_params = json.loads(decoded_json)
   except Exception as e:
       raise ValueError(f"Error decoding VMess JSON: {e}")

   remark = vmess_params.get("ps", vmess_params.get("add", "vmess"))
   host = vmess_params.get("add")
   port = int(vmess_params.get("port", 443))

   outbound = {
        "type": "vmess", "tag": f"vmess-out-{remark[:10]}", "server": host,
        "server_port": port, "uuid": vmess_params.get("id"),
        "security": vmess_params.get("scy", vmess_params.get("security", "auto")),
        "alter_id": int(vmess_params.get("aid", 0)),
   }

   # Инициализируем sni до условного блока
   sni = vmess_params.get("sni", vmess_params.get("host", host))  # SNI defaults to host or add
   
   tls_enabled = vmess_params.get("tls", "") == "tls"
   if tls_enabled:
        outbound["tls"] = {
            "enabled": True, "server_name": sni,
            "insecure": str(vmess_params.get("allowInsecure", vmess_params.get("allow_insecure", "false"))).lower() == "true",
            "alpn": vmess_params.get('alpn', '').split(',') if vmess_params.get('alpn') else None,
        }

   net_type = vmess_params.get("net", "tcp")
   if net_type != "tcp":
         transport = {"type": net_type}
         if net_type == "ws":
             transport["path"] = vmess_params.get("path", "/")
             ws_host = vmess_params.get("host", sni)  # Use host from vmess or sni
             if ws_host:
                 transport["headers"] = {"Host": ws_host}
         elif net_type == "grpc":
             transport["service_name"] = vmess_params.get("path", vmess_params.get("serviceName", ""))
         outbound["transport"] = transport
   return outbound

def parse_vless_config(config_str: str) -> Dict[str, Any]:
    """Parses VLESS configuration (vless://)."""
    parsed = urllib.parse.urlparse(config_str)
    uuid = parsed.username if parsed.username else parsed.netloc.split('@')[0]
    server_part = parsed.netloc.split('@')[1] if '@' in parsed.netloc else parsed.netloc
    host, port_str = server_part.split(':')
    port = int(port_str)
    remark = urllib.parse.unquote(parsed.fragment) if parsed.fragment else host
    query_params = urllib.parse.parse_qs(parsed.query)

    outbound = {
        "type": "vless", "tag": f"vless-out-{remark[:10]}", "server": host,
        "server_port": port, "uuid": uuid,
        "flow": query_params.get('flow', [None])[0],
    }

    security = query_params.get('security', ['none'])[0]
    sni = query_params.get('sni', [host])[0]  # SNI defaults to host
    fp = query_params.get('fp', [None])[0]  # Fingerprint

    if security == 'tls' or security == 'reality':
        tls_settings = {
            "enabled": True, "server_name": sni,
            "insecure": query_params.get('allowInsecure', ['0'])[0] == '1',
            "alpn": query_params.get('alpn', [None])[0].split(',') if query_params.get('alpn', [None])[0] else None,
        }
        if security == 'reality':
            reality_opts = {
                 "enabled": True,
                 "public_key": query_params.get('pbk', [None])[0],
                 "short_id": query_params.get('sid', [None])[0],
            }
            if fp: reality_opts["fingerprint"] = fp
            tls_settings["reality"] = reality_opts
        else:  # Just TLS
             if fp:
                 # For sing-box, fingerprint is usually inside utls
                 tls_settings["utls"] = {"enabled": True, "fingerprint": fp}

        outbound["tls"] = tls_settings

    transport_type = query_params.get('type', ['tcp'])[0]
    if transport_type != 'tcp':
        transport = {"type": transport_type}
        if transport_type == 'ws':
            transport["path"] = query_params.get('path', ['/'])[0]
            # Host for WS is from 'host' parameter or sni
            transport["headers"] = {"Host": query_params.get('host', [sni])[0]}
        elif transport_type == 'grpc':
             transport["service_name"] = query_params.get('serviceName', [''])[0]
        # Other transports (h2, quic) can be added similarly
        outbound["transport"] = transport

    return outbound

def convert_to_singbox_config(config_str: str, socks_port: int, log_level: str = "warn") -> Dict[str, Any]:
    """Converts a configuration string to sing-box JSON format."""
    base_config = {
        "log": {"level": log_level, "timestamp": True},
        "inbounds": [{
            "type": "socks", "tag": "socks-in", "listen": "127.0.0.1",
            "listen_port": socks_port, "sniff": True,
            "sniff_override_destination": True, "users": []
        }],
        "outbounds": []
    }
    parser_map = {
        "ss://": parse_ss_config, "trojan://": parse_trojan_config,
        "vmess://": parse_vmess_config, "vless://": parse_vless_config,
    }
    parsed_outbound = None
    protocol_parsed = "unknown"
    for prefix, parser in parser_map.items():
        if config_str.startswith(prefix):
            protocol_parsed = prefix.replace("://", "")
            try:
                parsed_outbound = parser(config_str)
                logging.debug(f"Successfully parsed as {protocol_parsed}: {config_str[:40]}...")
                break
            except Exception as e:
                logging.error(f"Error parsing '{config_str[:40]}...' as {protocol_parsed}: {e}", exc_info=False)
                raise ValueError(f"Error parsing {protocol_parsed} configuration: {e}") from e
    if not parsed_outbound:
        raise ValueError(f"Unsupported or invalid protocol: {config_str[:40]}...")

    base_config["outbounds"].append(parsed_outbound)
    base_config["outbounds"].append({"type": "direct", "tag": "direct"})  # Keep direct
    base_config["outbounds"].append({"type": "block", "tag": "block"})    # Add block outbound
    
    # Simplified routing configuration
    base_config["route"] = {
        "rules": [
            {"inbound": ["socks-in"], "outbound": parsed_outbound["tag"]}
        ],
        "final": parsed_outbound["tag"]
    }
    
    # Simplified DNS configuration
    base_config["dns"] = {
        "servers": [
            {"tag": "remote", "address": "1.1.1.1", "detour": parsed_outbound["tag"]},
            {"tag": "local", "address": "8.8.8.8", "detour": "direct"}
        ],
        "rules": [],
        "final": "remote",
        "strategy": "prefer_ipv4"
    }
    
    return base_config 