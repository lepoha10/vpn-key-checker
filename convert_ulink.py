import base64
import json
import urllib.parse
import sys

def decode_ulink_to_uris(ulink_str):
    try:
        parsed = urllib.parse.urlparse(ulink_str)
        query = urllib.parse.parse_qs(parsed.query)
        
        if 'content' not in query:
            return []
        
        content_b64 = query['content'][0]
        padding = '=' * (-len(content_b64) % 4)
        decoded_bytes = base64.urlsafe_b64decode(content_b64 + padding)
        decoded_str = decoded_bytes.decode('utf-8')
        
        proxies = json.loads(decoded_str)
        if not isinstance(proxies, list):
            proxies = [proxies]
        
        return [proxy_to_uri(p) for p in proxies if proxy_to_uri(p)]
    except Exception as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        return []

def proxy_to_uri(proxy):
    ptype = proxy.get('type', '').lower()
    server = proxy.get('server')
    port = proxy.get('server_port')
    if not server or not port:
        return None
    
    params = {}
    
    # TLS
    tls = proxy.get('tls', {})
    if tls.get('enabled'):
        params['security'] = 'tls'
        if tls.get('server_name'):
            params['sni'] = tls['server_name']
        if tls.get('insecure'):
            params['allowInsecure'] = '1'
        if tls.get('alpn'):
            alpn = tls['alpn']
            params['alpn'] = ','.join(alpn) if isinstance(alpn, list) else alpn
    
    # Transport
    transport = proxy.get('transport', {})
    ttype = transport.get('type', 'tcp').lower()
    
    if ttype == 'xhttp':
        params['type'] = 'xhttp'
        if transport.get('mode'):
            params['mode'] = transport['mode']
        if transport.get('host'):
            params['host'] = transport['host']
        if transport.get('path'):
            params['path'] = transport['path']
        
        extra = {}
        if transport.get('x_padding_bytes'):
            extra['xPaddingBytes'] = transport['x_padding_bytes']
        if transport.get('sc_max_each_post_bytes'):
            extra['scMaxEachPostBytes'] = transport['sc_max_each_post_bytes']
        if transport.get('sc_min_posts_interval_ms'):
            extra['scMinPostsIntervalMs'] = transport['sc_min_posts_interval_ms']
        if transport.get('xmux'):
            extra['xmux'] = transport['xmux']
        if extra:
            params['extra'] = json.dumps(extra, separators=(',', ':'))
    elif ttype == 'ws':
        params['type'] = 'ws'
        if transport.get('host'):
            params['host'] = transport['host']
        if transport.get('path'):
            params['path'] = transport['path']
    elif ttype == 'grpc':
        params['type'] = 'grpc'
        if transport.get('service_name'):
            params['serviceName'] = transport['service_name']
    
    if tls.get('fingerprint'):
        params['fp'] = tls['fingerprint']
    if proxy.get('flow'):
        params['flow'] = proxy['flow']
    if proxy.get('packet_encoding'):
        params['packetEncoding'] = proxy['packet_encoding']
    
    query_str = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
    tag = proxy.get('tag', '')
    fragment = urllib.parse.quote(tag) if tag else ''
    
    if ptype == 'vless':
        uuid = proxy.get('uuid', '')
        return f"vless://{uuid}@{server}:{port}?{query_str}#{fragment}"
    elif ptype == 'vmess':
        vmess_json = {
            "v": "2", "ps": tag, "add": server, "port": str(port),
            "id": proxy.get('uuid', ''), "aid": str(proxy.get('alter_id', 0)),
            "scy": proxy.get('security', 'auto'), "net": ttype, "type": "none",
            "host": transport.get('host', ''), "path": transport.get('path', ''),
            "tls": 'tls' if tls.get('enabled') else '',
            "sni": tls.get('server_name', '')
        }
        vmess_b64 = base64.b64encode(json.dumps(vmess_json, separators=(',', ':')).encode()).decode()
        return f"vmess://{vmess_b64}"
    elif ptype == 'trojan':
        password = proxy.get('password', '')
        return f"trojan://{password}@{server}:{port}?{query_str}#{fragment}"
    elif ptype in ('ss', 'shadowsocks'):
        method = proxy.get('method', proxy.get('cipher', ''))
        password = proxy.get('password', '')
        userinfo = base64.b64encode(f"{method}:{password}".encode()).decode().rstrip('=')
        return f"ss://{userinfo}@{server}:{port}#{fragment}"
    return None

if __name__ == "__main__":
    print("Вставь ULink-ссылку и нажми Enter:")
    ulink = input().strip()
    if not ulink.startswith("ulink://"):
        print("Это не ULink-ссылка!")
    else:
        uris = decode_ulink_to_uris(ulink)
        if not uris:
            print("Не удалось декодировать.")
        else:
            print("\n--- Результат ---")
            for uri in uris:
                print(uri)