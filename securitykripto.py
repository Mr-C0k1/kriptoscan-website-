#!/usr/bin/env python3
import requests
from urllib.parse import urlparse, urljoin
import socket
import ssl
import json

def get_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None

def scan_ports(ip, ports=[80, 443, 8545, 30303]):
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        try:
            if sock.connect_ex((ip, port)) == 0:
                open_ports.append(port)
        except Exception:
            pass
        sock.close()
    return open_ports

def get_tls_info(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(3)
            s.connect((domain, 443))
            cert = s.getpeercert()
            return cert
    except Exception as e:
        return {"error": str(e)}

def check_http_methods(url):
    methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']
    active_methods = []
    for method in methods:
        try:
            r = requests.request(method, url, timeout=5)
            if r.status_code < 400:
                active_methods.append(method)
        except:
            pass
    return active_methods

def check_cors(url):
    headers = {'Origin': 'http://evil.example.com'}
    try:
        r = requests.get(url, headers=headers, timeout=5)
        acao = r.headers.get('Access-Control-Allow-Origin', '')
        if acao == '*' or 'evil.example.com' in acao:
            return True, acao
        else:
            return False, acao
    except:
        return False, None

def check_security_headers(url):
    required_headers = [
        'Content-Security-Policy',
        'X-Frame-Options',
        'Strict-Transport-Security',
        'X-Content-Type-Options',
        'Referrer-Policy',
        'Permissions-Policy'
    ]
    missing = []
    present = {}
    try:
        r = requests.get(url, timeout=5)
        for h in required_headers:
            if h not in r.headers:
                missing.append(h)
            else:
                present[h] = r.headers[h]
        return missing, present
    except:
        return required_headers, {}

def error_fingerprinting(url):
    fake_path = '/invalid-input-xyz'
    keywords = ['exception', 'stack trace', 'mysql', 'mongo', 'oracle', 'warning', 'traceback', 'error']
    detected = []
    try:
        full_url = urljoin(url, fake_path)
        r = requests.get(full_url, timeout=5)
        content = r.text.lower()
        for k in keywords:
            if k in content:
                detected.append(k)
    except:
        pass
    return detected

def main(target_url):
    print(f"[+] Mulai scan untuk domain: {target_url}")

    parsed = urlparse(target_url)
    domain = parsed.netloc if parsed.netloc else parsed.path

    ip = get_ip(domain)
    print(f"IP address: {ip}")

    if ip:
        ports = scan_ports(ip)
        print(f"Port terbuka umum (default scan): {ports}")

    tls_info = get_tls_info(domain)
    print(f"Info sertifikat TLS:\n{json.dumps(tls_info, indent=2)}")

    methods = check_http_methods(target_url)
    print(f"HTTP Methods aktif: {methods}")

    cors_enabled, cors_header = check_cors(target_url)
    print(f"CORS misconfig detected: {cors_enabled}, header Access-Control-Allow-Origin: {cors_header}")

    missing_headers, present_headers = check_security_headers(target_url)
    print(f"Header keamanan hilang: {missing_headers}")
    print(f"Header keamanan terdeteksi: {present_headers}")

    errors = error_fingerprinting(target_url)
    print(f"Potensi kebocoran error ditemukan: {errors}")

if __name__ == '__main__':
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 securitykripto.py https://example.com")
        sys.exit(1)
    main(sys.argv[1])
