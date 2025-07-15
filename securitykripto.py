#!/usr/bin/env python3
import requests
from urllib.parse import urlparse, urljoin
import socket
import ssl
import json
import sys

def get_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None

def scan_ports(ip, ports=[80, 443, 8545, 30303]):
    open_ports = []
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=1):
                open_ports.append(port)
        except:
            continue
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
    methods = ['PUT', 'DELETE', 'PATCH']
    active = []
    for method in methods:
        try:
            r = requests.request(method, url, timeout=5)
            if r.status_code < 400:
                active.append(method)
        except:
            continue
    return active

def check_cors(url):
    headers = {'Origin': 'http://evil.example.com'}
    try:
        r = requests.get(url, headers=headers, timeout=5)
        acao = r.headers.get('Access-Control-Allow-Origin', '')
        if acao == '*' or 'evil.example.com' in acao:
            return True, acao
        return False, acao
    except:
        return False, None

def check_security_headers(url):
    required = [
        'Content-Security-Policy',
        'X-Frame-Options',
        'Strict-Transport-Security',
        'X-Content-Type-Options',
        'Referrer-Policy',
        'Permissions-Policy'
    ]
    try:
        r = requests.get(url, timeout=5)
        missing = [h for h in required if h not in r.headers]
        found = {h: r.headers[h] for h in required if h in r.headers}
        return missing, found
    except:
        return required, {}

def error_fingerprinting(url):
    fake_path = '/invalid-input-xyz'
    signatures = [
        'exception', 'stack trace', 'error', 'warning', 'traceback',

        # Python
        'traceback (most recent call last)', 'valueerror', 'typeerror',

        # PHP
        'fatal error', 'unexpected', 'undefined', 'in /var/www/', 'parse error',

        # Java
        'nullpointerexception', 'classcastexception', 'indexoutofboundsexception',

        # JavaScript
        'referenceerror', 'syntaxerror', 'typeerror at',

        # DB errors
        'mysql', 'you have an error in your sql syntax;',
        'psql:', 'postgresql', 'syntax error at or near',
        'sqlite error', 'unclosed quotation mark after the character string',
        'mongoerror', 'mongoparseerror', 'oracle error',

        # Server
        'internal server error', 'server at', 'nginx', 'apache'
    ]

    try:
        full_url = urljoin(url, fake_path)
        r = requests.get(full_url, timeout=5)
        content = r.text.lower()
        return [sig for sig in signatures if sig in content]
    except:
        return []

def main(target_url):
    print(f"\n[+] Mulai scan untuk domain: {target_url}")
    parsed = urlparse(target_url)
    domain = parsed.netloc or parsed.path

    ip = get_ip(domain)
    print(f"[+] IP address: {ip or 'Tidak ditemukan'}")

    if ip:
        ports = scan_ports(ip)
        print(f"[+] Port terbuka umum: {ports}")
    else:
        print("[!] Tidak bisa resolve IP.")

    print("\n[+] Info sertifikat TLS:")
    tls = get_tls_info(domain)
    print(json.dumps(tls, indent=2))

    print("\n[+] Mengecek HTTP Method Injection (PUT, DELETE, PATCH)...")
    active = check_http_methods(target_url)
    if active:
        print(f"  > Aktif: {', '.join(active)}")
    else:
        print("  > Tidak ada method injeksi aktif")

    print("\n[+] Mengecek CORS Misconfiguration...")
    cors, header = check_cors(target_url)
    if cors:
        print(f"  > ⚠️ CORS terbuka! Access-Control-Allow-Origin: {header}")
    else:
        print("  > Aman dari CORS origin jahat")

    print("\n[+] Mengecek Security Headers...")
    missing, found = check_security_headers(target_url)
    if missing:
        print(f"  > ⚠️ Header hilang: {', '.join(missing)}")
    else:
        print("  > Semua header utama ditemukan")
    print(f"  > Ditemukan: {found}")

    print("\n[+] Melakukan Error Fingerprinting...")
    errors = error_fingerprinting(target_url)
    if errors:
        print(f"  > ⚠️ Potensi kebocoran error ditemukan: {errors}")
    else:
        print("  > Tidak ditemukan error yang bocor")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 securitykripto.py https://example.com")
        sys.exit(1)
    main(sys.argv[1])
