#!/usr/bin/env python3
import requests
from urllib.parse import urlparse, urljoin
import socket
import ssl
import json
import sys
import re

COMMON_PATHS = ['/', '/api', '/admin', '/dashboard']
METHODS_TO_CHECK = ['PUT', 'DELETE', 'PATCH']
SEC_HEADERS = [
    'Content-Security-Policy',
    'X-Frame-Options',
    'Strict-Transport-Security',
    'X-Content-Type-Options',
    'Referrer-Policy',
    'Permissions-Policy'
]
ERROR_SIGNS = [
    'exception', 'stack trace', 'error', 'traceback',
    'fatal error', 'syntax error', 'mysql', 'postgres', 'nullpointerexception'
]

PHISHING_PATTERNS = [
    r'(metamask|walletconnect|phantom)[^\w\d]*login',
    r'connect[^\w\d]*(wallet|crypto)',
    r'web3[^\w\d]*(confirm|authorize)',
    r'(airdrop|claim)[^\w\d]*(eth|token)',
    r'wallet[^\w\d]*(drain|steal|sign)',
]
DAPP_INJECTION_SIGNS = [
    'window.ethereum.enable(',
    'web3.currentprovider',
    'eval(',
    'Function("return this")()',
    'atob(', 'new Function(',
    'document.write(',
    'unescape(',
]

def get_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
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
            return s.getpeercert()
    except Exception as e:
        return {"error": str(e)}

def check_http_methods(base_url):
    active = {}
    for path in COMMON_PATHS:
        url = urljoin(base_url, path)
        for method in METHODS_TO_CHECK:
            try:
                r = requests.request(method, url, timeout=5)
                if r.status_code < 400:
                    active.setdefault(path, []).append(method)
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
    try:
        r = requests.get(url, timeout=5)
        missing = [h for h in SEC_HEADERS if h not in r.headers]
        found = {h: r.headers[h] for h in SEC_HEADERS if h in r.headers}
        body = r.text.lower()
        return missing, found, r.headers, body
    except:
        return SEC_HEADERS, {}, {}, ""

def error_fingerprinting(url):
    try:
        fake = urljoin(url, '/invalid-input-xyz')
        r = requests.get(fake, timeout=5)
        content = r.text.lower()
        leak = [sig for sig in ERROR_SIGNS if sig in content]
        return leak, fake
    except:
        return [], None

def detect_stack(headers, body=""):
    framework = "Tidak diketahui"
    powered = headers.get('X-Powered-By', '').lower()
    server = headers.get('Server', '').lower()
    cookie = headers.get('Set-Cookie', '').lower()

    if 'express' in powered or 'node' in powered:
        framework = "Express.js (Node.js)"
    elif 'php' in powered or 'laravel' in cookie or 'phpsessid' in cookie:
        framework = "Laravel / PHP"
    elif 'python' in powered or 'werkzeug' in server or 'flask' in body:
        framework = "Flask (Python)"
    elif 'django' in body:
        framework = "Django (Python)"
    elif 'spring' in body:
        framework = "Java Spring"
    elif 'netlify' in server:
        framework = "Netlify Hosting"
    elif 'cloudflare' in server:
        framework = "Cloudflare Reverse Proxy"
    elif 'vercel' in server:
        framework = "Vercel Hosting"

    return framework

def detect_wallet_phishing(url):
    try:
        r = requests.get(url, timeout=5)
        body = r.text.lower()
        for pattern in PHISHING_PATTERNS:
            if re.search(pattern, body):
                return True, pattern
        return False, None
    except:
        return False, None

def detect_dapp_injection(url):
    try:
        r = requests.get(url, timeout=5)
        body = r.text.lower()
        return [s for s in DAPP_INJECTION_SIGNS if s in body]
    except:
        return []

def vulnerability_insight(active_methods, cors_info, missing_headers, error_result):
    print("\n[🔍] Posisi & Letak Kerentanan:")

    if active_methods:
        for path, methods in active_methods.items():
            print(f"\n🔥 HTTP Method Injection:")
            print(f"  • Endpoint: `{path}`")
            print(f"  • Method aktif: {', '.join(methods)}")
            print("  • Posisi Kerentanan:")
            print("     ↳ Di backend server (NodeJS, Flask, PHP, Laravel, dll) yang tidak membatasi HTTP methods.")

    if cors_info[0]:
        print(f"\n🌐 CORS Misconfiguration:")
        print(f"  • Header ditemukan: Access-Control-Allow-Origin: {cors_info[1]}")
        print("  • Posisi Kerentanan:")
        print("     ↳ Konfigurasi CORS di web server/backend salah. Bisa menyebabkan data bocor ke domain asing.")

    if missing_headers:
        print(f"\n🛡️ Missing Security Headers:")
        print(f"  • Header hilang: {', '.join(missing_headers)}")
        print("  • Posisi Kerentanan:")
        print("     ↳ Tidak ada konfigurasi global di web server atau middleware untuk menambah header keamanan.")

    if error_result[0]:
        print(f"\n🐞 Error Disclosure:")
        print(f"  • Ditemukan di URL: {error_result[1]}")
        print(f"  • Kata kunci error: {', '.join(error_result[0])}")
        print("  • Posisi Kerentanan:")
        print("     ↳ Routing fallback/backend menampilkan error mentah (traceback, detail internal server).")

def suggest_hardening(framework):
    print(f"\n[+] Terindikasi Framework: {framework}")
    print("\n🚨 Semua security header hilang. Saran konfigurasi:")

    if "Express" in framework:
        print("  ➤ Gunakan middleware `helmet` di Express.js:")
        print("      const helmet = require('helmet');")
        print("      app.use(helmet());")
    elif "Laravel" in framework:
        print("  ➤ Tambahkan middleware custom di Laravel:")
        print("      app/Http/Middleware/SecurityHeaders.php")
    elif "Flask" in framework:
        print("  ➤ Tambahkan `@after_request` untuk menyisipkan header.")
    elif "Django" in framework:
        print("  ➤ Aktifkan SecurityMiddleware dan tambahkan header di settings.py")
    elif "Netlify" in framework:
        print("  ➤ Buat file `public/_headers` dengan daftar header keamanan.")
    elif "Vercel" in framework:
        print("  ➤ Tambahkan header di file `vercel.json` pada bagian `headers`.")
    elif "nginx" in framework or "apache" in framework:
        print("  ➤ Tambahkan header menggunakan `add_header` (nginx) atau `Header set` (Apache).")
    else:
        print("  ➤ Tambahkan manual di backend sebelum mengirim response.")

def extended_checks(url):
    print("\n[+] Deteksi Wallet Phishing...")
    phishing, pattern = detect_wallet_phishing(url)
    if phishing:
        print(f"  > ⚠️ Pola phishing ditemukan: {pattern}")
    else:
        print("  > Tidak ditemukan indikasi phishing wallet")

    print("\n[+] Deteksi DApp Injection...")
    injections = detect_dapp_injection(url)
    if injections:
        print(f"  > ⚠️ Injeksi DApp terdeteksi: {', '.join(injections)}")
    else:
        print("  > Tidak ditemukan injeksi mencurigakan")

def main(target_url):
    print(f"\n[+] Memulai pemindaian terhadap: {target_url}")
    parsed = urlparse(target_url)
    domain = parsed.netloc or parsed.path
    ip = get_ip(domain)

    print(f"[+] IP Target: {ip or 'Gagal resolve'}")
    if ip:
        ports = scan_ports(ip)
        print(f"[+] Port terbuka: {ports}")

    print("\n[+] Info Sertifikat TLS:")
    print(json.dumps(get_tls_info(domain), indent=2))

    print("\n[+] Mengecek HTTP Method Injection...")
    active = check_http_methods(target_url)
    for path, methods in active.items():
        print(f"  > Aktif: {path} menerima {', '.join(methods)}")
    if not active:
        print("  > Tidak ditemukan metode berbahaya yang aktif.")

    print("\n[+] Mengecek CORS...")
    cors_info = check_cors(target_url)
    if cors_info[0]:
        print(f"  > ⚠️ CORS terbuka! Access-Control-Allow-Origin: {cors_info[1]}")
    else:
        print("  > Aman dari CORS jahat")

    print("\n[+] Mengecek Security Headers...")
    missing, found, raw_headers, body = check_security_headers(target_url)
    print(f"  > ⚠️ Header hilang: {', '.join(missing) if missing else 'Semua lengkap'}")
    print(f"  > Header ditemukan: {found}")

    framework = detect_stack(raw_headers, body)
    if not found:
        suggest_hardening(framework)

    print("\n[+] Melakukan Error Fingerprinting...")
    errors, error_url = error_fingerprinting(target_url)
    if errors:
        print(f"  > ⚠️ Potensi bocor error: {errors} di {error_url}")
    else:
        print("  > Tidak ditemukan bocoran error")

    vulnerability_insight(active, cors_info, missing, (errors, error_url))

    extended_checks(target_url)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 securitykripto.py https://target.com")
        sys.exit(1)
    main(sys.argv[1])
