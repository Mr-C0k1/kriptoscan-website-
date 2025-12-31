#!/usr/bin/env python3
"""
w3scan-api v2.0 (2025)
Advanced API Security Auditor untuk Trading Platform Kripto
Fokus: Binance, Indodax, Bybit, OKX, Tokocrypto, Pintu, dll.
"""

import argparse
import requests
import json
import re
import sys
from urllib.parse import urljoin, urlparse

# Disable SSL warnings (untuk testing API dengan cert custom)
requests.packages.urllib3.disable_warnings()

# Endpoint sensitif umum di exchange kripto
CRYPTO_API_PATHS = [
    '/', '/v1', '/v2', '/api', '/api/v1', '/api/v2', '/api/v3',
    '/public', '/private', '/account', '/balance', '/wallet',
    '/order', '/orders', '/trade', '/trades', '/ticker', '/tickers',
    '/depth', '/book', '/klines', '/candles', '/withdraw', '/deposit',
    '/user', '/profile', '/auth', '/login', '/signup', '/keys',
    '/graphql', '/graphiql', '/playground', '/altair', '/voyager'
]

# Header berbahaya yang sering bocor
DANGER_HEADERS = [
    'X-Api-Key', 'X-API-KEY', 'Authorization', 'Set-Cookie',
    'X-RateLimit-Limit', 'X-RateLimit-Remaining', 'Server', 'X-Powered-By'
]

# Pola API key leakage di response
API_KEY_PATTERNS = [
    r'[A-Za-z0-9]{32,64}',  # Generic API key / secret
    r'pk_live_[A-Za-z0-9]+', r'sk_live_[A-Za-z0-9]+',
    r'binance.*key', r'indodax.*key', r'api[_-]?key'
]

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]

def banner():
    print(r"""
    ╔══════════════════════════════════════════╗
    ║           W3SCAN-API v2.0 (2025)         ║
    ║   Advanced Crypto Exchange API Auditor   ║
    ╚══════════════════════════════════════════╝
    """)

def check_methods(base_url):
    print("[+] Mengecek HTTP Methods yang diizinkan...")
    allowed = {}
    for method in HTTP_METHODS:
        try:
            r = requests.request(method, base_url, timeout=6, verify=False)
            if r.status_code < 500:  # Bukan server error
                allowed[method] = r.status_code
                print(f"  → {method.ljust(7)} → {r.status_code}")
                if method in ["PUT", "DELETE", "PATCH"] and r.status_code in [200, 201, 204]:
                    print(f"  [!] {method} AKTIF → Potensi data tampering!")
        except:
            pass
    return allowed

def check_cors(base_url):
    print("[+] Mengecek konfigurasi CORS...")
    origins = ['https://evil.com', 'null', 'http://localhost']
    vulnerable = False
    for origin in origins:
        try:
            r = requests.options(base_url, headers={'Origin': origin}, timeout=6, verify=False)
            acao = r.headers.get('Access-Control-Allow-Origin')
            creds = r.headers.get('Access-Control-Allow-Credentials')
            if acao and (acao == origin or acao == '*'):
                if creds == 'true':
                    print(f"  [!] CORS KRITIS → Allow-Credentials + {acao}")
                else:
                    print(f"  [!] CORS Longgar → Origin: {origin} → ACAO: {acao}")
                vulnerable = True
        except:
            continue
    if not vulnerable:
        print("  [-] CORS tampak aman")

def check_security_headers(resp_headers):
    print("[+] Mengecek header keamanan kritis...")
    required = {
        "Strict-Transport-Security": "HSTS",
        "X-Frame-Options": "Clickjacking Protection",
        "X-Content-Type-Options": "MIME Sniffing",
        "Content-Security-Policy": "XSS/CSRF Mitigation",
        "Referrer-Policy": "Referrer Leakage",
        "Permissions-Policy": "Feature Control"
    }
    missing = []
    for h, desc in required.items():
        if h not in resp_headers:
            missing.append(h)
            print(f"  [!] Missing → {h}")
        else:
            print(f"  [=] {h}: {resp_headers[h][:50]}...")
    return missing

def check_rate_limit(headers):
    print("[+] Deteksi Rate Limiting...")
    indicators = ['X-RateLimit', 'Retry-After', 'X-Rate-Limit']
    found = {k: v for k, v in headers.items() if any(ind in k for ind in indicators)}
    if found:
        for k, v in found.items():
            print(f"  → {k}: {v}")
    else:
        print("  [-] Tidak terdeteksi rate limit header")

def check_graphql_introspection(base_url):
    print("[+] Mengecek GraphQL Introspection (sering terbuka di staging)...")
    gql_url = urljoin(base_url, "/graphql")
    payload = {
        "query": "{ __schema { types { name } } }"
    }
    try:
        r = requests.post(gql_url, json=payload, timeout=6, verify=False)
        if r.status_code == 200 and "__schema" in r.text:
            print(f"  [!] GRAPHQL INTROSPECTION ENABLED → {gql_url}")
            print("  → Endpoint GraphQL terbuka → Bisa dieksplorasi dengan tool seperti GraphQL Voyager")
            return True
    except:
        pass
    print("  [-] Introspection tidak aktif atau endpoint tidak ada")
    return False

def discover_sensitive_endpoints(base_url):
    print(f"[+] Brute-force ringan endpoint sensitif ({len(CRYPTO_API_PATHS)} paths)...")
    found = []
    for path in CRYPTO_API_PATHS:
        url = urljoin(base_url, path)
        try:
            r = requests.get(url, timeout=5, verify=False)
            if r.status_code in [200, 401, 403]:
                status = "OPEN" if r.status_code == 200 else "PROTECTED"
                print(f"  → [{status}] {url}")
                if r.status_code == 200:
                    found.append({"url": url, "status": 200, "type": "public_endpoint"})
        except:
            continue
    return found

def check_api_key_leakage(response_text):
    text = response_text.lower()
    matches = []
    for pattern in API_KEY_PATTERNS:
        found = re.findall(pattern, text)
        if found:
            matches.extend(found)
    if matches:
        print(f"  [!] POTENSI API KEY LEAKAGE → {len(matches)} kandidat ditemukan!")
        for m in matches[:3]:  # tampilkan maksimal 3
            print(f"      → {m}")
        return True
    return False

def error_fingerprinting(base_url):
    print("[+] Error Fingerprinting & Info Leakage...")
    trigger_urls = [
        base_url + "/nonexistent-xyz-123",
        base_url + "?id=-1' OR '1'='1",
        base_url.rstrip('/') + "/../admin"
    ]
    leaks_found = False
    for url in trigger_urls:
        try:
            r = requests.get(url, timeout=5, verify=False)
            if r.status_code >= 400 and len(r.text) > 50:
                if check_api_key_leakage(r.text):
                    leaks_found = True
                indicators = ["traceback", "exception", "debug", "stack", "mysql", "postgresql", "mongo", "query", "syntax error"]
                if any(ind in r.text.lower() for ind in indicators):
                    print(f"  [!] Verbose Error Detected → {url}")
                    print(f"      → Indikator: {[ind for ind in indicators if ind in r.text.lower()][:3]}")
                    leaks_found = True
        except:
            continue
    if not leaks_found:
        print("  [-] Tidak ada kebocoran error signifikan")

def main():
    parser = argparse.ArgumentParser(description="w3scan-api v2.0 - Crypto Exchange API Security Auditor")
    parser.add_argument("--api", required=True, help="Base URL API, contoh: https://api.indodax.com/api")
    parser.add_argument("--output", "-o", help="Simpan hasil ke file JSON")
    args = parser.parse_args()

    base_url = args.api.rstrip("/")
    if not base_url.startswith("http"):
        base_url = "https://" + base_url

    banner()
    print(f"[Target] {base_url}\n")

    result = {
        "target": base_url,
        "scan_date": "2025-12-31",
        "findings": {}
    }

    # 1. HTTP Methods
    methods = check_methods(base_url)
    result["findings"]["http_methods"] = methods

    # 2. CORS
    check_cors(base_url)

    # 3. Headers & Rate Limit
    try:
        head_resp = requests.get(base_url, timeout=6, verify=False)
        missing_headers = check_security_headers(head_resp.headers)
        check_rate_limit(head_resp.headers)
        result["findings"]["missing_headers"] = missing_headers
        result["findings"]["exposed_headers"] = {k: v for k, v in head_resp.headers.items() if k in DANGER_HEADERS}
    except:
        print("[!] Gagal mengambil header utama")

    # 4. Sensitive Endpoints
    sensitive = discover_sensitive_endpoints(base_url)
    result["findings"]["sensitive_endpoints"] = sensitive

    # 5. GraphQL
    graphql_vuln = check_graphql_introspection(base_url)
    result["findings"]["graphql_introspection"] = graphql_vuln

    # 6. Error & Leakage
    error_fingerprinting(base_url)

    # Output JSON
    if args.output:
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2)
        print(f"\n[+] Hasil lengkap disimpan ke: {args.output}")

    print("\n" + "="*60)
    print("               SCAN SELESAI - GUNAKAN HANYA UNTUK AUTHORIZED TESTING")
    print("="*60)

if __name__ == "__main__":
    main()
