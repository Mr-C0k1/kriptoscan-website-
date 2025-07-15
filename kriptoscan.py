#!/usr/bin/env python3
import argparse
import socket
import ssl
import requests
from urllib.parse import urlparse, urljoin, parse_qs
import json
import sys
import threading

# Simple built-in subdomain wordlist kecil untuk demo
DEFAULT_SUBDOMAIN_WORDLIST = [
    "www", "api", "dev", "test", "blog", "shop", "mail", "webmail", "portal",
    "admin", "beta", "m", "cdn", "static"
]

# Port penting Web & Blockchain
PORTS_TO_SCAN = [80, 443, 8545, 30303]

def resolve_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except Exception as e:
        return None

def scan_ports(ip):
    open_ports = []
    for port in PORTS_TO_SCAN:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        try:
            sock.connect((ip, port))
            open_ports.append(port)
        except:
            pass
        sock.close()
    return open_ports

def check_tls(domain):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return cert
    except Exception as e:
        return {"error": str(e)}

def check_json_rpc(domain, open_ports):
    found = False
    endpoints = []
    for port in open_ports:
        url = f"http://{domain}:{port}"
        try:
            headers = {'Content-Type': 'application/json'}
            payload = {"jsonrpc":"2.0","method":"web3_clientVersion","params":[],"id":1}
            r = requests.post(url, json=payload, headers=headers, timeout=3)
            if r.status_code == 200 and "result" in r.json():
                found = True
                endpoints.append(url)
        except:
            pass
    return found, endpoints

def fetch_homepage(domain):
    for scheme in ['https://', 'http://']:
        try:
            url = scheme + domain
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                return r.text, url
        except:
            continue
    return None, None

def detect_js_blockchain_libs(html):
    libs = {
        "web3.js": ["web3.min.js", "Web3"],
        "ethers.js": ["ethers.min.js", "ethers."],
        "web3modal": ["web3modal.min.js", "Web3Modal"],
    }
    detected = []
    for lib, signs in libs.items():
        for sign in signs:
            if sign in html:
                detected.append(lib)
                break
    return detected

def simple_subdomain_scan(domain, wordlist=None):
    print("[*] Mulai simple subdomain scan")
    found = []
    wl = wordlist if wordlist else DEFAULT_SUBDOMAIN_WORDLIST
    for sub in wl:
        test_domain = f"{sub}.{domain}"
        ip = resolve_ip(test_domain)
        if ip:
            print(f"  [OK] {test_domain} -> {ip}")
            found.append({"subdomain": test_domain, "ip": ip})
    return found

def param_bypass_scan(url):
    print("[*] Mulai simple parameter bypass scan")
    try:
        parsed = urlparse(url)
        if not parsed.query:
            print("  [!] URL tidak memiliki parameter untuk di-scan")
            return []
        params = parse_qs(parsed.query)
        vulnerable_params = []
        for param in params:
            test_url = url.replace(f"{param}={params[param][0]}", f"{param}=<script>alert(1)</script>")
            try:
                r = requests.get(test_url, timeout=5)
                if "<script>alert(1)</script>" in r.text:
                    print(f"  [Vulnerable] Parameter reflektif: {param}")
                    vulnerable_params.append(param)
            except:
                continue
        return vulnerable_params
    except Exception as e:
        print(f"  [!] Error scanning params: {e}")
        return []

def main():
    parser = argparse.ArgumentParser(description="kriptowebscan - Web3 & Blockchain Deep URL Scanner")
    parser.add_argument("--d", required=True, help="Target domain (contoh: example.com)")
    parser.add_argument("--output", help="Simpan hasil JSON ke file")
    parser.add_argument("--wordlist", help="File wordlist untuk subdomain scan")
    args = parser.parse_args()

    domain = args.d.strip().lower()
    print(f"[+] Mulai scan untuk domain: {domain}")

    ip = resolve_ip(domain)
    if ip:
        print(f"IP address: {ip}")
    else:
        print("[-] Gagal resolve IP")
        sys.exit(1)

    open_ports = scan_ports(ip)
    print(f"Port terbuka umum (80,443,8545,30303,...): {open_ports}")

    tls_info = check_tls(domain)
    print("Info sertifikat TLS:")
    print(json.dumps(tls_info, indent=2))

    found_json_rpc, endpoints = check_json_rpc(domain, open_ports)
    if found_json_rpc:
        print(f"JSON-RPC endpoint ditemukan di: {endpoints}")
    else:
        print("JSON-RPC endpoint tidak ditemukan atau tidak responsif.")

    html, homepage_url = fetch_homepage(domain)
    if html:
        detected_libs = detect_js_blockchain_libs(html)
        if detected_libs:
            print(f"Library JavaScript blockchain ditemukan di homepage: {detected_libs}")
        else:
            print("Library JavaScript blockchain tidak ditemukan di homepage.")
    else:
        print("Gagal mengambil homepage untuk scan library JS.")

    # Subdomain scan sederhana (tanpa wordlist eksternal)
    wl = None
    if args.wordlist:
        try:
            with open(args.wordlist, 'r') as f:
                wl = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"  [!] Gagal baca wordlist: {e}")
    subdomains = simple_subdomain_scan(domain, wl)

    # Simple param bypass scan terhadap homepage URL jika ada query params
    if homepage_url:
        vulnerable_params = param_bypass_scan(homepage_url)
    else:
        vulnerable_params = []

    # Hasil akhir
    hasil = {
        "domain": domain,
        "ip": ip,
        "open_ports": open_ports,
        "tls_certificate": tls_info,
        "json_rpc": {
            "found": found_json_rpc,
            "endpoints": endpoints
        },
        "js_blockchain_libs": detected_libs if html else [],
        "subdomains_found": subdomains,
        "param_bypass_vulnerable": vulnerable_params
    }

    if args.output:
        with open(args.output, 'w') as out:
            json.dump(hasil, out, indent=2)
        print(f"[+] Hasil scan disimpan ke {args.output}")

if __name__ == "__main__":
    main()
