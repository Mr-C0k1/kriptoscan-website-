import requests
import socket
import ssl
import re
import threading
import json
from queue import Queue
from urllib.parse import urlparse, parse_qs

ETHERSCAN_API_KEY = "YourEtherscanAPIKeyHere"  # Optional, bisa dikosongkan

def get_domain_from_url(url):
    parsed = urlparse(url)
    return parsed.hostname

def check_rpc_port(domain, port, results):
    try:
        sock = socket.create_connection((domain, port), timeout=3)
        results[port] = True
        sock.close()
    except:
        results[port] = False

def check_rpc_ports(domain):
    print(f"[+] Cek RPC ports di {domain}")
    ports = [8545, 8546, 8547]
    threads = []
    results = {}
    for port in ports:
        t = threading.Thread(target=check_rpc_port, args=(domain, port, results))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    for port, open_ in results.items():
        if open_:
            print(f"  [OPEN] Port RPC {port} terbuka (berbahaya jika tanpa proteksi)")
        else:
            print(f"  [CLOSE] Port RPC {port} tertutup")

def check_tls(domain):
    print(f"[+] Cek SSL/TLS {domain}")
    ctx = ssl.create_default_context()
    try:
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(3)
            s.connect((domain, 443))
            cert = s.getpeercert()
            print(f"  Issuer: {cert['issuer']}")
            print(f"  Valid dari {cert['notBefore']} sampai {cert['notAfter']}")
    except Exception as e:
        print(f"  Gagal cek TLS: {e}")

def scan_js_libs(url):
    print(f"[+] Scan JavaScript di {url}")
    try:
        r = requests.get(url, timeout=7)
        if r.status_code == 200:
            text = r.text.lower()
            libs = []
            if "web3.js" in text or "web3.min.js" in text:
                libs.append("web3.js")
            if "ethers.js" in text:
                libs.append("ethers.js")
            if libs:
                print(f"  Ditemukan library: {', '.join(libs)}")
            else:
                print("  Tidak ditemukan library Web3.js / Ethers.js")

            # Cek private key hardcoded sederhana
            keys = re.findall(r"['\"](0x[a-f0-9]{40})['\"]", text)
            if keys:
                print(f"  WARNING: Potensi private key ditemukan di frontend!")
            else:
                print("  Tidak ditemukan private key di frontend.")
        else:
            print(f"  Gagal akses halaman, status code: {r.status_code}")
    except Exception as e:
        print(f"  Error akses halaman: {e}")

def fuzz_bypass(url):
    print(f"[+] Test parameter bypass sederhana pada {url}")
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    if not qs:
        print("  Tidak ada parameter query untuk diuji bypass")
        return
    for param in qs.keys():
        test_url = url.replace(f"{param}={qs[param][0]}", f"{param}=../etc/passwd")
        try:
            r = requests.get(test_url, timeout=7)
            if "root:x:" in r.text:
                print(f"  POTENSI LFI ditemukan pada parameter {param}")
            else:
                print(f"  Parameter {param} aman dari bypass sederhana")
        except Exception as e:
            print(f"  Gagal menguji parameter {param}: {e}")

def check_xss(url):
    print("[+] Cek XSS sederhana pada parameter URL")
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    if not qs:
        print("  Tidak ada parameter untuk diuji XSS")
        return
    for param in qs.keys():
        payload = "<script>alert(1)</script>"
        test_url = url.replace(f"{param}={qs[param][0]}", f"{param}={payload}")
        try:
            r = requests.get(test_url, timeout=7)
            if payload in r.text:
                print(f"  POTENSI XSS ditemukan pada parameter {param}")
            else:
                print(f"  Parameter {param} aman dari XSS sederhana")
        except Exception as e:
            print(f"  Gagal menguji parameter {param}: {e}")

def etherscan_contract_info(contract_address):
    if not ETHERSCAN_API_KEY:
        print("[!] API key Etherscan tidak diset, melewati cek kontrak.")
        return None
    print(f"[+] Ambil info kontrak dari Etherscan untuk {contract_address}")
    url = f"https://api.etherscan.io/api?module=contract&action=getsourcecode&address={contract_address}&apikey={ETHERSCAN_API_KEY}"
    try:
        r = requests.get(url, timeout=7)
        data = r.json()
        if data['status'] == '1' and data['result']:
            source_code = data['result'][0]['SourceCode']
            if source_code:
                print("  Source code kontrak ditemukan.")
                return source_code
            else:
                print("  Tidak ada source code kontrak tersedia.")
        else:
            print(f"  Gagal ambil data kontrak: {data.get('message')}")
    except Exception as e:
        print(f"  Error ambil data kontrak: {e}")
    return None

def main(url):
    print(f"Mulai scanning mendalam untuk {url}")
    domain = get_domain_from_url(url)
    if not domain:
        print("URL tidak valid!")
        return

    check_rpc_ports(domain)
    check_tls(domain)
    scan_js_libs(url)
    fuzz_bypass(url)
    check_xss(url)
    print("Scanning selesai.")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 deep_web3_scan_plus.py https://example.com")
        sys.exit(1)
    main(sys.argv[1])
