#!/usr/bin/env python3
import argparse
import socket
import requests
import ssl
import datetime
import json
import urllib3
from urllib.parse import urlparse, parse_qs

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Port rahasia & umum di ekosistem kripto/blockchain
SECRET_PORTS = [80, 443, 8545, 8546, 8547, 8551, 30303, 6060, 8080, 8008, 5001]

WEAK_CIPHERS = ["RC4", "3DES", "DES", "MD5", "SHA1", "NULL"]

def resolve_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return None

def scan_ports(ip):
    open_ports = []
    for port in SECRET_PORTS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.8)
        if sock.connect_ex((ip, port)) == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

def check_tls(domain):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cipher = ssock.cipher()[0]
                version = ssock.version()
                weak = any(w in cipher.upper() for w in WEAK_CIPHERS)
                return {"version": version, "cipher": cipher, "weak_cipher": weak}
    except:
        return {"error": "TLS check failed"}

def check_security_headers(domain):
    try:
        r = requests.get(f"https://{domain}", timeout=5, verify=False)
        h = r.headers
        return {
            "missing": [k for k in ["Strict-Transport-Security", "X-Frame-Options", "X-Content-Type-Options"] if k not in h]
        }
    except:
        return {"error": "Header check failed"}

def check_json_rpc(domain, ports):
    endpoints = []
    for port in ports:
        if port in [80, 443]: continue
        url = f"http://{domain}:{port}"
        try:
            payload = {"jsonrpc":"2.0","method":"web3_clientVersion","params":[],"id":1}
            r = requests.post(url, json=payload, timeout=3, verify=False)
            if r.status_code == 200 and "result" in r.json():
                endpoints.append({"url": url, "client": r.json().get("result")})
        except:
            pass
    return endpoints

def fetch_homepage(domain):
    for scheme in ["https", "http"]:
        try:
            r = requests.get(f"{scheme}://{domain}", timeout=5, verify=False)
            if r.status_code == 200:
                return r.text, f"{scheme}://{domain}"
        except:
            pass
    return None, None

def detect_web3_libs(html):
    signs = {"web3.js": "Web3", "ethers.js": "ethers.", "web3modal": "Web3Modal"}
    return [lib for lib, sign in signs.items() if sign in html]

def simple_xss_check(url):
    if "?" not in url: return []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    vulns = []
    payload = "<script>alert(1)</script>"
    for param in params:
        test_url = url.replace(f"{param}={params[param][0]}", f"{param}={payload}")
        try:
            r = requests.get(test_url, timeout=5, verify=False)
            if payload in r.text:
                vulns.append(param)
        except:
            pass
    return vulns

def main():
    parser = argparse.ArgumentParser(description="KriptoScan - Fast Crypto & Web Vulnerability Scanner")
    parser.add_argument("--d", required=True, help="Target domain (e.g. example.com)")
    parser.add_argument("--output", help="Save JSON output")
    args = parser.parse_args()

    domain = args.d.strip().lower()
    print(f"[+] Scanning: {domain}")

    ip = resolve_ip(domain)
    if not ip:
        print("[-] Cannot resolve domain")
        return
    print(f"[+] IP: {ip}")

    open_ports = scan_ports(ip)
    print(f"[+] Open ports: {open_ports}")

    tls = check_tls(domain) if 443 in open_ports else {"note": "No HTTPS"}
    print(f"[+] TLS: {tls}")

    headers = check_security_headers(domain)
    print(f"[+] Missing security headers: {headers.get('missing', headers)}")

    rpc_endpoints = check_json_rpc(domain, open_ports)
    print(f"[+] Exposed JSON-RPC: {len(rpc_endpoints)} found")
    for ep in rpc_endpoints:
        print(f"    → {ep['url']} ({ep.get('client', 'unknown')})")

    html, homepage = fetch_homepage(domain)
    libs = detect_web3_libs(html) if html else []
    if libs:
        print(f"[+] Web3 libs detected: {libs}")

    xss_params = simple_xss_check(homepage) if homepage else []
    if xss_params:
        print(f"[+] Reflected XSS possible on params: {xss_params}")

    result = {
        "domain": domain,
        "ip": ip,
        "open_ports": open_ports,
        "tls_info": tls,
        "missing_headers": headers.get("missing", []),
        "exposed_rpc": rpc_endpoints,
        "web3_libs": libs,
        "potential_xss_params": xss_params,
        "scanned_at": datetime.datetime.now().isoformat()
    }

    if args.output:
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2)
        print(f"[+] Results saved to {args.output}")
    else:
        print("\n=== SUMMARY ===")
        print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
