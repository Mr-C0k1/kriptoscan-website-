#!/usr/bin/env python3
import requests
import socket
import ssl
import json
import sys
import re
from urllib.parse import urlparse, urljoin

# Disable warnings untuk self-signed cert (testing only)
requests.packages.urllib3.disable_warnings()

# Path sensitif khusus kripto & admin
CRYPTO_PATHS = [
    '/', '/api', '/admin', '/dashboard', '/rpc', '/jsonrpc', '/eth', '/web3',
    '/debug', '/console', '/wallet', '/connect', '/auth', '/signin', '/claim',
    '/airdrop', '/faucet', '/bridge', '/swap', '/stake'
]

# Metode HTTP berbahaya
DANGER_METHODS = ['PUT', 'DELETE', 'PATCH', 'TRACE', 'OPTIONS']

# Header keamanan penting
SEC_HEADERS = [
    'Content-Security-Policy', 'X-Frame-Options', 'Strict-Transport-Security',
    'X-Content-Type-Options', 'Referrer-Policy', 'Permissions-Policy'
]

# Pola phishing & drainer terbaru (2025)
PHISHING_PATTERNS = [
    r'metamask.*(login|connect|sync)',
    r'wallet.*(connect|sign|approve|drain)',
    r'phantom.*(connect|authorize)',
    r'confirm.*(transaction|signature|approval)',
    r'(airdrop|claim|reward).*eth',
    r'urgent.*maintenance',
    r'sync.*wallet.*now',
    r'unusual.*activity.*detected'
]

# Pola JavaScript drainer/injection berbahaya
DRAINER_SIGNS = [
    'wallet.requestpermissions',
    'ethereum.request({method:"eth_sendtransaction"',
    'personal_sign',
    'eth_signTypedData',
    'window.ethereum.enable()',
    'web3.currentProvider.sendAsync',
    'eval(', 'atob(', 'new Function(',
    'document.write(', 'setTimeout("location',
    'drainer', 'approve.*unlimited', 'setapprovalforall'
]

def resolve_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return None

def quick_port_scan(ip, ports=[80, 443, 8545, 30303, 8546, 6060]):
    open_ports = []
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.7)
        if s.connect_ex((ip, p)) == 0:
            open_ports.append(p)
        s.close()
    return open_ports

def check_tls(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.connect((domain, 443))
            cert = s.getpeercert()
            return {"valid": True, "subject": cert.get('subject'), "issuer": cert.get('issuer')}
    except:
        return {"valid": False, "error": "TLS failed or no cert"}

def check_methods(url):
    risky = {}
    for path in CRYPTO_PATHS:
        full = urljoin(url, path)
        for method in DANGER_METHODS:
            try:
                r = requests.request(method, full, timeout=4, verify=False)
                if 200 <= r.status_code < 400:
                    risky.setdefault(path, []).append(method)
            except:
                pass
    return risky

def check_cors(url):
    try:
        r = requests.options(url, headers={'Origin': 'https://evil.com'}, timeout=4, verify=False)
        acao = r.headers.get('Access-Control-Allow-Origin')
        creds = r.headers.get('Access-Control-Allow-Credentials')
        if acao in ['*', 'https://evil.com'] or (acao and creds == 'true'):
            return True, acao
    except:
        pass
    return False, None

def check_headers(url):
    try:
        r = requests.get(url, timeout=5, verify=False)
        missing = [h for h in SEC_HEADERS if h not in r.headers]
        return missing, r.headers
    except:
        return SEC_HEADERS, {}

def detect_phishing_and_drainer(url):
    try:
        r = requests.get(url, timeout=6, verify=False)
        body = r.text.lower()
        js_files = re.findall(r'src=["\']([^"\']+\.js)["\']', r.text)
        
        phishing_hits = [p for p in PHISHING_PATTERNS if re.search(p, body)]
        drainer_hits = [s for s in DRAINER_SIGNS if s.lower() in body]
        
        # Scan JS eksternal (opsional ringan)
        external_drainer = []
        for js in js_files[:5]:  # limit
            try:
                js_url = urljoin(url, js)
                js_content = requests.get(js_url, timeout=4, verify=False).text.lower()
                if any(d in js_content for d in DRAINER_SIGNS):
                    external_drainer.append(js_url)
            except:
                pass
        
        return {
            "phishing": bool(phishing_hits),
            "phishing_patterns": phishing_hits,
            "drainer_in_page": bool(drainer_hits),
            "drainer_signs": drainer_hits,
            "drainer_in_js": external_drainer
        }
    except:
        return {"error": "Failed to fetch page"}

def detect_stack(headers):
    server = headers.get('Server', '').lower()
    powered = headers.get('X-Powered-By', '').lower()
    if 'cloudflare' in server: return "Cloudflare"
    if 'vercel' in server: return "Vercel"
    if 'netlify' in server: return "Netlify"
    if 'express' in powered: return "Express.js"
    if 'nginx' in server: return "Nginx"
    if 'apache' in server: return "Apache"
    return "Unknown"

def print_risks(risks):
    print("\n" + "="*60)
    print("              RISIKO KEAMANAN KRIPTO PRIORITAS TINGGI")
    print("="*60)
    
    if risks['exposed_rpc']:
        print("🔥 EXPOSED RPC DETECTED → Potensi serangan langsung ke node/wallet!")
    
    if risks['drainer']:
        print("🚨 WALLET DRAINER DETECTED → Situs berbahaya! Jangan hubungkan wallet!")
    
    if risks['phishing']:
        print("⚠️ PHISHING PATTERN → Kemungkinan besar scam wallet")
    
    if risks['risky_methods']:
        print("⚡ RISKY HTTP METHODS → Potensi bypass autentikasi atau overwrite data")
    
    if risks['cors_misconfig']:
        print("🌐 CORS MISCONFIG → Data bisa dicuri via domain lain")
    
    if risks['missing_headers'] == len(SEC_HEADERS):
        print("🛡️ NO SECURITY HEADERS → Rentan clickjacking, XSS, MIME sniffing")
    
    if not any(risks.values()):
        print("✅ Tidak ditemukan risiko kritis kripto saat ini.")

def main(target_url):
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url
    
    print(f"\n[+] SecurityKripto Scanner 2025 → {target_url}\n")
    
    parsed = urlparse(target_url)
    domain = parsed.netloc
    
    ip = resolve_ip(domain)
    print(f"[IP] {ip or 'Gagal resolve'}")
    
    open_ports = quick_port_scan(ip) if ip else []
    print(f"[Port Terbuka] {open_ports}")
    
    tls = check_tls(domain)
    print(f"[TLS] {'Valid' if tls.get('valid') else 'Invalid/Failed'}")
    
    risky_methods = check_methods(target_url)
    cors_vuln, acao = check_cors(target_url)
    missing_headers, headers = check_headers(target_url)
    crypto_threats = detect_phishing_and_drainer(target_url)
    stack = detect_stack(headers)
    
    # Ringkasan risiko
    risks = {
        "exposed_rpc": any(p in [8545, 8546, 30303, 6060] for p in open_ports),
        "drainer": crypto_threats.get("drainer_in_page") or bool(crypto_threats.get("drainer_in_js")),
        "phishing": crypto_threats.get("phishing"),
        "risky_methods": bool(risky_methods),
        "cors_misconfig": cors_vuln,
        "missing_headers": len(missing_headers)
    }
    
    print(f"\n[Stack] {stack}")
    if risky_methods:
        print("\n[RISKY METHODS]")
        for path, methods in risky_methods.items():
            print(f"  → {path}: {', '.join(methods)}")
    
    if cors_vuln:
        print(f"\n[CORS VULN] Access-Control-Allow-Origin: {acao or '*'}")
    
    if missing_headers:
        print(f"\n[MISSING HEADERS] {', '.join(missing_headers)}")
    
    if crypto_threats.get("phishing_patterns"):
        print(f"\n[PHISHING HITS] {', '.join(crypto_threats['phishing_patterns'])}")
    
    if crypto_threats.get("drainer_signs") or crypto_threats.get("drainer_in_js"):
        print("\n[DRAINER SIGNS]")
        for sign in crypto_threats.get("drainer_signs", []):
            print(f"  → {sign}")
        for js in crypto_threats.get("drainer_in_js", []):
            print(f"  → External JS: {js}")
    
    print_risks(risks)
    
    # Output JSON opsional
    result = {
        "target": target_url,
        "ip": ip,
        "open_ports": open_ports,
        "tls": tls,
        "stack": stack,
        "risky_http_methods": risky_methods,
        "cors_vulnerable": cors_vuln,
        "missing_security_headers": missing_headers,
        "phishing_detected": crypto_threats.get("phishing"),
        "wallet_drainer_detected": risks["drainer"],
        "high_risk": any(risks.values())
    }
    
    print("\n[JSON OUTPUT]")
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 securitykripto.py https://target.com")
        sys.exit(1)
    main(sys.argv[1])
