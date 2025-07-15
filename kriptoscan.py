#!/usr/bin/env python3
"""
kriptowebscan.py
Hybrid CLI & GUI tool untuk scanning keamanan domain web tradisional + Web3/Blockchain crypto vuln.
"""

import subprocess
import threading
import json
import sys
import os
import argparse
import requests
import socket
import ssl
from urllib.parse import urlparse

# ==== Cek ketersediaan GUI ==== 
try:
    import tkinter as tk
    from tkinter import ttk, filedialog, scrolledtext
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False

# ==== Fungsi Scan Subdomain, Recon, Bypass (fallback) ====
def run_w3scan_modules(domain, wordlist=None, output=None, result_callback=None):
    def run_cmd(cmd, label):
        if result_callback:
            result_callback(f"[+] Menjalankan {label} untuk {domain}\n")
        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for line in process.stdout:
                if result_callback:
                    result_callback(line)
            process.wait()
        except FileNotFoundError:
            if result_callback:
                result_callback(f"[!] File {cmd[1]} tidak ditemukan, melewati...\n")

    # w3scan_subdomain.py
    cmd_subdomain = ["python3", "w3scan_subdomain.py", "--domain", domain]
    if wordlist:
        cmd_subdomain += ["--wordlist", wordlist]
    if output:
        cmd_subdomain += ["--output", output]
    run_cmd(cmd_subdomain, "w3scan_subdomain.py")

    # recon_url.py
    cmd_recon = ["python3", "modules/recon_url.py", "--domain", domain]
    run_cmd(cmd_recon, "recon_url.py")

    # param_bypass.py
    cmd_bypass = ["python3", "modules/param_bypass.py", "--domain", domain]
    run_cmd(cmd_bypass, "param_bypass.py")

# ==== Fungsi Deep Scan Crypto/Web3 Blockchain Vulnerabilities ====

def get_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except Exception:
        return "Tidak ditemukan"

def scan_open_ports(ip, ports=[80,443,8545,8546,30303,30304,7545]):
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        try:
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except:
            pass
    return open_ports

def check_tls(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                # Cek validitas sertifikat (waktu, issuer)
                return {
                    "subject": dict(x[0] for x in cert.get('subject', [])),
                    "issuer": dict(x[0] for x in cert.get('issuer', [])),
                    "notBefore": cert.get('notBefore'),
                    "notAfter": cert.get('notAfter'),
                }
    except Exception as e:
        return {"error": str(e)}

def detect_json_rpc(domain):
    """
    Cek endpoint JSON-RPC default Ethereum node
    Biasanya di port 8545, 8546 (HTTP RPC), port 30303 (p2p)
    """
    ip = get_ip(domain)
    results = []
    for port in [8545, 8546]:
        url = f"http://{ip}:{port}"
        try:
            r = requests.post(url, json={"jsonrpc":"2.0","method":"web3_clientVersion","params":[],"id":1}, timeout=3)
            if r.status_code == 200:
                results.append({"url": url, "response": r.json()})
        except:
            pass
    return results

def check_etherscan_contract(domain):
    """
    Placeholder: Jika domain punya kontrak di Etherscan, bisa ditambahkan API scan
    (Perlu API key & API call, jadi ini hanya dummy contoh)
    """
    return "Fitur belum diimplementasikan"

def analyze_javascript_libraries(domain):
    """
    Ambil source homepage dan cek library JS yang mungkin rentan
    (Contoh sederhana, cek keberadaan web3.js)
    """
    try:
        url = domain if domain.startswith("http") else "http://" + domain
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            content = r.text.lower()
            found_libs = []
            if "web3.js" in content or "web3.min.js" in content:
                found_libs.append("web3.js (library blockchain Web3)")
            if "ethers.js" in content or "ethers.min.js" in content:
                found_libs.append("ethers.js (library blockchain Web3)")
            # bisa tambah cek library lain dan versinya dengan regex
            return found_libs
    except:
        return []
    return []

def deep_crypto_scan(domain, result_callback=None):
    if result_callback:
        result_callback(f"\n=== Deep Crypto/Web3 Blockchain Vulnerability Scan untuk {domain} ===\n")

    ip = get_ip(domain)
    if result_callback:
        result_callback(f"IP address: {ip}\n")

    open_ports = scan_open_ports(ip)
    if result_callback:
        result_callback(f"Port terbuka umum (80,443,8545,30303,...): {open_ports}\n")

    tls_info = check_tls(domain)
    if result_callback:
        result_callback(f"Info sertifikat TLS:\n{json.dumps(tls_info, indent=2)}\n")

    json_rpc = detect_json_rpc(domain)
    if result_callback:
        if json_rpc:
            result_callback(f"JSON-RPC endpoint ditemukan:\n{json.dumps(json_rpc, indent=2)}\n")
        else:
            result_callback("JSON-RPC endpoint tidak ditemukan atau tidak responsif.\n")

    js_libs = analyze_javascript_libraries(domain)
    if result_callback:
        if js_libs:
            result_callback(f"Library JavaScript blockchain ditemukan: {', '.join(js_libs)}\n")
        else:
            result_callback("Library JavaScript blockchain tidak ditemukan di homepage.\n")

    etherscan_info = check_etherscan_contract(domain)
    if result_callback:
        result_callback(f"Scan kontrak di Etherscan: {etherscan_info}\n")

    if result_callback:
        result_callback("\n=== Scan selesai ===\n")

# ==== GUI Mode ====

if GUI_AVAILABLE:
    class CryptoWebScanGUI:
        def __init__(self, root):
            self.root = root
            self.root.title("KriptoWebScan - Hybrid Scanner")
            self.root.geometry("800x700")
            self.create_widgets()

        def create_widgets(self):
            frame = ttk.Frame(self.root, padding=10)
            frame.pack(fill=tk.BOTH, expand=True)

            ttk.Label(frame, text="Target Domain / URL:").grid(row=0, column=0, sticky=tk.W)
            self.domain_entry = ttk.Entry(frame, width=50)
            self.domain_entry.grid(row=0, column=1, columnspan=2, pady=5)

            ttk.Label(frame, text="Wordlist (opsional):").grid(row=1, column=0, sticky=tk.W)
            self.wordlist_entry = ttk.Entry(frame, width=50)
            self.wordlist_entry.grid(row=1, column=1, pady=5)
            ttk.Button(frame, text="Browse", command=self.browse_wordlist).grid(row=1, column=2)

            ttk.Label(frame, text="Output file JSON (opsional):").grid(row=2, column=0, sticky=tk.W)
            self.output_entry = ttk.Entry(frame, width=50)
            self.output_entry.grid(row=2, column=1, pady=5)
            ttk.Button(frame, text="Browse", command=self.browse_output).grid(row=2, column=2)

            ttk.Button(frame, text="Mulai Scan", command=self.run_scan).grid(row=3, column=1, pady=10)

            self.result_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, height=30)
            self.result_text.grid(row=4, column=0, columnspan=3, pady=10)

        def browse_wordlist(self):
            path = filedialog.askopenfilename(title="Pilih wordlist")
            if path:
                self.wordlist_entry.delete(0, tk.END)
                self.wordlist_entry.insert(0, path)

        def browse_output(self):
            path = filedialog.asksaveasfilename(title="Simpan output sebagai", defaultextension=".json")
            if path:
                self.output_entry.delete(0, tk.END)
                self.output_entry.insert(0, path)

        def append_text(self, text):
            self.result_text.insert(tk.END, text)
            self.result_text.see(tk.END)

        def run_scan(self):
            domain = self.domain_entry.get()
            wordlist = self.wordlist_entry.get()
            output = self.output_entry.get()

            if not domain:
                self.append_text("[!] Harap isi domain target.\n")
                return

            self.result_text.delete('1.0', tk.END)
            self.append_text(f"[+] Mulai scan untuk domain: {domain}\n")

            # Jalankan modul w3scan secara thread
            threading.Thread(target=run_w3scan_modules, args=(domain, wordlist, output, self.append_text), daemon=True).start()
            # Jalankan deep crypto scan juga thread
            threading.Thread(target=deep_crypto_scan, args=(domain, self.append_text), daemon=True).start()

# ==== CLI Mode ====

def main_cli(args):
    domain = args.d
    wordlist = args.wordlist
    output = args.output

    if not domain:
        print("[!] Harap masukkan domain target dengan opsi --d")
        sys.exit(1)

    print(f"[+] Mulai scan untuk domain: {domain}\n")

    def print_callback(text):
        print(text, end='')

    run_w3scan_modules(domain, wordlist, output, print_callback)
    deep_crypto_scan(domain, print_callback)

# ==== MAIN ENTRY ====

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="KriptoWebScan - Hybrid Scanner CLI/GUI")
    parser.add_argument("--d", help="Target domain untuk scan")
    parser.add_argument("--wordlist", help="Wordlist opsional untuk subdomain scan")
    parser.add_argument("--output", help="Output file JSON opsional")
    args = parser.parse_args()

    if args.d:
        main_cli(args)
    elif GUI_AVAILABLE:
        root = tk.Tk()
        app = CryptoWebScanGUI(root)
        root.mainloop()
    else:
        print("[!] Tidak ada GUI dan argumen domain ditemukan. Gunakan opsi --d example.com")
