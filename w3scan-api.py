#!/usr/bin/env python3
"""
w3scan-api
Module untuk audit endpoint API REST/GraphQL trading platform seperti Indodax, Binance, dsb.
Analisis mencakup: HTTP method, CORS, header keamanan, dan fingerprinting error untuk mendeteksi potensi kebocoran informasi.
"""
import argparse
import requests
import json
import re
from urllib.parse import urlparse

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"]

def cek_http_methods(base_url):
    print(f"\n[+] Memeriksa metode HTTP yang didukung oleh {base_url}")
    for method in HTTP_METHODS:
        try:
            resp = requests.request(method, base_url, timeout=5)
            print(f"[=] {method} - Status: {resp.status_code}")
            if resp.status_code == 200 and method not in ["GET", "POST"]:
                print(f"[!] Metode {method} terbuka! Mungkin rawan tampering/injection.")
        except Exception as e:
            print(f"[!] Gagal {method}: {e}")

def cek_cors(base_url):
    print("\n[+] Memeriksa konfigurasi CORS...")
    try:
        headers = {
            'Origin': 'https://evil.example.com'
        }
        resp = requests.get(base_url, headers=headers, timeout=5)
        acao = resp.headers.get("Access-Control-Allow-Origin")
        if acao == "*" or "evil" in (acao or ''):
            print(f"[!] CORS terlalu longgar! Access-Control-Allow-Origin: {acao}")
        else:
            print("[-] CORS aman.")
    except Exception as e:
        print(f"[!] Gagal mengecek CORS: {e}")

def cek_header_keamanan(base_url):
    print("\n[+] Memeriksa header keamanan...")
    try:
        resp = requests.get(base_url, timeout=5)
        headers = resp.headers
        for h in ["X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security"]:
            if h not in headers:
                print(f"[!] Header {h} tidak ada!")
            else:
                print(f"[=] {h} : {headers[h]}")
    except Exception as e:
        print(f"[!] Gagal mengecek header: {e}")

def fingerprint_error_leakage(base_url):
    print("\n[+] Mendeteksi fingerprint error & kebocoran struktur backend:")
    try:
        # Trigger error: misalnya akses ID tidak valid
        resp = requests.get(base_url + "/invalid-input-xyz", timeout=5)
        if resp.status_code >= 400:
            error_text = resp.text.lower()
            leaks = ["exception", "traceback", "stack trace", "error", "mysql", "sql syntax", "oracle", "mongo", "failed to", "warning"]
            for leak in leaks:
                if leak in error_text:
                    print(f"[!] Potensi kebocoran informasi: kata kunci '{leak}' ditemukan dalam error")
                    break
            else:
                print("[-] Tidak ada fingerprint error yang mencurigakan.")
        else:
            print("[-] Tidak berhasil trigger error valid untuk fingerprinting.")
    except Exception as e:
        print(f"[!] Gagal mencoba fingerprint error: {e}")

def main():
    parser = argparse.ArgumentParser(description="w3scan-api - Audit endpoint API trading platform.")
    parser.add_argument("--api", help="URL endpoint API target, misal: https://api.example.com/v1")
    args = parser.parse_args()

    if not args.api:
        print("[!] Harap masukkan URL API menggunakan --api")
        exit(1)

    print("\n=== W3SCAN API AUDITOR - Deep Scan Mode ===")
    print(f"Target: {args.api}")

    cek_http_methods(args.api)
    cek_cors(args.api)
    cek_header_keamanan(args.api)
    fingerprint_error_leakage(args.api)

if __name__ == "__main__":
    main()
