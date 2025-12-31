# W3Scan Toolkit — Web3 & Crypto Security Scanner (2025 Edition)
W3Scan adalah toolkit keamanan open-source berbasis command-line yang dirancang khusus untuk auditor, bug bounty hunter, red team, dan developer Web3/crypto di Indonesia & global.
Toolkit ini menggabungkan beberapa modul spesialis untuk melakukan deep security assessment terhadap berbagai komponen ekosistem kripto:

# Website & DApp (frontend)
Blockchain node & RPC endpoint
API trading platform.

# Modul yang Tersedia
ModulDeskripsiTarget Utamakriptoscan.pyWeb3 & Blockchain Website ScannerDApp, DEX, NFT marketplace, wallet UIsecuritykripto.pyAdvanced Crypto Website Vulnerability ScannerFrontend Web3 (phishing, drainer, injection)w3scan-api.pyCrypto Exchange API Security Auditor (REST & GraphQL).

# INSTALASI  
"Clone repository
git clone https://github.com/Mr-C0k1/kriptoscan-website-.git
cd kriptoscan-website"

# Beri izin eksekusi & jalankan installer (opsional untuk dependency)
"python3 w3scan-api.py --help
 python3 w3scan-api.py --api https://api.anonim.com/api
 python3 w3scan-api.py --api https://api.anonim.com/api/v3 --output binance.json
 python3 w3scan-api.py --api https://api.anonim.com/open/v1"

# Fitur Utama:
1. HTTP method abuse detection (PUT, DELETE, PATCH aktif?)
2. CORS misconfiguration (Allow-Credentials + wildcard)
3. Missing critical security headers
4. Rate limit header analysis
5. Sensitive endpoint discovery (/wallet, /withdraw, /keys, /graphql)
6. GraphQL introspection enabled check
7. Error fingerprinting & potential API key leakage
8. Verbose error disclosure (stack trace, DB error)

 ╔══════════════════════════════════════════╗
 ║           W3SCAN-API v2.0 (2025)         ║
 ║   Advanced Crypto Exchange API Auditor   ║
 ╚══════════════════════════════════════════╝

[Target] https://api.indodax.com/api

[+] Mengecek HTTP Methods yang diizinkan...
  → GET     → 200
  → POST    → 200
  [!] DELETE AKTIF → Potensi data tampering!

[+] Mengecek konfigurasi CORS...
  [!] CORS KRITIS → Allow-Credentials + *

[+] Mengecek header keamanan kritis...
  [!] Missing → Content-Security-Policy
  [!] Missing → X-Frame-Options

[+] Brute-force ringan endpoint sensitif...
  → [OPEN] https://api.anonim.com/api/wallet
  → [PROTECTED] https://api.anonim.com/api/keys

[+] Mengecek GraphQL Introspection...
  [-] Introspection tidak aktif

[+] Hasil lengkap disimpan ke: hasil-scan.json 


# DISCLAMER 
GUNAKAN TOOLS DI ATAS DENGAN BIJAK, DEVELOPER TIDAK BERTANGGUNG JAWAB APA BILA DI DALAM PENGGUNAAN TOOLS TERSEBUT DI SALAH GUNAKAN, TUJUAN DI ADAKAN NYA TOOLS TERSEBUT KHUSUS UNTUK DELIGASI KEAMANAN TESTING, BUKAN UNTUK PERETASAN ILEGAL





 




