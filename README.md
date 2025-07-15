# kriptoscan-website-scanner
w3scan adalah toolkit keamanan berbasis command-line yang dirancang untuk mendeteksi kerentanan pada smart contract, RPC endpoint, Web3 DApps, wallet UI, dan API platform trading seperti Indodax, Binance, dll.
Toolkit ini menyatukan beberapa modul audit untuk menganalisis keamanan secara menyeluruh terhadap berbagai komponen dunia Web3 dan sistem API modern.

**🧩 Modul Tersedia**
Modul	Deskripsi
w3scan-contract	Audit kode Solidity menggunakan Slither untuk mendeteksi kerentanan umum seperti reentrancy, integer overflow, dll.
w3scan-rpc	Mendeteksi konfigurasi buruk pada endpoint RPC publik (terbuka, debug aktif, anonymous calls).
w3scan-dapp	Cek potensi injeksi JavaScript, DOM-based XSS, dan kesalahan implementasi wallet connect pada Web3 DApps.
w3scan-wallet	Deteksi phishing pada antarmuka wallet connect (UI yang meminta seed phrase, private key, dll).
w3scan-api	Audit endpoint API REST/GraphQL (CORS, HTTP method abuse, header keamanan, dan error fingerprinting).

#SKEMASI INSTALL GIT 
git clone https://github.com/Mr-C0k1/kriptoscan-website-/tree/main
chmod +x install_w3scan.sh 
./install_w3scan.sh  (*running dengan bash*)
# Audit smart contract Solidity
w3scan --contract contracts/mycontract.sol

# Scan endpoint RPC
w3scan --rpc https://mainnet.infura.io/v3/KEY
# Scan DApp untuk XSS/injection
w3scan --dapp https://app.example.com
# Scan UI Wallet Connect dari phishing
w3scan --wallet https://fakeconnect.example.io
# Audit API REST trading platform
python3 w3scan_api_scanner.py --api https://api.exchange.com/v1/user



#**🔍 Fitur Tambahan (Deep Scan Mode)**
HTTP Method Injection Detection
Menandai jika PUT, DELETE, PATCH aktif
CORS Misconfig
Menyisipkan Origin: evil.example.com dan mendeteksi jika diterima
Security Header Analysis
Deteksi hilangnya CSP, X-Frame-Options, HSTS
Error Fingerprinting
Mengakses endpoint fiktif (/invalid-input-xyz)
Mendeteksi kebocoran seperti:
exception, stack trace
MySQL error, Mongo, Oracle
warning, traceback

python3 w3scan_api_scanner.py --api https://api.indodax.com/api/ticker/btc_idr (*running dengan python untuk api scan*)

(CONTOH OUPUT)
=== W3SCAN API AUDITOR ===
Target: https://api.indodax.com/api/ticker/btc_idr

[+] Memeriksa metode HTTP:
[=] GET - Status: 200
[=] POST - Status: 405
...

[+] Memeriksa konfigurasi CORS:
[-] CORS aman.

[+] Memeriksa header keamanan:
[=] Strict-Transport-Security : max-age=31536000
[!] Header Content-Security-Policy tidak ada!


