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
git clone 
