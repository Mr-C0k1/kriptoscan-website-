# W3Scan Toolkit — Pemindai Keamanan Web3 & Kriptografi (Edisi 2025)
W3Scan adalah toolkit keamanan open-source berbasis command-line (CLI) yang dirancang khusus untuk auditor, bug bounty hunter , red team , dan developer Web3/Crypto. Toolkit ini menggabungkan berbagai modul spesialis untuk melakukan penilaian keamanan mendalam terhadap ekosistem kripto, mulai dari frontend DApp hingga RPC endpoint.

🛠 Modul yang Tersedia
Modul	                      Deskripsi	                              Target Utama
kriptoscan.py	    | Pemindai Situs Web Web3 & Blockchain	     | DApp, DEX, Pasar NFT, Antarmuka Pengguna Dompet
securitykripto.py | Pemindai Kerentanan Kripto Tingkat Lanjut	| Frontend Web3 (Phishing, Drainer, Injection)
w3scan-api.py     | Auditor Keamanan API Bursa Kripto         | API REST & GraphQL, Endpoint RPC

🚀 Fitur Utama
> Deteksi Penyalahgunaan Metode HTTP: Mendeteksi metode berbahaya yang aktif (PUT, DELETE, PATCH).
> Kesalahan Konfigurasi CORS: identifikasi celah Allow-Credentialsdengan wildcard.
> Analisis Header Keamanan: Mengecek tidak adanya header kritis seperti CSP, HSTS, dan X-Frame-Options.
> Sensitive Endpoint Discovery: Brute-force ringan untuk menemukan jalur sensitif seperti /wallet, /withdraw, atau /keys.
> Auditor GraphQL: Mengecek apakah fitur introspectionaktif yang dapat membocorkan skema database.
> Kebocoran Informasi: Mendeteksi kebocoran API Key dan kesalahan verbose (stack trace/DB error).

💻 Instalasi & Penggunaan
   1. Repositori Kloning
      'git clone https://github.com/Mr-C0k1/kriptoscan-website-.git
       cd kriptoscan-website'
   2. Cara Menjalankan
      Pastikan Anda telah menginstal Python 3.x.
       '# Menampilkan menu bantuan
         python3 w3scan-api.py --help

        # Scan API standar
         python3 w3scan-api.py --api https://api.target.com/api

        # Scan dengan output file JSON
         python3 w3scan-api.py --api https://api.target.com/v3 --output hasil_scan.json'


📊 Contoh Output (Pratinjau)
 ╔══════════════════════════════════════════╗
 ║         W3SCAN-API v2.0 (2025)           ║
 ║    Advanced Crypto Exchange API Auditor  ║
 ╚══════════════════════════════════════════╝

[Target] https://api.target-exchange.com/api

[+] Mengecek HTTP Methods yang diizinkan...
  → GET     → 200
  → POST    → 200
  [!] DELETE AKTIF → Potensi data tampering!

[+] Mengecek konfigurasi CORS...
  [!] CORS KRITIS → Allow-Credentials + Wildcard (*)

[+] Mengecek header keamanan kritis...
  [!] Missing → Content-Security-Policy
  [!] Missing → X-Frame-Options

[+] Brute-force ringan endpoint sensitif...
  → [OPEN] https://api.target-exchange.com/api/wallet
  → [PROTECTED] https://api.target-exchange.com/api/keys

[+] Hasil lengkap disimpan ke: hasil-scan.json


⚠️ Penafian
Peringatan: Alat ini dibuat hanya untuk tujuan pendidikan dan pengujian keamanan yang sah ( Authorized Security Testing ). Penggunaan alat ini untuk menyerang target tanpa izin tertulis dari pemilik aset adalah tindakan ilegal. Pengembang tidak bertanggung jawab atas perlindungan atau kerusakan yang disebabkan oleh alat ini. Gunakan dengan bijak.



