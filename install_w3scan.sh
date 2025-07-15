#!/bin/bash
# install_w3scan.sh
# Installer untuk w3scan CLI tool

set -e

echo "🔧 Memulai instalasi w3scan..."

# Cek Python3
if ! command -v python3 &> /dev/null; then
    echo "[!] Python3 tidak ditemukan. Silakan instal Python3 terlebih dahulu."
    exit 1
fi

# Cek pip
if ! command -v pip3 &> /dev/null; then
    echo "[!] pip3 tidak ditemukan. Menginstal pip3..."
    sudo apt install -y python3-pip
fi

# Instalasi dependensi Python
echo "📦 Menginstal dependensi Python..."
pip3 install -U requests beautifulsoup4

# Instalasi Slither (via pip atau GitHub)
echo "🔍 Menginstal Slither..."
pip3 install slither-analyzer || {
    echo "[!] Gagal instalasi via pip. Coba via GitHub..."
    git clone https://github.com/crytic/slither.git && \
    cd slither && \
    pip3 install . && \
    cd ..
}

# Buat direktori tools jika belum ada
mkdir -p ~/w3scan
cp w3scan.py ~/w3scan/
chmod +x ~/w3scan/w3scan.py

# Tambahkan alias (opsional)
if ! grep -q 'alias w3scan=' ~/.bashrc; then
    echo "alias w3scan='python3 ~/w3scan/w3scan.py'" >> ~/.bashrc
    echo "✅ Alias \"w3scan\" ditambahkan ke ~/.bashrc"
fi

source ~/.bashrc || true

echo "✅ Instalasi selesai. Jalankan dengan perintah: w3scan --help"
