# W3Scan Toolkit — Web3 & Crypto Security Scanner (2025 Edition)
W3Scan is an open-source command-line (CLI) security toolkit specifically designed for auditors, bug bounty hunters, red teams, and Web3/Crypto developers. This toolkit combines multiple specialized modules to perform deep security assessments of the crypto ecosystem, ranging from DApp frontends to RPC endpoints.

🛠 Available Modules
kriptoscan.py > Web3 & Blockchain Website Scanner > DApps, DEXs, NFT Marketplaces, Wallet UIs
securitykripto.py	> Advanced Crypto Vulnerability Scanner > Web3 Frontend (Phishing, Drainers, Injections)
w3scan-api.py  > Crypto Exchange API Security Auditor > REST & GraphQL APIs, RPC Endpoints

🚀 Key Features
> HTTP Method Abuse Detection: Identifies dangerous active methods (PUT, DELETE, PATCH).
> CORS Misconfiguration: Detects Allow-Credentials vulnerabilities combined with wildcards.
> Security Header Analysis: Checks for the absence of critical headers such as CSP, HSTS, and X-Frame-Options.
> Sensitive Endpoint Discovery: Light brute-force to uncover sensitive paths like /wallet, /withdraw, or /keys.
> GraphQL Auditor: Checks if the introspection feature is enabled, which may leak database schemas.
> Information Leakage: Detects API Key exposure and verbose error messages (stack traces/DB errors).

💻 Installation & Usage
1. Clone the Repository
"git clone https://github.com/Mr-C0k1/kriptoscan-website-.git
cd kriptoscan-website"

2. How to Run
Ensure you have Python 3.x installed.
"# Display help menu
python3 w3scan-api.py --help

# Scan a standard API
python3 w3scan-api.py --api https://api.target.com/api

# Scan and save results to a JSON file
python3 w3scan-api.py --api https://api.target.com/v3 --output scan_results.json"

📊 Output Example (Preview)

           W3SCAN-API v2.0 (2025)           
      Advanced Crypto Exchange API Auditor   

[Target] https://api.target-exchange.com/api

[+] Checking allowed HTTP Methods...
  → GET     → 200
  → POST    → 200
  [!] DELETE ACTIVE → Potential data tampering!

[+] Checking CORS configuration...
  [!] CRITICAL CORS → Allow-Credentials + Wildcard (*)

[+] Checking critical security headers...
  [!] Missing → Content-Security-Policy
  [!] Missing → X-Frame-Options

[+] Performing light brute-force on sensitive endpoints...
  → [OPEN] https://api.target-exchange.com/api/wallet
  → [PROTECTED] https://api.target-exchange.com/api/keys

[+] Full results saved to: scan_results.json

⚠️ Disclaimer

Warning: This tool is created for educational purposes and Authorized Security Testing only. Using this tool to attack targets without prior written consent from the asset owner is illegal. The developer assumes no liability and is not responsible for any misuse or damage caused by this tool. Use it responsibly.
