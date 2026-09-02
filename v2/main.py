import csv
import sys
from datetime import datetime
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from core.openssl import check_pq_tls

# Paths
DOMAINS_FILE = Path(__file__).parent / "data" / "domains_br.txt"
RESULTS_DIR = Path(__file__).parent / "results"
LIMIT = 20


def scan_domain(domain):
    """Scan a single domain and return a result row"""
    result = check_pq_tls(domain)
    
    if result.get("error"):
        return {
            "host": domain,
            "port": 443,
            "tls_version": "None",
            "cipher": "None",
            "kex_group": "None",
            "signature_algorithm": "None",
            "country_name": "None",
            "organization_name": "None",
            "error": result["error"],
            "dns_retries": result.get("dns_retries", 0),
        }

    cert = result["certificate"]
    subj = {}
    for item in cert.get("subject", ()):
        for sub in item:
            if isinstance(sub, tuple) and len(sub) == 2:
                subj[sub[0]] = sub[1]

    negotiated = result.get("negotiated_group", "")

    return {
        "host": domain,
        "port": result["port"],
        "tls_version": result.get("version", "None"),
        "cipher": result["cipher"][0] if result.get("cipher") else "None",
        "kex_group": negotiated,
        "signature_algorithm": result.get("server_sigalg", "None"),
        "country_name": subj.get("countryName", "None"),
        "organization_name": subj.get("organizationName", "None"),
        "error": "",
        "dns_retries": result.get("dns_retries", 0),
    }


def main():
    # Read domains
    with open(DOMAINS_FILE) as f:
        domains = [line.strip() for line in f if line.strip()]

    # Apply limit
    domains = domains[:LIMIT]
    total = len(domains)

    # Create output file with timestamp
    RESULTS_DIR.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = RESULTS_DIR / f"scan_{timestamp}.csv"

    # CSV columns
    fields = [
        "host", "port", "tls_version", "cipher", "kex_group",
        "signature_algorithm", "country_name", "organization_name",
        "error", "dns_retries",
    ]

    with open(output_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()

        for i, domain in enumerate(domains, 1):
            row = scan_domain(domain)
            writer.writerow(row)

            status = "OK" if not row["error"] else f"ERROR: {row['error'][:50]}"
            print(f"[{i}/{total}] {domain}: {status}")

    print(f"\nResults saved to: {output_file}")


if __name__ == "__main__":
    main()
