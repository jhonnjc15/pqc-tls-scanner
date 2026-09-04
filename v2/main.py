import csv
import sys
import re
import socket
from datetime import datetime
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from core.openssl import check_pq_tls

# Paths
DOMAINS_FILE = Path(__file__).parent / "data" / "domains_br.txt"
RESULTS_DIR = Path(__file__).parent / "results"
LIMIT = 2000

STRIP_PATTERN = re.compile(r'^\d+[.-]*')


def scan_domain(domain):
    """Scan a domain with fallback chain: original -> www -> stripped -> www_stripped"""
    # Build probe list inline
    probes = [domain]
    if not domain.startswith("www."):
        probes.append(f"www.{domain}")
    stripped = STRIP_PATTERN.sub('', domain)
    if stripped != domain:
        probes.append(stripped)
        if not stripped.startswith("www."):
            probes.append(f"www.{stripped}")
    
    last_result = None
    
    for probe_host in probes:
        result = check_pq_tls(probe_host)
        last_result = result
        
        if not result.get("error"):
            # SUCCESS - build row with final_host
            cert = result["certificate"]
            subj = {}
            for item in cert.get("subject", ()):
                for sub in item:
                    if isinstance(sub, tuple) and len(sub) == 2:
                        subj[sub[0]] = sub[1]
            negotiated = result.get("negotiated_group", "")
            
            return {
                "host": domain,
                "final_host": probe_host,
                "port": result["port"],
                "protocol": "https",
                "tls_version": result.get("version", "None"),
                "cipher": result["cipher"][0] if result.get("cipher") else "None",
                "kex_group": negotiated,
                "signature_algorithm": result.get("server_sigalg", "None"),
                "country_name": subj.get("countryName", "None"),
                "organization_name": subj.get("organizationName", "None"),
                "error": "",
                "dns_retries": result.get("dns_retries", 0),
            }
    
    # ALL TLS PROBES FAILED - Quick HTTP check (port 80)
    try:
        with socket.create_connection((domain, 80), timeout=5) as sock:
            sock.send(b"HEAD / HTTP/1.0\r\nHost: " + domain.encode() + b"\r\n\r\n")
            resp = sock.recv(1024).decode()
            status = int(resp.split()[1]) if len(resp.split()) > 1 else 0
            return {
                "host": domain,
                "final_host": domain,
                "port": 80,
                "protocol": "http",
                "tls_version": "None",
                "cipher": "None",
                "kex_group": "None",
                "signature_algorithm": "None",
                "country_name": "None",
                "organization_name": "None",
                "error": "",
                "dns_retries": 0,
            }
    except:
        pass
    
    # ALL PROBES FAILED
    error_msg = last_result.get("error", "Unknown error") if last_result else "Unknown error"
    return {
        "host": domain,
        "final_host": "",
        "port": 443,
        "protocol": "failed",
        "tls_version": "None",
        "cipher": "None",
        "kex_group": "None",
        "signature_algorithm": "None",
        "country_name": "None",
        "organization_name": "None",
        "error": error_msg,
        "dns_retries": last_result.get("dns_retries", 0) if last_result else 0,
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
        "final_host", "protocol",
    ]

    with open(output_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()

        for i, domain in enumerate(domains, 1):
            row = scan_domain(domain)
            writer.writerow(row)

            status = "OK" if not row["error"] else f"ERROR: {row['error'][:80]}"
            if row["protocol"] == "http":
                status += " (HTTP only)"
            elif row["final_host"] and row["final_host"] != domain:
                status += f" (via {row['final_host']})"
            print(f"[{i}/{total}] {domain}: {status}")

    print(f"\nResults saved to: {output_file}")


if __name__ == "__main__":
    main()
