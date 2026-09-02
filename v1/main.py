from pathlib import Path
import sys

# Add project root to path ../../
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from core.openssl import check_pq_tls

host = sys.argv[1] if len(sys.argv) > 1 else "cloudflare.com"
groups = sys.argv[2] if len(sys.argv) > 2 else None
result = check_pq_tls(host, groups=groups)

if result.get("error"):
    print(f"Error: {result['error']}")
    if result.get("dns_retries", 0) > 0:
        print(f"  DNS retries: {result['dns_retries']}")
    sys.exit(1)

cert = result['certificate']
subj = {}
for item in cert.get('subject', ()):
    for sub in item:
        if isinstance(sub, tuple) and len(sub) == 2:
            subj[sub[0]] = sub[1]

print(f"{host}:{result['port']}")
print(f"  TLS Version: {result.get('version', 'None')}")
print(f"  Cipher: {result.get('cipher', 'None')}")
print(f"  KEX Group: {result.get('negotiated_group', 'None')}")
print(f"  Signature Algorithm: {result.get('server_sigalg', 'None')}")
if result.get("dns_retries", 0) > 0:
    print(f"  DNS Retries: {result['dns_retries']}")
print(f"  countryName: {subj.get('countryName', 'None')}")
print(f"  organizationName: {subj.get('organizationName', 'None')}")
