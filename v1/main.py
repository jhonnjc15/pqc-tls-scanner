from pathlib import Path
import sys
import re

# Add project root to path ../../
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from core.openssl import check_pq_tls

STRIP_PATTERN = re.compile(r'^\d+[.-]*')

host = sys.argv[1] if len(sys.argv) > 1 else "cloudflare.com"
groups = sys.argv[2] if len(sys.argv) > 2 else None

# Build probe list inline
probes = [host]
if not host.startswith("www."):
    probes.append(f"www.{host}")
stripped = STRIP_PATTERN.sub('', host)
if stripped != host:
    probes.append(stripped)
    if not stripped.startswith("www."):
        probes.append(f"www.{stripped}")

result = None
final_host = ""

for probe_host in probes:
    result = check_pq_tls(probe_host, groups=groups)
    if not result.get("error"):
        final_host = probe_host
        break

if result.get("error"):
    print(f"Error: {result['error']}")
    print(f"  Tried: {probes}")
    if result.get("dns_retries", 0) > 0:
        print(f"  DNS retries: {result['dns_retries']}")
    sys.exit(1)

print(f"Host: {host}")
if final_host and final_host != host:
    print(f"Final Host: {final_host}")
print(f"  TLS Version: {result.get('version', 'None')}")
print(f"  Cipher: {result.get('cipher', 'None')}")
print(f"  KEX Group: {result.get('negotiated_group', 'None')}")
print(f"  Signature Algorithm: {result.get('server_sigalg', 'None')}")
if result.get("dns_retries", 0) > 0:
    print(f"  DNS Retries: {result['dns_retries']}")

cert = result['certificate']
subj = {}
for item in cert.get("subject", ()):
    for sub in item:
        if isinstance(sub, tuple) and len(sub) == 2:
            subj[sub[0]] = sub[1]
print(f"  countryName: {subj.get('countryName', 'None')}")
print(f"  organizationName: {subj.get('organizationName', 'None')}")