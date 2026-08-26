from pathlib import Path
import sys

#Add project root to path ../../
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from core.openssl import check_pq_tls

def _subject_dict(cert):
    d = {}
    for item in cert.get('subject', ()):
        for sub in item:
            if isinstance(sub, tuple) and len(sub) == 2:
                d[sub[0]] = sub[1]
    return d

host = sys.argv[1] if len(sys.argv) > 1 else "cloudflare.com"
groups = sys.argv[2] if len(sys.argv) > 2 else "X25519MLKEM768:X25519"
result = check_pq_tls(host, groups=groups)

print("Original results:")
print(result)
print("\n")
print("\n")
print("\n")

cert = result['certificate']
subj = _subject_dict(cert)

print(f"{host}:{result['port']}")
print(f"  TLS Version: {result.get('version', 'None')}")
print(f"  Cipher: {result.get('cipher', 'None')}")
print(f"  KEX Group: {result.get('negotiated_group', 'None')}")
print(f"  Signature Algorithm: {result.get('server_sigalg', 'None')}")
#print(f"  Subject: {cert.get('subject')}")
#print(f"  Issuer: {cert.get('issuer')}")
#print(f"  SAN: {cert.get('subjectAltName')}")
print(f"  countryName: {subj.get('countryName', 'None')}")
print(f"  organizationName: {subj.get('organizationName', 'None')}")
