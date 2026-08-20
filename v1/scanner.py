import sys


sys.path.insert(0, ".")

from core import openssl, parser  # noqa: E402

host = sys.argv[1] if len(sys.argv) > 1 else "example.com"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 443

print(f"OpenSSL: {openssl.version()}")
print(f"IP: {openssl.peer_ip(host)}")

r = parser.parse(openssl.s_client(host, port).stdout)

if not r["connected"]:
    r = parser.parse(openssl.s_client(host, port, groups="X25519").stdout)

group = r.get("negotiated_group") or ""
print(f"Conectado: {'Sí' if r['connected'] else 'No'}")
print(f"Protocolo: {r['protocol']}")
print(f"Cipher: {r['cipher']}")
print(f"Grupo negociado: {group}")
print(f"Firma: {r['signature']}")
print(f"Organización: {r['org']} ({r['country']})")
print(f"PQC Support: {'Sí' if 'MLKEM' in group else 'No'}")
print(f"PQC Deployment: {'Sí' if group.startswith('X25519MLKEM') else 'No'}")
print(f"Brazilian website: {'Sí' if r['country'] == 'BR' else 'No'}")