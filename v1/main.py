# v1/scanner.py
from pathlib import Path
import sys

# Añade la raíz del proyecto al path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from core.openssl import check_pq_tls

# Ejecutar el comando
host = sys.argv[1] if len(sys.argv) > 1 else "cloudflare.com"
groups = sys.argv[2] if len(sys.argv) > 2 else "X25519MLKEM768:X25519"
resultado = check_pq_tls(host, groups=groups)

print(resultado)