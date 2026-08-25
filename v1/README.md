# v1

## Uso

```bash
# Sintaxis: uv run --python 3.15 v1/main.py <host> [grupos]
# Default: cloudflare.com con "X25519MLKEM768:X25519"

uv run --python 3.15 v1/main.py cloudflare.com
uv run --python 3.15 v1/main.py cloudflare.com "X25519MLKEM768:X25519"
uv run --python 3.15 v1/main.py cloudflare.com X25519
uv run --python 3.15 v1/main.py www.gov.br "X25519MLKEM768:X25519"
```

**Grupos** (orden de preferencia, separados por `:`):
- `X25519MLKEM768` — híbrido PQC (ML-KEM-768 + X25519)
- `X25519` — clásico
- `X448MLKEM1024`, `SecP256r1MLKEM768`, etc. — otros híbridos