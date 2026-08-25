# pqc-tls-scanner

Escáner TLS para detectar soporte de grupos post-cuánticos (ML-KEM) en servidores.

## Requisitos

- **Python 3.15+** (necesario para `ssl.SSLContext.set_groups()` y `SSLSocket.group()`)
- **uv** (gestor de Python y dependencias)

## Instalación rápida

```bash
# 1. Instalar uv
curl -LsSf https://astral.sh/uv/install.sh | sh
source $HOME/.local/bin/env

# 2. Instalar Python 3.15 (requerido para APIs de grupos TLS 1.3)
uv python install --pre 3.15

# 3. Clonar y usar
git clone git@github.com:jhonnjc15/pqc-tls-scanner.git
cd pqc-tls-scanner
uv run --python 3.15 v1/main.py cloudflare.com "X25519MLKEM768:X25519"
```

## Por qué Python 3.15

Las APIs `set_groups()` / `get_groups()` / `SSLSocket.group()` para inspeccionar y configurar grupos de intercambio de claves TLS 1.3 (incluyendo híbridos PQC como `X25519MLKEM768`) **solo existen en Python 3.15+**. Python 3.14 no las tiene.