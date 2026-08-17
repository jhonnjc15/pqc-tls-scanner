# pqc-tls-scanner

## Instalación de OpenSSL 4.0.1

El proyecto utiliza OpenSSL 4.0.1. La instalación se realiza desde el código
fuente para controlar explícitamente la versión de OpenSSL utilizada durante
los experimentos.

Archivo utilizado: `openssl-4.0.1.tar.gz`

1. **Descargar OpenSSL** desde la terminal:
   ```bash
   wget https://www.openssl.org/source/openssl-4.0.1.tar.gz
   ```
2. **Descomprimir**:
   ```bash
   tar -zxvf openssl-4.0.1.tar.gz
   ```
3. **Entrar al directorio**:
   ```bash
   cd openssl-4.0.1
   ```
4. **Configurar la compilación**:
   ```bash
   ./config
   ```
5. **Compilar** (puede tardar algunos minutos):
   ```bash
   make
   ```
6. **Instalar**:
   ```bash
   sudo make install
   ```
7. **Configurar las bibliotecas compartidas** (indicar al sistema dónde
   encontrarlas y actualizar el caché del dynamic linker):
   ```bash
   sudo sh -c 'echo "/usr/local/lib64" > /etc/ld.so.conf.d/openssl.conf'
   sudo ldconfig
   ```
8. **Verificar la instalación**:
   ```bash
   openssl version
   # Resultado esperado: OpenSSL 4.0.1 9 Jun 2026 (Library: OpenSSL 4.0.1 9 Jun 2026)

   which openssl
   # Resultado esperado: /usr/local/bin/openssl
   ```

La instalación coloca el ejecutable en `/usr/local/bin/openssl` y las
bibliotecas compartidas en `/usr/local/lib64/`.