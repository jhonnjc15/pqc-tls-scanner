# core/openssl.py
import ssl
import socket

def check_pq_tls(host, port=443, groups="X25519MLKEM768:X25519"):
    """Conecta usando SSL nativo de Python y devuelve los datos del certificado"""
    
    # Crear contexto SSL
    context = ssl.create_default_context()
    
    # Grupos TLS 1.3 parametrizables
    context.set_groups(groups)
    print(ssl.OPENSSL_VERSION)
    # Conectar y hacer handshake TLS
    with socket.create_connection((host, port), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            
            # Obtener el certificado (¡ya parseado en un diccionario!)
            cert = ssock.getpeercert(binary_form=False)
            
# Obtener información de la conexión
            cipher = ssock.cipher()
            version = ssock.version()
            negotiated_group = ssock.group()
            
            return {
                "certificate": cert,
                "cipher": cipher,
                "version": version,
                "negotiated_group": negotiated_group,
                "host": host,
                "port": port,
            }