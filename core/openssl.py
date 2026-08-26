import ssl
import socket


def check_pq_tls(host, port=443, groups="X25519MLKEM768:X25519"):
    """Connect using Python native SSL and return certificate data"""

    #SSL context
    context = ssl.create_default_context()

    #TLS 1.3 groups
    context.set_groups(groups)

    #Connect and perform TLS handshake
    with socket.create_connection((host, port), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:

            #Get certificate
            cert = ssock.getpeercert(binary_form=False)
            cert_chain = ssock.get_unverified_chain()

            #Connection information
            cipher = ssock.cipher()
            version = ssock.version()
            negotiated_group = ssock.group()
            server_sigalg = ssock.server_sigalg() if hasattr(ssock, 'server_sigalg') else None
            client_sigalg = ssock.client_sigalg() if hasattr(ssock, 'client_sigalg') else None
            client_groups = context.get_groups()

            return {
                "certificate": cert,
                "cert_chain": cert_chain,
                "cipher": cipher,
                "version": version,
                "negotiated_group": negotiated_group,
                "server_sigalg": server_sigalg,
                "client_sigalg": client_sigalg,
                "client_groups": client_groups,
                "host": host,
                "port": port,
            }