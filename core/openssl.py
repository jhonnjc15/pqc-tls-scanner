import ssl
import socket
import time


DEFAULT_GROUPS = (
    "MLKEM512:MLKEM768:MLKEM1024:SecP256r1MLKEM768:X25519MLKEM768:SecP384r1MLKEM1024:"
    "secp256r1:secp384r1:secp521r1:x448:"
    "brainpoolP256r1tls13:brainpoolP384r1tls13:brainpoolP512r1tls13:"
    "ffdhe2048:ffdhe3072:ffdhe4096:ffdhe6144:ffdhe8192:x25519"
)

DNS_TRANSIENT_ERRNOS = (-3, -2)  # EAI_AGAIN, EAI_NONAME


def check_pq_tls(host, port=443, groups=None, max_retries=3, base_delay=1.0):
    """Connect using Python native SSL and return certificate data"""
    if groups is None:
        groups = DEFAULT_GROUPS

    context = ssl.create_default_context()
    context.set_groups(groups)

    retries = 0
    last_error = None

    while retries <= max_retries:
        try:
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:

                    cert = ssock.getpeercert(binary_form=False)

                    cipher = ssock.cipher()
                    version = ssock.version()
                    negotiated_group = ssock.group()
                    server_sigalg = ssock.server_sigalg() if hasattr(ssock, 'server_sigalg') else None

                    return {
                        "certificate": cert,
                        "cipher": cipher,
                        "version": version,
                        "negotiated_group": negotiated_group,
                        "server_sigalg": server_sigalg,
                        "host": host,
                        "port": port,
                        "dns_retries": retries,
                        "error": "",
                    }
        except socket.gaierror as e:
            if e.errno in DNS_TRANSIENT_ERRNOS and retries < max_retries:
                retries += 1
                time.sleep(base_delay * (2 ** (retries - 1)))
                last_error = e
                continue
            last_error = e
            break
        except Exception as e:
            last_error = e
            break

    return {
        "certificate": {},
        "cipher": None,
        "version": "None",
        "negotiated_group": "None",
        "server_sigalg": None,
        "host": host,
        "port": port,
        "dns_retries": retries,
        "error": str(last_error)[:200] if last_error else "Unknown error",
    }