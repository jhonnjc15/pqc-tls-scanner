import socket
import subprocess



def s_client(host, port, groups="X25519MLKEM768"):
    return subprocess.run(
        ["openssl", "s_client", "-connect", f"{host}:{port}", "-groups", groups],
        capture_output=True,
        text=True,
        timeout=60,
    )


def version():
    return subprocess.run(
        ["openssl", "version"], capture_output=True, text=True
    ).stdout.strip()


def peer_ip(host):
    return socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)[0][4][0]