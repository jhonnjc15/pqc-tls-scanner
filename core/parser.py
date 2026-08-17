import re


def parse(output):
    data = {
        "connected": "CONNECTED" in output,
        "protocol": None,
        "cipher": None,
        "negotiated_group": None,
        "signature": None,
        "org": None,
        "country": None,
    }
    for line in output.splitlines():
        if line.startswith("Protocol"):
            data["protocol"] = line.split(":", 1)[1].strip()
        elif "Cipher is" in line:
            data["cipher"] = line.split("Cipher is", 1)[1].strip()
        elif line.startswith("Negotiated TLS1.3 group"):
            data["negotiated_group"] = line.split(":", 1)[1].strip()
        elif line.startswith("Peer signature type"):
            data["signature"] = line.split(":", 1)[1].strip()
        elif line.startswith("subject="):
            subject = line.split("=", 1)[1]
            data["org"] = _field(subject, "O=")
            data["country"] = _field(subject, "C=") or _field(
                subject, "jurisdictionC="
            )
    return data


def _field(text, key):
    m = re.search(r"(?:^|,)\s*" + re.escape(key) + r"([^,]+)", text)
    return m.group(1).strip() if m else None