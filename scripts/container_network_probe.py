#!/usr/bin/env python3
"""Credential-free TCP probe, executed in an existing service network namespace.

Targets must be literal, fixture-owned private addresses. No HTTP requests or
credentials are sent. This file is passed as Python source to ephemeral probes;
it is not mounted into or installed in the application containers.
"""
import errno
import ipaddress
import json
from pathlib import Path
import socket
import sys

MARKER = b"FUSE_SYNTHETIC_NETWORK_FIXTURE\n"
DENIED_ERRNOS = {errno.ECONNREFUSED, errno.EHOSTUNREACH, errno.ENETUNREACH,
                 errno.EACCES, errno.EPERM, errno.ETIMEDOUT}


def ipv4_default_routes(text):
    return sum(1 for row in text.splitlines()[1:] if len(fields := row.split()) >= 8
               and fields[1] == "00000000" and fields[7] == "00000000"
               and int(fields[3], 16) & 1 and not int(fields[3], 16) & 0x200)


def ipv6_default_routes(text):
    return sum(1 for row in text.splitlines() if len(fields := row.split()) >= 10
               and fields[0] == "0" * 32 and fields[1] == "00"
               and int(fields[8], 16) & 1 and not int(fields[8], 16) & 0x200)


def check_target(target):
    address = ipaddress.ip_address(target["address"])
    if (address.version != 4 or not address.is_private or address.is_loopback
            or address.is_link_local or address.is_unspecified or address.is_multicast):
        raise ValueError("Only inspected isolated Docker fixture IPv4 addresses are allowed")
    if type(target["port"]) is not int or not 1 <= target["port"] <= 65535:
        raise ValueError("Invalid fixture port")
    if target["expected"] not in {"ALLOW", "DENY"}:
        raise ValueError("Invalid probe expectation")
    marker_seen = False
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.settimeout(2)
            connection.connect((str(address), target["port"]))
            connected = True
            if target.get("marker"):
                data = bytearray()
                while len(data) < len(MARKER):
                    chunk = connection.recv(len(MARKER) - len(data))
                    if not chunk:
                        break
                    data.extend(chunk)
                marker_seen = bytes(data) == MARKER
    except (TimeoutError, OSError) as error:
        if not isinstance(error, TimeoutError) and error.errno not in DENIED_ERRNOS:
            raise
        connected = False
    passed = connected if target["expected"] == "ALLOW" else not connected
    if target.get("marker"):
        passed = passed and marker_seen
    return {"check": target["check"], "expected": target["expected"],
            "observed": "CONNECTED" if connected else "DENIED",
            "status": "PASS" if passed else "FAIL"}


def probe(targets):
    return {"checks": [check_target(target) for target in targets],
            "ipv4DefaultRoutes": ipv4_default_routes(Path("/proc/net/route").read_text()),
            "ipv6DefaultRoutes": ipv6_default_routes(Path("/proc/net/ipv6_route").read_text())}


if __name__ == "__main__":
    print(json.dumps(probe(json.loads(sys.argv[1])), separators=(",", ":")))
