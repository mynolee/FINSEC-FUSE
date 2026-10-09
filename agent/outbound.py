"""Fixed-origin, TLS-verified model transport with connection-time address pinning."""
import asyncio
import ipaddress
import socket

import httpcore
import httpx
from httpcore._backends.anyio import AnyIOBackend

MODEL_BASE_URL = "https://api.openai.com/v1"


class PublicModelBackend(AnyIOBackend):
    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        if host != "api.openai.com" or port != 443:
            raise httpcore.ConnectError("unregistered model destination")
        # Resolve once; pass a validated IP literal to the actual socket backend.
        # httpcore still uses the original origin for SNI/certificate verification.
        async with asyncio.timeout(timeout):
            records = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
            addresses = list(dict.fromkeys(record[4][0] for record in records))
            if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
                raise httpcore.ConnectError("model destination resolved outside public egress")
            return await super().connect_tcp(addresses[0], port, timeout, local_address, socket_options)


def model_transport():
    transport = httpx.AsyncHTTPTransport(verify=True, trust_env=False, retries=0,
        limits=httpx.Limits(max_connections=4, max_keepalive_connections=4))
    # Version-pinned httpx/httpcore adapter seam. Only the network backend is
    # replaced; HTTP framing and default verified TLS remain library-owned.
    transport._pool._network_backend = PublicModelBackend()
    return transport
