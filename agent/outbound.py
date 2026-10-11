"""Fixed-origin, TLS-verified model transport with connection-time address pinning."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import socket
import threading

import httpcore
import httpx
from httpcore._backends.anyio import AnyIOBackend

from .security_policy import POLICY

MODEL_BASE_URL = "https://api.openai.com/v1"


class BoundedResolver:
    """Bound submitted, unfinished native DNS work across threads and event loops.

    The executor is lazy and process-owned. Request cancellation cannot interrupt
    native DNS or return its capacity early. Process shutdown may consequently
    wait for an outstanding native resolver call to finish.
    """

    def __init__(self, max_workers=POLICY["modelConcurrency"]):
        if isinstance(max_workers, bool) or not isinstance(max_workers, int) or not 1 <= max_workers <= POLICY["modelConcurrency"]:
            raise ValueError("invalid resolver capacity")
        self._capacity = max_workers
        self._lock = threading.Lock()
        self._unfinished = 0
        self._executor = None
        self._closed = False

    def _completed(self, _future):
        with self._lock:
            self._unfinished -= 1

    @staticmethod
    def _consume_result(future):
        # A timed-out caller no longer observes its bridge, but DNS may fail later.
        if not future.cancelled():
            future.exception()

    async def resolve(self, host, port):
        submission_error = None
        with self._lock:
            if self._closed or self._unfinished >= self._capacity:
                raise httpcore.ConnectError("model DNS capacity unavailable")
            self._unfinished += 1
            try:
                if self._executor is None:
                    self._executor = ThreadPoolExecutor(
                        max_workers=self._capacity, thread_name_prefix="model-dns")
            except Exception as exc:
                self._unfinished -= 1
                self._closed = True
                raise httpcore.ConnectError("model DNS executor unavailable") from exc
            try:
                native = self._executor.submit(socket.getaddrinfo, host, port,
                                               type=socket.SOCK_STREAM)
            except Exception as exc:
                # submit can enqueue work before thread creation fails. Without
                # a returned future its lifetime is unknown: retain the slot,
                # stop admission permanently, and never replace this executor.
                self._closed = True
                submission_error = exc
        if submission_error is not None:
            # Pending-future cancellation may invoke other completion callbacks.
            # Never shut the executor down while holding their accounting lock.
            try:
                self._executor.shutdown(wait=False, cancel_futures=True)
            finally:
                raise httpcore.ConnectError("model DNS submission failed") from submission_error
        # Register outside the lock: already-completed futures call this inline.
        native.add_done_callback(self._completed)
        bridge = asyncio.wrap_future(native)
        bridge.add_done_callback(self._consume_result)
        try:
            # Do not cancel queued executor jobs on waiter timeout: their work
            # items would otherwise accumulate while newly freed slots refill.
            return await asyncio.shield(bridge)
        except Exception as exc:
            raise httpcore.ConnectError("model DNS resolution failed") from exc

    def close(self, *, wait=False):
        """Terminal shutdown for an explicitly owned resolver; never recycle it."""
        with self._lock:
            self._closed = True
            executor = self._executor
        if executor is not None:
            executor.shutdown(wait=wait, cancel_futures=True)


# Shared across per-request transports. Stdlib owns final process shutdown;
# closing one HTTP client or application must not close other callers' DNS.
_MODEL_RESOLVER = BoundedResolver()


class PublicModelBackend(AnyIOBackend):
    def __init__(self, resolver=None):
        super().__init__()
        self._resolver = _MODEL_RESOLVER if resolver is None else resolver

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        if host != "api.openai.com" or port != 443:
            raise httpcore.ConnectError("unregistered model destination")
        # Resolve once; pass a validated IP literal to the actual socket backend.
        # httpcore still uses the original origin for SNI/certificate verification.
        async with asyncio.timeout(timeout):
            records = await self._resolver.resolve(host, port)
            addresses = list(dict.fromkeys(record[4][0] for record in records))
            if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
                raise httpcore.ConnectError("model destination resolved outside public egress")
            return await super().connect_tcp(addresses[0], port, timeout, local_address, socket_options)


def model_transport(resolver=None):
    transport = httpx.AsyncHTTPTransport(verify=True, trust_env=False, retries=0,
        limits=httpx.Limits(max_connections=4, max_keepalive_connections=4))
    # Version-pinned httpx/httpcore adapter seam. Only the network backend is
    # replaced; HTTP framing and default verified TLS remain library-owned.
    transport._pool._network_backend = PublicModelBackend(resolver=resolver)
    return transport
