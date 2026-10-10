"""Real loopback TLS handshakes through the production model transport.

Only DNS and the final TCP destination are replaced. HTTP framing, SNI, trust
verification and hostname checks remain the real httpx/httpcore/ssl stack.
Certificates and private keys are generated in a temporary directory. No
provider request, real credential, pre-existing private file or public socket
is used. OpenSSL must be installed; missing tooling is a failure, not a skip.
"""
import asyncio
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import httpx

from agent.outbound import AnyIOBackend, model_transport


class ModelTLSHandshakeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which("openssl"):
            raise RuntimeError("The TLS regression suite requires installed OpenSSL")
        cls.directory = tempfile.TemporaryDirectory(prefix="fuse-test-tls-")
        cls.addClassCleanup(cls.directory.cleanup)
        cls.root = Path(cls.directory.name)

        def openssl(*args):
            result = subprocess.run(["openssl", *args], cwd=cls.root,
                                    capture_output=True, timeout=30)
            if result.returncode:
                raise RuntimeError("Synthetic TLS fixture generation failed")

        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                "-keyout", "ca.key", "-out", "ca.pem", "-subj", "/CN=FUSE synthetic test CA",
                "-addext", "basicConstraints=critical,CA:TRUE")
        for name, host, days in (("correct", "api.openai.com", "2"),
                                 ("wrong-host", "wrong-host.invalid", "2"),
                                 ("expired", "api.openai.com", "-1")):
            openssl("req", "-new", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", f"{name}.key", "-out", f"{name}.csr",
                    "-subj", f"/CN={host}")
            (cls.root / f"{name}.ext").write_text(
                f"subjectAltName=DNS:{host}\nbasicConstraints=critical,CA:FALSE\n"
                "extendedKeyUsage=serverAuth\n", encoding="utf-8")
            if name == "expired":
                # ca's explicit dates also work on Ubuntu 24.04/OpenSSL 3.0.
                # They avoid clock-dependent sleeps or an unsupported -days -1.
                (cls.root / "index.txt").write_text("", encoding="utf-8")
                (cls.root / "serial.txt").write_text("1000\n", encoding="utf-8")
                (cls.root / "ca.cnf").write_text(
                    "[ca]\ndefault_ca=fixture\n[fixture]\n"
                    "database=index.txt\nserial=serial.txt\nnew_certs_dir=.\n"
                    "certificate=ca.pem\nprivate_key=ca.key\ndefault_md=sha256\n"
                    "policy=fixture_policy\n[fixture_policy]\ncommonName=supplied\n",
                    encoding="utf-8")
                openssl("ca", "-config", "ca.cnf", "-batch", "-notext",
                        "-in", f"{name}.csr", "-out", f"{name}.pem",
                        "-startdate", "20200101000000Z", "-enddate", "20200102000000Z",
                        "-extfile", f"{name}.ext")
            else:
                openssl("x509", "-req", "-in", f"{name}.csr", "-CA", "ca.pem",
                        "-CAkey", "ca.key", "-CAcreateserial", "-days", days,
                        "-extfile", f"{name}.ext", "-out", f"{name}.pem")
        for key in cls.root.glob("*.key"):
            key.chmod(0o600)

    def handshake(self, certificate, *, trust_fixture, expected_error=None):
        async def run():
            requests, server_names, destinations = [], [], []
            server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_context.load_cert_chain(self.root / f"{certificate}.pem",
                                           self.root / f"{certificate}.key")
            server_context.set_servername_callback(
                lambda _socket, name, _context: server_names.append(name))

            async def respond(reader, writer):
                try:
                    requests.append(await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2))
                    writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                    await writer.drain()
                finally:
                    writer.close()
                    await writer.wait_closed()

            server = await asyncio.start_server(respond, "127.0.0.1", 0, ssl=server_context)
            port = server.sockets[0].getsockname()[1]
            original_connect = AnyIOBackend.connect_tcp

            async def local_socket(backend, host, requested_port, timeout=None,
                                   local_address=None, socket_options=None):
                # Production DNS pinning must have passed this validated public
                # literal to the socket seam. The only actual socket is loopback.
                self.assertEqual((host, requested_port), ("93.184.216.34", 443))
                destinations.append(("127.0.0.1", port))
                return await original_connect(backend, "127.0.0.1", port,
                                              timeout, local_address, socket_options)

            async def synthetic_dns(host, requested_port, *args, **kwargs):
                self.assertEqual((host, requested_port), ("api.openai.com", 443))
                return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP,
                         "", ("93.184.216.34", 443))]

            transport = model_transport()
            context = transport._pool._ssl_context
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            self.assertTrue(context.check_hostname)
            if trust_fixture:
                context.load_verify_locations(cafile=self.root / "ca.pem")
            try:
                with patch.object(asyncio.get_running_loop(), "getaddrinfo", synthetic_dns), \
                        patch.object(AnyIOBackend, "connect_tcp", local_socket):
                    async with httpx.AsyncClient(transport=transport, trust_env=False, timeout=2) as client:
                        if expected_error is None:
                            response = await client.get("https://api.openai.com/v1/synthetic-tls-only")
                            self.assertEqual((response.status_code, response.text), (200, "OK"))
                        else:
                            with self.assertRaises(httpx.ConnectError) as error:
                                await client.get("https://api.openai.com/v1/synthetic-tls-only")
                            self.assertIn("CERTIFICATE_VERIFY_FAILED", str(error.exception))
                            self.assertIn(expected_error, str(error.exception).lower())
            finally:
                server.close()
                await server.wait_closed()
            self.assertEqual(server_names, ["api.openai.com"])
            self.assertEqual(destinations, [("127.0.0.1", port)])
            self.assertEqual(len(requests), int(expected_error is None))
            if requests:
                self.assertIn(b"Host: api.openai.com\r\n", requests[0])
                self.assertNotIn(b"Authorization:", requests[0])
        asyncio.run(run())

    def test_trusted_correct_host_completes_real_tls_and_http(self):
        self.handshake("correct", trust_fixture=True)

    def test_trusted_wrong_host_fails_before_http_is_sent(self):
        self.handshake("wrong-host", trust_fixture=True, expected_error="hostname mismatch")

    def test_untrusted_ca_fails_before_http_is_sent(self):
        self.handshake("correct", trust_fixture=False, expected_error="unable to get local issuer certificate")

    def test_expired_certificate_fails_before_http_is_sent(self):
        self.handshake("expired", trust_fixture=True, expected_error="certificate has expired")

    def test_environment_ca_cannot_override_production_trust(self):
        with patch.dict("os.environ", {"SSL_CERT_FILE": str(self.root / "ca.pem"),
                                       "SSL_CERT_DIR": str(self.root),
                                       "HTTPS_PROXY": "http://127.0.0.1:1"}):
            self.handshake("correct", trust_fixture=False,
                           expected_error="unable to get local issuer certificate")


if __name__ == "__main__":
    unittest.main()
