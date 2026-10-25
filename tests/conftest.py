import shutil
import socket
import socketserver
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import NamedTuple

import pytest


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        headers = {name.lower(): value for name, value in self.headers.items()}
        self.server.seen.append((self.path, headers))
        status, extra, body = self.server.reply(self.path, headers)
        self.send_response(status)
        for name, value in extra:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class _Loopback(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, reply, tls=None):
        super().__init__(("127.0.0.1", 0), _Handler)
        if tls is not None:
            self.socket = tls.wrap_socket(self.socket, server_side=True)
        self.reply = reply
        self.seen = []  # (path, headers with lower-case names) for every request, in order
        self.url = f"{'http' if tls is None else 'https'}://127.0.0.1:{self.server_address[1]}"
        self._thread = threading.Thread(
            target=self.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        self._thread.start()

    def server_bind(self):
        # The stock bind asks DNS for the host's full name. That can stall on a machine with a
        # slow resolver, and nothing here reads the name.
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = "127.0.0.1", self.server_address[1]

    def close(self):
        self.shutdown()
        self.server_close()
        self._thread.join()


@pytest.fixture
def loopback():
    """A factory for HTTP servers on 127.0.0.1, stopped when the test ends.

    start(reply) takes reply(path, headers) -> (status, [(name, value)], body) and returns the
    server, with url, seen, and close(). Nothing leaves the machine. start(reply, tls=context)
    serves https with a server-side ssl context, such as the one self_signed provides.
    """
    started = []

    def start(reply, tls=None):
        server = _Loopback(reply, tls)
        started.append(server)
        return server

    yield start
    for server in started:
        server.close()


@pytest.fixture
def drip():
    """A factory for servers on 127.0.0.1 that answer one byte at a time.

    start(prefix, pace, count) accepts one connection, reads its request, sends prefix, and then
    sends count bytes of "a", one every pace seconds. It returns the port. The servers stop when
    the test ends. A wait on the socket never runs out against them, because a byte always
    arrives before it does.
    """
    started = []

    def start(prefix, pace, count):
        stop = threading.Event()
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)

        def serve():
            try:
                conn, _ = listener.accept()
                with conn:
                    conn.recv(4096)
                    conn.sendall(prefix)
                    for _ in range(count):
                        if stop.wait(pace):
                            return
                        conn.sendall(b"a")
            except OSError:
                pass  # the client gave up

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        started.append((stop, thread, listener))
        return listener.getsockname()[1]

    yield start
    for stop, thread, listener in started:
        stop.set()
        thread.join(5)
        listener.close()


class SelfSigned(NamedTuple):
    context: ssl.SSLContext  # server side, presents the certificate
    der: bytes  # the certificate, as a client receives it
    cn: str  # its subject common name
    names: tuple  # its subject alternative names: DNS names, then addresses


@pytest.fixture(scope="session")
def self_signed(tmp_path_factory):
    """A self-signed certificate that no client trusts, minted once per run with openssl.

    The key exists only in the temp directory of the run. The test is skipped when the openssl
    command line is missing or cannot mint the certificate.
    """
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("the openssl command line is not installed")
    where = tmp_path_factory.mktemp("tls")
    key, cert = where / "key.pem", where / "cert.pem"
    cn, names = "radar-test.local", ("radar-test.local", "alt.radar-test.local", "10.1.2.3")
    try:
        subprocess.run(
            [openssl, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
             "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "2", "-subj", "/CN=" + cn,
             "-addext", "subjectAltName=DNS:radar-test.local,DNS:alt.radar-test.local,IP:10.1.2.3"],
            check=True, capture_output=True, timeout=60)
    except subprocess.CalledProcessError as exc:
        pytest.skip("openssl cannot mint a test certificate: "
                    + exc.stderr.decode(errors="replace")[-200:])
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(key))
    return SelfSigned(context, ssl.PEM_cert_to_DER_cert(cert.read_text()), cn, names)
