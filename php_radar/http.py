"""A small HTTP client for the sources that read from a server.

get makes one GET and returns the answer, whatever its status. It never follows a redirect and
never uses a proxy. A header such as Authorization therefore reaches only the host it was written
for. A Location header cannot lead a probe out of its scope. A caller that wants to follow a
redirect reads the Location of the answer and decides.

The certificate of an https host is checked. Only verify=False turns that off. A scanner uses it to
read what a host presents, and it believes none of that. get then takes only a User-Agent and an
Accept from the caller. Any other header is refused. http.client adds Host and Accept-Encoding to
every request.
"""
import functools
import ssl
import time
from http.client import HTTPConnection, HTTPException, HTTPResponse, HTTPSConnection
from typing import NamedTuple, Optional
from urllib.parse import urlsplit

# The most of an answer that is read. The caps bound what one hostile or broken server can cost.
_MAX_BODY = 32 << 20

# The most of the status line and headers that is read, in all. http.client alone allows 100 lines
# of 64 KiB each.
_MAX_HEAD = 64 << 10

_CHUNK = 1 << 16

# The whole read of an answer, from its status line to the end of its body, may take this many
# timeouts. A timeout limits one wait on the socket, so a server that sends a byte per wait could
# otherwise hold the read for as long as it liked.
_READ_WAITS = 4

# The clock goes through this name so that a test can move it.
_now = time.monotonic

# The only headers a caller may pass where the certificate is not checked. That peer may be an
# impostor, so no credential may reach it. A list of the credential headers would miss the next one
# (X-Api-Key, X-Auth-Token, a name with a space beside it, a name given as bytes), so this lists
# the two headers that carry none.
_UNVERIFIED_HEADERS = frozenset({"user-agent", "accept"})


class TransportError(OSError):
    """There was no answer: the host did not respond, the exchange broke off, or the answer ran
    past the cap. The message says which, and never holds a request header."""


class Response(NamedTuple):
    status: int
    headers: dict[str, str]  # lower-case names, and a repeated header joined with a comma
    body: bytes
    cert: Optional[bytes] = None  # DER of the certificate an https server presented, else None


class _Budget:
    """The time allowed for reading an answer. One timeout limits a wait. This limits them all."""

    def __init__(self, seconds: float) -> None:
        self._seconds = seconds
        self._end = _now() + seconds

    def check(self) -> None:
        """Call before each wait. It raises once the time is up. A wait that began just before
        can still run for a timeout, so a read ends within one timeout of its deadline."""
        if _now() >= self._end:
            raise TransportError(f"the answer took longer than {self._seconds:g} seconds to arrive")


class _Reader:
    """The file an answer reads from, with each wait on the socket counted against the budget.

    A buffered file blocks in readline and read until a whole line or size has arrived, one wait
    after another, and nothing in between can stop it. Here each wait is taken alone, by peek
    and read1, and the budget is checked before it. Everything else goes to the file.
    """

    def __init__(self, fp, budget: _Budget) -> None:
        self._fp = fp
        self._budget = budget

    def __getattr__(self, name: str):
        return getattr(self._fp, name)

    def readline(self, size: Optional[int] = -1) -> bytes:
        limit = None if size is None or size < 0 else size
        line = bytearray()
        while limit is None or len(line) < limit:
            self._budget.check()
            ready = self._fp.peek(1)  # at most one wait, and it returns all that is buffered
            if not ready:
                break
            end = ready.find(b"\n") + 1 or len(ready)
            line += self._fp.read(end if limit is None else min(end, limit - len(line)))
            if line.endswith(b"\n"):
                break
        return bytes(line)

    def read(self, size: Optional[int] = -1) -> bytes:
        limit = None if size is None or size < 0 else size
        data = bytearray()
        while limit is None or len(data) < limit:
            self._budget.check()
            part = self._fp.read1(_CHUNK if limit is None else limit - len(data))
            if not part:
                break
            data += part
        return bytes(data)

    def read1(self, size: int = -1) -> bytes:
        self._budget.check()
        return self._fp.read1(size)


class _Head:
    """The file an answer reads its status line and headers from, cut off after _MAX_HEAD bytes.

    Everything but readline goes to the file underneath, because http.client also closes it from
    there.
    """

    def __init__(self, fp) -> None:
        self._fp = fp
        self._left = _MAX_HEAD

    def __getattr__(self, name: str):
        return getattr(self._fp, name)

    def readline(self, size: int = -1) -> bytes:
        # One byte more than is left is asked for, so that a head over the cap is seen as over.
        limit = self._left + 1 if size is None or size < 0 else min(size, self._left + 1)
        line = self._fp.readline(limit)
        self._left -= len(line)
        if self._left < 0:
            raise TransportError(f"the status line and headers are longer than {_MAX_HEAD} bytes")
        return line


class _Answer(HTTPResponse):
    """An HTTPResponse that reads within a budget of time, and holds its head to _MAX_HEAD bytes."""

    def __init__(self, sock, *args, budget: _Budget, **kwargs) -> None:
        super().__init__(sock, *args, **kwargs)
        self.fp = _Reader(self.fp, budget)

    def begin(self) -> None:
        # The cap covers the head. The body is read from the reader itself, under its own cap. When
        # http.client has already closed the answer it has set fp to None, and that stays.
        reader = self.fp
        head = self.fp = _Head(reader)
        try:
            super().begin()
        finally:
            if self.fp is head:
                self.fp = reader


def _headers(answer) -> dict[str, str]:
    joined: dict[str, str] = {}
    for name, value in answer.getheaders():
        name = name.lower()
        joined[name] = f"{joined[name]}, {value}" if name in joined else value
    return joined


def _body(answer) -> bytes:
    body = bytearray()
    while True:
        chunk = answer.read1(_CHUNK)
        if not chunk:
            break
        body += chunk
        if len(body) > _MAX_BODY:
            raise TransportError(f"the answer is larger than {_MAX_BODY} bytes")
    # A read of a set size does not raise when the server hangs up early. What is still owed of a
    # declared length is left in .length, so this check catches a cut-off answer before anything
    # parses it as a whole one.
    if answer.length:
        raise TransportError("the answer ended before its declared length")
    return bytes(body)


def _send(connection, target: str, headers: dict) -> None:
    refused = False
    try:
        # The connecting happens in here too, so a host name that cannot be encoded lands below.
        connection.request("GET", target, headers=headers)
    except ValueError as exc:
        # A TLS certificate failure is a ValueError as well as an OSError. It is raised again here
        # for get to name.
        if isinstance(exc, OSError):
            raise
        refused = True
    if refused:
        # http.client quotes a refused header value in its message, and for Authorization that
        # value is the token. This is raised once the handler above has closed, so no exception is
        # active and nothing is left in __context__.
        raise TransportError("the request cannot be sent as written")


def _unverified() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # The host name check goes first, because CERT_NONE is refused while it is on.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _certificate(connection) -> Optional[bytes]:
    # Read before getresponse, because an answer that closes the connection takes its socket away.
    return connection.sock.getpeercert(binary_form=True)


def get(url: str, headers: dict, timeout: float, verify: bool = True,
        read_body: bool = True) -> Response:
    """The answer to one GET of url. Any status comes back, and only a missing answer raises.

    Raises TransportError when the URL is not an http or https URL with a host, when the host
    cannot be reached or stops answering, or when the answer is malformed or over a cap. The
    status line and headers may run to 64 KiB together, and the body to 32 MiB. timeout is in
    seconds and limits each wait on the socket, so it must be positive, and ValueError says
    otherwise. The whole read of the answer, from its status line to the end of its body, may
    take four timeouts, so a server that sends a byte per wait is cut off, and the read ends
    within one timeout of that. The connect and the TLS handshake are bounded by timeout alone,
    and a name that is slow to resolve is not bounded.

    The certificate and host name of an https host are verified. Only the literal False for verify
    turns that off, so a config value such as the string "false" keeps it on. The answer then
    comes from a host the caller cannot vouch for, and no credential may reach it. Any header
    other than User-Agent and Accept raises ValueError before anything is sent, whatever it is
    called. For an https answer, cert holds the certificate the server presented, as DER.

    Only the literal False for read_body skips the body. The answer then comes back with an empty
    body, whatever it was, and the rest of it is left unread when the connection closes.
    """
    if timeout is None or not timeout > 0:
        raise ValueError("timeout must be a positive number of seconds")
    if verify is False and not all(
            isinstance(name, str) and name.lower() in _UNVERIFIED_HEADERS for name in headers):
        raise ValueError("only User-Agent and Accept are sent where the certificate is not checked")
    try:
        parts = urlsplit(url)
        host, port = parts.hostname, parts.port
    except ValueError:
        raise TransportError("not a valid URL") from None
    if parts.scheme not in ("http", "https") or not host:
        raise TransportError("not an http or https URL")
    secure = parts.scheme == "https"
    # A context is passed only to switch verification off. HTTPConnection takes none, and the
    # default of HTTPSConnection is the verifying one.
    options = {"context": _unverified()} if secure and verify is False else {}
    # The port is always given. http.client reads the tail of an IPv6 literal as a port otherwise.
    connection = (HTTPSConnection if secure else HTTPConnection)(
        host, port or (443 if secure else 80), timeout=timeout, **options)
    target = (parts.path or "/") + ("?" + parts.query if parts.query else "")
    answer = None
    try:
        _send(connection, target, headers)
        cert = _certificate(connection) if secure else None
        # The read starts here. The connect and the handshake are bounded by timeout alone, and a
        # name that is slow to resolve is not bounded at all.
        budget = _Budget(_READ_WAITS * timeout)
        connection.response_class = functools.partial(_Answer, budget=budget)
        answer = connection.getresponse()
        body = b"" if read_body is False else _body(answer)
        return Response(answer.status, _headers(answer), body, cert)
    except TransportError:
        raise
    except (OSError, HTTPException) as exc:
        raise TransportError(f"{type(exc).__name__}: {exc}") from exc
    finally:
        connection.close()
        # An answer that closes the connection leaves its socket with the answer, and a body that
        # was not read leaves the answer open.
        if answer is not None:
            answer.close()
