import ast
import collections.abc
import contextlib
import io
import pathlib
import socket
import ssl
import threading
import time
import traceback

import pytest

from php_radar import http as php_http
from php_radar.http import Response, TransportError, get


def serve(loopback, status=200, headers=(), body=b"ok"):
    return loopback(lambda path, seen: (status, list(headers), body))


@contextlib.contextmanager
def raw(reply):
    """A one-shot server on 127.0.0.1 that answers its first request with exactly these bytes."""
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)

        def answer():
            try:
                conn, _ = listener.accept()
                with conn:
                    conn.recv(4096)
                    conn.sendall(reply)
            except OSError:
                pass  # the test ended without a client

        worker = threading.Thread(target=answer, daemon=True)
        worker.start()
        yield f"http://127.0.0.1:{listener.getsockname()[1]}/"
        worker.join(5)


# --- what comes back ---

def test_a_200_comes_back_with_its_status_headers_and_body(loopback):
    server = serve(loopback, headers=[("X-Powered-By", "PHP/8.3.35")], body=b"hello")
    answer = get(server.url + "/", {}, 5)
    assert isinstance(answer, Response)
    assert answer.status == 200
    assert answer.headers["x-powered-by"] == "PHP/8.3.35"
    assert answer.body == b"hello"


@pytest.mark.parametrize("status", [200, 301, 302, 307, 403, 404, 429, 500, 503])
def test_every_status_comes_back_and_none_raises(loopback, status):
    server = serve(loopback, status=status, body=b"{}")
    answer = get(server.url + "/x", {}, 5)
    assert answer.status == status
    assert answer.body == b"{}"


def test_header_names_are_lower_case_and_a_repeated_header_is_joined(loopback):
    server = serve(loopback, headers=[("Set-Cookie", "a=1"), ("SET-COOKIE", "b=2"),
                                      ("X-Mixed-Case", "v")])
    headers = get(server.url + "/", {}, 5).headers
    assert headers["set-cookie"] == "a=1, b=2"
    assert headers["x-mixed-case"] == "v"
    assert all(name == name.lower() for name in headers)


def test_the_request_carries_the_path_the_query_and_the_headers_it_was_given(loopback):
    server = serve(loopback)
    get(server.url + "/a/b%20c?per_page=100&page=2#frag", {"Accept": "text/x", "User-Agent": "u/1"},
        5)
    (path, seen), = server.seen
    assert path == "/a/b%20c?per_page=100&page=2"  # a fragment is for the client
    assert seen["accept"] == "text/x"
    assert seen["user-agent"] == "u/1"
    assert seen["host"] == server.url.split("//")[1]


def test_a_bare_host_is_requested_at_the_root(loopback):
    server = serve(loopback)
    get(server.url, {}, 5)
    assert server.seen[0][0] == "/"


def test_a_body_larger_than_one_read_comes_back_whole(loopback):
    body = bytes(range(256)) * 1024  # 256 KiB, past the size of one read
    assert get(serve(loopback, body=body).url + "/", {}, 5).body == body


def test_a_body_over_the_cap_raises_and_one_at_the_cap_comes_back(loopback, monkeypatch):
    monkeypatch.setattr(php_http, "_MAX_BODY", 1000)
    exact = serve(loopback, body=b"a" * 1000)
    assert get(exact.url + "/", {}, 5).body == b"a" * 1000
    over = serve(loopback, body=b"a" * 1001)
    with pytest.raises(TransportError):
        get(over.url + "/", {}, 5)


# --- redirects and credentials ---

def test_a_redirect_is_not_followed_and_nothing_is_sent_to_its_target(loopback):
    elsewhere = serve(loopback, body=b"landed")
    server = serve(loopback, status=302, headers=[("Location", elsewhere.url + "/landing")])
    answer = get(server.url + "/start", {"Authorization": "Bearer sekret"}, 5)
    assert answer.status == 302
    assert answer.headers["location"] == elsewhere.url + "/landing"
    assert answer.body == b"ok"
    assert elsewhere.seen == []
    assert [path for path, _ in server.seen] == ["/start"]


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_no_redirect_status_is_followed(loopback, status):
    elsewhere = serve(loopback)
    server = serve(loopback, status=status, headers=[("Location", elsewhere.url + "/")])
    assert get(server.url + "/", {"Authorization": "Bearer sekret"}, 5).status == status
    assert elsewhere.seen == []


def test_the_authorization_header_goes_to_the_host_it_was_written_for(loopback):
    server = serve(loopback)
    get(server.url + "/", {"Authorization": "Bearer sekret"}, 5)
    assert server.seen[0][1]["authorization"] == "Bearer sekret"


# --- when there is no answer ---

def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def test_a_refused_connection_raises_transport_error():
    with pytest.raises(TransportError) as caught:
        get(f"http://127.0.0.1:{free_port()}/", {}, 2)
    assert str(caught.value)


def test_a_server_that_never_answers_times_out():
    with socket.socket() as silent:
        silent.bind(("127.0.0.1", 0))
        silent.listen(1)  # the handshake completes in the backlog, and nothing ever replies
        started = time.monotonic()
        with pytest.raises(TransportError):
            get(f"http://127.0.0.1:{silent.getsockname()[1]}/", {}, 0.3)
    assert time.monotonic() - started < 5


def test_an_answer_that_is_not_http_raises():
    with raw(b"this is not http\r\n\r\n") as url:
        with pytest.raises(TransportError):
            get(url, {}, 5)


def test_an_answer_that_stops_short_of_its_length_raises():
    with raw(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n" + b"x" * 10) as url:
        with pytest.raises(TransportError):
            get(url, {}, 5)


def test_a_transport_error_is_an_os_error_so_one_except_covers_every_failure():
    assert issubclass(TransportError, OSError)


# --- what is requested ---

# Every host here is 127.0.0.1:9. A check that regressed would then reach only the local machine.
@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "file:///C:/Windows/win.ini",
    "ftp://127.0.0.1:9/file",
    "gopher://127.0.0.1:9/",
    "data:text/plain,hello",
    "javascript:alert(1)",
    "//127.0.0.1:9/x",
    "127.0.0.1:9/x",
    "/just/a/path",
    "",
    "http:///no-host",
    "https://",
])
def test_only_an_http_or_https_url_with_a_host_is_requested(url):
    # The message is checked as well, because a refused connection to 127.0.0.1:9 is also a
    # TransportError and would pass for a URL that the check let through.
    with pytest.raises(TransportError) as caught:
        get(url, {}, 1)
    assert str(caught.value) == "not an http or https URL"


@pytest.mark.parametrize("url", [
    "http://[::1/unclosed",
    "http://127.0.0.1:notaport/",
    "http://127.0.0.1:99999/",
])
def test_a_url_that_does_not_parse_is_a_transport_error(url):
    with pytest.raises(TransportError) as caught:
        get(url, {}, 1)
    assert str(caught.value) == "not a valid URL"


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:9/a b",
    "http://127.0.0.1:9/a\r\nHost: evil",
    "http://127.0.0.1:9/a\x00b",
])
def test_a_url_with_a_space_or_a_control_character_is_refused(url):
    with pytest.raises(TransportError):
        get(url, {}, 1)


@pytest.mark.parametrize("timeout", [None, 0, -1, float("nan")])
def test_a_request_without_a_positive_timeout_is_refused(timeout):
    with pytest.raises(ValueError):
        get("http://127.0.0.1:9/", {}, timeout)


class Spy:
    """Stands in for a connection class, records how it was built, and ends the request."""
    made = []

    def __init__(self, host, port, timeout):
        # No context parameter on purpose. The default context verifies the certificate and the
        # host name, so a call that passed one of its own would raise TypeError here.
        Spy.made.append((type(self).__name__, host, port, timeout))

    def request(self, method, target, headers):
        Spy.made.append((method, target))
        raise OSError("stop here")

    def close(self):
        pass


class PlainSpy(Spy):
    pass


class SecureSpy(Spy):
    pass


@pytest.mark.parametrize("url, kind, host, port, target", [
    ("http://example.com/a", "PlainSpy", "example.com", 80, "/a"),
    ("https://example.com/a?x=1", "SecureSpy", "example.com", 443, "/a?x=1"),
    ("https://example.com:8443", "SecureSpy", "example.com", 8443, "/"),
    ("HTTPS://Example.COM/", "SecureSpy", "example.com", 443, "/"),
    # http.client reads an IPv6 literal with no port as a host and a port, and gets both wrong.
    ("http://[::1]/x", "PlainSpy", "::1", 80, "/x"),
    ("https://[2001:db8::7]:8080/x", "SecureSpy", "2001:db8::7", 8080, "/x"),
])
def test_the_connection_is_built_from_the_url(monkeypatch, url, kind, host, port, target):
    Spy.made.clear()
    monkeypatch.setattr(php_http, "HTTPConnection", PlainSpy)
    monkeypatch.setattr(php_http, "HTTPSConnection", SecureSpy)
    with pytest.raises(TransportError):
        get(url, {}, 7.5)
    assert Spy.made == [(kind, host, port, 7.5), ("GET", target)]


def failing(error):
    """A connection class whose request raises error."""
    class Failing:
        def __init__(self, host, port, timeout):
            pass

        def request(self, method, target, headers):
            raise error

        def close(self):
            pass

    return Failing


def test_a_certificate_failure_is_named_and_is_not_called_a_bad_request(monkeypatch):
    # SSLCertVerificationError is a ValueError as well as an OSError, and the handler for a header
    # that cannot be sent used to take it. The message has to carry the real cause: a TLS-inspecting
    # proxy, a stale CA store, a wrong clock, or a self-signed host.
    error = ssl.SSLCertVerificationError(1, "certificate verify failed")
    monkeypatch.setattr(php_http, "HTTPSConnection", failing(error))
    with pytest.raises(TransportError) as caught:
        get("https://127.0.0.1:9/", {}, 1)
    assert str(caught.value) == "SSLCertVerificationError: certificate verify failed"
    assert caught.value.__cause__ is error


@pytest.mark.parametrize("error", [
    ssl.SSLError(1, "handshake failure"), ssl.SSLZeroReturnError(6, "closed"),
    ConnectionResetError("reset"), TimeoutError("timed out")])
def test_any_other_failure_of_the_connection_is_named_too(monkeypatch, error):
    monkeypatch.setattr(php_http, "HTTPSConnection", failing(error))
    with pytest.raises(TransportError) as caught:
        get("https://127.0.0.1:9/", {}, 1)
    assert str(caught.value).startswith(type(error).__name__ + ": ")
    assert "cannot be sent" not in str(caught.value)


@pytest.mark.parametrize("url", [
    "http://a..b:9/", "https://a..b/", "http://" + "a" * 64 + ".test:9/"])
def test_a_host_name_that_cannot_be_encoded_is_a_transport_error(url):
    # The connection is made inside request(), which is where the encoding fails. A guard that
    # left the connecting outside would let the UnicodeError out of get.
    with pytest.raises(TransportError) as caught:
        get(url, {}, 1)
    assert str(caught.value) == "the request cannot be sent as written"


# --- the credential stays out of every message ---

@pytest.mark.parametrize("headers", [
    {"Authorization": "Bearer SEKRET\r\nX-Evil: 1"},
    {"Authorization": "Bearer SEKRET\n"},
    {"Authorization": "Bearer SEKRET\u20ac"},
    {"Authorization": "Bearer SEKRET", "Bad:Name": "v"},
    {"Authorization\r\n": "Bearer SEKRET"},
])
def test_a_header_that_cannot_be_sent_leaves_the_token_out_of_the_error_and_its_context(headers):
    with pytest.raises(TransportError) as caught:
        get("http://127.0.0.1:9/", headers, 1)
    error = caught.value
    printed = "".join(traceback.format_exception(type(error), error, error.__traceback__))
    assert "SEKRET" not in str(error)
    assert "SEKRET" not in repr(error)
    assert "SEKRET" not in printed
    # Suppressing the context for display leaves it on the error, where code can still read it.
    assert error.__cause__ is None
    assert error.__context__ is None


def test_a_refused_header_value_is_in_nothing_the_error_links_to(monkeypatch):
    refused = ValueError("Invalid header value b'Bearer SEKRET\\r\\n'")
    monkeypatch.setattr(php_http, "HTTPConnection", failing(refused))
    with pytest.raises(TransportError) as caught:
        get("http://127.0.0.1:9/", {"Authorization": "Bearer SEKRET\r\n"}, 1)
    link, chain = caught.value, []
    while link is not None:
        chain.append(link)
        link = link.__cause__ or link.__context__
    assert chain == [caught.value]
    assert str(caught.value) == "the request cannot be sent as written"


# --- certificates ---

class ContextSpy:
    """Stands in for HTTPSConnection, records the context it was built with, and ends the
    request."""
    contexts = []

    def __init__(self, host, port, timeout, context=None):
        ContextSpy.contexts.append(context)

    def request(self, method, target, headers):
        raise OSError("stop here")

    def close(self):
        pass


def test_verify_false_builds_a_context_that_takes_any_certificate(monkeypatch):
    ContextSpy.contexts.clear()
    monkeypatch.setattr(php_http, "HTTPSConnection", ContextSpy)
    with pytest.raises(TransportError):
        get("https://example.com/", {}, 1, verify=False)
    context, = ContextSpy.contexts
    assert context.verify_mode == ssl.CERT_NONE
    assert context.check_hostname is False


@pytest.mark.parametrize("verify", [True, None, 0, "", "no", "false", 1])
def test_only_the_literal_false_turns_verification_off(monkeypatch, verify):
    # A value read from an environment variable or a config file is a string, and "false" is truthy.
    # SecureSpy takes no context argument, so a call that passed one would raise TypeError here.
    monkeypatch.setattr(php_http, "HTTPSConnection", SecureSpy)
    Spy.made.clear()
    with pytest.raises(TransportError):
        get("https://example.com/", {}, 1, verify=verify)
    assert Spy.made[0][0] == "SecureSpy"


def test_verify_false_passes_nothing_extra_to_a_plain_http_connection(monkeypatch):
    # PlainSpy takes no context argument either, and http.client would refuse one.
    monkeypatch.setattr(php_http, "HTTPConnection", PlainSpy)
    Spy.made.clear()
    with pytest.raises(TransportError):
        get("http://example.com/", {}, 1, verify=False)
    assert Spy.made[0][0] == "PlainSpy"


class Odd(collections.abc.Mapping):
    """A mapping with one key that can be any object, such as a bytearray, which no dict can hold.
    http.client takes any mapping, so the key reaches it as given."""

    def __init__(self, key, value):
        self._key, self._value = key, value

    def __iter__(self):
        yield self._key

    def __getitem__(self, key):
        return self._value

    def __len__(self):
        return 1


@pytest.mark.parametrize("name", [
    # The credential headers, in the cases a lookup by name would handle.
    "Authorization", "authorization", "AUTHORIZATION", "Proxy-Authorization", "Cookie",
    # The same names in shapes that http.client still sends: a space or a tab beside the name
    # (the server may read it as the header), and a name given as bytes.
    "Authorization ", " Authorization", "Authorization\t", "Cookie ",
    b"Authorization", b"authorization ", bytearray(b"Authorization"), b"Cookie",
    # A credential header that no list of names would hold, and the headers that are no credential
    # but are not on the list of what may go.
    "X-Api-Key", "X-Auth-Token", "Api-Key", "Private-Token", "X-CSRF-Token",
    "Accept-Language", "Host",
    # The two names that may go, in the shapes that may not: the check is on the exact name.
    "User-Agent ", " Accept", "Accept\t", b"Accept", b"User-Agent", bytearray(b"Accept"),
])
@pytest.mark.parametrize("url", ["https://example.com/", "http://example.com/"])
def test_only_user_agent_and_accept_are_sent_where_the_certificate_is_not_checked(
        monkeypatch, name, url):
    # An unverified peer may be an impostor, and it would be handed the credential.
    Spy.made.clear()
    monkeypatch.setattr(php_http, "HTTPConnection", PlainSpy)
    monkeypatch.setattr(php_http, "HTTPSConnection", SecureSpy)
    headers = {name: "Bearer SEKRET"} if isinstance(name, collections.abc.Hashable) \
        else Odd(name, "Bearer SEKRET")
    with pytest.raises(ValueError) as caught:
        get(url, headers, 1, verify=False)
    assert "SEKRET" not in str(caught.value)
    assert Spy.made == []  # nothing was built, so nothing was sent


def test_one_header_that_may_not_go_stops_the_whole_request(monkeypatch):
    monkeypatch.setattr(php_http, "HTTPSConnection", SecureSpy)
    Spy.made.clear()
    with pytest.raises(ValueError):
        get("https://example.com/", {"User-Agent": "u/1", "Authorization ": "Bearer x"}, 1,
            verify=False)
    assert Spy.made == []


@pytest.mark.parametrize("verify", [True, None, 0, "", "false"])
def test_a_credential_is_sent_where_the_certificate_is_still_checked(monkeypatch, verify):
    # Only the literal False skips the check, and only then is a credential refused.
    monkeypatch.setattr(php_http, "HTTPSConnection", SecureSpy)
    Spy.made.clear()
    with pytest.raises(TransportError):  # the spy ends the request once it is built
        get("https://example.com/", {"Authorization": "Bearer x"}, 1, verify=verify)
    assert Spy.made[0][0] == "SecureSpy"


@pytest.mark.parametrize("headers", [
    {"User-Agent": "u/1", "Accept": "*/*"},
    {"user-agent": "u/1"},
    {"ACCEPT": "*/*"},
    {},
])
def test_user_agent_and_accept_go_where_the_certificate_is_not_checked(monkeypatch, headers):
    ContextSpy.contexts.clear()
    monkeypatch.setattr(php_http, "HTTPSConnection", ContextSpy)
    with pytest.raises(TransportError):  # the spy ends the request once it is built
        get("https://example.com/", headers, 1, verify=False)
    assert len(ContextSpy.contexts) == 1


def test_an_unverified_request_carries_nothing_but_those_two_headers(loopback, self_signed):
    server = loopback(lambda path, seen: (200, [], b"ok"), tls=self_signed.context)
    get(server.url + "/", {"User-Agent": "u/1", "Accept": "*/*"}, 5, verify=False)
    (_, seen), = server.seen
    # Host and Accept-Encoding are the two that http.client adds itself.
    assert set(seen) == {"host", "user-agent", "accept", "accept-encoding"}


def test_a_self_signed_server_fails_by_default_and_answers_with_verify_false(loopback, self_signed):
    server = loopback(lambda path, seen: (200, [("X-Powered-By", "PHP/8.3.35")], b"hello"),
                      tls=self_signed.context)
    with pytest.raises(TransportError) as caught:
        get(server.url + "/", {}, 5)
    assert str(caught.value).startswith("SSLCertVerificationError: ")
    answer = get(server.url + "/", {}, 5, verify=False)
    assert answer.status == 200
    assert answer.headers["x-powered-by"] == "PHP/8.3.35"
    assert answer.body == b"hello"


def test_the_certificate_the_server_presented_comes_back_as_der(loopback, self_signed):
    # The stock handler answers HTTP/1.0 and closes the connection, and http.client drops the
    # socket from the connection when it sees that. The certificate is read before then.
    server = loopback(lambda path, seen: (200, [], b"ok"), tls=self_signed.context)
    assert get(server.url + "/", {}, 5, verify=False).cert == self_signed.der


class Sock:
    def getpeercert(self, binary_form=False):
        return b"DER" if binary_form else {}


class Answer:
    status, length = 204, 0
    closes = 0

    def getheaders(self):
        return []

    def read1(self, size):
        return b""

    def close(self):
        Answer.closes += 1


class Handshaken:
    """An https connection as http.client leaves it: the socket is there after request() and gone
    once getresponse() meets an answer that closes the connection."""

    def __init__(self, host, port, timeout, context=None):
        self.sock = None

    def request(self, method, target, headers):
        self.sock = Sock()

    def getresponse(self):
        self.sock = None
        return Answer()

    def close(self):
        pass


def test_the_certificate_is_read_before_the_answer_can_close_the_connection(monkeypatch):
    monkeypatch.setattr(php_http, "HTTPSConnection", Handshaken)
    answer = get("https://example.com/", {}, 1, verify=False)
    assert (answer.status, answer.cert) == (204, b"DER")


@pytest.mark.parametrize("read_body", [True, False])
def test_the_answer_is_closed_whether_or_not_its_body_was_read(monkeypatch, read_body):
    # An answer that closes the connection keeps the socket until the answer itself is closed.
    monkeypatch.setattr(php_http, "HTTPSConnection", Handshaken)
    Answer.closes = 0
    get("https://example.com/", {}, 1, verify=False, read_body=read_body)
    assert Answer.closes == 1


def test_a_plain_http_answer_carries_no_certificate(loopback):
    server = serve(loopback)
    assert server.url.startswith("http://")
    assert get(server.url + "/", {}, 5).cert is None


def test_a_response_built_without_a_certificate_still_works():
    # Callers that build a Response by hand pass three values.
    answer = Response(200, {}, b"")
    assert answer.cert is None
    assert tuple(answer)[:3] == (200, {}, b"")


# --- the time an answer may take ---

def test_a_head_that_drips_in_is_cut_off_at_the_deadline(drip):
    # A byte every 50 ms never runs out a wait of 250 ms, so only the total can end this. The total
    # is four waits, one second. Left alone the server would go on for five.
    port = drip(b"HTTP/1.1 200 OK\r\nX-A: ", 0.05, 100)
    started = time.monotonic()
    with pytest.raises(TransportError) as caught:
        get(f"http://127.0.0.1:{port}/", {}, 0.25)
    assert str(caught.value) == "the answer took longer than 1 seconds to arrive"
    assert time.monotonic() - started < 3.5


def test_a_status_line_that_drips_in_is_cut_off_at_the_deadline(drip):
    port = drip(b"HTTP/1.1 2", 0.05, 100)
    started = time.monotonic()
    with pytest.raises(TransportError) as caught:
        get(f"http://127.0.0.1:{port}/", {}, 0.25)
    assert str(caught.value) == "the answer took longer than 1 seconds to arrive"
    assert time.monotonic() - started < 3.5


def test_a_body_that_drips_in_is_cut_off_at_the_deadline(drip):
    port = drip(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n", 0.05, 100)
    started = time.monotonic()
    with pytest.raises(TransportError) as caught:
        get(f"http://127.0.0.1:{port}/", {}, 0.25)
    assert str(caught.value) == "the answer took longer than 1 seconds to arrive"
    assert time.monotonic() - started < 3.5


def test_a_body_that_drips_in_costs_nothing_when_it_is_not_read(drip):
    port = drip(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n", 0.05, 100)
    started = time.monotonic()
    assert get(f"http://127.0.0.1:{port}/", {}, 0.25, read_body=False).status == 200
    assert time.monotonic() - started < 1


def test_a_chunk_size_line_that_drips_in_is_cut_off_too(drip):
    # The size line of a chunk can carry an extension as long as the server likes.
    port = drip(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;", 0.05, 100)
    started = time.monotonic()
    with pytest.raises(TransportError) as caught:
        get(f"http://127.0.0.1:{port}/", {}, 0.25)
    assert str(caught.value) == "the answer took longer than 1 seconds to arrive"
    assert time.monotonic() - started < 3.5


def test_a_slow_answer_that_finishes_inside_the_deadline_comes_back(drip):
    # Eight bytes at 50 ms is 0.4 s of dripping against a deadline of two seconds.
    port = drip(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\n", 0.05, 8)
    assert get(f"http://127.0.0.1:{port}/", {}, 0.5).body == b"a" * 8


def test_the_deadline_is_four_waits_of_the_timeout(monkeypatch):
    seen = []

    class Recorder:
        def __init__(self, seconds):
            seen.append(seconds)

    monkeypatch.setattr(php_http, "_Budget", Recorder)
    monkeypatch.setattr(php_http, "HTTPSConnection", Handshaken)
    get("https://example.com/", {}, 7.5, verify=False)
    assert seen == [30.0]


def test_the_budget_allows_its_seconds_and_not_a_moment_more(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(php_http, "_now", lambda: clock[0])
    budget = php_http._Budget(8.0)
    for at in (100.0, 100.5, 107.9):
        clock[0] = at
        budget.check()
    for at in (108.0, 108.1, 500.0):
        clock[0] = at
        with pytest.raises(TransportError) as caught:
            budget.check()
        assert str(caught.value) == "the answer took longer than 8 seconds to arrive"


class Trickle(io.RawIOBase):
    """A raw stream that hands over one byte at a time, as a slow server does."""

    def __init__(self, data):
        self._data = data

    def readable(self):
        return True

    def readinto(self, buffer):
        if not self._data:
            return 0
        buffer[0:1] = self._data[:1]
        self._data = self._data[1:]
        return 1


class Counting:
    """A stand-in for the budget that counts the waits it is checked before."""

    def __init__(self, ends_after=None):
        self.waits, self._ends_after = 0, ends_after

    def check(self):
        self.waits += 1
        if self._ends_after is not None and self.waits > self._ends_after:
            raise TransportError("over")


def reader(data, budget=None):
    return php_http._Reader(io.BufferedReader(Trickle(data)), budget or Counting())


def test_readline_returns_the_lines_a_buffered_reader_returns():
    lines = reader(b"abc\ndef\n\nghi")
    assert [lines.readline(100) for _ in range(5)] == [b"abc\n", b"def\n", b"\n", b"ghi", b""]


def test_readline_stops_at_the_size_it_is_given():
    lines = reader(b"abcdef\nxyz\n")
    assert [lines.readline(4), lines.readline(4), lines.readline(4), lines.readline(4)] == [
        b"abcd", b"ef\n", b"xyz\n", b""]


def test_readline_stops_at_its_size_when_the_buffer_holds_more():
    # Here the whole input is buffered at once, so the limit is what ends each line.
    lines = php_http._Reader(io.BufferedReader(io.BytesIO(b"abcdef\nxyz\n")), Counting())
    assert [lines.readline(4), lines.readline(4), lines.readline(100), lines.readline(100)] == [
        b"abcd", b"ef\n", b"xyz\n", b""]


@pytest.mark.parametrize("size", [-1, None])
def test_readline_without_a_size_reads_to_the_end_of_the_line(size):
    lines = reader(b"abc\ndef\n")
    assert lines.readline(size) == b"abc\n"
    assert lines.readline(size) == b"def\n"


def test_read_returns_what_a_buffered_reader_returns():
    data = reader(b"abc\ndefghi")
    assert data.read(5) == b"abc\nd"
    assert data.read(2) == b"ef"
    assert data.read() == b"ghi"
    assert data.read(3) == b""


def test_read1_makes_one_read_of_whatever_has_come():
    assert reader(b"abc").read1(10) == b"a"


def test_every_wait_is_counted_against_the_budget():
    budget = Counting()
    lines = reader(b"abc\n", budget)
    lines.readline(100)
    assert budget.waits >= 4  # a byte at a time is four waits, and a fifth could find the end
    before = budget.waits
    reader(b"xy", budget).read(2)
    assert budget.waits - before >= 2
    before = budget.waits
    reader(b"x", budget).read1(1)
    assert budget.waits - before == 1


@pytest.mark.parametrize("call", [
    lambda r: r.readline(100), lambda r: r.read(5), lambda r: r.read()])
def test_a_budget_that_runs_out_ends_the_read_wherever_it_is(call):
    with pytest.raises(TransportError):
        call(reader(b"abcdefgh\n", Counting(ends_after=2)))


def test_a_budget_that_has_run_out_ends_read1_before_it_waits():
    with pytest.raises(TransportError):
        reader(b"abc", Counting(ends_after=0)).read1(5)


def test_the_reader_leaves_everything_else_to_the_file():
    inner = io.BufferedReader(Trickle(b"abc"))
    wrapped = php_http._Reader(inner, Counting())
    assert wrapped.closed is False
    wrapped.close()
    assert inner.closed is True


# --- the cap on the status line and headers ---

def head(*lines):
    return b"HTTP/1.1 200 OK\r\n" + b"".join(lines) + b"\r\n"


def header_of(size):
    """One header line that is size bytes long, line break included."""
    return b"X-A: " + b"a" * (size - 7) + b"\r\n"


def test_a_head_of_exactly_64_kib_comes_back_and_one_byte_more_does_not():
    room = 65536 - len(head())
    at_cap, over = head(header_of(room)), head(header_of(room + 1))
    assert (len(at_cap), len(over)) == (65536, 65537)
    with raw(at_cap) as url:
        assert get(url, {}, 5).status == 200
    with raw(over) as url:
        with pytest.raises(TransportError) as caught:
            get(url, {}, 5)
    assert str(caught.value) == "the status line and headers are longer than 65536 bytes"


def test_many_short_lines_are_held_to_the_same_cap():
    # http.client alone allows 100 lines of 64 KiB, and no single line here is near its limit.
    with raw(head(*[header_of(1024)] * 70)) as url:
        with pytest.raises(TransportError) as caught:
            get(url, {}, 5)
    assert "longer than 65536 bytes" in str(caught.value)


def test_the_cap_does_not_reach_the_body(loopback):
    body = b"b" * 200_000
    answer = get(serve(loopback, headers=[("X-A", "1")], body=body).url + "/", {}, 5)
    assert answer.body == body


def test_the_size_lines_of_a_chunked_body_are_not_counted_in_the_head():
    # http.client reads the size of each chunk with readline, as it reads the head. A chunk
    # extension makes each of those lines 52 bytes, so 1,400 chunks put 72,800 bytes of them in
    # the body, more than the head may hold.
    chunk = b"1;" + b"e" * 48 + b"\r\nx\r\n"
    reply = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + chunk * 1_400 + b"0\r\n\r\n"
    with raw(reply) as url:
        assert get(url, {}, 5).body == b"x" * 1_400


def test_the_head_of_a_100_continue_counts_toward_the_cap():
    skipped = b"HTTP/1.1 100 Continue\r\n" + header_of(40_000) + b"\r\n"
    with raw(skipped + head(header_of(40_000))) as url:
        with pytest.raises(TransportError):
            get(url, {}, 5)


# --- reading no body ---

def test_read_body_false_returns_the_status_and_headers_and_no_body(loopback):
    server = serve(loopback, headers=[("X-Powered-By", "PHP/8.3.35")], body=b"hello")
    answer = get(server.url + "/", {}, 5, read_body=False)
    assert (answer.status, answer.headers["x-powered-by"], answer.body) == (200, "PHP/8.3.35", b"")


def test_a_body_over_the_cap_is_no_problem_when_it_is_not_read(loopback, monkeypatch):
    monkeypatch.setattr(php_http, "_MAX_BODY", 10)
    server = serve(loopback, body=b"a" * 100)
    with pytest.raises(TransportError):
        get(server.url + "/", {}, 5)
    assert get(server.url + "/", {}, 5, read_body=False).status == 200


def test_a_cut_off_body_is_no_problem_when_it_is_not_read():
    with raw(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n" + b"x" * 10) as url:
        assert get(url, {}, 5, read_body=False).status == 200


@pytest.mark.parametrize("read_body", [True, None, 0, "", "no"])
def test_only_the_literal_false_skips_the_body(loopback, read_body):
    answer = get(serve(loopback, body=b"hello").url + "/", {}, 5, read_body=read_body)
    assert answer.body == b"hello"


# --- the source ---

def test_the_module_is_standard_library_only_and_reads_no_environment():
    source = pathlib.Path(php_http.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source, feature_version=(3, 9))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])
    assert imported <= {"functools", "http", "ssl", "time", "typing", "urllib"}
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    names |= {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    assert not names & {"environ", "getenv", "print", "logging", "urlopen", "build_opener"}
