import ast
import contextlib
import inspect
import ipaddress
import pathlib
import random
import socket
import ssl
import threading
import time
from urllib.parse import urlsplit

import pytest

from php_radar import http as php_http
from php_radar.http import Response, TransportError
from php_radar.knowledge import DATA_PATH, grade, grade_evidence, load_matrix
from php_radar.model import Asset, AssetInventory, Confidence, Evidence, Sapi, Source, Verdict
from php_radar.report import redact
from php_radar.scope import Target
from php_radar.sources import network
from php_radar.sources.network import fingerprint_version, probe, sweep

MATRIX = load_matrix(DATA_PATH)
FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "network" / "selfsigned.pem"


# --- nothing here leaves the machine ---

def _literal(host):
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _on_this_machine(host):
    if not isinstance(host, str) or host == "localhost":
        return True
    address = _literal(host)
    return address is not None and address.is_loopback


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    """Refuses every connection and name lookup that would leave this machine, and returns the
    list of what it refused.

    A test that expects the probe to stay in scope asserts the list is empty. The guard also
    stops the unreachable-host test, which names a documentation address, from sending anything.
    A literal address needs no lookup, so it passes the lookup guard and meets the connect guard.
    """
    refused = []
    connect, lookup = socket.socket.connect, socket.getaddrinfo

    def guarded_connect(self, address):
        if not _on_this_machine(address[0]):
            refused.append(address)
            raise ConnectionRefusedError(f"{address[0]} is outside this machine")
        return connect(self, address)

    def guarded_lookup(host, *args, **kwargs):
        if _literal(host) is None and not _on_this_machine(host):
            refused.append(host)
            raise socket.gaierror(f"{host} is outside this machine")
        return lookup(host, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket, "getaddrinfo", guarded_lookup)
    return refused


# --- stand-ins ---

class Stub:
    """A web server on 127.0.0.1 that answers every request the same way."""
    host = "127.0.0.1"

    def __init__(self, loopback):
        self.status, self.headers, self.body = 200, [], b"ok"
        self._server = loopback(self._reply)
        self.port = self._server.server_address[1]
        self.seen = self._server.seen

    def _reply(self, path, headers):
        return self.status, self.headers, self.body

    def set_headers(self, headers):
        self.headers = list(headers.items()) if isinstance(headers, dict) else list(headers)


@pytest.fixture
def stub_server(loopback):
    return Stub(loopback)


@pytest.fixture
def new_stub(loopback):
    return lambda: Stub(loopback)


@contextlib.contextmanager
def raw(reply, hold=False):
    """A one-shot server on 127.0.0.1 that answers its first request with exactly these bytes.
    It yields the Target to probe. With hold, the connection stays open until the test is done."""
    done = threading.Event()
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)

        def answer():
            try:
                conn, _ = listener.accept()
                with conn:
                    conn.recv(4096)
                    conn.sendall(reply)
                    if hold:
                        done.wait(10)
            except OSError:
                pass  # the test ended without a client

        worker = threading.Thread(target=answer, daemon=True)
        worker.start()
        try:
            yield Target("127.0.0.1", listener.getsockname()[1])
        finally:
            done.set()
            worker.join(5)


def recorder(status=200, headers=None, body=b"", cert=None):
    """A stand-in for http.get that records each call and answers the same way every time."""
    calls = []

    def fake(url, sent, timeout, verify=True, read_body=True):
        calls.append((url, dict(sent), timeout, verify, read_body))
        return Response(status, dict(headers or {}), body, cert)

    fake.calls = calls
    return fake


def by_host(table, delay=0.0):
    """A stand-in for http.get that answers by the host in the URL. A table value is a Response,
    or an exception to raise. It records when each call started and how many ran at once."""
    lock = threading.Lock()
    stats = {"running": 0, "peak": 0, "starts": []}

    def fake(url, sent, timeout, verify=True, read_body=True):
        with lock:
            stats["starts"].append(time.monotonic())
            stats["running"] += 1
            stats["peak"] = max(stats["peak"], stats["running"])
        try:
            time.sleep(delay)
        finally:
            with lock:
                stats["running"] -= 1
        outcome = table[urlsplit(url).hostname]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    fake.stats = stats
    return fake


def free_port():
    with socket.socket() as probe_socket:
        probe_socket.bind(("127.0.0.1", 0))
        return probe_socket.getsockname()[1]


# --- certificates, built by hand so every shape can be tried ---

def tlv(tag, *parts):
    body = b"".join(parts)
    if len(body) < 0x80:
        size = bytes([len(body)])
    else:
        count = (len(body).bit_length() + 7) // 8
        size = bytes([0x80 | count]) + len(body).to_bytes(count, "big")
    return bytes([tag]) + size + body


OID_CN = bytes.fromhex("550403")
OID_ORG = bytes.fromhex("55040a")
OID_SAN = bytes.fromhex("551d11")
OID_BASIC = bytes.fromhex("551d13")
ALGORITHM = tlv(0x30, tlv(0x06, bytes.fromhex("2a8648ce3d040302")))
VALIDITY = tlv(0x30, tlv(0x17, b"260101000000Z"), tlv(0x17, b"360101000000Z"))
KEY = tlv(0x30, tlv(0x30, tlv(0x06, bytes.fromhex("2a8648ce3d0201"))), tlv(0x03, bytes(66)))


def attr(oid, text, tag=0x0C):
    value = text if isinstance(text, bytes) else text.encode()
    return tlv(0x31, tlv(0x30, tlv(0x06, oid), tlv(tag, value)))


def name(*attrs):
    return tlv(0x30, *attrs)


def dns(text):
    return 0x82, text if isinstance(text, bytes) else text.encode()


def ip(text):
    return 0x87, ipaddress.ip_address(text).packed


def general_names(*entries):
    return tlv(0x30, *[tlv(tag, body) for tag, body in entries])


def extension(oid, value, critical=False):
    return tlv(0x30, tlv(0x06, oid), *([tlv(0x01, b"\xff")] if critical else []), tlv(0x04, value))


def certificate(subject, san=None, *, v3=True, more=(), outer=0x30, signed=0x30):
    fields = [tlv(0xA0, tlv(0x02, b"\x02"))] if v3 else []
    fields += [tlv(0x02, b"\x01"), ALGORITHM, name(attr(OID_CN, "Test CA")), VALIDITY, subject, KEY]
    extensions = list(more)
    if san is not None:
        extensions.append(extension(OID_SAN, san))
    if v3 and extensions:
        fields.append(tlv(0xA3, tlv(0x30, *extensions)))
    return tlv(outer, tlv(signed, *fields), ALGORITHM, tlv(0x03, b"\x00"))


def names_of(der):
    return network._cert_signals(der)


# --- a version, a hidden version, and an unreachable host ---

def test_reads_version_from_header(stub_server):
    stub_server.set_headers({"X-Powered-By": "PHP/8.3.35"})
    ev = probe(Target(stub_server.host, stub_server.port), timeout=2.0)
    assert ev.detected_version == "8.3.35"


def test_hidden_version_is_present_but_unknown(stub_server):
    stub_server.set_headers({})
    ev = probe(Target(stub_server.host, stub_server.port), timeout=2.0)
    assert ev.detected_version is None
    assert ev.signals.get("php_present") in ("true", "false")


def test_unreachable_host_degrades_not_raises():
    ev = probe(Target("203.0.113.254", 9), timeout=0.5)
    assert ev.note  # records the failure reason rather than raising


def test_the_documentation_address_never_leaves_the_machine(offline):
    ev = probe(Target("203.0.113.254", 9), timeout=0.5)
    assert offline == [("203.0.113.254", 9)]
    assert ev.note.startswith("no answer: ")


# --- what the answer shows about PHP ---

@pytest.mark.parametrize("headers, status, present, version", [
    ([("X-Powered-By", "PHP/8.3.35")], 200, "true", "8.3.35"),
    ([("X-Powered-By", "PHP")], 200, "true", None),
    ([("X-Powered-By", "php")], 200, "true", None),
    ([("X-Powered-By", "CakePHP/4.2.1")], 200, "true", None),
    ([("X-Powered-By", "PHP/8.1.2-1ubuntu2.14")], 200, "true", "8.1.2-1ubuntu2.14"),
    ([("X-Powered-By", "PHP/8.3.35"), ("Server", "Apache PHP/8.3.36")], 200, "true", "8.3.35"),
    ([("X-Powered-By", "PHP/8.3.35")], 503, "true", "8.3.35"),
    ([("Server", "Apache/2.4.58 (Ubuntu) PHP/8.3.6")], 200, "true", "8.3.6"),
    ([("Server", "Apache/2.4.58 (Ubuntu) mod_php")], 200, "true", None),
    ([("Server", "Apache/2.4.58 (Ubuntu)")], 200, "false", None),
    ([("Server", "nginx")], 200, "false", None),
    ([("X-Powered-By", "ASP.NET")], 200, "false", None),
    ([("Set-Cookie", "PHPSESSID=abc; path=/")], 200, "true", None),
    ([("Set-Cookie", "phpsessid=abc")], 200, "true", None),
    ([("Set-Cookie", "a=1"), ("Set-Cookie", "PHPSESSID=abc")], 200, "true", None),
    ([("Set-Cookie", "sessionid=abc")], 200, "false", None),
    ([("Content-Type", "application/x-httpd-php")], 200, "true", None),
    ([("Content-Type", "text/html; charset=UTF-8")], 200, "false", None),
    ([("Location", "/index.php")], 302, "true", None),
    ([("Location", "https://other.example/app/login.php?next=1")], 302, "true", None),
    ([("Location", "/home")], 302, "false", None),
    ([("Location", "https://www.php.net/manual/en/")], 302, "false", None),
    ([("Location", "/search?q=index.php")], 302, "false", None),
    ([("Location", "/php/home")], 302, "false", None),
    ([("Location", "/index.php/home")], 302, "true", None),
    ([("Location", "/INDEX.PHP")], 302, "true", None),
    ([("Location", "http://[::1/x.php")], 302, "false", None),
    ([], 200, "false", None),
    ([], 404, "false", None),
    # A server error says nothing about what runs the site, so it is neither a yes nor a no.
    ([], 500, None, None),
    ([], 503, None, None),
    # Nor does a gate in front of the application: a login, a firewall, a rate limit.
    ([], 401, None, None),
    ([], 403, None, None),
    ([("Server", "cloudflare")], 403, None, None),
    ([], 429, None, None),
    ([("X-Powered-By", "PHP/8.3.35")], 403, "true", "8.3.35"),
    ([("Set-Cookie", "PHPSESSID=abc")], 401, "true", None),
    # Other statuses with no sign of PHP are the clean answers they look like.
    ([], 301, "false", None),
    ([], 404, "false", None),
])
def test_what_the_answer_shows_about_php(stub_server, headers, status, present, version):
    stub_server.set_headers(headers)
    stub_server.status = status
    ev = probe(Target(stub_server.host, stub_server.port), 2.0)
    assert ev.signals.get("php_present") == present
    assert ev.detected_version == version


def test_a_server_error_with_nothing_in_it_keeps_a_note(stub_server):
    stub_server.status = 503
    ev = probe(Target(stub_server.host, stub_server.port), 2.0)
    assert ev.note.startswith("HTTP 503")
    assert "php_present" not in ev.signals


@pytest.mark.parametrize("host", [
    "token", "secret", "password", "pwd", "auth", "auth-service", "api-key", "key", "keycloak",
    "bearer", "credential", "pass", "pw", "secret-store", "web1.example.com", "10.0.0.5"])
@pytest.mark.parametrize("port", [80, 443, 8443])
def test_the_location_survives_the_redactor_whatever_the_host_is_called(host, port):
    # host:port reads as name:value to the redactor, which would turn token:443 into
    # token:[REDACTED]. Short internal names such as keycloak and auth-service are common.
    ev = probe(Target(host, port), 1.0, get=recorder())
    assert redact(ev.location) == ev.location
    assert ev.location.endswith(f":{port}/")


@pytest.mark.parametrize("status, reason", [
    (401, "access blocked or gated"), (403, "access blocked or gated"),
    (429, "access blocked or gated"), (500, "a server error"), (503, "a server error")])
def test_an_answer_that_tells_nothing_about_the_site_keeps_a_note_with_the_reason(
        stub_server, status, reason):
    stub_server.status = status
    ev = probe(Target(stub_server.host, stub_server.port), 2.0)
    assert ev.note == f"HTTP {status}, {reason}: could not determine what runs the site"
    assert "php_present" not in ev.signals


def test_a_clean_answer_has_no_note(stub_server):
    ev = probe(Target(stub_server.host, stub_server.port), 2.0)
    assert ev.note == ""


def test_the_evidence_is_a_network_read_with_the_target_as_its_location(stub_server):
    ev = probe(Target(stub_server.host, stub_server.port), 2.0)
    assert isinstance(ev, Evidence)
    assert ev.source is Source.NETWORK
    assert ev.location == f"http://127.0.0.1:{stub_server.port}/"
    assert ev.sapi is Sapi.UNKNOWN


# --- fingerprint_version ---

@pytest.mark.parametrize("headers, want", [
    ({"x-powered-by": "PHP/8.3.35"}, "8.3.35"),
    ({"X-Powered-By": "PHP/8.3.35"}, "8.3.35"),
    ({"X-POWERED-BY": "php/8.3.35"}, "8.3.35"),
    ({"server": "Apache/2.4.58 (Ubuntu) PHP/8.3.6"}, "8.3.6"),
    ({"Server": "Apache/2.4.58 (Ubuntu) PHP/8.3.6 mod_ssl/2.4.58 OpenSSL/3.0.2"}, "8.3.6"),
    ({"server": "Apache/2.4.58 (Ubuntu)"}, None),
    ({"server": "nginx/1.25.3"}, None),
    ({"server": "BaseHTTP/0.6 Python/3.14.3"}, None),
    ({}, None),
    ({"x-powered-by": "PHP"}, None),
    ({"x-powered-by": "PHP/"}, None),
    ({"x-powered-by": "PHP/8.3"}, None),
    ({"x-powered-by": "PHP/8"}, None),
    ({"x-powered-by": "PHP/x.y.z"}, None),
    ({"x-powered-by": "PHP/8.3.35.1"}, None),
    ({"x-powered-by": "PHP/99999.1.1"}, None),
    ({"x-powered-by": "ASP.NET"}, None),
    ({"x-powered-by": "CakePHP/4.2.1"}, None),
    ({"x-powered-by": "PHP/8.3.35, Express"}, "8.3.35"),
    ({"x-powered-by": "PHP/8.3.35;evil"}, "8.3.35"),
    ({"x-powered-by": "PHP/8.1.2-1ubuntu2.14"}, "8.1.2-1ubuntu2.14"),
    ({"x-powered-by": "PHP/7.4.3-4ubuntu2.19 OpenSSL"}, "7.4.3-4ubuntu2.19"),
    ({"x-powered-by": "PHP/8.3.6-1+ubuntu22.04.1+deb.sury.org+1"},
     "8.3.6-1+ubuntu22.04.1+deb.sury.org+1"),
    ({"x-powered-by": "PHP/8.3.0RC1"}, "8.3.0RC1"),
    # Two banners that disagree are both claims, so the lower version is the one reported.
    ({"x-powered-by": "PHP/8.3.35 PHP/8.3.36"}, "8.3.35"),
    ({"x-powered-by": "PHP/8.3.36", "server": "Apache PHP/8.3.35"}, "8.3.35"),
    ({"x-powered-by": "PHP/8.3.35", "server": "Apache PHP/8.3.36"}, "8.3.35"),
    ({"x-powered-by": "PHP/8.3.36 PHP/7.4.33"}, "7.4.33"),
    # A banner that gives no version beside one that does leaves the version.
    ({"x-powered-by": "PHP", "server": "Apache PHP/8.3.36"}, "8.3.36"),
    # A version longer than any real build is a hostile one, and it is not shortened to fit.
    ({"x-powered-by": "PHP/8.3.35-" + "a" * 100}, None),
    ({"x-powered-by": "PHP/8.3.35-" + "a" * 40}, "8.3.35-" + "a" * 40),
    ({"x-powered-by": "PHP/8.3.35-" + "a" * 57}, "8.3.35-" + "a" * 57),  # 64 characters
    ({"x-powered-by": "PHP/8.3.35-" + "a" * 58}, None),  # 65
    # Only the two named headers are read.
    ({"x-generator": "PHP/8.3.35", "via": "PHP/8.3.35"}, None),
])
def test_fingerprint_version(headers, want):
    assert fingerprint_version(headers) == want


def test_fingerprint_version_lower_cases_only_ascii():
    # The Turkish capital I lower-cases to two code points, which would shift every index after it.
    assert fingerprint_version({"server": "\u0130\u0130\u0130 PHP/8.3.35"}) == "8.3.35"
    assert fingerprint_version({"server": "\u212a PHP/8.3.35"}) == "8.3.35"


# --- who the evidence is about ---

def test_an_address_goes_in_ip_and_never_in_hostname(stub_server):
    ev = probe(Target(stub_server.host, stub_server.port), 2.0)
    assert ev.signals["ip"] == "127.0.0.1"
    assert "hostname" not in ev.signals


def test_a_name_goes_in_hostname_and_never_in_ip():
    ev = probe(Target("web1.example.com", 443), 2.0, get=recorder())
    assert ev.signals["hostname"] == "web1.example.com"
    assert "ip" not in ev.signals


@pytest.mark.parametrize("host, key", [
    ("10.0.0.5", "ip"),
    ("10.0.0.5.", "ip"),
    ("0.0.0.0", "ip"),
    # The OS resolver reads these as addresses, and the last label of each starts with a digit.
    ("127.1", "ip"),
    ("2130706433", "ip"),
    ("0x7f.1", "ip"),
    ("web1", "hostname"),
    ("Web1.Example.COM", "hostname"),
    ("web1.example.com.", "hostname"),
    ("localhost", "hostname"),
    ("a-b.example", "hostname"),
    ("10.0.0.5.example", "hostname"),
])
def test_an_address_is_told_from_a_name_as_the_scope_file_tells_them(host, key):
    ev = probe(Target(host, 80), 1.0, get=recorder())
    assert ev.signals[key] == host
    assert ({"ip", "hostname"} & set(ev.signals)) == {key}


def test_the_probe_records_the_name_as_given_for_the_model_to_normalize():
    ev = probe(Target("Web1.Example.COM.", 443), 1.0, get=recorder())
    assert ev.signals["hostname"] == "Web1.Example.COM."


# --- a named probe joins the machine, an address never does ---

def test_a_probe_by_name_joins_the_host_read_of_the_same_machine():
    seen = probe(Target("Web1.Example.com", 443), 1.0,
                 get=recorder(headers={"x-powered-by": "PHP/8.3.35"}))
    host = Evidence(Source.HOST, "web1.example.com", "8.3.36", Sapi.UNKNOWN,
                    {"hostname": "web1.example.com"})
    inventory = AssetInventory()
    inventory.add(seen)
    inventory.add(host)
    assets = inventory.assets()
    assert len(assets) == 1
    assert {ev.source for ev in assets[0].evidence} == {Source.NETWORK, Source.HOST}


def test_the_two_ports_of_a_named_host_are_one_asset():
    inventory = AssetInventory()
    for port in (80, 443):
        inventory.add(probe(Target("web1.example.com", port), 1.0,
                            get=recorder(headers={"x-powered-by": "PHP/8.3.35"})))
    assert len(inventory.assets()) == 1


def test_an_address_never_merges_with_anything():
    inventory = AssetInventory()
    for port in (80, 443):
        inventory.add(probe(Target("10.0.0.5", port), 1.0,
                            get=recorder(headers={"x-powered-by": "PHP/8.3.35"})))
    inventory.add(Evidence(Source.HOST, "10.0.0.5", "8.3.36", Sapi.UNKNOWN, {"ip": "10.0.0.5"}))
    assert len(inventory.assets()) == 3


# --- one plain request, and no way out of scope ---

def test_the_probe_sends_one_plain_get_of_the_root_and_no_credential(stub_server):
    probe(Target(stub_server.host, stub_server.port), 2.0)
    (path, seen), = stub_server.seen
    assert path == "/"
    assert seen["user-agent"] == "php-radar"
    assert not {"authorization", "cookie", "content-length", "content-type",
                "transfer-encoding", "range", "expect"} & set(seen)


def test_the_probe_asks_http_for_no_certificate_check_and_no_body():
    fake = recorder()
    probe(Target("web1.example.com", 443), 3.0, get=fake)
    (url, sent, timeout, verify, read_body), = fake.calls
    assert (timeout, verify, read_body) == (3.0, False, False)
    assert sent == {"User-Agent": "php-radar", "Accept": "*/*"}


def test_the_probe_hands_http_a_copy_of_its_headers():
    # Shared between threads, a dict that one get could change would change every later request.
    first = recorder()
    probe(Target("a.example", 80), 1.0, get=first)

    def meddling(url, sent, timeout, verify=True, read_body=True):
        sent["Authorization"] = "Bearer SEKRET"
        return Response(200, {}, b"")

    probe(Target("b.example", 80), 1.0, get=meddling)
    probe(Target("c.example", 80), 1.0, get=first)
    assert first.calls[1][1] == {"User-Agent": "php-radar", "Accept": "*/*"}


def test_a_body_is_never_read(stub_server, monkeypatch):
    # With the cap lowered beneath the size of the body, a probe that read it would fail.
    monkeypatch.setattr(php_http, "_MAX_BODY", 100)
    stub_server.set_headers({"X-Powered-By": "PHP/8.3.35"})
    stub_server.body = b"x" * 10_000
    ev = probe(Target(stub_server.host, stub_server.port), 2.0)
    assert ev.detected_version == "8.3.35"
    assert ev.note == ""


def test_a_length_that_is_never_sent_does_not_hold_the_probe():
    # The headers promise ten bytes and the server holds the connection open without sending them.
    # Waiting for them would take until the timeout.
    reply = b"HTTP/1.1 200 OK\r\nX-Powered-By: PHP/8.3.35\r\nContent-Length: 10\r\n\r\n"
    with raw(reply, hold=True) as target:
        started = time.monotonic()
        ev = probe(target, 5.0)
    assert time.monotonic() - started < 3
    assert ev.detected_version == "8.3.35"
    assert ev.note == ""


def test_a_huge_declared_length_is_no_problem():
    reply = (b"HTTP/1.1 200 OK\r\nX-Powered-By: PHP/8.3.35\r\n"
             b"Content-Length: 99999999999\r\n\r\n")
    with raw(reply) as target:
        assert probe(target, 2.0).detected_version == "8.3.35"


def test_the_default_get_is_http_get():
    assert inspect.signature(probe).parameters["get"].default is php_http.get


@pytest.mark.parametrize("host, port, url", [
    ("web1.example.com", 443, "https://web1.example.com:443/"),
    ("web1.example.com", 80, "http://web1.example.com:80/"),
    ("10.0.0.5", 443, "https://10.0.0.5:443/"),
    ("10.0.0.5", 8443, "https://10.0.0.5:8443/"),
    ("10.0.0.5", 8080, "http://10.0.0.5:8080/"),
    ("10.0.0.5", 9443, "http://10.0.0.5:9443/"),
    ("10.0.0.5", 1, "http://10.0.0.5:1/"),
    ("10.0.0.5", 65535, "http://10.0.0.5:65535/"),
])
def test_the_port_decides_between_http_and_https(host, port, url):
    fake = recorder()
    probe(Target(host, port), 3.0, get=fake)
    assert [call[0] for call in fake.calls] == [url]


def test_a_redirect_is_read_as_evidence_and_never_followed(new_stub, offline):
    elsewhere = new_stub()
    elsewhere.set_headers({"X-Powered-By": "PHP/9.9.9"})
    front = new_stub()
    front.status = 302
    front.set_headers({"Location": f"http://127.0.0.1:{elsewhere.port}/landing",
                       "X-Powered-By": "PHP/8.3.35"})
    ev = probe(Target(front.host, front.port), 2.0)
    # The version is the 302's own header. Followed, the redirect would have said 9.9.9.
    assert ev.detected_version == "8.3.35"
    assert elsewhere.seen == []
    assert [path for path, _ in front.seen] == ["/"]
    assert offline == []


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
@pytest.mark.parametrize("where", [
    "http://203.0.113.9/x",
    "https://evil.example/x",
    "//evil.example/x",
    "http://evil.example:8080/x.php",
])
def test_a_redirect_to_a_public_address_is_not_even_looked_up(stub_server, offline, status, where):
    stub_server.status = status
    stub_server.set_headers({"Location": where})
    ev = probe(Target(stub_server.host, stub_server.port), 2.0)
    assert ev.source is Source.NETWORK
    assert offline == []  # no connection and no name lookup was attempted
    assert len(stub_server.seen) == 1


def test_a_host_of_253_characters_is_probed_and_one_of_254_is_not():
    longest = ("a" * 63 + ".") * 3 + "a" * 61
    assert len(longest) == 253
    fake = recorder()
    probe(Target(longest, 80), 1.0, get=fake)
    assert fake.calls[0][0] == f"http://{longest}:80/"
    assert probe(Target(longest + "a", 80), 1.0, get=fake).note.startswith("not probed")


@pytest.mark.parametrize("target", [
    Target("", 80),
    Target("10.0.0.5@127.0.0.1", 80),
    Target("127.0.0.1/x", 80),
    Target("127.0.0.1?x=1", 80),
    Target("127.0.0.1#x", 80),
    Target("127.0.0.1:81", 80),
    Target("a b", 80),
    Target("127.0.0.1\r\nHost: evil", 80),
    Target("127.0.0.1\x00", 80),
    Target("::1", 80),
    Target("[::1]", 80),
    Target("ex\u00e4mple.com", 80),
    Target("a" * 254, 80),
    Target("127.0.0.1", 0),
    Target("127.0.0.1", -1),
    Target("127.0.0.1", 65536),
    Target("127.0.0.1", "80"),
    Target("127.0.0.1", True),
    Target("127.0.0.1", None),
    Target(None, 80),
])
def test_a_target_that_is_not_a_plain_host_and_port_is_refused_before_anything_is_sent(
        target, offline):
    fake = recorder()
    ev = probe(target, 1.0, get=fake)
    assert fake.calls == []
    assert offline == []
    assert ev.source is Source.NETWORK
    assert ev.detected_version is None
    assert ev.note.startswith("not probed: ")
    assert ev.signals == {}  # a string that is no host names no asset


# --- a host that cannot be read becomes a finding ---

@pytest.mark.parametrize("reply", [
    pytest.param(b"", id="closes without answering"),
    pytest.param(b"this is not http\r\n\r\n", id="not http"),
    pytest.param(b"HTTP/9.9 200 OK\r\n\r\n", id="unknown protocol"),
    pytest.param(b"HTTP/1.1 200 OK\r\n" + b"X-A: b\r\n" * 150 + b"\r\n", id="150 headers"),
    pytest.param(b"HTTP/1.1 200 OK\r\nX-A: " + b"a" * 70000 + b"\r\n\r\n",
                 id="a header line over the limit"),
    pytest.param(b"x" * 100000, id="a status line over the limit"),
])
def test_an_answer_that_is_not_usable_http_becomes_a_note(reply):
    with raw(reply) as target:
        ev = probe(target, 2.0)
    assert ev.source is Source.NETWORK
    assert ev.detected_version is None
    assert "php_present" not in ev.signals
    assert ev.signals == {"ip": "127.0.0.1"}
    assert ev.note.startswith("no answer: ")
    assert len(ev.note) <= len("no answer: ") + 200


def test_a_note_is_cut_at_200_characters():
    # http.client puts the whole line it could not read in the message of its error.
    with raw(b"A" * 5000 + b"\r\n\r\n") as target:
        ev = probe(target, 2.0)
    assert ev.note.startswith("no answer: BadStatusLine")
    assert len(ev.note) == len("no answer: ") + 200


def test_a_host_that_drips_its_answer_becomes_a_note_at_the_deadline(drip):
    # A byte every 50 ms never runs out a wait of 250 ms. The total does, after four of them.
    port = drip(b"HTTP/1.1 200 OK\r\nX-A: ", 0.05, 100)
    started = time.monotonic()
    ev = probe(Target("127.0.0.1", port), 0.25)
    assert ev.note == "no answer: the answer took longer than 1 seconds to arrive"
    assert ev.signals == {"ip": "127.0.0.1"}
    assert time.monotonic() - started < 3.5


def test_a_port_nothing_listens_on_becomes_a_note():
    # Linux refuses at once. Windows retries for about two seconds first, so the wait can end the
    # attempt before the refusal arrives. Either way there is no answer, and the note says so.
    ev = probe(Target("127.0.0.1", free_port()), 0.5)
    assert ev.note.startswith("no answer: ")
    assert ev.signals == {"ip": "127.0.0.1"}
    assert ev.location.startswith("http://127.0.0.1:") and ev.location.endswith("/")


def test_a_host_that_never_answers_times_out_into_a_note():
    with socket.socket() as silent:
        silent.bind(("127.0.0.1", 0))
        silent.listen(1)  # the handshake completes in the backlog, and nothing ever replies
        started = time.monotonic()
        ev = probe(Target("127.0.0.1", silent.getsockname()[1]), 0.3)
    assert time.monotonic() - started < 5
    assert ev.note.startswith("no answer: ")
    assert "timed out" in ev.note


def test_a_name_that_does_not_resolve_becomes_a_note_and_keeps_its_name(offline):
    ev = probe(Target("web1.example.com", 443), 1.0)
    assert ev.note.startswith("no answer: ")
    assert ev.signals == {"hostname": "web1.example.com"}
    assert offline == ["web1.example.com"]  # the guard refused the lookup, so nothing went out


@pytest.mark.parametrize("error, note", [
    (TransportError("TimeoutError: timed out"), "no answer: TimeoutError: timed out"),
    (OSError("boom"), "no answer: OSError: boom"),
    (ConnectionResetError("reset"), "no answer: ConnectionResetError: reset"),
    (ssl.SSLError(1, "handshake failure"), "no answer: SSLError: handshake failure"),
])
def test_an_os_error_from_get_becomes_a_note(error, note):
    def failing(url, sent, timeout, verify=True, read_body=True):
        raise error

    ev = probe(Target("web1.example.com", 443), 1.0, get=failing)
    assert ev.note == note
    assert ev.signals == {"hostname": "web1.example.com"}


@pytest.mark.parametrize("error", [RuntimeError("bug"), ValueError("bad"), KeyError("k")])
def test_an_error_that_is_no_failure_to_connect_is_not_swallowed(error):
    def buggy(url, sent, timeout, verify=True, read_body=True):
        raise error

    with pytest.raises(type(error)):
        probe(Target("web1.example.com", 443), 1.0, get=buggy)


def test_an_unusable_timeout_raises_before_anything_is_sent(stub_server):
    for timeout in (0, -1, None, float("nan")):
        with pytest.raises(ValueError):
            probe(Target(stub_server.host, stub_server.port), timeout)
    assert stub_server.seen == []


# --- the certificate of an https host ---

def test_names_are_read_from_the_subject_and_the_alternative_names():
    der = certificate(
        name(attr(OID_ORG, "Example Corp"), attr(OID_CN, "web1.example.com")),
        general_names(dns("web1.example.com"), dns("*.example.com"), ip("192.0.2.7"),
                      ip("2001:db8::1")))
    assert names_of(der) == {
        "cert_cn": "web1.example.com",
        "cert_san": "web1.example.com, *.example.com, 192.0.2.7, 2001:db8::1"}


def test_the_certificate_fixture_holds_a_certificate_and_no_key():
    text = FIXTURE.read_text()
    assert text.startswith("-----BEGIN CERTIFICATE-----")
    assert "PRIVATE" not in text


def test_a_real_certificate_gives_the_names_openssl_gives():
    der = ssl.PEM_cert_to_DER_cert(FIXTURE.read_text())
    assert names_of(der) == {
        "cert_cn": "radar-test.local",
        "cert_san": "radar-test.local, alt.radar-test.local, 10.1.2.3"}


def test_the_issuer_is_not_the_subject():
    der = certificate(name(attr(OID_CN, "web1.example.com")),
                      general_names(dns("web1.example.com")))
    assert "Test CA" not in str(names_of(der))


def test_a_certificate_with_no_common_name_gives_only_its_alternative_names():
    der = certificate(name(attr(OID_ORG, "Example Corp")), general_names(dns("web1.example.com")))
    assert names_of(der) == {"cert_san": "web1.example.com"}


def test_a_certificate_with_no_alternative_names_gives_only_its_common_name():
    assert names_of(certificate(name(attr(OID_CN, "web1")))) == {"cert_cn": "web1"}


def test_a_certificate_with_no_names_gives_nothing():
    assert names_of(certificate(name())) == {}


def test_a_version_1_certificate_has_a_subject_and_no_extensions():
    assert names_of(certificate(name(attr(OID_CN, "old.example.com")), v3=False)) == {
        "cert_cn": "old.example.com"}


def test_more_than_one_common_name_are_all_kept():
    der = certificate(name(attr(OID_CN, "a.example"), attr(OID_CN, "b.example")))
    assert names_of(der) == {"cert_cn": "a.example, b.example"}


@pytest.mark.parametrize("tag, raw_name", [
    (0x0C, "web1".encode("utf-8")),  # UTF8String
    (0x13, b"web1"),  # PrintableString
    (0x16, b"web1"),  # IA5String
    (0x14, b"web1"),  # TeletexString
    (0x1E, "web1".encode("utf-16-be")),  # BMPString
])
def test_every_string_type_a_name_can_use_is_read(tag, raw_name):
    der = certificate(name(attr(OID_CN, raw_name, tag)))
    assert names_of(der) == {"cert_cn": "web1"}


def test_a_string_type_that_is_not_text_gives_no_name():
    assert names_of(certificate(name(attr(OID_CN, b"web1", 0x04)))) == {}
    assert names_of(certificate(name(attr(OID_CN, b"web1", 0x1C)))) == {}


def test_a_utf8_common_name_keeps_its_letters():
    der = certificate(name(attr(OID_CN, "m\u00fcnchen.example")))
    assert names_of(der) == {"cert_cn": "m\u00fcnchen.example"}


def test_alternative_names_of_other_kinds_are_left_out():
    san = general_names((0x81, b"admin@example.com"), (0x86, b"https://example.com/"),
                        dns("web1.example.com"), (0xA4, tlv(0x30)), (0x88, bytes.fromhex("550403")))
    assert names_of(certificate(name(), san)) == {"cert_san": "web1.example.com"}


def test_an_address_of_the_wrong_length_is_left_out():
    san = general_names((0x87, b"\x01\x02\x03\x04\x05"), (0x87, b"\x01\x02\x03"), ip("192.0.2.7"))
    assert names_of(certificate(name(), san)) == {"cert_san": "192.0.2.7"}


def test_other_extensions_and_a_critical_flag_are_stepped_over():
    other = extension(OID_BASIC, tlv(0x30, tlv(0x01, b"\xff")), critical=True)
    der = certificate(name(), general_names(dns("web1.example.com")), more=[other])
    assert names_of(der) == {"cert_san": "web1.example.com"}
    critical_san = extension(OID_SAN, general_names(dns("web2.example.com")), critical=True)
    assert names_of(certificate(name(), more=[other, critical_san])) == {
        "cert_san": "web2.example.com"}


@pytest.mark.parametrize("bad", [
    b"web\x00one.example",
    b"web\none.example",
    b"web1.ex\xe4mple.com",
    "web\u202e1.example".encode("utf-8"),
])
def test_a_dns_name_with_a_control_or_non_ascii_character_is_left_out(bad):
    san = general_names(dns(bad), dns("web1.example.com"))
    assert names_of(certificate(name(), san)) == {"cert_san": "web1.example.com"}


def test_a_common_name_with_a_control_character_is_left_out():
    assert names_of(certificate(name(attr(OID_CN, "web\n1.example")))) == {}


def test_the_names_are_capped_at_32_of_each_kind():
    many = general_names(*[dns(f"h{i}.example") for i in range(72)])
    out = names_of(certificate(name(*[attr(OID_CN, f"c{i}") for i in range(40)]), many))
    assert out["cert_san"].split(", ") == [f"h{i}.example" for i in range(32)]
    assert out["cert_cn"].split(", ") == [f"c{i}" for i in range(32)]


def test_a_name_longer_than_253_characters_is_left_out_and_not_shortened():
    at_cap, over = "a" * 253, "a" * 254
    der = certificate(name(attr(OID_CN, over), attr(OID_CN, at_cap)),
                      general_names(dns(over), dns(at_cap), dns("ok")))
    assert names_of(der) == {"cert_cn": at_cap, "cert_san": at_cap + ", ok"}


@pytest.mark.parametrize("der", [
    None,
    b"",
    b"\x30",
    b"\x30\x00",
    b"\x30\x80",
    b"\x30\x84\xff\xff\xff\xff",
    b"\x30\x03\x01\x02",
    b"\x1f\x7f\x00",
    b"\x30\x82\x01\x00" + b"\x00" * 10,
    b"not a certificate at all",
    bytes(range(256)) * 4,
    tlv(0x30, tlv(0x30)),
    tlv(0x30, tlv(0x30, tlv(0x02, b"\x01"))),
    tlv(0x31, tlv(0x30)),
])
def test_bytes_that_are_no_certificate_give_nothing(der):
    assert names_of(der) == {}


def test_a_certificate_cut_short_anywhere_is_read_without_error():
    der = ssl.PEM_cert_to_DER_cert(FIXTURE.read_text())
    for cut in range(len(der) + 1):
        out = names_of(der[:cut])
        assert set(out) <= {"cert_cn", "cert_san"}
    assert names_of(der[:-1]) == {}  # the outer length now runs past the data


def test_a_certificate_with_bytes_changed_is_read_without_error():
    der = ssl.PEM_cert_to_DER_cert(FIXTURE.read_text())
    rng = random.Random(20261023)
    bound = network._MAX_NAMES * (network._MAX_NAME + 2)
    for _ in range(4000):
        mutated = bytearray(der)
        for _ in range(rng.randint(1, 6)):
            mutated[rng.randrange(len(mutated))] = rng.randrange(256)
        out = names_of(bytes(mutated))
        assert set(out) <= {"cert_cn", "cert_san"}
        assert all(value.isprintable() and 0 < len(value) <= bound for value in out.values())


def test_random_bytes_are_read_without_error():
    rng = random.Random(7)
    for _ in range(3000):
        blob = bytes(rng.randrange(256) for _ in range(rng.randint(0, 80)))
        assert set(names_of(blob)) <= {"cert_cn", "cert_san"}


def test_a_long_form_tag_ends_the_walk():
    # Tag number 3 in the long form is 1f 03, and the length follows. X.509 names use no such tag,
    # so the walk stops there and the name after it is not reached.
    odd = bytes.fromhex("1f03000000")
    der = certificate(name(attr(OID_CN, "a"), odd, attr(OID_CN, "b")))
    assert names_of(der) == {"cert_cn": "a"}


@pytest.mark.parametrize("odd", [
    pytest.param(bytes.fromhex("3180") + bytes(128), id="an indefinite length"),
    pytest.param(bytes.fromhex("3184") + bytes(4), id="a length in four bytes"),
])
def test_a_length_that_der_does_not_allow_ends_the_walk(odd):
    der = certificate(name(attr(OID_CN, "a"), odd, attr(OID_CN, "b")))
    assert names_of(der) == {"cert_cn": "a"}


def test_a_length_in_three_bytes_is_read():
    padding = extension(OID_BASIC, bytes(70_000))
    der = certificate(name(), general_names(dns("web1.example.com")), more=[padding])
    assert names_of(der) == {"cert_san": "web1.example.com"}


def test_an_empty_element_at_the_end_of_its_parent_is_still_an_element():
    assert list(network._elements(b"\x30\x00", 0, 2)) == [(0x30, 2, 2)]
    assert list(network._elements(b"\x30\x00\x05\x00", 0, 4)) == [(0x30, 2, 2), (0x05, 4, 4)]
    assert list(network._elements(b"\x30\x00", 0, 1)) == []


def test_the_outer_part_and_the_signed_part_must_be_sequences():
    subject = name(attr(OID_CN, "web1"))
    assert names_of(certificate(subject)) == {"cert_cn": "web1"}
    assert names_of(certificate(subject, outer=0x31)) == {}
    assert names_of(certificate(subject, signed=0x31)) == {}


def test_a_subject_alternative_name_extension_must_hold_a_sequence():
    bare = extension(OID_SAN, tlv(0x31, tlv(0x82, b"x.example")))
    assert names_of(certificate(name(), more=[bare])) == {}


def test_an_extension_value_that_is_no_octet_string_is_not_read():
    odd = tlv(0x30, tlv(0x06, OID_SAN), tlv(0x0C, general_names(dns("x.example"))))
    assert names_of(certificate(name(), more=[odd])) == {}


def test_a_name_attribute_must_be_exactly_a_type_and_a_value():
    three = tlv(0x31, tlv(0x30, tlv(0x06, OID_CN), tlv(0x0C, b"x"), tlv(0x0C, b"y")))
    one = tlv(0x31, tlv(0x30, tlv(0x06, OID_CN)))
    assert names_of(certificate(name(three, one))) == {}


def test_an_attribute_type_and_an_extension_id_must_be_object_identifiers():
    wrong_type = tlv(0x31, tlv(0x30, tlv(0x04, OID_CN), tlv(0x0C, b"x")))
    wrong_id = tlv(0x30, tlv(0x04, OID_SAN), tlv(0x04, general_names(dns("x.example"))))
    assert names_of(certificate(name(wrong_type), more=[wrong_id])) == {}


def test_the_names_are_recorded_and_identify_nothing():
    der = certificate(name(attr(OID_CN, "victim.corp")), general_names(dns("victim.corp")))
    seen = probe(Target("10.0.0.9", 443), 1.0,
                 get=recorder(headers={"x-powered-by": "PHP/8.3.35"}, cert=der))
    assert seen.signals["cert_cn"] == "victim.corp"
    assert seen.signals["cert_san"] == "victim.corp"
    assert seen.signals["ip"] == "10.0.0.9"
    assert "hostname" not in seen.signals
    # A certificate can claim any name, so a host that presents this one is not that host. If it
    # were, a vulnerable box could fold into a patched asset and be cleared.
    patched = Evidence(Source.HOST, "victim.corp", "8.3.36", Sapi.UNKNOWN,
                       {"hostname": "victim.corp"})
    inventory = AssetInventory()
    inventory.add(seen)
    inventory.add(patched)
    assert len(inventory.assets()) == 2


def test_a_named_probe_keeps_its_own_name_whatever_the_certificate_says():
    der = certificate(name(attr(OID_CN, "victim.corp")))
    seen = probe(Target("web1.example.com", 443), 1.0, get=recorder(cert=der))
    assert seen.signals["hostname"] == "web1.example.com"
    assert seen.signals["cert_cn"] == "victim.corp"


def test_a_plain_http_probe_has_no_certificate_signals(stub_server):
    ev = probe(Target(stub_server.host, stub_server.port), 2.0)
    assert not {"cert_cn", "cert_san"} & set(ev.signals)


# --- a real https host with a certificate nobody trusts ---

def test_a_self_signed_https_host_is_probed_and_its_names_recorded(
        loopback, self_signed, monkeypatch, offline):
    server = loopback(lambda path, seen: (200, [("X-Powered-By", "PHP/8.3.35")], b"ok"),
                      tls=self_signed.context)
    port = server.server_address[1]
    monkeypatch.setattr(network, "_TLS_PORTS", frozenset({port}))
    ev = probe(Target("127.0.0.1", port), 3.0)
    assert ev.detected_version == "8.3.35"
    assert ev.signals["php_present"] == "true"
    assert ev.signals["cert_cn"] == self_signed.cn
    assert ev.signals["cert_san"] == ", ".join(self_signed.names)
    assert ev.signals["ip"] == "127.0.0.1"
    assert [path for path, _ in server.seen] == ["/"]
    assert ev.note == ""


def test_a_tls_port_that_answers_in_plain_text_becomes_a_note(monkeypatch):
    # The server answers as soon as the first handshake bytes arrive. A line-reading server would
    # wait for a line break that random handshake bytes may never hold.
    with raw(b"HTTP/1.1 400 Bad Request\r\n\r\n") as target:
        monkeypatch.setattr(network, "_TLS_PORTS", frozenset({target.port}))
        ev = probe(target, 2.0)
    assert ev.note.startswith("no answer: SSLError")
    assert ev.signals == {"ip": "127.0.0.1"}


def test_a_tls_server_that_redirects_is_read_and_not_followed(
        loopback, self_signed, new_stub, monkeypatch):
    elsewhere = new_stub()
    server = loopback(lambda path, seen: (
        302, [("Location", f"http://127.0.0.1:{elsewhere.port}/"), ("X-Powered-By", "PHP/8.2.34")],
        b""), tls=self_signed.context)
    port = server.server_address[1]
    monkeypatch.setattr(network, "_TLS_PORTS", frozenset({port}))
    ev = probe(Target("127.0.0.1", port), 3.0)
    assert ev.detected_version == "8.2.34"
    assert elsewhere.seen == []


# --- what the grader makes of it ---

@pytest.mark.parametrize("headers, verdict, confidence", [
    ({"x-powered-by": "PHP/8.3.35"}, Verdict.EXPOSED, Confidence.LOW),
    ({"x-powered-by": "PHP/7.4.33"}, Verdict.EXPOSED, Confidence.LOW),
    ({"x-powered-by": "PHP/8.3.36"}, Verdict.LIKELY_PATCHED, Confidence.LOW),
    # PHP is there and its version is hidden: a lead, and never a clearance.
    ({"x-powered-by": "PHP"}, Verdict.INDETERMINATE, Confidence.MEDIUM),
    ({"set-cookie": "PHPSESSID=abc"}, Verdict.INDETERMINATE, Confidence.MEDIUM),
    ({"location": "/index.php"}, Verdict.INDETERMINATE, Confidence.MEDIUM),
    # A banner cannot name the distribution, so a packaged build is not graded on its number.
    ({"x-powered-by": "PHP/8.1.2-1ubuntu2.28"}, Verdict.INDETERMINATE, Confidence.MEDIUM),
    ({"x-powered-by": "PHP/8.1.2-1ubuntu2.14"}, Verdict.INDETERMINATE, Confidence.MEDIUM),
    # Nothing shown settles nothing.
    ({}, Verdict.INDETERMINATE, Confidence.LOW),
])
def test_the_grader_reads_what_the_probe_records(headers, verdict, confidence):
    ev = probe(Target("web1.example.com", 443), 1.0, get=recorder(headers=headers))
    assert grade_evidence(ev, MATRIX) == (verdict, confidence)


@pytest.mark.parametrize("status", [401, 403, 429, 500, 503])
def test_a_gate_or_a_server_error_with_nothing_in_it_grades_as_a_read_that_saw_nothing(status):
    ev = probe(Target("web1.example.com", 443), 1.0, get=recorder(status=status))
    assert grade_evidence(ev, MATRIX) == (Verdict.INDETERMINATE, Confidence.LOW)


def test_a_host_that_cannot_be_read_grades_as_a_read_that_saw_nothing():
    def failing(url, sent, timeout, verify=True, read_body=True):
        raise TransportError("TimeoutError: timed out")

    ev = probe(Target("web1.example.com", 443), 1.0, get=failing)
    assert grade_evidence(ev, MATRIX) == (Verdict.INDETERMINATE, Confidence.LOW)
    hidden = probe(Target("web1.example.com", 80), 1.0,
                   get=recorder(headers={"set-cookie": "PHPSESSID=a"}))
    asset = Asset("web1.example.com", "host", [ev, hidden])
    assert grade(asset, MATRIX) == (Verdict.INDETERMINATE, Confidence.MEDIUM)


# --- sweep ---

def php(version="8.3.35"):
    return Response(200, {"x-powered-by": f"PHP/{version}"}, b"")


def test_sweep_keeps_what_shows_php_and_what_could_not_be_read_in_order():
    table = {
        "a.example": php(),
        "b.example": Response(200, {"server": "nginx"}, b""),
        "c.example": TransportError("TimeoutError: timed out"),
        "d.example": Response(200, {"set-cookie": "PHPSESSID=1"}, b""),
        "e.example": Response(503, {}, b""),
        "f.example": Response(404, {}, b""),
        "g.example": Response(302, {"location": "/home"}, b""),
        "h.example": php("8.3.36"),
    }
    found = sweep([Target(host, 80) for host in table], 1000, 3, get=by_host(table))
    assert [ev.signals["hostname"] for ev in found] == [
        "a.example", "c.example", "d.example", "e.example", "h.example"]
    assert [ev.signals.get("php_present") for ev in found] == ["true", None, "true", None, "true"]


def test_sweep_keeps_a_host_that_answers_from_behind_a_gate():
    table = {
        "a.example": Response(401, {}, b""),
        "b.example": Response(403, {"server": "cloudflare"}, b""),
        "c.example": Response(429, {}, b""),
        "d.example": Response(404, {}, b""),
        "e.example": Response(200, {"server": "nginx"}, b""),
        "f.example": Response(403, {"x-powered-by": "PHP/8.3.35"}, b""),
    }
    found = sweep([Target(host, 443) for host in table], 1000, 2, get=by_host(table))
    assert [ev.signals["hostname"] for ev in found] == [
        "a.example", "b.example", "c.example", "f.example"]
    assert [ev.signals.get("php_present") for ev in found] == [None, None, None, "true"]
    assert [ev.note.startswith("HTTP 4") for ev in found] == [True, True, True, False]


def test_a_clean_perimeter_leaves_no_evidence():
    table = {f"h{i}.example": Response(200, {"server": "nginx"}, b"") for i in range(6)}
    assert sweep([Target(host, 443) for host in table], 1000, 2, get=by_host(table)) == []


def test_sweep_leaves_no_worker_threads_behind():
    table = {f"h{i}.example": php() for i in range(6)}
    sweep([Target(host, 80) for host in table], 10_000, 3, get=by_host(table))
    left = [t.name for t in threading.enumerate() if t.name.startswith("ThreadPoolExecutor")]
    assert left == []


def test_sweep_of_no_targets_is_empty():
    assert sweep([], 1, 1, get=by_host({})) == []


def test_each_target_is_probed_once_and_by_its_own_name():
    table = {"a.example": php(), "b.example": php("8.2.1")}
    fake = by_host(table)
    found = sweep([Target("a.example", 80), Target("b.example", 8443)], 1000, 4, get=fake)
    assert [ev.location for ev in found] == ["http://a.example:80/", "https://b.example:8443/"]
    assert [ev.detected_version for ev in found] == ["8.3.35", "8.2.1"]
    assert len(fake.stats["starts"]) == 2


def test_sweep_runs_no_more_probes_at_once_than_workers():
    table = {f"h{i}.example": php() for i in range(12)}
    fake = by_host(table, delay=0.05)
    sweep([Target(host, 80) for host in table], 10_000, 3, get=fake)
    assert 2 <= fake.stats["peak"] <= 3
    assert len(fake.stats["starts"]) == 12


def test_one_worker_runs_one_probe_at_a_time():
    table = {f"h{i}.example": php() for i in range(5)}
    fake = by_host(table, delay=0.01)
    sweep([Target(host, 80) for host in table], 10_000, 1, get=fake)
    assert fake.stats["peak"] == 1


def test_sweep_spaces_the_start_of_probes_by_the_rate_whatever_the_workers():
    table = {f"h{i}.example": php() for i in range(6)}
    started = time.monotonic()
    sweep([Target(host, 80) for host in table], 20, 4, get=by_host(table))  # a start per 50 ms
    # Six starts are five gaps apart, so the sweep cannot end sooner. A stalled thread only makes
    # it longer, which is why this is a lower bound. The fake-clock tests below pin the arithmetic.
    assert time.monotonic() - started >= 0.2


def test_the_pacer_sleeps_for_the_gap_between_starts(monkeypatch):
    clock, slept = [100.0], []

    def sleep(seconds):
        slept.append(seconds)
        clock[0] += seconds

    monkeypatch.setattr(network, "_now", lambda: clock[0])
    monkeypatch.setattr(network, "_sleep", sleep)
    pacer = network._Pacer(4)  # a start every 0.25 s
    for _ in range(4):
        pacer.wait()
    assert slept == [0.25, 0.25, 0.25]


def test_time_that_passes_on_its_own_counts_toward_the_gap(monkeypatch):
    clock, slept = [100.0], []
    monkeypatch.setattr(network, "_now", lambda: clock[0])
    monkeypatch.setattr(network, "_sleep", slept.append)
    pacer = network._Pacer(4)
    pacer.wait()
    clock[0] += 1.0  # a slow probe has used up the gap
    pacer.wait()
    clock[0] += 0.1
    pacer.wait()
    assert slept == [pytest.approx(0.15)]


@pytest.mark.parametrize("rate", [0, 0.0, -1, float("nan"), float("inf"), None, "5", True])
def test_sweep_refuses_a_rate_that_is_not_a_positive_finite_number(rate):
    fake = recorder()
    with pytest.raises(ValueError):
        sweep([Target("a.example", 80)], rate, 1, get=fake)
    assert fake.calls == []


@pytest.mark.parametrize("workers", [0, -1, 1.5, None, "2", True])
def test_sweep_refuses_a_worker_count_that_is_not_a_whole_number_of_at_least_one(workers):
    fake = recorder()
    with pytest.raises(ValueError):
        sweep([Target("a.example", 80)], 1, workers, get=fake)
    assert fake.calls == []


def test_a_probe_that_raises_stops_the_ones_not_yet_started():
    calls = []

    def buggy(url, sent, timeout, verify=True, read_body=True):
        calls.append(url)
        raise RuntimeError("bug")

    with pytest.raises(RuntimeError):
        sweep([Target(f"h{i}.example", 80) for i in range(50)], 10, 1, get=buggy)
    assert len(calls) < 25  # to the end it would be 50 calls and five seconds


def test_sweep_passes_its_timeout_and_get_to_every_probe():
    fake = recorder()
    sweep([Target("a.example", 80), Target("b.example", 443)], 1000, 2, timeout=7.5, get=fake)
    assert sorted(call[2] for call in fake.calls) == [7.5, 7.5]
    assert {call[3] for call in fake.calls} == {False}


def test_sweep_over_real_servers_asks_each_one_once(new_stub, offline):
    versioned, clean, hidden, front = new_stub(), new_stub(), new_stub(), new_stub()
    versioned.set_headers({"X-Powered-By": "PHP/8.3.35"})
    hidden.set_headers({"Set-Cookie": "PHPSESSID=abc"})
    elsewhere = new_stub()
    front.status = 302
    front.set_headers({"Location": f"http://127.0.0.1:{elsewhere.port}/x.php"})
    servers = [versioned, clean, hidden, front]
    found = sweep([Target(s.host, s.port) for s in servers], 100, 2)
    assert [ev.location for ev in found] == [
        f"http://127.0.0.1:{s.port}/" for s in (versioned, hidden, front)]
    assert [ev.signals["php_present"] for ev in found] == ["true", "true", "true"]
    assert [len(s.seen) for s in servers] == [1, 1, 1, 1]
    assert elsewhere.seen == []
    assert offline == []


# --- hostile input ---

def test_headers_made_of_anything_are_read_without_error():
    rng = random.Random(99)
    pieces = ["php", "PHP", "/", "8", "3", ".", "35", "-", "+", "~", " ", "x", ";", ",", "(", ")",
              "\u0130", "\u212a", "\x00", "\n", "RC1", "ubuntu", "phpsessid", "=", "9" * 30]
    for _ in range(4000):
        value = "".join(rng.choice(pieces) for _ in range(rng.randint(0, 14)))
        headers = {rng.choice(["x-powered-by", "server", "set-cookie", "location"]): value}
        version = fingerprint_version(headers)
        assert version is None or (version.isprintable() and " " not in version)
        ev = probe(Target("web1.example.com", 443), 1.0, get=recorder(headers=headers))
        assert ev.signals.get("php_present") in ("true", "false")
        assert ev.detected_version == version


def test_a_banner_cannot_put_anything_but_a_version_in_the_evidence():
    hostile = "PHP/8.3.35<script>alert(1)</script>\r\nX-Evil: 1"
    ev = probe(Target("web1.example.com", 443), 1.0,
               get=recorder(headers={"x-powered-by": hostile}))
    assert ev.detected_version == "8.3.35"
    everything = ev.detected_version + ev.location + ev.note + str(ev.signals)
    assert "<" not in everything and "script" not in everything and "Evil" not in everything


# --- the source ---

def test_the_module_is_standard_library_only_and_sends_nothing_but_a_get():
    source = pathlib.Path(network.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source, feature_version=(3, 9))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])
    assert imported <= {"concurrent", "ipaddress", "itertools", "math", "php_radar", "string",
                        "threading", "time", "typing", "urllib"}
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    names |= {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    assert not names & {"environ", "getenv", "print", "logging", "urlopen", "build_opener",
                        "socket", "subprocess", "system", "post", "request", "HTTPConnection",
                        "HTTPSConnection"}
    strings = {n.value for n in ast.walk(tree) if isinstance(n, ast.Constant)
               and isinstance(n.value, str)}
    assert not {s for s in strings if s.upper() in ("POST", "PUT", "DELETE", "PATCH", "OPTIONS")}
