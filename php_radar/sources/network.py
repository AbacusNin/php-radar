"""Probes a live host over the network and reads what its web server says about PHP.

probe sends one GET for the root path and nothing else: no body, no query, no credential, and
nothing built to trigger PHP2Shell. It reads the headers of the answer and, on an https port, the
certificate. sweep runs it over the targets that guard returned.

The scope is the authorization boundary, so nothing here leaves it. A redirect is never followed.
http.get returns the 3xx like any other answer, its headers count as evidence, and its Location
is never requested or looked up. The certificate is not verified, because a scanner reads what a
host presents and believes none of it. For the same reason a name in a certificate is recorded
and never used to identify the asset. A certificate can claim any name. A vulnerable box that
claimed a patched host's name would merge into that host's asset, and the patched read would
clear it.

Treat a banner as a lead. It can be hidden, rewritten, or sent by a proxy in front of the real
server.
"""
import ipaddress
import itertools
import math
import string
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Iterator, Optional
from urllib.parse import urlsplit

from php_radar import http
from php_radar.model import Evidence, Sapi, Source
from php_radar.scope import Target
from php_radar.versions import PhpVersion

# Seconds, for each wait on the socket: the connect, the handshake, and each read.
_TIMEOUT = 5.0

# A scope entry has no scheme, so the port decides. A TLS service on any other port is probed in
# plain HTTP, gets no usable answer, and shows up as a row that says so.
_TLS_PORTS = frozenset({443, 8443})

# The request names the tool, so an operator reading their logs can tell the scan from an attack.
# It carries no cookie and no credential.
_REQUEST = {"User-Agent": "php-radar", "Accept": "*/*"}

# An answer with one of these statuses is the gate's own: a login, a firewall, or a rate limit. A
# vulnerable application can sit behind any of them, and the answer shows nothing about it.
_GATED = frozenset({401, 403, 429})

_NAME_CHARS = frozenset(string.ascii_letters + string.digits + "-.")
_VERSION_CHARS = frozenset(string.ascii_letters + string.digits + ".+~_-")

# The longest build string taken from a banner. Real ones run to about 45 characters.
_MAX_VERSION = 64

# The most names kept from a certificate, and the longest one. A DNS name is 253 characters at most.
_MAX_NAMES = 32
_MAX_NAME = 253

_OID_CN = bytes.fromhex("550403")
_OID_SAN = bytes.fromhex("551d11")

# The DER string types a name can come in, and how each is encoded.
_STRING_CODECS = {0x0C: "utf-8", 0x13: "utf-8", 0x14: "utf-8", 0x16: "utf-8", 0x1E: "utf-16-be"}

# Lower-casing only A to Z keeps every index of the result on the same character of the original.
# str.lower() turns one capital I with a dot above (U+0130) into two characters.
_ASCII_LOWER = {ord(c): ord(c.lower()) for c in string.ascii_uppercase}

# Pacing goes through these two names so that a test never sleeps.
_sleep = time.sleep
_now = time.monotonic


def _fold(text: str) -> str:
    return text.translate(_ASCII_LOWER)


def _lowered(headers: dict) -> dict[str, str]:
    return {_fold(str(name)): str(value) for name, value in headers.items()}


def _versions(value: str) -> Iterator[tuple[PhpVersion, str]]:
    """Each PHP version that follows a PHP/ token in one header value."""
    folded = _fold(value)
    at = folded.find("php/")
    while at != -1:
        begin = at + len("php/")
        end = begin
        while end < len(value) and value[end] in _VERSION_CHARS:
            end += 1
        text = value[begin:end]
        # CakePHP/4.2.1 names another product, so PHP has to start a word. A build longer than any
        # real one is hostile, and cutting it down would hand the grader a build no server sent.
        if (at == 0 or not value[at - 1].isalnum()) and len(text) <= _MAX_VERSION:
            version = PhpVersion.parse(text)
            if version is not None:
                yield version, text
        at = folded.find("php/", begin)


def fingerprint_version(headers: dict) -> Optional[str]:
    """The PHP version in the Server or X-Powered-By header, or None when neither gives one.

    The version is the text after PHP/. An Apache or nginx version in Server is ignored. A distro
    revision such as -1ubuntu2.14 stays on it, because the grader reads one as a packaged build
    and does not grade it on the upstream number. Header names may be in any case. When two
    banners disagree the lower version is returned. Each is only a claim, and the lower one could
    be exposed.
    """
    found = []
    for name, value in _lowered(headers).items():
        if name in ("server", "x-powered-by"):
            found.extend(_versions(value))
    return min(found, key=lambda pair: pair[0])[1] if found else None


def _is_script(location: str) -> bool:
    """True when a Location points at a .php file. Only the path counts, so php.net does not."""
    try:
        path = urlsplit(location).path
    except ValueError:
        return False  # a Location that does not parse names no script
    return ".php" in _fold(path)


def _names_php(headers: dict[str, str]) -> bool:
    """True when the answer shows PHP in a header, whether or not it gives a version."""
    return ("php" in _fold(headers.get("x-powered-by", ""))
            or "php" in _fold(headers.get("server", ""))
            or "phpsessid" in _fold(headers.get("set-cookie", ""))
            or "php" in _fold(headers.get("content-type", ""))
            or _is_script(headers.get("location", "")))


def _says_nothing(status: int) -> str:
    """Why an answer with this status and no sign of PHP tells nothing about the site, or ""."""
    if status >= 500:
        return "a server error"  # a gateway, or an application that did not run
    return "access blocked or gated" if status in _GATED else ""


def _url(target: Target) -> Optional[str]:
    """The URL to request for target, or None when target is not a plain host and port."""
    host, port = target.host, target.port
    # The host goes straight into a URL, and anything past name characters could point the request
    # at a host the scope never named: user@other, a/b, h:80.
    if not (isinstance(host, str) and 0 < len(host) <= 253 and _NAME_CHARS.issuperset(host)
            and type(port) is int and 0 < port < 65536):
        return None
    return f"{'https' if port in _TLS_PORTS else 'http'}://{host}:{port}/"


def _identity(host: str) -> dict[str, str]:
    # The scope file tells a name from an address by the last label. The last label of a name
    # starts with a letter. The last label of every spelling the OS resolver reads as an address
    # (2130706433, 0x7f.1, 127.1) starts with a digit. An address goes in ip, because the model
    # merges on hostname and a literal there would join assets that it must keep apart.
    last = host.rstrip(".").rpartition(".")[2]
    return {"hostname": host} if last[:1].isalpha() else {"ip": host}


def _why(exc: OSError) -> str:
    # A TransportError is worded to be shown. Any other error names its class, because its own
    # text alone says too little. A hostile server can put text in the message, so it is cut.
    text = str(exc) if isinstance(exc, http.TransportError) else f"{type(exc).__name__}: {exc}"
    return text[:200]


def _elements(data: bytes, pos: int, end: int) -> Iterator[tuple[int, int, int]]:
    """The (tag, start, end) of each DER element in data[pos:end], where start and end bound the
    content of the element.

    Anything that is not well-formed DER ends the walk: a length that runs past end, an
    indefinite length, or a tag number past 30 (X.509 names use none).
    """
    while pos + 2 <= end:
        tag, size = data[pos], data[pos + 1]
        pos += 2
        if tag & 0x1F == 0x1F:
            return
        if size >= 0x80:
            count = size & 0x7F
            if not 0 < count <= 3:
                return
            size = int.from_bytes(data[pos:pos + count], "big")
            pos += count
        if pos + size > end:
            return
        yield tag, pos, pos + size
        pos += size


def _is_oid(data: bytes, element: tuple[int, int, int], oid: bytes) -> bool:
    return element[0] == 0x06 and data[element[1]:element[2]] == oid


def _text(data: bytes, tag: int, start: int, end: int) -> str:
    """The text of a DER string, or "" when it is no text, not printable, or longer than a name."""
    codec = _STRING_CODECS.get(tag)
    if codec is None:
        return ""
    text = data[start:end].decode(codec, "replace")
    return text if text.isprintable() and len(text) <= _MAX_NAME else ""


def _common_names(der: bytes, subject: tuple[int, int, int]) -> Iterator[str]:
    for _, rdn, rdn_end in _elements(der, subject[1], subject[2]):
        for _, start, end in _elements(der, rdn, rdn_end):
            pair = list(_elements(der, start, end))
            if len(pair) == 2 and _is_oid(der, pair[0], _OID_CN):
                text = _text(der, *pair[1])
                if text:
                    yield text


def _general_names(der: bytes, octets: tuple[int, int, int]) -> Iterator[str]:
    for tag, start, end in _elements(der, octets[1], octets[2]):
        if tag != 0x30:
            continue
        for kind, pos, stop in _elements(der, start, end):
            raw = der[pos:stop]
            if kind == 0x82 and raw.isascii() and 0 < len(raw) <= _MAX_NAME:
                text = raw.decode("ascii")
                if text.isprintable():
                    yield text
            elif kind == 0x87 and len(raw) in (4, 16):
                yield str(ipaddress.ip_address(raw))


def _alt_names(der: bytes, fields: list[tuple[int, int, int]]) -> Iterator[str]:
    for tag, start, end in fields:
        if tag != 0xA3:  # [3], the extensions
            continue
        for _, ext_start, ext_end in _elements(der, start, end):
            for _, pos, stop in _elements(der, ext_start, ext_end):
                parts = list(_elements(der, pos, stop))
                # The extension is its OID, an optional critical flag, and an OCTET STRING.
                if len(parts) >= 2 and _is_oid(der, parts[0], _OID_SAN) and parts[-1][0] == 0x04:
                    yield from _general_names(der, parts[-1])


def _cert_signals(der: Optional[bytes]) -> dict[str, str]:
    """The names an X.509 certificate gives itself, as signals.

    cert_cn lists the common names in the subject. cert_san lists the DNS names and addresses in
    the subject alternative names. Each list is comma separated and cut at _MAX_NAMES. A name that
    is not printable, or is longer than any name, is left out. The DER comes from the host being
    probed, so every length is checked against the bytes that remain, and anything unreadable
    ends the walk with fewer names. Nothing is verified, and the names are only the host's claims.
    """
    if not der:
        return {}
    outer = next(_elements(der, 0, len(der)), None)
    if outer is None or outer[0] != 0x30:
        return {}
    # The first element inside is the part of the certificate that is signed.
    tbs = next(_elements(der, outer[1], outer[2]), None)
    if tbs is None or tbs[0] != 0x30:
        return {}
    fields = list(_elements(der, tbs[1], tbs[2]))
    # A version 1 certificate has no [0] version. After it come the serial number, the signature
    # algorithm, the issuer, the validity, and then the subject.
    first = 1 if fields and fields[0][0] == 0xA0 else 0
    if len(fields) <= first + 4 or fields[first + 4][0] != 0x30:
        return {}
    found = {
        "cert_cn": list(itertools.islice(_common_names(der, fields[first + 4]), _MAX_NAMES)),
        "cert_san": list(itertools.islice(_alt_names(der, fields[first + 5:]), _MAX_NAMES)),
    }
    return {key: ", ".join(names) for key, names in found.items() if names}


def probe(target: Target, timeout: float, get: Callable[..., http.Response] = http.get) -> Evidence:
    """One Evidence for what the server at target shows about PHP.

    The request is a GET of / with no body and no credential, made without checking the
    certificate. Only the headers of the answer are read. A redirect is never followed. The
    location of the evidence is the URL that was requested. Written host:port it would read as
    name:value to the redactor, and a host called token or keycloak would lose its port.

    detected_version is the PHP version in the Server or X-Powered-By header, or None.

    The target is recorded as hostname when it is a name and as ip when it is an address. Only
    the hostname lets the asset merge with a host or cloud read of the same machine.

    php_present is "true" when the answer shows PHP: a version, PHP in X-Powered-By or Server, a
    PHPSESSID cookie, a PHP content type (a server sends one when it serves a script's source),
    or a Location that points at a .php file. It is "false" when the host answered and shows
    none. It is absent when the answer tells nothing about the site: a server error, or a 401,
    403 or 429, that shows no sign of PHP. Those keep a note with the reason.

    cert_cn and cert_san hold the names in the certificate of an https server. They are recorded
    and identify nothing.

    A host that cannot be reached, or that answers with something other than HTTP, gets a note
    with the reason, and probe does not raise for it. An unusable timeout raises ValueError, and
    a target that is not a plain host and port is refused. Nothing is sent in either case.
    """
    url = _url(target)
    if url is None:
        return Evidence(Source.NETWORK, f"{target.host}:{target.port}", None, Sapi.UNKNOWN, {},
                        "not probed: the target is not a host name or IPv4 address with a port")
    signals = _identity(target.host)
    try:
        answer = get(url, dict(_REQUEST), timeout, verify=False, read_body=False)
    except OSError as exc:
        return Evidence(Source.NETWORK, url, None, Sapi.UNKNOWN, signals,
                        "no answer: " + _why(exc))
    headers = _lowered(answer.headers)
    version = fingerprint_version(headers)
    note = ""
    if version is not None or _names_php(headers):
        signals["php_present"] = "true"
    else:
        reason = _says_nothing(answer.status)
        if reason:
            # Silence is no clean bill, so the host stays in the findings with the reason.
            note = f"HTTP {answer.status}, {reason}: could not determine what runs the site"
        else:
            signals["php_present"] = "false"
    signals.update(_cert_signals(answer.cert))
    return Evidence(Source.NETWORK, url, version, Sapi.UNKNOWN, signals, note)


class _Pacer:
    """Spaces the start of probes at least 1/rate seconds apart, across every thread."""

    def __init__(self, rate: float) -> None:
        self._gap = 1.0 / rate
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self) -> None:
        # Each caller reserves a slot under the lock and sleeps outside it, so a long wait for one
        # slot does not hold up the reservation of the next.
        with self._lock:
            now = _now()
            start = max(now, self._next)
            self._next = start + self._gap
        if start > now:
            _sleep(start - now)


def sweep(targets: list[Target], rate: float, workers: int, *, timeout: float = _TIMEOUT,
          get: Callable[..., http.Response] = http.get) -> list[Evidence]:
    """The evidence for each target that shows PHP or could not be read, in the order of targets.

    targets is the list that guard returned. Each is probed once and none is added. A host that
    answered and shows no sign of PHP leaves no evidence, so a clean perimeter gives an empty
    list. A host that gave no answer keeps its row. So does one that answered with a server
    error, or a 401, 403 or 429, and nothing else. The reason is in note. Silence is not a clean
    bill.

    rate is probes started per second across all workers. workers is how many can be waiting on a
    host at once. rate must be a positive finite number and workers a whole number of at least 1,
    or ValueError says so before anything is sent. timeout limits each wait on the socket, and
    http.get ends the read of an answer after four of them, so a host that drips its answer in
    cannot hold a worker. Nothing caps a trickled TLS handshake as a whole, and a name that is
    slow to resolve is not capped at all. An error that is no failure to reach a host propagates
    and drops the probes that have not started.
    """
    if isinstance(rate, bool) or not isinstance(rate, (int, float)) or not 0 < rate < math.inf:
        raise ValueError("rate must be a positive number of probes per second")
    if isinstance(workers, bool) or not isinstance(workers, int) or workers < 1:
        raise ValueError("workers must be a whole number, 1 or more")
    pacer = _Pacer(rate)

    def one(target: Target) -> Evidence:
        pacer.wait()
        return probe(target, timeout, get)

    # An error or an interrupt leaves map, and map cancels the probes that have not started. The
    # ones running end within their timeouts.
    with ThreadPoolExecutor(max_workers=workers) as pool:
        found = list(pool.map(one, targets))
    return [ev for ev in found if ev.signals.get("php_present") != "false"]
