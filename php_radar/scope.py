"""Scope file parsing, and the guardrails the network scanner passes before it sends a packet.

The scope file is the authorization boundary. Each line is an IPv4 address, an IPv4 range in
CIDR form, or a hostname, with an optional :port. IPv6 literals are refused for now. Parsing is
offline: nothing here resolves a name or opens a socket.
"""
import ipaddress
import string
from dataclasses import dataclass
from typing import Iterator, Union

# A line with no port is probed on the two usual web ports.
DEFAULT_PORTS = (80, 443)

_LABEL_CHARS = frozenset(string.ascii_letters + string.digits + "-")

_Spec = Union[ipaddress.IPv4Network, str]


class ScopeError(Exception):
    """The scope file cannot be read or parsed, or guard refused what it names."""


@dataclass(frozen=True)
class Target:
    host: str
    port: int


@dataclass(frozen=True)
class _Entry:
    line: int
    text: str  # the line as written, minus the comment and the padding
    spec: _Spec  # a bare address is a /32; a name stays a string
    ports: tuple[int, ...]

    def hosts(self) -> Iterator[tuple[str, bool]]:
        """Each host the line names, with whether the guard counts it as public."""
        if isinstance(self.spec, str):
            # Telling a name from public space takes a DNS lookup, and a lookup here is a side
            # effect whose answer can change before the probe. So a name counts as public and
            # needs the override. The one exception is localhost, which resolvers pin to loopback.
            yield self.spec, self.spec.lower().rstrip(".") != "localhost"
            return
        # Judge each address on its own. A range's ends say nothing about its middle, and
        # 0.0.0.0/1 starts and ends in private space. The host string that gets probed is
        # built from the same address object that gets classified.
        for addr in self.spec.hosts():
            yield str(addr), addr.is_global


@dataclass(frozen=True)
class Scope:
    source: str
    entries: tuple[_Entry, ...]

    def targets(self) -> Iterator[Target]:
        for _, target, _ in self._walk():
            yield target

    def _walk(self) -> Iterator[tuple[_Entry, Target, bool]]:
        # Lazy, so guard can stop at the cap instead of expanding a /8. A target listed twice
        # (overlapping ranges, a range and one of its members) comes out once. Probing it twice
        # would report the same box twice, because the asset inventory never merges on an ip.
        seen: set[Target] = set()
        for entry in self.entries:
            for host, public in entry.hosts():
                for port in entry.ports:
                    target = Target(host, port)
                    if target not in seen:
                        seen.add(target)
                        yield entry, target, public


def _port(text: str) -> int:
    # ASCII digits only, because int() also takes fullwidth and Arabic-Indic digits. A leading
    # zero is out, which also rules out 0, and the length check keeps a huge string away from int().
    if text.isascii() and text.isdigit() and text[0] != "0" and len(text) <= 5:
        port = int(text)
        if port <= 65535:
            return port
    raise ValueError(f"{text!r} is not a port from 1 to 65535")


def _label_ok(label: str) -> bool:
    return (0 < len(label) <= 63 and label[0] != "-" and label[-1] != "-"
            and _LABEL_CHARS.issuperset(label))


def _hostname(text: str) -> str:
    name = text[:-1] if text.endswith(".") else text  # one trailing dot marks a rooted name
    labels = name.split(".")
    # The last label has to start with a letter. The OS resolver reads 2130706433, 0x7f.1 and
    # 127.1 as addresses while ipaddress rejects them, and the last label of every such spelling
    # starts with a digit. Without this rule they would pass as names and skip the public check.
    if not (len(name) <= 253 and all(map(_label_ok, labels)) and labels[-1][0].isalpha()):
        raise ValueError(f"{text!r} is not an IPv4 address, an IPv4 range, or a hostname")
    return text


def _spec(text: str) -> _Spec:
    try:
        # Strict, so 10.0.0.5/24 is an error. Widening it to 10.0.0.0/24 would probe hosts
        # nobody listed.
        return ipaddress.IPv4Network(text)
    except ValueError:
        if "/" in text:
            raise
    return _hostname(text)


def _parse_entry(text: str) -> tuple[_Spec, tuple[int, ...]]:
    if any(ch.isspace() for ch in text):
        raise ValueError("one entry per line, with no spaces inside it")
    if text.count(":") > 1:
        raise ValueError("too many colons; IPv6 is not supported, so use an IPv4 address "
                         "or a hostname")
    spec, colon, port = text.partition(":")
    return _spec(spec), ((_port(port),) if colon else DEFAULT_PORTS)


def parse_scope(path: str) -> Scope:
    """Read a scope file. An unreadable file or a single bad line raises ScopeError."""
    try:
        # utf-8-sig drops the byte order mark that Windows editors put at the front.
        with open(path, encoding="utf-8-sig") as f:
            lines = f.read().split("\n")
    except UnicodeDecodeError as exc:
        raise ScopeError(f"cannot read scope file {path}: it must be UTF-8 text") from exc
    except OSError as exc:
        raise ScopeError(f"cannot read scope file {path}: {exc.strerror or exc}") from exc
    entries = []
    for number, raw in enumerate(lines, 1):
        text = raw.split("#", 1)[0].strip()
        if not text:
            continue
        try:
            spec, ports = _parse_entry(text)
        except ValueError as exc:
            raise ScopeError(f"{path} line {number}: {exc}") from exc
        entries.append(_Entry(number, text, spec, ports))
    # An empty scan would read as a clean result, so an empty file is an error.
    if not entries:
        raise ScopeError(f"{path} lists no targets")
    return Scope(path, tuple(entries))


def guard(scope: Scope, allow_public: bool, max_hosts: int) -> list[Target]:
    """The targets a scan may probe, or a ScopeError. It fails closed and sends nothing itself.

    Public space needs allow_public. So does every hostname except localhost, because a name
    cannot be classified without DNS. max_hosts caps targets, which are host and port pairs, so
    a host on two ports counts twice. The list comes back only when every target has passed.
    """
    # Only the literal True opens the gate. A flag read from the environment or a config file
    # is a string, and the string "false" is truthy.
    open_gate = allow_public is True
    found: list[Target] = []
    for entry, target, public in scope._walk():
        if public and not open_gate:
            where = f"{scope.source} line {entry.line}: {entry.text!r}"
            if isinstance(entry.spec, str):
                raise ScopeError(f"{where} is a hostname. A name cannot be checked against "
                                 "private address space without a DNS lookup, so it needs the "
                                 "explicit public override")
            raise ScopeError(f"{where} reaches {target.host}, a public address, which needs "
                             "the explicit public override")
        found.append(target)
        if len(found) > max_hosts:
            raise ScopeError(f"scope expands past the cap of {max_hosts} targets (a host counts "
                             "once per port). Narrow the ranges or raise the cap")
    if not found:
        raise ScopeError("scope lists no targets")
    return found
