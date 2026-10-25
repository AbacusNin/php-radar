import ipaddress
import socket

import pytest

from php_radar.scope import Scope, ScopeError, Target, guard, parse_scope

# The fixture below hands write_scope a fresh directory for each test.
_where = {}


@pytest.fixture(autouse=True)
def _scope_dir(tmp_path_factory):
    # A neutral name on purpose. tmp_path is named after the test, error messages quote the path,
    # and a match= word found in both would pass without checking anything.
    _where["dir"] = tmp_path_factory.mktemp("scope")


def write_raw(data, name="scope.txt"):
    path = _where["dir"] / name
    path.write_bytes(data)
    return str(path)


def write_scope(text, name="scope.txt"):
    # Bytes, so a "\r\n" or a byte order mark reaches the parser as given, on Windows too.
    return write_raw(text.encode("utf-8"), name)


def targets(text):
    return list(parse_scope(write_scope(text)).targets())


def limit_expansion(monkeypatch, most):
    """Fail the test the moment more than `most` addresses are pulled out of any range.

    Without it, a guard that expands a /0 before checking the cap would hang the suite and
    exhaust memory instead of failing.
    """
    pulled = []
    real = ipaddress.IPv4Network.hosts

    def counting(self):
        for addr in real(self):
            assert len(pulled) < most, "expanded far past what the cap allows"
            pulled.append(addr)
            yield addr

    monkeypatch.setattr(ipaddress.IPv4Network, "hosts", counting)
    return pulled


def test_expands_cidr_to_hosts():
    s = parse_scope(write_scope("10.0.0.0/30\n"))
    assert {t.host for t in s.targets()} >= {"10.0.0.1", "10.0.0.2"}

def test_public_range_without_override_refused():
    # A public range is refused unless allow_public is set.
    s = parse_scope(write_scope("8.8.8.0/24\n"))
    with pytest.raises(ScopeError):
        guard(s, allow_public=False, max_hosts=100000)

def test_public_range_allowed_with_override():
    s = parse_scope(write_scope("8.8.8.8\n"))
    assert Target("8.8.8.8", 443) in guard(s, allow_public=True, max_hosts=100)

def test_breadth_cap_enforced():
    s = parse_scope(write_scope("10.0.0.0/16\n"))
    with pytest.raises(ScopeError):
        guard(s, allow_public=False, max_hosts=256)


# --- expansion ---

def test_a_range_expands_to_its_usable_hosts_only():
    assert {t.host for t in targets("10.0.0.0/30\n")} == {"10.0.0.1", "10.0.0.2"}


def test_a_bare_address_and_a_slash_32_are_one_host_and_a_slash_31_is_two():
    assert {t.host for t in targets("10.0.0.7\n")} == {"10.0.0.7"}
    assert {t.host for t in targets("10.0.0.7/32\n")} == {"10.0.0.7"}
    assert {t.host for t in targets("10.0.0.6/31\n")} == {"10.0.0.6", "10.0.0.7"}


def test_a_line_with_no_port_gets_both_web_ports():
    assert targets("10.0.0.5\n") == [Target("10.0.0.5", 80), Target("10.0.0.5", 443)]


def test_an_explicit_port_replaces_the_defaults():
    assert targets("10.0.0.5:8443\n") == [Target("10.0.0.5", 8443)]
    assert targets("intranet.example.com:8080\n") == [Target("intranet.example.com", 8080)]


def test_a_range_takes_its_port_after_the_prefix():
    assert targets("10.0.0.0/30:8080\n") == [Target("10.0.0.1", 8080), Target("10.0.0.2", 8080)]


@pytest.mark.parametrize("port", [1, 80, 443, 8080, 65535])
def test_ports_at_both_ends_of_the_valid_range_are_accepted(port):
    assert targets(f"10.0.0.5:{port}\n") == [Target("10.0.0.5", port)]


def test_a_hostname_passes_through_as_written():
    assert targets("Intranet.Example.COM:8443\n") == [Target("Intranet.Example.COM", 8443)]
    assert targets("web1\n") == [Target("web1", 80), Target("web1", 443)]
    assert targets("example.com.\n") == [Target("example.com.", 80), Target("example.com.", 443)]


@pytest.mark.parametrize("name", [
    "web-01.corp.example.com",
    "1web.example.com",
    "123.example.com",
    "127.0.0.1.nip.io",
    "xn--mnchen-3ya.example.com",
    "a" * 63 + ".example.com",
    ".".join(["a" * 63] * 3 + ["b" * 61]),  # 253 characters, the longest legal name
])
def test_ordinary_hostnames_are_accepted(name):
    assert [t.host for t in targets(name + "\n")] == [name, name]


def test_no_name_is_ever_resolved(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("scope code tried to resolve a name")

    for fn in ("getaddrinfo", "gethostbyname", "gethostbyname_ex"):
        monkeypatch.setattr(socket, fn, boom)
    s = parse_scope(write_scope("web.example.com\n10.0.0.0/30\n"))
    assert len(list(s.targets())) == 6
    assert len(guard(s, allow_public=True, max_hosts=100)) == 6


# --- file shape ---

def test_comments_blank_lines_and_padding_are_ignored():
    text = "# the perimeter\n\n   \n10.0.0.5   \n\t10.0.0.6:8080\t# prod db\n  # indented comment\n"
    assert targets(text) == [
        Target("10.0.0.5", 80), Target("10.0.0.5", 443), Target("10.0.0.6", 8080),
    ]


def test_crlf_line_endings_and_a_missing_final_newline_parse():
    assert targets("10.0.0.5\r\n10.0.0.6:8080") == [
        Target("10.0.0.5", 80), Target("10.0.0.5", 443), Target("10.0.0.6", 8080),
    ]


def test_a_utf8_byte_order_mark_is_skipped():
    # Windows editors add one, and it would otherwise glue itself onto the first address.
    assert targets(chr(0xFEFF) + "10.0.0.5:8080\n") == [Target("10.0.0.5", 8080)]


def test_a_target_listed_twice_comes_out_once_in_first_seen_order():
    got = targets("10.0.0.0/30\n10.0.0.2:80\n10.0.0.9:80\n10.0.0.1\n")
    assert got == [
        Target("10.0.0.1", 80), Target("10.0.0.1", 443),
        Target("10.0.0.2", 80), Target("10.0.0.2", 443),
        Target("10.0.0.9", 80),
    ]


def test_targets_can_be_walked_more_than_once():
    s = parse_scope(write_scope("10.0.0.0/30\nweb1\n"))
    first = list(s.targets())
    assert len(first) == 6
    assert list(s.targets()) == first


def test_the_scope_remembers_the_file_it_came_from():
    path = write_scope("10.0.0.5\n")
    assert parse_scope(path).source == path


# --- a malformed file is refused whole ---

@pytest.mark.parametrize("line", [
    "10.0.0.0/33",
    "10.0.0.0/",
    "/24",
    "10.0.0.0/24/8",
    "10.0.0.1/24.5",
    "10.0.0.256",
    "10.0.0",
    "10.0.0.1.5",
])
def test_a_malformed_address_or_range_is_refused(line):
    with pytest.raises(ScopeError):
        parse_scope(write_scope(line + "\n"))


def test_a_range_with_host_bits_set_is_refused_and_not_widened():
    # Widening 10.0.0.5/24 to 10.0.0.0/24 would probe hosts nobody listed.
    with pytest.raises(ScopeError, match="host bits"):
        parse_scope(write_scope("10.0.0.5/24\n"))


def test_a_prefix_out_of_range_says_so():
    with pytest.raises(ScopeError, match="netmask"):
        parse_scope(write_scope("10.0.0.0/33\n"))


@pytest.mark.parametrize("line", [
    "2130706433",  # 127.0.0.1 as one 32-bit number
    "134744072",  # 8.8.8.8, a public address, the same way
    "0x7f000001",
    "0x7f.1",
    "0x7f.0x0.0x0.0x1",
    "0177.0.0.1",  # octal octets
    "010.0.0.1",
    "127.1",
    "8.8.8",
    "8.8.8.8.",
    "1.2.3.4.5",
])
def test_the_resolver_spellings_of_an_address_are_refused(line):
    # ipaddress rejects all of these while the OS resolver reads them as addresses. A parser that
    # let them through as hostnames would skip the public check for a name that dials 8.8.8.8.
    with pytest.raises(ScopeError):
        parse_scope(write_scope(line + "\n"))


@pytest.mark.parametrize("line", [
    "::1",
    "2001:db8::1",
    "2001:db8::/32",
    "[::1]:80",
    "[2001:db8::1]:443",
    "fe80::1%eth0",
    "::ffff:8.8.8.8",
    "10.0.0.5:80:90",
])
def test_ipv6_and_stray_colons_are_refused_with_a_clear_message(line):
    with pytest.raises(ScopeError, match="IPv6 is not supported"):
        parse_scope(write_scope(line + "\n"))


@pytest.mark.parametrize("port", [
    "0", "65536", "99999", "123456", "-1", "+80", "80.5", "http", "", "0080",
    "9" * 5000,  # int() refuses a string this long on 3.11 and later
    chr(0xFF18) + chr(0xFF10),  # fullwidth 80, which int() would take
    chr(0x0668) + chr(0x0660),  # Arabic-Indic 80, which int() would take
])
def test_an_invalid_port_is_refused(port):
    with pytest.raises(ScopeError, match="is not a port"):
        parse_scope(write_scope(f"10.0.0.5:{port}\n"))
    with pytest.raises(ScopeError, match="is not a port"):
        parse_scope(write_scope(f"web1:{port}\n"))


@pytest.mark.parametrize("line", [
    "10.0.0.1 10.0.0.2",
    "web1 web2",
    "web 1",
    "10.0.0.1\x0b10.0.0.2",  # a vertical tab is not a line break in an editor
])
def test_two_entries_on_one_line_are_refused_and_not_cut_to_the_first(line):
    with pytest.raises(ScopeError, match="one entry per line"):
        parse_scope(write_scope(line + "\n"))


@pytest.mark.parametrize("name", [
    "-web.example.com",
    "web-.example.com",
    "web..example.com",
    ".example.com",
    "web_1.example.com",
    "*.example.com",
    "web.example.com/path",
    "web.example.com\\share",
    "http://web.example.com",
    "user@web.example.com",
    "web.example.com?x=1",
    "web%20.example.com",
    "10.0.0.1,10.0.0.2",
    "10.0.0.1;10.0.0.2",
    "web.1",  # a final label that starts with a digit is how an address is spelled
    "web.example.com..",
    "m" + chr(0xFC) + "nchen.example.com",  # non-ASCII, so punycode only
    "a" * 64 + ".example.com",  # label over 63
    ".".join(["a" * 63] * 3 + ["b" * 62]),  # name over 253
    "-",
    "...",
])
def test_a_string_that_is_not_a_hostname_is_refused(name):
    with pytest.raises(ScopeError):
        parse_scope(write_scope(name + "\n"))


def test_one_bad_line_refuses_the_whole_file_and_says_where():
    path = write_scope("10.0.0.5\n# note\n10.0.0.999\n10.0.0.6\n")
    with pytest.raises(ScopeError, match=r"scope\.txt line 3"):
        parse_scope(path)


@pytest.mark.parametrize("text", ["", "\n\n", "# nothing here\n   \n"])
def test_a_file_with_no_entries_is_refused(text):
    # An empty scan would read as a clean result, so it has to be an error.
    with pytest.raises(ScopeError, match="lists no targets"):
        parse_scope(write_scope(text))


def test_a_missing_file_is_a_scope_error(tmp_path):
    with pytest.raises(ScopeError, match="cannot read"):
        parse_scope(str(tmp_path / "absent.txt"))


def test_a_directory_is_a_scope_error(tmp_path):
    with pytest.raises(ScopeError, match="cannot read"):
        parse_scope(str(tmp_path))


def test_a_file_that_is_not_utf8_is_a_scope_error():
    # Windows PowerShell writes UTF-16 when it redirects output into a file.
    path = write_raw("10.0.0.5\n".encode("utf-16"))
    with pytest.raises(ScopeError, match="must be UTF-8"):
        parse_scope(path)


# --- guard: the public-range gate ---

@pytest.mark.parametrize("line", [
    "8.8.8.8",
    "8.8.8.8:8443",
    "1.1.1.0/30",
    "172.32.0.1",  # one past the end of 172.16.0.0/12
    "172.15.255.254",  # one before it
    "11.0.0.1",
    "192.169.0.1",
])
def test_public_space_is_refused_without_the_override(line):
    s = parse_scope(write_scope(line + "\n"))
    with pytest.raises(ScopeError, match="a public address"):
        guard(s, allow_public=False, max_hosts=1000)


@pytest.mark.parametrize("line", [
    "10.1.2.3",
    "172.16.5.5",
    "172.31.255.254",
    "192.168.1.1",
    "127.0.0.1",
    "169.254.10.10",
    "100.64.0.1",  # shared address space: ipaddress calls it not private and not global
    "192.0.2.10",
    "198.51.100.10",
    "203.0.113.10",
    "10.0.0.0/24",
    "192.168.0.0/28",
])
def test_private_and_special_purpose_space_needs_no_override(line):
    s = parse_scope(write_scope(line + "\n"))
    assert guard(s, allow_public=False, max_hosts=1000) == list(s.targets())


@pytest.mark.parametrize("text", [
    "10.0.0.0/30\n8.8.8.8\n",
    "8.8.8.8\n10.0.0.0/30\n",
    "10.0.0.5\n# note\n10.0.0.6\n1.1.1.1:8443\n",
])
def test_one_public_line_in_a_private_file_refuses_the_whole_file(text):
    s = parse_scope(write_scope(text))
    with pytest.raises(ScopeError, match="a public address"):
        guard(s, allow_public=False, max_hosts=1000)


def test_the_refusal_names_the_line_and_the_address():
    s = parse_scope(write_scope("10.0.0.5\n\n8.8.4.0/30\n"))
    with pytest.raises(ScopeError, match=r"scope\.txt line 3.*8\.8\.4\.0/30.*8\.8\.4\.1"):
        guard(s, allow_public=False, max_hosts=1000)


def test_a_range_that_is_only_partly_private_is_refused():
    # 192.168.0.0/15 is the private /16 followed by a public one. The first public address comes
    # after 131070 targets, so a guard that judged only the first few addresses would pass it.
    s = parse_scope(write_scope("192.168.0.0/15\n"))
    with pytest.raises(ScopeError, match=r"192\.169\.0\.0, a public address"):
        guard(s, allow_public=False, max_hosts=200000)


def test_the_whole_internet_is_refused_with_or_without_the_override(monkeypatch):
    limit_expansion(monkeypatch, 5000)  # shared by both calls, which pull about 500 each
    s = parse_scope(write_scope("0.0.0.0/0\n"))
    with pytest.raises(ScopeError, match="past the cap"):
        guard(s, allow_public=False, max_hosts=1000)
    with pytest.raises(ScopeError, match="past the cap"):
        guard(s, allow_public=True, max_hosts=1000)


@pytest.mark.parametrize("flag", ["true", "yes", "false", "0", 1, None])
def test_only_a_literal_true_opens_the_public_gate(flag):
    # A flag read from an environment variable or a config file arrives as a string.
    s = parse_scope(write_scope("8.8.8.8\n"))
    with pytest.raises(ScopeError, match="a public address"):
        guard(s, allow_public=flag, max_hosts=100)


def test_the_override_lets_private_and_public_through_together():
    s = parse_scope(write_scope("10.0.0.5:8080\n8.8.8.8\n"))
    assert guard(s, allow_public=True, max_hosts=100) == [
        Target("10.0.0.5", 8080), Target("8.8.8.8", 80), Target("8.8.8.8", 443),
    ]


# --- guard: names ---

def test_a_hostname_needs_the_override_because_a_name_cannot_be_classified_offline():
    s = parse_scope(write_scope("www.example.com\n"))
    with pytest.raises(ScopeError, match="is a hostname"):
        guard(s, allow_public=False, max_hosts=100)
    assert guard(s, allow_public=True, max_hosts=100) == [
        Target("www.example.com", 80), Target("www.example.com", 443),
    ]


def test_a_numeric_looking_name_is_still_just_a_name():
    # 127.0.0.1.nip.io resolves to 127.0.0.1 today and could resolve anywhere tomorrow.
    s = parse_scope(write_scope("127.0.0.1.nip.io\n"))
    with pytest.raises(ScopeError, match="is a hostname"):
        guard(s, allow_public=False, max_hosts=100)


@pytest.mark.parametrize("name", ["localhost", "LOCALHOST", "Localhost.", "localhost:8080"])
def test_localhost_needs_no_override(name):
    s = parse_scope(write_scope(name + "\n"))
    assert guard(s, allow_public=False, max_hosts=100) == list(s.targets())


@pytest.mark.parametrize("name", ["foo.localhost", "localhost.example.com", "notlocalhost", "localhost2"])
def test_only_localhost_itself_is_exempt(name):
    s = parse_scope(write_scope(name + "\n"))
    with pytest.raises(ScopeError, match="is a hostname"):
        guard(s, allow_public=False, max_hosts=100)


# --- guard: the breadth cap ---

def test_the_cap_counts_targets_and_a_scope_exactly_at_the_cap_passes():
    s = parse_scope(write_scope("10.0.0.0/30\n"))  # 2 hosts, 2 ports each
    assert len(guard(s, allow_public=False, max_hosts=4)) == 4
    with pytest.raises(ScopeError, match="past the cap"):
        guard(s, allow_public=False, max_hosts=3)


def test_an_explicit_port_counts_once_per_host():
    s = parse_scope(write_scope("10.0.0.0/30:8080\n"))
    assert len(guard(s, allow_public=False, max_hosts=2)) == 2
    with pytest.raises(ScopeError, match="past the cap"):
        guard(s, allow_public=False, max_hosts=1)


def test_a_duplicate_does_not_count_twice_against_the_cap():
    s = parse_scope(write_scope("10.0.0.0/30\n10.0.0.0/30\n10.0.0.1\n"))
    assert len(guard(s, allow_public=False, max_hosts=4)) == 4


def test_the_cap_holds_with_the_override_too():
    s = parse_scope(write_scope("8.8.8.0/24\n"))
    with pytest.raises(ScopeError, match="past the cap"):
        guard(s, allow_public=True, max_hosts=10)


def test_a_cap_of_zero_refuses_everything():
    s = parse_scope(write_scope("10.0.0.5\n"))
    with pytest.raises(ScopeError, match="past the cap"):
        guard(s, allow_public=False, max_hosts=0)


def test_the_cap_is_enforced_before_the_scope_is_expanded(monkeypatch):
    pulled = limit_expansion(monkeypatch, 1000)
    s = parse_scope(write_scope("10.0.0.0/8\n"))  # 16 million addresses
    with pytest.raises(ScopeError, match="past the cap"):
        guard(s, allow_public=False, max_hosts=100)
    assert len(pulled) <= 100


def test_guard_refuses_a_scope_with_nothing_in_it():
    with pytest.raises(ScopeError, match="lists no targets"):
        guard(Scope("empty.txt", ()), allow_public=True, max_hosts=100)


def test_guard_returns_every_target_in_file_order():
    s = parse_scope(write_scope("10.0.0.9:8080\n10.0.0.0/30:9090\nlocalhost:7070\n"))
    assert guard(s, allow_public=False, max_hosts=10) == [
        Target("10.0.0.9", 8080),
        Target("10.0.0.1", 9090),
        Target("10.0.0.2", 9090),
        Target("localhost", 7070),
    ]
