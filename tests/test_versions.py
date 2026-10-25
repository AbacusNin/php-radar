import pytest

from php_radar.versions import PhpVersion, parse_branch


def test_parse_and_branch():
    v = PhpVersion.parse("8.3.35")
    assert (v.major, v.minor, v.micro) == (8, 3, 35)
    assert v.branch == "8.3"

def test_parse_rejects_junk():
    assert PhpVersion.parse("not-a-version") is None


# Lookalike digits, spelled by code point so this file stays plain ASCII.
FULLWIDTH_8 = chr(0xFF18)
ARABIC_INDIC_3 = chr(0x0663)
SUPERSCRIPT_2 = chr(0x00B2)


def triple(text):
    v = PhpVersion.parse(text)
    return (v.major, v.minor, v.micro)


@pytest.mark.parametrize("text, want", [
    ("7.4.33", (7, 4, 33)),
    ("5.6.40", (5, 6, 40)),
    ("8.10.1", (8, 10, 1)),
    ("  8.3.35\n", (8, 3, 35)),
    ("8.3.35-fpm", (8, 3, 35)),
    ("8.3.35-fpm-alpine", (8, 3, 35)),
    ("8.1.2-1ubuntu2.28", (8, 1, 2)),
    ("8.4.27-1~deb13u1", (8, 4, 27)),
    ("8.3.36-r0", (8, 3, 36)),
    ("8.3.36+dfsg-1", (8, 3, 36)),
    ("8.4.0RC1", (8, 4, 0)),
    ("8.4.0alpha2", (8, 4, 0)),
])
def test_parse_reads_the_leading_version_and_ignores_a_build_suffix(text, want):
    assert triple(text) == want


@pytest.mark.parametrize("text", [
    "",
    "   ",
    "8",
    "8.3",
    "8.3.",
    ".3.35",
    "8..35",
    "8.3-apache",
    "8.3.x",
    "8.3.*",
    "8.3.35.1",
    "php8.3",
    "PHP/8.3.35",
    "v8.3.35",
    ">=8.3.36",
    "^8.3",
    "~8.3.0",
    "8.1.0 - 8.3.9",
    "8.3.35,8.4.1",
    "8.3.35 (cli)",
    "-8.3.35",
    "+8.3.35",
    "8.3.-5",
    FULLWIDTH_8 + ".3.35",
    "8." + ARABIC_INDIC_3 + ".35",  # int() would accept it
    "8.3." + SUPERSCRIPT_2,  # isdigit() accepts it and int() does not
])
def test_parse_rejects_what_is_not_a_full_build(text):
    # A floating tag, a constraint, or a header line has no micro to grade, so it never parses.
    assert PhpVersion.parse(text) is None


def test_parse_survives_absurd_numbers():
    # int() refuses more than 4300 digits on 3.11 and later, and a probed server controls this text.
    assert PhpVersion.parse("8.3." + "9" * 5000) is None
    assert PhpVersion.parse("9" * 5000 + ".3.35") is None
    assert PhpVersion.parse("8." + "9" * 5000 + ".35") is None


def test_ordering_is_numeric_by_major_minor_micro():
    texts = ["8.3.36", "8.10.0", "8.9.9", "7.4.33", "8.3.4"]
    ordered = sorted(PhpVersion.parse(t) for t in texts)
    assert [(v.major, v.minor, v.micro) for v in ordered] == [
        (7, 4, 33), (8, 3, 4), (8, 3, 36), (8, 9, 9), (8, 10, 0),
    ]
    assert PhpVersion.parse("8.3.35") < PhpVersion.parse("8.3.36")
    assert PhpVersion.parse("8.3.36") >= PhpVersion.parse("8.3.36")


def test_equal_versions_are_equal_and_hash_alike():
    a = PhpVersion.parse("8.3.35")
    b = PhpVersion.parse("8.3.35-fpm")
    assert a == b == PhpVersion(8, 3, 35)
    assert len({a, b}) == 1


def test_branch_of_a_two_digit_minor():
    assert PhpVersion.parse("8.10.1").branch == "8.10"


@pytest.mark.parametrize("text, want", [
    ("8.3", (8, 3)),
    ("8.10", (8, 10)),
    (" 7.4 ", (7, 4)),
    ("5.6", (5, 6)),
])
def test_parse_branch(text, want):
    assert parse_branch(text) == want


@pytest.mark.parametrize("text", [
    "", "8", "8.", ".3", "8.3.35", "8.3-fpm", "8.x", "abc", FULLWIDTH_8 + ".3", "8." + "9" * 5000,
])
def test_parse_branch_rejects_anything_but_major_dot_minor(text):
    assert parse_branch(text) is None


@pytest.mark.parametrize("text, suffix", [
    ("8.3.35", ""),
    ("8.3.35-fpm", "-fpm"),
    ("8.1.2-1ubuntu2.28", "-1ubuntu2.28"),
    ("8.4.27-1~deb13u1", "-1~deb13u1"),
    ("8.3.36-r0", "-r0"),
    ("8.4.0RC1", "RC1"),
    ("  8.3.36+dfsg-1\n", "+dfsg-1"),
])
def test_parse_keeps_the_build_suffix(text, suffix):
    assert PhpVersion.parse(text).suffix == suffix


def test_a_version_built_by_hand_has_no_suffix():
    assert PhpVersion(8, 3, 35).suffix == ""


def test_the_suffix_never_affects_equality_hashing_or_ordering():
    plain = PhpVersion.parse("8.3.35")
    variant = PhpVersion.parse("8.3.35-fpm")
    later = PhpVersion.parse("8.3.36-dev")
    assert plain == variant
    assert hash(plain) == hash(variant)
    assert not plain < variant
    assert not variant < plain
    assert variant < later
    assert sorted([later, variant, plain])[-1] is later
