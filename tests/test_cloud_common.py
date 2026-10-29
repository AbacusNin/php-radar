import ast
import pathlib
from collections import abc

import pytest

from php_radar.model import Evidence, Sapi, Source
from php_radar.sources.cloud import _common
from php_radar.sources.cloud._common import (
    _BRANCH, _MAX_DNS, _MAX_MISSES, _MAX_PAGES, _MAX_TAG, _NAME, _PATH, _Stop, _dns, _entries,
    _fits, _gap, _iterable, _number, _repo_gap, _tag_note, _tag_version, _unread, _where)

SOURCE = pathlib.Path(_common.__file__).read_text(encoding="utf-8")

# Characters outside ASCII, by name, so that this file stays plain ASCII.
E_ACUTE = "\N{LATIN SMALL LETTER E WITH ACUTE}"
DASHES_AND_QUOTES = ("\N{EM DASH}\N{EN DASH}\N{LEFT SINGLE QUOTATION MARK}"
                     "\N{RIGHT SINGLE QUOTATION MARK}\N{LEFT DOUBLE QUOTATION MARK}"
                     "\N{RIGHT DOUBLE QUOTATION MARK}")


# --- the PHP version in an image tag ---

# (tag, official, version it names or None). official is true for a repository whose last path
# part is php, where the official image's tags (8.3.12-fpm) name PHP by starting with the number.
TAGS = [
    # A full version stands, in an official repository or after the word php.
    ("8.3.12-fpm", True, "8.3.12"),
    ("php-8.3.12", False, "8.3.12"),
    ("php8.3.12", False, "8.3.12"),
    ("php_8.3.12", False, "8.3.12"),
    ("PHP-8.3.12-FPM", False, "8.3.12"),
    ("bookworm-php8.3.12", False, "8.3.12"),
    # A branch gives the branch alone.
    ("php8.3", False, "8.3"),
    ("8.3-fpm", True, "8.3"),
    # No version in the tag, or a number that is no PHP version.
    ("latest", True, None),
    ("latest", False, None),
    ("8", True, None),
    ("8", False, None),
    ("1.4.2", True, None),
    ("10.1.2", True, None),
    # Outside an official repository a tag has to say php.
    ("8.3.12-fpm", False, None),
    ("php-fpm", False, None),
    # A full number counts unless what follows it reads as a distro revision or a pre-release.
    # Then the tag gives the branch alone. A variant such as fpm is neither.
    ("8.3.12-1ubuntu2.28", True, "8.3"),
    ("php-8.3.12-r1", False, "8.3"),
    ("8.3.36-rc1", True, "8.3"),
    ("8.3.12-fpm-prod", True, "8.3.12"),
]


@pytest.mark.parametrize("tag,official,version", TAGS, ids=[f"{t}-{o}" for t, o, _ in TAGS])
def test_a_tag_names_a_php_version_or_it_does_not(tag, official, version):
    assert _tag_version(tag, official) == version


# --- a word that is a PHP version ---

@pytest.mark.parametrize("word,number", [
    ("8.3.12", "8.3.12"),
    ("8.3", "8.3"),
    # PHP 5 is the oldest major read and 9 the newest accepted.
    ("5.6.40", "5.6.40"),
    ("9.0", "9.0"),
    ("9.0.1", "9.0.1"),
    ("4.9", None),
    ("10.0.0", None),
    ("2.1.0", None),
    # Anything after the version means the word is not exactly one.
    ("8.3.12-fpm", None),
    ("8.3.12RC1", None),
    ("8.3.12.1", None),
    ("8", None),
    ("latest", None),
    ("", None),
])
def test_a_word_is_a_php_version_only_when_it_is_exactly_one(word, number):
    assert _number(word) == number


# --- a value that fits a character set and a length ---

@pytest.mark.parametrize("value,chars,limit,fits", [
    ("abc", _NAME, 3, True),
    ("abcd", _NAME, 3, False),
    ("", _NAME, 3, False),
    ("a b", _NAME, 9, False),
    ("caf" + E_ACUTE, _NAME, 9, False),
    # A repository name may hold a slash and a tag may not.
    ("a/b", _NAME, 9, False),
    ("a/b", _PATH, 9, True),
    (None, _NAME, 9, False),
    (5, _NAME, 9, False),
])
def test_a_value_fits_when_it_is_a_string_in_the_set_and_within_the_limit(
        value, chars, limit, fits):
    assert _fits(value, chars, limit) is fits


# --- a host name taken from an answer ---

@pytest.mark.parametrize("value,name", [
    ("shop.example.com", "shop.example.com"),
    ("web1", "web1"),
    ("a-b.example.com", "a-b.example.com"),
    ("x" * 253, "x" * 253),
    ("x" * 254, None),
    # A name starts with a letter or a digit.
    (".example.com", None),
    ("-x.example.com", None),
    ("a b", None),
    ("a/b", None),
    ("caf" + E_ACUTE + ".example.com", None),
    ("", None),
    (None, None),
    (5, None),
])
def test_a_host_name_is_a_short_run_of_name_characters_that_does_not_start_with_a_dot(
        value, name):
    assert _dns(value) == name


def test_the_longest_dns_name_is_253_characters():
    assert _MAX_DNS == 253


# --- the lists an SDK answers with ---

class SequenceOnly:
    """A repeated field of a raw protobuf response under the default (upb) backend.

    It has a length and an index and no __iter__, and the backend registers its containers as
    mutable sequences.
    """

    def __init__(self, entries):
        self._entries = list(entries)

    def __len__(self):
        return len(self._entries)

    def __getitem__(self, at):
        return self._entries[at]


abc.MutableSequence.register(SequenceOnly)


@pytest.mark.parametrize("value", [
    [], [1], (1, 2), {1}, {"a": 1}, iter([1]), (n for n in range(3)), range(2),
    SequenceOnly(["us"])])
def test_a_list_an_iterator_or_a_registered_sequence_is_iterable(value):
    assert _iterable(value) is True


@pytest.mark.parametrize("value", ["us", "", b"us", None, 5, 1.5, True, object()])
def test_a_string_and_anything_that_does_not_iterate_is_no_list_of_entries(value):
    assert _iterable(value) is False
    assert _entries(value) is None


def test_the_stand_in_for_a_repeated_field_has_no_iter_and_still_iterates():
    # The fixture itself. Given an __iter__ it would no longer stand for protobuf's container.
    field = SequenceOnly(["us", "europe"])
    assert not hasattr(field, "__iter__")
    assert _iterable(field)
    assert _entries(field) == ["us", "europe"]


def test_entries_are_copied_into_a_list_that_can_be_read_twice():
    spent = iter(["a", "b"])
    got = _entries(spent)
    assert got == ["a", "b"]
    assert list(spent) == []
    assert _entries(got) == got and _entries(got) is not got


# --- a read that cannot go on, and the caps that end one ---

def test_a_stop_is_an_exception_that_carries_the_reason_to_record():
    stop = _Stop("the answer is not understood")
    assert isinstance(stop, Exception)
    assert str(stop) == "the answer is not understood"


def test_a_listing_is_cut_after_200_pages_and_a_registry_after_three_misses_in_a_row():
    assert (_MAX_PAGES, _MAX_MISSES) == (200, 3)


# --- the label of a read ---

@pytest.mark.parametrize("provider,service,scope,label", [
    ("aws", "lambda", "us-east-1", "aws lambda us-east-1"),
    ("gcp", "appengine", "my-project", "gcp appengine my-project"),
    ("azure", "appservice", "00000000-0000-0000-0000-000000000000",
     "azure appservice 00000000-0000-0000-0000-000000000000"),
    # A read with no scope, such as a session with no region, is labeled by service alone.
    ("aws", "lambda", None, "aws lambda"),
    ("aws", "lambda", "", "aws lambda"),
])
def test_a_label_names_the_provider_the_service_and_the_scope_when_there_is_one(
        provider, service, scope, label):
    assert _where(provider, service, scope) == label


# --- the rows that record a read that was skipped ---

@pytest.mark.parametrize("service,where", [
    ("lambda", "aws lambda us-east-1"),
    ("lambda", "aws lambda"),
    ("appengine", "gcp appengine my-project"),
    ("appservice", "azure appservice 00000000-0000-0000-0000-000000000000"),
])
def test_a_gap_is_a_skipped_cloud_row_located_at_its_label(service, where):
    assert _gap(service, where, "boom") == Evidence(
        Source.CLOUD, where, None, Sapi.UNKNOWN,
        {"service": service, "kind": "skipped"}, "not inventoried: boom")


@pytest.mark.parametrize("count,entries", [(1, "entry"), (2, "entries"), (17, "entries")])
def test_unread_entries_are_counted_in_one_gap_that_gives_the_cause(count, entries):
    row = _unread("artifactregistry", "gcp artifactregistry my-project", count, "images",
                  "no usable tag")
    assert row == Evidence(
        Source.CLOUD, "gcp artifactregistry my-project", None, Sapi.UNKNOWN,
        {"service": "artifactregistry", "kind": "skipped"},
        f"not inventoried: {count} {entries} in the list of images could not be read "
        "(no usable tag)")


def test_the_label_goes_in_as_where_for_both_builders():
    # An adapter passes the whole label, provider and service included, never a bare project.
    assert _gap(service="appengine", where="gcp appengine my-project", why="boom").location == (
        "gcp appengine my-project")
    row = _unread(service="appengine", where="gcp appengine my-project", count=1,
                  what="versions", lacks="no usable name")
    assert row.location == "gcp appengine my-project"


# --- a registry that was read only in part, and the note on an image find ---

REPO = "projects/my-project/locations/us/repositories/php"


@pytest.mark.parametrize("saw_php,extra", [(False, {}), (True, {"php_present": "true"})])
def test_a_repository_gap_names_the_repository_and_keeps_the_php_it_already_showed(
        saw_php, extra):
    row = _repo_gap("artifactregistry", REPO, "us-docker.pkg.dev/my-project/php", "boom", saw_php)
    assert row == Evidence(
        Source.CLOUD, "us-docker.pkg.dev/my-project/php", None, Sapi.UNKNOWN,
        {"resource": REPO, "service": "artifactregistry", "kind": "skipped", **extra},
        "not fully inventoried: boom")


def test_the_branch_note_leaves_a_slot_for_what_named_the_branch():
    assert _BRANCH.format("runtime php83") == (
        "runtime php83 names only the PHP branch, so the build is not read")


@pytest.mark.parametrize("number,note", [
    ("8.3.12", "version read from the image tag"),
    ("5.6.40", "version read from the image tag"),
    ("8.3", "the tag names only the PHP branch, so the build is not read"),
    ("9.0", "the tag names only the PHP branch, so the build is not read"),
])
def test_an_image_find_says_whether_its_tag_gave_the_build_or_only_the_branch(number, note):
    assert _tag_note(number) == note


def test_an_image_tag_is_at_most_128_characters():
    assert _MAX_TAG == 128


# --- the source ---

def test_the_module_imports_only_the_standard_library_and_the_core_of_the_package():
    # Full module names, so a provider module or a source cannot slip in under php_radar.
    found = set()
    for node in ast.walk(ast.parse(SOURCE, feature_version=(3, 9))):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            found.add(node.module or "")
    assert found <= {"string", "typing", "collections", "php_radar.model", "php_radar.versions",
                     "php_radar.knowledge"}


def test_the_module_has_no_way_to_read_credentials_the_environment_or_a_file():
    tree = ast.parse(SOURCE, feature_version=(3, 9))
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    names |= {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    assert not names & {
        "environ", "getenv", "os", "open", "print", "logging", "eval", "exec", "compile",
        "__import__", "subprocess", "socket", "urllib"}


def test_the_module_is_plain_ascii_with_no_dash_or_curly_quote():
    assert SOURCE.isascii()
    assert not set(SOURCE) & set(DASHES_AND_QUOTES)
    assert not [c for c in SOURCE if ord(c) < 32 and c != "\n"]
