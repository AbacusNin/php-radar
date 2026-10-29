"""The parts of a cloud adapter that do not depend on the provider.

_tag_version reads the PHP version out of an image tag. A tag names it the same way on AWS, GCP,
and Azure. _where labels a read. _gap and _unread build the row for a read that was skipped, in
the one shape that lets a caller count the gaps of every provider together. _repo_gap and
_tag_note serve the container registries, which share the tag limit and the branch note.

_Stop is how a reader says it cannot go on. _MAX_PAGES ends a listing and _MAX_MISSES ends a run
of failures. _iterable and _entries guard the lists an SDK answers with. _dns picks a host name
out of an answer.
"""
import string
from collections import abc
from typing import Any, Optional

from php_radar.model import Evidence, Sapi, Source
from php_radar.versions import PhpVersion, parse_branch
# The grader decides what a distro revision and a pre-release are. Using its test keeps a tag read
# in step with the grader.
from php_radar.knowledge import _is_prerelease, _is_revision

# The characters in DNS names, image tags, resource names, and error codes.
_NAME = frozenset(string.ascii_letters + string.digits + "-._")
_PATH = _NAME | frozenset("/")  # repository names and the URIs docker pulls from

# PHP 5 is the oldest major worth reading and 9 the newest accepted, so an app version such as
# 2.1.0 in a repository called php is not taken for PHP.
_MAJORS = range(5, 10)

# The longest an image tag can be, by the Docker and OCI rules.
_MAX_TAG = 128

# The note on a find that names only the PHP branch. The slot holds what named it.
_BRANCH = "{} names only the PHP branch, so the build is not read"

# Pages read from one listing. A listing past this is cut and says so, which also ends a service
# that keeps handing back a continuation.
_MAX_PAGES = 200

# How many repositories or sites in a row may fail before that read stops. A repository fails when
# its images cannot be listed. A site fails when its configuration cannot be read.
_MAX_MISSES = 3

# A DNS name is 253 characters at most.
_MAX_DNS = 253


class _Stop(Exception):
    """A read that cannot go on. The message is the reason to record."""


def _fits(value: object, chars: frozenset, limit: int) -> bool:
    return isinstance(value, str) and 0 < len(value) <= limit and chars.issuperset(value)


def _dns(value: object) -> Optional[str]:
    return value if _fits(value, _NAME, _MAX_DNS) and value[0] not in ".-" else None


def _iterable(value: Any) -> bool:
    # A string iterates, and is no list of entries. The ABC is asked, and not hasattr(value,
    # "__iter__"), because protobuf's default backend keeps a repeated field in a container with a
    # length and an index and no __iter__. It registers the container as a sequence, and the ABC
    # knows it by that.
    return isinstance(value, abc.Iterable) and not isinstance(value, (str, bytes))


def _entries(value: Any) -> Optional[list]:
    return list(value) if _iterable(value) else None


def _number(word: str) -> Optional[str]:
    """X.Y.Z or X.Y when the word is exactly that and could be PHP, else None."""
    release = PhpVersion.parse(word)
    if release is not None:
        parts = None if release.suffix else (release.major, release.minor, release.micro)
    else:
        parts = parse_branch(word)
    return ".".join(map(str, parts)) if parts and parts[0] in _MAJORS else None


def _number_word(words: list[str], official: bool) -> Optional[tuple[int, str]]:
    """(index, text) of the word that should hold the PHP number in a tag, or None.

    Two shapes name PHP. The word php can be followed by the number (php-8.3.12), or a word can
    start with php and a digit and hold the number itself (php8.3.12). In a repository called php,
    a tag names PHP by starting with the number, as the official image's tags do.
    """
    for at, word in enumerate(words):
        if word == "php" and at + 1 < len(words):
            return at + 1, words[at + 1]
        if word.startswith("php") and word[3:4].isdigit():
            return at, word[3:]
    return (0, words[0]) if official else None


def _tag_version(tag: str, official: bool) -> Optional[str]:
    """The PHP version an image tag names, X.Y.Z or X.Y, or None when it names none.

    A full number stands unless what follows it reads as a distro revision or a pre-release, by
    the grader's own test. Then the tag gives the branch alone. The number could be the upstream
    one of a build with fixes of its own.
    """
    words = tag.lower().replace("_", "-").split("-")
    found = _number_word(words, official)
    number = _number(found[1]) if found else None
    if found and number is not None and number.count(".") == 2:
        # The number parsed on its own, so it parses with a suffix after it too.
        release = PhpVersion.parse("-".join([found[1]] + words[found[0] + 1:]))
        if _is_revision(release) or _is_prerelease(release):
            number = number.rpartition(".")[0]
    return number


def _tag_note(number: str) -> str:
    # A full number came out of the tag. A branch is all the tag said, and a branch cannot place
    # the build.
    full = number.count(".") == 2
    return "version read from the image tag" if full else _BRANCH.format("the tag")


def _where(provider: str, service: str, scope: Optional[str]) -> str:
    # What a row says it was reading: the provider, the service, and the scope, such as a region or
    # a project. A read with no scope is labeled by the provider and the service alone.
    return f"{provider} {service} {scope}" if scope else f"{provider} {service}"


def _gap(service: str, where: str, why: str) -> Evidence:
    # The repo scan marks a row about something it passed over with kind skipped. The same mark
    # lets a caller count the gaps of every source one way. where is the whole label of what the
    # adapter was reading, as _where builds it. It becomes the row's location.
    return Evidence(Source.CLOUD, where, None, Sapi.UNKNOWN,
                    {"service": service, "kind": "skipped"}, "not inventoried: " + why)


def _unread(service: str, where: str, count: int, what: str, lacks: str) -> Evidence:
    # lacks says what the unread entries were missing, because a dropped entry is a puzzle without
    # it. The cause depends on the provider, so the adapter passes it in.
    entries = "entry" if count == 1 else "entries"
    return _gap(service, where,
                f"{count} {entries} in the list of {what} could not be read ({lacks})")


def _repo_gap(service: str, resource: str, location: str, why: str, saw_php: bool) -> Evidence:
    # A repository whose images could not all be listed. resource is the one its finds carry, so
    # this row folds into the same asset as they do.
    signals = {"resource": resource, "service": service, "kind": "skipped"}
    if saw_php:
        # The part not read may hold an older build, so the part that was read cannot clear it.
        signals["php_present"] = "true"
    return Evidence(Source.CLOUD, location, None, Sapi.UNKNOWN, signals,
                    "not fully inventoried: " + why)
