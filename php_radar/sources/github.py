"""Finds where the repositories of a GitHub organization pin or declare a PHP runtime.

scan_github_org lists the repositories of an organization through the REST API and reads, in the
default branch of each, the files scan_path reads in a checkout. The reading is repo.py's: the same
file names, the same parsers, the same limits, and the same rule that a file the scan could not
read holds its repository at INDETERMINATE. This module only fetches.

The token goes to api.github.com and nowhere else. Every URL is checked before it is requested, so
a redirect or a pagination link that names another host is refused. A rate limit is waited out in
short steps up to a ceiling, and then the scan stops. Other branches are not read. A submodule is
not entered, because it is another repository.
"""
import base64
import json
import string
import time
from typing import Callable, Iterator, NamedTuple, Optional
from urllib.parse import quote, urljoin, urlsplit

from php_radar import http
from php_radar.model import Evidence
# The parsing seam that the local scan shares. A rename in repo.py breaks this import at once, so
# the two scans cannot drift apart unnoticed.
from php_radar.sources.repo import _MAX_BYTES, _SKIP_DIRS, _decode, _finds, _reader, _skipped

_API = "https://api.github.com"

# Seconds, for each request.
_TIMEOUT = 20.0

# The most the API puts on a page.
_PER_PAGE = 100

# An organization past this many pages (10,000 repositories) is listed no further.
_MAX_PAGES = 100

# A redirect chain longer than this is a loop.
_MAX_HOPS = 3

# How often one request waits out a rate limit before the scan gives up, and the longest single
# wait. A limit that asks for more is not waited out, because a scan that sat for an hour would
# look hung and the person can run it again once the limit lifts.
_MAX_RETRIES = 3
_MAX_WAIT = 120

# GitHub says to wait at least a minute when a secondary limit names no time.
_DEFAULT_WAIT = 60

# This many requests in a row with no answer or a 5xx answer, and the scan decides GitHub is down.
# Without the stop, each remaining file would cost another timeout or another error.
_MAX_MISSES = 3

# Files read in one repository. Each is a request against a limit that the person's other tools
# share, and a repository with thousands of package manifests would spend all of it.
_MAX_FILES = 300

# How much of an answer is searched for the words of a rate limit message.
_PEEK = 4096

_NAME_CHARS = frozenset(string.ascii_letters + string.digits + "-._")
_HEX = frozenset("0123456789abcdef")
_REDIRECTS = frozenset({301, 302, 303, 307, 308})
_WHY = {403: "forbidden", 404: "not found, or hidden from this token"}
_TOO_BIG = f"it is larger than {_MAX_BYTES} bytes"

# Waiting goes through these two names so that a test never sleeps.
_sleep = time.sleep
_now = time.time


class _Failed(Exception):
    """A request that gave no usable answer. The message is the reason to record."""

    def __init__(self, reason: str, answer: Optional[http.Response] = None) -> None:
        super().__init__(reason)
        self.answer = answer


class _Stop(Exception):
    """The scan cannot go on, because every request after this one would fail the same way."""


class _Repo(NamedTuple):
    ident: str  # org/name, the repo signal of each find
    name: str
    branch: str


def _is_name(text: object) -> bool:
    """True for what GitHub allows in the name of an account or a repository."""
    return (isinstance(text, str) and 0 < len(text) <= 100 and text not in (".", "..")
            and _NAME_CHARS.issuperset(text))


def _is_sha(text: object) -> bool:
    return isinstance(text, str) and len(text) in (40, 64) and _HEX.issuperset(text)


def _is_api(url: str) -> bool:
    """True when url is on the API host, with the same scheme and no port or user name."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    base = urlsplit(_API)
    return parts.scheme == base.scheme and parts.netloc.lower() == base.netloc


def _header(answer: http.Response, name: str) -> str:
    return next((value.strip() for key, value in answer.headers.items() if key.lower() == name), "")


def _seconds(text: str) -> Optional[int]:
    """The whole number in a header value, or None for anything else."""
    return int(text) if 0 < len(text) <= 12 and text.isascii() and text.isdigit() else None


def _limit_wait(answer: http.Response) -> Optional[float]:
    """Seconds GitHub asks for when the answer is a rate limit, or None when it is no limit."""
    if answer.status not in (403, 429):
        return None
    after = _seconds(_header(answer, "retry-after"))
    if after is not None:
        return max(after, 1)
    if _header(answer, "x-ratelimit-remaining") == "0":
        reset = _seconds(_header(answer, "x-ratelimit-reset"))
        return _DEFAULT_WAIT if reset is None else max(reset - _now(), 0) + 1
    # A secondary limit can come with neither header, and then only the message says so.
    if b"rate limit" in answer.body[:_PEEK].lower():
        return _DEFAULT_WAIT
    return None


def _next_link(header: str) -> str:
    """The target of the rel="next" entry of a Link header, or an empty string."""
    for entry in header.split("<")[1:]:
        target, _, params = entry.partition(">")
        # An entry that another follows ends in the comma between them.
        for param in params.rstrip(" \t,").split(";"):
            name, _, value = param.partition("=")
            if name.strip().lower() == "rel" and "next" in value.strip().strip('"').lower().split():
                return target.strip()
    return ""


def _why(exc: OSError) -> str:
    # A TransportError is worded to be shown. Any other error names its class, because its own
    # text alone ("boom") says too little.
    text = str(exc) if isinstance(exc, http.TransportError) else f"{type(exc).__name__}: {exc}"
    return text[:200]


def _status(code: int) -> str:
    why = _WHY.get(code)
    return f"HTTP {code}, {why}" if why else f"HTTP {code}"


def _not_understood(count: int, where: str) -> str:
    entries, verb = ("entry", "was") if count == 1 else ("entries", "were")
    return f"{count} {entries} in {where} {verb} not understood"


def _load(answer: http.Response) -> object:
    try:
        return json.loads(answer.body)
    except (ValueError, RecursionError):
        raise _Failed("the answer is not JSON") from None


class _Api:
    """The requests of one scan. It holds the headers, and with them the only copy of the token."""

    def __init__(self, get: Callable[[str, dict, float], http.Response], token: str) -> None:
        self._get = get
        self._headers = {"Accept": "application/vnd.github+json", "User-Agent": "php-radar"}
        if token:
            self._headers["Authorization"] = "Bearer " + token
        self._misses = 0  # requests in a row that got no answer or a 5xx

    def _miss(self, reason: str) -> None:
        self._misses += 1
        if self._misses >= _MAX_MISSES:
            raise _Stop(f"GitHub keeps failing ({reason})")

    def fetch(self, url: str) -> http.Response:
        """The 200 answer for url. Redirects stay inside the API, and a rate limit is waited out."""
        hops = retries = 0
        while True:
            # Every request is checked, the redirected and the paginated ones included. So the
            # token goes nowhere else, whatever put the URL here.
            if not _is_api(url):
                raise _Failed("the link leads away from api.github.com")
            try:
                answer = self._get(url, self._headers, _TIMEOUT)
            except OSError as exc:
                self._miss(_why(exc))
                raise _Failed(_why(exc)) from exc
            if answer.status >= 500:
                self._miss(_status(answer.status))
            else:
                self._misses = 0
            if answer.status in _REDIRECTS:
                where = _header(answer, "location")
                hops += 1
                if not where:
                    raise _Failed("a redirect names no place")
                if hops > _MAX_HOPS:
                    raise _Failed("too many redirects")
                url = urljoin(url, where)
                continue
            wait = _limit_wait(answer)
            if wait is not None:
                wait *= 2 ** retries
                if wait > _MAX_WAIT:
                    raise _Stop("the GitHub rate limit was reached, and the wait would run past "
                                f"{_MAX_WAIT} seconds")
                if retries == _MAX_RETRIES:
                    raise _Stop(f"the GitHub rate limit was still in force after {retries} waits")
                retries += 1
                _sleep(wait)
                continue
            if answer.status == 401:
                raise _Stop("GitHub rejected the token (HTTP 401)")
            if answer.status != 200:
                raise _Failed(_status(answer.status), answer)
            return answer

    def fetch_json(self, url: str) -> object:
        return _load(self.fetch(url))


def _repo(org: str, item: object) -> Optional[_Repo]:
    if not isinstance(item, dict):
        return None
    name, branch = item.get("name"), item.get("default_branch")
    if not _is_name(name) or not isinstance(branch, str) or not branch:
        return None
    return _Repo(f"{org}/{name}", name, branch)


def _repos(api: _Api, org: str, gaps: list[str]) -> Iterator[_Repo]:
    """The repositories of org, a page at a time. gaps takes the reasons the list falls short."""
    url = f"{_API}/orgs/{quote(org, safe='')}/repos?per_page={_PER_PAGE}&sort=full_name"
    seen = set()  # a repository created while the pages are read can turn up on two of them
    pages = 0
    while url:
        if pages == _MAX_PAGES:
            gaps.append(f"the list of repositories runs past {_MAX_PAGES} pages, and only those "
                        "were read")
            return
        pages += 1
        answer = api.fetch(url)
        page = _load(answer)
        if not isinstance(page, list):
            raise _Failed("the answer is not a list")
        odd = 0
        for item in page:
            repo = _repo(org, item)
            if repo is None:
                odd += 1
            elif repo.name not in seen:
                seen.add(repo.name)
                yield repo
        if odd:
            gaps.append(_not_understood(odd, "the list of repositories"))
        url = _next_link(_header(answer, "link"))


def _blob(api: _Api, url: str) -> bytes:
    data = api.fetch_json(url)
    content = data.get("content") if isinstance(data, dict) else None
    encoding = data.get("encoding") if isinstance(data, dict) else None
    if encoding != "base64" or not isinstance(content, str):
        raise _Failed("the answer holds no base64 content")
    try:
        # GitHub breaks the encoding into lines. Any other byte outside the alphabet is an error,
        # and the decoder would otherwise drop it and return a shorter file.
        return base64.b64decode("".join(content.split()), validate=True)
    except ValueError:
        raise _Failed("the content is not valid base64") from None


def _scan_file(api: _Api, base: str, ident: str, path: str, entry: dict,
               reader) -> Iterator[Evidence]:
    if entry.get("mode") == "120000":
        yield _skipped(ident, path, "it is a symbolic link, and links are not followed")
        return
    size, sha = entry.get("size"), entry.get("sha")
    if isinstance(size, int) and size > _MAX_BYTES:
        yield _skipped(ident, path, _TOO_BIG)
        return
    if not _is_sha(sha):
        yield _skipped(ident, path, "cannot read it (its object id is not understood)")
        return
    try:
        data = _blob(api, f"{base}/blobs/{sha}")
    except _Failed as exc:
        yield _skipped(ident, path, f"cannot read it ({exc})")
        return
    if len(data) > _MAX_BYTES:
        yield _skipped(ident, path, _TOO_BIG)
        return
    yield from _finds(ident, path, reader, _decode(data))


def _is_empty(failure: _Failed) -> bool:
    answer = failure.answer
    return answer is not None and answer.status == 409 and b"empty" in answer.body[:_PEEK].lower()


def _scan_repo(api: _Api, org: str, repo: _Repo) -> Iterator[Evidence]:
    ident = repo.ident
    base = f"{_API}/repos/{quote(org, safe='')}/{quote(repo.name, safe='')}/git"
    try:
        tree = api.fetch_json(f"{base}/trees/{quote(repo.branch, safe='')}?recursive=1")
    except _Failed as exc:
        # A repository with no commits has no files to read, and GitHub says so with a 409.
        if not _is_empty(exc):
            yield _skipped(ident, ".", f"cannot list its files ({exc})")
        return
    entries = tree.get("tree") if isinstance(tree, dict) else None
    if not isinstance(entries, list):
        yield _skipped(ident, ".", "cannot list its files (the answer is not a file list)")
        return
    wanted = []
    odd = 0
    for entry in entries:
        path = entry.get("path") if isinstance(entry, dict) else None
        kind = entry.get("type") if isinstance(entry, dict) else None
        if not isinstance(path, str) or not isinstance(kind, str):
            odd += 1
        elif kind == "blob" and not _SKIP_DIRS.intersection(path.split("/")[:-1]):
            reader = _reader(path)
            if reader is not None:
                wanted.append((path, entry, reader))
    # The files nearest the root come first, because they are the project's own, and the cap
    # drops the deepest.
    wanted.sort(key=lambda found: (found[0].count("/"), found[0]))
    for path, entry, reader in wanted[:_MAX_FILES]:
        yield from _scan_file(api, base, ident, path, entry, reader)
    if len(wanted) > _MAX_FILES:
        yield _skipped(ident, ".", f"it holds {len(wanted)} files the scan reads, and only the "
                       f"first {_MAX_FILES} were read")
    if odd:
        yield _skipped(ident, ".", _not_understood(odd, "its file list"))
    if tree.get("truncated") is True:
        yield _skipped(ident, ".", "its file list was cut short by GitHub, so some files were "
                       "not read")


def scan_github_org(org: str, token: str,
                    get: Callable[[str, dict, float], http.Response] = http.get) -> list[Evidence]:
    """One Evidence per PHP pin in the default branches of the repositories of the organization org.

    Each find has the repo signal org/name and, as its location, the path of the file within that
    repository. The token is a GitHub token that can read the contents of the repositories. It goes
    to api.github.com and to no other host, and it appears in no evidence, note, or message. The
    caller reads it from the environment and passes it in. An empty token scans without one, and
    GitHub allows that 60 requests an hour. get takes (url, headers, timeout) and returns an
    http.Response, as http.get does. The guarantee about the token holds while get follows no
    redirect, and http.get follows none. The host check runs on the URLs this function requests,
    so it cannot see a hop that a custom get makes inside itself.

    A repository with no PHP pins leaves no evidence. Failures of the network and of GitHub never
    raise. Each leaves a skipped row with the reason in note, and the row's repo signal is the
    repository, or the organization when its repositories cannot be listed. That row holds the
    repository at INDETERMINATE, as an unread file does in a local scan. ValueError means org or
    token cannot be used, and nothing was sent.
    """
    if not _is_name(org):
        raise ValueError("org is not the name of a GitHub organization")
    token = (token or "").strip()
    if not (token.isascii() and token.isprintable() and " " not in token):
        raise ValueError("token holds a character that cannot go in an HTTP header")
    api = _Api(get, token)
    found: list[Evidence] = []
    gaps: list[str] = []
    repos: list[_Repo] = []
    stop = ""  # once set, the reason no request will be made
    try:
        for repo in _repos(api, org, gaps):
            repos.append(repo)
    except _Failed as exc:
        gaps.append(f"cannot list all the repositories ({exc})")
    except _Stop as halt:
        stop = str(halt)
        gaps.append(f"cannot list all the repositories ({halt})")
    found.extend(_skipped(org, ".", gap) for gap in gaps)
    for repo in repos:
        if stop:
            found.append(_skipped(repo.ident, ".", f"not scanned ({stop})"))
            continue
        try:
            for ev in _scan_repo(api, org, repo):
                found.append(ev)
        except _Stop as halt:
            stop = str(halt)
            found.append(_skipped(repo.ident, ".", f"not fully scanned ({stop})"))
    return found
