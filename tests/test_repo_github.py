import ast
import base64
import hashlib
import inspect
import json
import pathlib
import socket
from typing import NamedTuple
from urllib.parse import parse_qs, unquote, urlsplit

import pytest

from php_radar import http as php_http
from php_radar.http import Response, TransportError
from php_radar.knowledge import DATA_PATH, grade, load_matrix
from php_radar.model import Asset, AssetInventory, Confidence, Source, Verdict
from php_radar.report import redact, render_console, render_json, render_sarif
from php_radar.sources import github as github_module
from php_radar.sources import repo as repo_module
from php_radar.sources.github import scan_github_org
from php_radar.sources.repo import scan_path

EXPOSED, INDETERMINATE, LIKELY_PATCHED = (
    Verdict.EXPOSED, Verdict.INDETERMINATE, Verdict.LIKELY_PATCHED)
HIGH, LOW = Confidence.HIGH, Confidence.LOW

API = "https://api.github.com"
NOW = 1_000_000
CANARY = "ghp_CANARY" + "x" * 30

CI = """name: ci
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: shivammathur/setup-php@v2
        with:
          php-version: '8.2'
"""


def reply(status=200, body=b"", headers=None):
    if not isinstance(body, bytes):
        body = json.dumps(body).encode()
    return Response(status, {k.lower(): v for k, v in (headers or {}).items()}, body)


def limit(headers, message="Slow down", status=403):
    return reply(status, {"message": message}, headers)


class Call(NamedTuple):
    url: str
    headers: dict
    timeout: float

    @property
    def path(self):
        return unquote(urlsplit(self.url).path)


class FakeGitHub:
    """Stands in for http.get. It serves a small GitHub from tables and records every request.

    script maps a request path to answers served first, in order: a Response, or an exception to
    raise. Once a path's answers are used up, the tables answer.
    """

    def __init__(self, org="acme"):
        self.org = org
        self.base = API
        self.calls = []
        self.last_headers = None
        self.script = {}
        self.page_size = 100
        self.next_link = None  # a Link target for the first page, whatever the page count
        self.listing = []
        self.trees = {}  # name -> (branch, tree entries, truncated)
        self.shas = {}
        self.blobs = {}
        self.empty = set()
        self.blob_log = []

    def add_repo(self, name, files=None, branch="main", modes=None, sizes=None, truncated=False,
                 empty=False, extra=()):
        entries = []
        shas = {}
        for path, data in (files or {}).items():
            data = data.encode() if isinstance(data, str) else data
            sha = hashlib.sha1(data).hexdigest()
            self.blobs[sha] = data
            shas[path] = sha
            entries.append({"path": path, "mode": (modes or {}).get(path, "100644"),
                            "type": "blob", "sha": sha,
                            "size": (sizes or {}).get(path, len(data))})
        entries.extend(extra)
        self.listing.append({"name": name, "full_name": f"{self.org}/{name}",
                             "default_branch": branch, "archived": False, "fork": False,
                             "owner": {"login": self.org}})
        self.trees[name] = (branch, entries, truncated)
        self.shas[name] = shas
        if empty:
            self.empty.add(name)

    def sha(self, name, path):
        return self.shas[name][path]

    def fetched(self, name):
        by_sha = {}
        for path, sha in self.shas[name].items():
            by_sha.setdefault(sha, []).append(path)
        return [path for repo, sha in self.blob_log if repo == name for path in by_sha[sha]]

    @property
    def paths(self):
        return [call.path for call in self.calls]

    def __call__(self, url, headers, timeout):
        self.calls.append(Call(url, dict(headers), timeout))
        self.last_headers = headers
        path = unquote(urlsplit(url).path)
        queued = self.script.get(path)
        if queued:
            answer = queued.pop(0)
            if isinstance(answer, BaseException):
                raise answer
            return answer
        parts = path.split("/", 6)
        if len(parts) == 4 and parts[1] in ("orgs", "organizations") and parts[3] == "repos":
            return self._page(url)
        if len(parts) == 7 and parts[1:3] == ["repos", self.org] and parts[3] in self.trees:
            if parts[4:6] == ["git", "trees"]:
                return self._tree(parts[3], parts[6])
            if parts[4:6] == ["git", "blobs"]:
                return self._blob(parts[3], parts[6])
        return reply(404, {"message": "Not Found"})

    def _page(self, url):
        page = int(parse_qs(urlsplit(url).query).get("page", ["1"])[0])
        size = self.page_size
        headers = {}
        if page == 1 and self.next_link is not None:
            headers["Link"] = f'<{self.next_link}>; rel="next"'
        elif page * size < len(self.listing):
            where = f"{self.base}/organizations/1/repos"
            headers["Link"] = (f'<{where}?per_page={size}&page={page + 1}>; rel="next", '
                               f'<{where}?page=99>; rel="last"')
        return reply(200, self.listing[(page - 1) * size:page * size], headers)

    def _tree(self, name, branch):
        want, entries, truncated = self.trees[name]
        if name in self.empty:
            return reply(409, {"message": "Git Repository is empty."})
        if branch != want:
            return reply(404, {"message": "Not Found"})
        return reply(200, {"sha": "t" * 40, "url": "x", "tree": entries, "truncated": truncated})

    def _blob(self, name, sha):
        if sha not in self.blobs:
            return reply(404, {"message": "Not Found"})
        self.blob_log.append((name, sha))
        data = self.blobs[sha]
        wrapped = base64.encodebytes(data).decode()  # GitHub breaks the encoding into lines
        return reply(200, {"sha": sha, "size": len(data), "encoding": "base64", "content": wrapped})


def acme():
    world = FakeGitHub()
    world.add_repo("web", {
        "Dockerfile": "FROM php:8.3.35-fpm\n",
        "composer.json": '{"require": {"php": ">=8.2"}}',
        ".github/workflows/ci.yml": CI,
        "README.md": "# web\n",
    })
    world.add_repo("api", {
        "docker-compose.yml": "services:\n  app:\n    image: php:8.3-apache\n",
        ".php-version": "8.3.35\n",
    })
    return world


@pytest.fixture(autouse=True)
def slept(monkeypatch):
    """No test waits for real, and the clock stands still. The list holds each wait asked for."""
    waits = []
    monkeypatch.setattr(github_module, "_sleep", waits.append)
    monkeypatch.setattr(github_module, "_now", lambda: NOW)
    return waits


@pytest.fixture(scope="module")
def matrix():
    return load_matrix(DATA_PATH)


@pytest.fixture
def fake_get():
    return acme()


def run(world, token="t", org="acme"):
    return scan_github_org(org, token, world)


def digest(evs):
    rows = [(e.signals["repo"], e.location, e.signals["kind"], e.signals.get("declared", ""),
             e.detected_version, e.signals["confidence"]) for e in evs]
    return sorted(rows, key=str)


def finds(evs):
    return [e for e in evs if e.signals["kind"] != "skipped"]


def skips(evs, repo=None):
    return [e for e in evs if e.signals["kind"] == "skipped"
            and (repo is None or e.signals["repo"] == repo)]


def grade_of(evs, repo, matrix):
    return grade(Asset(repo, "repo", [e for e in evs if e.signals["repo"] == repo]), matrix)


def one_repo(files, **kw):
    world = FakeGitHub()
    world.add_repo("web", files, **kw)
    return world


# --- the interface ---

def test_github_org_scan_uses_token_and_finds_pins(fake_get):
    evs = scan_github_org("acme", token="t", get=fake_get)
    assert fake_get.last_headers["Authorization"] == "Bearer t"
    assert any(e.source == Source.REPO for e in evs)


def test_the_default_get_is_http_get():
    assert inspect.signature(scan_github_org).parameters["get"].default is php_http.get


# --- what a find carries ---

def test_the_finds_of_an_org_are_named_by_repository_and_file(fake_get):
    assert digest(run(fake_get)) == [
        ("acme/api", ".php-version", "php-version-file", "8.3.35", "8.3.35", "MEDIUM"),
        ("acme/api", "docker-compose.yml", "compose", "8.3-apache", None, "LOW"),
        ("acme/web", ".github/workflows/ci.yml", "ci-setup-php", "8.2", None, "LOW"),
        ("acme/web", "Dockerfile", "dockerfile", "8.3.35-fpm", "8.3.35", "HIGH"),
        ("acme/web", "composer.json", "composer-constraint", ">=8.2", None, "LOW"),
    ]


def test_a_find_sets_the_repo_signal_and_a_location_relative_to_the_repository():
    world = one_repo({"Dockerfile": "FROM php:8.3.35\n",
                      "docker/php/Dockerfile": "FROM php:8.2.5\n",
                      ".github/workflows/ci.yml": CI})
    evs = run(world)
    assert {e.location for e in evs} == {"Dockerfile", "docker/php/Dockerfile",
                                         ".github/workflows/ci.yml"}
    for ev in evs:
        assert ev.source is Source.REPO
        assert ev.signals["repo"] == "acme/web"
        assert not ev.location.startswith(("/", "./", "acme"))
        assert "\\" not in ev.location


def test_a_find_carries_the_sapi_the_version_and_the_confidence_of_the_local_scan():
    (ev,) = run(one_repo({"Dockerfile": "FROM php:8.3.35-fpm-alpine3.20\n"}))
    assert (ev.detected_version, ev.sapi.name, ev.signals["confidence"]) == (
        "8.3.35", "FPM", "HIGH")


def test_two_repositories_that_share_a_file_stay_two_assets():
    world = FakeGitHub()
    world.add_repo("one", {"Dockerfile": "FROM php:8.3.35\n"})
    world.add_repo("two", {"Dockerfile": "FROM php:8.3.35\n"})
    inventory = AssetInventory()
    for ev in run(world):
        inventory.add(ev)
    assert sorted(asset.key for asset in inventory.assets()) == ["acme/one", "acme/two"]


def test_the_name_comes_from_the_listing_and_the_org_from_the_argument():
    world = FakeGitHub()
    world.add_repo("Web.App_2", {"Dockerfile": "FROM php:8.3.35\n"})
    (ev,) = run(world)
    assert ev.signals["repo"] == "acme/Web.App_2"


def test_a_repository_with_nothing_to_read_leaves_no_evidence():
    assert run(one_repo({"README.md": "hello", "src/app.php": "<?php"})) == []


def test_an_org_with_no_repositories_leaves_no_evidence():
    assert run(FakeGitHub()) == []


def test_a_repository_listed_twice_is_read_once():
    world = one_repo({"Dockerfile": "FROM php:8.3.35\n"})
    world.listing.append(dict(world.listing[0]))
    assert len(run(world)) == 1
    assert world.paths.count("/repos/acme/web/git/trees/main") == 1


# --- the same reading as the local scan ---

def test_a_repository_reads_the_same_as_the_same_files_on_disk(tmp_path):
    files = {
        "Dockerfile": "FROM php:8.3.35-fpm-alpine3.20\nFROM node:20\n",
        "docker/php/Dockerfile.dev": "FROM php:8.1.2\n",
        "docker-compose.yml": "services:\n  web:\n    image: php:8.3-apache\n",
        ".github/workflows/ci.yml": CI,
        ".php-version": "8.3.35\n",
        ".tool-versions": "php 8.2.12\nnodejs 20.1.0\n",
        "composer.json": '{"require": {"php": "^8.2"}, "config": {"platform": {"php": "8.2.12"}}}',
        "apps/blog/composer.json": "{not json",
        ".devcontainer/devcontainer.json": (
            '// the dev container\n{"image": "mcr.microsoft.com/devcontainers/php:8.3.35", /* c */ '
            '"features": {"ghcr.io/devcontainers/features/php:1": {"version": "8.2"},},}'),
        "too/big/Dockerfile": b"#" * (repo_module._MAX_BYTES + 1),
        # None of these is read.
        "README.md": "FROM php:7.4.33\n",
        "src/index.php": "<?php echo 1;",
        "Dockerfile.md": "FROM php:7.4.33\n",
        "vendor/acme/lib/Dockerfile": "FROM php:7.4.33\n",
        "node_modules/x/.php-version": "7.4.33\n",
    }
    root = tmp_path / "site"
    for rel, data in files.items():
        path = root.joinpath(*rel.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data.encode() if isinstance(data, str) else data)
    world = FakeGitHub()
    world.add_repo("site", files)

    def comparable(evs):
        rows = [(e.location, e.detected_version, e.sapi.name, e.note,
                 sorted((k, v) for k, v in e.signals.items() if k != "repo")) for e in evs]
        return sorted(rows, key=repr)

    local, remote = scan_path(str(root)), run(world)
    assert len(remote) >= 10
    assert comparable(remote) == comparable(local)
    assert {e.signals["repo"] for e in remote} == {"acme/site"}


def test_only_files_the_local_scan_reads_are_fetched():
    world = one_repo({
        "Dockerfile": "FROM php:8.3.35\n",
        "README.md": "a",
        "src/app.php": "b",
        "vendor/x/Dockerfile": "FROM php:7.4.33\n",
        "node_modules/y/.php-version": "7.4.33\n",
        "docs/Dockerfile.md": "FROM php:7.4.33 (documented)\n",
        "a/vendor/z/composer.json": "{}",
        "a/.git/Dockerfile": "FROM php:7.4.31\n",
    })
    run(world)
    assert world.fetched("web") == ["Dockerfile"]


def test_a_folder_and_a_submodule_with_the_name_of_a_dockerfile_are_not_files():
    world = one_repo({"Dockerfile": "FROM php:8.3.35\n"}, extra=[
        {"path": "Dockerfile.d", "mode": "040000", "type": "tree", "sha": "a" * 40},
        {"path": "Dockerfile.sub", "mode": "160000", "type": "commit", "sha": "b" * 40},
    ])
    evs = run(world)
    assert [e.location for e in evs] == ["Dockerfile"]
    assert len(world.blob_log) == 1


# --- the requests ---

def test_the_requests_are_the_documented_ones(fake_get):
    run(fake_get)
    urls = [call.url for call in fake_get.calls]
    assert urls[0] == f"{API}/orgs/acme/repos?per_page=100&sort=full_name"
    assert f"{API}/repos/acme/web/git/trees/main?recursive=1" in urls
    assert f"{API}/repos/acme/web/git/blobs/{fake_get.sha('web', 'Dockerfile')}" in urls
    assert len(urls) == len(set(urls))


def test_a_branch_name_with_a_slash_is_quoted_in_the_path():
    world = one_repo({"Dockerfile": "FROM php:8.3.35\n"}, branch="release/8.3")
    assert len(run(world)) == 1
    urls = [c.url for c in world.calls]
    assert f"{API}/repos/acme/web/git/trees/release%2F8.3?recursive=1" in urls


def test_every_request_has_a_timeout_and_the_same_headers(fake_get):
    run(fake_get)
    assert len(fake_get.calls) >= 8
    for call in fake_get.calls:
        assert 0 < call.timeout <= 60
        assert call.headers["Authorization"] == "Bearer t"
        assert call.headers["Accept"] == "application/vnd.github+json"
        assert call.headers["User-Agent"]


def test_every_request_goes_to_https_api_github_com(fake_get):
    run(fake_get)
    for call in fake_get.calls:
        parts = urlsplit(call.url)
        assert (parts.scheme, parts.netloc) == ("https", "api.github.com")


# --- the token ---

def test_the_token_is_sent_only_in_the_authorization_header(fake_get):
    run(fake_get, token=CANARY)
    for call in fake_get.calls:
        assert call.headers["Authorization"] == "Bearer " + CANARY
        assert CANARY not in call.url
        assert all(CANARY not in value for name, value in call.headers.items()
                   if name != "Authorization")


def test_the_token_comes_from_the_argument_and_never_from_the_environment(fake_get, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "env-canary")
    run(fake_get, token="t")
    assert {call.headers["Authorization"] for call in fake_get.calls} == {"Bearer t"}
    assert "env-canary" not in json.dumps([call.headers for call in fake_get.calls])


@pytest.mark.parametrize("token", ["", None, "   ", "\n"])
def test_with_no_token_the_scan_is_anonymous_and_ignores_the_environment(monkeypatch, token):
    monkeypatch.setenv("GITHUB_TOKEN", "env-canary")
    world = one_repo({"Dockerfile": "FROM php:8.3.35\n"})
    assert len(scan_github_org("acme", token, world)) == 1
    assert world.calls
    for call in world.calls:
        assert "Authorization" not in call.headers
        assert "env-canary" not in json.dumps(call.headers)


def test_whitespace_around_a_token_is_dropped(fake_get):
    run(fake_get, token="  tok\n")
    assert {call.headers["Authorization"] for call in fake_get.calls} == {"Bearer tok"}


@pytest.mark.parametrize("token", ["a b", "a\tb", "tok\u00e9n", "a\x00b", "a\r\nX-Evil: 1",
                                   "to\u2028k"])
def test_a_token_that_cannot_go_in_a_header_is_refused_without_being_quoted(fake_get, token):
    with pytest.raises(ValueError) as caught:
        run(fake_get, token=token)
    assert token.strip() not in str(caught.value)
    assert repr(token) not in str(caught.value)
    assert fake_get.calls == []


def break_with_a_bad_token(world):
    world.script["/orgs/acme/repos"] = [reply(401, {"message": "Bad credentials"})]


def break_with_forbidden(world):
    world.script["/orgs/acme/repos"] = [reply(403, {"message": "Forbidden"})]


def break_with_not_found(world):
    world.script["/orgs/acme/repos"] = [reply(404, {"message": "Not Found"})]


def break_offline(world):
    world.script["/orgs/acme/repos"] = [TransportError("TimeoutError: timed out")]


def break_by_redirect_off_site(world):
    world.script["/orgs/acme/repos"] = [reply(302, b"", {"Location": "https://evil.example/x"})]


def break_by_rate_limit(world):
    world.script["/orgs/acme/repos"] = [
        limit({"x-ratelimit-remaining": "0", "x-ratelimit-reset": str(NOW + 3600)})]


def break_by_html(world):
    world.script["/orgs/acme/repos"] = [reply(200, b"<html>captive portal</html>")]


def break_a_tree(world):
    world.script["/repos/acme/web/git/trees/main"] = [reply(500, b"oops")]


def break_a_blob(world):
    sha = world.sha("web", "Dockerfile")
    world.script[f"/repos/acme/web/git/blobs/{sha}"] = [OSError("reset by peer")]


@pytest.mark.parametrize("break_it", [
    lambda world: None, break_with_a_bad_token, break_with_forbidden, break_with_not_found,
    break_offline, break_by_redirect_off_site, break_by_rate_limit, break_by_html, break_a_tree,
    break_a_blob])
def test_the_token_reaches_no_evidence_note_or_report(fake_get, matrix, break_it):
    break_it(fake_get)
    evs = run(fake_get, token=CANARY)
    assert CANARY not in repr(evs)
    inventory = AssetInventory()
    for ev in evs:
        inventory.add(ev)
    assets = inventory.assets()
    for rendered in (render_console(assets, matrix), render_json(assets, matrix),
                     render_sarif(assets, matrix)):
        assert CANARY not in rendered
    for call in fake_get.calls:
        assert all(CANARY not in value for name, value in call.headers.items()
                   if name != "Authorization")


def test_the_scan_has_no_way_to_read_the_environment_or_to_log():
    for module in (github_module, php_http):
        source = pathlib.Path(module.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source, feature_version=(3, 9))
        names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
        names |= {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add((node.module or "").split(".")[0])
        assert not names & {"environ", "environb", "getenv", "putenv", "print", "logging",
                            "warnings", "stderr", "stdout"}
        assert not imported & {"os", "sys", "logging", "warnings", "subprocess"}


def test_github_scanning_is_standard_library_only_and_parses_under_python_3_9():
    source = pathlib.Path(github_module.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source, feature_version=(3, 9))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])
    assert imported <= {"base64", "json", "string", "time", "typing", "urllib", "php_radar"}


# --- what is accepted as input ---

@pytest.mark.parametrize("org", ["", " ", "a b", "a/b", "..", ".", "a?b", "a#b", "a\n", "a:b",
                                 "a@b", "\u00e9", "a%2Fb", "x" * 101, None, 7])
def test_an_org_that_is_not_a_name_is_refused_before_any_request(fake_get, org):
    with pytest.raises(ValueError):
        scan_github_org(org, "t", fake_get)
    assert fake_get.calls == []


@pytest.mark.parametrize("org", ["acme", "Acme-Co", "a", "a.b_c-d", "x" * 100])
def test_an_org_name_is_taken_as_it_is_written(org):
    world = FakeGitHub(org=org)
    world.add_repo("web", {"Dockerfile": "FROM php:8.3.35\n"})
    (ev,) = scan_github_org(org, "t", world)
    assert ev.signals["repo"] == f"{org}/web"


# --- the helpers on their own ---

@pytest.mark.parametrize("name, ok", [
    ("acme", True), ("Acme-Co", True), ("a.b_c-d", True), ("x" * 100, True), ("1", True),
    ("", False), (".", False), ("..", False), ("a b", False), ("a/b", False), ("a\n", False),
    ("\u00e9", False), ("x" * 101, False), ("a%2Fb", False), ("a?b", False), (None, False),
    (5, False),
])
def test_is_name(name, ok):
    assert github_module._is_name(name) is ok


@pytest.mark.parametrize("url, ok", [
    ("https://api.github.com/orgs/acme/repos", True),
    ("https://api.github.com/", True),
    ("https://api.github.com", True),
    ("https://API.GITHUB.COM/orgs/acme/repos", True),
    ("https://api.github.com/repos/a/b?x=1#f", True),
    ("http://api.github.com/orgs/acme/repos", False),
    ("https://api.github.com:8443/orgs", False),
    ("https://api.github.com:443/orgs", False),
    ("https://api.github.com.evil.example/orgs", False),
    ("https://api.github.com@evil.example/orgs", False),
    ("https://evil.example@api.github.com/orgs", False),
    ("https://user:pw@api.github.com/orgs", False),
    ("https://api.github.com\\@evil.example/orgs", False),
    ("https://evil.example/https://api.github.com/orgs", False),
    ("https://xapi.github.com/orgs", False),
    ("https://api.github.com./orgs", False),
    ("https://github.com/orgs", False),
    ("https://raw.githubusercontent.com/a/b/main/Dockerfile", False),
    ("https://codeload.github.com/a/b/legacy.tar.gz/main", False),
    ("//evil.example/orgs", False),
    ("/orgs/acme/repos", False),
    ("orgs/acme/repos", False),
    ("ftp://api.github.com/orgs", False),
    ("file:///etc/passwd", False),
    ("javascript:alert(1)", False),
    ("https://[::1/", False),
    ("", False),
])
def test_is_api(url, ok):
    assert github_module._is_api(url) is ok


@pytest.mark.parametrize("header, want", [
    ('<https://api.github.com/x?page=2>; rel="next"', "https://api.github.com/x?page=2"),
    ('<https://api.github.com/x?page=2>; rel="next", <https://api.github.com/x?page=9>; rel="last"',
     "https://api.github.com/x?page=2"),
    ('<https://api.github.com/x?page=1>; rel="prev", <https://api.github.com/x?page=3>; rel="next"',
     "https://api.github.com/x?page=3"),
    ('<https://api.github.com/x?page=9>; rel="last", <https://api.github.com/x?page=2>; rel="next"',
     "https://api.github.com/x?page=2"),
    ('<https://api.github.com/x?page=2>;rel="next"', "https://api.github.com/x?page=2"),
    ('<https://api.github.com/x?page=2>; REL="Next"', "https://api.github.com/x?page=2"),
    ('<https://api.github.com/x?page=2>; rel=next', "https://api.github.com/x?page=2"),
    ('<https://api.github.com/x?page=2>; rel="prev next"', "https://api.github.com/x?page=2"),
    ('<https://api.github.com/x?page=2>; title="a"; rel="next"', "https://api.github.com/x?page=2"),
    ('<https://api.github.com/x?a=1,2>; rel="next"', "https://api.github.com/x?a=1,2"),
    ('<https://api.github.com/x?page=1>; rel="prev"', ""),
    ('<https://api.github.com/x?page=9>; rel="last"', ""),
    ('<https://api.github.com/x?page=2>; rel="nextish"', ""),
    ('<https://api.github.com/x?page=2>; rel=nextish', ""),
    ('<https://api.github.com/x?page=2>; title="rel=next"', ""),
    ("https://api.github.com/x?page=2; rel=next", ""),
    ("rel=next", ""),
    ("", ""),
])
def test_next_link(header, want):
    assert github_module._next_link(header) == want


@pytest.mark.parametrize("status, headers, body, want", [
    (200, {"retry-after": "5"}, b"", None),
    (500, {"retry-after": "5"}, b"", None),
    (404, {"x-ratelimit-remaining": "0"}, b"", None),
    (403, {}, b'{"message": "Forbidden"}', None),
    (403, {"retry-after": "7"}, b"", 7),
    (429, {"retry-after": "7"}, b"", 7),
    (403, {"Retry-After": "7"}, b"", 7),
    (403, {"retry-after": " 7 "}, b"", 7),
    (403, {"retry-after": "0"}, b"", 1),
    (403, {"x-ratelimit-remaining": "0", "x-ratelimit-reset": str(NOW + 30)}, b"", 31),
    (429, {"x-ratelimit-remaining": "0", "x-ratelimit-reset": str(NOW + 30)}, b"", 31),
    (403, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": str(NOW + 30)}, b"", 31),
    (403, {"x-ratelimit-remaining": "0", "x-ratelimit-reset": str(NOW - 500)}, b"", 1),
    (403, {"x-ratelimit-remaining": "0"}, b"", 60),
    (403, {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "soon"}, b"", 60),
    (403, {"x-ratelimit-remaining": "12", "x-ratelimit-reset": str(NOW + 30)}, b"", None),
    (403, {"retry-after": "7", "x-ratelimit-remaining": "0", "x-ratelimit-reset": str(NOW + 90)},
     b"", 7),
    (403, {}, b'{"message": "You have exceeded a secondary rate limit."}', 60),
    (403, {}, b'{"message": "API RATE LIMIT exceeded for user ID 1."}', 60),
    (403, {"retry-after": "soon"}, b"", None),
    (403, {"retry-after": "-5"}, b"", None),
    (403, {"retry-after": "1e3"}, b"", None),
    (403, {"retry-after": "nan"}, b"", None),
    (403, {"retry-after": "inf"}, b"", None),
    (403, {"retry-after": "\u00b2"}, b"", None),
    (403, {"retry-after": "9" * 40}, b"", None),
    (403, {"retry-after": "soon"}, b"rate limit", 60),
])
def test_limit_wait(status, headers, body, want):
    assert github_module._limit_wait(Response(status, headers, body)) == want


def mixed(status, headers, body=b""):
    # reply() lowercases the names, as http.get does. A get of someone else's may not.
    return Response(status, headers, body)


def test_the_headers_the_scan_reads_are_matched_whatever_their_case(slept):
    world = FakeGitHub()
    for name in "abc":
        world.add_repo(name, {"Dockerfile": "FROM php:8.3.35\n"})
    world.page_size = 2
    world.script["/orgs/acme/repos"] = [
        mixed(302, {"LOCATION": f"{API}/organizations/2/repos?per_page=2"})]
    world.script["/organizations/2/repos"] = [
        mixed(200, {"Link": f'<{API}/organizations/1/repos?per_page=2&page=2>; rel="next"'},
              json.dumps(world.listing[:2]).encode())]
    world.script["/repos/acme/a/git/trees/main"] = [
        mixed(403, {"Retry-After": "4"}, b"{}")]
    world.script["/repos/acme/b/git/trees/main"] = [
        mixed(403, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": str(NOW + 9)}, b"{}")]
    evs = run(world)
    assert sorted(e.signals["repo"] for e in evs) == ["acme/a", "acme/b", "acme/c"]
    assert slept == [4, 10]


# --- redirects ---

HOSTILE = [
    "https://evil.example/x",
    "http://api.github.com/orgs/acme/repos",
    "https://api.github.com.evil.example/orgs/acme/repos",
    "https://api.github.com@evil.example/orgs/acme/repos",
    "https://evil.example/https://api.github.com/orgs/acme/repos",
    "https://api.github.com:8443/orgs/acme/repos",
    "https://api.github.com\\@evil.example/orgs/acme/repos",
    "//evil.example/orgs/acme/repos",
    "https://raw.githubusercontent.com/acme/web/main/Dockerfile",
    "https://codeload.github.com/acme/web/legacy.tar.gz/main",
    "ftp://api.github.com/orgs/acme/repos",
    "file:///etc/passwd",
    "javascript:alert(1)",
]


@pytest.mark.parametrize("target", HOSTILE)
def test_a_redirect_off_api_github_com_is_not_followed_and_sends_no_token(fake_get, target):
    fake_get.script["/orgs/acme/repos"] = [reply(301, b"", {"Location": target})]
    evs = run(fake_get, token=CANARY)
    assert [c.url for c in fake_get.calls] == [f"{API}/orgs/acme/repos?per_page=100&sort=full_name"]
    (row,) = evs
    assert row.signals["repo"] == "acme" and row.signals["kind"] == "skipped"
    assert row.note.startswith("skipped: cannot list all the repositories (")
    assert "away from api.github.com" in row.note
    assert CANARY not in repr(evs)


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_a_redirect_within_api_github_com_is_followed_with_the_token(fake_get, status):
    fake_get.script["/orgs/acme/repos"] = [
        reply(status, b"", {"Location": f"{API}/organizations/1/repos?per_page=100"})]
    evs = run(fake_get, token=CANARY)
    assert len(digest(evs)) == 5
    first, second = fake_get.calls[:2]
    assert second.url == f"{API}/organizations/1/repos?per_page=100"
    assert first.headers["Authorization"] == second.headers["Authorization"] == "Bearer " + CANARY


def test_a_relative_redirect_is_resolved_against_the_request(fake_get):
    fake_get.script["/orgs/acme/repos"] = [
        reply(302, b"", {"Location": "/organizations/1/repos?per_page=100"})]
    assert len(digest(run(fake_get))) == 5
    assert fake_get.calls[1].url == f"{API}/organizations/1/repos?per_page=100"


def test_every_hop_of_a_redirect_is_checked_and_the_last_one_is_refused(fake_get):
    fake_get.script["/orgs/acme/repos"] = [
        reply(302, b"", {"Location": "/organizations/1/repos?per_page=100"})]
    fake_get.script["/organizations/1/repos"] = [
        reply(302, b"", {"Location": "https://evil.example/steal"})]
    (row,) = run(fake_get, token=CANARY)
    assert [c.path for c in fake_get.calls] == ["/orgs/acme/repos", "/organizations/1/repos"]
    assert "away from api.github.com" in row.note


def test_a_redirect_that_loops_stops_after_a_few_hops(fake_get):
    loop = reply(302, b"", {"Location": f"{API}/orgs/acme/repos"})
    fake_get.script["/orgs/acme/repos"] = [loop] * 50
    (row,) = run(fake_get)
    assert len(fake_get.calls) == github_module._MAX_HOPS + 1
    assert "too many redirects" in row.note


def test_a_redirect_with_no_place_to_go_is_a_failure(fake_get):
    fake_get.script["/orgs/acme/repos"] = [reply(302)]
    (row,) = run(fake_get)
    assert "names no place" in row.note
    assert len(fake_get.calls) == 1


@pytest.mark.parametrize("target", HOSTILE)
def test_a_file_that_redirects_off_site_is_recorded_and_the_scan_goes_on(target):
    world = one_repo({"Dockerfile": "FROM php:8.3.35\n",
                      "docker-compose.yml": "image: php:8.1.2\n"})
    sha = world.sha("web", "Dockerfile")
    world.script[f"/repos/acme/web/git/blobs/{sha}"] = [reply(302, b"", {"Location": target})]
    evs = run(world, token=CANARY)
    assert [(e.location, e.detected_version) for e in finds(evs)] == [
        ("docker-compose.yml", "8.1.2")]
    (row,) = skips(evs)
    assert (row.signals["repo"], row.location) == ("acme/web", "Dockerfile")
    assert "away from api.github.com" in row.note
    assert target not in [c.url for c in world.calls]


# --- pagination ---

def test_every_page_of_the_listing_is_read():
    world = FakeGitHub()
    for name in "abcde":
        world.add_repo(name, {"Dockerfile": "FROM php:8.3.35\n"})
    world.page_size = 2
    evs = run(world)
    assert sorted(e.signals["repo"] for e in evs) == [f"acme/{n}" for n in "abcde"]
    listing = [c.url for c in world.calls if c.path.endswith("/repos") and "git" not in c.path]
    assert listing == [f"{API}/orgs/acme/repos?per_page=100&sort=full_name",
                       f"{API}/organizations/1/repos?per_page=2&page=2",
                       f"{API}/organizations/1/repos?per_page=2&page=3"]


@pytest.mark.parametrize("target", HOSTILE)
def test_a_next_link_off_api_github_com_is_not_followed_and_sends_no_token(fake_get, target):
    fake_get.next_link = target
    evs = run(fake_get, token=CANARY)
    assert target not in [c.url for c in fake_get.calls]
    assert all(c.url.startswith(API + "/") for c in fake_get.calls)
    assert len(finds(evs)) == 5
    (row,) = skips(evs, "acme")
    assert "cannot list all the repositories" in row.note
    assert "away from api.github.com" in row.note
    assert CANARY not in repr(evs)


def test_the_listing_stops_at_the_page_cap_and_says_so(monkeypatch):
    monkeypatch.setattr(github_module, "_MAX_PAGES", 2)
    world = FakeGitHub()
    for name in "abcdef":
        world.add_repo(name, {"Dockerfile": "FROM php:8.3.35\n"})
    world.page_size = 2
    evs = run(world)
    assert sorted(e.signals["repo"] for e in finds(evs)) == [
        "acme/a", "acme/b", "acme/c", "acme/d"]
    (row,) = skips(evs, "acme")
    assert row.note == (
        "skipped: the list of repositories runs past 2 pages, and only those were read")
    assert sum(1 for p in world.paths if p.endswith("/repos") and "git" not in p) == 2


def test_a_listing_that_fails_on_a_later_page_keeps_the_pages_before_it():
    world = FakeGitHub()
    for name in "abcd":
        world.add_repo(name, {"Dockerfile": "FROM php:8.3.35\n"})
    world.page_size = 2
    world.script["/organizations/1/repos"] = [reply(502, b"bad gateway")]
    evs = run(world)
    assert sorted(e.signals["repo"] for e in finds(evs)) == ["acme/a", "acme/b"]
    (row,) = skips(evs, "acme")
    assert row.note == "skipped: cannot list all the repositories (HTTP 502)"


# --- rate limits ---

def test_a_retry_after_is_waited_out_and_the_request_repeated(fake_get, slept):
    fake_get.script["/orgs/acme/repos"] = [limit({"retry-after": "7"})]
    assert len(digest(run(fake_get))) == 5
    assert slept == [7]
    assert fake_get.paths[:2] == ["/orgs/acme/repos", "/orgs/acme/repos"]


def test_a_primary_limit_waits_until_the_reset_time(fake_get, slept):
    fake_get.script["/orgs/acme/repos"] = [
        limit({"x-ratelimit-remaining": "0", "x-ratelimit-reset": str(NOW + 45)}, status=429)]
    assert len(digest(run(fake_get))) == 5
    assert slept == [46]


def test_a_secondary_limit_with_no_times_waits_a_minute_and_then_longer(fake_get, slept):
    fake_get.script["/orgs/acme/repos"] = [
        limit({}, "You have exceeded a secondary rate limit."),
        limit({}, "You have exceeded a secondary rate limit.")]
    assert len(digest(run(fake_get))) == 5
    assert slept == [60, 120]


def test_the_waits_double_and_the_retries_are_bounded(fake_get, slept):
    fake_get.script["/orgs/acme/repos"] = [limit({"retry-after": "7"})] * 20
    (row,) = run(fake_get)
    assert slept == [7, 14, 28]
    assert len(fake_get.calls) == 4
    assert "still in force after 3 waits" in row.note


def test_a_wait_past_the_ceiling_is_not_taken_and_ends_the_scan(fake_get, slept):
    fake_get.script["/orgs/acme/repos"] = [
        limit({"x-ratelimit-remaining": "0", "x-ratelimit-reset": str(NOW + 3600)})]
    (row,) = run(fake_get)
    assert slept == []
    assert len(fake_get.calls) == 1
    assert row.signals["repo"] == "acme"
    assert "rate limit" in row.note


@pytest.mark.parametrize("asked, waits", [(120, [120]), (121, [])])
def test_a_wait_of_two_minutes_is_taken_and_one_second_more_is_not(fake_get, slept, asked, waits):
    fake_get.script["/orgs/acme/repos"] = [limit({"retry-after": str(asked)})]
    evs = run(fake_get)
    assert slept == waits
    assert (len(finds(evs)) == 5) is bool(waits)


def test_a_secondary_limit_that_keeps_coming_stops_before_its_wait_passes_the_ceiling(
        fake_get, slept):
    fake_get.script["/orgs/acme/repos"] = [limit({}, "secondary rate limit")] * 20
    run(fake_get)
    assert slept == [60, 120]
    assert len(fake_get.calls) == 3


def test_a_plain_403_is_not_a_rate_limit_and_is_not_retried(fake_get, slept):
    fake_get.script["/orgs/acme/repos"] = [reply(403, {"message": "Forbidden"})]
    (row,) = run(fake_get)
    assert slept == []
    assert len(fake_get.calls) == 1
    assert "HTTP 403" in row.note


def test_a_limit_hit_midway_keeps_what_was_read_and_marks_the_rest_unscanned(slept):
    world = FakeGitHub()
    for name in "abc":
        world.add_repo(name, {"Dockerfile": "FROM php:8.3.35\n"})
    world.script["/repos/acme/b/git/trees/main"] = [limit({"retry-after": "100000"})]
    evs = run(world)
    assert [(e.signals["repo"], e.location) for e in finds(evs)] == [("acme/a", "Dockerfile")]
    (second,) = skips(evs, "acme/b")
    (third,) = skips(evs, "acme/c")
    assert second.location == third.location == "."
    assert "not fully scanned" in second.note and "rate limit" in second.note
    assert "not scanned" in third.note and "rate limit" in third.note
    assert "/repos/acme/c/git/trees/main" not in world.paths
    assert slept == []


def test_a_limit_hit_inside_a_repository_keeps_the_files_already_read(slept):
    world = one_repo({"Dockerfile": "FROM php:8.3.35\n",
                      "docker-compose.yml": "image: php:8.1.2\n",
                      "docker/Dockerfile": "FROM php:8.2.5\n"})
    sha = world.sha("web", "docker-compose.yml")
    world.script[f"/repos/acme/web/git/blobs/{sha}"] = [limit({"retry-after": "100000"})]
    evs = run(world)
    assert [e.location for e in finds(evs)] == ["Dockerfile"]
    (row,) = skips(evs)
    assert (row.signals["repo"], row.location) == ("acme/web", ".")
    assert row.note.startswith("skipped: not fully scanned (the GitHub rate limit")
    assert world.fetched("web") == ["Dockerfile"]
    assert slept == []


def test_a_limit_hit_while_listing_leaves_the_listed_repositories_unscanned(slept):
    world = FakeGitHub()
    for name in "abcd":
        world.add_repo(name, {"Dockerfile": "FROM php:8.3.35\n"})
    world.page_size = 2
    world.script["/organizations/1/repos"] = [limit({"retry-after": "100000"})]
    evs = run(world)
    assert finds(evs) == []
    (listing,) = skips(evs, "acme")
    assert listing.note.startswith(
        "skipped: cannot list all the repositories (the GitHub rate limit")
    for name in "ab":
        (row,) = skips(evs, f"acme/{name}")
        assert row.note.startswith("skipped: not scanned (the GitHub rate limit")
    assert not [p for p in world.paths if "/git/" in p]
    assert slept == []


def test_a_limit_that_lifts_in_time_costs_nothing_but_the_wait(slept):
    world = FakeGitHub()
    for name in "abc":
        world.add_repo(name, {"Dockerfile": "FROM php:8.3.35\n"})
    world.script["/repos/acme/b/git/trees/main"] = [limit({"retry-after": "3"})]
    evs = run(world)
    assert skips(evs) == []
    assert len(evs) == 3
    assert slept == [3]


def test_each_request_gets_its_own_retries(slept):
    world = FakeGitHub()
    for name in "ab":
        world.add_repo(name, {"Dockerfile": "FROM php:8.3.35\n"})
        world.script[f"/repos/acme/{name}/git/trees/main"] = [limit({"retry-after": "5"})] * 3
    assert skips(run(world)) == []
    assert slept == [5, 10, 20, 5, 10, 20]


# --- a rejected token ---

def test_a_rejected_token_ends_the_scan_at_once(fake_get):
    fake_get.script["/orgs/acme/repos"] = [reply(401, {"message": "Bad credentials"})]
    (row,) = run(fake_get, token="nope")
    assert len(fake_get.calls) == 1
    assert row.signals["repo"] == "acme"
    assert "rejected the token" in row.note
    assert "nope" not in row.note


def test_a_token_revoked_midway_stops_the_requests():
    world = FakeGitHub()
    for name in "abc":
        world.add_repo(name, {"Dockerfile": "FROM php:8.3.35\n"})
    world.script["/repos/acme/b/git/trees/main"] = [reply(401, {"message": "Bad credentials"})]
    evs = run(world)
    assert "/repos/acme/c/git/trees/main" not in world.paths
    assert "rejected the token" in skips(evs, "acme/b")[0].note
    assert "not scanned" in skips(evs, "acme/c")[0].note


# --- no answer ---

@pytest.mark.parametrize("failure", [
    TransportError("TimeoutError: timed out"), OSError("boom"), ConnectionResetError("reset"),
    TimeoutError("slow"), socket.gaierror(11001, "getaddrinfo failed")])
def test_a_transport_error_on_the_listing_is_recorded_not_raised(fake_get, failure):
    fake_get.script["/orgs/acme/repos"] = [failure]
    (row,) = run(fake_get)
    assert row.signals["repo"] == "acme"
    assert row.signals["kind"] == "skipped"
    assert row.signals["php_present"] == "true"
    assert row.note.startswith("skipped: cannot list all the repositories (")
    assert len(fake_get.calls) == 1


def test_the_reason_of_a_transport_error_is_in_the_note(fake_get):
    fake_get.script["/orgs/acme/repos"] = [TransportError("TimeoutError: timed out")]
    assert "(TimeoutError: timed out)" in run(fake_get)[0].note
    fake_get.script["/orgs/acme/repos"] = [OSError("boom")]
    assert "(OSError: boom)" in run(fake_get)[0].note


def test_one_repository_that_cannot_be_listed_does_not_stop_the_others(fake_get):
    fake_get.script["/repos/acme/api/git/trees/main"] = [TransportError("ConnectionResetError: x")]
    evs = run(fake_get)
    assert {e.signals["repo"] for e in finds(evs)} == {"acme/web"}
    (row,) = skips(evs)
    assert (row.signals["repo"], row.location) == ("acme/api", ".")
    assert row.note == "skipped: cannot list its files (ConnectionResetError: x)"


def test_one_file_that_cannot_be_read_does_not_stop_the_others(fake_get):
    sha = fake_get.sha("web", "composer.json")
    fake_get.script[f"/repos/acme/web/git/blobs/{sha}"] = [
        TransportError("TimeoutError: timed out")]
    evs = run(fake_get)
    assert len(finds(evs)) == 4
    (row,) = skips(evs)
    assert (row.signals["repo"], row.location) == ("acme/web", "composer.json")
    assert row.note == "skipped: cannot read it (TimeoutError: timed out)"


def test_an_unread_file_holds_a_patched_repository_at_indeterminate(matrix):
    files = {"Dockerfile": "FROM php:8.3.36-fpm\n", "docker-compose.yml": "image: php:7.4.33\n"}
    assert grade_of(run(one_repo(files)), "acme/web", matrix) == (EXPOSED, HIGH)
    world = one_repo(files)
    sha = world.sha("web", "docker-compose.yml")
    world.script[f"/repos/acme/web/git/blobs/{sha}"] = [OSError("reset")]
    assert grade_of(run(world), "acme/web", matrix) == (INDETERMINATE, LOW)
    clean = one_repo({"Dockerfile": "FROM php:8.3.36-fpm\n"})
    assert grade_of(run(clean), "acme/web", matrix) == (LIKELY_PATCHED, HIGH)


def five_repositories_whose_trees_fail_with(failure):
    world = FakeGitHub()
    for name in "abcde":
        world.add_repo(name, {"Dockerfile": "FROM php:8.3.35\n"})
        world.script[f"/repos/acme/{name}/git/trees/main"] = [failure()]
    return world


def test_three_failures_in_a_row_end_the_scan():
    world = five_repositories_whose_trees_fail_with(lambda: OSError("down"))
    evs = run(world)
    assert github_module._MAX_MISSES == 3
    assert sum(1 for p in world.paths if p.endswith("/git/trees/main")) == 3
    assert sorted(e.signals["repo"] for e in skips(evs)) == [f"acme/{n}" for n in "abcde"]
    notes = {e.signals["repo"]: e.note for e in skips(evs)}
    assert notes["acme/a"] == "skipped: cannot list its files (OSError: down)"
    assert notes["acme/b"] == "skipped: cannot list its files (OSError: down)"
    assert notes["acme/c"] == "skipped: not fully scanned (GitHub keeps failing (OSError: down))"
    assert notes["acme/d"] == "skipped: not scanned (GitHub keeps failing (OSError: down))"
    assert notes["acme/e"] == "skipped: not scanned (GitHub keeps failing (OSError: down))"


@pytest.mark.parametrize("status", [500, 502, 503, 504, 599])
def test_three_server_errors_in_a_row_end_the_scan_as_well(status):
    world = five_repositories_whose_trees_fail_with(lambda: reply(status, {"message": "oops"}))
    evs = run(world)
    assert sum(1 for p in world.paths if p.endswith("/git/trees/main")) == 3
    notes = {e.signals["repo"]: e.note for e in skips(evs)}
    assert notes["acme/a"] == f"skipped: cannot list its files (HTTP {status})"
    assert notes["acme/c"] == (
        f"skipped: not fully scanned (GitHub keeps failing (HTTP {status}))")
    assert notes["acme/e"].startswith("skipped: not scanned (")


def test_no_answer_and_a_server_error_count_toward_the_same_end():
    world = FakeGitHub()
    for name in "abcde":
        world.add_repo(name, {"Dockerfile": "FROM php:8.3.35\n"})
    world.script["/repos/acme/a/git/trees/main"] = [OSError("down")]
    world.script["/repos/acme/b/git/trees/main"] = [reply(502, b"")]
    world.script["/repos/acme/c/git/trees/main"] = [OSError("down")]
    evs = run(world)
    assert "/repos/acme/d/git/trees/main" not in world.paths
    assert "not fully scanned" in skips(evs, "acme/c")[0].note


def test_an_answer_in_between_resets_the_count_of_failures():
    world = FakeGitHub()
    for name in "abcde":
        world.add_repo(name, {"Dockerfile": "FROM php:8.3.35\n"})
    for name in "ace":
        world.script[f"/repos/acme/{name}/git/trees/main"] = [OSError("down")]
    evs = run(world)
    assert sorted(e.signals["repo"] for e in finds(evs)) == ["acme/b", "acme/d"]
    assert {e.note for e in skips(evs)} == {"skipped: cannot list its files (OSError: down)"}
    assert len(skips(evs)) == 3


def test_a_server_error_between_answers_does_not_end_the_scan():
    world = FakeGitHub()
    for name in "abcde":
        world.add_repo(name, {"Dockerfile": "FROM php:8.3.35\n"})
    for name in "ace":
        world.script[f"/repos/acme/{name}/git/trees/main"] = [reply(500, b"")]
    evs = run(world)
    assert sorted(e.signals["repo"] for e in finds(evs)) == ["acme/b", "acme/d"]
    assert {e.note for e in skips(evs)} == {"skipped: cannot list its files (HTTP 500)"}


def test_a_client_error_is_not_a_failure_of_github():
    world = FakeGitHub()
    for name in "abcde":
        world.add_repo(name, {"Dockerfile": "FROM php:8.3.35\n"})
        world.script[f"/repos/acme/{name}/git/trees/main"] = [reply(404, {"message": "Not Found"})]
    evs = run(world)
    assert sum(1 for p in world.paths if p.endswith("/git/trees/main")) == 5
    assert len(skips(evs)) == 5
    assert all(e.note.startswith("skipped: cannot list its files") for e in skips(evs))


def test_a_failure_that_is_not_a_transport_failure_is_not_swallowed(fake_get):
    fake_get.script["/orgs/acme/repos"] = [RuntimeError("a bug in the caller")]
    with pytest.raises(RuntimeError):
        run(fake_get)


# --- answers that are not what GitHub documents ---

@pytest.mark.parametrize("body", [b"<html>captive portal</html>", b"", b"{", b"\xff\xfe", b'"text"',
                                  b"null", b'{"message": "x"}'])
def test_a_listing_that_is_not_a_list_is_recorded(fake_get, body):
    fake_get.script["/orgs/acme/repos"] = [reply(200, body)]
    (row,) = run(fake_get)
    assert row.note.startswith("skipped: cannot list all the repositories (")


def test_a_deeply_nested_answer_is_recorded_not_raised(fake_get):
    fake_get.script["/orgs/acme/repos"] = [reply(200, b"[" * 100_000)]
    (row,) = run(fake_get)
    assert row.note.startswith("skipped: cannot list all the repositories (")


@pytest.mark.parametrize("entry", [
    None, 5, "web", [], {}, {"name": "web"}, {"default_branch": "main"},
    {"name": "web", "default_branch": ""}, {"name": "web", "default_branch": None},
    {"name": "web", "default_branch": 5}, {"name": "..", "default_branch": "main"},
    {"name": "a/b", "default_branch": "main"}, {"name": "", "default_branch": "main"},
    {"name": 7, "default_branch": "main"}, {"name": "x" * 101, "default_branch": "main"},
])
def test_a_listing_entry_that_is_not_understood_is_counted_and_the_rest_are_read(entry):
    world = FakeGitHub()
    world.add_repo("web", {"Dockerfile": "FROM php:8.3.35\n"})
    world.listing.insert(0, entry)
    evs = run(world)
    assert [e.signals["repo"] for e in finds(evs)] == ["acme/web"]
    (row,) = skips(evs, "acme")
    assert row.note == "skipped: 1 entry in the list of repositories was not understood"


def test_several_entries_that_are_not_understood_are_counted_in_one_row():
    world = FakeGitHub()
    world.add_repo("web", {"Dockerfile": "FROM php:8.3.35\n"})
    world.listing[:0] = [None, 5, {}]
    (row,) = skips(run(world), "acme")
    assert row.note == "skipped: 3 entries in the list of repositories were not understood"


@pytest.mark.parametrize("tree", [
    b"<html>", b"[]", b'{"tree": "x"}', b'{"tree": null}', b'{"truncated": false}', b"5"])
def test_a_file_list_that_is_not_a_list_is_recorded_against_the_repository(tree):
    world = one_repo({"Dockerfile": "FROM php:8.3.35\n"})
    world.script["/repos/acme/web/git/trees/main"] = [reply(200, tree)]
    (row,) = run(world)
    assert (row.signals["repo"], row.location) == ("acme/web", ".")
    assert row.note.startswith("skipped: cannot list its files (")


@pytest.mark.parametrize("entry", [None, 5, "x", [], {}, {"path": "Dockerfile"},
                                   {"type": "blob"}, {"path": 5, "type": "blob"},
                                   {"path": "Dockerfile", "type": 5}])
def test_a_file_entry_that_is_not_understood_is_counted_and_the_rest_are_read(entry):
    world = one_repo({"Dockerfile": "FROM php:8.3.35\n"}, extra=[entry])
    evs = run(world)
    assert [e.location for e in finds(evs)] == ["Dockerfile"]
    (row,) = skips(evs)
    assert (row.signals["repo"], row.location) == ("acme/web", ".")
    assert row.note == "skipped: 1 entry in its file list was not understood"


@pytest.mark.parametrize("sha", [None, 5, "", "xyz", "g" * 40, "A" * 40, "a" * 39, "a" * 41,
                                 "../../x", "a" * 40 + "/x", "a" * 63, "a" * 65])
def test_a_file_entry_with_an_object_id_that_is_not_one_is_recorded_and_not_fetched(sha):
    world = one_repo({"Dockerfile": "FROM php:8.3.35\n"})
    world.trees["web"][1][0]["sha"] = sha
    (row,) = run(world)
    assert row.location == "Dockerfile"
    assert "object id" in row.note
    assert world.blob_log == []


@pytest.mark.parametrize("sha", ["a" * 40, "0123456789abcdef" * 4])
def test_the_object_id_of_a_sha_1_or_a_sha_256_repository_is_fetched(sha):
    world = one_repo({"Dockerfile": "FROM php:8.3.35\n"})
    world.trees["web"][1][0]["sha"] = sha
    world.blobs[sha] = b"FROM php:8.3.35\n"
    assert [e.detected_version for e in run(world)] == ["8.3.35"]


@pytest.mark.parametrize("blob", [
    b"<html>", b"[]", b'{"encoding": "base64"}', b'{"content": 5, "encoding": "base64"}',
    b'{"content": "aGk=", "encoding": "rot13"}', b'{"content": "aGk="}',
    b'{"content": "!!!", "encoding": "base64"}', b'{"content": "a", "encoding": "base64"}',
    b'{"content": "\xc3\xa9\xc3\xa9", "encoding": "base64"}'])
def test_a_blob_answer_that_cannot_be_decoded_is_recorded_against_the_file(blob):
    world = one_repo({"Dockerfile": "FROM php:8.3.35\n"})
    world.script[f"/repos/acme/web/git/blobs/{world.sha('web', 'Dockerfile')}"] = [reply(200, blob)]
    (row,) = run(world)
    assert (row.signals["repo"], row.location) == ("acme/web", "Dockerfile")
    assert row.note.startswith("skipped: cannot read it (")


def test_a_blob_encoded_without_line_breaks_reads_the_same():
    world = one_repo({"Dockerfile": "FROM php:8.3.35\n"})
    data = base64.b64encode(b"FROM php:8.3.35\n").decode()
    world.script[f"/repos/acme/web/git/blobs/{world.sha('web', 'Dockerfile')}"] = [
        reply(200, {"content": data, "encoding": "base64"})]
    assert [e.detected_version for e in run(world)] == ["8.3.35"]


def test_a_blob_with_a_byte_order_mark_or_utf_16_reads_like_a_file_on_disk():
    world = one_repo({
        "Dockerfile": b"\xef\xbb\xbfFROM php:8.3.35\n",
        "docker-compose.yml": "image: php:8.1.2\n".encode("utf-16"),
    })
    assert sorted(e.detected_version for e in run(world)) == ["8.1.2", "8.3.35"]


# --- files the scan will not fetch ---

def test_a_symbolic_link_is_recorded_and_not_followed(matrix):
    world = one_repo({"Dockerfile": "FROM php:8.3.36\n", "web/Dockerfile": "build/prod.docker"},
                     modes={"web/Dockerfile": "120000"})
    evs = run(world)
    (row,) = skips(evs)
    assert (row.signals["repo"], row.location) == ("acme/web", "web/Dockerfile")
    assert row.note == "skipped: it is a symbolic link, and links are not followed"
    assert row.signals["php_present"] == "true"
    assert world.fetched("web") == ["Dockerfile"]
    assert grade_of(evs, "acme/web", matrix) == (INDETERMINATE, LOW)


def test_a_link_with_a_name_the_scan_does_not_read_is_left_alone():
    world = one_repo({"Dockerfile": "FROM php:8.3.35\n", "link": "README.md"},
                     modes={"link": "120000"})
    assert skips(run(world)) == []


def test_a_file_over_the_size_cap_is_recorded_without_being_fetched():
    big = repo_module._MAX_BYTES + 1
    world = one_repo({"Dockerfile": "FROM php:8.3.35\n", "docker-compose.yml": "x"},
                     sizes={"docker-compose.yml": big})
    (row,) = skips(run(world))
    assert (row.location, row.note) == (
        "docker-compose.yml", f"skipped: it is larger than {repo_module._MAX_BYTES} bytes")
    assert world.fetched("web") == ["Dockerfile"]


def test_a_file_at_the_size_cap_is_fetched_and_one_a_byte_over_is_not():
    cap = repo_module._MAX_BYTES
    text = "FROM php:8.3.35\n"
    at = text + "#" * (cap - len(text))
    assert len(at) == cap
    assert [e.detected_version for e in run(one_repo({"Dockerfile": at}))] == ["8.3.35"]
    (row,) = run(one_repo({"Dockerfile": at + "#"}))
    assert "larger than" in row.note


def test_a_file_bigger_than_the_listing_said_is_recorded_when_it_arrives():
    cap = repo_module._MAX_BYTES
    world = one_repo({"Dockerfile": "FROM php:8.3.35\n" + "#" * cap}, sizes={"Dockerfile": 20})
    (row,) = run(world)
    assert row.note == f"skipped: it is larger than {cap} bytes"
    assert world.fetched("web") == ["Dockerfile"]


def test_a_listing_cut_short_by_github_is_recorded_and_what_it_holds_is_read(matrix):
    world = one_repo({"Dockerfile": "FROM php:8.3.36\n"}, truncated=True)
    evs = run(world)
    (row,) = skips(evs)
    assert (row.signals["repo"], row.location) == ("acme/web", ".")
    assert "cut short" in row.note
    assert [e.location for e in finds(evs)] == ["Dockerfile"]
    assert grade_of(evs, "acme/web", matrix) == (INDETERMINATE, LOW)


def test_a_complete_listing_leaves_no_row_about_truncation():
    assert skips(run(one_repo({"Dockerfile": "FROM php:8.3.35\n"}, truncated=False))) == []


def test_a_repository_with_more_files_than_the_cap_is_read_shallowest_first(monkeypatch):
    monkeypatch.setattr(github_module, "_MAX_FILES", 3)
    world = one_repo({
        "deep/er/est/Dockerfile": "FROM php:8.0.1\n",
        "a/b/Dockerfile": "FROM php:8.1.1\n",
        "a/Dockerfile": "FROM php:8.2.1\n",
        "Dockerfile": "FROM php:8.3.1\n",
        ".php-version": "8.4.1\n",
        "z/.tool-versions": "php 8.5.1\n",
    })
    evs = run(world)
    assert sorted(world.fetched("web")) == [".php-version", "Dockerfile", "a/Dockerfile"]
    (row,) = skips(evs)
    assert (row.signals["repo"], row.location) == ("acme/web", ".")
    assert row.note == "skipped: it holds 6 files the scan reads, and only the first 3 were read"


def test_a_repository_at_the_file_cap_is_read_whole(monkeypatch):
    monkeypatch.setattr(github_module, "_MAX_FILES", 2)
    world = one_repo({"Dockerfile": "FROM php:8.3.35\n", ".php-version": "8.3.35\n"})
    assert skips(run(world)) == []
    assert len(world.fetched("web")) == 2


def test_an_empty_repository_leaves_no_evidence_and_no_row():
    world = FakeGitHub()
    world.add_repo("empty", {}, empty=True)
    world.add_repo("web", {"Dockerfile": "FROM php:8.3.35\n"})
    assert [e.signals["repo"] for e in run(world)] == ["acme/web"]


def test_a_409_that_is_not_an_empty_repository_is_recorded():
    world = one_repo({"Dockerfile": "FROM php:8.3.35\n"})
    world.script["/repos/acme/web/git/trees/main"] = [reply(409, {"message": "Conflict"})]
    (row,) = run(world)
    assert row.note == "skipped: cannot list its files (HTTP 409)"


@pytest.mark.parametrize("status, why", [
    (404, "HTTP 404, not found, or hidden from this token"),
    (403, "HTTP 403, forbidden"),
    (500, "HTTP 500"),
    (502, "HTTP 502"),
    (422, "HTTP 422"),
    (304, "HTTP 304"),
])
def test_a_status_other_than_200_is_recorded_with_its_code_and_nothing_the_server_said(
        status, why):
    world = one_repo({"Dockerfile": "FROM php:8.3.35\n"})
    world.script["/repos/acme/web/git/trees/main"] = [reply(status, {"message": "secret text"})]
    (row,) = run(world)
    assert row.note == f"skipped: cannot list its files ({why})"


# --- what the reports make of it ---

def test_repository_ids_survive_the_redactor_whatever_the_name_says():
    for name in ("token-service", "auth-api", "api_key_rotator", "secret-santa", "DB_PASS"):
        assert redact(f"acme/{name}") == f"acme/{name}"
    world = FakeGitHub(org="token-org")
    world.add_repo("auth-api", {"Dockerfile": "FROM php:8.3.35\n"})
    evs = scan_github_org("token-org", "t", world)
    assert [e.signals["repo"] for e in evs] == ["token-org/auth-api"]


def test_the_reports_show_the_repository_and_a_repository_relative_path(fake_get, matrix):
    inventory = AssetInventory()
    for ev in run(fake_get):
        inventory.add(ev)
    assets = inventory.assets()
    console = render_console(assets, matrix)
    assert "acme/web (repo)" in console and "acme/api (repo)" in console
    assert "[REDACTED]" not in console
    document = json.loads(render_json(assets, matrix))
    assert sorted(row["key"] for row in document["assets"]) == ["acme/api", "acme/web"]
    sarif = json.loads(render_sarif(assets, matrix))
    uris = {w["physicalLocation"]["artifactLocation"]["uri"]
            for r in sarif["runs"][0]["results"]
            for w in r["locations"] + r.get("relatedLocations", [])}
    assert uris == {".php-version", "docker-compose.yml", ".github/workflows/ci.yml", "Dockerfile",
                    "composer.json"}


def test_the_grader_reads_a_github_repository_like_a_local_one(matrix):
    def verdict(dockerfile):
        return grade_of(run(one_repo({"Dockerfile": dockerfile})), "acme/web", matrix)

    assert verdict("FROM php:8.3.35-fpm\n") == (EXPOSED, HIGH)
    assert verdict("FROM php:8.3.36-fpm\n") == (LIKELY_PATCHED, HIGH)
    assert verdict("FROM php:8.3-apache\n") == (INDETERMINATE, LOW)


def test_a_failure_to_list_shows_in_the_report_as_an_indeterminate_asset(fake_get, matrix):
    fake_get.script["/orgs/acme/repos"] = [reply(404, {"message": "Not Found"})]
    inventory = AssetInventory()
    for ev in run(fake_get):
        inventory.add(ev)
    console = render_console(inventory.assets(), matrix)
    assert "INDETERMINATE (1)" in console
    assert "acme (repo)" in console
    assert ("cannot list all the repositories (HTTP 404, not found, or hidden from this token)"
            in console)
    assert "[REDACTED]" not in console


# --- over a real connection ---

def start_github(loopback, world, monkeypatch):
    def relay(path, headers):
        answer = world(world.base + path, headers, 0)
        return answer.status, list(answer.headers.items()), answer.body

    server = loopback(relay)
    world.base = server.url
    monkeypatch.setattr(github_module, "_API", server.url)
    return server


def test_a_scan_over_a_real_connection_reads_what_the_fake_gives(loopback, monkeypatch, fake_get):
    expected = digest(run(acme()))
    server = start_github(loopback, fake_get, monkeypatch)
    evs = scan_github_org("acme", "t")
    assert digest(evs) == expected
    assert len(server.seen) == len(fake_get.calls) >= 8
    assert {headers["authorization"] for _, headers in server.seen} == {"Bearer t"}


def test_a_redirect_off_site_over_a_real_connection_sends_nothing_to_the_other_host(
        loopback, monkeypatch, fake_get):
    elsewhere = loopback(lambda path, headers: (200, [], b"[]"))
    server = start_github(loopback, fake_get, monkeypatch)
    fake_get.script["/orgs/acme/repos"] = [
        reply(302, b"", {"Location": elsewhere.url + "/orgs/acme/repos"})]
    evs = scan_github_org("acme", CANARY)
    assert elsewhere.seen == []
    assert len(server.seen) == 1
    (row,) = evs
    assert "away from api.github.com" in row.note
    assert CANARY not in repr(evs)


def test_a_redirect_within_the_api_over_a_real_connection_is_followed_with_the_token(
        loopback, monkeypatch, fake_get):
    server = start_github(loopback, fake_get, monkeypatch)
    fake_get.script["/orgs/acme/repos"] = [
        reply(301, b"", {"Location": "/organizations/1/repos?per_page=100"})]
    assert len(digest(scan_github_org("acme", "t"))) == 5
    assert [path for path, _ in server.seen][:2] == [
        "/orgs/acme/repos?per_page=100&sort=full_name", "/organizations/1/repos?per_page=100"]
    assert {headers["authorization"] for _, headers in server.seen} == {"Bearer t"}


def test_a_listing_over_a_real_connection_follows_its_pages(loopback, monkeypatch):
    world = FakeGitHub()
    for name in "abcde":
        world.add_repo(name, {"Dockerfile": "FROM php:8.3.35\n"})
    world.page_size = 2
    start_github(loopback, world, monkeypatch)
    evs = scan_github_org("acme", "t")
    assert sorted(e.signals["repo"] for e in evs) == [f"acme/{n}" for n in "abcde"]


def test_a_dead_host_over_a_real_connection_is_recorded(monkeypatch):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    monkeypatch.setattr(github_module, "_API", f"http://127.0.0.1:{port}")
    (row,) = scan_github_org("acme", CANARY)
    assert row.signals["repo"] == "acme"
    assert row.note.startswith("skipped: cannot list all the repositories (")
    assert CANARY not in repr(row)
