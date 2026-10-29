"""Reads a Google Cloud project, read-only, and reports where PHP runs.

GcpSource(clients).inventory() looks at the App Engine versions, the Cloud Functions, and the
Artifact Registry images of a project and returns one CLOUD Evidence for each that runs or holds
PHP. It makes six calls and every one is a read: ListServices, ListVersions, ListFunctions,
ListLocations, ListRepositories, and ListDockerImages. A role that allows those is all the access
it uses.

The clients are the way in. Their credentials come from Application Default Credentials and are
used when a call goes out, so this module takes no key as an argument and never asks a client for
one. From each answer it copies the few fields it names, because a version or a function record
carries the values of its environment variables. A failed call is recorded by the class of its
error. The message stays out. It can name the caller's account or repeat part of the request.

No service reports a PHP build, so PHP is found by name, and each find carries what the name gave.
An App Engine runtime called php83 gives the branch, 8.3. A flexible version keeps its version in
a setting. That is read first. A Cloud Functions runtime called php82 gives 8.2. An image tag
gives a version when it names one. In a repository, or on an image, called php, the official
image's tags do (8.3.12-fpm). Anywhere else the tag has to say php (php8.3, php-8.3.12).

Only a full 8.3.12 hands the grader a build to compare. A branch grades INDETERMINATE, because the
PHP2Shell fix landed in a patch release of each branch. A full number in a tag counts unless what
follows it reads as a distro revision or a pre-release, by the grader's own test, and then the tag
gives the branch alone.

Every tag of an Artifact Registry repository carries the repository's name, so the tags of one
repository fold into one asset whose verdict is the worst of them, and each tag keeps its own
evidence line. A function of the 2nd generation runs on a Cloud Run service. Its row names that
service in cloudrun_service.

Nothing is skipped quietly. A failed call, a listing that runs past its limit, a location the API
could not reach, and an entry that cannot be read each leave a row. The row has the reason in note
and kind skipped, as the repo scan marks its own, and with no PHP in it the row grades
INDETERMINATE at LOW. A failure inside a repository that already showed PHP leaves a row that says
PHP is there, so a repository read only in part is never cleared by the part that was read. Three
repositories in a row that cannot be listed end the Artifact Registry read. One answer leaves no
row. A project with no App Engine application answers not found to the first listing, and that is
a finished read when the credentials name a quota project. Without one, an App Engine Admin API
that is switched off answers not found too. The answer then says nothing about the application,
and it leaves a row.

Limits. A run reads one project at a time, the clients' own unless projects says otherwise. PHP
that does not say so by name goes unseen: a custom App Engine runtime, or an image whose tags
never say php. A tag is a label somebody typed. The image behind it may never run. A tag that can
be pushed again may point at another build tomorrow. The SDK's own timeouts and retries apply.

Cloud Run is deferred. Its container images surface through Artifact Registry, and a function of
the 2nd generation already appears through Cloud Functions. Reading Cloud Run itself will have to
merge with that row.

It has been run read-only against a live project, which held no PHP, so no find has been seen
live. The tests answer from stand-ins written by hand, and the field names come from the API's
published definitions. The SDK is an optional install that this module never imports.
"""
from collections import Counter
from typing import Any, Callable, Iterable, Iterator, NamedTuple, Optional, Union

from php_radar.model import Evidence, Sapi, Source
from php_radar.sources.cloud._common import (
    _BRANCH, _MAX_MISSES, _MAX_TAG, _NAME, _PATH, _Stop, _entries, _fits, _gap, _iterable,
    _number, _repo_gap, _tag_note, _tag_version, _unread, _where)
# The repo scan reads a SAPI out of an image tag. Using its reader keeps a cloud read in step with
# it.
from php_radar.sources.repo import _sapi

# Entries read from one listing. A listing past this is cut and says so, which also ends a service
# that keeps handing back a page token.
_MAX_ENTRIES = 100_000

# The page size asked of Artifact Registry, its largest. The other services choose their own.
_PAGE = 1000

# The longest value of each kind taken from an answer. No resource name or image URI comes near
# 1024 characters, and the limit keeps one odd answer from putting a page of text in a report row.
_MAX_NAME = 1024
_MAX_TEXT = 256

# Names under a project scoped to a domain (example.com:my-project) carry its colon. An image URI
# has a colon in its digest, after an @.
_PROJECT = _NAME | frozenset(":")
_RESOURCE = _PATH | frozenset(":")
_URI = _PATH | frozenset(":@")

# What an entry of each list lacks when it cannot be read. The row that counts the entries says so,
# because a dropped entry is a puzzle otherwise.
_UNREAD = {"services": "no usable name", "versions": "no usable name",
           "functions": "no usable name", "locations": "no usable id",
           "repositories": "no usable name", "images": "no usable tag"}

# A person meets these first, and the class name alone says too little. Google's error classes are
# optional here, so an error is known by the name of its class.
_DENIED = "access was denied, or the API is not enabled in the project"
_KNOWN = {"PermissionDenied": _DENIED, "Forbidden": _DENIED,
          "RefreshError": "the Google credentials could not be refreshed"}


class _Repo(NamedTuple):
    name: str  # what every find in the repository carries as its resource
    official: bool  # php is the last part of the name, as in a mirror of the official image


def _is(exc: Exception, name: str) -> bool:
    return any(cls.__name__ == name for cls in type(exc).__mro__)


def _why(exc: Exception) -> str:
    """What to record about a failed call: the error's class, with a plain word for common ones.

    The message is left out. It can name the caller's account, or repeat part of the request.
    """
    name = type(exc).__name__
    return f"{_KNOWN[name]} ({name})" if name in _KNOWN else name


def _name(value: object, prefix: str) -> Optional[str]:
    # A resource name starts with the collection it is in. It becomes the identity of an asset and
    # goes into a report line, so it has to be a short run of path characters.
    return value if _fits(value, _RESOURCE, _MAX_NAME) and value.startswith(prefix) else None


def _walk(answer: Any, items: Optional[str], lost: list) -> Iterator[object]:
    """The entries of an answer. What its pages name as unreachable goes into lost.

    A pager with items named is read page by page. It passes any other attribute on to the latest
    page it fetched, so once the last entry is read only the last page's list is left to ask.
    """
    pages = getattr(answer, "pages", None) if items else None
    if pages is None:
        if not _iterable(answer):
            raise _Stop("the answer is not understood")
        yield from answer
        return
    for page in pages:
        lost.extend(_entries(getattr(page, "unreachable", None)) or ())
        found = _entries(getattr(page, items, None))
        if found is None:
            raise _Stop("the answer is not understood")
        yield from found


def _listing(call: Callable[..., Any], request: dict, *, items: Optional[str] = None,
             missing_ok: bool = False) -> Iterator[object]:
    """Each entry that call returns for the request, over every page its pager reads.

    The request goes in as a dict, which every client method takes. Only some declare a flattened
    argument such as parent. A pager fetches pages as it is read, so a call can fail at any entry.
    A failure ends the listing with _Stop, once the entries already read have been handed over.
    A call that raises is one. So is an answer that is not a list, and so is a listing past the
    limit. missing_ok turns an answer of not found into an empty listing, but only before the
    first entry. Later it means a page could not be fetched.

    A list across locations says on each page which locations it could not reach. items names the
    field that holds the entries, and the pages are then read one by one, so that no page's list
    is missed. A location named on any page is a failure at the end, because the entries are then
    only part of the answer.
    """
    count = 0
    lost: list = []
    try:
        answer = call(request=request)
        for entry in _walk(answer, items, lost):
            if count == _MAX_ENTRIES:
                raise _Stop(f"the list runs past {_MAX_ENTRIES} entries")
            count += 1
            yield entry
        if lost:
            names = sorted({x.rpartition("/")[2] for x in lost if _fits(x, _RESOURCE, _MAX_TEXT)})
            raise _Stop("the API could not reach " + (", ".join(names[:10]) or "some locations"))
    except _Stop:
        raise
    except Exception as exc:  # google-api-core is optional, so its errors cannot be named
        if missing_ok and count == 0 and _is(exc, "NotFound"):
            return
        raise _Stop(_why(exc)) from None


# --- the runtime of a version or a function ---

def _branch(text: object) -> Optional[str]:
    # A full number is cut to its branch, because a runtime label or setting does not fix the build.
    number = _number(text) if _fits(text, _NAME, _MAX_TEXT) else None
    return number.rpartition(".")[0] if number and number.count(".") == 2 else number


def _php_runtime(label: object, setting: object = None) -> Optional[tuple[Optional[str], str]]:
    """(branch or None, note) for a runtime that names PHP, or None for any other runtime.

    App Engine and Cloud Functions write the label as php83 for 8.3. A flexible App Engine version
    keeps its version in a setting instead, and the setting wins when it holds one.
    """
    if not (_fits(label, _NAME, _MAX_TEXT) and label.lower().startswith("php")):
        return None
    given = _branch(setting)
    digits = label[3:]
    branch = given or (_branch(f"{digits[0]}.{digits[1:]}")
                       if len(digits) > 1 and digits.isdigit() else None)
    if branch is None:
        return None, f"runtime {label} names PHP, and the build is not read"
    return branch, _BRANCH.format(f"runtime {label} {given}" if given else f"runtime {label}")


def _runtime_find(service: str, name: str, php: tuple[Optional[str], str],
                  more: Optional[dict] = None) -> Evidence:
    number, note = php
    signals = {"resource": name, "service": service, "php_present": "true"}
    signals.update(more or {})
    return Evidence(Source.CLOUD, name, number, Sapi.UNKNOWN, signals, note)


# --- App Engine ---

def _appengine(clients: Any, project: str, odd: Counter) -> Iterator[Evidence]:
    # A project with no application answers not found, and that is no failure, when the
    # credentials name a quota project. Without one, an App Engine Admin API that is switched off
    # answers not found too, and the answer cannot be taken for no application.
    quota = getattr(clients, "quota_project", None)
    for service in _listing(clients.app_engine_services.list_services,
                            {"parent": f"apps/{project}"}, missing_ok=bool(quota)):
        parent = _name(getattr(service, "name", None), "apps/")
        if parent is None:
            odd["services"] += 1
            continue
        for version in _listing(clients.app_engine_versions.list_versions, {"parent": parent}):
            name = _name(getattr(version, "name", None), "apps/")
            if name is None:
                odd["versions"] += 1
                continue
            # The SDK's message may lack the settings, and a flexible version is the only one to
            # hold a runtime version. Read by name, a missing one reads as no setting.
            settings = getattr(version, "flexible_runtime_settings", None)
            php = _php_runtime(getattr(version, "runtime", None),
                               getattr(settings, "runtime_version", None))
            if php is not None:
                yield _runtime_find("appengine", name, php)


# --- Cloud Functions ---

def _functions(clients: Any, project: str, odd: Counter) -> Iterator[Evidence]:
    # The - stands for every location.
    for fn in _listing(clients.functions.list_functions,
                       {"parent": f"projects/{project}/locations/-"}, items="functions"):
        name = _name(getattr(fn, "name", None), "projects/")
        if name is None:
            odd["functions"] += 1
            continue
        php = _php_runtime(getattr(getattr(fn, "build_config", None), "runtime", None))
        if php is None:
            continue
        more = {}
        # A function of the 2nd generation is a Cloud Run service underneath. Its name is kept for
        # the day Cloud Run is read and the two rows have to become one asset.
        run = _name(getattr(getattr(fn, "service_config", None), "service", None), "projects/")
        if run is not None:
            more["cloudrun_service"] = run
        yield _runtime_find("cloudfunctions", name, php, more)


# --- Artifact Registry ---

def _locations(client: Any, project: str, odd: Counter) -> Iterator[str]:
    """The id of each location the project reports, in the order they come."""
    try:
        answer = client.list_locations(request={"name": f"projects/{project}"})
    except Exception as exc:  # google-api-core is optional, so its errors cannot be named
        raise _Stop(_why(exc)) from None
    found = _entries(getattr(answer, "locations", None))
    if found is None:
        raise _Stop("the answer is not understood")
    for entry in found:
        ident = getattr(entry, "location_id", None)
        if _fits(ident, _NAME, _MAX_TEXT):
            yield ident
        else:
            odd["locations"] += 1
    # The locations come in one answer, so a page token means some were left behind.
    if getattr(answer, "next_page_token", ""):
        raise _Stop("the list of locations runs past one page")


def _repository(item: object) -> Optional[_Repo]:
    name = _name(getattr(item, "name", None), "projects/")
    return None if name is None else _Repo(name, name.rpartition("/")[2] == "php")


def _is_docker(item: object) -> bool:
    # Only a Docker repository holds images, and a project has repositories of every other format.
    # The format is an SDK enum, so it is matched by name. One that does not say its format is
    # tried anyway: a field read wrongly then costs a row, where a skip would cost the registry.
    kind = getattr(item, "format_", getattr(item, "format", None))
    return kind is None or getattr(kind, "name", kind) in ("DOCKER", 1)


def _images(repo: _Repo, image: object, odd: Counter) -> Iterator[Evidence]:
    tags = _entries(getattr(image, "tags", None))
    if tags is None:
        odd["images"] += 1
        return
    uri = getattr(image, "uri", None)
    # The URI ends in the digest of the image. A tag points at the image without it.
    base = uri.partition("@")[0] if _fits(uri, _URI, _MAX_NAME) else repo.name
    # A gcr.io path has no repository called php in it, so the image path counts as well.
    official = repo.official or base.rpartition("/")[2] == "php"
    for tag in tags:
        if not _fits(tag, _NAME, _MAX_TAG):
            odd["images"] += 1
            continue
        number = _tag_version(tag, official)
        if number is not None:
            signals = {"resource": repo.name, "service": "artifactregistry",
                       "php_present": "true"}
            yield Evidence(Source.CLOUD, f"{base}:{tag}", number, _sapi(tag.lower()), signals,
                           _tag_note(number))


def _registry(clients: Any, project: str, odd: Counter) -> Iterator[Evidence]:
    client = clients.artifact_registry
    misses = 0
    for location in _locations(client, project, odd):
        request = {"parent": f"projects/{project}/locations/{location}", "page_size": _PAGE}
        for item in _listing(client.list_repositories, request):
            repo = _repository(item)
            if repo is None:
                odd["repositories"] += 1
                continue
            if not _is_docker(item):
                continue
            saw_php = False
            try:
                for image in _listing(client.list_docker_images,
                                      {"parent": repo.name, "page_size": _PAGE}):
                    for ev in _images(repo, image, odd):
                        saw_php = True
                        yield ev
            except _Stop as stop:
                misses += 1
                yield _repo_gap("artifactregistry", repo.name, repo.name, str(stop), saw_php)
                if misses == _MAX_MISSES:
                    raise _Stop(f"{_MAX_MISSES} repositories in a row could not be read") from None
            else:
                misses = 0


_READERS = (("appengine", _appengine), ("cloudfunctions", _functions),
            ("artifactregistry", _registry))


class GcpSource:
    """The PHP in a Google Cloud project, read through the SDK's clients.

    clients is any object with the four clients as attributes: app_engine_services and
    app_engine_versions (the ServicesClient and VersionsClient of appengine_admin_v1), functions
    (the FunctionServiceClient of functions_v2), and artifact_registry (the ArtifactRegistryClient
    of artifactregistry_v1). Its project attribute, when it has one, is the project of the
    credentials. Its quota_project attribute, when it has one, is their quota project. A bundle
    that lacks it, or leaves it empty, names no quota project. An answer of not found from App
    Engine is then a failure and no finished read. projects is the project to read as an id, or
    several as a list, a tuple, or any iterator of ids. It is the clients' own by default and when
    it is empty. The projects read are kept in projects, so a caller can say what was covered.
    inventory() reads afresh each time it is called.
    """

    def __init__(self, clients: Any,
                 projects: Union[str, Iterable[Optional[str]], None] = None) -> None:
        self._clients = clients
        if isinstance(projects, str):
            # One id is one project. Read as a sequence it would be one project for each letter.
            # An empty id is no project, so it leaves the clients' own.
            projects = [projects] if projects else None
        self.projects = tuple(projects or ()) or (getattr(clients, "project", None),)

    def inventory(self) -> list[Evidence]:
        """One Evidence for each App Engine version, Cloud Function, and image tag that names PHP.
        Whatever could not be read leaves a row in the same list."""
        found: list[Evidence] = []
        for project in self.projects:
            for service, read in _READERS:
                found += self._read(service, project, read)
        return found

    def _read(self, service: str, project: Optional[str],
              read: Callable[[Any, str, Counter], Iterator[Evidence]]) -> list[Evidence]:
        found: list[Evidence] = []
        usable = _fits(project, _PROJECT, _MAX_TEXT)
        # An id that is no name stays out of the label, which goes into a report line.
        where = _where("gcp", service, project if usable else None)
        odd: Counter = Counter()  # entries that could not be read, by the list they came from
        try:
            if not usable:
                raise _Stop("the project id is not usable" if project
                            else "no GCP project is configured")
            for ev in read(self._clients, project, odd):
                found.append(ev)
        except _Stop as stop:
            found.append(_gap(service, where, str(stop)))
        # After the stop as well, so a count is never lost to a failure that comes later.
        found.extend(_unread(service, where, count, what, _UNREAD[what])
                     for what, count in odd.items())
        return found
