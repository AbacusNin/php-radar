"""GcpSource against stand-ins for the four SDK clients. No SDK, no network, no credentials.

The SDK is an optional install. The source never imports it, so these tests need none. A stand-in
has the shape the SDK hands back, because a stand-in of the wrong shape is how a defect hides. A
listing comes back as a generated pager, which fetches pages as it is read, can fail partway, and
passes any other attribute on to the latest page it fetched. The list of locations comes back as
a raw protobuf response, whose repeated field has no __iter__. An error keeps the class and the
parents that google-api-core and google-auth give it. The source cannot import the class, so it
records the name. The field names follow the API's published messages. A few tests build real
protobuf messages from googleapis-common-protos and are skipped without it. No test here has run
against a live project.
"""
import ast
import enum
import itertools
import json
import pathlib
import random
import re
import subprocess
import sys
from collections import abc
from types import SimpleNamespace as NS
from typing import NamedTuple

import pytest

from php_radar.knowledge import DATA_PATH, grade, grade_evidence, load_matrix
from php_radar.model import AssetInventory, Confidence, Evidence, Sapi, Source, Verdict
from php_radar.report import render_console, render_json, render_sarif
from php_radar.sources.cloud import CloudSource, gcp
from php_radar.sources.cloud.gcp import GcpSource

MATRIX = load_matrix(DATA_PATH)
ROOT = pathlib.Path(__file__).resolve().parent.parent

# Stands for anything a response holds that the source has no business copying: an environment
# variable of a function, an exception message. It is not token-shaped, so the report's redactor
# would let it through if it ever got that far.
SECRET = "hunter2-" + "CANARY-gcp"

# Characters outside ASCII, by name, so that this file stays plain ASCII.
E_ACUTE = "\N{LATIN SMALL LETTER E WITH ACUTE}"
BIDI = "\N{RIGHT-TO-LEFT OVERRIDE}"
DASHES_AND_QUOTES = ("\N{EM DASH}\N{EN DASH}\N{LEFT SINGLE QUOTATION MARK}"
                     "\N{RIGHT SINGLE QUOTATION MARK}\N{LEFT DOUBLE QUOTATION MARK}"
                     "\N{RIGHT DOUBLE QUOTATION MARK}")

PROJECT = "my-project"
OTHER = "other-project"
QUOTA = "quota-project"  # the project that credentials with a quota project charge their calls to
APP = f"apps/{PROJECT}"
SERVICE = f"{APP}/services/default"
VERSION = f"{SERVICE}/versions/v1"
FN = f"projects/{PROJECT}/locations/us-central1/functions/legacy-api"
RUN = f"projects/{PROJECT}/locations/us-central1/services/legacy-api"
REPO = f"projects/{PROJECT}/locations/us/repositories/php"
IMAGE = f"us-docker.pkg.dev/{PROJECT}/php/php"  # the php image in the repository called php
DIGEST = "sha256:" + "0" * 64
DENIED = "access was denied, or the API is not enabled in the project"

# The only calls the source may make, with the keys of the request each may send. Each one reads.
# The request goes in as a dict, which every SDK method takes. Only some have a parent argument of
# their own, so the stand-ins refuse one.
REQUESTS = {"list_services": {"parent"}, "list_versions": {"parent"},
            "list_functions": {"parent"}, "list_locations": {"name"},
            "list_repositories": {"parent", "page_size"},
            "list_docker_images": {"parent", "page_size"}}
READS = set(REQUESTS)

# The field that holds the entries on the response to each listing. A scripted list comes back as
# a pager over that field. list_locations has none, because its answer is a raw response.
FIELDS = {"list_services": "services", "list_versions": "versions",
          "list_functions": "functions", "list_repositories": "repositories",
          "list_docker_images": "docker_images"}

SIGNAL_KEYS = {"resource", "service", "php_present", "kind", "cloudrun_service"}
SERVICES = ("appengine", "cloudfunctions", "artifactregistry")

Format = enum.IntEnum(
    "Format", "FORMAT_UNSPECIFIED DOCKER MAVEN NPM APT YUM GOOGET PYTHON", start=0)


# --- stand-ins ---
# Each has the shape the SDK hands back. An error keeps the class and the parents that
# google-api-core and google-auth give it. A generated pager reads page by page and passes any
# other attribute on to the latest page it fetched. The raw response to a list of locations holds
# its repeated field in a container that has a length and an index and no __iter__.

class GoogleAPICallError(Exception):
    pass


class ClientError(GoogleAPICallError):
    pass


class ServerError(GoogleAPICallError):
    pass


class Forbidden(ClientError):
    pass


class PermissionDenied(Forbidden):
    pass


class NotFound(ClientError):
    pass


class ServiceUnavailable(ServerError):
    pass


class GoogleAuthError(Exception):
    pass


class RefreshError(GoogleAuthError):
    pass


class Call(NamedTuple):
    method: str
    kwargs: dict


# What a scripted method hands back once its answers run out.
_END = object()


class SequenceOnly:
    """A repeated field of a raw protobuf response under the default (upb) backend.

    It has a length and an index and no __iter__. So hasattr(field, "__iter__") is False, and
    iter(field) still works through the index. The backend registers its containers as mutable
    sequences, so isinstance(field, collections.abc.Iterable) finds them.
    """

    def __init__(self, entries):
        self._entries = list(entries)

    def __len__(self):
        return len(self._entries)

    def __getitem__(self, at):
        return self._entries[at]


abc.MutableSequence.register(SequenceOnly)


class Pager:
    """Stands in for a generated SDK pager.

    The call that makes a pager fetches its first page, so that response is held from the start.
    The pages property yields the latest response and fetches the rest as it is read. Iterating
    reads the entries of every page. Any other attribute comes from the latest response, which
    after a full read is the last page, so the fields of page one are gone by then.

    field names the entries on a response, and pages holds the entries of each page. unreachable
    holds the list each page names, for a response that has one. fail_at is the index of the page
    whose fetch raises error. The page before it carries a page token, as a response does when
    more is to come.
    """

    def __init__(self, field, pages, unreachable=None, fail_at=None, error=None):
        self._field, self._fail_at, self._error = field, fail_at, error
        self._responses = []
        for at, entries in enumerate(pages):
            more = at < len(pages) - 1 or at + 1 == fail_at
            # A page that is not a list stands for a response with something else in the field.
            held = list(entries) if isinstance(entries, (list, tuple)) else entries
            response = NS(**{field: held, "next_page_token": "more" if more else ""})
            if unreachable is not None:
                response.unreachable = unreachable[at] if at < len(unreachable) else []
            self._responses.append(response)
        self._at = 0
        self._response = self._responses[0]

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        return getattr(self._response, name)

    @property
    def pages(self):
        yield self._response
        while self._response.next_page_token:
            self._at += 1
            if self._at == self._fail_at:
                raise self._error
            self._response = self._responses[self._at]
            yield self._response

    def __iter__(self):
        for page in self.pages:
            yield from getattr(page, self._field)


def locations_answer(entries, token=""):
    """The raw response to a list of locations, with the container protobuf makes."""
    return NS(locations=SequenceOnly(entries), next_page_token=token)


class Client:
    """One SDK client of a World. Only the reads of its service exist."""

    def __init__(self, world, name, reads):
        self._world, self._name, self._reads = world, name, reads

    def __getattr__(self, attr):
        if attr in self._reads:
            return lambda **kw: self._world.read(attr, kw)
        self._world.touched.append(f"{self._name}.{attr}")
        raise AttributeError(attr)


class World:
    """The bundle of clients the source takes, answering from what a test stubbed.

    project is the default project, as the Application Default Credentials give it. quota_project
    is the project they charge calls to, or None for credentials that name none. The default names
    one, which is the setup where an answer of not found from App Engine means no application.
    page is how many entries one page of a listing holds, or None for a single page. Anything the
    source touches on the bundle or on a client beyond the four clients, the project, the quota
    project, and the six reads lands in touched and raises, so a test can see it.
    """

    def __init__(self, project=PROJECT, quota_project=QUOTA):
        self.touched = []
        self.project = project
        self.quota_project = quota_project
        self.page = None
        self.calls = []  # every call made on a client, in order
        self.location_ids = []  # what list_locations reports
        self.location_token = ""
        self.unreachable_by_page = []  # what each page of list_functions lists as unreachable
        self._script = {}  # method -> iterator of raw answers, or exceptions to raise
        self._fail = []  # [method, exception, calls to let through first, parent or None]
        self._services, self._versions, self._functions = {}, {}, {}
        self._repos, self._images = {}, {}
        self.app_engine_services = Client(self, "app_engine_services", {"list_services"})
        self.app_engine_versions = Client(self, "app_engine_versions", {"list_versions"})
        self.functions = Client(self, "functions", {"list_functions"})
        self.artifact_registry = Client(
            self, "artifact_registry",
            {"list_locations", "list_repositories", "list_docker_images"})

    def __getattr__(self, name):
        self.touched.append(name)
        raise AttributeError(name)

    def read(self, method, kw):
        self.calls.append(Call(method, dict(kw)))
        if set(kw) != {"request"}:
            raise TypeError(f"{method} takes its request as a dict and nothing else")
        request = kw["request"]
        if not isinstance(request, dict) or set(request) - REQUESTS[method]:
            raise TypeError(f"{method} does not take {request!r}")
        for rule in self._fail:
            if rule[0] == method and rule[3] in (None, request.get("parent")):
                if rule[2] > 0:
                    rule[2] -= 1
                else:
                    raise rule[1]
        scripted = self._script.get(method)
        if scripted is not None:
            answer = next(scripted, _END)
            if isinstance(answer, BaseException):
                raise answer
            if answer is _END:
                answer = [] if method in FIELDS else locations_answer([])
            if isinstance(answer, list) and method in FIELDS:
                answer = self._pager(method, answer)
            return answer
        return getattr(self, "_" + method)(request)

    # What the clients answer from.

    def _pager(self, method, entries, **kw):
        size = self.page or max(len(entries), 1)
        pages = [entries[at:at + size] for at in range(0, len(entries), size)] or [[]]
        return Pager(FIELDS[method], pages, **kw)

    def _list_services(self, request):
        return self._pager("list_services", self._services.get(request["parent"], []))

    def _list_versions(self, request):
        return self._pager("list_versions", self._versions.get(request["parent"], []))

    def _list_functions(self, request):
        return self._pager("list_functions", self._functions.get(request["parent"], []),
                           unreachable=self.unreachable_by_page)

    def _list_locations(self, request):
        return locations_answer(
            [NS(name=f"{request['name']}/locations/{ident}", location_id=ident,
                display_name=SECRET) for ident in self.location_ids],
            self.location_token)

    def _list_repositories(self, request):
        return self._pager("list_repositories", self._repos.get(request["parent"], []))

    def _list_docker_images(self, request):
        parent = request["parent"]
        if parent not in self._images:
            raise NotFound(f"404 {parent} {SECRET}")
        return self._pager("list_docker_images", self._images[parent])

    # What a test can stub.

    def stub_service(self, service="default", project=None):
        app = f"apps/{project or self.project}"
        record = NS(name=f"{app}/services/{service}", id=service, labels={"k": SECRET})
        self._services.setdefault(app, []).append(record)
        return record

    def stub_version(self, runtime, service="default", version="v1", project=None, **fields):
        project = project or self.project
        parent = f"apps/{project}/services/{service}"
        if not any(s.name == parent for s in self._services.get(f"apps/{project}", [])):
            self.stub_service(service, project)
        record = NS(name=f"{parent}/versions/{version}", id=version, runtime=runtime,
                    env="standard", env_variables={"DB_PASSWORD": SECRET},
                    beta_settings={"k": SECRET}, service_account=SECRET,
                    version_url=f"https://{version}-dot-{service}-dot-{project}.appspot.com",
                    flexible_runtime_settings=NS(operating_system="", runtime_version=""))
        record.__dict__.update(fields)
        self._versions.setdefault(parent, []).append(record)
        return record

    def stub_function(self, name, runtime="php82", location="us-central1", project=None,
                      service="", **fields):
        project = project or self.project
        record = NS(
            name=f"projects/{project}/locations/{location}/functions/{name}",
            description=SECRET, environment=2, state=1,
            build_config=NS(runtime=runtime, entry_point="main",
                            environment_variables={"B": SECRET}),
            service_config=NS(service=service, uri=f"https://{name}-abc-uc.a.run.app",
                              environment_variables={"DB_PASSWORD": SECRET}))
        record.__dict__.update(fields)
        self._functions.setdefault(f"projects/{project}/locations/-", []).append(record)
        return record

    def stub_repository(self, name, images=(), location="us", project=None, fmt=Format.DOCKER,
                        prefix=None):
        """A repository and its images. images is a list of (image path, tags) pairs.

        prefix goes before the image path in a URI. A gcr.io path has no repository there.
        """
        project = project or self.project
        parent = f"projects/{project}/locations/{location}"
        repo = NS(name=f"{parent}/repositories/{name}", format_=fmt, mode=1, description=SECRET)
        prefix = prefix or f"{location}-docker.pkg.dev/{project}/{name}"
        self._repos.setdefault(parent, []).append(repo)
        self._images[repo.name] = [
            NS(name=f"{repo.name}/dockerImages/{path.replace('/', '%2F')}@{DIGEST}",
               uri=f"{prefix}/{path}@{DIGEST}", tags=list(tags), update_time=SECRET)
            for path, tags in images]
        if location not in self.location_ids:
            self.location_ids.append(location)
        return repo

    def script(self, method, answers):
        """Answers calls to method from answers, in order. An exception in the list is raised.

        A list comes back as a pager over its entries, as a listing does. Anything else comes
        back as given. After the last answer a call gets an empty listing.
        """
        self._script[method] = iter(answers)

    def fail(self, method, exc, skip=0, parent=None):
        self._fail.append([method, exc, skip, parent])


@pytest.fixture
def world():
    return World()


def inventory(world, **kw):
    return GcpSource(world, **kw).inventory()


def only(world, **kw):
    (found,) = inventory(world, **kw)
    return found


def only_one(evs):
    (ev,) = evs
    return ev


def text_of(evidence):
    return repr(evidence)


def asked(world, method):
    """The parent of each call to method, in order."""
    return [c.kwargs["request"]["parent"] for c in world.calls if c.method == method]


def rendered(evs):
    inv = AssetInventory()
    for ev in evs:
        inv.add(ev)
    assets = inv.assets()
    return [render_console(assets, MATRIX), render_json(assets, MATRIX),
            render_sarif(assets, MATRIX)]


def stubbed_everything(world):
    world.stub_version("php83")
    world.stub_function("legacy-api", service=RUN)
    world.stub_repository("php", [("php", ["8.3.36-fpm"])])


def repo_name(name, location="us"):
    return f"projects/{PROJECT}/locations/{location}/repositories/{name}"


# --- an App Engine version ---

def test_an_app_engine_version_on_a_php_runtime_becomes_evidence(world):
    world.stub_version("php83")
    ev = only(world)
    assert ev.source is Source.CLOUD
    assert ev.location == VERSION
    assert ev.detected_version == "8.3"
    assert ev.sapi is Sapi.UNKNOWN
    assert ev.signals == {"resource": VERSION, "service": "appengine", "php_present": "true"}
    assert ev.note == "runtime php83 names only the PHP branch, so the build is not read"
    assert grade_evidence(ev, MATRIX) == (Verdict.INDETERMINATE, Confidence.MEDIUM)


@pytest.mark.parametrize("runtime", [
    "python312", "nodejs20", "go122", "java21", "ruby33", "python", "custom", "nophp", "x-php83",
    "", " php83", "php83 ", "caf" + E_ACUTE + "php", None, 5, ["php83"]])
def test_a_runtime_that_is_not_php_leaves_no_row(world, runtime):
    world.stub_version(runtime)
    assert inventory(world) == []


# (runtime label, the runtime_version setting of a flexible version, the branch it gives)
RUNTIMES = [
    ("php83", None, "8.3"), ("php82", "", "8.2"), ("php85", None, "8.5"), ("php81", None, "8.1"),
    ("php74", None, "7.4"), ("php72", None, "7.2"), ("php55", None, "5.5"), ("PHP83", None, "8.3"),
    # A flexible environment keeps its version in a setting, and that wins when it is one.
    ("php", "8.5", "8.5"), ("php", "8.3", "8.3"), ("php83", "8.4", "8.4"),
    # A full number is cut to its branch, because a setting does not fix the build.
    ("php", "8.3.12", "8.3"),
    # A setting that is no version leaves the label to speak.
    ("php83", "latest", "8.3"), ("php83", "8", "8.3"), ("php83", "10.1", "8.3"),
    ("php83", 5, "8.3"), ("php83", "8.3 ", "8.3"),
    # PHP by name and no version anywhere.
    ("php", None, None), ("php", "", None), ("php", "latest", None), ("php8", None, None),
    ("php10", None, None), ("phpmyadmin", None, None),
]


@pytest.mark.parametrize("runtime,setting,branch", RUNTIMES)
def test_a_php_runtime_gives_its_branch_from_the_setting_or_else_the_label(
        world, runtime, setting, branch):
    world.stub_version(runtime, flexible_runtime_settings=NS(
        operating_system="ubuntu22", runtime_version=setting))
    ev = only(world)
    assert ev.detected_version == branch
    assert ev.signals["php_present"] == "true"
    assert ev.note.startswith(f"runtime {runtime}")
    if branch is None:
        assert ev.note == f"runtime {runtime} names PHP, and the build is not read"
    else:
        assert ev.note.endswith("names only the PHP branch, so the build is not read")
    assert grade_evidence(ev, MATRIX) == (Verdict.INDETERMINATE, Confidence.MEDIUM)


def test_a_flexible_version_names_the_version_it_took_from_its_setting(world):
    world.stub_version("php", flexible_runtime_settings=NS(
        operating_system="ubuntu22", runtime_version="8.5"))
    assert only(world).note == "runtime php 8.5 names only the PHP branch, so the build is not read"


@pytest.mark.parametrize("settings", [None, NS(), "8.5", 5, ["8.5"], NS(runtime_version=None)])
def test_a_setting_the_message_lacks_or_holds_oddly_reads_as_no_setting(world, settings):
    world.stub_version("php83", flexible_runtime_settings=settings)
    assert only(world).detected_version == "8.3"


def test_a_message_with_no_flexible_settings_field_reads_from_its_label(world):
    record = world.stub_version("php83")
    del record.flexible_runtime_settings
    assert only(world).detected_version == "8.3"


def test_every_service_is_asked_for_its_versions_and_only_the_php_ones_are_found(world):
    world.stub_version("php83", service="default", version="v1")
    world.stub_version("python312", service="default", version="v2")
    world.stub_version("php74", service="api", version="v7")
    world.stub_version("nodejs20", service="web", version="v1")
    evs = inventory(world)
    assert [(e.signals["resource"], e.detected_version) for e in evs] == [
        (f"{APP}/services/default/versions/v1", "8.3"), (f"{APP}/services/api/versions/v7", "7.4")]
    got = asked(world, "list_versions")
    assert got == [f"{APP}/services/{name}" for name in ("default", "api", "web")]


def test_two_versions_stay_two_assets(world):
    world.stub_version("php83", version="v1")
    world.stub_version("php83", version="v2")
    inv = AssetInventory()
    for ev in inventory(world):
        inv.add(ev)
    assert len(inv.assets()) == 2


def test_a_project_with_no_app_engine_application_has_nothing_to_read(world):
    # The API answers not found when the project has no application, and that is no failure.
    world.fail("list_services", NotFound(f"404 Not found: {APP} {SECRET}"))
    assert inventory(world) == []


def test_a_subclass_of_not_found_means_the_same(world):
    class ApplicationNotFound(NotFound):
        pass

    world.fail("list_services", ApplicationNotFound(SECRET))
    assert inventory(world) == []


def test_not_found_with_a_quota_project_on_the_credentials_is_no_application_and_no_row(world):
    # On the live run, a switched-off App Engine Admin API answered PermissionDenied once the
    # credentials named a quota project. So not found is taken to mean there is no application,
    # and a project with no application stays quiet.
    world.quota_project = QUOTA
    world.fail("list_services", NotFound(f"404 Not found: {APP} {SECRET}"))
    assert inventory(world) == []


@pytest.mark.parametrize("quota", [None, ""])
def test_not_found_with_no_quota_project_on_the_credentials_is_a_row_and_not_a_clean_read(
        world, quota):
    # On the live run, with no quota project, a switched-off App Engine Admin API answered not
    # found, as a project with no application does. The two cannot be told apart, and reading the
    # answer as no application would pass a service that was never read. So it is a failure like
    # any other, and the other two services are still read.
    stubbed_everything(world)
    world.quota_project = quota
    world.fail("list_services", NotFound(f"404 Not found: {APP} {SECRET}"))
    evs = inventory(world)
    gaps = [e for e in evs if e.signals.get("kind") == "skipped"]
    assert [g.note for g in gaps] == ["not inventoried: NotFound"]
    (gap,) = gaps
    assert gap.source is Source.CLOUD
    assert gap.location == f"gcp appengine {PROJECT}"
    assert gap.detected_version is None
    assert gap.signals == {"service": "appengine", "kind": "skipped"}
    assert grade_evidence(gap, MATRIX) == (Verdict.INDETERMINATE, Confidence.LOW)
    assert {e.signals["service"] for e in evs} == set(SERVICES)
    assert len(evs) == 3
    assert SECRET not in text_of(evs)


def test_a_bundle_that_does_not_name_a_quota_project_reads_as_having_none(world):
    # A bundle that cannot say what its credentials charge to gets no benefit of the doubt.
    del world.quota_project
    world.fail("list_services", NotFound(SECRET))
    assert [e.note for e in inventory(world)] == ["not inventoried: NotFound"]


def test_credentials_with_no_quota_project_still_read_an_application_that_answers(world):
    # Only an answer of not found is in doubt. Versions that were listed are found as before.
    world.quota_project = None
    world.stub_version("php83")
    assert only(world).detected_version == "8.3"


def test_an_empty_listing_with_no_quota_project_is_still_a_clean_read(world):
    # A listing that came back empty was read. It is not the answer of not found.
    world.quota_project = None
    world.script("list_services", [[]])
    assert inventory(world) == []


@pytest.mark.parametrize("entries", [1, 2])
def test_not_found_after_a_service_was_read_is_a_failure_and_no_empty_listing(world, entries):
    # Only an answer of not found before the first entry means there is no application. Later it
    # means a page could not be fetched, and the services after it would be lost without a word.
    world.stub_version("php83")
    services = [NS(name=SERVICE), NS(name=f"{APP}/services/api")][:entries]
    pager = Pager("services", [services], fail_at=1, error=NotFound(SECRET))
    world.script("list_services", [pager])
    found, gap = inventory(world)
    assert found.signals["service"] == "appengine"
    assert gap.note == "not inventoried: NotFound"
    assert gap.location == f"gcp appengine {PROJECT}"


@pytest.mark.parametrize("method", ["list_versions", "list_functions", "list_locations"])
def test_not_found_anywhere_but_the_first_app_engine_listing_is_a_failure_like_any_other(
        world, method):
    world.stub_version("php83")
    world.fail(method, NotFound(SECRET))
    gaps = [e for e in inventory(world) if e.signals.get("kind") == "skipped"]
    assert [g.note for g in gaps] == ["not inventoried: NotFound"]


SERVICE_UNREAD = ("not inventoried: 1 entry in the list of services could not be read "
                  "(no usable name)")
VERSION_UNREAD = ("not inventoried: 1 entry in the list of versions could not be read "
                  "(no usable name)")


def odd_entries(prefix):
    """Entries that a listing of the collection starting with prefix can hold and the source
    cannot use. Each one that is an object would be a find if its name were good."""
    names = [None, "", 42, "not/" + prefix, prefix.rstrip("/"), prefix + "x y",
             prefix + "x\nINJECTED", prefix + "caf" + E_ACUTE, prefix + "a" * 1020,
             prefix.capitalize() + "x", prefix + "x%2Fy"]
    return [None, 42, "x", [], {}, NS()] + [
        NS(name=name, runtime="php83", build_config=NS(runtime="php82")) for name in names]


ODD_APPS = odd_entries("apps/")
ODD_PROJECTS = odd_entries("projects/")


@pytest.mark.parametrize("entry", ODD_APPS)
def test_a_service_with_no_usable_name_is_counted_and_never_asked_for_versions(world, entry):
    good = world.stub_version("php83")
    world.script("list_services", [[entry, NS(name=SERVICE)]])
    found, gap = inventory(world)
    assert found.location == good.name
    assert gap.note == SERVICE_UNREAD
    got = asked(world, "list_versions")
    assert got == [SERVICE]


@pytest.mark.parametrize("entry", ODD_APPS)
def test_a_version_with_no_usable_name_is_counted_and_never_emitted(world, entry):
    good = world.stub_version("php83")
    world.script("list_versions", [[entry, good]])
    found, gap = inventory(world)
    assert found.location == good.name
    assert gap.note == VERSION_UNREAD


def test_the_name_of_a_project_scoped_to_a_domain_is_a_usable_name(world):
    name = "apps/example.com:my-project/services/default/versions/v1"
    world.stub_version("php83", name=name)
    assert only(world).location == name


# --- a Cloud Function ---

def test_a_function_on_a_php_runtime_becomes_evidence(world):
    world.stub_function("legacy-api", runtime="php82")
    ev = only(world)
    assert ev.source is Source.CLOUD
    assert ev.location == FN
    assert ev.detected_version == "8.2"
    assert ev.sapi is Sapi.UNKNOWN
    assert ev.signals == {"resource": FN, "service": "cloudfunctions", "php_present": "true"}
    assert ev.note == "runtime php82 names only the PHP branch, so the build is not read"
    assert grade_evidence(ev, MATRIX) == (Verdict.INDETERMINATE, Confidence.MEDIUM)


@pytest.mark.parametrize("runtime", [
    "nodejs20", "python312", "go122", "java21", "dotnet8", "ruby33", "", None, 5, "x-php82",
    ["php82"]])
def test_a_function_on_another_runtime_leaves_no_row(world, runtime):
    world.stub_function("fn", runtime=runtime)
    assert inventory(world) == []


@pytest.mark.parametrize("config", [None, NS(), "php82", 5, ["php82"]])
def test_a_function_with_no_readable_build_config_leaves_no_row(world, config):
    world.stub_function("fn", build_config=config)
    assert inventory(world) == []


def test_every_location_is_asked_for_at_once_with_the_wildcard(world):
    world.stub_function("a", location="us-central1")
    world.stub_function("b", location="europe-west1", runtime="php81")
    world.stub_function("c", location="asia-east1", runtime="nodejs20")
    evs = inventory(world)
    assert [(e.location.split("/")[3], e.detected_version) for e in evs] == [
        ("us-central1", "8.2"), ("europe-west1", "8.1")]
    got = asked(world, "list_functions")
    assert got == [f"projects/{PROJECT}/locations/-"]


def test_a_second_generation_function_names_the_cloud_run_service_it_runs_on(world):
    world.stub_function("legacy-api", service=RUN)
    assert only(world).signals == {
        "resource": FN, "service": "cloudfunctions", "php_present": "true", "cloudrun_service": RUN}


@pytest.mark.parametrize("service", [
    "", None, 5, "legacy-api", "services/legacy-api", RUN + " x", RUN + "\nINJECTED",
    "projects/caf" + E_ACUTE, "projects/" + "a" * 1020, [RUN]])
def test_a_service_name_that_is_not_one_is_left_out_and_the_function_is_still_found(
        world, service):
    world.stub_function("legacy-api", service=service)
    ev = only(world)
    assert ev.signals == {"resource": FN, "service": "cloudfunctions", "php_present": "true"}


FUNCTION_UNREAD = ("not inventoried: 1 entry in the list of functions could not be read "
                   "(no usable name)")


@pytest.mark.parametrize("entry", ODD_PROJECTS)
def test_a_function_with_no_usable_name_is_counted_and_never_emitted(world, entry):
    good = world.stub_function("good")
    world.script("list_functions", [[entry, good]])
    found, gap = inventory(world)
    assert found.location == good.name
    assert gap.note == FUNCTION_UNREAD


def test_locations_the_api_says_it_could_not_reach_are_a_row_after_the_functions_it_read(world):
    world.stub_function("legacy-api")
    world.unreachable_by_page = [[f"projects/{PROJECT}/locations/us-east5",
                                  f"projects/{PROJECT}/locations/europe-west9"]]
    found, gap = inventory(world)
    assert found.location == FN
    assert gap.location == f"gcp cloudfunctions {PROJECT}"
    assert gap.note == "not inventoried: the API could not reach europe-west9, us-east5"


def test_a_location_unreachable_on_an_early_page_still_leaves_a_row(world):
    # A pager passes any other attribute on to the latest page it fetched, so after a full read
    # the unreachable list of page one is gone. A location that was down while page one was built
    # and back for page two has to leave its row all the same.
    world.page = 1
    world.stub_function("a")
    world.stub_function("b", location="europe-west1")
    world.unreachable_by_page = [[f"projects/{PROJECT}/locations/us-east5"], []]
    first, second, gap = inventory(world)
    assert [first.detected_version, second.detected_version] == ["8.2", "8.2"]
    assert gap.note == "not inventoried: the API could not reach us-east5"
    assert gap.location == f"gcp cloudfunctions {PROJECT}"


def test_what_every_page_lists_as_unreachable_is_pooled_and_named_once(world):
    world.page = 1
    for name in "abc":
        world.stub_function(name)
    us, eu = (f"projects/{PROJECT}/locations/{where}" for where in ("us-east5", "europe-west9"))
    # The last page names only one of the two, so reading it alone would miss the other.
    world.unreachable_by_page = [[us], [eu, us], [eu]]
    *found, gap = inventory(world)
    assert len(found) == 3
    assert gap.note == "not inventoried: the API could not reach europe-west9, us-east5"


def test_the_pager_stand_in_passes_attributes_to_the_latest_page_as_the_sdks_do():
    # The fixture the early-page test depends on. After a full read only the last page speaks.
    pager = Pager("functions", [[1], [2]], unreachable=[["x"], []])
    assert pager.unreachable == ["x"]
    assert list(pager) == [1, 2]
    assert pager.unreachable == []
    assert pager.next_page_token == ""
    with pytest.raises(AttributeError):
        pager.nothing


@pytest.mark.parametrize("lost", [["a b", 5, None], ["x" * 300], "us-east5", 5, [[]]])
def test_unreachable_locations_that_cannot_be_named_still_leave_a_row(world, lost):
    world.stub_function("legacy-api")
    world.unreachable_by_page = [lost]
    found, *rest = inventory(world)
    # A bare string or a number is no list of locations, so only a list of entries counts.
    if isinstance(lost, list):
        (gap,) = rest
        assert gap.note == "not inventoried: the API could not reach some locations"
    else:
        assert rest == []


def test_no_unreachable_locations_leave_no_row(world):
    world.stub_function("legacy-api")
    world.unreachable_by_page = [[]]
    assert len(inventory(world)) == 1


@pytest.mark.parametrize("held", [None, 5, "fn", NS()])
def test_a_page_whose_entries_are_no_list_ends_the_listing_with_a_row(world, held):
    world.script("list_functions", [Pager("functions", [held])])
    assert only(world).note == "not inventoried: the answer is not understood"


def test_a_page_that_lacks_the_field_of_its_entries_ends_the_listing_with_a_row(world):
    world.script("list_functions", [Pager("something_else", [[]])])
    assert only(world).note == "not inventoried: the answer is not understood"


def test_a_page_that_cannot_be_fetched_ends_the_functions_with_a_row_and_keeps_the_ones_read(
        world):
    first, second = world.stub_function("a"), world.stub_function("b")
    pager = Pager("functions", [[first], [second]], unreachable=[[], []], fail_at=1,
                  error=ServiceUnavailable(SECRET))
    world.script("list_functions", [pager])
    found, gap = inventory(world)
    assert found.location == first.name
    assert gap.note == "not inventoried: ServiceUnavailable"


# --- an Artifact Registry repository ---

def test_an_image_tag_in_the_php_repository_gives_its_version_and_sapi(world):
    world.stub_repository("php", [("php", ["8.3.12-fpm"])])
    ev = only(world)
    assert ev.source is Source.CLOUD
    assert ev.location == IMAGE + ":8.3.12-fpm"
    assert ev.detected_version == "8.3.12"
    assert ev.sapi is Sapi.FPM
    assert ev.signals == {"resource": REPO, "service": "artifactregistry", "php_present": "true"}
    assert ev.note == "version read from the image tag"
    assert grade_evidence(ev, MATRIX) == (Verdict.EXPOSED, Confidence.HIGH)


def test_a_latest_tag_names_no_version_and_leaves_no_row(world):
    world.stub_repository("php", [("php", ["latest"])])
    assert inventory(world) == []


# (repository, image path, tag, version it names or None, SAPI)
TAGS = [
    # The official image's tags, in a repository called php or on an image called php.
    ("php", "php", "8.3.12", "8.3.12", Sapi.UNKNOWN),
    ("php", "php", "8.3.12-fpm", "8.3.12", Sapi.FPM),
    ("php", "php", "8.3.12-apache", "8.3.12", Sapi.MOD_PHP),
    ("php", "php", "8.3.12-cli-alpine3.20", "8.3.12", Sapi.CLI),
    ("php", "php", "5.6.40-apache", "5.6.40", Sapi.MOD_PHP),
    ("php", "php", "9.0.1", "9.0.1", Sapi.UNKNOWN),
    ("php", "php", "4.4.9", None, None),
    ("php", "php", "8.3", "8.3", Sapi.UNKNOWN),
    ("php", "php", "8.3-fpm", "8.3", Sapi.FPM),
    # Every image in a repository called php is read as the official one.
    ("php", "app", "8.3.12-fpm", "8.3.12", Sapi.FPM),
    # So is an image called php in any repository, as in a mirror of the official image.
    ("mirror", "php", "8.3.12-fpm", "8.3.12", Sapi.FPM),
    ("mirror", "library/php", "8.4.2-cli", "8.4.2", Sapi.CLI),
    ("mirror", "docker-hub/library/php", "8.2.35-zts-bookworm", "8.2.35", Sapi.CLI),
    # A tag with no version, or one that is no PHP version.
    ("php", "php", "latest", None, None),
    ("php", "php", "fpm", None, None),
    ("php", "php", "8-fpm", None, None),
    ("php", "php", "8.3.12RC1", None, None),
    ("php", "php", "main", None, None),
    ("php", "php", "1.4.2", None, None),
    ("php", "php", "2024.10.1", None, None),
    ("php", "php", "10.1.2", None, None),
    # A full number counts unless what follows it reads as a distro revision or a pre-release.
    # Then the tag gives the branch alone.
    ("php", "php", "8.3.12-1ubuntu2.28", "8.3", Sapi.UNKNOWN),
    ("php", "php", "8.3.36-rc1", "8.3", Sapi.UNKNOWN),
    ("php", "php", "8.3.12-fpm-prod", "8.3.12", Sapi.FPM),
    # Elsewhere a tag has to say php.
    ("web", "app", "php8.3", "8.3", Sapi.UNKNOWN),
    ("web", "app", "php8.3.12-fpm", "8.3.12", Sapi.FPM),
    ("web", "app", "php-8.3.12", "8.3.12", Sapi.UNKNOWN),
    ("web", "app", "PHP-8.3.12-FPM", "8.3.12", Sapi.FPM),
    ("web", "app", "bookworm-php8.3.12", "8.3.12", Sapi.UNKNOWN),
    ("web", "app", "php-8.3-apache", "8.3", Sapi.MOD_PHP),
    ("web", "app", "8.3.12-fpm", None, None),
    ("web", "app", "latest", None, None),
    ("web", "app", "php-fpm", None, None),
    ("web", "app", "1.2.3", None, None),
    # php has to be the last part of the repository name or of the image path.
    ("php-app", "app", "8.3.12-fpm", None, None),
    ("phpmyadmin", "phpmyadmin", "5.2.1", None, None),
    ("web", "php-app", "8.3.12", None, None),
    ("web", "myphp", "8.3.12", None, None),
    ("web", "php/app", "8.3.12", None, None),
]


@pytest.mark.parametrize("repo,image,tag,version,sapi", TAGS,
                         ids=[f"{r}/{i}:{t}" for r, i, t, _, _ in TAGS])
def test_an_image_tag_names_a_php_version_or_it_does_not(world, repo, image, tag, version, sapi):
    world.stub_repository(repo, [(image, [tag])])
    evs = inventory(world)
    if version is None:
        assert evs == []
    else:
        ev = only_one(evs)
        assert ev.detected_version == version
        assert ev.sapi is sapi
        assert ev.location == f"us-docker.pkg.dev/{PROJECT}/{repo}/{image}:{tag}"


def test_a_branch_tag_says_the_build_is_unread(world):
    world.stub_repository("php", [("php", ["8.3-fpm"])])
    assert only(world).note == "the tag names only the PHP branch, so the build is not read"


def test_a_gcr_io_image_is_read_through_its_repository_in_artifact_registry(world):
    # Artifact Registry serves gcr.io from a repository called gcr.io. The image path ends in php.
    world.stub_repository("gcr.io", [("php", ["8.3.12-fpm"])], prefix=f"gcr.io/{PROJECT}")
    ev = only(world)
    assert ev.location == f"gcr.io/{PROJECT}/php:8.3.12-fpm"
    assert ev.signals["resource"] == repo_name("gcr.io")
    assert grade_evidence(ev, MATRIX)[0] is Verdict.EXPOSED


def test_every_tag_of_a_repository_carries_its_name_and_folds_into_one_asset(world):
    world.stub_repository("php", [("php", ["7.4.33-fpm", "8.3.36-fpm"]),
                                  ("php", ["8.3.36-apache", "latest"]), ("php", [])])
    evs = inventory(world)
    assert {e.signals["resource"] for e in evs} == {REPO}
    assert len(evs) == 3
    inv = AssetInventory()
    for ev in evs:
        inv.add(ev)
    (asset,) = inv.assets()
    assert len(asset.evidence) == 3
    assert asset.key == REPO
    assert grade(asset, MATRIX)[0] is Verdict.EXPOSED


def test_repositories_with_no_php_tag_leave_nothing(world):
    world.stub_repository("web", [("app", ["1.0.0", "latest", "main-abc123"])])
    world.stub_repository("empty", [])
    assert inventory(world) == []


def test_the_digest_is_left_off_the_location_and_the_tag_goes_on(world):
    world.stub_repository("php", [("php", ["8.3.36-fpm"])])
    ev = only(world)
    assert "@" not in ev.location
    assert ev.location.endswith("/php/php:8.3.36-fpm")


@pytest.mark.parametrize("uri", [
    "bad uri", "", None, 5, "caf" + E_ACUTE + "/php", "x" * 2000, "a\nb"])
def test_an_image_with_no_usable_uri_is_named_by_its_repository(world, uri):
    world.stub_repository("php", [])
    world.script("list_docker_images", [[NS(uri=uri, tags=["8.3.36-fpm"])]])
    assert only(world).location == f"{REPO}:8.3.36-fpm"


@pytest.mark.parametrize("fmt", [Format.MAVEN, Format.NPM, Format.APT, Format.PYTHON,
                                 Format.FORMAT_UNSPECIFIED, "MAVEN", 2])
def test_a_repository_of_another_format_is_never_asked_for_docker_images(world, fmt):
    world.stub_repository("libs", [("x", ["8.3.12-fpm"])], fmt=fmt)
    assert inventory(world) == []
    assert "list_docker_images" not in [c.method for c in world.calls]


@pytest.mark.parametrize("fmt", [Format.DOCKER, "DOCKER", 1])
def test_a_docker_repository_is_asked_whichever_way_the_format_is_written(world, fmt):
    world.stub_repository("php", [("php", ["8.3.12-fpm"])], fmt=fmt)
    assert len(inventory(world)) == 1


def test_a_repository_that_does_not_say_its_format_is_tried(world):
    # A field read wrongly has to cost a row at worst, and never every repository.
    repo = world.stub_repository("php", [("php", ["8.3.12-fpm"])])
    del repo.format_
    assert len(inventory(world)) == 1


def test_repositories_of_other_formats_never_count_toward_a_run_of_failures(world):
    for n in range(5):
        world.stub_repository(f"libs{n}", [], fmt=Format.MAVEN)
    world.stub_repository("php", [("php", ["8.3.12-fpm"])])
    assert [e.detected_version for e in inventory(world)] == ["8.3.12"]


# --- locations ---

def test_every_location_the_project_reports_is_asked_for_its_repositories(world):
    world.location_ids = ["us", "europe", "us-central1"]
    world.stub_repository("php", [("php", ["8.3.36-fpm"])], location="europe")
    inventory(world)
    got = asked(world, "list_repositories")
    assert got == [f"projects/{PROJECT}/locations/{where}"
                     for where in ("us", "europe", "us-central1")]
    located = [c.kwargs for c in world.calls if c.method == "list_locations"]
    assert located == [{"request": {"name": f"projects/{PROJECT}"}}]


def test_repositories_in_two_locations_are_both_found(world):
    world.stub_repository("php", [("php", ["8.3.36-fpm"])], location="us")
    world.stub_repository("php", [("php", ["7.4.33-fpm"])], location="europe")
    evs = inventory(world)
    assert {e.signals["resource"] for e in evs} == {
        repo_name("php", "us"), repo_name("php", "europe")}
    inv = AssetInventory()
    for ev in evs:
        inv.add(ev)
    assert len(inv.assets()) == 2


LOCATION_UNREAD = ("not inventoried: 1 entry in the list of locations could not be read "
                   "(no usable id)")


def test_the_stand_in_for_a_repeated_field_has_no_iter_and_still_iterates():
    # The fixture itself. Given an __iter__ it would no longer stand for protobuf's container.
    field = SequenceOnly(["us", "europe"])
    assert not hasattr(field, "__iter__")
    assert isinstance(field, abc.Iterable)
    assert list(field) == ["us", "europe"]
    assert len(field) == 2 and field[1] == "europe"


def test_locations_in_a_container_with_no_iter_are_read_through_to_the_repositories(world):
    # The list of locations is a mixin, so the client hands back the raw response. Under
    # protobuf's default backend its repeated field has no __iter__.
    world.stub_repository("php", [("php", ["8.3.36-fpm"])], location="europe")
    world.script("list_locations", [locations_answer(
        [NS(location_id="us"), NS(location_id="europe")])])
    found = only(world)
    assert found.detected_version == "8.3.36"
    got = asked(world, "list_repositories")
    assert got == [f"projects/{PROJECT}/locations/{where}" for where in ("us", "europe")]


@pytest.mark.parametrize("make", [list, tuple, SequenceOnly])
def test_the_tags_of_an_image_are_read_from_whatever_container_holds_them(world, make):
    world.stub_repository("php", [])
    world.script("list_docker_images", [[NS(uri=f"{IMAGE}@{DIGEST}", tags=make(["8.3.36-fpm"]))]])
    assert only(world).detected_version == "8.3.36"


@pytest.fixture
def locations_pb2():
    # googleapis-common-protos ships with every Google client, so the gcp extra has it.
    return pytest.importorskip("google.cloud.location.locations_pb2")


def test_a_real_list_locations_response_is_read_through_to_the_repository_calls(
        world, locations_pb2):
    response = locations_pb2.ListLocationsResponse(locations=[
        locations_pb2.Location(name=f"projects/{PROJECT}/locations/us", location_id="us"),
        locations_pb2.Location(name=f"projects/{PROJECT}/locations/europe",
                               location_id="europe")])
    world.stub_repository("php", [("php", ["8.3.36-fpm"])], location="europe")
    world.script("list_locations", [response])
    found = only(world)
    assert found.detected_version == "8.3.36"
    got = asked(world, "list_repositories")
    assert got == [f"projects/{PROJECT}/locations/{where}" for where in ("us", "europe")]


def test_a_real_location_that_names_no_id_is_counted_and_the_rest_are_read(world, locations_pb2):
    # protobuf reads a string that was never set as "", which is no usable id.
    response = locations_pb2.ListLocationsResponse(
        locations=[locations_pb2.Location(), locations_pb2.Location(location_id="us")])
    world.stub_repository("php", [("php", ["8.3.36-fpm"])])
    world.script("list_locations", [response])
    found, gap = inventory(world)
    assert found.detected_version == "8.3.36"
    assert gap.note == LOCATION_UNREAD


def test_a_real_response_with_a_page_token_leaves_a_row(world, locations_pb2):
    response = locations_pb2.ListLocationsResponse(
        locations=[locations_pb2.Location(location_id="us")], next_page_token="more")
    world.stub_repository("php", [("php", ["8.3.36-fpm"])])
    world.script("list_locations", [response])
    found, gap = inventory(world)
    assert found.detected_version == "8.3.36"
    assert gap.note == "not inventoried: the list of locations runs past one page"


def test_a_real_empty_response_means_no_repositories_and_no_failure(world, locations_pb2):
    world.script("list_locations", [locations_pb2.ListLocationsResponse()])
    assert inventory(world) == []
    assert "list_repositories" not in [c.method for c in world.calls]


def test_the_request_the_source_sends_for_locations_builds_a_real_request(world, locations_pb2):
    # The client turns a dict into the request by keyword expansion, so every key is a field.
    world.stub_repository("php", [("php", ["8.3.36-fpm"])])
    inventory(world)
    (request,) = [c.kwargs["request"] for c in world.calls if c.method == "list_locations"]
    assert locations_pb2.ListLocationsRequest(**request).name == f"projects/{PROJECT}"


@pytest.mark.parametrize("entry", [
    None, 5, "us", NS(), NS(location_id=None), NS(location_id=""), NS(location_id=5),
    NS(location_id="us central"), NS(location_id="us/central"), NS(location_id="x" * 300),
    NS(location_id="us" + E_ACUTE), NS(location_id="us\n")])
def test_a_location_with_no_usable_id_is_counted_and_never_asked_for(world, entry):
    world.stub_repository("php", [("php", ["8.3.36-fpm"])])
    world.script("list_locations", [locations_answer([entry, NS(location_id="us")])])
    found, gap = inventory(world)
    assert found.detected_version == "8.3.36"
    assert gap.note == LOCATION_UNREAD
    got = asked(world, "list_repositories")
    assert got == [f"projects/{PROJECT}/locations/us"]


def test_a_page_token_on_the_list_of_locations_is_a_row_after_the_locations_it_gave(world):
    world.stub_repository("php", [("php", ["8.3.36-fpm"])])
    world.location_token = "more"
    found, gap = inventory(world)
    assert found.detected_version == "8.3.36"
    assert gap.note == "not inventoried: the list of locations runs past one page"
    assert gap.location == f"gcp artifactregistry {PROJECT}"


@pytest.mark.parametrize("bad", [
    None, 5, "us", [], NS(), NS(locations=None), NS(locations="us"), NS(locations=5)])
def test_a_list_of_locations_that_is_not_the_documented_shape_ends_the_read_with_a_row(
        world, bad):
    world.script("list_locations", [bad])
    gap = only(world)
    assert gap.note == "not inventoried: the answer is not understood"


REPOSITORY_UNREAD = ("not inventoried: 1 entry in the list of repositories could not be read "
                     "(no usable name)")


@pytest.mark.parametrize("record", ODD_PROJECTS + [NS(name=REPO + "\n")])
def test_a_repository_with_no_usable_name_is_counted_and_never_listed(world, record):
    world.location_ids = ["us"]
    world.script("list_repositories", [[record]])
    gap = only(world)
    assert gap.note == REPOSITORY_UNREAD
    assert "list_docker_images" not in [c.method for c in world.calls]


IMAGE_UNREAD = "not inventoried: 1 entry in the list of images could not be read (no usable tag)"


def good_image():
    return NS(uri=f"{IMAGE}@{DIGEST}", tags=["8.3.36"])


@pytest.mark.parametrize("tags", [None, 5, "8.3.36", 1.5, True, NS()])
def test_an_image_whose_tags_are_no_list_is_counted_and_never_emitted(world, tags):
    world.stub_repository("php", [])
    world.script("list_docker_images", [[NS(uri=f"{IMAGE}@{DIGEST}", tags=tags), good_image()]])
    found, gap = inventory(world)
    assert found.detected_version == "8.3.36"
    assert gap.note == IMAGE_UNREAD


@pytest.mark.parametrize("tag", [
    None, 5, "", "8.3.36 ", "8.3.36\n", "8.3/36", "p" * 129, "php" + E_ACUTE + "8.3", ["x"]])
def test_a_tag_that_is_no_usable_name_is_counted_and_never_emitted(world, tag):
    world.stub_repository("php", [])
    world.script("list_docker_images", [[NS(uri=f"{IMAGE}@{DIGEST}", tags=[tag, "8.3.36"])]])
    found, gap = inventory(world)
    assert found.detected_version == "8.3.36"
    assert gap.note == IMAGE_UNREAD


def test_a_tag_of_128_characters_reads_and_one_of_129_does_not(world):
    ok = "php8.3-" + "a" * 121
    assert len(ok) == 128
    world.stub_repository("shop", [])
    world.script("list_docker_images", [[NS(uri=f"{IMAGE}@{DIGEST}", tags=[ok + "a", ok])]])
    found, gap = inventory(world)
    assert found.detected_version == "8.3"
    assert gap.note == IMAGE_UNREAD


def test_an_untagged_image_names_no_version_and_is_no_oddity(world):
    world.stub_repository("php", [("php", [])])
    assert inventory(world) == []


@pytest.mark.parametrize("image", [None, 5, "x", NS(), NS(uri=f"{IMAGE}@{DIGEST}")])
def test_an_entry_that_is_no_image_is_counted(world, image):
    world.stub_repository("php", [])
    world.script("list_docker_images", [[image]])
    assert only(world).note == IMAGE_UNREAD


# --- what goes wrong in a repository ---

def test_a_failing_repository_is_a_row_and_the_others_are_still_read(world):
    for name in ("a", "b", "c"):
        world.stub_repository(name, [("php", ["php8.3.36"])])
    world.fail("list_docker_images", ServiceUnavailable(SECRET), parent=repo_name("b"))
    evs = inventory(world)
    (gap,) = [e for e in evs if e.note.startswith("not fully inventoried")]
    assert gap.location == repo_name("b")
    assert gap.detected_version is None
    # Nothing in b was read, so nothing says it holds PHP.
    assert gap.signals == {"resource": repo_name("b"), "service": "artifactregistry",
                           "kind": "skipped"}
    assert gap.note == "not fully inventoried: ServiceUnavailable"
    assert {e.signals["resource"].rpartition("/")[2] for e in evs if e is not gap} == {"a", "c"}
    assert SECRET not in text_of(evs)


def test_a_repository_read_only_in_part_stays_indeterminate_whatever_it_showed(world):
    images = [NS(uri=f"{IMAGE}@{DIGEST}", tags=[tag])
              for tag in ("8.3.36-fpm", "7.4.33-fpm", "8.2.35-fpm")]
    world.stub_repository("php", [])
    pager = Pager("docker_images", [images[:1], images[1:]], fail_at=1,
                  error=ServiceUnavailable(SECRET))
    world.script("list_docker_images", [pager])
    seen, gap = inventory(world)
    assert grade_evidence(seen, MATRIX)[0] is Verdict.LIKELY_PATCHED
    assert gap.signals == {"resource": REPO, "service": "artifactregistry", "kind": "skipped",
                           "php_present": "true"}
    inv = AssetInventory()
    for ev in (seen, gap):
        inv.add(ev)
    (asset,) = inv.assets()
    assert grade(asset, MATRIX)[0] is Verdict.INDETERMINATE


def test_a_repository_read_in_full_with_no_failure_is_not_held_back(world):
    world.stub_repository("php", [("php", ["8.3.36-fpm", "8.2.35-fpm"])])
    inv = AssetInventory()
    for ev in inventory(world):
        inv.add(ev)
    (asset,) = inv.assets()
    assert grade(asset, MATRIX)[0] is Verdict.LIKELY_PATCHED


def test_the_registry_read_stops_after_repositories_fail_in_a_row(world):
    for i in range(6):
        world.stub_repository(f"r{i}", [("php", ["php8.3.36"])])
        world.fail("list_docker_images", ServiceUnavailable(SECRET), parent=repo_name(f"r{i}"))
    evs = inventory(world)
    got = asked(world, "list_docker_images")
    assert got == [repo_name(f"r{i}") for i in range(gcp._MAX_MISSES)]
    *repos, stop = evs
    assert len(repos) == gcp._MAX_MISSES
    assert stop.location == f"gcp artifactregistry {PROJECT}"
    assert stop.signals == {"service": "artifactregistry", "kind": "skipped"}
    assert stop.note == (
        f"not inventoried: {gcp._MAX_MISSES} repositories in a row could not be read")


def test_a_repository_that_reads_ends_the_run_of_failures(world):
    names = ["a", "b", "c", "d", "e", "f"]
    for name in names:
        world.stub_repository(name, [("php", ["php8.3.36"])])
    # Two fail, one reads, two fail, one reads. No run reaches the limit.
    for name in ("a", "b", "d", "e"):
        world.fail("list_docker_images", ServiceUnavailable(SECRET), parent=repo_name(name))
    evs = inventory(world)
    got = asked(world, "list_docker_images")
    assert got == [repo_name(name) for name in names]
    assert len([e for e in evs if e.note.startswith("not fully")]) == 4
    assert not [e for e in evs if "in a row" in e.note]


def test_a_failed_repository_listing_ends_the_read_and_keeps_the_locations_before_it(world):
    world.location_ids = ["us", "europe", "asia"]
    world.stub_repository("php", [("php", ["8.3.36-fpm"])], location="us")
    world.fail("list_repositories", Forbidden(SECRET), skip=1)
    found, gap = inventory(world)
    assert found.detected_version == "8.3.36"
    assert gap.note == f"not inventoried: {DENIED} (Forbidden)"
    got = asked(world, "list_repositories")
    assert got == [f"projects/{PROJECT}/locations/{where}" for where in ("us", "europe")]


# --- how the grader reads what the source writes ---

@pytest.mark.parametrize("tag,verdict,confidence", [
    ("8.3.36-fpm", Verdict.LIKELY_PATCHED, Confidence.HIGH),
    ("8.3.35-fpm", Verdict.EXPOSED, Confidence.HIGH),
    ("7.4.33-cli", Verdict.EXPOSED, Confidence.HIGH),
    ("8.3-fpm", Verdict.INDETERMINATE, Confidence.MEDIUM),
    ("8.3.12-1ubuntu2.28", Verdict.INDETERMINATE, Confidence.MEDIUM),
])
def test_registry_evidence_grades_as_the_version_it_names(world, tag, verdict, confidence):
    world.stub_repository("php", [("php", [tag])])
    assert grade_evidence(only(world), MATRIX) == (verdict, confidence)


def test_a_gap_row_grades_indeterminate_at_low_confidence(world):
    stubbed_everything(world)
    world.fail("list_functions", PermissionDenied(SECRET))
    gap = next(e for e in inventory(world) if e.signals.get("kind") == "skipped")
    assert grade_evidence(gap, MATRIX) == (Verdict.INDETERMINATE, Confidence.LOW)
    inv = AssetInventory()
    inv.add(gap)
    (asset,) = inv.assets()
    assert grade(asset, MATRIX) == (Verdict.INDETERMINATE, Confidence.LOW)


# --- what goes wrong in a call ---

@pytest.mark.parametrize("service,method", [
    ("appengine", "list_services"), ("cloudfunctions", "list_functions"),
    ("artifactregistry", "list_locations")])
def test_a_permission_error_is_one_row_and_the_other_services_still_read(
        world, service, method):
    stubbed_everything(world)
    world.fail(method, PermissionDenied(f"403 {SECRET} may not list"))
    evs = inventory(world)
    gaps = [e for e in evs if e.note.startswith("not inventoried")]
    assert len(gaps) == 1
    gap = gaps[0]
    assert gap.source is Source.CLOUD
    assert gap.location == f"gcp {service} {PROJECT}"
    assert gap.detected_version is None
    assert gap.sapi is Sapi.UNKNOWN
    assert gap.signals == {"service": service, "kind": "skipped"}
    assert gap.note == f"not inventoried: {DENIED} (PermissionDenied)"
    assert {e.signals["service"] for e in evs} == set(SERVICES)
    assert len([e for e in evs if e is not gap]) == 2
    assert SECRET not in text_of(evs)


@pytest.mark.parametrize("exc,why", [
    (PermissionDenied(SECRET), f"{DENIED} (PermissionDenied)"),
    (Forbidden(SECRET), f"{DENIED} (Forbidden)"),
    (RefreshError(SECRET), "the Google credentials could not be refreshed (RefreshError)"),
    (NotFound(SECRET), "NotFound"),
    (ServiceUnavailable(SECRET), "ServiceUnavailable"),
    (ValueError(SECRET), "ValueError"),
    (OSError(SECRET), "OSError"),
    (KeyError(SECRET), "KeyError"),
])
def test_a_failure_is_recorded_by_class_and_never_by_message(world, exc, why):
    world.stub_function("legacy-api")
    world.fail("list_functions", exc)
    gap = only(world)
    assert gap.note == "not inventoried: " + why
    assert SECRET not in text_of(gap)


def test_an_error_that_a_pager_raises_midway_is_recorded_the_same_way(world):
    fn = world.stub_function("legacy-api")
    pager = Pager("functions", [[fn]], fail_at=1, error=ServiceUnavailable(SECRET))
    world.script("list_functions", [pager])
    *found, gap = inventory(world)
    assert len(found) == 1
    assert gap.note == "not inventoried: ServiceUnavailable"


def test_entries_read_before_a_failure_are_kept_and_the_failure_is_a_row(world):
    world.stub_service()
    versions = [NS(name=f"{SERVICE}/versions/v{n}", runtime="php83") for n in range(4)]
    pager = Pager("versions", [versions[:2], versions[2:]], fail_at=1,
                  error=ServiceUnavailable(SECRET))
    world.script("list_versions", [pager])
    *found, gap = inventory(world)
    assert [e.location for e in found] == [v.name for v in versions[:2]]
    assert gap.note == "not inventoried: ServiceUnavailable"
    assert gap.location == f"gcp appengine {PROJECT}"


@pytest.mark.parametrize("entries", [0, 1])
def test_a_pager_whose_next_page_cannot_be_fetched_is_a_row_whatever_the_last_page_held(
        world, entries):
    world.stub_service()
    versions = [NS(name=VERSION, runtime="php83")] * entries
    pager = Pager("versions", [versions], fail_at=1, error=ServiceUnavailable(SECRET))
    world.script("list_versions", [pager])
    *found, gap = inventory(world)
    assert len(found) == entries
    assert gap.note == "not inventoried: ServiceUnavailable"


def test_a_listing_that_never_ends_is_cut_and_says_so(world, monkeypatch):
    monkeypatch.setattr(gcp, "_MAX_ENTRIES", 5)
    version = world.stub_version("php83")
    world.script("list_versions", [itertools.repeat(version)])
    *found, gap = inventory(world)
    assert len(found) == 5
    assert gap.note == "not inventoried: the list runs past 5 entries"
    assert gap.location == f"gcp appengine {PROJECT}"


def test_a_listing_of_exactly_the_limit_is_read_in_full(world, monkeypatch):
    monkeypatch.setattr(gcp, "_MAX_ENTRIES", 5)
    version = world.stub_version("php83")
    world.script("list_versions", [[version] * 5])
    assert len(inventory(world)) == 5


@pytest.mark.parametrize("bad", [None, 5, 1.5, "x", b"x", True])
def test_an_answer_that_is_not_a_list_ends_the_listing_with_a_row(world, bad):
    world.script("list_functions", [bad])
    assert only(world).note == "not inventoried: the answer is not understood"


def test_every_page_of_every_listing_is_read(world):
    world.page = 2
    for n in range(5):
        world.stub_version("php83", version=f"v{n}")
        world.stub_function(f"fn{n}")
    world.stub_repository("php", [("php", [f"8.3.{n}-fpm"]) for n in range(30, 35)])
    world.stub_repository("web", [("app", [f"php8.2.{n}"]) for n in range(30, 33)])
    evs = inventory(world)
    by_service = {s: [e for e in evs if e.signals["service"] == s] for s in SERVICES}
    assert [len(by_service[s]) for s in SERVICES] == [5, 5, 8]
    assert not [e for e in evs if e.signals.get("kind") == "skipped"]
    assert world.touched == []


def test_a_listing_read_page_by_page_is_cut_at_the_limit_too(world, monkeypatch):
    monkeypatch.setattr(gcp, "_MAX_ENTRIES", 3)
    world.page = 2
    for n in range(5):
        world.stub_function(f"fn{n}")
    *found, gap = inventory(world)
    assert len(found) == 3
    assert gap.note == "not inventoried: the list runs past 3 entries"


def test_an_empty_answer_is_an_empty_listing_and_no_failure(world):
    for method in ("list_services", "list_functions", "list_repositories"):
        world.script(method, [[]])
    world.location_ids = ["us"]
    assert inventory(world) == []


def test_unreadable_entries_are_still_counted_when_the_listing_then_fails(world):
    world.stub_service()
    good = NS(name=VERSION, runtime="php83")
    pager = Pager("versions", [[None, good]], fail_at=1, error=ServiceUnavailable(SECRET))
    world.script("list_versions", [pager])
    found, stop, unread = inventory(world)
    assert found.location == VERSION
    assert stop.note == "not inventoried: ServiceUnavailable"
    assert unread.note == VERSION_UNREAD


def test_the_count_of_unreadable_entries_is_plural_when_it_should_be(world):
    world.script("list_functions", [[None, 5, NS(name="")]])
    world.script("list_services", [[None, NS(name="x")]])
    gaps = {e.signals["service"]: e.note for e in inventory(world)}
    assert gaps == {
        "cloudfunctions": ("not inventoried: 3 entries in the list of functions could not be "
                           "read (no usable name)"),
        "appengine": ("not inventoried: 2 entries in the list of services could not be read "
                      "(no usable name)")}


# --- projects ---

def test_the_default_project_is_the_clients_own_and_every_listing_names_it(world):
    stubbed_everything(world)
    source = GcpSource(world)
    assert source.projects == (PROJECT,)
    source.inventory()
    assert [(c.method, c.kwargs) for c in world.calls] == [
        ("list_services", {"request": {"parent": APP}}),
        ("list_versions", {"request": {"parent": SERVICE}}),
        ("list_functions", {"request": {"parent": f"projects/{PROJECT}/locations/-"}}),
        ("list_locations", {"request": {"name": f"projects/{PROJECT}"}}),
        ("list_repositories", {"request": {"parent": f"projects/{PROJECT}/locations/us",
                                           "page_size": 1000}}),
        ("list_docker_images", {"request": {"parent": REPO, "page_size": 1000}})]


def test_every_call_sends_its_request_as_a_dict_and_nothing_else(world):
    # Only some SDK methods have a parent argument of their own, and a dict suits all of them.
    stubbed_everything(world)
    inventory(world)
    assert world.calls
    assert all(set(c.kwargs) == {"request"} and isinstance(c.kwargs["request"], dict)
               for c in world.calls)


def test_the_registry_asks_for_the_largest_page_and_the_others_choose_their_own(world):
    stubbed_everything(world)
    inventory(world)
    sizes = {c.method: c.kwargs["request"].get("page_size") for c in world.calls}
    assert sizes == {"list_services": None, "list_versions": None, "list_functions": None,
                     "list_locations": None, "list_repositories": gcp._PAGE,
                     "list_docker_images": gcp._PAGE}
    # Artifact Registry documents 1000 as the most a page can hold.
    assert gcp._PAGE == 1000


def test_each_project_given_is_read_and_a_row_names_the_one_that_failed():
    world = World()
    world.stub_version("php83")
    world.stub_version("php74", project=OTHER)
    world.stub_function("fn", project=OTHER)
    world.fail("list_functions", PermissionDenied(SECRET), parent=f"projects/{OTHER}/locations/-")
    source = GcpSource(world, projects=[PROJECT, OTHER])
    assert source.projects == (PROJECT, OTHER)
    evs = source.inventory()
    assert {e.signals["resource"] for e in evs if "resource" in e.signals} == {
        VERSION, f"apps/{OTHER}/services/default/versions/v1"}
    assert [e.location for e in evs if e.signals.get("kind") == "skipped"] == [
        f"gcp cloudfunctions {OTHER}"]


@pytest.mark.parametrize("projects", [[], (), None, iter(()), ""])
def test_no_projects_given_reads_the_clients_own(world, projects):
    assert GcpSource(world, projects=projects).projects == (PROJECT,)


@pytest.mark.parametrize("projects", [
    OTHER, [OTHER], (OTHER,), iter([OTHER]), (p for p in [OTHER])])
def test_one_project_as_a_string_a_list_a_tuple_or_an_iterator_is_one_project(world, projects):
    # A bare name read as a sequence would be one project for each of its letters.
    assert GcpSource(world, projects=projects).projects == (OTHER,)


def test_projects_assigned_after_the_source_is_made_are_the_ones_read(world):
    world.stub_version("php83", project=OTHER)
    source = GcpSource(world)
    source.projects = (OTHER,)
    assert only_one(source.inventory()).signals["resource"].startswith(f"apps/{OTHER}/")


def test_inventory_can_run_twice_and_gives_the_same_answer(world):
    stubbed_everything(world)
    source = GcpSource(world)
    assert source.inventory() == source.inventory()


def test_a_project_scoped_to_a_domain_is_a_usable_project(world):
    project = "example.com:my-project"
    world.stub_version("php83", project=project)
    ev = only(world, projects=[project])
    assert ev.location == f"apps/{project}/services/default/versions/v1"


def test_clients_with_no_project_and_none_given_leave_a_row_per_service_named_without_one():
    world = World(project=None)
    source = GcpSource(world)
    assert source.projects == (None,)
    assert [(e.location, e.note) for e in source.inventory()] == [
        (f"gcp {service}", "not inventoried: no GCP project is configured")
        for service in SERVICES]
    assert world.calls == []


def test_clients_with_no_project_attribute_at_all_read_the_same_way():
    source = GcpSource(NS())
    assert source.projects == (None,)
    assert len(source.inventory()) == 3


@pytest.mark.parametrize("project", [
    "my project", "my-project/services/x", "../x", "a\nb", "caf" + E_ACUTE, "x" * 300, 42,
    "my-project\x00", "apps/my-project"])
def test_a_project_id_that_is_no_name_is_a_row_per_service_and_no_call(world, project):
    rows = inventory(world, projects=[project])
    assert [(e.location, e.note) for e in rows] == [
        (f"gcp {service}", "not inventoried: the project id is not usable")
        for service in SERVICES]
    assert world.calls == []


# --- the protocol and the optional extra ---

def test_the_source_satisfies_the_protocol(world):
    assert isinstance(GcpSource(world), CloudSource)
    assert not isinstance(object(), CloudSource)


def test_importing_the_module_does_not_import_the_sdk():
    code = ("import sys\n"
            "import php_radar.sources.cloud, php_radar.sources.cloud.gcp\n"
            "bad = [m for m in sys.modules if m.split('.')[0] in ('google', 'grpc', 'proto')]\n"
            "assert not bad, bad\n")
    done = subprocess.run([sys.executable, "-c", code], cwd=str(ROOT), capture_output=True,
                          text=True, timeout=60)
    assert done.returncode == 0, done.stderr


# --- read-only, and nothing taken from the answers but the fields it names ---

def test_only_the_six_reads_are_called_and_the_clients_are_touched_for_nothing_else(world):
    stubbed_everything(world)
    inventory(world)
    assert {c.method for c in world.calls} == READS
    assert world.touched == []


def test_a_response_field_the_source_does_not_name_never_reaches_the_evidence(world):
    stubbed_everything(world)
    world.fail("list_docker_images", PermissionDenied(SECRET))
    evs = inventory(world)
    # The version, the function, and the repository whose images could not be listed.
    assert len(evs) == 3
    for ev in evs:
        assert SECRET not in text_of(ev)
    for out in rendered(evs):
        assert SECRET not in out


def test_the_report_prints_names_whole_whatever_they_are_called(world):
    version = f"{APP}/services/token-key-auth-password/versions/v1"
    function = f"projects/{PROJECT}/locations/us-central1/functions/token-key-auth-password"
    world.stub_version("php83", service="token-key-auth-password")
    world.stub_function("token-key-auth-password")
    world.stub_repository("keycloak-php", [("app", ["php8.3.36"])])
    console, as_json, sarif = rendered(inventory(world))
    for out in (console, as_json, sarif):
        assert version in out
        assert function in out
        assert "repositories/keycloak-php" in out
        assert out.isascii()
    assert "runtime php83 names only the PHP branch, so the build is not read" in console
    assert "us-docker.pkg.dev/my-project/keycloak-php/app:php8.3.36" in console
    assert json.loads(as_json)["summary"]["total"] == 3
    json.loads(sarif)


def test_a_failed_service_reads_as_a_row_in_the_report(world):
    world.fail("list_functions", RefreshError(SECRET))
    console = rendered(inventory(world))[0]
    assert f"gcp cloudfunctions {PROJECT}" in console
    assert ("not inventoried: the Google credentials could not be refreshed (RefreshError)"
            in console)
    assert "INDETERMINATE" in console


# --- nothing a service sends can crash the source ---

def check(ev):
    assert isinstance(ev, Evidence) and ev.source is Source.CLOUD and isinstance(ev.sapi, Sapi)
    for value in [ev.location, ev.note] + list(ev.signals.values()):
        assert isinstance(value, str) and value.isascii() and value.isprintable()
        assert len(value) <= 1200
    assert set(ev.signals) <= SIGNAL_KEYS
    resource = ev.signals.get("resource")
    assert resource is None or (resource.startswith(("apps/", "projects/")) and " " not in resource)
    assert ev.detected_version is None or re.fullmatch(
        r"[5-9]\.\d{1,4}(\.\d{1,4})?", ev.detected_version)
    # A row that records a gap is marked skipped, and a find never is. A find says PHP is there.
    gap = ev.note.startswith(("not inventoried", "not fully inventoried"))
    assert (ev.signals.get("kind") == "skipped") is gap
    if gap:
        assert ev.detected_version is None
    else:
        assert ev.signals.get("php_present") == "true"
    grade_evidence(ev, MATRIX)


POOL = [None, True, 0, -7, 2 ** 70, 1.5, "", " ", "x", "apps/", "projects/", "a\nb",
        "caf" + E_ACUTE, BIDI, "php", "php83", "8.3", "8.3.12", "x" * 3000, [], {}, [None],
        {"a": 1}, ["projects/x"], NS(), NS(name=None)]
VERSION_NAMES = [VERSION, f"{SERVICE}/versions/v2", "apps/x/services/y/versions/z", "apps/a:b/x",
                 "apps/" + "z" * 1020]
FUNCTION_NAMES = [FN, f"projects/{PROJECT}/locations/europe-west1/functions/fn", "projects/x",
                  "projects/" + "z" * 1020]
REPO_NAMES = [REPO, repo_name("web"), repo_name("gcr.io"), "projects/x", "projects/" + "z" * 1020]
URIS = [f"{IMAGE}@{DIGEST}", f"us-docker.pkg.dev/{PROJECT}/web/app@{DIGEST}",
        f"gcr.io/{PROJECT}/php@{DIGEST}", "a b", "x" * 1500]
RUNTIME_NAMES = ["php83", "php82", "php", "PHP74", "php8", "phpunit", "python312", "nodejs20"]
SETTING_NAMES = ["8.3", "8.5", "8.3.12", "latest", "8", ""]
TAG_NAMES = [["8.3.12-fpm"], ["8.3-apache", "php8.3"], ["latest"], ["8.3.12-1ubuntu2.28"],
             ["PHP-5.6.40-cli"], ["php\n8.3"], ["x" * 200], ["8.3.12RC1"], [], ["8.3.36", None]]
LOCATION_NAMES = ["us", "us-central1", "europe", "a b", "x" * 300]


def pick(rng, pool):
    """A value from pool, or from the odd values, which are all of POOL when pool is empty."""
    return rng.choice(pool + POOL) if rng.random() < 0.6 or not pool else rng.choice(pool)


def junk_service(rng):
    return NS(name=pick(rng, [SERVICE, f"{APP}/services/api", "apps/x"]))


def junk_version(rng):
    return NS(name=pick(rng, VERSION_NAMES), runtime=pick(rng, RUNTIME_NAMES),
              flexible_runtime_settings=pick(rng, [NS(runtime_version=pick(rng, SETTING_NAMES))]))


def junk_function(rng):
    return NS(name=pick(rng, FUNCTION_NAMES),
              build_config=pick(rng, [NS(runtime=pick(rng, RUNTIME_NAMES))]),
              service_config=pick(rng, [NS(service=pick(rng, [RUN, "projects/x"]))]))


def junk_repository(rng):
    return NS(name=pick(rng, REPO_NAMES),
              format_=pick(rng, [Format.DOCKER, Format.MAVEN, "DOCKER", 1, None]))


def junk_image(rng):
    return NS(uri=pick(rng, URIS), tags=pick(rng, TAG_NAMES))


def junk_locations(rng):
    entries = [NS(location_id=pick(rng, LOCATION_NAMES)) for _ in range(rng.randrange(4))]
    held = SequenceOnly(entries) if rng.random() < 0.5 else entries
    return NS(locations=held if rng.random() < 0.9 else pick(rng, []),
              next_page_token=pick(rng, ["", ""]) if rng.random() < 0.9 else "more")


def junk_listing(rng, make):
    entries = [make(rng) if rng.random() < 0.85 else pick(rng, []) for _ in range(rng.randrange(5))]
    return entries if rng.random() < 0.95 else pick(rng, [])


@pytest.mark.parametrize("seed", range(8))
def test_nothing_a_service_sends_crashes_the_source_or_slips_past_a_bound(seed):
    rng = random.Random(seed)
    for _ in range(150):
        world = World()
        world.script("list_services", [junk_listing(rng, junk_service) for _ in range(2)])
        world.script("list_versions", [junk_listing(rng, junk_version) for _ in range(4)])
        world.script("list_functions", [junk_listing(rng, junk_function) for _ in range(2)])
        world.script("list_locations", [junk_locations(rng) for _ in range(2)])
        world.script("list_repositories", [junk_listing(rng, junk_repository) for _ in range(4)])
        world.script("list_docker_images", [junk_listing(rng, junk_image) for _ in range(8)])
        # Some answers are not answers at all, and some calls fail.
        for method in list(world._script):
            if rng.random() < 0.15:
                world._script[method] = iter([pick(rng, []), ServiceUnavailable("503")])
        evs = inventory(world)
        for ev in evs:
            check(ev)
        assert {c.method for c in world.calls} <= READS
        assert world.touched == []


# --- the source ---

def source_of(module):
    return pathlib.Path(module.__file__).read_text(encoding="utf-8")


def imports_of(tree):
    """The full module name of every import in a tree."""
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            found.add(node.module or "")
    return found


def test_the_module_is_standard_library_only_and_names_no_sdk():
    tree = ast.parse(source_of(gcp), feature_version=(3, 9))
    assert imports_of(tree) <= {
        "collections", "typing", "php_radar.model", "php_radar.sources.cloud._common",
        "php_radar.sources.repo"}


VERBS = ("list_", "get_", "create_", "delete_", "update_", "set_", "patch_", "batch_", "export_",
         "import_", "run_", "deploy_", "test_", "call_", "undelete_", "move_", "start_", "stop_")


def test_the_source_never_names_an_operation_but_the_six_reads():
    tree = ast.parse(source_of(gcp), feature_version=(3, 9))
    used = {n.attr for n in ast.walk(tree)
            if isinstance(n, ast.Attribute) and n.attr.startswith(VERBS)}
    assert used == READS


def test_the_source_takes_four_clients_from_the_bundle_and_the_project_by_name():
    tree = ast.parse(source_of(gcp), feature_version=(3, 9))
    used = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)
            and ((isinstance(n.value, ast.Name) and n.value.id == "clients")
                 or (isinstance(n.value, ast.Attribute) and n.value.attr == "_clients"))}
    assert used <= {"app_engine_services", "app_engine_versions", "functions", "artifact_registry"}


def test_the_source_has_no_way_to_read_credentials_the_environment_or_a_file():
    tree = ast.parse(source_of(gcp), feature_version=(3, 9))
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    names |= {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    assert not names & {
        "get_credentials", "credentials", "_credentials", "transport", "token", "access_token",
        "environ", "getenv", "os", "open", "google", "grpc", "print", "logging", "eval", "exec",
        "compile", "__import__", "subprocess", "socket", "urllib"}


def test_the_source_is_plain_ascii_with_no_dash_or_curly_quote():
    source = source_of(gcp)
    assert source.isascii()
    assert not set(source) & set(DASHES_AND_QUOTES)
    assert not [c for c in source if ord(c) < 32 and c != "\n"]
