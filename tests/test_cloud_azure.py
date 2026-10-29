"""AzureSource against stand-ins for the SDK clients. No SDK, no network, no credentials.

The SDKs are optional installs. The source never imports them, so these tests need none. A
stand-in has the shape the SDK hands back, because a stand-in of the wrong shape is how a defect
hides. A listing comes back as azure-core's ItemPaged, which is an iterator with no length and no
index. It fetches a page when the one before it is spent, and it can fail at any page. The site
configuration and the registry are models of the newer generation. Each is a mapping that keeps its
fields under properties and reads them as its own. The container app comes in both generations, and
the older one has plain attributes. An error keeps the class and the parents that azure-core and
azure-identity give it, with the status and the code the service sent. Its message holds what the
source must never copy. The source cannot import the class, so it records the name. The field names
follow the packages' published models. A few tests build the real azure-core and management
types, and more run the real management clients over a transport that opens no socket. They are
skipped without the packages. No test here has run against a live subscription.
"""
import ast
import itertools
import json
import pathlib
import random
import re
import socket
import subprocess
import sys
from collections import abc
from types import SimpleNamespace as NS
from typing import NamedTuple

import pytest

from php_radar.knowledge import DATA_PATH, grade, grade_evidence, load_matrix
from php_radar.model import AssetInventory, Confidence, Evidence, Sapi, Source, Verdict
from php_radar.report import render_console, render_json, render_sarif
from php_radar.sources.cloud import CloudSource, azure
from php_radar.sources.cloud.azure import AzureSource

MATRIX = load_matrix(DATA_PATH)
ROOT = pathlib.Path(__file__).resolve().parent.parent

# Stands for anything a response holds that the source has no business copying: an app setting,
# a connection string, an environment variable of a container, an exception message. It is not
# token-shaped, so the report's redactor would let it through if it ever got that far.
SECRET = "hunter2-" + "CANARY-azure"

# Characters outside ASCII, by name, so that this file stays plain ASCII.
E_ACUTE = "\N{LATIN SMALL LETTER E WITH ACUTE}"
BIDI = "\N{RIGHT-TO-LEFT OVERRIDE}"
DASHES_AND_QUOTES = ("\N{EM DASH}\N{EN DASH}\N{LEFT SINGLE QUOTATION MARK}"
                     "\N{RIGHT SINGLE QUOTATION MARK}\N{LEFT DOUBLE QUOTATION MARK}"
                     "\N{RIGHT DOUBLE QUOTATION MARK}")

SUB = "00000000-0000-0000-0000-000000000001"
OTHER = "00000000-0000-0000-0000-000000000002"
SERVER = "myreg.azurecr.io"
DIGEST = "sha256:" + "0" * 64


def site_id(name="app1", group="rg1", sub=SUB):
    return f"/subscriptions/{sub}/resourceGroups/{group}/providers/Microsoft.Web/sites/{name}"


def app_id(name="capp1", group="rg1", sub=SUB):
    return (f"/subscriptions/{sub}/resourceGroups/{group}/providers/Microsoft.App/"
            f"containerApps/{name}")


def registry_id(name="myreg", group="rg1", sub=SUB):
    return (f"/subscriptions/{sub}/resourceGroups/{group}/providers/Microsoft.ContainerRegistry/"
            f"registries/{name}")


# The only calls the source may make, and how many positional arguments each takes. Each one reads.
ARGS = {"web_apps.list": 0, "web_apps.get_configuration": 2,
        "container_apps.list_by_subscription": 0, "registries.list": 0,
        "list_repository_names": 0, "list_tag_properties": 1}
READS = set(ARGS)
LISTINGS = READS - {"web_apps.get_configuration"}

SIGNAL_KEYS = {"resource", "service", "php_present", "kind", "hostname", "ip"}
SERVICES = ("appservice", "containerapps", "acr")
DENIED = "access was denied"
WHY_DENIED = f"{DENIED} (HttpResponseError 403 AuthorizationFailed)"
NO_SCOPE = "no Azure subscription is configured and none could be enumerated"
CREDENTIAL_LOST = "the Azure credential was not accepted, or it could not get a token"


# --- stand-ins ---
# Each has the shape the SDK hands back. An error keeps the class and the parents that azure-core
# and azure-identity give it. A listing is an iterator that fetches a page when the one before it
# is spent. A model of the newer generation is a mapping with its fields under properties. Its
# state sits in _data, as the real one does, so that vars() of it shows no field.

class AzureError(Exception):
    continuation_token = None


class ODataError:
    def __init__(self, code, message):
        self.code, self.message = code, message


class HttpResponseError(AzureError):
    def __init__(self, message=None, *, status=None, code=None):
        super().__init__(message)
        self.message, self.status_code, self.reason = message, status, None
        self.error = ODataError(code, message) if code else None


class ClientAuthenticationError(HttpResponseError):
    pass


class CredentialUnavailableError(ClientAuthenticationError):
    pass


class ResourceNotFoundError(HttpResponseError):
    pass


class ServiceRequestError(AzureError):
    pass


class PageIterator:
    """What by_page() hands back. Each page it yields is an iterator over the items of the page."""

    def __init__(self, source):
        self._source, self._at, self._started = source, 0, False
        self.continuation_token = None

    def __iter__(self):
        return self

    def __next__(self):
        if self._started and self.continuation_token is None:
            raise StopIteration
        items, more = self._source.fetch(self._at)
        self._started = True
        self.continuation_token = f"page{self._at + 1}" if more else None
        self._at += 1
        return iter(items)


class Pager:
    """Stands in for azure-core's ItemPaged.

    It is an iterator. It reads once, has no length and no index, and fetches nothing until it is
    read. pages holds the items of each page. fail_at is the index of the page whose fetch raises
    error, and the page before it carries a continuation, as a response does when more is to come.
    forever is the items of a page that comes back for every fetch.
    """

    def __init__(self, pages, *, fail_at=None, error=None, forever=None):
        self._pages, self._fail_at, self._error = list(pages), fail_at, error
        self._forever = forever
        self._chain = None
        self.fetched = 0

    def fetch(self, at):
        self.fetched += 1
        if at == self._fail_at:
            raise self._error
        if self._forever is not None:
            return self._forever, True
        return self._pages[at], at + 1 < len(self._pages) or at + 1 == self._fail_at

    def by_page(self, continuation_token=None):
        return PageIterator(self)

    def __iter__(self):
        return self

    def __next__(self):
        if self._chain is None:
            self._chain = itertools.chain.from_iterable(self.by_page())
        return next(self._chain)


class Flat(abc.MutableMapping):
    """A model of the newer SDK generation, as azure-mgmt-web 11 and azure-mgmt-containerregistry
    15 build them. It is a mapping with its fields under properties. They read as the model's own,
    and a field never set reads None."""

    FLAT = frozenset()
    TOP = frozenset({"id", "name", "type", "kind", "location", "tags", "properties", "sku",
                     "identity", "system_data"})

    def __init__(self, properties=None, **top):
        self._data = dict(top)
        if properties is not None:
            self._data["properties"] = properties

    def __getattr__(self, name):
        data = self.__dict__.get("_data", {})
        if name in data:
            return data[name]
        if name in self.TOP:
            return None
        if name in self.FLAT:
            return getattr(data.get("properties"), name, None)
        raise AttributeError(name)

    def __getitem__(self, key):
        return self._data[key]

    def __setitem__(self, key, value):
        self._data[key] = value

    def __delitem__(self, key):
        del self._data[key]

    def __iter__(self):
        return iter(self._data)

    def __len__(self):
        return len(self._data)


class Site(Flat):
    FLAT = frozenset({"resource_group", "default_host_name", "host_names", "state", "site_config",
                      "custom_domain_verification_id", "outbound_ip_addresses"})


class SiteConfigResource(Flat):
    FLAT = frozenset({"linux_fx_version", "windows_fx_version", "php_version", "app_settings",
                      "connection_strings", "publishing_username", "scm_type"})


class ContainerApp(Flat):
    FLAT = frozenset({"template", "configuration", "managed_environment_id", "provisioning_state",
                      "latest_revision_fqdn"})


class Registry(Flat):
    FLAT = frozenset({"login_server", "admin_user_enabled", "public_network_access",
                      "provisioning_state"})


class TagProperties:
    """azure.containerregistry.ArtifactTagProperties. Its name is read-only, and it is "" when the
    service sent none."""

    def __init__(self, **kwargs):
        self._name = kwargs.get("name", "")
        self._repository_name = kwargs.get("repository_name", "")
        self._digest = kwargs.get("digest", "")
        self.can_delete = self.can_read = self.can_list = self.can_write = None

    name = property(lambda self: self._name)
    repository_name = property(lambda self: self._repository_name)
    digest = property(lambda self: self._digest)


def make_site(name, group, sub, host, style, kind="app,linux"):
    fields = dict(resource_group=group, default_host_name=host, host_names=[host] if host else [],
                  state="Running", site_config=None, custom_domain_verification_id=SECRET,
                  outbound_ip_addresses="20.1.2.3")
    top = dict(id=site_id(name, group, sub), name=name, type="Microsoft.Web/sites", kind=kind,
               location="eastus", tags={"k": SECRET})
    return Site(properties=NS(**fields), **top) if style == "flat" else NS(**top, **fields)


def make_config(linux, php, style, name="web"):
    fields = dict(linux_fx_version=linux, windows_fx_version=None, php_version=php,
                  scm_type="None", publishing_username=SECRET,
                  app_settings=[NS(name="DB_PASSWORD", value=SECRET)],
                  connection_strings=[NS(name="db", connection_string=SECRET, type="MySql")])
    top = dict(id="x", name=name, type="Microsoft.Web/sites/config", kind=None)
    return SiteConfigResource(properties=NS(**fields), **top) if style == "flat" \
        else NS(**top, **fields)


def make_app(name, images, group, sub, fqdn, style):
    containers = [
        NS(name=f"c{n}", image=image, command=[], args=[], probes=[],
           env=[NS(name="DB_PASSWORD", value=SECRET, secret_ref=None)],
           resources=NS(cpu=0.5, memory="1Gi"))
        for n, image in enumerate(images)]
    init = [NS(name="init", image="myreg.azurecr.io/php:5.6.40-cli",
               env=[NS(name="TOKEN", value=SECRET, secret_ref=None)])]
    template = NS(containers=containers, init_containers=init, revision_suffix="",
                  scale=NS(min_replicas=1, max_replicas=3))
    configuration = NS(
        ingress=NS(fqdn=fqdn, external=True, target_port=80),
        secrets=[NS(name="db", value=SECRET)],
        registries=[NS(server=SERVER, username=SECRET, password_secret_ref="db")],
        active_revisions_mode="Single")
    fields = dict(template=template, configuration=configuration, managed_environment_id=SECRET,
                  provisioning_state="Succeeded", latest_revision_fqdn=fqdn)
    top = dict(id=app_id(name, group, sub), name=name, type="Microsoft.App/containerApps",
               location="eastus", tags={"k": SECRET})
    return ContainerApp(properties=NS(**fields), **top) if style == "flat" else NS(**top, **fields)


def put(model, field, value):
    """Set a field of a stand-in model, wherever its generation keeps it."""
    if isinstance(model, Flat) and field in model.FLAT:
        setattr(model["properties"], field, value)
    elif isinstance(model, Flat):
        model[field] = value
    else:
        setattr(model, field, value)


def make_registry(name, group, sub, server, style):
    fields = dict(login_server=server, admin_user_enabled=False, public_network_access="Enabled",
                  provisioning_state="Succeeded")
    top = dict(id=registry_id(name, group, sub), name=name,
               type="Microsoft.ContainerRegistry/registries", location="eastus",
               sku=NS(name="Basic", tier="Basic"), tags={"k": SECRET})
    return Registry(properties=NS(**fields), **top) if style == "flat" else NS(**top, **fields)


class Call(NamedTuple):
    method: str
    scope: str  # the subscription of a management client, or the login server of a registry's
    args: tuple
    kwargs: dict


# What a scripted method hands back once its answers run out.
_END = object()


class Credential:
    """Stands in for DefaultAzureCredential. The source holds it, hands it to the factories, and
    calls nothing on it, so anything read off it is recorded."""

    def __init__(self):
        self.touched = []

    def __getattr__(self, name):
        if not name.startswith("_"):
            self.touched.append(name)
        raise AttributeError(name)


class Ops:
    """One operation group of a management client. Only its reads exist."""

    def __init__(self, world, scope, group, reads):
        self._world, self._scope, self._group, self._reads = world, scope, group, reads

    def __getattr__(self, attr):
        if attr.startswith("_"):
            raise AttributeError(attr)
        if attr in self._reads:
            method = f"{self._group}.{attr}"
            return lambda *args, **kw: self._world.read(method, self._scope, args, kw)
        self._world.touched.append(f"{self._group}.{attr}")
        raise AttributeError(attr)


GROUPS = {"web": ("web_apps", {"list", "get_configuration"}),
          "container_apps": ("container_apps", {"list_by_subscription"}),
          "registries": ("registries", {"list"})}


class Mgmt:
    """A management client of one subscription."""

    def __init__(self, world, kind, scope):
        self._world, self._kind, self._scope = world, kind, scope
        group, reads = GROUPS[kind]
        setattr(self, group, Ops(world, scope, group, reads))

    def close(self):
        self._world.closed.append((self._kind, self._scope))

    def __getattr__(self, attr):
        if not attr.startswith("_"):
            self._world.touched.append(f"{self._kind}.{attr}")
        raise AttributeError(attr)


class Data:
    """The data-plane client of one registry. Like the real one, it takes keyword arguments."""

    def __init__(self, world, server):
        self._world, self._server = world, server

    def list_repository_names(self, **kw):
        return self._world.read("list_repository_names", self._server, (), kw)

    def list_tag_properties(self, repository, **kw):
        return self._world.read("list_tag_properties", self._server, (repository,), kw)

    def close(self):
        self._world.closed.append(("registry_data", self._server))

    def __getattr__(self, attr):
        if not attr.startswith("_"):
            self._world.touched.append(f"registry_data.{attr}")
        raise AttributeError(attr)


class World:
    """The bundle of client factories the source takes, answering from what a test stubbed.

    subscription_id is the default subscription. subscription_ids is the function the factory
    supplies to list the subscriptions of the credential. It hands back plain ID strings, from
    visible, or raises enumeration_error, and enumerated records the credential of each call. style
    is "flat" for the newer generation of model and "plain" for the older one. page is how many
    entries a page of a listing holds, or None for a single page. Whatever the source touches on
    the bundle, a client, or the credential beyond the four factories, the two subscription
    attributes, and the six reads lands in touched and raises. A test can see it there.
    """

    def __init__(self, subscription=SUB, style="flat"):
        self.touched = []
        self.credential = Credential()
        self.subscription_id = subscription
        self.visible = []  # the IDs subscription_ids returns
        self.enumeration_error = None
        self.enumerated = []  # the credential each call to subscription_ids was given
        self.style = style
        self.page = None
        self.calls = []  # every call made on a client, in order
        self.made = []  # (factory, credential, subscription or login server) for each client built
        self.closed = []
        self.configs = {}  # (subscription, site name) -> (resource group, configuration)
        self._script = {}  # method -> iterator of raw answers, or exceptions to raise
        self._fail = []  # [method, exception, calls to let through first, scope or None, arg]
        self._factory_fail = {}  # factory -> exception
        self._sites, self._apps, self._registries, self._repos = {}, {}, {}, {}

    def __getattr__(self, name):
        if not name.startswith("_"):
            self.touched.append(name)
        raise AttributeError(name)

    # The four factories. The first three take what the SDK's own classes take.

    def web(self, credential, subscription):
        return self._make("web", credential, subscription, Mgmt)

    def container_apps(self, credential, subscription):
        return self._make("container_apps", credential, subscription, Mgmt)

    def registries(self, credential, subscription):
        return self._make("registries", credential, subscription, Mgmt)

    def registry_data(self, credential, login_server):
        return self._make("registry_data", credential, login_server, lambda w, k, s: Data(w, s))

    def subscription_ids(self, credential):
        self.enumerated.append(credential)
        if self.enumeration_error is not None:
            raise self.enumeration_error
        return list(self.visible)

    def _make(self, kind, credential, scope, build):
        self.made.append((kind, credential, scope))
        if kind in self._factory_fail:
            raise self._factory_fail[kind]
        return build(self, kind, scope)

    # What the clients answer from.

    def read(self, method, scope, args, kw):
        self.calls.append(Call(method, scope, tuple(args), dict(kw)))
        if len(args) != ARGS[method]:
            raise TypeError(f"{method} takes {ARGS[method]} arguments and got {len(args)}")
        for rule in self._fail:
            if rule[0] == method and rule[3] in (None, scope) and rule[4] in (None, *args):
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
                answer = [] if method in LISTINGS else None
            if isinstance(answer, list) and method in LISTINGS:
                answer = self._pager(answer)
            return answer
        return getattr(self, "_" + method.replace(".", "_"))(scope, args)

    def _pager(self, entries, **kw):
        size = self.page or max(len(entries), 1)
        pages = [entries[at:at + size] for at in range(0, len(entries), size)] or [[]]
        return Pager(pages, **kw)

    def _web_apps_list(self, scope, args):
        return self._pager(self._sites.get(scope, []))

    def _web_apps_get_configuration(self, scope, args):
        group, name = args
        held = self.configs.get((scope, name))
        if held is None or held[0].lower() != group.lower():
            raise ResourceNotFoundError(f"404 {name} {SECRET}", status=404,
                                        code="ResourceNotFound")
        return held[1]

    def _container_apps_list_by_subscription(self, scope, args):
        return self._pager(self._apps.get(scope, []))

    def _registries_list(self, scope, args):
        return self._pager(self._registries.get(scope, []))

    def _list_repository_names(self, scope, args):
        if scope not in self._repos:
            raise ServiceRequestError(f"no route to {scope} {SECRET}")
        return self._pager(list(self._repos[scope]))

    def _list_tag_properties(self, scope, args):
        repos = self._repos.get(scope, {})
        if args[0] not in repos:
            raise ResourceNotFoundError(f"404 {args[0]} {SECRET}", status=404, code="NAME_UNKNOWN")
        return self._pager([TagProperties(name=tag, repository_name=args[0])
                            for tag in repos[args[0]]])

    # What a test can stub.

    def stub_site(self, name="app1", linux="PHP|8.3", php=None, group="rg1", sub=None,
                  host="default", kind="app,linux", config=None):
        sub = sub or self.subscription_id
        host = f"{name}.azurewebsites.net" if host == "default" else host
        site = make_site(name, group, sub, host, self.style, kind)
        self._sites.setdefault(sub, []).append(site)
        self.configs[(sub, name)] = (
            group, config if config is not None else make_config(linux, php, self.style))
        return site

    def stub_app(self, name="capp1", images=(f"{SERVER}/php:8.3.12",), group="rg1", sub=None,
                 fqdn="default"):
        sub = sub or self.subscription_id
        fqdn = f"{name}.kindhill-123.eastus.azurecontainerapps.io" if fqdn == "default" else fqdn
        app = make_app(name, list(images), group, sub, fqdn, self.style)
        self._apps.setdefault(sub, []).append(app)
        return app

    def stub_registry(self, name="myreg", repos=None, group="rg1", sub=None, server=None):
        """A registry and what it holds. repos maps a repository to the list of its tags."""
        sub = sub or self.subscription_id
        server = server or f"{name}.azurecr.io"
        registry = make_registry(name, group, sub, server, self.style)
        self._registries.setdefault(sub, []).append(registry)
        self._repos[server] = {repo: list(tags) for repo, tags in (repos or {}).items()}
        return registry

    def script(self, method, answers):
        """Answers calls to method from answers, in order. An exception in the list is raised.

        A list comes back as a pager over its entries, as a listing does. Anything else comes
        back as given. After the last answer a listing is empty.
        """
        self._script[method] = iter(answers)

    def fail(self, method, exc, skip=0, scope=None, arg=None):
        """Raise exc on calls to method, after letting skip of them through. scope narrows it to
        one subscription or one login server, and arg to the calls that pass that argument."""
        self._fail.append([method, exc, skip, scope, arg])

    def fail_factory(self, kind, exc):
        self._factory_fail[kind] = exc


@pytest.fixture
def world():
    return World()


@pytest.fixture(params=["flat", "plain"])
def any_world(request):
    """The same stand-ins with the models of each generation, newer and older."""
    return World(style=request.param)


def inventory(world, **kw):
    return AzureSource(world.credential, world, **kw).inventory()


def only(world, **kw):
    (found,) = inventory(world, **kw)
    return found


def only_one(evs):
    (ev,) = evs
    return ev


def text_of(evidence):
    return repr(evidence)


def asked(world, method):
    """The arguments of each call to method, in order."""
    return [c.args for c in world.calls if c.method == method]


def finds(evs):
    return [e for e in evs if e.signals.get("kind") != "skipped"]


def gaps(evs):
    return [e for e in evs if e.signals.get("kind") == "skipped"]


def rendered(evs):
    inv = AssetInventory()
    for ev in evs:
        inv.add(ev)
    assets = inv.assets()
    return [render_console(assets, MATRIX), render_json(assets, MATRIX),
            render_sarif(assets, MATRIX)]


def stubbed_everything(world):
    world.stub_site("app1", linux="PHP|8.3")
    world.stub_app("capp1", [f"{SERVER}/php:8.3.36"])
    world.stub_registry("myreg", {"php": ["8.3.36-fpm"]})


def denied():
    return HttpResponseError(f"403 {SECRET} may not list", status=403, code="AuthorizationFailed")


# --- an App Service app ---

def test_a_linux_app_service_on_a_php_runtime_becomes_evidence(any_world):
    any_world.stub_site("app1", linux="PHP|8.2")
    ev = only(any_world)
    assert ev.source is Source.CLOUD
    assert ev.location == site_id()
    assert ev.detected_version == "8.2"
    assert ev.sapi is Sapi.UNKNOWN
    assert ev.signals == {"resource": site_id(), "service": "appservice", "php_present": "true",
                          "hostname": "app1.azurewebsites.net"}
    assert ev.note == "linux_fx_version PHP|8.2 names only the PHP branch, so the build is not read"
    assert grade_evidence(ev, MATRIX) == (Verdict.INDETERMINATE, Confidence.MEDIUM)


@pytest.mark.parametrize("runtime", [
    "NODE|20-lts", "PYTHON|3.12", "DOTNETCORE|8.0", "JAVA|17-java17", "TOMCAT|10.0-java17",
    "RUBY|3.2", "STATICSITE|1.0",
    # A custom container keeps its image in the same field. That is not read this round.
    "DOCKER|php:8.3.12-apache", "DOCKER|myreg.azurecr.io/php:8.3.12", "COMPOSE|dmVyc2lvbjog",
    "KUBE|dmVyc2lvbjog",
    "", None, "x-PHP|8.3", "PHPMYADMIN|5", "PHP |8.3", "|PHP", "PHP|8.3 ", "PHP|8.3\n",
    " PHP|8.3", "PHP|8.3" + E_ACUTE, 5, ["PHP|8.3"], b"PHP|8.3"])
def test_a_site_on_another_runtime_leaves_no_row(any_world, runtime):
    any_world.stub_site("app1", linux=runtime)
    assert inventory(any_world) == []


# (linux_fx_version, php_version, the branch it gives, the field that names it)
RUNTIMES = [
    ("PHP|8.3", None, "8.3", "linux_fx_version"), ("PHP|8.2", "", "8.2", "linux_fx_version"),
    ("PHP|8.5", None, "8.5", "linux_fx_version"), ("PHP|8.4", None, "8.4", "linux_fx_version"),
    ("PHP|8.1", None, "8.1", "linux_fx_version"), ("PHP|7.4", None, "7.4", "linux_fx_version"),
    ("PHP|5.6", None, "5.6", "linux_fx_version"), ("php|8.3", None, "8.3", "linux_fx_version"),
    ("Php|8.3", None, "8.3", "linux_fx_version"),
    # A full number is cut to its branch, because a runtime label does not fix the build.
    ("PHP|8.3.12", None, "8.3", "linux_fx_version"),
    # A Windows site leaves linux_fx_version empty and keeps its version in php_version.
    ("", "7.4", "7.4", "php_version"), (None, "8.0", "8.0", "php_version"),
    (None, "5.6", "5.6", "php_version"), ("", "7.4.33", "7.4", "php_version"),
    # A Linux site is decided by linux_fx_version, and a stale php_version beside it is ignored.
    ("PHP|8.3", "7.4", "8.3", "linux_fx_version"),
    # PHP by name and no version anywhere.
    ("PHP|latest", None, None, "linux_fx_version"), ("PHP|", None, None, "linux_fx_version"),
    ("PHP", None, None, "linux_fx_version"), ("PHP|8", None, None, "linux_fx_version"),
    ("PHP|10.1", None, None, "linux_fx_version"), ("PHP|8.3|8.4", None, None, "linux_fx_version"),
    ("PHP|8.3-apache", None, None, "linux_fx_version"),
    ("", "latest", None, "php_version"), (None, "10.1", None, "php_version"),
]


@pytest.mark.parametrize("linux,php,branch,field", RUNTIMES)
def test_a_php_site_gives_its_branch_from_the_field_that_names_it(any_world, linux, php, branch,
                                                                    field):
    any_world.stub_site("app1", linux=linux, php=php)
    ev = only(any_world)
    value = linux if field == "linux_fx_version" else php
    assert ev.detected_version == branch
    assert ev.signals["php_present"] == "true"
    if branch is None:
        assert ev.note == f"{field} {value} names PHP, and the build is not read"
    else:
        assert ev.note == (
            f"{field} {value} names only the PHP branch, so the build is not read")
    assert grade_evidence(ev, MATRIX) == (Verdict.INDETERMINATE, Confidence.MEDIUM)


@pytest.mark.parametrize("linux,php", [
    ("NODE|20-lts", "7.4"), ("DOCKER|php:8.3", "7.4"), ("", ""), (None, None), ("", None),
    (None, ""), ("", 7.4), ("", ["7.4"]), ("", " "), ("", "7.4 "), ("", "7.4\n"),
    ("", "7." + E_ACUTE)])
def test_a_site_that_names_no_php_in_either_field_leaves_no_row(any_world, linux, php):
    any_world.stub_site("app1", linux=linux, php=php)
    assert inventory(any_world) == []


def test_a_legacy_windows_site_names_its_branch_in_php_version(any_world):
    any_world.stub_site("legacy", linux="", php="7.4", kind="app")
    ev = only(any_world)
    assert ev.detected_version == "7.4"
    assert ev.signals["php_present"] == "true"
    assert ev.note == "php_version 7.4 names only the PHP branch, so the build is not read"


@pytest.mark.parametrize("linux,php", [
    ("PHP|8.5", None), ("PHP|8.3", None), ("PHP|8.1", None), ("PHP|7.4", None), ("", "7.4"),
    ("", "5.6")])
def test_a_branch_from_a_site_grades_indeterminate_whether_or_not_the_branch_is_supported(
        world, linux, php):
    # A legacy Windows site on php_version 7.4 could be expected to grade EXPOSED, as an end of
    # life branch. The grader calls a branch end of life only when it has a full number to
    # compare, and a branch label from a managed runtime grades INDETERMINATE. An App Engine
    # runtime of php74 and a Beanstalk platform of PHP 7.4 grade the same way. The tag tests
    # below show an end of life build grading EXPOSED once the source has a full number.
    world.stub_site("app1", linux=linux, php=php)
    assert grade_evidence(only(world), MATRIX) == (Verdict.INDETERMINATE, Confidence.MEDIUM)


def test_the_configuration_is_read_site_by_site_by_the_group_and_name_in_the_id(world):
    world.stub_site("app1", group="rg-One", linux="PHP|8.3")
    world.stub_site("shop-2", group="Rg(two)", linux="NODE|20-lts")
    world.stub_site("api", group="rg-one", linux="PHP|8.2")
    evs = inventory(world)
    assert [e.detected_version for e in evs] == ["8.3", "8.2"]
    assert asked(world, "web_apps.list") == [()]
    assert asked(world, "web_apps.get_configuration") == [
        ("rg-One", "app1"), ("Rg(two)", "shop-2"), ("rg-one", "api")]


def test_a_configuration_that_came_with_the_site_list_is_not_trusted(world):
    # The list does not carry the configuration reliably, so what it does carry is never read.
    site = world.stub_site("app1", linux="PHP|8.3")
    site["properties"].site_config = NS(linux_fx_version="PHP|7.4", php_version="5.6")
    assert only(world).detected_version == "8.3"


def test_a_site_is_read_whatever_its_kind(world):
    world.stub_site("fn", linux="PHP|8.3", kind="functionapp,linux")
    world.stub_site("other", linux="PHP|8.2", kind=None)
    assert [e.detected_version for e in inventory(world)] == ["8.3", "8.2"]


def test_two_sites_stay_two_assets(world):
    world.stub_site("app1", linux="PHP|8.3")
    world.stub_site("app2", linux="PHP|8.3")
    inv = AssetInventory()
    for ev in inventory(world):
        inv.add(ev)
    assert len(inv.assets()) == 2


# (the default host name of the site, the signals it adds)
HOSTS = [
    ("app1.azurewebsites.net", {"hostname": "app1.azurewebsites.net"}),
    ("app1-abc123.eastus-01.azurewebsites.net",
     {"hostname": "app1-abc123.eastus-01.azurewebsites.net"}),
    ("web1", {"hostname": "web1"}),
    ("a" * 253, {"hostname": "a" * 253}),
    ("10.0.0.4", {"ip": "10.0.0.4"}),
    ("a" * 254, {}), ("x" * 300, {}), ("", {}), (None, {}), (7, {}), (["x"], {}),
    ("caf" + E_ACUTE + ".example.com", {}), ("ok.example.com\nINJECTED", {}),
    (".example.com", {}), ("-a.example.com", {}), ("a b.example.com", {}),
]


@pytest.mark.parametrize("host,expected", HOSTS)
def test_the_default_host_name_goes_in_hostname_when_it_is_one(any_world, host, expected):
    any_world.stub_site("app1", host=host)
    ev = only(any_world)
    assert {k: v for k, v in ev.signals.items() if k in ("hostname", "ip")} == expected
    assert ev.signals["resource"] == site_id()


def test_a_host_read_of_the_default_host_name_merges_with_the_site(world):
    # The name differs in case and in a trailing dot. The model folds both.
    world.stub_site("shop", host="Shop.AzureWebsites.net.")
    host = Evidence(Source.HOST, "shop", "8.3.36", Sapi.FPM,
                    {"hostname": "shop.azurewebsites.net", "php_present": "true"}, "")
    inv = AssetInventory()
    for ev in inventory(world) + [host]:
        inv.add(ev)
    (asset,) = inv.assets()
    assert len(asset.evidence) == 2
    assert asset.kind == "host"
    assert asset.key == site_id("shop")


# --- ARM resource IDs ---

def odd_ids(kind):
    """Strings that are no ID of a resource of this kind, to stand in for the id of an entry."""
    good = f"/subscriptions/{SUB}/resourceGroups/rg1/providers/{kind}/x1"
    return [
        None, "", 5, ["x"], "x1", "/subscriptions/" + SUB, good + "/slots/staging",
        good.replace("Microsoft.", "Other."), good.replace("/providers/", "/provider/"),
        good.replace("/subscriptions/", "/subscription/"),
        good.replace("/resourceGroups/", "/groups/"), good + "/", good.replace("/rg1/", "//"),
        "x" + good, good + " x", good + "\nINJECTED", good.replace("rg1", "caf" + E_ACUTE),
        good.replace("x1", "a" * 1100), good.replace("rg1", "rg;1"), good.replace("x1", "x%2F1"),
        "relative/" + good, good.replace("rg1", "r\x00g")]


ODD_SITE_IDS = odd_ids("Microsoft.Web/sites")
SITE_UNREAD = ("not inventoried: 1 entry in the list of sites could not be read "
               "(no usable resource ID)")


@pytest.mark.parametrize("ident", ODD_SITE_IDS)
def test_a_site_with_no_usable_id_is_counted_and_never_asked_for_its_configuration(world, ident):
    good = world.stub_site("app1")
    odd = NS(id=ident, name="app1", default_host_name="x.example.com")
    world.script("web_apps.list", [[odd, good]])
    found, gap = inventory(world)
    assert found.location == site_id()
    assert gap.note == SITE_UNREAD
    assert asked(world, "web_apps.get_configuration") == [("rg1", "app1")]


@pytest.mark.parametrize("entry", [None, 5, "x", [], {}, NS(), NS(id=None), NS(name="app1")])
def test_an_entry_that_is_no_site_is_counted(world, entry):
    world.script("web_apps.list", [[entry]])
    assert only(world).note == SITE_UNREAD


def test_the_fixed_parts_of_an_id_match_in_any_case(world):
    ident = f"/SUBSCRIPTIONS/{SUB}/RESOURCEGROUPS/RG1/PROVIDERS/MICROSOFT.WEB/SITES/app1"
    world.stub_site("app1")
    world.script("web_apps.list", [[NS(id=ident, default_host_name="app1.azurewebsites.net")]])
    assert only(world).location == ident
    assert asked(world, "web_apps.get_configuration") == [("RG1", "app1")]


def test_a_resource_group_with_parentheses_and_dots_is_a_usable_name(world):
    world.stub_site("app1", group="rg.(prod)_1")
    assert only(world).location == site_id("app1", "rg.(prod)_1")


# --- a configuration that cannot be read ---

def test_a_site_whose_configuration_cannot_be_read_is_a_row_and_the_others_are_still_read(world):
    for name in ("a", "b", "c"):
        world.stub_site(name, linux="PHP|8.3")
    world.fail("web_apps.get_configuration", denied(), arg="b")
    evs = inventory(world)
    (gap,) = gaps(evs)
    assert gap.location == site_id("b")
    assert gap.detected_version is None
    # Nothing was read from b, so nothing says it runs PHP.
    assert gap.signals == {"resource": site_id("b"), "service": "appservice", "kind": "skipped"}
    assert gap.note == f"not fully inventoried: {WHY_DENIED}"
    assert [e.location for e in finds(evs)] == [site_id("a"), site_id("c")]
    assert SECRET not in text_of(evs)


@pytest.mark.parametrize("answer", [None, 5, "PHP|8.3", [], NS(), NS(id="x"), 1.5, True])
def test_a_configuration_that_is_not_one_is_a_row_and_never_a_clean_site(world, answer):
    world.stub_site("app1", linux="PHP|8.3")
    world.script("web_apps.get_configuration", [answer])
    (gap,) = inventory(world)
    assert gap.signals == {"resource": site_id(), "service": "appservice", "kind": "skipped"}
    assert gap.note == "not fully inventoried: the answer is not understood"
    assert grade_evidence(gap, MATRIX) == (Verdict.INDETERMINATE, Confidence.LOW)


def test_a_configuration_with_either_field_but_not_the_other_is_still_a_configuration(world):
    world.stub_site("a", linux="PHP|8.2")
    world.stub_site("b", linux="PHP|8.3")
    world.script("web_apps.get_configuration", [NS(linux_fx_version="PHP|8.2"),
                                                NS(php_version="7.4")])
    evs = inventory(world)
    assert [e.detected_version for e in evs] == ["8.2", "7.4"]


def test_the_appservice_read_stops_after_sites_fail_in_a_row(world):
    for i in range(6):
        world.stub_site(f"s{i}", linux="PHP|8.3")
    world.fail("web_apps.get_configuration", denied())
    evs = inventory(world)
    assert asked(world, "web_apps.get_configuration") == [
        ("rg1", f"s{i}") for i in range(azure._MAX_MISSES)]
    *sites, stop = evs
    assert len(sites) == azure._MAX_MISSES
    assert stop.location == f"azure appservice {SUB}"
    assert stop.signals == {"service": "appservice", "kind": "skipped"}
    assert stop.note == f"not inventoried: {azure._MAX_MISSES} sites in a row could not be read"


def test_a_site_that_reads_ends_the_run_of_failures(world):
    names = ["a", "b", "c", "d", "e", "f"]
    for name in names:
        world.stub_site(name, linux="PHP|8.3")
    # Two fail, one reads, two fail, one reads. No run reaches the limit.
    for name in ("a", "b", "d", "e"):
        world.fail("web_apps.get_configuration", denied(), arg=name)
    evs = inventory(world)
    assert asked(world, "web_apps.get_configuration") == [("rg1", name) for name in names]
    assert len(gaps(evs)) == 4
    assert not [e for e in evs if "in a row" in e.note]


def test_failures_with_reads_between_them_never_end_the_read(world):
    # Read, read, fail, read, read, read, fail, read. No three failures stand in a row, and a run
    # of reads is no run of failures either.
    names = [f"s{i}" for i in range(8)]
    for name in names:
        world.stub_site(name, linux="PHP|8.3")
    for name in ("s2", "s6"):
        world.fail("web_apps.get_configuration", denied(), arg=name)
    evs = inventory(world)
    assert asked(world, "web_apps.get_configuration") == [("rg1", n) for n in names]
    assert (len(finds(evs)), len(gaps(evs))) == (6, 2)


def test_a_listing_error_after_some_sites_were_read_keeps_them_and_adds_a_row(world):
    for name in ("a", "b", "c"):
        world.stub_site(name, linux="PHP|8.3")
    sites = world._sites[SUB]
    pager = Pager([sites[:2], sites[2:]], fail_at=1, error=ServiceRequestError(SECRET))
    world.script("web_apps.list", [pager])
    *found, gap = inventory(world)
    assert [e.location for e in found] == [site_id("a"), site_id("b")]
    assert gap.location == f"azure appservice {SUB}"
    assert gap.note == "not inventoried: the service could not be reached (ServiceRequestError)"


# --- a Container App ---

def test_a_container_app_on_a_php_image_from_a_registry_is_graded_on_its_tag(any_world):
    any_world.stub_app("capp1", [f"{SERVER}/php:8.3.12"])
    ev = only(any_world)
    assert ev.source is Source.CLOUD
    assert ev.location == f"{SERVER}/php:8.3.12"
    assert ev.detected_version == "8.3.12"
    assert ev.sapi is Sapi.UNKNOWN
    assert ev.signals == {"resource": app_id(), "service": "containerapps", "php_present": "true",
                          "hostname": "capp1.kindhill-123.eastus.azurecontainerapps.io"}
    assert ev.note == "version read from the image tag"
    # 8.3.12 is older than the 8.3.36 that carries the fix.
    assert grade_evidence(ev, MATRIX) == (Verdict.EXPOSED, Confidence.HIGH)


# (image reference, version it names or None, SAPI)
IMAGES = [
    # The official image's tags, in a repository called php or on an image called php.
    (f"{SERVER}/php:8.3.12", "8.3.12", Sapi.UNKNOWN),
    (f"{SERVER}/php:8.3.12-fpm", "8.3.12", Sapi.FPM),
    (f"{SERVER}/php:8.3.12-apache", "8.3.12", Sapi.MOD_PHP),
    (f"{SERVER}/php:8.3.12-cli-alpine3.20", "8.3.12", Sapi.CLI),
    (f"{SERVER}/library/php:8.4.2-cli", "8.4.2", Sapi.CLI),
    ("php:8.3.12-apache", "8.3.12", Sapi.MOD_PHP),
    ("docker.io/library/php:8.2.35-zts-bookworm", "8.2.35", Sapi.CLI),
    ("localhost:5000/php:8.3.12", "8.3.12", Sapi.UNKNOWN),
    (f"{SERVER}/php:5.6.40-apache", "5.6.40", Sapi.MOD_PHP),
    (f"{SERVER}/php:8.3", "8.3", Sapi.UNKNOWN),
    (f"{SERVER}/php:8.3-fpm", "8.3", Sapi.FPM),
    # The digest after the tag is left off, and the tag stands.
    (f"{SERVER}/php:8.3.12@{DIGEST}", "8.3.12", Sapi.UNKNOWN),
    # Elsewhere the tag has to say php.
    (f"{SERVER}/app:php8.3", "8.3", Sapi.UNKNOWN),
    (f"{SERVER}/app:php8.3.12-fpm", "8.3.12", Sapi.FPM),
    (f"{SERVER}/app:php-8.3.12", "8.3.12", Sapi.UNKNOWN),
    (f"{SERVER}/shop/app:PHP-8.3.12-FPM", "8.3.12", Sapi.FPM),
    # A full number counts unless what follows it reads as a distro revision or a pre-release.
    (f"{SERVER}/php:8.3.12-1ubuntu2.28", "8.3", Sapi.UNKNOWN),
    (f"{SERVER}/php:8.3.36-rc1", "8.3", Sapi.UNKNOWN),
    (f"{SERVER}/php:8.3.12-fpm-prod", "8.3.12", Sapi.FPM),
    # No version in the reference, or one that is no PHP version.
    (f"{SERVER}/php:latest", None, None),
    (f"{SERVER}/php", None, None),
    (f"{SERVER}/php@{DIGEST}", None, None),
    ("localhost:5000/php", None, None),
    ("php", None, None),
    (f"{SERVER}/php:4.4.9", None, None),
    (f"{SERVER}/php:10.1.2", None, None),
    (f"{SERVER}/php:8-fpm", None, None),
    (f"{SERVER}/php:8.3.12RC1", None, None),
    (f"{SERVER}/app:8.3.12", None, None),
    (f"{SERVER}/app:1.2.3", None, None),
    (f"{SERVER}/app:latest", None, None),
    # php has to be the last part of the image path.
    (f"{SERVER}/php-app:8.3.12", None, None),
    (f"{SERVER}/myphp:8.3.12", None, None),
    (f"{SERVER}/phpmyadmin:5.2.1", None, None),
    (f"{SERVER}/php/app:8.3.12", None, None),
    (f"{SERVER}/app/php-fpm:8.3.12", None, None),
]


@pytest.mark.parametrize("image,version,sapi", IMAGES, ids=[i for i, _, _ in IMAGES])
def test_an_image_reference_names_a_php_version_or_it_does_not(any_world, image, version, sapi):
    any_world.stub_app("capp1", [image])
    evs = inventory(any_world)
    if version is None:
        assert evs == []
    else:
        ev = only_one(evs)
        assert ev.detected_version == version
        assert ev.sapi is sapi
        assert ev.location == image.partition("@")[0]
        assert ev.signals["resource"] == app_id()


def test_every_container_of_an_app_is_read_and_each_php_one_leaves_a_row(world):
    world.stub_app("capp1", [f"{SERVER}/app:1.0", f"{SERVER}/php:8.3.36-fpm",
                             f"{SERVER}/sidecar:php8.2.35"])
    evs = inventory(world)
    assert [(e.location, e.detected_version) for e in evs] == [
        (f"{SERVER}/php:8.3.36-fpm", "8.3.36"), (f"{SERVER}/sidecar:php8.2.35", "8.2.35")]
    inv = AssetInventory()
    for ev in evs:
        inv.add(ev)
    (asset,) = inv.assets()
    assert asset.key == app_id()
    assert len(asset.evidence) == 2
    assert grade(asset, MATRIX)[0] is Verdict.LIKELY_PATCHED


def test_an_app_with_one_old_container_among_patched_ones_grades_on_the_old_one(world):
    world.stub_app("capp1", [f"{SERVER}/php:8.3.36", f"{SERVER}/php:8.2.30"])
    inv = AssetInventory()
    for ev in inventory(world):
        inv.add(ev)
    (asset,) = inv.assets()
    assert grade(asset, MATRIX)[0] is Verdict.EXPOSED


def test_an_init_container_is_not_read(world):
    # The stand-in app has an init container on a php image, and no row comes of it.
    world.stub_app("capp1", [f"{SERVER}/app:1.0"])
    assert inventory(world) == []


def test_apps_with_no_php_leave_nothing(world):
    world.stub_app("a", [f"{SERVER}/app:1.0", "mcr.microsoft.com/dotnet/aspnet:8.0"])
    world.stub_app("b", [])
    assert inventory(world) == []


@pytest.mark.parametrize("fqdn,expected", [
    ("capp1.kindhill-123.eastus.azurecontainerapps.io",
     {"hostname": "capp1.kindhill-123.eastus.azurecontainerapps.io"}),
    ("10.0.0.4", {"ip": "10.0.0.4"}), (None, {}), ("", {}), (5, {}), ("a b", {}),
    ("x" * 300, {}), ("caf" + E_ACUTE + ".example.com", {})])
def test_the_ingress_fqdn_goes_in_hostname_when_it_is_one(any_world, fqdn, expected):
    any_world.stub_app("capp1", fqdn=fqdn)
    ev = only(any_world)
    assert {k: v for k, v in ev.signals.items() if k in ("hostname", "ip")} == expected


@pytest.mark.parametrize("configuration", [None, NS(), NS(ingress=None), NS(ingress=NS()), 5])
def test_an_app_with_no_ingress_is_still_read(any_world, configuration):
    put(any_world.stub_app("capp1"), "configuration", configuration)
    ev = only(any_world)
    assert ev.detected_version == "8.3.12"
    assert "hostname" not in ev.signals and "ip" not in ev.signals


ODD_APP_IDS = odd_ids("Microsoft.App/containerApps")
APP_UNREAD = ("not inventoried: 1 entry in the list of container apps could not be read "
              "(no usable resource ID or container list)")


@pytest.mark.parametrize("ident", ODD_APP_IDS)
def test_an_app_with_no_usable_id_is_counted_and_never_emitted(any_world, ident):
    good = any_world.stub_app("capp1")
    odd = any_world.stub_app("odd")
    put(odd, "id", ident)
    any_world._apps[SUB] = [odd, good]
    found, gap = inventory(any_world)
    assert found.signals["resource"] == app_id()
    assert gap.note == APP_UNREAD


@pytest.mark.parametrize("template", [None, 5, "x", NS(), NS(containers=None),
                                      NS(containers=5), NS(containers="php:8.3.12")])
def test_an_app_whose_containers_are_no_list_is_counted_and_never_emitted(any_world, template):
    put(any_world.stub_app("capp1"), "template", template)
    assert only(any_world).note == APP_UNREAD


@pytest.mark.parametrize("entry", [None, 5, "x", [], {}, NS(), NS(id=None)])
def test_an_entry_that_is_no_app_is_counted(world, entry):
    world.script("container_apps.list_by_subscription", [[entry]])
    assert only(world).note == APP_UNREAD


CONTAINER_UNREAD = ("not inventoried: 1 entry in the list of containers could not be read "
                    "(no usable image)")


@pytest.mark.parametrize("image", [
    None, 5, "", "has space", "x" * 3000, "caf" + E_ACUTE + "/php:8.3", f"{SERVER}/php:",
    f"{SERVER}/php:8.3.12\n", ["x"], "@" + DIGEST, f"{SERVER}/php:8.3.12 "])
def test_a_container_with_no_usable_image_is_counted_and_the_others_are_read(world, image):
    world.stub_app("capp1", [image, f"{SERVER}/php:8.3.36"])
    found, gap = inventory(world)
    assert found.detected_version == "8.3.36"
    assert gap.note == CONTAINER_UNREAD


@pytest.mark.parametrize("make", [list, tuple, lambda c: iter(c)])
def test_the_containers_are_read_from_whatever_container_holds_them(any_world, make):
    template = any_world.stub_app("capp1").template
    template.containers = make(template.containers)
    assert only(any_world).detected_version == "8.3.12"


# --- an Azure Container Registry ---

def test_an_image_tag_in_a_registry_repository_called_php_gives_its_version_and_sapi(world):
    world.stub_registry("myreg", {"php": ["8.3.12-fpm"]})
    ev = only(world)
    assert ev.source is Source.CLOUD
    assert ev.location == f"{SERVER}/php:8.3.12-fpm"
    assert ev.detected_version == "8.3.12"
    assert ev.sapi is Sapi.FPM
    assert ev.signals == {"resource": f"{SERVER}/php", "service": "acr", "php_present": "true"}
    assert ev.note == "version read from the image tag"
    assert grade_evidence(ev, MATRIX) == (Verdict.EXPOSED, Confidence.HIGH)


def test_a_branch_tag_grades_indeterminate_and_says_the_build_is_unread(world):
    world.stub_registry("myreg", {"php": ["8.3-fpm"]})
    ev = only(world)
    assert ev.detected_version == "8.3"
    assert ev.sapi is Sapi.FPM
    assert ev.note == "the tag names only the PHP branch, so the build is not read"
    assert grade_evidence(ev, MATRIX) == (Verdict.INDETERMINATE, Confidence.MEDIUM)


def test_a_latest_tag_names_no_version_and_leaves_no_row(world):
    world.stub_registry("myreg", {"php": ["latest"]})
    assert inventory(world) == []


# (repository, tag, version it names or None, SAPI)
TAGS = [
    # The official image's tags, in a repository whose last part is php.
    ("php", "8.3.12", "8.3.12", Sapi.UNKNOWN), ("php", "8.3.12-fpm", "8.3.12", Sapi.FPM),
    ("php", "8.3.12-apache", "8.3.12", Sapi.MOD_PHP),
    ("php", "8.3.12-cli-alpine3.20", "8.3.12", Sapi.CLI),
    ("php", "5.6.40-apache", "5.6.40", Sapi.MOD_PHP), ("php", "9.0.1", "9.0.1", Sapi.UNKNOWN),
    ("php", "4.4.9", None, None), ("php", "8.3", "8.3", Sapi.UNKNOWN),
    ("php", "8.3-fpm", "8.3", Sapi.FPM),
    ("library/php", "8.4.2-cli", "8.4.2", Sapi.CLI),
    ("docker-hub/library/php", "8.2.35-zts-bookworm", "8.2.35", Sapi.CLI),
    # A tag with no version, or one that is no PHP version.
    ("php", "latest", None, None), ("php", "fpm", None, None), ("php", "8-fpm", None, None),
    ("php", "8.3.12RC1", None, None), ("php", "main", None, None), ("php", "1.4.2", None, None),
    ("php", "2024.10.1", None, None), ("php", "10.1.2", None, None),
    # A full number counts unless what follows it reads as a distro revision or a pre-release.
    ("php", "8.3.12-1ubuntu2.28", "8.3", Sapi.UNKNOWN), ("php", "8.3.36-rc1", "8.3", Sapi.UNKNOWN),
    ("php", "8.3.12-fpm-prod", "8.3.12", Sapi.FPM),
    # Elsewhere a tag has to say php.
    ("app", "php8.3", "8.3", Sapi.UNKNOWN), ("app", "php8.3.12-fpm", "8.3.12", Sapi.FPM),
    ("shop/app", "php-8.3.12", "8.3.12", Sapi.UNKNOWN),
    ("app", "PHP-8.3.12-FPM", "8.3.12", Sapi.FPM),
    ("app", "bookworm-php8.3.12", "8.3.12", Sapi.UNKNOWN),
    ("app", "php-8.3-apache", "8.3", Sapi.MOD_PHP),
    ("app", "8.3.12-fpm", None, None), ("app", "latest", None, None),
    ("app", "php-fpm", None, None), ("app", "1.2.3", None, None),
    # php has to be the last part of the repository name.
    ("php-app", "8.3.12-fpm", None, None), ("phpmyadmin", "5.2.1", None, None),
    ("myphp", "8.3.12", None, None), ("php/app", "8.3.12", None, None),
]


@pytest.mark.parametrize("repo,tag,version,sapi", TAGS, ids=[f"{r}:{t}" for r, t, _, _ in TAGS])
def test_an_image_tag_names_a_php_version_or_it_does_not(world, repo, tag, version, sapi):
    world.stub_registry("myreg", {repo: [tag]})
    evs = inventory(world)
    if version is None:
        assert evs == []
    else:
        ev = only_one(evs)
        assert ev.detected_version == version
        assert ev.sapi is sapi
        assert ev.location == f"{SERVER}/{repo}:{tag}"
        assert ev.signals["resource"] == f"{SERVER}/{repo}"


def test_every_tag_of_a_repository_carries_its_name_and_folds_into_one_asset(world):
    world.stub_registry("myreg", {"php": ["7.4.33-fpm", "8.3.36-fpm", "8.3.36-apache", "latest"]})
    evs = inventory(world)
    assert {e.signals["resource"] for e in evs} == {f"{SERVER}/php"}
    assert len(evs) == 3
    inv = AssetInventory()
    for ev in evs:
        inv.add(ev)
    (asset,) = inv.assets()
    assert len(asset.evidence) == 3
    assert asset.key == f"{SERVER}/php"
    assert grade(asset, MATRIX)[0] is Verdict.EXPOSED


def test_repositories_in_two_registries_are_two_assets(world):
    world.stub_registry("one", {"php": ["8.3.36-fpm"]})
    world.stub_registry("two", {"php": ["8.3.36-fpm"]})
    inv = AssetInventory()
    for ev in inventory(world):
        inv.add(ev)
    assert [a.key for a in inv.assets()] == ["one.azurecr.io/php", "two.azurecr.io/php"]


def test_registries_with_no_php_tag_leave_nothing(world):
    world.stub_registry("a", {"web": ["1.0.0", "latest", "main-abc123"]})
    world.stub_registry("b", {})
    assert inventory(world) == []


def test_every_registry_is_opened_by_its_login_server_and_listed_once(world):
    world.stub_registry("one", {"php": ["8.3.36-fpm"], "web": ["1.0"]})
    world.stub_registry("two", {"worker": ["php8.2.35"]}, server="two.example.azurecr.io")
    inventory(world)
    assert [(k, s) for k, _, s in world.made if k == "registry_data"] == [
        ("registry_data", "one.azurecr.io"), ("registry_data", "two.example.azurecr.io")]
    assert [(c.scope, c.args) for c in world.calls if c.method == "list_tag_properties"] == [
        ("one.azurecr.io", ("php",)), ("one.azurecr.io", ("web",)),
        ("two.example.azurecr.io", ("worker",))]


ODD_LOGIN_SERVERS = [None, "", 5, ["x"], "a b", "x" * 300, "caf" + E_ACUTE + ".azurecr.io",
                     ".azurecr.io", "-a.azurecr.io", "a.azurecr.io\nINJECTED", "a/b.azurecr.io"]
REGISTRY_UNREAD = ("not inventoried: 1 entry in the list of registries could not be read "
                   "(no usable login server)")


@pytest.mark.parametrize("server", ODD_LOGIN_SERVERS)
def test_a_registry_with_no_usable_login_server_is_counted_and_never_opened(world, server):
    world.stub_registry("good", {"php": ["8.3.36-fpm"]})
    world.script("registries.list", [[NS(id=registry_id("odd"), login_server=server),
                                      world._registries[SUB][0]]])
    found, gap = inventory(world)
    assert found.detected_version == "8.3.36"
    assert gap.note == REGISTRY_UNREAD
    assert [s for k, _, s in world.made if k == "registry_data"] == ["good.azurecr.io"]


@pytest.mark.parametrize("entry", [None, 5, "x", [], {}, NS()])
def test_an_entry_that_is_no_registry_is_counted(world, entry):
    world.script("registries.list", [[entry]])
    assert only(world).note == REGISTRY_UNREAD


REPOSITORY_UNREAD = ("not inventoried: 1 entry in the list of repositories could not be read "
                     "(no usable name)")


@pytest.mark.parametrize("name", [
    None, 5, "", "a b", "x" * 300, "caf" + E_ACUTE, "a\nb", ["php"], "php:8.3", "php@sha"])
def test_a_repository_with_no_usable_name_is_counted_and_never_listed(world, name):
    world.stub_registry("myreg", {"php": ["8.3.36-fpm"]})
    world.script("list_repository_names", [[name, "php"]])
    found, gap = inventory(world)
    assert found.detected_version == "8.3.36"
    assert gap.note == REPOSITORY_UNREAD
    assert asked(world, "list_tag_properties") == [("php",)]


TAG_UNREAD = "not inventoried: 1 entry in the list of tags could not be read (no usable name)"


@pytest.mark.parametrize("tag", [
    None, 5, "", "8.3.36 ", "8.3.36\n", "8.3/36", "p" * 129, "php" + E_ACUTE + "8.3", ["x"]])
def test_a_tag_that_is_no_usable_name_is_counted_and_never_emitted(world, tag):
    world.stub_registry("myreg", {"php": []})
    world.script("list_tag_properties", [[TagProperties(name="8.3.36"), NS(name=tag)]])
    found, gap = inventory(world)
    assert found.detected_version == "8.3.36"
    assert gap.note == TAG_UNREAD


def test_a_tag_with_no_name_reads_as_empty_and_is_counted_like_any_other(world):
    # The SDK's own model holds "" when the service sent no name.
    world.stub_registry("myreg", {"php": []})
    world.script("list_tag_properties", [[TagProperties(), TagProperties(name="8.3.36")]])
    found, gap = inventory(world)
    assert found.detected_version == "8.3.36"
    assert gap.note == TAG_UNREAD


@pytest.mark.parametrize("entry", [None, 5, "8.3.36", NS(), NS(tag="8.3.36"), []])
def test_an_entry_that_is_no_tag_record_is_counted(world, entry):
    world.stub_registry("myreg", {"php": []})
    world.script("list_tag_properties", [[entry]])
    assert only(world).note == TAG_UNREAD


def test_a_tag_of_128_characters_reads_and_one_of_129_does_not(world):
    ok = "php8.3-" + "a" * 121
    assert len(ok) == 128
    world.stub_registry("myreg", {"shop": [ok + "a", ok]})
    found, gap = inventory(world)
    assert found.detected_version == "8.3"
    assert gap.note == TAG_UNREAD


def test_the_stand_in_tag_record_has_a_read_only_name():
    props = TagProperties(name="8.3-fpm")
    assert props.name == "8.3-fpm"
    with pytest.raises(AttributeError):
        props.name = "x"
    assert TagProperties().name == ""


# --- a registry that cannot be read ---

def test_a_registry_that_cannot_be_opened_is_a_row_that_names_it_and_the_others_are_read(world):
    for name in ("a", "b", "c"):
        world.stub_registry(name, {"php": ["8.3.36-fpm"]})
    world.fail("list_repository_names", denied(), scope="b.azurecr.io")
    evs = inventory(world)
    (gap,) = gaps(evs)
    assert gap.location == f"azure acr {SUB} b.azurecr.io"
    assert gap.signals == {"service": "acr", "kind": "skipped"}
    assert gap.note == f"not inventoried: {WHY_DENIED}"
    assert [e.signals["resource"] for e in finds(evs)] == ["a.azurecr.io/php", "c.azurecr.io/php"]
    assert SECRET not in text_of(evs)


def test_a_run_with_no_data_plane_access_leaves_a_row_for_every_registry(world):
    # The Reader role lists the registries and holds no data action, so each one is refused.
    for n in range(5):
        world.stub_registry(f"reg{n}", {"php": ["8.3.36-fpm"]})
    world.fail("list_repository_names", denied())
    evs = inventory(world)
    assert [e.location for e in evs] == [f"azure acr {SUB} reg{n}.azurecr.io" for n in range(5)]
    assert all(e.signals == {"service": "acr", "kind": "skipped"} for e in evs)
    assert len(asked(world, "list_repository_names")) == 5
    assert not [e for e in evs if "in a row" in e.note]


@pytest.mark.parametrize("exc,why", [
    (ClientAuthenticationError(SECRET, status=401),
     f"{CREDENTIAL_LOST} (ClientAuthenticationError 401)"),
    (HttpResponseError(SECRET, status=403), f"{DENIED} (HttpResponseError 403)"),
    (ServiceRequestError(SECRET), "the service could not be reached (ServiceRequestError)"),
    (ValueError(SECRET), "ValueError")])
def test_each_failure_of_the_data_plane_is_recorded_by_class_and_never_by_message(
        world, exc, why):
    world.stub_registry("myreg", {"php": ["8.3.36-fpm"]})
    world.fail("list_repository_names", exc)
    gap = only(world)
    assert gap.note == "not inventoried: " + why
    assert SECRET not in text_of(gap)


def test_a_failure_to_build_the_data_client_is_a_row_for_that_registry(world):
    world.stub_registry("a", {"php": ["8.3.36-fpm"]})
    world.fail_factory("registry_data", ValueError(SECRET))
    gap = only(world)
    assert gap.location == f"azure acr {SUB} a.azurecr.io"
    assert gap.note == "not inventoried: ValueError"


def test_the_names_listing_failing_after_some_repositories_keeps_them_and_adds_a_row(world):
    world.stub_registry("myreg", {"a": ["php8.3.36"], "b": ["php8.3.36"], "c": ["php8.3.36"]})
    pager = Pager([["a", "b"], ["c"]], fail_at=1, error=ServiceRequestError(SECRET))
    world.script("list_repository_names", [pager])
    *found, gap = inventory(world)
    assert [e.signals["resource"] for e in found] == [f"{SERVER}/a", f"{SERVER}/b"]
    assert gap.location == f"azure acr {SUB} {SERVER}"
    assert gap.note == "not inventoried: the service could not be reached (ServiceRequestError)"


def test_a_failing_repository_is_a_row_and_the_others_are_still_read(world):
    world.stub_registry("myreg", {n: ["php8.3.36"] for n in ("a", "b", "c")})
    world.fail("list_tag_properties", denied(), arg="b")
    evs = inventory(world)
    (gap,) = gaps(evs)
    assert gap.location == f"{SERVER}/b"
    assert gap.detected_version is None
    # Nothing in b was read, so nothing says it holds PHP.
    assert gap.signals == {"resource": f"{SERVER}/b", "service": "acr", "kind": "skipped"}
    assert gap.note == f"not fully inventoried: {WHY_DENIED}"
    assert {e.signals["resource"] for e in finds(evs)} == {f"{SERVER}/a", f"{SERVER}/c"}
    assert SECRET not in text_of(evs)


def test_a_repository_read_only_in_part_stays_indeterminate_whatever_it_showed(world):
    world.stub_registry("myreg", {"php": []})
    tags = [TagProperties(name=t) for t in ("8.3.36-fpm", "7.4.33-fpm", "8.2.35-fpm")]
    pager = Pager([tags[:1], tags[1:]], fail_at=1, error=ServiceRequestError(SECRET))
    world.script("list_tag_properties", [pager])
    seen, gap = inventory(world)
    assert grade_evidence(seen, MATRIX)[0] is Verdict.LIKELY_PATCHED
    assert gap.signals == {"resource": f"{SERVER}/php", "service": "acr", "kind": "skipped",
                           "php_present": "true"}
    inv = AssetInventory()
    for ev in (seen, gap):
        inv.add(ev)
    (asset,) = inv.assets()
    assert grade(asset, MATRIX)[0] is Verdict.INDETERMINATE


def test_a_repository_read_in_full_with_no_failure_is_not_held_back(world):
    world.stub_registry("myreg", {"php": ["8.3.36-fpm", "8.2.35-fpm"]})
    inv = AssetInventory()
    for ev in inventory(world):
        inv.add(ev)
    (asset,) = inv.assets()
    assert grade(asset, MATRIX)[0] is Verdict.LIKELY_PATCHED


def test_the_registry_read_stops_after_repositories_fail_in_a_row(world):
    world.stub_registry("one", {f"r{i}": ["php8.3.36"] for i in range(4)})
    world.stub_registry("two", {f"r{i}": ["php8.3.36"] for i in range(4)})
    world.fail("list_tag_properties", ServiceRequestError(SECRET))
    evs = inventory(world)
    assert asked(world, "list_tag_properties") == [(f"r{i}",) for i in range(azure._MAX_MISSES)]
    *repos, stop = evs
    assert len(repos) == azure._MAX_MISSES
    assert stop.location == f"azure acr {SUB}"
    assert stop.signals == {"service": "acr", "kind": "skipped"}
    assert stop.note == (
        f"not inventoried: {azure._MAX_MISSES} repositories in a row could not be read")
    # The second registry is never opened, because the run of failures ended the read.
    assert [s for k, _, s in world.made if k == "registry_data"] == ["one.azurecr.io"]


def test_a_run_of_failures_carries_over_from_one_registry_to_the_next(world):
    world.stub_registry("one", {"a": ["php8.3.36"], "b": ["php8.3.36"]})
    world.stub_registry("two", {"c": ["php8.3.36"], "d": ["php8.3.36"]})
    world.fail("list_tag_properties", ServiceRequestError(SECRET))
    evs = inventory(world)
    assert asked(world, "list_tag_properties") == [("a",), ("b",), ("c",)]
    assert evs[-1].note.endswith("3 repositories in a row could not be read")


def test_a_repository_that_reads_ends_the_run_of_failures(world):
    names = ["a", "b", "c", "d", "e", "f"]
    world.stub_registry("myreg", {n: ["php8.3.36"] for n in names})
    # Two fail, one reads, two fail, one reads. No run reaches the limit.
    for name in ("a", "b", "d", "e"):
        world.fail("list_tag_properties", ServiceRequestError(SECRET), arg=name)
    evs = inventory(world)
    assert asked(world, "list_tag_properties") == [(n,) for n in names]
    assert len([e for e in evs if e.note.startswith("not fully")]) == 4
    assert not [e for e in evs if "in a row" in e.note]


def test_repository_failures_with_reads_between_them_never_end_the_read(world):
    names = [f"r{i}" for i in range(8)]
    world.stub_registry("myreg", {n: ["php8.3.36"] for n in names})
    for name in ("r2", "r6"):
        world.fail("list_tag_properties", ServiceRequestError(SECRET), arg=name)
    evs = inventory(world)
    assert asked(world, "list_tag_properties") == [(n,) for n in names]
    assert (len(finds(evs)), len(gaps(evs))) == (6, 2)


def test_a_registry_that_cannot_be_opened_does_not_count_toward_the_run_of_failures(world):
    for n in range(4):
        world.stub_registry(f"reg{n}", {"php": ["8.3.36-fpm"]})
    world.fail("list_repository_names", denied(), scope="reg0.azurecr.io")
    world.fail("list_repository_names", denied(), scope="reg1.azurecr.io")
    world.fail("list_repository_names", denied(), scope="reg2.azurecr.io")
    evs = inventory(world)
    assert len(gaps(evs)) == 3
    assert [e.signals["resource"] for e in finds(evs)] == ["reg3.azurecr.io/php"]


def test_the_tag_failure_of_a_repository_after_a_read_one_leaves_the_earlier_find(world):
    world.stub_registry("myreg", {"a": ["php8.3.36"], "b": ["php8.3.36"]})
    world.fail("list_tag_properties", ServiceRequestError(SECRET), arg="b")
    found, gap = inventory(world)
    assert found.signals["resource"] == f"{SERVER}/a"
    assert gap.signals["resource"] == f"{SERVER}/b"


# --- what goes wrong in a call ---

METHODS = [("appservice", "web_apps.list"),
           ("containerapps", "container_apps.list_by_subscription"), ("acr", "registries.list")]


@pytest.mark.parametrize("service,method", METHODS)
def test_a_management_client_that_raises_a_permission_error_leaves_one_skipped_row(
        world, service, method):
    stubbed_everything(world)
    world.fail(method, denied())
    evs = inventory(world)
    (gap,) = gaps(evs)
    assert gap.source is Source.CLOUD
    assert gap.location == f"azure {service} {SUB}"
    assert gap.detected_version is None
    assert gap.sapi is Sapi.UNKNOWN
    assert gap.signals == {"service": service, "kind": "skipped"}
    assert gap.note == f"not inventoried: {WHY_DENIED}"
    # The other two services still answer.
    assert {e.signals["service"] for e in evs} == set(SERVICES)
    assert len(finds(evs)) == 2
    assert SECRET not in text_of(evs)


@pytest.mark.parametrize("exc,why", [
    (denied(), WHY_DENIED),
    (HttpResponseError(SECRET, status=403), f"{DENIED} (HttpResponseError 403)"),
    (HttpResponseError(SECRET, status=401, code="InvalidAuthenticationToken"),
     f"{DENIED} (HttpResponseError 401 InvalidAuthenticationToken)"),
    (ClientAuthenticationError(SECRET), f"{CREDENTIAL_LOST} (ClientAuthenticationError)"),
    (ClientAuthenticationError(SECRET, status=401, code="InvalidAuthenticationToken"),
     f"{CREDENTIAL_LOST} (ClientAuthenticationError 401 InvalidAuthenticationToken)"),
    (CredentialUnavailableError(SECRET), "no Azure credential was found "
     "(CredentialUnavailableError)"),
    (HttpResponseError(SECRET, status=409, code="MissingSubscriptionRegistration"),
     "the resource provider is not registered in the subscription "
     "(HttpResponseError 409 MissingSubscriptionRegistration)"),
    (ResourceNotFoundError(SECRET, status=404, code="SubscriptionNotFound"),
     "ResourceNotFoundError 404 SubscriptionNotFound"),
    (HttpResponseError(SECRET, status=429, code="TooManyRequests"),
     "HttpResponseError 429 TooManyRequests"),
    (HttpResponseError(SECRET, status=500), "HttpResponseError 500"),
    (HttpResponseError(SECRET), "HttpResponseError"),
    (ServiceRequestError(SECRET), "the service could not be reached (ServiceRequestError)"),
    (ValueError(SECRET), "ValueError"), (OSError(SECRET), "OSError"),
    (KeyError(SECRET), "KeyError"), (TypeError(SECRET), "TypeError"),
])
def test_a_failure_is_recorded_by_class_status_and_code_and_never_by_message(world, exc, why):
    world.stub_site("app1")
    world.fail("web_apps.list", exc)
    gap = only(world)
    assert gap.note == "not inventoried: " + why
    assert SECRET not in text_of(gap)


@pytest.mark.parametrize("status,code,why", [
    (True, None, "HttpResponseError"), (99, None, "HttpResponseError"),
    (600, None, "HttpResponseError"), ("403", None, "HttpResponseError"),
    (None, "x" * 65, "HttpResponseError"), (None, "a b", "HttpResponseError"),
    (None, "caf" + E_ACUTE, "HttpResponseError"), (None, 5, "HttpResponseError"),
    (None, "HttpResponseError", "HttpResponseError"),
    (500, "x" * 64, "HttpResponseError 500 " + "x" * 64)])
def test_a_status_or_a_code_that_is_not_one_is_left_out_of_the_reason(world, status, code, why):
    exc = HttpResponseError(SECRET)
    exc.status_code = status
    exc.error = NS(code=code)
    world.fail("web_apps.list", exc)
    assert only(world).note == "not inventoried: " + why


@pytest.mark.parametrize("error", [None, 5, "AuthorizationFailed", NS(), NS(code=None)])
def test_an_error_object_that_is_not_the_documented_shape_is_left_out_of_the_reason(world, error):
    exc = HttpResponseError(SECRET, status=500)
    exc.error = error
    world.fail("web_apps.list", exc)
    assert only(world).note == "not inventoried: HttpResponseError 500"


def test_an_error_that_a_pager_raises_midway_is_recorded_the_same_way(world):
    site = world.stub_site("app1")
    pager = Pager([[site]], fail_at=1, error=denied())
    world.script("web_apps.list", [pager])
    *found, gap = inventory(world)
    assert len(found) == 1
    assert gap.note == f"not inventoried: {WHY_DENIED}"


def test_an_error_on_the_first_page_of_a_pager_is_a_row_and_no_find(world):
    world.stub_site("app1")
    world.script("web_apps.list", [Pager([], fail_at=0, error=denied())])
    (gap,) = inventory(world)
    assert gap.location == f"azure appservice {SUB}"


def test_a_factory_that_raises_is_a_row_for_that_service_and_the_others_still_read(world):
    stubbed_everything(world)
    world.fail_factory("container_apps", ValueError(SECRET))
    evs = inventory(world)
    (gap,) = gaps(evs)
    assert gap.location == f"azure containerapps {SUB}"
    assert gap.note == "not inventoried: ValueError"
    assert len(finds(evs)) == 2
    assert SECRET not in text_of(evs)


@pytest.mark.parametrize("missing", ["web", "container_apps", "registries", "registry_data"])
def test_a_bundle_that_lacks_a_factory_leaves_a_row_and_never_a_crash(world, missing):
    stubbed_everything(world)
    bundle = NS(web=world.web, container_apps=world.container_apps, registries=world.registries,
                registry_data=world.registry_data, subscription_id=SUB)
    delattr(bundle, missing)
    evs = AzureSource(world.credential, bundle).inventory()
    (gap,) = gaps(evs)
    assert gap.note == f"not inventoried: the clients have no {missing}"
    assert len(finds(evs)) == 2


@pytest.mark.parametrize("factory", [None, 5, "web", []])
def test_a_factory_that_is_not_callable_is_a_row_too(world, factory):
    stubbed_everything(world)
    bundle = NS(web=factory, container_apps=world.container_apps, registries=world.registries,
                registry_data=world.registry_data, subscription_id=SUB)
    (gap,) = gaps(AzureSource(world.credential, bundle).inventory())
    assert gap.note == "not inventoried: the clients have no web"


@pytest.mark.parametrize("bad", [None, 5, 1.5, "x", b"x", True, object(), NS()])
def test_an_answer_that_is_not_a_listing_ends_it_with_a_row(world, bad):
    world.script("web_apps.list", [bad])
    assert only(world).note == "not inventoried: the answer is not understood"


@pytest.mark.parametrize("make", [lambda: iter([]), lambda: [], lambda: ()])
def test_any_empty_listing_is_a_finished_read_and_no_failure(world, make):
    for method in ("web_apps.list", "container_apps.list_by_subscription", "registries.list"):
        world.script(method, [make()])
    assert inventory(world) == []


def test_a_listing_with_no_by_page_is_read_as_one_page(world):
    world.stub_site("a")
    world.script("web_apps.list", [iter(world._sites[SUB])])
    assert [e.detected_version for e in inventory(world)] == ["8.3"]


def test_a_by_page_that_hands_back_no_pages_ends_the_listing_with_a_row(world):
    class Odd:
        def __iter__(self):
            return iter([])

        def by_page(self):
            return 5

    world.script("web_apps.list", [Odd()])
    assert only(world).note == "not inventoried: the answer is not understood"


def test_a_by_page_that_is_no_method_leaves_the_answer_to_be_read_as_one_page(world):
    site = world.stub_site("a")

    class Odd:
        by_page = 5

        def __iter__(self):
            return iter([site])

    world.script("web_apps.list", [Odd()])
    assert [e.detected_version for e in inventory(world)] == ["8.3"]


def test_a_page_that_is_no_list_ends_the_listing_with_a_row(world):
    class Odd:
        def __iter__(self):
            return iter([])

        def by_page(self):
            return iter([5])

    world.script("web_apps.list", [Odd()])
    assert only(world).note == "not inventoried: the answer is not understood"


def test_a_listing_that_never_ends_is_cut_and_says_so(world, monkeypatch):
    monkeypatch.setattr(azure, "_MAX_PAGES", 5)
    site = world.stub_site("app1")
    pager = Pager([], forever=[site])
    world.script("web_apps.list", [pager])
    *found, gap = inventory(world)
    assert len(found) == 5
    assert gap.note == "not inventoried: the list runs past 5 pages"
    assert gap.location == f"azure appservice {SUB}"


def test_a_listing_of_exactly_the_limit_is_read_in_full(world, monkeypatch):
    monkeypatch.setattr(azure, "_MAX_PAGES", 5)
    site = world.stub_site("app1")
    world.script("web_apps.list", [Pager([[site]] * 5)])
    assert len(inventory(world)) == 5


def test_every_page_of_every_listing_is_read(world):
    world.page = 2
    for n in range(5):
        world.stub_site(f"s{n}")
        world.stub_app(f"c{n}", [f"{SERVER}/php:8.3.36"])
    world.stub_registry("myreg", {repo: [f"8.3.{n}-fpm" for n in range(30, 33)]
                                  for repo in ("php", "library/php", "mirror/php")})
    world.stub_registry("other", {"web": [f"php8.2.{n}" for n in range(30, 33)]})
    evs = inventory(world)
    by_service = {s: [e for e in evs if e.signals["service"] == s] for s in SERVICES}
    assert [len(by_service[s]) for s in SERVICES] == [5, 5, 12]
    assert not gaps(evs)
    assert world.touched == []


def test_unreadable_entries_are_still_counted_when_the_listing_then_fails(world):
    good = world.stub_site("app1")
    pager = Pager([[None, good]], fail_at=1, error=ServiceRequestError(SECRET))
    world.script("web_apps.list", [pager])
    found, stop, unread = inventory(world)
    assert found.location == site_id()
    assert stop.note == "not inventoried: the service could not be reached (ServiceRequestError)"
    assert unread.note == SITE_UNREAD


def test_the_count_of_unreadable_entries_is_plural_when_it_should_be(world):
    world.script("web_apps.list", [[None, 5, NS(id="")]])
    world.script("container_apps.list_by_subscription", [[None, NS(id="x")]])
    notes = {e.signals["service"]: e.note for e in inventory(world)}
    assert notes == {
        "appservice": ("not inventoried: 3 entries in the list of sites could not be read "
                       "(no usable resource ID)"),
        "containerapps": ("not inventoried: 2 entries in the list of container apps could not "
                          "be read (no usable resource ID or container list)")}


# --- how the grader reads what the source writes ---

@pytest.mark.parametrize("tag,verdict,confidence", [
    ("8.3.36-fpm", Verdict.LIKELY_PATCHED, Confidence.HIGH),
    ("8.3.35-fpm", Verdict.EXPOSED, Confidence.HIGH),
    ("7.4.33-cli", Verdict.EXPOSED, Confidence.HIGH),
    ("8.3-fpm", Verdict.INDETERMINATE, Confidence.MEDIUM),
    ("8.3.12-1ubuntu2.28", Verdict.INDETERMINATE, Confidence.MEDIUM),
])
def test_registry_evidence_grades_as_the_version_it_names(world, tag, verdict, confidence):
    # An end of life build grades EXPOSED when the tag gives a full number to compare.
    world.stub_registry("myreg", {"php": [tag]})
    assert grade_evidence(only(world), MATRIX) == (verdict, confidence)


@pytest.mark.parametrize("image,verdict", [
    (f"{SERVER}/php:7.4.33-apache", Verdict.EXPOSED), (f"{SERVER}/php:8.1.30", Verdict.EXPOSED),
    (f"{SERVER}/php:8.2.35-fpm", Verdict.LIKELY_PATCHED),
    (f"{SERVER}/php:8.3", Verdict.INDETERMINATE)])
def test_container_app_evidence_grades_as_the_version_its_image_names(world, image, verdict):
    world.stub_app("capp1", [image])
    assert grade_evidence(only(world), MATRIX)[0] is verdict


def test_a_gap_row_grades_indeterminate_at_low_confidence(world):
    stubbed_everything(world)
    world.fail("container_apps.list_by_subscription", denied())
    gap = gaps(inventory(world))[0]
    assert grade_evidence(gap, MATRIX) == (Verdict.INDETERMINATE, Confidence.LOW)
    inv = AssetInventory()
    inv.add(gap)
    (asset,) = inv.assets()
    assert grade(asset, MATRIX) == (Verdict.INDETERMINATE, Confidence.LOW)


# --- subscriptions ---

def test_the_default_subscription_is_the_bundles_own_and_the_calls_are_exactly_the_reads(world):
    stubbed_everything(world)
    source = AzureSource(world.credential, world)
    assert source.subscriptions == (SUB,)
    source.inventory()
    assert [(c.method, c.scope, c.args, c.kwargs) for c in world.calls] == [
        ("web_apps.list", SUB, (), {}),
        ("web_apps.get_configuration", SUB, ("rg1", "app1"), {}),
        ("container_apps.list_by_subscription", SUB, (), {}),
        ("registries.list", SUB, (), {}),
        ("list_repository_names", SERVER, (), {}),
        ("list_tag_properties", SERVER, ("php",), {})]


def test_every_client_is_built_from_the_credential_and_its_scope_and_closed_when_done(world):
    stubbed_everything(world)
    inventory(world)
    assert [(k, s) for k, _, s in world.made] == [
        ("web", SUB), ("container_apps", SUB), ("registries", SUB), ("registry_data", SERVER)]
    assert all(c is world.credential for _, c, _ in world.made)
    assert sorted((k, s) for k, _, s in world.made) == sorted(world.closed)
    assert world.credential.touched == []


def test_clients_are_closed_when_a_read_ends_in_a_failure(world):
    stubbed_everything(world)
    world.fail("web_apps.list", denied())
    world.fail("list_tag_properties", ServiceRequestError(SECRET))
    inventory(world)
    assert sorted((k, s) for k, _, s in world.made) == sorted(world.closed)


def test_a_client_that_fails_to_close_does_not_lose_what_was_read(world):
    stubbed_everything(world)

    class Stubborn(Mgmt):
        def close(self):
            raise OSError(SECRET)

    world.web = lambda credential, subscription: Stubborn(world, "web", subscription)
    evs = inventory(world)
    assert len(evs) == 3
    assert SECRET not in text_of(evs)


def test_a_client_with_no_close_is_left_as_it_is(world):
    stubbed_everything(world)
    world.web = lambda credential, subscription: NS(
        web_apps=Mgmt(world, "web", subscription).web_apps)
    assert len(inventory(world)) == 3


def test_every_call_takes_no_keyword_the_sdk_could_misread(world):
    stubbed_everything(world)
    inventory(world)
    assert world.calls
    assert all(c.kwargs == {} for c in world.calls)


def test_each_subscription_given_is_read_and_a_row_names_the_one_that_failed():
    world = World()
    world.stub_site("app1", linux="PHP|8.3")
    world.stub_site("app2", linux="PHP|7.4", sub=OTHER)
    world.stub_app("capp1", [f"{SERVER}/php:8.3.36"], sub=OTHER)
    world.fail("container_apps.list_by_subscription", denied(), scope=OTHER)
    source = AzureSource(world.credential, world, subscriptions=[SUB, OTHER])
    assert source.subscriptions == (SUB, OTHER)
    evs = source.inventory()
    assert [e.signals["resource"] for e in finds(evs)] == [
        site_id("app1"), site_id("app2", sub=OTHER)]
    assert [e.location for e in gaps(evs)] == [f"azure containerapps {OTHER}"]
    assert [(k, s) for k, _, s in world.made if k == "web"] == [("web", SUB), ("web", OTHER)]


def test_the_same_credential_serves_every_subscription():
    world = World()
    AzureSource(world.credential, world, subscriptions=[SUB, OTHER]).inventory()
    assert len({id(c) for _, c, _ in world.made}) == 1


@pytest.mark.parametrize("subscriptions", [[], (), None, iter(()), ""])
def test_no_subscriptions_given_reads_the_bundles_own(world, subscriptions):
    assert AzureSource(world.credential, world, subscriptions=subscriptions).subscriptions == (SUB,)


@pytest.mark.parametrize("subscriptions", [
    OTHER, [OTHER], (OTHER,), iter([OTHER]), (s for s in [OTHER])])
def test_one_subscription_as_a_string_a_list_a_tuple_or_an_iterator_is_one_subscription(
        world, subscriptions):
    # A bare id read as a sequence would be one subscription for each of its letters.
    got = AzureSource(world.credential, world, subscriptions=subscriptions).subscriptions
    assert got == (OTHER,)


def test_subscriptions_assigned_after_the_source_is_made_are_the_ones_read(world):
    world.stub_site("app1", sub=OTHER)
    source = AzureSource(world.credential, world)
    source.subscriptions = (OTHER,)
    assert only_one(source.inventory()).signals["resource"].startswith(f"/subscriptions/{OTHER}/")


def test_inventory_can_run_twice_and_gives_the_same_answer(world):
    stubbed_everything(world)
    source = AzureSource(world.credential, world)
    assert source.inventory() == source.inventory()


# --- which subscriptions are read ---
# The ones the caller names come first, then the bundle's own, and only then the function that
# lists the subscriptions of the credential. That function is a read, so it is never called when
# an earlier source has an answer, and a failure of it is one row.

def listing_world(*visible):
    """A bundle with no default subscription, whose function lists the IDs given."""
    world = World(subscription=None)
    world.visible = list(visible)
    return world


def only_row(world, **kw):
    """The one row that inventory() returns when the scope cannot be found."""
    (row,) = inventory(world, **kw)
    assert row.source is Source.CLOUD
    assert row.location == "azure subscriptions"
    assert row.detected_version is None and row.sapi is Sapi.UNKNOWN
    assert row.signals == {"service": "subscriptions", "kind": "skipped"}
    assert world.calls == [] and world.made == []
    assert grade_evidence(row, MATRIX) == (Verdict.INDETERMINATE, Confidence.LOW)
    return row


@pytest.mark.parametrize("how", ["constructor", "attribute"])
def test_subscriptions_that_are_named_are_read_and_the_credential_is_never_asked_to_list(how):
    world = listing_world(OTHER)
    world.stub_site("app1", sub=SUB)
    named = [SUB] if how == "constructor" else None
    source = AzureSource(world.credential, world, subscriptions=named)
    if how == "attribute":
        source.subscriptions = [SUB]
    assert source.subscriptions == (SUB,)
    assert [e.location for e in source.inventory()] == [site_id("app1")]
    assert world.enumerated == []
    assert source.subscriptions == (SUB,)


def test_names_that_are_unusable_are_not_replaced_by_the_subscriptions_the_credential_lists():
    # Naming a subscription wrongly must never widen the scan to everything the credential sees.
    world = listing_world(SUB)
    rows = inventory(world, subscriptions=["Azure for Students"])
    assert [(e.location, e.note) for e in rows] == [
        (f"azure {service}", "not inventoried: the subscription id is not usable")
        for service in SERVICES]
    assert world.enumerated == [] and world.calls == []


def test_an_unusable_bundle_default_is_not_replaced_by_the_subscriptions_the_credential_lists():
    # The same guard for the default. A display name in subscription_id is used as it stands, and
    # it never hands the scan over to everything the credential can see.
    world = listing_world(SUB)
    world.subscription_id = "Azure for Students"
    source = AzureSource(world.credential, world)
    assert source.subscriptions == ("Azure for Students",)
    rows = source.inventory()
    assert [(e.location, e.note) for e in rows] == [
        (f"azure {service}", "not inventoried: the subscription id is not usable")
        for service in SERVICES]
    assert world.enumerated == [] and world.calls == [] and world.made == []
    assert source.subscriptions == ("Azure for Students",)


@pytest.mark.parametrize("named", [[None, ""], (None,), "", [""], iter([None])])
def test_names_that_are_all_empty_leave_the_scope_to_the_bundle_and_then_the_credential(named):
    world = listing_world(SUB)
    world.stub_site("app1", sub=SUB)
    source = AzureSource(world.credential, world, subscriptions=named)
    assert source.subscriptions == ()
    assert [e.location for e in source.inventory()] == [site_id("app1")]
    assert world.enumerated == [world.credential]


def test_the_bundles_own_subscription_is_read_and_the_credential_is_never_asked_to_list(world):
    world.visible = [OTHER]
    world.stub_site("app1")
    source = AzureSource(world.credential, world)
    assert source.subscriptions == (SUB,)
    assert [e.location for e in source.inventory()] == [site_id("app1")]
    assert world.enumerated == []
    assert source.subscriptions == (SUB,)


def test_with_nothing_named_or_defaulted_the_credential_is_asked_and_the_ids_it_lists_are_read():
    world = listing_world(SUB, OTHER)
    world.stub_site("app1", sub=SUB)
    world.stub_site("app2", linux="PHP|7.4", sub=OTHER)
    source = AzureSource(world.credential, world)
    # Nothing is listed until inventory() needs it.
    assert source.subscriptions == ()
    assert world.enumerated == []
    evs = source.inventory()
    assert len(world.enumerated) == 1 and world.enumerated[0] is world.credential
    assert source.subscriptions == (SUB, OTHER)
    assert [e.signals["resource"] for e in evs] == [site_id("app1"), site_id("app2", sub=OTHER)]
    assert [(k, s) for k, _, s in world.made if k == "web"] == [("web", SUB), ("web", OTHER)]
    assert world.credential.touched == []


@pytest.mark.parametrize("exc,why", [
    (denied(), WHY_DENIED),
    (ClientAuthenticationError(SECRET, status=401),
     f"{CREDENTIAL_LOST} (ClientAuthenticationError 401)"),
    (CredentialUnavailableError(SECRET), "no Azure credential was found "
     "(CredentialUnavailableError)"),
    (ServiceRequestError(SECRET), "the service could not be reached (ServiceRequestError)"),
    (ValueError(SECRET), "ValueError")])
def test_a_failure_to_list_the_subscriptions_is_one_skipped_row_and_reads_nothing(exc, why):
    world = listing_world(SUB)
    world.stub_site("app1", sub=SUB)
    world.enumeration_error = exc
    source = AzureSource(world.credential, world)
    row = only_row(world)
    assert row.note == f"not inventoried: {NO_SCOPE}: {why}"
    assert SECRET not in text_of(row)
    assert source.inventory() == [row] and source.subscriptions == ()


@pytest.mark.parametrize("make", [
    lambda: [], lambda: (), lambda: iter(()), lambda: [None, "", None]])
def test_a_list_with_no_id_in_it_is_one_skipped_row_and_reads_nothing(make):
    world = World(subscription=None)
    world.visible = make()
    row = only_row(world)
    assert row.note == f"not inventoried: {NO_SCOPE}: the list of subscriptions is empty"
    assert len(world.enumerated) == 1


@pytest.mark.parametrize("bundle", [NS(), NS(subscription_id=None), NS(subscription_ids=None),
                                    NS(subscription_ids="not a function")])
def test_a_bundle_with_no_function_to_list_them_leaves_one_skipped_row(bundle):
    source = AzureSource(Credential(), bundle)
    assert source.subscriptions == ()
    (row,) = source.inventory()
    assert (row.location, row.signals, row.note) == (
        "azure subscriptions", {"service": "subscriptions", "kind": "skipped"},
        f"not inventoried: {NO_SCOPE}")
    assert source.subscriptions == ()


@pytest.mark.parametrize("answer", [None, 5, 1.5, True, SUB, b"sub", NS()])
def test_an_answer_that_is_no_list_of_ids_is_one_skipped_row(answer):
    world = World(subscription=None)
    world.subscription_ids = lambda credential: answer
    assert only_row(world).note == f"not inventoried: {NO_SCOPE}: the answer is not understood"


def test_a_list_that_fails_partway_is_one_skipped_row_and_no_partial_scope():
    world = World(subscription=None)
    world.stub_site("app1", sub=SUB)

    def partway(credential):
        yield SUB
        raise ServiceRequestError(SECRET)

    world.subscription_ids = partway
    source = AzureSource(world.credential, world)
    row = only_row(world)
    assert row.note == (f"not inventoried: {NO_SCOPE}: "
                        "the service could not be reached (ServiceRequestError)")
    assert source.subscriptions == ()


def test_empty_entries_in_the_list_are_left_out():
    world = listing_world(None, SUB, "")
    world.stub_site("app1", sub=SUB)
    source = AzureSource(world.credential, world)
    assert [e.location for e in source.inventory()] == [site_id("app1")]
    assert source.subscriptions == (SUB,)


def test_a_listed_id_that_is_no_name_is_a_row_per_service_like_a_named_one():
    world = listing_world("my subscription")
    rows = inventory(world)
    assert [(e.location, e.note) for e in rows] == [
        (f"azure {service}", "not inventoried: the subscription id is not usable")
        for service in SERVICES]
    assert world.calls == [] and world.made == []


def test_the_subscriptions_are_listed_afresh_each_time_nothing_names_them():
    world = listing_world(SUB)
    world.stub_site("app1", sub=SUB)
    world.stub_site("app2", sub=OTHER)
    source = AzureSource(world.credential, world)
    world.enumeration_error = ServiceRequestError(SECRET)
    (row,) = source.inventory()
    assert source.subscriptions == ()
    world.enumeration_error = None
    first = source.inventory()
    assert source.subscriptions == (SUB,)
    world.visible = [SUB, OTHER]
    second = source.inventory()
    assert source.subscriptions == (SUB, OTHER)
    assert len(world.enumerated) == 3
    assert [e.location for e in first] == [site_id("app1")]
    assert [e.location for e in second] == [site_id("app1"), site_id("app2", sub=OTHER)]
    # A failure after a good run leaves no scope behind, so the note never reports a stale one.
    world.enumeration_error = ServiceRequestError(SECRET)
    assert len(source.inventory()) == 1
    assert source.subscriptions == ()


def test_naming_subscriptions_after_a_run_pins_them_and_an_empty_assignment_lets_go():
    world = listing_world(SUB, OTHER)
    world.stub_site("app1", sub=SUB)
    world.stub_site("app2", sub=OTHER)
    source = AzureSource(world.credential, world)
    source.inventory()
    assert source.subscriptions == (SUB, OTHER)
    source.subscriptions = [OTHER]
    assert [e.location for e in source.inventory()] == [site_id("app2", sub=OTHER)]
    assert len(world.enumerated) == 1
    source.subscriptions = []
    assert source.subscriptions == ()
    assert len(source.inventory()) == 2 and len(world.enumerated) == 2


@pytest.mark.parametrize("subscription", [
    "my subscription", "sub/with/slash", "../x", "a\nb", "caf" + E_ACUTE, "x" * 300, 42,
    "sub\x00", "Azure for Students"])
def test_a_subscription_that_is_no_id_is_a_row_per_service_and_no_call(world, subscription):
    rows = inventory(world, subscriptions=[subscription])
    assert [(e.location, e.note) for e in rows] == [
        (f"azure {service}", "not inventoried: the subscription id is not usable")
        for service in SERVICES]
    assert world.calls == [] and world.made == []


# --- the protocol and the optional extra ---

def test_the_source_satisfies_the_protocol(world):
    assert isinstance(AzureSource(world.credential, world), CloudSource)
    assert not isinstance(object(), CloudSource)


def test_importing_the_module_does_not_import_the_sdk():
    code = ("import sys\n"
            "import php_radar.sources.cloud, php_radar.sources.cloud.azure\n"
            "bad = [m for m in sys.modules if m.split('.')[0] in ('azure', 'msrest', 'isodate',"
            " 'msal', 'requests')]\n"
            "assert not bad, bad\n")
    done = subprocess.run([sys.executable, "-c", code], cwd=str(ROOT), capture_output=True,
                          text=True, timeout=60)
    assert done.returncode == 0, done.stderr


# --- read-only, and nothing taken from the answers but the fields it names ---

def test_only_the_six_reads_are_called_and_nothing_else_is_touched(world):
    stubbed_everything(world)
    inventory(world)
    assert {c.method for c in world.calls} == READS
    assert world.touched == []
    assert world.credential.touched == []


def test_a_response_field_the_source_does_not_name_never_reaches_the_evidence(world):
    stubbed_everything(world)
    world.fail("list_tag_properties", denied())
    evs = inventory(world)
    # The site, the container, and the repository whose tags could not be listed.
    assert len(evs) == 3
    for ev in evs:
        assert SECRET not in text_of(ev)
    for out in rendered(evs):
        assert SECRET not in out


def test_the_app_settings_and_connection_strings_of_a_site_are_never_copied(any_world):
    any_world.stub_site("app1", linux="PHP|8.3")
    config = any_world.configs[(SUB, "app1")][1]
    holder = config["properties"] if any_world.style == "flat" else config
    assert holder.app_settings[0].value == SECRET
    assert holder.connection_strings[0].connection_string == SECRET
    ev = only(any_world)
    assert SECRET not in text_of(ev)
    assert all(SECRET not in out for out in rendered([ev]))


def test_the_environment_of_a_container_is_never_copied(world):
    app = world.stub_app("capp1", [f"{SERVER}/php:8.3.36"])
    assert app.template.containers[0].env[0].value == SECRET
    ev = only(world)
    assert SECRET not in text_of(ev)
    assert all(SECRET not in out for out in rendered([ev]))


def test_the_report_prints_names_whole_whatever_they_are_called(world):
    site = site_id("token-key-auth-password", "rg-pass-vault")
    world.stub_site("token-key-auth-password", group="rg-pass-vault", linux="PHP|8.3")
    world.stub_app("auth-api-key", [f"{SERVER}/token-service:php8.3.36"], group="rg-secret")
    world.stub_registry("keyvaultreg", {"keycloak-php": ["php8.3.36"]})
    console, as_json, sarif = rendered(inventory(world))
    for out in (console, as_json, sarif):
        assert site in out
        assert app_id("auth-api-key", "rg-secret") in out
        assert "keyvaultreg.azurecr.io/keycloak-php" in out
        assert out.isascii()
    assert "linux_fx_version PHP|8.3 names only the PHP branch, so the build is not read" in console
    assert f"{SERVER}/token-service:php8.3.36" in console
    assert json.loads(as_json)["summary"]["total"] == 3
    json.loads(sarif)


def test_a_failed_service_reads_as_a_row_in_the_report(world):
    world.fail("web_apps.list", ClientAuthenticationError(SECRET, status=401))
    console = rendered(inventory(world))[0]
    assert f"azure appservice {SUB}" in console
    assert f"not inventoried: {CREDENTIAL_LOST} (ClientAuthenticationError 401)" in console
    assert "INDETERMINATE" in console
    assert SECRET not in console


# --- the stand-ins keep the shape of the SDK ---

def test_the_pager_stand_in_is_an_iterator_with_no_length_and_no_index():
    pager = Pager([[1, 2], [3]])
    assert isinstance(pager, abc.Iterator)
    assert iter(pager) is pager
    assert not hasattr(pager, "__len__") and not hasattr(pager, "__getitem__")
    assert pager.fetched == 0
    assert list(pager) == [1, 2, 3]
    assert pager.fetched == 2
    assert list(pager) == []


def test_the_pager_stand_in_fetches_a_page_only_when_the_one_before_is_spent():
    pager = Pager([[1, 2], [3, 4]])
    assert next(pager) == 1 and pager.fetched == 1
    assert next(pager) == 2 and pager.fetched == 1
    assert next(pager) == 3 and pager.fetched == 2


def test_the_pager_stand_in_hands_back_pages_that_are_iterators_with_a_continuation():
    pages = Pager([[1, 2], [3]]).by_page()
    first = next(pages)
    assert isinstance(first, abc.Iterator) and list(first) == [1, 2]
    assert pages.continuation_token is not None
    assert list(next(pages)) == [3]
    assert pages.continuation_token is None
    with pytest.raises(StopIteration):
        next(pages)


def test_the_pager_stand_in_raises_at_the_page_that_fails_after_the_ones_before_it():
    pager = Pager([[1], [2]], fail_at=1, error=ServiceRequestError("x"))
    assert next(pager) == 1
    with pytest.raises(ServiceRequestError):
        next(pager)


def test_a_model_of_the_newer_generation_reads_its_fields_through_properties():
    config = SiteConfigResource(properties=NS(linux_fx_version="PHP|8.3"), id="x")
    assert config.linux_fx_version == "PHP|8.3"
    assert config.php_version is None
    assert SiteConfigResource().linux_fx_version is None
    assert vars(config) == {"_data": {"properties": config["properties"], "id": "x"}}
    assert isinstance(config, abc.MutableMapping) and list(config) == ["id", "properties"]
    with pytest.raises(AttributeError):
        config.nothing


# --- the same reads against the real azure-core and the real management models ---
# These run when the SDK packages are installed and are skipped otherwise.

@pytest.fixture
def core():
    paging = pytest.importorskip("azure.core.paging")
    exceptions = pytest.importorskip("azure.core.exceptions")
    return NS(paging=paging, exceptions=exceptions)


class Response:
    """What azure-core reads off a response to build an HttpResponseError."""

    def __init__(self, status, reason, code=None):
        self.status_code, self.reason, self.code = status, reason, code
        self.headers = {"content-type": "application/json"}
        self.content_type = "application/json"
        self.request = None

    def text(self, encoding=None):
        body = {"error": {"code": self.code, "message": f"The client {SECRET} may not read"}}
        return json.dumps(body)

    def body(self):
        return self.text().encode()


def real_paged(core, pages, fail_at=None, error=None):
    """An ItemPaged built the way a generated client builds one, from a get_next and an
    extract_data."""

    def get_next(token=None):
        at = 0 if token is None else int(token)
        if at == fail_at:
            raise error
        return pages[at], (str(at + 1) if at + 1 < len(pages) or at + 1 == fail_at else None)

    def extract_data(response):
        items, token = response
        return token, iter(items)

    return core.paging.ItemPaged(get_next, extract_data)


class CoreWorld(World):
    """The same stand-ins with every listing an ItemPaged of the real azure-core."""

    core = None

    def _pager(self, entries, **kw):
        size = self.page or max(len(entries), 1)
        pages = [entries[at:at + size] for at in range(0, len(entries), size)] or [[]]
        return real_paged(self.core, pages, **kw)


@pytest.fixture
def core_world(core):
    world = CoreWorld()
    world.core = core
    return world


def test_the_pager_stand_in_matches_azure_cores_item_paged(core):
    pages = [[1, 2], [3], [4, 5]]
    fake, real = Pager(pages), real_paged(core, pages)
    assert isinstance(real, abc.Iterator)
    assert iter(real) is real and iter(fake) is fake
    assert not hasattr(real, "__len__") and not hasattr(real, "__getitem__")
    assert list(fake) == list(real) == [1, 2, 3, 4, 5]
    assert list(fake) == list(real) == []
    by_fake = [(list(p), t) for p, t in _pages_with_tokens(Pager(pages))]
    by_real = [(list(p), t) for p, t in _pages_with_tokens(real_paged(core, pages))]
    assert [items for items, _ in by_fake] == [items for items, _ in by_real]
    assert [t is None for _, t in by_fake] == [t is None for _, t in by_real]


def _pages_with_tokens(paged):
    pages = paged.by_page()
    for page in pages:
        yield page, pages.continuation_token


def test_the_error_stand_ins_have_the_hierarchy_azure_core_gives_them(core):
    exceptions = core.exceptions
    for name in ("HttpResponseError", "ClientAuthenticationError", "ResourceNotFoundError",
                 "ServiceRequestError"):
        real, fake = getattr(exceptions, name), globals()[name]
        assert [c.__name__ for c in real.__mro__ if c.__name__ in HIERARCHY] == [
            c.__name__ for c in fake.__mro__ if c.__name__ in HIERARCHY]


HIERARCHY = {"HttpResponseError", "ClientAuthenticationError", "ResourceNotFoundError",
             "ServiceRequestError", "AzureError"}


def test_the_whole_read_works_over_real_item_paged_listings_of_many_pages(core_world):
    core_world.page = 1
    for n in range(3):
        core_world.stub_site(f"s{n}", linux="PHP|8.3")
        core_world.stub_app(f"c{n}", [f"{SERVER}/php:8.3.36"])
    core_world.stub_registry("myreg", {f"mirror{n}/php": ["8.3.36-fpm"] for n in range(3)})
    evs = inventory(core_world)
    assert len(evs) == 9 and not gaps(evs)
    assert core_world.touched == []


def test_a_real_item_paged_that_fails_on_its_second_page_keeps_the_first(core_world, core):
    site = core_world.stub_site("app1", linux="PHP|8.3")
    error = core.exceptions.ServiceRequestError("no route " + SECRET)
    core_world.script("web_apps.list", [real_paged(core, [[site], [site]], fail_at=1, error=error)])
    *found, gap = inventory(core_world)
    assert len(found) == 1
    assert gap.note == "not inventoried: the service could not be reached (ServiceRequestError)"
    assert SECRET not in text_of(gap)


def test_a_real_item_paged_that_never_ends_is_cut(core_world, core, monkeypatch):
    monkeypatch.setattr(azure, "_MAX_PAGES", 4)
    site = core_world.stub_site("app1", linux="PHP|8.3")

    def get_next(token=None):
        return [site], "again"

    paged = core.paging.ItemPaged(get_next, lambda r: (r[1], iter(r[0])))
    core_world.script("web_apps.list", [paged])
    *found, gap = inventory(core_world)
    assert len(found) == 4
    assert gap.note == "not inventoried: the list runs past 4 pages"


@pytest.mark.parametrize("name,status,code,why", [
    ("HttpResponseError", 403, "AuthorizationFailed",
     f"{DENIED} (HttpResponseError 403 AuthorizationFailed)"),
    ("HttpResponseError", 409, "MissingSubscriptionRegistration",
     "the resource provider is not registered in the subscription "
     "(HttpResponseError 409 MissingSubscriptionRegistration)"),
    ("ResourceNotFoundError", 404, "SubscriptionNotFound",
     "ResourceNotFoundError 404 SubscriptionNotFound"),
    ("ClientAuthenticationError", 401, "InvalidAuthenticationToken",
     f"{CREDENTIAL_LOST} (ClientAuthenticationError 401 InvalidAuthenticationToken)"),
])
def test_a_real_azure_core_error_is_recorded_by_class_status_and_code(
        core_world, core, name, status, code, why):
    core_world.stub_site("app1")
    exc = getattr(core.exceptions, name)(response=Response(status, "Reason", code))
    # The real message names the caller, and it must not travel.
    assert SECRET in str(exc)
    core_world.fail("web_apps.list", exc)
    gap = only(core_world)
    assert gap.note == "not inventoried: " + why
    assert SECRET not in text_of(gap)


def test_real_errors_that_carry_no_response_are_recorded_by_class(core_world, core):
    core_world.stub_site("app1")
    exc = core.exceptions.ClientAuthenticationError(
        "DefaultAzureCredential failed to retrieve a token. Attempted: " + SECRET)
    core_world.fail("web_apps.list", exc)
    assert only(core_world).note == (
        f"not inventoried: {CREDENTIAL_LOST} (ClientAuthenticationError)")


def test_a_real_acr_style_error_with_no_odata_body_still_gives_its_status(core_world, core):
    # The registry data plane sends {"errors": [...]}, which azure-core does not parse into
    # error.code, so the status is all there is.
    core_world.stub_registry("myreg", {"php": ["8.3.36-fpm"]})

    class AcrResponse(Response):
        def text(self, encoding=None):
            return json.dumps({"errors": [{"code": "DENIED", "message": SECRET}]})

    exc = core.exceptions.HttpResponseError(response=AcrResponse(403, "Forbidden"))
    core_world.fail("list_repository_names", exc)
    assert only(core_world).note == f"not inventoried: {DENIED} (HttpResponseError 403)"


@pytest.fixture
def web_models():
    return pytest.importorskip("azure.mgmt.web.models")


@pytest.fixture
def app_models():
    return pytest.importorskip("azure.mgmt.appcontainers.models")


@pytest.fixture
def registry_models():
    return pytest.importorskip("azure.mgmt.containerregistry.models")


def real_site(models, name, group="rg1", host=None, sub=SUB):
    return models.Site({
        "id": site_id(name, group, sub), "name": name, "location": "eastus", "kind": "app,linux",
        "properties": {"resourceGroup": group, "customDomainVerificationId": SECRET,
                       "defaultHostName": host or f"{name}.azurewebsites.net"}})


def real_config(models, linux=None, php=None):
    return models.SiteConfigResource(properties=models.SiteConfig(
        linux_fx_version=linux, php_version=php, publishing_username=SECRET,
        app_settings=[models.NameValuePair(name="DB_PASSWORD", value=SECRET)],
        connection_strings=[models.ConnStringInfo(
            name="db", connection_string=SECRET, type="MySql")]))


def test_a_real_site_and_a_real_site_configuration_are_read(world, web_models):
    site = real_site(web_models, "app1", group="rg-Prod")
    config = real_config(web_models, linux="PHP|8.2")
    # The real configuration holds the secrets the source must leave alone, and shows them in repr.
    assert SECRET in repr(config)
    world._sites[SUB] = [site]
    world.configs[(SUB, "app1")] = ("rg-Prod", config)
    ev = only(world)
    assert ev.location == site_id("app1", "rg-Prod")
    assert ev.detected_version == "8.2"
    assert ev.signals == {"resource": site_id("app1", "rg-Prod"), "service": "appservice",
                          "php_present": "true", "hostname": "app1.azurewebsites.net"}
    assert SECRET not in text_of(ev)
    assert all(SECRET not in out for out in rendered([ev]))


@pytest.mark.parametrize("linux,php,branch", [
    (None, "7.4", "7.4"), ("", "7.4", "7.4"), ("PHP|8.3", None, "8.3"), ("NODE|20-lts", None, None),
    (None, None, None), ("", "", None)])
def test_a_real_configuration_gives_the_branch_a_stand_in_would(world, web_models, linux, php,
                                                                 branch):
    world._sites[SUB] = [real_site(web_models, "app1")]
    world.configs[(SUB, "app1")] = ("rg1", real_config(web_models, linux, php))
    evs = inventory(world)
    if branch is None:
        assert evs == []
    else:
        assert only_one(evs).detected_version == branch


def test_a_real_configuration_with_no_properties_is_a_configuration_with_no_php(world, web_models):
    # The model reads a flattened field as None when nothing was sent, and that is no PHP.
    world._sites[SUB] = [real_site(web_models, "app1")]
    world.configs[(SUB, "app1")] = ("rg1", web_models.SiteConfigResource({}))
    assert inventory(world) == []


def test_a_real_site_with_no_default_host_name_still_reads(world, web_models):
    site = web_models.Site({"id": site_id("app1"), "name": "app1", "location": "eastus"})
    world._sites[SUB] = [site]
    world.configs[(SUB, "app1")] = ("rg1", real_config(web_models, linux="PHP|8.3"))
    ev = only(world)
    assert "hostname" not in ev.signals


def test_real_container_apps_are_read(world, app_models):
    app = app_models.ContainerApp.deserialize({
        "id": app_id("capp1"), "name": "capp1", "location": "eastus",
        "properties": {
            "configuration": {"ingress": {"fqdn": "capp1.kindhill-123.eastus.azurecontainerapps.io",
                                          "external": True}},
            "template": {
                "containers": [
                    {"image": f"{SERVER}/php:8.3.12", "name": "web",
                     "env": [{"name": "DB_PASSWORD", "value": SECRET}]},
                    {"image": "busybox:1.36", "name": "side"}],
                "initContainers": [{"image": f"{SERVER}/php:5.6.40-cli", "name": "init"}]}}})
    assert isinstance(app.template.containers[0].env, list)
    world._apps[SUB] = [app]
    ev = only(world)
    assert ev.location == f"{SERVER}/php:8.3.12"
    assert ev.detected_version == "8.3.12"
    assert ev.signals == {"resource": app_id("capp1"), "service": "containerapps",
                          "php_present": "true",
                          "hostname": "capp1.kindhill-123.eastus.azurecontainerapps.io"}
    assert SECRET not in text_of(ev)


def test_a_real_container_app_with_no_template_is_counted(world, app_models):
    app = app_models.ContainerApp.deserialize({
        "id": app_id("capp1"), "name": "capp1", "location": "eastus", "properties": {}})
    world._apps[SUB] = [app]
    assert only(world).note == APP_UNREAD


def test_real_registries_are_opened_by_their_login_server(world, registry_models):
    registry = registry_models.Registry({
        "id": registry_id("myreg"), "name": "myreg", "location": "eastus", "sku": {"name": "Basic"},
        "properties": {"loginServer": SERVER, "adminUserEnabled": False}})
    world._registries[SUB] = [registry]
    world._repos[SERVER] = {"php": ["8.3.12-fpm"]}
    ev = only(world)
    assert ev.location == f"{SERVER}/php:8.3.12-fpm"
    assert [s for k, _, s in world.made if k == "registry_data"] == [SERVER]


def test_a_real_registry_with_no_login_server_is_counted(world, registry_models):
    registry = registry_models.Registry({"id": registry_id("myreg"), "name": "myreg",
                                         "location": "eastus", "sku": {"name": "Basic"}})
    world._registries[SUB] = [registry]
    assert only(world).note == REGISTRY_UNREAD


def test_a_real_artifact_tag_properties_object_is_read_by_its_name(world):
    containerregistry = pytest.importorskip("azure.containerregistry")
    props = containerregistry.ArtifactTagProperties(name="8.3.12-fpm", repository_name="php")
    # The source relies on this field, so the precondition is stated before the read.
    assert props.name == "8.3.12-fpm"
    world.stub_registry("myreg", {"php": []})
    world.script("list_tag_properties", [[props]])
    ev = only(world)
    assert ev.detected_version == "8.3.12"
    assert containerregistry.ArtifactTagProperties().name == ""


# --- the real management clients, over a transport that answers from a table ---
# The generated clients build the request, page through nextLink, deserialize into the real models,
# and map an error status to an azure-core error. Only the socket is missing: the transport hands
# the clients canned ARM JSON, and a guard fails any attempt to connect or to resolve a name.

REASONS = {200: "OK", 403: "Forbidden", 404: "Not Found", 409: "Conflict"}
ENVIRONMENT = "kindhill-1.eastus.azurecontainerapps.io"
NEXT_PAGE = (f"https://management.azure.com/subscriptions/{SUB}/providers/Microsoft.Web/sites"
             "?api-version=2025-03-01&$skiptoken=page2")


def arm_page(items, next_link=None):
    return {"value": items, **({"nextLink": next_link} if next_link else {})}


def arm_site(name, group="rg1"):
    return {"id": site_id(name, group), "name": name, "type": "Microsoft.Web/sites",
            "kind": "app,linux", "location": "eastus", "tags": {"k": SECRET},
            "properties": {"resourceGroup": group, "defaultHostName": f"{name}.azurewebsites.net",
                           "state": "Running", "customDomainVerificationId": SECRET}}


def arm_config(linux=None, php=None):
    return {"id": "x", "name": "web", "type": "Microsoft.Web/sites/config",
            "properties": {"linuxFxVersion": linux, "phpVersion": php, "publishingUsername": SECRET,
                           "appSettings": [{"name": "DB_PASSWORD", "value": SECRET}],
                           "connectionStrings": [{"name": "db", "connectionString": SECRET,
                                                  "type": "MySql"}]}}


def arm_app(name, images):
    containers = [{"image": image, "name": f"c{n}", "env": [{"name": "TOKEN", "value": SECRET}]}
                  for n, image in enumerate(images)]
    return {"id": app_id(name), "name": name, "type": "Microsoft.App/containerApps",
            "location": "eastus",
            "properties": {
                "configuration": {"ingress": {"fqdn": f"{name}.{ENVIRONMENT}"}},
                "template": {"containers": containers}}}


def arm_registry(name):
    return {"id": registry_id(name), "name": name, "type": "Microsoft.ContainerRegistry/registries",
            "location": "eastus", "sku": {"name": "Basic", "tier": "Basic"},
            "properties": {"loginServer": f"{name}.azurecr.io", "adminUserEnabled": False}}


def arm_empty(url):
    return 200, arm_page([])


def arm_subscription(ident):
    return {"id": f"/subscriptions/{ident}", "subscriptionId": ident, "displayName": SECRET,
            "state": "Enabled", "tenantId": "00000000-0000-0000-0000-0000000000ff"}


def arm_error(code):
    return {"error": {"code": code, "message": f"The client {SECRET} may not read"}}


class Arm:
    """The three real management clients over one transport, and the table it answers from.

    routes maps the end of a request path to a function from the URL to (status, JSON body).
    requests lists the path of every request made, in order.
    """

    def __init__(self, monkeypatch):
        requests = pytest.importorskip("requests")
        transport = pytest.importorskip("azure.core.pipeline.transport")
        credentials = pytest.importorskip("azure.core.credentials")
        self._models = {name: pytest.importorskip(f"azure.mgmt.{name}") for name in (
            "web", "appcontainers", "containerregistry")}

        def refuse(*args, **kwargs):
            raise AssertionError("the network was touched")

        monkeypatch.setattr(socket.socket, "connect", refuse)
        monkeypatch.setattr(socket, "getaddrinfo", refuse)
        self.routes, self.requests = {}, []
        arm = self

        class Session(requests.Session):
            def request(self, method, url, **kwargs):
                return arm._answer(requests, method, url)

        self._transport = transport.RequestsTransport(session=Session(), session_owner=False)
        self.credential = NS(get_token=lambda *scopes, **kw: credentials.AccessToken(
            "stub-token", 4102444800))

    def _answer(self, requests, method, url):
        path = url.partition("?")[0].partition("management.azure.com")[2]
        self.requests.append(path)
        status, body = 404, arm_error("NotFound")
        for suffix, make in self.routes.items():
            if path.endswith(suffix):
                status, body = make(url)
                break
        response = requests.Response()
        response.status_code, response.reason, response.url = status, REASONS[status], url
        response._content = json.dumps(body).encode()
        response.headers["content-type"] = "application/json"
        response.raw = NS()  # the transport sets enforce_content_length on it
        response._content_consumed = True
        return response

    def bundle(self, registry_data=None, subscription_ids=None, default=SUB):
        """The factories of the source: the real clients, each given the transport."""
        def make(name, cls):
            return lambda credential, subscription: getattr(self._models[name], cls)(
                credential, subscription, transport=self._transport)

        return NS(web=make("web", "WebSiteManagementClient"),
                  container_apps=make("appcontainers", "ContainerAppsAPIClient"),
                  registries=make("containerregistry", "ContainerRegistryManagementClient"),
                  registry_data=registry_data, subscription_id=default,
                  subscription_ids=subscription_ids)

    def source(self, registry_data=None, subscription_ids=None, default=SUB):
        return AzureSource(self.credential, self.bundle(registry_data, subscription_ids, default))

    def listing_function(self):
        """The function a factory supplies to list subscriptions: the ID of each one the real
        SubscriptionClient lists for the credential."""
        resource = pytest.importorskip("azure.mgmt.resource.subscriptions")

        def subscription_ids(credential):
            client = resource.SubscriptionClient(credential, transport=self._transport)
            return [s.subscription_id for s in client.subscriptions.list()]

        return subscription_ids


@pytest.fixture
def arm(monkeypatch):
    return Arm(monkeypatch)


def test_the_real_clients_are_read_page_by_page_and_site_by_site(arm):
    def sites(url):
        if "skiptoken=page2" in url:
            return 200, arm_page([arm_site("api"), arm_site("legacy")])
        return 200, arm_page([arm_site("app1"), arm_site("node1")], NEXT_PAGE)

    configs = {"app1": arm_config("PHP|8.3"), "node1": arm_config("NODE|20-lts"),
               "api": arm_config("PHP|8.2"), "legacy": arm_config("", "7.4")}
    arm.routes = {
        "/providers/Microsoft.Web/sites": sites,
        "/config/web": lambda url: (200, configs[url.partition("/sites/")[2].partition("/")[0]]),
        "/providers/Microsoft.App/containerApps": lambda url: (200, arm_page([
            arm_app("capp1", [f"{SERVER}/php:8.3.12", "busybox:1.36"]),
            arm_app("capp2", ["nginx:1.27"])])),
        "/providers/Microsoft.ContainerRegistry/registries": lambda url: (200, arm_page([
            arm_registry("myreg")]))}
    world = World()
    world.stub_registry("myreg", {"php": ["8.3.36-fpm"]})
    evs = arm.source(registry_data=world.registry_data).inventory()
    assert [(e.signals["service"], e.location, e.detected_version) for e in evs] == [
        ("appservice", site_id("app1"), "8.3"), ("appservice", site_id("api"), "8.2"),
        ("appservice", site_id("legacy"), "7.4"),
        ("containerapps", f"{SERVER}/php:8.3.12", "8.3.12"),
        ("acr", f"{SERVER}/php:8.3.36-fpm", "8.3.36")]
    assert evs[0].signals["hostname"] == "app1.azurewebsites.net"
    assert evs[3].signals["hostname"] == f"capp1.{ENVIRONMENT}"
    assert [grade_evidence(e, MATRIX)[0] for e in evs] == [
        Verdict.INDETERMINATE, Verdict.INDETERMINATE, Verdict.INDETERMINATE, Verdict.EXPOSED,
        Verdict.LIKELY_PATCHED]
    # The second page of sites is asked for when the first is spent, and each site is read once.
    sites_path = f"/subscriptions/{SUB}/providers/Microsoft.Web/sites"
    config_path = (f"/subscriptions/{SUB}/resourceGroups/rg1/providers/Microsoft.Web/sites/"
                   "{}/config/web")
    assert arm.requests == [
        sites_path, config_path.format("app1"), config_path.format("node1"),
        sites_path, config_path.format("api"), config_path.format("legacy"),
        f"/subscriptions/{SUB}/providers/Microsoft.App/containerApps",
        f"/subscriptions/{SUB}/providers/Microsoft.ContainerRegistry/registries"]
    # The responses carried app settings, connection strings, and environment values.
    assert SECRET not in text_of(evs)
    assert all(SECRET not in out for out in rendered(evs))


def test_real_error_responses_are_recorded_by_class_status_and_code_without_their_message(arm):
    arm.routes = {
        "/providers/Microsoft.Web/sites": lambda url: (403, arm_error("AuthorizationFailed")),
        "/providers/Microsoft.App/containerApps": arm_empty,
        "/providers/Microsoft.ContainerRegistry/registries": lambda url: (
            409, arm_error("MissingSubscriptionRegistration"))}
    evs = arm.source().inventory()
    assert [(e.location, e.note) for e in evs] == [
        (f"azure appservice {SUB}", f"not inventoried: {WHY_DENIED}"),
        (f"azure acr {SUB}", "not inventoried: the resource provider is not registered in the "
                             "subscription (ResourceExistsError 409 "
                             "MissingSubscriptionRegistration)")]
    assert SECRET not in text_of(evs)


def test_a_real_subscription_with_nothing_in_it_is_a_finished_read(arm):
    arm.routes = {suffix: arm_empty for suffix in (
        "/providers/Microsoft.Web/sites", "/providers/Microsoft.App/containerApps",
        "/providers/Microsoft.ContainerRegistry/registries")}
    assert arm.source().inventory() == []
    assert len(arm.requests) == 3


def test_a_real_configuration_that_cannot_be_read_is_a_row_for_that_site(arm):
    arm.routes = {
        "/providers/Microsoft.Web/sites": lambda url: (200, arm_page([
            arm_site("app1"), arm_site("gone")])),
        "/sites/app1/config/web": lambda url: (200, arm_config("PHP|8.3")),
        "/sites/gone/config/web": lambda url: (404, arm_error("ResourceNotFound")),
        "/providers/Microsoft.App/containerApps": arm_empty,
        "/providers/Microsoft.ContainerRegistry/registries": arm_empty}
    found, gap = arm.source().inventory()
    assert found.location == site_id("app1")
    assert gap.signals == {"resource": site_id("gone"), "service": "appservice",
                           "kind": "skipped"}
    assert gap.note == "not fully inventoried: ResourceNotFoundError 404 ResourceNotFound"


def test_the_real_subscription_client_lists_the_ids_the_source_then_reads(arm):
    # The listing is lazy and sits inside the function the factory supplies, so the pager is read
    # there, and the source is handed plain strings.
    arm.routes = {
        "/subscriptions": lambda url: (200, arm_page([arm_subscription(SUB),
                                                      arm_subscription(OTHER)])),
        "/providers/Microsoft.Web/sites": arm_empty,
        "/providers/Microsoft.App/containerApps": arm_empty,
        "/providers/Microsoft.ContainerRegistry/registries": arm_empty}
    source = arm.source(subscription_ids=arm.listing_function(), default=None)
    assert source.subscriptions == ()
    assert arm.requests == []
    assert source.inventory() == []
    assert source.subscriptions == (SUB, OTHER)
    assert arm.requests == ["/subscriptions"] + [
        f"/subscriptions/{sub}/providers/{provider}" for sub in (SUB, OTHER) for provider in (
            "Microsoft.Web/sites", "Microsoft.App/containerApps",
            "Microsoft.ContainerRegistry/registries")]


def test_a_real_refusal_to_list_the_subscriptions_is_one_skipped_row(arm):
    arm.routes = {"/subscriptions": lambda url: (403, arm_error("AuthorizationFailed"))}
    source = arm.source(subscription_ids=arm.listing_function(), default=None)
    (row,) = source.inventory()
    assert (row.location, row.signals) == (
        "azure subscriptions", {"service": "subscriptions", "kind": "skipped"})
    assert row.note == f"not inventoried: {NO_SCOPE}: {WHY_DENIED}"
    assert source.subscriptions == ()
    assert arm.requests == ["/subscriptions"]
    assert SECRET not in text_of(row)


def test_a_named_subscription_never_reaches_the_real_subscription_client(arm):
    arm.routes = {"/providers/Microsoft.Web/sites": arm_empty,
                  "/providers/Microsoft.App/containerApps": arm_empty,
                  "/providers/Microsoft.ContainerRegistry/registries": arm_empty}
    source = arm.source(subscription_ids=arm.listing_function(), default=None)
    source.subscriptions = [OTHER]
    assert source.inventory() == []
    assert "/subscriptions" not in arm.requests
    assert source.subscriptions == (OTHER,)


# --- nothing a service sends can crash the source ---

def check(ev):
    assert isinstance(ev, Evidence) and ev.source is Source.CLOUD and isinstance(ev.sapi, Sapi)
    for value in [ev.location, ev.note] + list(ev.signals.values()):
        assert isinstance(value, str) and value.isascii() and value.isprintable()
        assert len(value) <= 1200
    assert set(ev.signals) <= SIGNAL_KEYS
    resource = ev.signals.get("resource")
    assert resource is None or (" " not in resource and (
        resource.startswith("/subscriptions/") or re.fullmatch(r"[\w.-]+/[\w./-]+", resource)))
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


POOL = [None, True, 0, -7, 2 ** 70, 1.5, "", " ", "x", "a\nb", "caf" + E_ACUTE, BIDI, "php",
        "PHP|8.3", "8.3", "8.3.12", "x" * 3000, [], {}, [None], {"a": 1}, NS(), NS(id=None)]
SITE_IDS = [site_id(), site_id("api"), site_id("shop-2", "rg(2)"), "/subscriptions/x",
            site_id().replace("Microsoft.Web", "Microsoft.Compute"), site_id("z" * 1100)]
APP_IDS = [app_id(), app_id("api"), "/subscriptions/x", app_id().replace("App", "Web")]
LINUX = ["PHP|8.3", "PHP|7.4", "php|8.2.1", "NODE|20-lts", "PHP|", "PHP", "DOCKER|php:8.3", ""]
PHPV = ["7.4", "8.0", "", "latest", "7.4.33", "10.1"]
HOST_NAMES = ["app1.azurewebsites.net", "10.0.0.1", "a b", "x" * 300, ".x"]
IMAGE_REFS = [i for i, _, _ in IMAGES] + ["x" * 2000, "a b", "@x", "php:"]
SERVERS = [SERVER, "other.azurecr.io", "a b", "x" * 300, ".x", "-x.io"]
REPOS = ["php", "library/php", "web", "app/php", "x" * 300, "a b", "php:8"]
TAG_NAMES = ["8.3.12-fpm", "8.3-apache", "php8.3", "latest", "8.3.12-1ubuntu2.28", "PHP-5.6.40-cli",
             "php\n8.3", "x" * 200, "8.3.12RC1", ""]


def pick(rng, pool):
    """A value from pool, or from the odd values, which are all of POOL when pool is empty."""
    return rng.choice(pool + POOL) if rng.random() < 0.6 or not pool else rng.choice(pool)


def junk_site(rng):
    if rng.random() < 0.3:
        return Site(properties=NS(default_host_name=pick(rng, HOST_NAMES)), id=pick(rng, SITE_IDS))
    return NS(id=pick(rng, SITE_IDS), default_host_name=pick(rng, HOST_NAMES))


def junk_config(rng):
    if rng.random() < 0.15:
        return pick(rng, [])
    fields = dict(linux_fx_version=pick(rng, LINUX), php_version=pick(rng, PHPV))
    if rng.random() < 0.3:
        return SiteConfigResource(properties=NS(**fields))
    return NS(**fields)


def junk_app(rng):
    containers = [NS(image=pick(rng, IMAGE_REFS)) for _ in range(rng.randrange(4))]
    template = NS(containers=containers if rng.random() < 0.9 else pick(rng, []))
    configuration = NS(ingress=NS(fqdn=pick(rng, HOST_NAMES)))
    return NS(id=pick(rng, APP_IDS), template=pick(rng, [template]),
              configuration=pick(rng, [configuration]))


def junk_registry(rng):
    return NS(login_server=pick(rng, SERVERS))


def junk_repo(rng):
    return pick(rng, REPOS)


def junk_tag(rng):
    return pick(rng, [TagProperties(name=pick(rng, TAG_NAMES))])


def junk_listing(rng, make):
    entries = [make(rng) if rng.random() < 0.85 else pick(rng, []) for _ in range(rng.randrange(5))]
    return entries if rng.random() < 0.95 else pick(rng, [])


@pytest.mark.parametrize("seed", range(8))
def test_nothing_a_service_sends_crashes_the_source_or_slips_past_a_bound(seed):
    rng = random.Random(seed)
    for _ in range(150):
        world = World()
        world.script("web_apps.list", [junk_listing(rng, junk_site) for _ in range(2)])
        world.script("web_apps.get_configuration", [junk_config(rng) for _ in range(8)])
        world.script("container_apps.list_by_subscription",
                     [junk_listing(rng, junk_app) for _ in range(2)])
        world.script("registries.list", [junk_listing(rng, junk_registry) for _ in range(2)])
        world.script("list_repository_names", [junk_listing(rng, junk_repo) for _ in range(4)])
        world.script("list_tag_properties", [junk_listing(rng, junk_tag) for _ in range(8)])
        # Some answers are not answers at all, and some calls fail.
        for method in list(world._script):
            if rng.random() < 0.15:
                world._script[method] = iter([pick(rng, []), ServiceRequestError("503")])
        evs = inventory(world)
        for ev in evs:
            check(ev)
        assert {c.method for c in world.calls} <= READS
        assert world.touched == [] and world.credential.touched == []
        assert sorted((k, s) for k, _, s in world.made) == sorted(world.closed)


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
    tree = ast.parse(source_of(azure), feature_version=(3, 9))
    assert imports_of(tree) <= {
        "collections", "contextlib", "typing", "php_radar.model", "php_radar.sources.cloud._common",
        "php_radar.sources.network", "php_radar.sources.repo"}


VERBS = ("list", "get_", "create_", "delete_", "update_", "set_", "patch_", "batch_", "export_",
         "import_", "run_", "deploy_", "test_", "call_", "undelete_", "move_", "start_", "stop_",
         "begin_", "regenerate_", "restart_", "swap_", "sync_", "upload_", "download_")


def test_the_source_never_names_an_operation_but_the_six_reads():
    tree = ast.parse(source_of(azure), feature_version=(3, 9))
    used = {n.attr for n in ast.walk(tree)
            if isinstance(n, ast.Attribute) and n.attr.startswith(VERBS)}
    assert used == {"list", "get_configuration", "list_by_subscription", "list_repository_names",
                    "list_tag_properties"}


def test_the_source_takes_four_factories_and_two_subscription_attributes_from_the_bundle():
    tree = ast.parse(source_of(azure), feature_version=(3, 9))
    asked_of_the_bundle = {
        n.args[1].value for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "getattr"
        and isinstance(n.args[0], (ast.Name, ast.Attribute))
        and getattr(n.args[0], "id", getattr(n.args[0], "attr", None)) in ("clients", "_clients")
        and isinstance(n.args[1], ast.Constant)}
    assert asked_of_the_bundle == {"subscription_id", "subscription_ids"}
    kinds = {n.args[0].value for n in ast.walk(tree)
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
             and n.func.id == "client_of" and isinstance(n.args[0], ast.Constant)}
    assert kinds == {"web", "container_apps", "registries", "registry_data"}


def test_the_credential_is_only_passed_on_and_nothing_is_read_off_it():
    tree = ast.parse(source_of(azure), feature_version=(3, 9))
    on_credential = [n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)
                     and isinstance(n.value, ast.Attribute) and n.value.attr == "_credential"]
    assert on_credential == []
    on_param = [n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)
                and isinstance(n.value, ast.Name) and n.value.id == "credential"]
    assert on_param == []


def test_the_source_has_no_way_to_read_credentials_the_environment_or_a_file():
    tree = ast.parse(source_of(azure), feature_version=(3, 9))
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    names |= {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    assert not names & {
        "get_token", "get_credentials", "get_credential", "token", "access_token", "secret",
        "secrets", "password", "app_settings", "connection_strings", "publishing_username",
        "environ", "getenv", "os", "open", "azure", "msrest", "msal", "requests", "print",
        "logging", "eval", "exec", "compile", "__import__", "subprocess", "socket", "urllib"}


def test_the_source_reads_only_the_fields_it_names_off_an_answer():
    tree = ast.parse(source_of(azure), feature_version=(3, 9))
    read = {n.args[1].value for n in ast.walk(tree)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "getattr"
            and len(n.args) >= 2 and isinstance(n.args[1], ast.Constant)}
    models = {"id", "linux_fx_version", "php_version", "default_host_name", "template",
              "containers", "configuration", "ingress", "fqdn", "image", "login_server", "name"}
    # The pager's by_page, the error's status and code, the bundle's two subscription attributes,
    # and a client's close.
    around = {"by_page", "status_code", "error", "code", "subscription_id", "subscription_ids",
              "close"}
    assert read == models | around


def test_the_source_is_plain_ascii_with_no_dash_or_curly_quote():
    source = source_of(azure)
    assert source.isascii()
    assert not set(source) & set(DASHES_AND_QUOTES)
    assert not [c for c in source if ord(c) < 32 and c != "\n"]
