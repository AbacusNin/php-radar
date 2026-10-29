"""get_cloud_source for gcp and azure, and the cloud command that builds them.

Both SDKs are optional installs, and no test here needs either one. A test that builds a source
puts stand-ins for the packages in sys.modules under the names the factory imports. A test that
wants a package missing puts None there, which makes its import raise ImportError whether or not
the real package is installed. The stand-ins have the shape of the real classes. A Google client
takes keyword arguments only and a list call takes a request. A Google list comes back from a pager
that reads page by page and passes other attributes to the latest page it fetched, and the list of
locations comes back as a raw response whose repeated field has no __iter__. An Azure list comes
back from an ItemPaged, which has by_page. A few tests use the real google-auth or the real Azure
management packages and are skipped without them. No test here has run against a live account.
"""
import ast
import enum
import importlib
import importlib.util
import json
import pathlib
import random
import re
import socket
import subprocess
import sys
import types
import uuid
from collections import abc
from types import SimpleNamespace as NS
from urllib.parse import urlsplit

import pytest

from php_radar.cli import main
from php_radar.knowledge import DATA_PATH, grade_evidence, load_matrix
from php_radar.model import Verdict
from php_radar.sources import cloud
from php_radar.sources.cloud import get_cloud_source
from php_radar.sources.cloud.azure import AzureSource
from php_radar.sources.cloud.gcp import GcpSource

MATRIX = load_matrix(DATA_PATH)
ROOT = pathlib.Path(__file__).resolve().parent.parent

# Stands for anything a message or a path could carry that a report must not repeat.
SECRET = "hunter2-" + "CANARY-factory"

PROJECT = "my-project"
ADC_PROJECT = "adc-project"
QUOTA_PROJECT = "quota-project"
SUB = "00000000-0000-0000-0000-000000000001"
OTHER = "00000000-0000-0000-0000-000000000002"
SERVER = "myreg.azurecr.io"
DIGEST = "sha256:" + "0" * 64

Format = enum.IntEnum("Format", "FORMAT_UNSPECIFIED DOCKER MAVEN", start=0)


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch):
    # The settings the factories read. The machine that runs the tests must not change a result.
    for name in ("AZURE_SUBSCRIPTION_ID", "GOOGLE_CLOUD_PROJECT", "GCLOUD_PROJECT",
                 "GOOGLE_APPLICATION_CREDENTIALS"):
        monkeypatch.delenv(name, raising=False)


# --- stand-in modules ---

def fake_module(name, **attrs):
    mod = types.ModuleType(name)
    mod.__dict__.update(attrs)
    return mod


def fake_package(name, **attrs):
    mod = fake_module(name, **attrs)
    mod.__path__ = []  # a package, so that a name can be imported from it
    return mod


def install(monkeypatch, *modules):
    """Puts the modules in sys.modules, and each on its parent when the parent is among them."""
    by_name = {mod.__name__: mod for mod in modules}
    for mod in modules:
        monkeypatch.setitem(sys.modules, mod.__name__, mod)
    for mod in modules:
        parent, _, child = mod.__name__.rpartition(".")
        if parent in by_name:
            monkeypatch.setattr(by_name[parent], child, mod, raising=False)


def block(monkeypatch, *names):
    """Makes an import of each name raise ImportError, installed or not."""
    for name in names:
        monkeypatch.setitem(sys.modules, name, None)
        # A package that has the name as an attribute hands it out without asking sys.modules.
        parent, _, child = name.rpartition(".")
        if getattr(sys.modules.get(parent), child, None) is not None:
            monkeypatch.delattr(sys.modules[parent], child)


def spy(monkeypatch, name):
    """Puts a subclass of cloud.<name>, a source class, in its place. It records its arguments."""
    made = []
    real = getattr(cloud, name)

    class Spy(real):
        def __init__(self, *args, **kwargs):
            made.append((args, kwargs))
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(cloud, name, Spy)
    return made


def rows(evs):
    return [(ev.signals["service"], ev.location, ev.detected_version, ev.signals.get("kind"))
            for ev in evs]


def verdicts(evs):
    return [grade_evidence(ev, MATRIX)[0] for ev in evs]


# --- Google ---
# The exceptions keep the parents google-auth gives them.

class GoogleAuthError(Exception):
    pass


class RefreshError(GoogleAuthError):
    pass


class MutualTLSChannelError(GoogleAuthError):
    pass


class DefaultCredentialsError(GoogleAuthError):
    pass


class MalformedError(DefaultCredentialsError, ValueError):
    pass


# The error a read raises when the API answers not found, with the parents google-api-core gives it.
class GoogleAPICallError(Exception):
    pass


class ClientError(GoogleAPICallError):
    pass


class NotFound(ClientError):
    pass


class SequenceOnly:
    """A repeated protobuf field under the default (upb) backend: a length and an index, and no
    __iter__. The backend registers its containers as mutable sequences."""

    def __init__(self, entries):
        self._entries = list(entries)

    def __len__(self):
        return len(self._entries)

    def __getitem__(self, at):
        return self._entries[at]


abc.MutableSequence.register(SequenceOnly)


class Pager:
    """A generated Google pager over one field.

    pages yields every response, and iterating yields the entries of every page. Any other
    attribute comes from the latest response, which after a full read is the last page.
    unreachable holds the list each page names.
    """

    def __init__(self, field, pages, unreachable=()):
        self._field = field
        self._responses = [
            NS(**{field: list(entries),
                  "unreachable": list(unreachable[at]) if at < len(unreachable) else [],
                  "next_page_token": "more" if at < len(pages) - 1 else ""})
            for at, entries in enumerate(pages)]
        self._response = self._responses[0]

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        return getattr(self._response, name)

    @property
    def pages(self):
        for response in self._responses:
            self._response = response
            yield response

    def __iter__(self):
        for page in self.pages:
            yield from getattr(page, self._field)


FIELDS = {"list_services": "services", "list_versions": "versions",
          "list_functions": "functions", "list_repositories": "repositories",
          "list_docker_images": "docker_images"}


class Google:
    """Stand-ins for the Google packages of the gcp extra, and a record of what the factory did.

    default is google.auth.default: it returns the credentials and project, or raises error. The
    credentials carry quota_project_id, as the real ones do, and it is None when they name no quota
    project. The four clients take keyword arguments only, as the generated ones do. Each has the
    reads of its own service and no others, so a client wired to the wrong place fails when it is
    read. The reads answer from answers, a map from the method to a function of the request.

    real_auth leaves google.auth to the real package, which has to be installed. The test then
    sets up its environment itself.
    """

    def __init__(self, monkeypatch, project=ADC_PROJECT, real_auth=False,
                 quota_project=QUOTA_PROJECT):
        self.project, self.error = project, None
        self.credentials = NS(kind="adc", quota_project_id=quota_project)
        self.build_error = {}  # class name -> what its constructor raises
        self.default_calls = []  # (args, kwargs) of each call to google.auth.default
        self.built = []  # (class name, keyword arguments given) of each client
        self.calls = []  # (method, request) of each read, in order
        self.answers = {}
        sdk = self

        def default(*args, **kwargs):
            sdk.default_calls.append((args, kwargs))
            if sdk.error is not None:
                raise sdk.error
            return sdk.credentials, sdk.project

        def client(name, *methods):
            def __init__(self, *, credentials=None, transport=None, client_options=None,
                         client_info=None):
                given = {"credentials": credentials, "transport": transport,
                         "client_options": client_options, "client_info": client_info}
                sdk.built.append((name, {k: v for k, v in given.items() if v is not None}))
                if name in sdk.build_error:
                    raise sdk.build_error[name]

            body = {"__init__": __init__}
            for method in methods:
                body[method] = sdk._reader(method)
            return type(name, (), body)

        self.ServicesClient = client("ServicesClient", "list_services")
        self.VersionsClient = client("VersionsClient", "list_versions")
        self.FunctionServiceClient = client("FunctionServiceClient", "list_functions")
        self.ArtifactRegistryClient = client(
            "ArtifactRegistryClient", "list_locations", "list_repositories", "list_docker_images")
        clients = [
            fake_module("google.cloud.appengine_admin_v1", ServicesClient=self.ServicesClient,
                        VersionsClient=self.VersionsClient),
            fake_module("google.cloud.functions_v2",
                        FunctionServiceClient=self.FunctionServiceClient),
            fake_module("google.cloud.artifactregistry_v1",
                        ArtifactRegistryClient=self.ArtifactRegistryClient)]
        if real_auth:
            self._install_beside_real_auth(monkeypatch, clients)
            return
        exceptions = fake_module(
            "google.auth.exceptions", GoogleAuthError=GoogleAuthError, RefreshError=RefreshError,
            DefaultCredentialsError=DefaultCredentialsError, MalformedError=MalformedError,
            MutualTLSChannelError=MutualTLSChannelError)
        install(monkeypatch, fake_package("google"),
                fake_package("google.auth", default=default, exceptions=exceptions), exceptions,
                fake_package("google.cloud"), *clients)

    @staticmethod
    def _install_beside_real_auth(monkeypatch, clients):
        # A name that is already an attribute of a package comes from the attribute, and sys.modules
        # is not asked. So the stand-ins go onto whatever google.cloud is installed.
        if importlib.util.find_spec("google.cloud") is None:
            install(monkeypatch, fake_package("google.cloud"))
        install(monkeypatch, *clients)
        cloud_package = importlib.import_module("google.cloud")
        for mod in clients:
            monkeypatch.setattr(cloud_package, mod.__name__.rpartition(".")[2], mod, raising=False)

    def _reader(self, method):
        sdk = self

        def read(self, request=None, *, retry=None, timeout=None, metadata=()):
            sdk.calls.append((method, request))
            if method in sdk.answers:
                return sdk.answers[method](request)
            if method == "list_locations":
                return NS(locations=SequenceOnly([]), next_page_token="")
            return Pager(FIELDS[method], [[]])

        read.__name__ = method
        return read


def stub_project(sdk, project=PROJECT, unreachable=True):
    """A project that runs PHP in App Engine, Cloud Functions, and Artifact Registry.

    With unreachable, the first page of functions names a location the API could not reach.
    """
    service = f"apps/{project}/services/default"
    repo = f"projects/{project}/locations/us/repositories/php"
    function = f"projects/{project}/locations/us-central1/functions/legacy-api"
    lost = [[f"projects/{project}/locations/us-east5"], []] if unreachable else []
    sdk.answers.update({
        "list_services": lambda request: Pager("services", [[NS(name=service)]]),
        "list_versions": lambda request: Pager("versions", [[NS(
            name=f"{service}/versions/v1", runtime="php83",
            flexible_runtime_settings=NS(runtime_version=""))]]),
        "list_functions": lambda request: Pager("functions", [[NS(
            name=function, build_config=NS(runtime="php82"), service_config=NS(service=""))], []],
            unreachable=lost),
        "list_locations": lambda request: NS(
            locations=SequenceOnly([NS(location_id="us")]), next_page_token=""),
        "list_repositories": lambda request: Pager(
            "repositories", [[NS(name=repo, format_=Format.DOCKER)]]),
        "list_docker_images": lambda request: Pager("docker_images", [[NS(
            uri=f"us-docker.pkg.dev/{project}/php/php@{DIGEST}", tags=["8.3.36-fpm"])]])})


def project_requests(project=PROJECT):
    """The reads a source makes of stub_project, in order, with the request of each."""
    return [("list_services", {"parent": f"apps/{project}"}),
            ("list_versions", {"parent": f"apps/{project}/services/default"}),
            ("list_functions", {"parent": f"projects/{project}/locations/-"}),
            ("list_locations", {"name": f"projects/{project}"}),
            ("list_repositories", {"parent": f"projects/{project}/locations/us",
                                   "page_size": 1000}),
            ("list_docker_images", {"parent": f"projects/{project}/locations/us/repositories/php",
                                    "page_size": 1000})]


# --- Azure ---

class ClientAuthenticationError(Exception):
    pass


class ItemPaged:
    """The shape of azure.core.paging.ItemPaged. Iterating reads every item, and by_page() hands
    back an iterator of pages that are iterators themselves."""

    def __init__(self, *pages):
        self._pages = [list(page) for page in pages]

    def by_page(self):
        return iter([iter(page) for page in self._pages])

    def __iter__(self):
        return iter([item for page in self._pages for item in page])


def arm_id(sub, kind, name, group="rg1"):
    return f"/subscriptions/{sub}/resourceGroups/{group}/providers/{kind}/{name}"


class Azure:
    """Stand-ins for the Azure packages of the azure extra, and a record of what was done.

    The management clients take the credential and a subscription and are bound to that
    subscription. The data client takes an endpoint, a credential, and keyword arguments. What
    they list comes from the maps sites, configs, apps, registries, and repositories, and
    subscription listing comes from listing.
    """

    def __init__(self, monkeypatch, real_management=False):
        self.credential_args, self.credentials = [], []
        self.credential_error = None
        self.made = []  # (class name, credential, subscription) of each management client
        self.closed = []  # (class name, subscription) of each one closed
        self.registry_clients = []  # (endpoint, credential, keyword arguments)
        self.listed = []  # the credential of each SubscriptionClient made
        self.listing_closed = []
        self.listing, self.listing_error = [], None
        self.sites, self.configs, self.apps, self.registries = {}, {}, {}, {}
        self.repositories = {}  # login server -> {repository: [tags]}
        sdk = self

        class DefaultAzureCredential:
            def __init__(self, **kwargs):
                sdk.credential_args.append(kwargs)
                if sdk.credential_error is not None:
                    raise sdk.credential_error
                sdk.credentials.append(self)

            def get_token(self, *scopes, **kwargs):
                raise AssertionError("a token was asked for")

        class Management:
            def __init__(self, credential, subscription_id, base_url=None, **kwargs):
                sdk.made.append((type(self).__name__, credential, subscription_id))
                self.subscription_id = subscription_id

            def close(self):
                sdk.closed.append((type(self).__name__, self.subscription_id))

        class WebSiteManagementClient(Management):
            def __init__(self, credential, subscription_id, base_url=None, **kwargs):
                super().__init__(credential, subscription_id)
                self.web_apps = NS(
                    list=lambda: ItemPaged(sdk.sites.get(self.subscription_id, [])),
                    get_configuration=lambda group, name: sdk.configs[name])

        class ContainerAppsAPIClient(Management):
            def __init__(self, credential, subscription_id, base_url=None, **kwargs):
                super().__init__(credential, subscription_id)
                self.container_apps = NS(list_by_subscription=lambda: ItemPaged(
                    sdk.apps.get(self.subscription_id, [])))

        class ContainerRegistryManagementClient(Management):
            def __init__(self, credential, subscription_id, base_url=None, **kwargs):
                super().__init__(credential, subscription_id)
                self.registries = NS(list=lambda: ItemPaged(
                    sdk.registries.get(self.subscription_id, [])))

        class ContainerRegistryClient:
            def __init__(self, endpoint, credential=None, **kwargs):
                sdk.registry_clients.append((endpoint, credential, kwargs))
                self._server = endpoint.partition("//")[2]

            def close(self):
                pass

            def list_repository_names(self, **kwargs):
                return ItemPaged(list(sdk.repositories.get(self._server, {})))

            def list_tag_properties(self, repository, **kwargs):
                tags = sdk.repositories.get(self._server, {}).get(repository, [])
                return ItemPaged([NS(name=tag) for tag in tags])

        class SubscriptionClient:
            def __init__(self, credential, api_version=None, base_url=None, profile=None,
                         **kwargs):
                sdk.listed.append(credential)
                self.subscriptions = NS(list=self._list)

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                sdk.listing_closed.append(True)

            def _list(self):
                if sdk.listing_error is not None:
                    raise sdk.listing_error
                return ItemPaged([NS(subscription_id=ident, display_name=SECRET)
                                  for ident in sdk.listing])

        self.DefaultAzureCredential = DefaultAzureCredential
        self.WebSiteManagementClient = WebSiteManagementClient
        self.ContainerAppsAPIClient = ContainerAppsAPIClient
        self.ContainerRegistryManagementClient = ContainerRegistryManagementClient
        self.ContainerRegistryClient = ContainerRegistryClient
        self.SubscriptionClient = SubscriptionClient
        data = [fake_module("azure.identity", DefaultAzureCredential=DefaultAzureCredential),
                fake_module("azure.containerregistry",
                            ContainerRegistryClient=ContainerRegistryClient)]
        if real_management:
            # The management packages are the real ones, and the test has skipped without them.
            install(monkeypatch, *data)
            return
        install(monkeypatch, fake_package("azure"), fake_package("azure.mgmt"),
                fake_package("azure.mgmt.resource"), *data,
                fake_module("azure.mgmt.web", WebSiteManagementClient=WebSiteManagementClient),
                fake_module("azure.mgmt.appcontainers",
                            ContainerAppsAPIClient=ContainerAppsAPIClient),
                fake_module("azure.mgmt.containerregistry",
                            ContainerRegistryManagementClient=ContainerRegistryManagementClient),
                fake_module("azure.mgmt.resource.subscriptions",
                            SubscriptionClient=SubscriptionClient))


def stub_subscription(sdk, sub=SUB):
    """A subscription with a PHP site, a Container App on an end-of-life image, and two registries.

    The second registry has a login server that no Azure registry domain holds.
    """
    sdk.sites[sub] = [NS(id=arm_id(sub, "Microsoft.Web/sites", name),
                         default_host_name=f"{name}.azurewebsites.net")
                      for name in ("app1", "node1")]
    sdk.configs.update({"app1": NS(linux_fx_version="PHP|8.3", php_version=None),
                        "node1": NS(linux_fx_version="NODE|20-lts", php_version=None)})
    sdk.apps[sub] = [NS(
        id=arm_id(sub, "Microsoft.App/containerApps", "capp1"),
        template=NS(containers=[NS(image=f"{SERVER}/php:7.4.33-apache")]),
        configuration=NS(ingress=NS(fqdn="capp1.kindhill-1.eastus.azurecontainerapps.io")))]
    sdk.registries[sub] = [NS(login_server=SERVER), NS(login_server="evil.example.com")]
    sdk.repositories[SERVER] = {"php": ["8.3.36-fpm"]}


def bundle_of(monkeypatch):
    """(stand-ins, credential, clients) of the azure source the factory builds."""
    sdk = Azure(monkeypatch)
    made = spy(monkeypatch, "AzureSource")
    get_cloud_source("azure")
    (credential, clients), kwargs = made[0]
    assert kwargs == {}
    return sdk, credential, clients


def run(capsys, *argv):
    rc = main(list(argv))
    out, err = capsys.readouterr()
    return rc, out, err


# --- the providers ---

def test_an_unknown_provider_is_refused_and_the_three_known_ones_are_named():
    with pytest.raises(ValueError) as caught:
        get_cloud_source("bogus")
    assert str(caught.value) == "unknown cloud provider 'bogus', the choices are: aws, gcp, azure"


@pytest.mark.parametrize("name", ["", "AWS", "Gcp", "azure ", "gcp,azure", "all"])
def test_a_provider_name_is_matched_exactly(name):
    with pytest.raises(ValueError, match="the choices are: aws, gcp, azure"):
        get_cloud_source(name)


def test_importing_the_package_and_the_cli_loads_no_sdk():
    code = ("import sys\n"
            "import php_radar.cli, php_radar.sources.cloud\n"
            "google = ('google.auth', 'google.cloud.appengine_admin_v1',\n"
            "          'google.cloud.functions_v2', 'google.cloud.artifactregistry_v1')\n"
            "bad = [m for m in sys.modules if m.split('.')[0] in ('azure', 'boto3', 'botocore')\n"
            "       or m.startswith(google)]\n"
            "assert not bad, bad\n")
    done = subprocess.run([sys.executable, "-c", code], cwd=str(ROOT), capture_output=True,
                          text=True, timeout=60)
    assert done.returncode == 0, done.stderr


def test_every_sdk_module_is_imported_inside_a_function():
    tree = ast.parse(pathlib.Path(cloud.__file__).read_text(encoding="utf-8"),
                     feature_version=(3, 9))
    top = {a.name for n in tree.body if isinstance(n, ast.Import) for a in n.names}
    top |= {n.module for n in tree.body if isinstance(n, ast.ImportFrom)}
    # The standard library may be imported at the top. An SDK may not, because the rest of
    # php-radar has to run without one.
    assert "php_radar.model" in top  # the scan did read the top level
    assert not {m.split(".")[0] for m in top} & {"azure", "boto3", "botocore", "google"}
    inside = set()
    for fn in (n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)):
        for node in ast.walk(fn):
            if isinstance(node, ast.Import):
                inside |= {a.name for a in node.names}
            elif isinstance(node, ast.ImportFrom):
                inside.add(node.module)
    assert inside == {
        "boto3", "google.auth", "google.auth.exceptions", "google.cloud",
        "azure.containerregistry", "azure.identity", "azure.mgmt.appcontainers",
        "azure.mgmt.containerregistry", "azure.mgmt.resource.subscriptions", "azure.mgmt.web"}


def test_the_only_environment_variable_the_factory_reads_is_the_default_subscription():
    source = pathlib.Path(cloud.__file__).read_text(encoding="utf-8")
    uses = [n for n in ast.walk(ast.parse(source))
            if isinstance(n, ast.Attribute) and n.attr in ("environ", "getenv")]
    assert len(uses) == 1
    assert 'os.environ.get("AZURE_SUBSCRIPTION_ID"' in source


def test_the_factory_runs_no_program_and_opens_no_file():
    tree = ast.parse(pathlib.Path(cloud.__file__).read_text(encoding="utf-8"))
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    names |= {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    assert not names & {"subprocess", "open", "eval", "exec", "compile", "__import__", "socket",
                        "print", "logging", "urllib"}


# --- gcp: the extra is missing ---

GOOGLE = ("google.auth", "google.auth.exceptions", "google.cloud.appengine_admin_v1",
          "google.cloud.functions_v2", "google.cloud.artifactregistry_v1")


@pytest.mark.parametrize("missing", GOOGLE)
def test_a_missing_google_package_is_a_message_that_names_the_extra(monkeypatch, missing):
    sdk = Google(monkeypatch)
    block(monkeypatch, missing)
    with pytest.raises(RuntimeError) as caught:
        get_cloud_source("gcp")
    assert 'pip install "php-radar[gcp]"' in str(caught.value)
    assert sdk.default_calls == [] and sdk.built == []


def test_with_no_google_package_at_all_the_extra_is_named(monkeypatch):
    block(monkeypatch, *GOOGLE)
    with pytest.raises(RuntimeError, match=r'pip install "php-radar\[gcp\]"') as caught:
        get_cloud_source("gcp")
    assert not isinstance(caught.value, ImportError)


# --- gcp: credentials ---

@pytest.mark.parametrize("error", [
    DefaultCredentialsError(f"File /home/me/{SECRET}.json was not found."),
    MalformedError(f"Failed to load {SECRET}"),
    RefreshError(SECRET),
    GoogleAuthError(SECRET)], ids=lambda error: type(error).__name__)
def test_credentials_that_cannot_be_loaded_are_a_message_with_the_class_and_not_the_text(
        monkeypatch, error):
    sdk = Google(monkeypatch)
    sdk.error = error
    with pytest.raises(RuntimeError) as caught:
        get_cloud_source("gcp")
    text = str(caught.value)
    assert "php-radar[gcp]" in text
    assert type(error).__name__ in text
    assert "gcloud auth application-default login" in text
    assert SECRET not in text
    assert sdk.built == []


def test_a_client_that_cannot_be_built_is_the_same_message(monkeypatch):
    sdk = Google(monkeypatch)
    sdk.build_error["ArtifactRegistryClient"] = MutualTLSChannelError(SECRET)
    with pytest.raises(RuntimeError) as caught:
        get_cloud_source("gcp")
    assert "php-radar[gcp]" in str(caught.value)
    assert "MutualTLSChannelError" in str(caught.value)
    assert SECRET not in str(caught.value)


def test_a_failure_that_is_no_credentials_problem_is_not_hidden(monkeypatch):
    sdk = Google(monkeypatch)
    sdk.error = KeyError("a bug")
    with pytest.raises(KeyError):
        get_cloud_source("gcp")


# --- gcp: the clients ---

def test_the_four_clients_are_built_once_each_from_one_set_of_credentials(monkeypatch):
    sdk = Google(monkeypatch)
    made = spy(monkeypatch, "GcpSource")
    source = get_cloud_source("gcp")
    assert isinstance(source, GcpSource)
    # No argument, so the credentials come from Application Default Credentials and nowhere else.
    assert sdk.default_calls == [((), {})]
    assert sorted(sdk.built, key=lambda built: built[0]) == [
        ("ArtifactRegistryClient", {"credentials": sdk.credentials}),
        ("FunctionServiceClient", {"credentials": sdk.credentials}),
        ("ServicesClient", {"credentials": sdk.credentials}),
        ("VersionsClient", {"credentials": sdk.credentials})]
    (clients,), kwargs = made[0]
    assert kwargs == {}
    assert type(clients.app_engine_services) is sdk.ServicesClient
    assert type(clients.app_engine_versions) is sdk.VersionsClient
    assert type(clients.functions) is sdk.FunctionServiceClient
    assert type(clients.artifact_registry) is sdk.ArtifactRegistryClient
    assert clients.project == ADC_PROJECT
    assert sdk.calls == []  # building the clients reads nothing


def test_the_project_of_the_credentials_is_the_default_project(monkeypatch):
    Google(monkeypatch, project=ADC_PROJECT)
    assert get_cloud_source("gcp").projects == (ADC_PROJECT,)


def test_credentials_that_name_no_project_leave_the_source_with_none(monkeypatch):
    Google(monkeypatch, project=None)
    assert get_cloud_source("gcp").projects == (None,)


def test_the_quota_project_of_the_credentials_reaches_the_source_with_the_clients(monkeypatch):
    Google(monkeypatch, quota_project=QUOTA_PROJECT)
    made = spy(monkeypatch, "GcpSource")
    get_cloud_source("gcp")
    (clients,), kwargs = made[0]
    assert kwargs == {}
    assert clients.quota_project == QUOTA_PROJECT


@pytest.mark.parametrize("credentials", [NS(kind="adc", quota_project_id=None), NS(kind="adc")],
                         ids=["names none", "has no such attribute"])
def test_credentials_that_name_no_quota_project_leave_the_source_with_none(
        monkeypatch, credentials):
    # Credentials of a kind that lacks the attribute read as naming none.
    sdk = Google(monkeypatch)
    sdk.credentials = credentials
    made = spy(monkeypatch, "GcpSource")
    get_cloud_source("gcp")
    (clients,), _ = made[0]
    assert clients.quota_project is None


def test_a_project_assigned_afterward_replaces_the_default(monkeypatch):
    sdk = Google(monkeypatch)
    stub_project(sdk, PROJECT, unreachable=False)
    source = get_cloud_source("gcp")
    source.projects = (PROJECT,)  # as cloud --project does
    source.inventory()
    assert sdk.calls == project_requests(PROJECT)


def test_a_gcp_source_the_factory_built_reads_through_the_clients_it_was_given(monkeypatch):
    sdk = Google(monkeypatch, project=PROJECT)
    stub_project(sdk)
    evs = get_cloud_source("gcp").inventory()
    function = f"projects/{PROJECT}/locations/us-central1/functions/legacy-api"
    assert rows(evs) == [
        ("appengine", f"apps/{PROJECT}/services/default/versions/v1", "8.3", None),
        ("cloudfunctions", function, "8.2", None),
        ("cloudfunctions", f"gcp cloudfunctions {PROJECT}", None, "skipped"),
        ("artifactregistry", f"us-docker.pkg.dev/{PROJECT}/php/php:8.3.36-fpm", "8.3.36", None)]
    # The location the first page of functions could not reach is read off that page, so the pager
    # has to be walked page by page.
    assert evs[2].note == "not inventoried: the API could not reach us-east5"
    assert verdicts(evs) == [Verdict.INDETERMINATE, Verdict.INDETERMINATE,
                             Verdict.INDETERMINATE, Verdict.LIKELY_PATCHED]
    assert sdk.calls == project_requests(PROJECT)


# --- azure: the extra is missing ---

AZURE = ("azure.containerregistry", "azure.identity", "azure.mgmt.appcontainers",
         "azure.mgmt.containerregistry", "azure.mgmt.resource.subscriptions", "azure.mgmt.web")


@pytest.mark.parametrize("missing", AZURE)
def test_a_missing_azure_package_is_a_message_that_names_the_extra(monkeypatch, missing):
    sdk = Azure(monkeypatch)
    block(monkeypatch, missing)
    with pytest.raises(RuntimeError) as caught:
        get_cloud_source("azure")
    assert 'pip install "php-radar[azure]"' in str(caught.value)
    assert sdk.credential_args == []


def test_with_no_azure_package_at_all_the_extra_is_named(monkeypatch):
    block(monkeypatch, *AZURE)
    with pytest.raises(RuntimeError, match=r'pip install "php-radar\[azure\]"') as caught:
        get_cloud_source("azure")
    assert not isinstance(caught.value, ImportError)


def test_a_credential_that_cannot_start_is_a_message_with_the_class_and_not_the_text(monkeypatch):
    sdk = Azure(monkeypatch)
    sdk.credential_error = ValueError(f"'{SECRET}' is an invalid authority")
    with pytest.raises(RuntimeError) as caught:
        get_cloud_source("azure")
    assert "php-radar[azure]" in str(caught.value)
    assert "ValueError" in str(caught.value)
    assert SECRET not in str(caught.value)


def test_a_failure_that_is_no_authority_problem_is_not_hidden(monkeypatch):
    sdk = Azure(monkeypatch)
    sdk.credential_error = KeyError("a bug")
    with pytest.raises(KeyError):
        get_cloud_source("azure")


# --- azure: the bundle ---

def test_the_factory_returns_the_azure_source(monkeypatch):
    Azure(monkeypatch)
    assert isinstance(get_cloud_source("azure"), AzureSource)


def test_the_bundle_hands_out_the_sdk_clients_themselves_and_the_one_credential(monkeypatch):
    sdk, credential, clients = bundle_of(monkeypatch)
    # No argument, so the credential comes from DefaultAzureCredential's own chain.
    assert sdk.credential_args[0] == {}
    assert credential is sdk.credentials[0]
    assert clients.web is sdk.WebSiteManagementClient
    assert clients.container_apps is sdk.ContainerAppsAPIClient
    assert clients.registries is sdk.ContainerRegistryManagementClient
    assert sdk.made == [] and sdk.listed == []  # nothing is built or listed until a read needs it


def test_an_azure_source_the_factory_built_reads_through_the_clients_it_was_given(monkeypatch):
    sdk = Azure(monkeypatch)
    stub_subscription(sdk)
    source = get_cloud_source("azure")
    source.subscriptions = (SUB,)  # as cloud --subscription does
    evs = source.inventory()
    site = arm_id(SUB, "Microsoft.Web/sites", "app1")
    assert rows(evs) == [
        ("appservice", site, "8.3", None),
        ("containerapps", f"{SERVER}/php:7.4.33-apache", "7.4.33", None),
        ("acr", f"{SERVER}/php:8.3.36-fpm", "8.3.36", None),
        ("acr", f"azure acr {SUB} evil.example.com", None, "skipped")]
    assert verdicts(evs[:3]) == [Verdict.INDETERMINATE, Verdict.EXPOSED, Verdict.LIKELY_PATCHED]
    # Every management client got the credential first and the subscription second.
    cred = sdk.credentials[0]
    assert sdk.made == [
        ("WebSiteManagementClient", cred, SUB), ("ContainerAppsAPIClient", cred, SUB),
        ("ContainerRegistryManagementClient", cred, SUB)]
    assert {name for name, _ in sdk.closed} == {
        "WebSiteManagementClient", "ContainerAppsAPIClient", "ContainerRegistryManagementClient"}
    assert sdk.listed == []  # the subscription was named, so none was listed
    assert source.subscriptions == (SUB,)


# --- azure: the registry host, which comes out of an ARM answer ---

@pytest.mark.parametrize("server, audience", [
    ("myreg.azurecr.io", "https://management.azure.com"),
    ("MyReg.AzureCR.IO", "https://management.azure.com"),
    ("myreg-a1b2c3d4.azurecr.io", "https://management.azure.com"),
    ("a.b.azurecr.io", "https://management.azure.com"),
    ("myreg.azurecr.us", "https://management.usgovcloudapi.net"),
    ("myreg.azurecr.cn", "https://management.chinacloudapi.cn")])
def test_a_host_under_an_azure_registry_domain_gets_a_client_with_the_audience_of_its_cloud(
        monkeypatch, server, audience):
    sdk, credential, clients = bundle_of(monkeypatch)
    clients.registry_data(credential, server)
    assert sdk.registry_clients == [(f"https://{server.lower()}", credential,
                                     {"audience": audience})]


BAD_HOSTS = [
    "", "evil.example.com", "azurecr.io", ".azurecr.io", "-x.azurecr.io", "evilazurecr.io",
    "myreg.azurecr.io.evil.com", "myreg.azurecr.io.", "myreg.azurecr.ioo", "myreg.azurecr.com",
    "myreg.azurecr.eu", "myreg.azurecr.io@evil.com", "evil.com/myreg.azurecr.io",
    "evil.com#.azurecr.io", "evil.com?.azurecr.io", "myreg.azurecr.io:8443", "myreg.azurecr.io/",
    "myreg.azurecr.io\\evil.com", "my reg.azurecr.io", "myreg.azurecr.io\n",
    "myreg.azurecr.io\x00evil.com", "127.0.0.1", "169.254.169.254", "localhost", "[::1]",
    "myr\N{CYRILLIC SMALL LETTER IE}g.azurecr.io", "\N{KELVIN SIGN}evil.azurecr.io",
    "myreg.azurecr.io\N{ZERO WIDTH SPACE}", "myreg_x.azurecr.io", None, 5, b"myreg.azurecr.io",
    ["myreg.azurecr.io"]]


@pytest.mark.parametrize("server", BAD_HOSTS, ids=repr)
def test_a_host_outside_the_azure_registry_domains_is_refused_before_any_client_is_made(
        monkeypatch, server):
    sdk, credential, clients = bundle_of(monkeypatch)
    with pytest.raises(cloud.RegistryHostRefused):
        clients.registry_data(credential, server)
    assert sdk.registry_clients == []


def test_a_registry_with_a_foreign_login_server_is_one_row_and_the_credential_stays_home(
        monkeypatch):
    sdk = Azure(monkeypatch)
    stub_subscription(sdk)
    source = get_cloud_source("azure")
    source.subscriptions = (SUB,)
    evs = source.inventory()
    (gap,) = [ev for ev in evs if ev.location == f"azure acr {SUB} evil.example.com"]
    assert gap.note == "not inventoried: RegistryHostRefused"
    assert gap.signals == {"service": "acr", "kind": "skipped"}
    # Only the registry under azurecr.io was ever handed the credential.
    assert [endpoint for endpoint, _, _ in sdk.registry_clients] == [f"https://{SERVER}"]


def test_whatever_a_login_server_says_a_request_goes_to_a_host_under_a_registry_domain(
        monkeypatch):
    sdk, credential, clients = bundle_of(monkeypatch)
    rng = random.Random(7)
    pieces = ["myreg", "a-b", ".azurecr.io", ".azurecr.us", ".azurecr.cn", "evil.com", "@", ":",
              "8443", "/", "#", "?", "\\", " ", "..", ".", "-", "%2e", "\x00", "\n", "[", "]",
              "\N{KELVIN SIGN}", "\N{CYRILLIC SMALL LETTER IE}", "\N{FULLWIDTH FULL STOP}",
              "xn--", "127.0.0.1", "user:pass@"]
    domains = (".azurecr.io", ".azurecr.us", ".azurecr.cn")
    reached = refused = 0
    for _ in range(20000):
        # Half the logins start from a real host, and the pieces then damage it.
        server = rng.choice(["", "", "myreg" + rng.choice(domains), "MyReg" + rng.choice(domains)])
        for _ in range(rng.randint(0, 3)):
            at = rng.randrange(len(server) + 1)
            server = server[:at] + rng.choice(pieces) + server[at:]
        before = len(sdk.registry_clients)
        try:
            clients.registry_data(credential, server)
        except cloud.RegistryHostRefused:
            assert len(sdk.registry_clients) == before
            refused += 1
            continue
        reached += 1
        (endpoint, given, kwargs) = sdk.registry_clients[-1]
        url = urlsplit(endpoint)
        assert given is credential
        assert url.scheme == "https"
        assert endpoint == f"https://{url.netloc}"  # no path, query, or fragment
        assert url.hostname == url.netloc  # no user name and no port
        assert url.netloc.endswith(domains) and url.netloc[0] not in ".-"
        assert set(kwargs) == {"audience"}
    assert reached > 1000 and refused > 1000  # both sides of the check were exercised


# --- azure: the default subscription ---

def test_with_nothing_set_no_subscription_is_defaulted(monkeypatch):
    sdk, credential, clients = bundle_of(monkeypatch)
    assert clients.subscription_id is None


@pytest.mark.parametrize("value, expected", [
    (SUB, SUB),
    (f"  {SUB}\n", SUB),
    ("0A1B2C3D-4E5F-6A7B-8C9D-0E1F2A3B4C5D", "0a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d")])
def test_a_subscription_id_in_the_environment_is_the_default_scope(monkeypatch, value, expected):
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", value)
    sdk, credential, clients = bundle_of(monkeypatch)
    assert clients.subscription_id == expected


@pytest.mark.parametrize("value", ["", "   ", "\t"])
def test_a_blank_setting_stops_the_run_as_an_empty_flag_does(monkeypatch, value):
    # A pipeline that fills the variable from a secret it does not have sends it blank. Reading
    # that as no setting would hand the run to every subscription the credential can list.
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", value)
    sdk = Azure(monkeypatch)
    with pytest.raises(RuntimeError) as caught:
        get_cloud_source("azure")
    assert "AZURE_SUBSCRIPTION_ID" in str(caught.value)
    assert "blank" in str(caught.value)  # it says what is wrong, since a blank value cannot be seen
    assert sdk.credential_args == []  # refused before the credential was touched
    assert sdk.made == [] and sdk.listed == []


def test_a_blank_setting_gets_the_message_of_any_other_value_that_is_no_id(monkeypatch):
    Azure(monkeypatch)
    messages = set()
    for value in ("", "   ", "\t", "Azure for Students", SUB[:-1]):
        monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", value)
        with pytest.raises(RuntimeError) as caught:
            get_cloud_source("azure")
        messages.add(str(caught.value))
    assert len(messages) == 1


@pytest.mark.parametrize("value", [
    "Azure for Students", "my-subscription", SUB[:-1], SUB + "0", SUB.replace("-", ""),
    "{" + SUB + "}", "urn:uuid:" + SUB, "0000000g-0000-0000-0000-000000000001",
    f"{SUB},{OTHER}", "*", f"{SECRET}"])
def test_a_setting_that_is_no_subscription_id_stops_the_run_and_is_not_repeated(
        monkeypatch, value):
    # Ignoring it would hand the run to every subscription the credential can list.
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", value)
    sdk = Azure(monkeypatch)
    with pytest.raises(RuntimeError) as caught:
        get_cloud_source("azure")
    text = str(caught.value)
    assert "AZURE_SUBSCRIPTION_ID" in text
    assert "GUID" in text
    assert value not in text
    assert sdk.credential_args == []  # refused before the credential was touched


def test_the_default_scope_is_read_and_nothing_is_listed(monkeypatch):
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", SUB)
    sdk = Azure(monkeypatch)
    stub_subscription(sdk, SUB)
    source = get_cloud_source("azure")
    assert source.subscriptions == (SUB,)
    source.inventory()
    assert {sub for _, _, sub in sdk.made} == {SUB}
    assert sdk.listed == []


def test_a_subscription_named_beats_the_default(monkeypatch):
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", SUB)
    sdk = Azure(monkeypatch)
    source = get_cloud_source("azure")
    source.subscriptions = (OTHER,)
    source.inventory()
    assert {sub for _, _, sub in sdk.made} == {OTHER}
    assert sdk.listed == []


# --- azure: the listing of subscriptions, which runs only when nothing else names one ---

def test_with_nothing_named_or_defaulted_the_credential_lists_the_subscriptions_lazily(monkeypatch):
    sdk = Azure(monkeypatch)
    sdk.listing = [SUB, OTHER]
    stub_subscription(sdk, SUB)
    source = get_cloud_source("azure")
    assert sdk.listed == [] and source.subscriptions == ()  # nothing is listed when it is built
    evs = source.inventory()
    assert sdk.listed == [sdk.credentials[0]]  # one listing, with the credential
    assert sdk.listing_closed == [True]
    assert source.subscriptions == (SUB, OTHER)
    assert {sub for _, _, sub in sdk.made} == {SUB, OTHER}
    assert len(evs) == 4


def test_a_listing_that_fails_is_one_row_and_no_subscription_is_read(monkeypatch):
    sdk = Azure(monkeypatch)
    sdk.listing_error = ClientAuthenticationError(f"the account {SECRET} may not list")
    source = get_cloud_source("azure")
    (ev,) = source.inventory()
    assert ev.location == "azure subscriptions"
    assert ev.signals == {"service": "subscriptions", "kind": "skipped"}
    assert "none could be enumerated" in ev.note
    assert "ClientAuthenticationError" in ev.note
    assert SECRET not in repr(ev)
    assert source.subscriptions == () and sdk.made == []


# --- the subscription id ---

@pytest.mark.parametrize("text", [SUB, "0a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d",
                                  "0A1B2C3D-4E5F-6A7B-8C9D-0E1F2A3B4C5D"])
def test_a_guid_is_a_subscription_id(text):
    assert cloud.is_subscription_id(text) is True


@pytest.mark.parametrize("text", [
    "", " ", "Azure for Students", "prod", SUB[:-1], SUB + "0", SUB + "\n", " " + SUB,
    SUB.replace("-", ""), "{" + SUB + "}", "urn:uuid:" + SUB,
    "0000000g-0000-0000-0000-000000000001",
    "\N{FULLWIDTH DIGIT ZERO}" * 8 + SUB[8:], "00000000-0000-0000-0000-00000000000-",
    "-" * 36, None, 5, b"00000000-0000-0000-0000-000000000001", [SUB]])
def test_anything_else_is_not(text):
    assert cloud.is_subscription_id(text) is False


def test_the_check_agrees_with_the_pattern_on_guids_that_were_damaged():
    pattern = re.compile(r"[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")
    rng = random.Random(11)
    alphabet = "0123456789abcdefABCDEFgG-_ \n{}\N{FULLWIDTH DIGIT ONE}"
    agreed = {True: 0, False: 0}
    for _ in range(20000):
        text = str(uuid.UUID(int=rng.getrandbits(128)))
        if rng.random() < 0.3:
            text = text.upper()
        for _ in range(rng.choice([0, 0, 1, 2])):
            at = rng.randrange(len(text) + 1)
            kind = rng.choice(["replace", "insert", "delete"])
            if kind == "replace" and at < len(text):
                text = text[:at] + rng.choice(alphabet) + text[at + 1:]
            elif kind == "insert":
                text = text[:at] + rng.choice(alphabet) + text[at:]
            elif at < len(text):
                text = text[:at] + text[at + 1:]
        expected = bool(pattern.fullmatch(text))
        assert cloud.is_subscription_id(text) is expected, text
        agreed[expected] += 1
    assert agreed[True] > 1000 and agreed[False] > 1000


# --- the cloud command with the factory built for real ---

def test_gcp_reads_the_project_it_was_told_to_and_says_so(monkeypatch, capsys):
    sdk = Google(monkeypatch, project=ADC_PROJECT)
    stub_project(sdk, PROJECT, unreachable=False)
    rc, out, err = run(capsys, "cloud", "--provider", "gcp", "--project", PROJECT)
    assert rc == 0
    assert "GCP projects read: my-project." in out
    assert "Repeat --project" not in out
    assert f"apps/{PROJECT}/services/default/versions/v1" in out
    assert sdk.calls == project_requests(PROJECT)


def test_gcp_without_a_flag_reads_the_project_of_the_credentials_and_says_it_is_the_only_one(
        monkeypatch, capsys):
    sdk = Google(monkeypatch, project=ADC_PROJECT)
    stub_project(sdk, ADC_PROJECT, unreachable=False)
    rc, out, err = run(capsys, "cloud", "--provider", "gcp")
    assert rc == 0
    assert "GCP projects read: adc-project. Only these are covered. Repeat --project" in out
    assert sdk.calls == project_requests(ADC_PROJECT)


def test_gcp_with_no_project_anywhere_says_so_and_is_an_incomplete_scan(monkeypatch, capsys):
    Google(monkeypatch, project=None)
    rc, out, err = run(capsys, "cloud", "--provider", "gcp")
    assert rc == 3
    assert "no GCP project is configured, so no project was read" in out
    assert "GOOGLE_CLOUD_PROJECT" in out


def test_gcp_with_a_location_the_api_could_not_reach_exits_three(monkeypatch, capsys):
    sdk = Google(monkeypatch)
    stub_project(sdk, PROJECT)
    rc, out, err = run(capsys, "cloud", "--provider", "gcp", "--project", PROJECT)
    assert rc == 3
    assert "the API could not reach us-east5" in out


def app_engine_not_found(request):
    raise NotFound(f"404 Not found: {SECRET}")


def test_gcp_with_app_engine_not_found_and_no_quota_project_is_an_incomplete_scan(
        monkeypatch, capsys):
    # On the live run, with no quota project, a switched-off App Engine Admin API answered not
    # found, as a project with no application does. The scan cannot call it clean.
    sdk = Google(monkeypatch, project=PROJECT, quota_project=None)
    sdk.answers["list_services"] = app_engine_not_found
    rc, out, err = run(capsys, "cloud", "--provider", "gcp")
    assert rc == 3
    assert f"gcp appengine {PROJECT}" in out
    assert "not inventoried: NotFound" in out
    assert "1 read skipped, so the result is incomplete" in out
    assert SECRET not in out + err


def test_gcp_with_app_engine_not_found_and_a_quota_project_is_a_project_with_no_application(
        monkeypatch, capsys):
    sdk = Google(monkeypatch, project=PROJECT, quota_project=QUOTA_PROJECT)
    sdk.answers["list_services"] = app_engine_not_found
    rc, out, err = run(capsys, "cloud", "--provider", "gcp")
    assert rc == 0
    assert "appengine" not in out
    assert "skipped" not in out + err


def test_gcp_keeps_stdout_a_document_in_json(monkeypatch, capsys):
    sdk = Google(monkeypatch)
    stub_project(sdk, PROJECT, unreachable=False)
    rc, out, err = run(capsys, "cloud", "--provider", "gcp", "--project", PROJECT,
                       "--format", "json")
    assert json.loads(out)["assets"]
    assert "GCP projects read: my-project." in err


def test_azure_names_the_subscription_it_was_told_to_read(monkeypatch, capsys):
    sdk = Azure(monkeypatch)
    stub_subscription(sdk)
    rc, out, err = run(capsys, "cloud", "--provider", "azure", "--subscription", SUB)
    assert rc == 1  # the Container App runs an end-of-life image
    assert f"Azure subscriptions read: {SUB}." in out
    assert "Repeat --subscription" not in out
    assert f"{SERVER}/php:7.4.33-apache" in out
    assert {sub for _, _, sub in sdk.made} == {SUB}
    assert sdk.listed == []


def test_azure_without_a_flag_lists_the_subscriptions_and_names_them_after_the_read(
        monkeypatch, capsys):
    sdk = Azure(monkeypatch)
    sdk.listing = [SUB, OTHER]
    stub_subscription(sdk, SUB)
    rc, out, err = run(capsys, "cloud", "--provider", "azure")
    # What the credential could list is all there is to read, so the note does not offer more.
    assert (f"Azure subscriptions read: {SUB}, {OTHER}. That is every subscription the "
            "credential can list.") in out
    assert "Only these are covered" not in out and "Repeat --subscription" not in out
    assert sdk.listed == [sdk.credentials[0]]


def test_azure_that_cannot_list_says_so_and_is_an_incomplete_scan(monkeypatch, capsys):
    sdk = Azure(monkeypatch)
    sdk.listing_error = ClientAuthenticationError(SECRET)
    rc, out, err = run(capsys, "cloud", "--provider", "azure")
    assert rc == 3
    assert "no Azure subscription was named, and none could be listed" in out
    assert "AZURE_SUBSCRIPTION_ID" in out
    assert SECRET not in out + err


def test_azure_reads_the_subscription_of_the_environment_when_no_flag_is_given(
        monkeypatch, capsys):
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", OTHER)
    sdk = Azure(monkeypatch)
    sdk.listing = [SUB, OTHER]
    stub_subscription(sdk, OTHER)
    rc, out, err = run(capsys, "cloud", "--provider", "azure")
    # The variable names one subscription, and the credential can list others.
    assert (f"Azure subscriptions read: {OTHER}. Only these are covered. "
            "Repeat --subscription to read more.") in out
    assert "every subscription the credential can list" not in out
    assert sdk.listed == []


BAD_SETTINGS = pytest.mark.parametrize("value", ["Azure for Students", "", "   "],
                                       ids=["a name", "empty", "blank"])


@BAD_SETTINGS
def test_azure_refuses_a_bad_setting_in_the_environment_and_does_not_list_instead(
        monkeypatch, capsys, value):
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", value)
    sdk = Azure(monkeypatch)
    sdk.listing = [SUB, OTHER]
    rc, out, err = run(capsys, "cloud", "--provider", "azure")
    assert rc == 2
    assert out == ""
    assert "AZURE_SUBSCRIPTION_ID" in err
    assert sdk.listed == [] and sdk.made == []


@BAD_SETTINGS
def test_a_bad_setting_in_the_environment_stops_even_a_run_that_names_a_subscription(
        monkeypatch, capsys, value):
    # A decision, and this test is what keeps it one. The factory runs before the flag is applied,
    # and a default that cannot be honored is an error even where the flag would make it moot. So
    # a bad setting is found today and not on the day the flag is left off.
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", value)
    sdk = Azure(monkeypatch)
    stub_subscription(sdk, SUB)
    rc, out, err = run(capsys, "cloud", "--provider", "azure", "--subscription", SUB)
    assert rc == 2
    assert out == ""
    assert "AZURE_SUBSCRIPTION_ID" in err
    assert sdk.credential_args == [] and sdk.made == [] and sdk.listed == []


@pytest.mark.parametrize("provider, modules", [("gcp", GOOGLE), ("azure", AZURE)])
def test_a_missing_extra_is_a_message_and_exit_two(monkeypatch, capsys, provider, modules):
    block(monkeypatch, *modules)
    rc, out, err = run(capsys, "cloud", "--provider", provider)
    assert rc == 2
    assert out == ""
    assert f'pip install "php-radar[{provider}]"' in err
    assert "Traceback" not in err


def test_credentials_that_cannot_be_loaded_are_exit_two_and_the_path_is_not_printed(
        monkeypatch, capsys):
    sdk = Google(monkeypatch)
    sdk.error = DefaultCredentialsError(f"File /home/me/{SECRET}.json was not found.")
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", f"/home/me/{SECRET}.json")
    rc, out, err = run(capsys, "cloud", "--provider", "gcp")
    assert rc == 2
    assert out == ""
    assert "DefaultCredentialsError" in err
    assert SECRET not in out + err


# --- the real packages, when they are installed ---

def refuse(*args, **kwargs):
    raise AssertionError("the network was touched")


@pytest.fixture
def no_network(monkeypatch):
    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


@pytest.fixture
def no_adc(monkeypatch, tmp_path, no_network):
    """An environment in which google-auth finds no credentials and cannot look for a server."""
    monkeypatch.setenv("CLOUDSDK_CONFIG", str(tmp_path / "gcloud"))
    monkeypatch.setenv("NO_GCE_CHECK", "true")


def test_real_google_auth_with_no_credentials_is_the_message_and_names_the_extra(
        monkeypatch, no_adc):
    pytest.importorskip("google.auth")
    sdk = Google(monkeypatch, real_auth=True)
    with pytest.raises(RuntimeError) as caught:
        get_cloud_source("gcp")
    assert "php-radar[gcp]" in str(caught.value)
    assert "DefaultCredentialsError" in str(caught.value)
    assert sdk.built == []


@pytest.mark.parametrize("content", [None, "{not json"], ids=["missing file", "malformed file"])
def test_real_google_auth_names_the_file_in_its_message_and_the_factory_does_not(
        monkeypatch, no_adc, tmp_path, content):
    pytest.importorskip("google.auth")
    key = tmp_path / f"{SECRET}.json"
    if content is not None:
        key.write_text(content)
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(key))
    # The real error repeats the path of the file.
    google_auth = importlib.import_module("google.auth")
    with pytest.raises(google_auth.exceptions.DefaultCredentialsError) as real:
        google_auth.default()
    assert SECRET in str(real.value)
    sdk = Google(monkeypatch, real_auth=True)
    with pytest.raises(RuntimeError) as caught:
        get_cloud_source("gcp")
    assert "DefaultCredentialsError" in str(caught.value)
    assert SECRET not in str(caught.value)
    assert sdk.built == []


def test_real_google_auth_credentials_and_project_reach_the_clients(monkeypatch, no_adc, tmp_path):
    pytest.importorskip("google.oauth2.credentials")
    info = {"type": "authorized_user", "client_id": "cid", "client_secret": "csecret",
            "refresh_token": "rtoken"}
    key = tmp_path / "user.json"
    key.write_text(json.dumps(info))
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(key))
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "env-project")
    sdk = Google(monkeypatch, real_auth=True)
    source = get_cloud_source("gcp")
    assert source.projects == ("env-project",)
    assert len(sdk.built) == 4
    for name, given in sdk.built:
        assert type(given["credentials"]).__module__ == "google.oauth2.credentials"
    assert sdk.calls == []


def real_management():
    """The four management packages, or a skip when one of them is not installed."""
    return [pytest.importorskip(name) for name in (
        "azure.mgmt.web", "azure.mgmt.appcontainers", "azure.mgmt.containerregistry",
        "azure.mgmt.resource.subscriptions")]


def stub_credential():
    from azure.core.credentials import AccessToken
    return NS(get_token=lambda *scopes, **kwargs: AccessToken("stub-token", 4102444800))


def test_the_bundle_holds_the_real_management_classes_and_they_take_a_credential_and_an_id(
        monkeypatch, no_network):
    web, apps, registries, _ = real_management()
    Azure(monkeypatch, real_management=True)
    made = spy(monkeypatch, "AzureSource")
    get_cloud_source("azure")
    (credential, clients), _ = made[0]
    assert clients.web is web.WebSiteManagementClient
    assert clients.container_apps is apps.ContainerAppsAPIClient
    assert clients.registries is registries.ContainerRegistryManagementClient
    for make in (clients.web, clients.container_apps, clients.registries):
        client = make(stub_credential(), SUB)  # as the source calls it, with no network
        client.close()


def test_the_listing_function_reads_the_ids_through_the_real_subscription_client(
        monkeypatch, no_network):
    requests = pytest.importorskip("requests")
    transport = pytest.importorskip("azure.core.pipeline.transport")
    subscriptions = real_management()[-1]
    seen = []

    def subscription(ident):
        return {"id": f"/subscriptions/{ident}", "subscriptionId": ident, "displayName": SECRET,
                "state": "Enabled", "tenantId": "00000000-0000-0000-0000-0000000000ff"}

    class Session(requests.Session):
        def request(self, method, url, **kwargs):
            seen.append(url.partition("?")[0].partition("management.azure.com")[2])
            response = requests.Response()
            response.status_code, response.reason, response.url = 200, "OK", url
            response._content = json.dumps(
                {"value": [subscription(SUB), subscription(OTHER)]}).encode()
            response.headers["content-type"] = "application/json"
            response.raw = NS()  # the transport sets enforce_content_length on it
            response._content_consumed = True
            return response

    canned = transport.RequestsTransport(session=Session(), session_owner=False)

    class Canned(subscriptions.SubscriptionClient):
        def __init__(self, credential, **kwargs):
            super().__init__(credential, transport=canned, **kwargs)

    monkeypatch.setattr(subscriptions, "SubscriptionClient", Canned)
    Azure(monkeypatch, real_management=True)
    made = spy(monkeypatch, "AzureSource")
    get_cloud_source("azure")
    (_, clients), _ = made[0]
    assert seen == []  # building the source lists nothing
    assert clients.subscription_ids(stub_credential()) == [SUB, OTHER]
    assert seen == ["/subscriptions"]
