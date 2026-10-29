"""Cloud inventory sources, one per provider, behind one interface.

A cloud source lists what an account runs and returns CLOUD Evidence for the resources that run or
hold PHP. get_cloud_source(name) builds one for aws, gcp, or azure. Each provider's SDK is an
optional install, imported only when its source is asked for, so the rest of php-radar runs without
them.
"""
import os
from typing import Any, Callable, NamedTuple, Optional, Protocol, runtime_checkable

from php_radar.model import Evidence
from php_radar.sources.cloud.aws import AwsSource
from php_radar.sources.cloud.azure import AzureSource
from php_radar.sources.cloud.gcp import GcpSource


@runtime_checkable
class CloudSource(Protocol):
    """What a provider adapter offers. The runtime check lets a caller test for it."""

    def inventory(self) -> list[Evidence]:
        ...


# The default of _boto3. A sentinel, because None has to mean a boto3 that is not installed.
_IMPORT = object()

# A subscription id is a GUID: 8, 4, 4, 4, and 12 hex digits.
_HEX = frozenset("0123456789abcdefABCDEF")

# The login server of a registry is a host name in the answer of an ARM call, and the registry
# client sends the credential to it. So the data plane is reached only under Azure's own registry
# domains. Each domain comes with the audience of its cloud's management endpoint.
_REGISTRY_CLOUDS = {".azurecr.io": "https://management.azure.com",
                    ".azurecr.us": "https://management.usgovcloudapi.net",
                    ".azurecr.cn": "https://management.chinacloudapi.cn"}
# Nothing outside these can put a port, a path, or a user name in the URL built from a host.
_HOST_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-.")


class RegistryHostRefused(ValueError):
    """A login server that is under none of Azure's registry domains.

    The class name goes into the report row of the registry, so it says what happened.
    """


class _GcpClients(NamedTuple):
    """What GcpSource reads off its clients argument."""

    app_engine_services: Any
    app_engine_versions: Any
    functions: Any
    artifact_registry: Any
    project: Optional[str]  # the project of the credentials, or None when they name none
    quota_project: Optional[str]  # their quota project, or None when they name none


class _AzureClients(NamedTuple):
    """What AzureSource reads off its clients argument.

    The first four make a client when the source needs one, because a management client is bound
    to one subscription and a data client to one registry. The listing function is called only
    when nothing names a subscription.
    """

    web: Callable[..., Any]
    container_apps: Callable[..., Any]
    registries: Callable[..., Any]
    registry_data: Callable[[Any, Any], Any]
    subscription_id: Optional[str]  # the default subscription, or None
    subscription_ids: Callable[[Any], list]


def is_subscription_id(text: object) -> bool:
    """True for a subscription id, which is a GUID written as 8-4-4-4-12 hex digits."""
    parts = text.split("-") if isinstance(text, str) else []
    return [len(part) for part in parts] == [8, 4, 4, 4, 12] and _HEX.issuperset("".join(parts))


def _import_boto3() -> Optional[Any]:
    try:
        import boto3
    except ImportError:
        return None
    return boto3


# The install hints below quote the extra, because zsh reads the brackets as a glob and refuses an
# unquoted command.
def _aws(sdk: Any) -> CloudSource:
    module = _import_boto3() if sdk is _IMPORT else sdk
    if module is None:
        raise RuntimeError("the aws source needs boto3, and it is not installed. "
                           'Install the extra with: pip install "php-radar[aws]"')
    try:
        # No argument, so credentials come from boto3's default chain and from nowhere else.
        session = module.Session()
    except Exception as exc:  # a profile that is not there, or a config file boto3 cannot read
        # The message stays out. It can quote the profile name or a path.
        raise RuntimeError(f"boto3 could not start a session ({type(exc).__name__})") from None
    return AwsSource(session)


def _gcp(_sdk: Any) -> CloudSource:
    try:
        import google.auth
        from google.auth.exceptions import GoogleAuthError
        from google.cloud import appengine_admin_v1, artifactregistry_v1, functions_v2
    except ImportError:
        raise RuntimeError(
            "the gcp source needs the Google Cloud packages, and one of them is not installed. "
            'Install the extra with: pip install "php-radar[gcp]"') from None
    try:
        # No argument, so credentials come from Application Default Credentials and from nowhere
        # else. The clients are built here, so a source that starts has every client it reads.
        credentials, project = google.auth.default()
        clients = _GcpClients(
            app_engine_services=appengine_admin_v1.ServicesClient(credentials=credentials),
            app_engine_versions=appengine_admin_v1.VersionsClient(credentials=credentials),
            functions=functions_v2.FunctionServiceClient(credentials=credentials),
            artifact_registry=artifactregistry_v1.ArtifactRegistryClient(credentials=credentials),
            project=project,
            # Credentials without the attribute count as naming none, and then App Engine's not
            # found stays a failure.
            quota_project=getattr(credentials, "quota_project_id", None))
    except GoogleAuthError as exc:  # no credentials, or a key file google-auth cannot use
        # The message stays out. It can quote the path of the key file.
        raise RuntimeError(
            "php-radar[gcp] could not load Application Default Credentials "
            f"({type(exc).__name__}). Run gcloud auth application-default login, or point "
            "GOOGLE_APPLICATION_CREDENTIALS at a key file") from None
    return GcpSource(clients)


def _default_subscription() -> Optional[str]:
    """The subscription AZURE_SUBSCRIPTION_ID names, or None when the variable is not set.

    It is the scope of a run that names none. A variable that is set to anything that is no
    subscription id stops the run, a blank value included, because skipping it would hand the run
    to every subscription the credential can list. A pipeline that fills the variable from a
    secret it does not have sends it blank. The message does not repeat the value.
    """
    value = os.environ.get("AZURE_SUBSCRIPTION_ID")
    if value is None:
        return None
    value = value.strip()
    if not is_subscription_id(value):
        raise RuntimeError("AZURE_SUBSCRIPTION_ID is set, and its value is blank or is not a "
                           "subscription id (a GUID). Fix it or unset it")
    return value.lower()


def _registry_endpoint(login_server: object) -> tuple[str, str]:
    """(URL, audience) for the data plane of a registry, or RegistryHostRefused for a login server
    that is not a host under one of Azure's registry domains."""
    # A name outside ASCII is refused before it is lowercased, because a few such characters
    # lowercase to ASCII ones.
    host = login_server.lower() if isinstance(login_server, str) and login_server.isascii() else ""
    if host and _HOST_CHARS.issuperset(host):
        for suffix, audience in _REGISTRY_CLOUDS.items():
            if host.endswith(suffix):
                name = host[:-len(suffix)]
                if name and name[0] not in ".-":
                    return f"https://{host}", audience
    raise RegistryHostRefused("the login server is under none of .azurecr.io, .azurecr.us, and "
                              ".azurecr.cn, so no request was made to it")


def _azure(_sdk: Any) -> CloudSource:
    try:
        from azure.containerregistry import ContainerRegistryClient
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.appcontainers import ContainerAppsAPIClient
        from azure.mgmt.containerregistry import ContainerRegistryManagementClient
        from azure.mgmt.resource.subscriptions import SubscriptionClient
        from azure.mgmt.web import WebSiteManagementClient
    except ImportError:
        raise RuntimeError(
            "the azure source needs the Azure packages, and one of them is not installed. "
            'Install the extra with: pip install "php-radar[azure]"') from None
    subscription = _default_subscription()
    try:
        # No argument, so the credential comes from DefaultAzureCredential's own chain and from
        # nowhere else.
        credential = DefaultAzureCredential()
    except ValueError as exc:  # a setting in the environment that azure-identity rejects
        # The message stays out. It can quote the setting.
        raise RuntimeError("php-radar[azure] could not start the Azure credential "
                           f"({type(exc).__name__})") from None

    def registry_data(cred: Any, login_server: Any) -> Any:
        endpoint, audience = _registry_endpoint(login_server)
        return ContainerRegistryClient(endpoint, cred, audience=audience)

    def subscription_ids(cred: Any) -> list:
        # Called when nothing else names a subscription, and not before. It is a read like the rest.
        with SubscriptionClient(cred) as client:
            return [sub.subscription_id for sub in client.subscriptions.list()]

    return AzureSource(credential, _AzureClients(
        web=WebSiteManagementClient, container_apps=ContainerAppsAPIClient,
        registries=ContainerRegistryManagementClient, registry_data=registry_data,
        subscription_id=subscription, subscription_ids=subscription_ids))


# Each builder takes what a test passes in for its SDK. Only boto3 has such a stand-in. The google
# and azure packages are found in sys.modules, so their builders ignore the argument.
_PROVIDERS: dict[str, Callable[[Any], CloudSource]] = {"aws": _aws, "gcp": _gcp, "azure": _azure}


def get_cloud_source(name: str, _boto3: Any = _IMPORT) -> CloudSource:
    """The source for the provider called name: aws, gcp, or azure.

    ValueError means name is no provider. RuntimeError means the source cannot start, for one of
    three reasons. The provider's SDK is not installed, and the message gives the pip command that
    installs its extra. Its credentials could not be loaded, and the message names the class of the
    error. Or, for azure, AZURE_SUBSCRIPTION_ID is set and is blank or is no subscription id.

    _boto3 is for tests and stands in for the boto3 module. Anything with a Session() that returns
    a session will do. None means boto3 is not installed. By default boto3 is imported here, on
    the call, and nowhere else. The google and azure packages are imported the same way, and a
    test stands in for them through sys.modules.
    """
    if name not in _PROVIDERS:
        choices = ", ".join(_PROVIDERS)
        raise ValueError(f"unknown cloud provider {name!r}, the choices are: {choices}")
    return _PROVIDERS[name](_boto3)
