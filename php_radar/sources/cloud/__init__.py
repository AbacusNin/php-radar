"""Cloud inventory sources, one per provider, behind one interface.

A cloud source lists what an account runs and returns CLOUD Evidence for the resources that run or
hold PHP. get_cloud_source(name) builds one. The provider's SDK is an optional install, imported
only when its source is asked for, so the rest of php-radar runs without it.
"""
from typing import Any, Callable, Optional, Protocol, runtime_checkable

from php_radar.model import Evidence
from php_radar.sources.cloud.aws import AwsSource


@runtime_checkable
class CloudSource(Protocol):
    """What a provider adapter offers. The runtime check lets a caller test for it."""

    def inventory(self) -> list[Evidence]:
        ...


# The default of _boto3. A sentinel, because None has to mean a boto3 that is not installed.
_IMPORT = object()


def _import_boto3() -> Optional[Any]:
    try:
        import boto3
    except ImportError:
        return None
    return boto3


def _aws(sdk: Any) -> CloudSource:
    module = _import_boto3() if sdk is _IMPORT else sdk
    if module is None:
        raise RuntimeError("the aws source needs boto3, and it is not installed. "
                           "Install the extra with: pip install php-radar[aws]")
    try:
        # No argument, so credentials come from boto3's default chain and from nowhere else.
        session = module.Session()
    except Exception as exc:  # a profile that is not there, or a config file boto3 cannot read
        # The message stays out. It can quote the profile name or a path.
        raise RuntimeError(f"boto3 could not start a session ({type(exc).__name__})") from None
    return AwsSource(session)


_PROVIDERS: dict[str, Callable[[Any], CloudSource]] = {"aws": _aws}


def get_cloud_source(name: str, _boto3: Any = _IMPORT) -> CloudSource:
    """The source for the provider called name.

    The only provider is aws. ValueError means name is no provider. RuntimeError means the source
    cannot start: boto3 is not installed, and the message gives the pip command that installs it,
    or boto3 could not make a session.

    _boto3 is for tests and stands in for the boto3 module. Anything with a Session() that returns
    a session will do. None means boto3 is not installed. By default boto3 is imported here, on
    the call, and nowhere else.
    """
    if name not in _PROVIDERS:
        choices = ", ".join(_PROVIDERS)
        raise ValueError(f"unknown cloud provider {name!r}, the choices are: {choices}")
    return _PROVIDERS[name](_boto3)
