"""Reads an Azure subscription, read-only, and reports where PHP runs.

AzureSource(credential, clients).inventory() looks at the App Service apps, the Container Apps,
and the Azure Container Registry images of a subscription and returns one CLOUD Evidence for each
that runs or holds PHP. It makes six calls and every one is a read: web_apps.list,
web_apps.get_configuration, container_apps.list_by_subscription, registries.list, and a registry's
list_repository_names and list_tag_properties. The Reader role covers the first four. The last two
are data-plane reads that Reader does not include, so a run with Reader alone leaves a skipped row
for each registry. A run that names no subscription and has no default makes a seventh call before
these. It goes to the bundle's subscription_ids function, which lists the subscriptions the
credential can see.

The credential is the way in. The clients ask it for a token when a call goes out, so this module
takes no key as an argument and never asks the credential for one. From each answer it copies the
few fields it names, because a site configuration carries app settings and connection strings, and
a container carries its environment. A failed call is recorded by the class of its error, with the
status and the code the service sent. The message stays out. It can name the caller's object ID or
repeat part of the request.

The subscriptions to read come from three places, tried in this order. The ones the caller names
come first, and when there are any nothing is listed. The bundle's own subscription_id comes next.
Last comes the bundle's subscription_ids function. It takes the credential and returns the IDs of
every subscription the credential can list. The call is a read like the rest: when the function is
missing, raises, or returns no ID, one skipped row says so and nothing else is read. The IDs that
were read stay in subscriptions.

No service reports a PHP build, so PHP is found by name, and each find carries what the name gave.
An App Service app on Linux keeps its runtime in linux_fx_version, as PHP|8.3, which gives the
branch, 8.3. A site on Windows leaves that empty and keeps its version in php_version, as 7.4. PHP
on Windows is retired, so only a legacy site has one. A Container App or a registry gives a version
only through an image tag. In a repository, or on an image, called php, the official image's tags
name it (8.3.12-fpm). Elsewhere the tag has to say php, as in php8.3 or php-8.3.12.

Only a full 8.3.12 hands the grader a build to compare. A branch grades INDETERMINATE, because the
PHP2Shell fix landed in a patch release of each branch. The grader calls a branch end of life only
when it has a full number to compare, so a legacy site on php_version 7.4 grades INDETERMINATE as
well. A full number in a tag counts unless what follows it reads as a distro revision or a
pre-release, by the grader's own test, and then the tag gives the branch alone.

An App Service app and a Container App carry their resource ID in resource and their host name in
hostname (the default host name, or the ingress FQDN), so a host read or a network probe of that
name merges with them. Every tag of a registry repository carries the login server and the
repository, so the tags of one repository fold into one asset whose verdict is the worst of them,
and each tag keeps its own evidence line.

Nothing it reads is skipped quietly. What it leaves unread is listed under Unread, below. A failed
call, a listing that runs past its page limit, and a site whose configuration cannot be read each
leave a row. So does an entry that cannot be read, and so does a scope that cannot be found. The
row has the reason in note and kind skipped, as the repo scan marks its own, and with no PHP in it
the row grades INDETERMINATE at LOW. A registry that cannot be opened leaves a row that names it. A
failure inside a repository that already showed PHP leaves a row that says PHP is there, so a
repository read only in part is never cleared by the part that was read. Three sites in a row whose
configuration cannot be read end the App Service read, and three repositories in a row that cannot
be listed end the registry read. A credential that expired midway would otherwise cost a slow
failure for every one left.

Limits. A run reads one subscription at a time. The list of sites does not carry the configuration
reliably. Each site costs a call of its own. A tag is a label somebody typed. The image behind it
may never run, and a tag that can be pushed again may point at another build tomorrow. The SDK's
own timeouts and retries apply.

Unread, and left for later: Container Instances, an App Service app on a custom container
(linux_fx_version DOCKER|image), a deployment slot of an App Service app, a Container Apps job, and
an init container. The custom container leaves no row and no count until its image is read the way
a Container App's is. An image whose tags never say php goes unseen too. The exact build in an
image's config blob would settle a branch tag. Reading it is a data-plane pull, which asks for more
access than a listing does.

It has been run read-only against a live subscription, which held no PHP, so no find has been seen
live. The tests answer from stand-ins written by hand, and the field names come from the packages'
published models. The SDKs are optional installs that this module never imports.
"""
from collections import Counter
from contextlib import AbstractContextManager, contextmanager
from typing import Any, Callable, Iterable, Iterator, NamedTuple, Optional, Union

from php_radar.model import Evidence, Sapi, Source
from php_radar.sources.cloud._common import (
    _BRANCH, _MAX_MISSES, _MAX_PAGES, _MAX_TAG, _NAME, _PATH, _Stop, _dns, _entries, _fits, _gap,
    _iterable, _number, _repo_gap, _tag_note, _tag_version, _unread, _where)
# The network source tells a name from an address, and the repo scan reads a SAPI out of an image
# tag. Using theirs keeps a cloud read in step with the other sources.
from php_radar.sources.network import _identity
from php_radar.sources.repo import _sapi

# The longest value of each kind taken from an answer. A resource ID runs a few hundred characters
# and a runtime label a few dozen. The limit keeps one odd answer from putting a page of text in a
# report row.
_MAX_ID = 1024
_MAX_TEXT = 256
_MAX_CODE = 64

# A resource ID is a path, and a resource group may hold parentheses. A runtime label is a name, a
# pipe, and a version. An image reference has a colon before its tag, and before the port of a
# registry, and an @ before its digest.
_ARM = _PATH | frozenset("()")
_FX = _NAME | frozenset("|")
_IMAGE = _PATH | frozenset(":@")

# What an entry of each list lacks when it cannot be read. The row that counts the entries says so,
# because a dropped entry is a puzzle otherwise. A resource group named in Unicode is one cause.
_UNREAD = {"sites": "no usable resource ID",
           "container apps": "no usable resource ID or container list",
           "containers": "no usable image", "registries": "no usable login server",
           "repositories": "no usable name", "tags": "no usable name"}

# A person meets these first, and the class name alone says too little. azure-core and
# azure-identity are optional here, so an error is known by the name of its class.
_DENIED = "access was denied"
_KNOWN = {"ClientAuthenticationError": "the Azure credential was not accepted, or it could not "
                                       "get a token",
          "CredentialUnavailableError": "no Azure credential was found",
          "ServiceRequestError": "the service could not be reached"}
_CODES = {"MissingSubscriptionRegistration":
          "the resource provider is not registered in the subscription"}

# Why a run reads nothing when no subscription is named, defaulted, or listed.
_NO_SCOPE = "no Azure subscription is configured and none could be enumerated"

# What getattr returns for a field the configuration does not have. A field that holds None is
# another case.
_UNSET = object()

# Opens a client of a kind: web, container_apps, registries, or registry_data.
_Open = Callable[..., AbstractContextManager[Any]]


class _Ref(NamedTuple):
    base: str  # the reference without its digest, which is what a registry hands out
    tag: Optional[str]
    official: bool  # php is the last part of the image path, as in a mirror of the official image


def _why(exc: Exception) -> str:
    """What to record about a failed call: the error's class, the status and code the service
    sent, and a plain word for the common ones.

    The message is left out. It can name the caller's object ID or repeat part of the request.
    """
    name = type(exc).__name__
    status = getattr(exc, "status_code", None)
    status = int(status) if isinstance(status, int) and 100 <= status <= 599 else None
    code = getattr(getattr(exc, "error", None), "code", None)
    code = code if _fits(code, _NAME, _MAX_CODE) and code != name else None
    label = " ".join(str(part) for part in (name, status, code) if part)
    words = _KNOWN.get(name) or (_DENIED if status in (401, 403) else None) or _CODES.get(code)
    return f"{words} ({label})" if words else label


def _call(call: Callable[[], Any]) -> Any:
    try:
        return call()
    except Exception as exc:  # azure-core is optional, so its errors cannot be named
        raise _Stop(_why(exc)) from None


def _listing(call: Callable[[], Any]) -> Iterator[object]:
    """Each item that call returns, over every page its pager reads.

    azure-core hands back an ItemPaged, an iterator that fetches a page when the one before it is
    spent, so a call can fail at any item. A failure ends the listing with _Stop, once the items
    already read have been handed over. A call that raises is one. So is an answer that is not a
    list of pages, and so is a listing past the page limit. An answer with no by_page is one page.

    call takes no arguments and runs when the listing is first read. A client that lacks the
    attribute it names then fails inside the listing and leaves a row.
    """
    try:
        answer = call()
        by_page = getattr(answer, "by_page", None)
        pages = by_page() if callable(by_page) else [answer]
        if not _iterable(pages):
            raise _Stop("the answer is not understood")
        count = 0
        for page in pages:
            count += 1
            if count > _MAX_PAGES:
                raise _Stop(f"the list runs past {_MAX_PAGES} pages")
            if not _iterable(page):
                raise _Stop("the answer is not understood")
            yield from page
    except _Stop:
        raise
    except Exception as exc:  # azure-core is optional, so its errors cannot be named
        raise _Stop(_why(exc)) from None


def _arm(value: object, kind: str) -> Optional[list]:
    """The parts of a resource ID of this kind (Microsoft.Web/sites), or None for any other string.

    An ID reads /subscriptions/{id}/resourceGroups/{group}/providers/{namespace}/{type}/{name}.
    Azure writes the fixed parts in more than one case, so they match in any.
    """
    if not _fits(value, _ARM, _MAX_ID):
        return None
    parts = value.split("/")
    namespace, _, resource = kind.partition("/")
    fixed = ["subscriptions", "resourcegroups", "providers", namespace.lower(), resource.lower()]
    ok = len(parts) == 9 and all(parts[1:]) and not parts[0]
    return parts if ok and [parts[i].lower() for i in (1, 3, 5, 6, 7)] == fixed else None


def _branch(text: str) -> Optional[str]:
    # A full number is cut to its branch, because a runtime label does not fix the build.
    number = _number(text)
    return number.rpartition(".")[0] if number and number.count(".") == 2 else number


def _named(field: str, value: str, version: str) -> tuple[Optional[str], str]:
    # (branch or None, note) for a field that names PHP. With no branch it still says PHP is there.
    branch = _branch(version)
    if branch is None:
        return None, f"{field} {value} names PHP, and the build is not read"
    return branch, _BRANCH.format(f"{field} {value}")


def _site_php(config: Any) -> Optional[tuple[Optional[str], str]]:
    """(branch or None, note) for a site that runs PHP, or None for a site that names none.

    A Linux site names its runtime in linux_fx_version, whatever the runtime is. A Windows site
    leaves that empty and keeps its PHP version in php_version. A configuration with neither field
    is no configuration at all, and it raises _Stop.
    """
    linux = getattr(config, "linux_fx_version", _UNSET)
    windows = getattr(config, "php_version", _UNSET)
    if linux is _UNSET and windows is _UNSET:
        raise _Stop("the answer is not understood")
    if linux and linux is not _UNSET:
        if not _fits(linux, _FX, _MAX_TEXT):
            return None
        runtime, _, version = linux.partition("|")
        return _named("linux_fx_version", linux, version) if runtime.lower() == "php" else None
    return _named("php_version", windows, windows) if _fits(windows, _NAME, _MAX_TEXT) else None


def _site(item: object) -> Optional[tuple[str, str, str]]:
    """(resource ID, resource group, name) of a site, or None when the entry names none."""
    ident = getattr(item, "id", None)
    parts = _arm(ident, "Microsoft.Web/sites")
    return (ident, parts[4], parts[8]) if parts else None


def _reference(value: object) -> Optional[_Ref]:
    # registry.example/library/php:8.3.12@sha256:... The tag is in the last part of the path, so the
    # colon of a registry port is never taken for one.
    if not _fits(value, _IMAGE, _MAX_ID):
        return None
    base = value.partition("@")[0]
    name, colon, tag = base.rpartition("/")[2].partition(":")
    if not base or (colon and not _fits(tag, _NAME, _MAX_TAG)):
        return None
    return _Ref(base, tag if colon else None, name == "php")


def _image_find(service: str, resource: str, location: str, tag: str, official: bool,
                host: Optional[str] = None) -> Optional[Evidence]:
    number = _tag_version(tag, official)
    if number is None:
        return None
    signals = {"resource": resource, "service": service, "php_present": "true"}
    if host:
        signals.update(_identity(host))
    return Evidence(Source.CLOUD, location, number, _sapi(tag.lower()), signals, _tag_note(number))


# --- App Service ---

def _site_find(ident: str, item: object, config: Any) -> Optional[Evidence]:
    php = _site_php(config)
    if php is None:
        return None
    number, note = php
    signals = {"resource": ident, "service": "appservice", "php_present": "true"}
    host = _dns(getattr(item, "default_host_name", None))
    if host:
        signals.update(_identity(host))
    return Evidence(Source.CLOUD, ident, number, Sapi.UNKNOWN, signals, note)


def _appservice(client_of: _Open, subscription: str, odd: Counter) -> Iterator[Evidence]:
    misses = 0
    with client_of("web", subscription) as client:
        for item in _listing(lambda: client.web_apps.list()):
            site = _site(item)
            if site is None:
                odd["sites"] += 1
                continue
            ident, group, name = site
            try:
                config = _call(lambda: client.web_apps.get_configuration(group, name))
                found = _site_find(ident, item, config)
            except _Stop as stop:
                misses += 1
                yield _repo_gap("appservice", ident, ident, str(stop), False)
                if misses == _MAX_MISSES:
                    raise _Stop(f"{_MAX_MISSES} sites in a row could not be read") from None
            else:
                misses = 0
                if found is not None:
                    yield found


# --- Container Apps ---

def _containerapps(client_of: _Open, subscription: str, odd: Counter) -> Iterator[Evidence]:
    with client_of("container_apps", subscription) as client:
        for app in _listing(lambda: client.container_apps.list_by_subscription()):
            ident = getattr(app, "id", None)
            containers = _entries(getattr(getattr(app, "template", None), "containers", None))
            if _arm(ident, "Microsoft.App/containerApps") is None or containers is None:
                odd["container apps"] += 1
                continue
            ingress = getattr(getattr(app, "configuration", None), "ingress", None)
            host = _dns(getattr(ingress, "fqdn", None))
            for container in containers:
                ref = _reference(getattr(container, "image", None))
                if ref is None:
                    odd["containers"] += 1
                elif ref.tag is not None:
                    ev = _image_find("containerapps", ident, ref.base, ref.tag, ref.official, host)
                    if ev is not None:
                        yield ev


# --- Container Registry ---

def _repositories(client_of: _Open, server: str, odd: Counter,
                  misses: list) -> Iterator[Evidence]:
    """The finds in every repository of one registry. misses[0] counts the repositories in a row
    whose tags could not be listed, across registries, and this read ends when it reaches the
    limit."""
    with client_of("registry_data", server) as data:
        for name in _listing(lambda: data.list_repository_names()):
            if not _fits(name, _PATH, _MAX_TEXT):
                odd["repositories"] += 1
                continue
            resource = f"{server}/{name}"
            official = name.rpartition("/")[2] == "php"
            saw_php = False
            try:
                for record in _listing(lambda: data.list_tag_properties(name)):
                    tag = getattr(record, "name", None)
                    if not _fits(tag, _NAME, _MAX_TAG):
                        odd["tags"] += 1
                        continue
                    ev = _image_find("acr", resource, f"{resource}:{tag}", tag, official)
                    if ev is not None:
                        saw_php = True
                        yield ev
            except _Stop as stop:
                misses[0] += 1
                yield _repo_gap("acr", resource, resource, str(stop), saw_php)
                if misses[0] == _MAX_MISSES:
                    return
            else:
                misses[0] = 0


def _acr(client_of: _Open, subscription: str, odd: Counter) -> Iterator[Evidence]:
    misses = [0]
    with client_of("registries", subscription) as client:
        for item in _listing(lambda: client.registries.list()):
            server = _dns(getattr(item, "login_server", None))
            if server is None:
                odd["registries"] += 1
                continue
            try:
                yield from _repositories(client_of, server, odd, misses)
            except _Stop as stop:
                # A registry that cannot be opened is no run of failures. Each one gets its row.
                yield _gap("acr", _where("azure", "acr", f"{subscription} {server}"), str(stop))
            if misses[0] == _MAX_MISSES:
                raise _Stop(f"{_MAX_MISSES} repositories in a row could not be read")


_READERS = (("appservice", _appservice), ("containerapps", _containerapps), ("acr", _acr))


def _ids(value: Any) -> tuple:
    """The subscription IDs in value, in order, with the empty ones left out.

    One ID as a string is one subscription. Read as a sequence it would be one for each letter.
    """
    if isinstance(value, str):
        value = [value]
    return tuple(sub for sub in (value or ()) if sub)


class AzureSource:
    """The PHP in an Azure subscription, read through the SDK's clients.

    credential is a DefaultAzureCredential, or anything the clients take as one. It is handed to
    the factories and to nothing else. clients is any object with four factories as attributes.
    web, container_apps, and registries each take the credential and a subscription ID, and return
    the management client of that subscription. The SDK's own classes do this as they stand:
    WebSiteManagementClient, ContainerAppsAPIClient, ContainerRegistryManagementClient.
    registry_data takes the credential and a login server and returns the ContainerRegistryClient
    of that registry. A client is closed when its read is done.

    Two more attributes of the bundle say which subscriptions to read, and both are optional.
    subscription_id is one subscription. subscription_ids is a function that takes the credential
    and returns the IDs of every subscription it can list, as strings, such as the subscription_id
    of each item that SubscriptionClient(credential).subscriptions.list() gives. It is the only
    thing here that lists subscriptions, and it is called only when nothing else names one.

    subscriptions is the subscription to read as an ID, or several as a list, a tuple, or any
    iterator of IDs, and an empty one is left out. Without any, the source reads the bundle's
    subscription_id, and without that it calls subscription_ids once for each inventory() and reads
    what comes back. When no ID comes out of any of the three, inventory() returns one skipped row
    and reads nothing else. After inventory() the attribute holds the IDs that were read, as a
    tuple, or an empty one when there were none, so a caller can say what was covered. Assigning to
    it names the subscriptions to read, and an empty assignment leaves them to the bundle.
    """

    def __init__(self, credential: Any, clients: Any,
                 subscriptions: Union[str, Iterable[Optional[str]], None] = None) -> None:
        self._credential = credential
        self._clients = clients
        self.subscriptions = subscriptions

    @property
    def subscriptions(self) -> tuple:
        return self._scope

    @subscriptions.setter
    def subscriptions(self, value: Union[str, Iterable[Optional[str]], None]) -> None:
        # What the caller named, or else the bundle's own. Neither takes a call, so both are known
        # now. The bundle's function is not asked until inventory() needs it.
        self._named = _ids(value)
        self._scope = self._named or self._default()

    def _default(self) -> tuple:
        default = getattr(self._clients, "subscription_id", None)
        return (default,) if default else ()

    def _enumerate(self) -> tuple:
        """The IDs the bundle's subscription_ids function returns for the credential.

        It is a read like any other, so a function that is missing, raises, returns no list, or
        returns no ID ends the scope with _Stop and a reason.
        """
        make = getattr(self._clients, "subscription_ids", None)
        if not callable(make):
            raise _Stop(_NO_SCOPE)
        try:
            listed = _entries(make(self._credential))
        except Exception as exc:  # the SDK is optional here, so its errors cannot be named
            raise _Stop(f"{_NO_SCOPE}: {_why(exc)}") from None
        if listed is None:
            raise _Stop(f"{_NO_SCOPE}: the answer is not understood")
        ids = _ids(listed)
        if not ids:
            raise _Stop(f"{_NO_SCOPE}: the list of subscriptions is empty")
        return ids

    def inventory(self) -> list[Evidence]:
        """One Evidence for each App Service app, Container App image, and registry image tag that
        names PHP. Whatever could not be read leaves a row in the same list."""
        try:
            scope = self._named or self._default() or self._enumerate()
        except _Stop as stop:
            self._scope = ()
            return [_gap("subscriptions", _where("azure", "subscriptions", None), str(stop))]
        self._scope = scope
        found: list[Evidence] = []
        for subscription in scope:
            for service, read in _READERS:
                found += self._read(service, subscription, read)
        return found

    @contextmanager
    def _client(self, kind: str, *scope: str) -> Iterator[Any]:
        make = getattr(self._clients, kind, None)
        if not callable(make):
            raise _Stop(f"the clients have no {kind}")
        try:
            client = make(self._credential, *scope)
        except Exception as exc:  # the SDK is optional here, so its errors cannot be named
            raise _Stop(_why(exc)) from None
        try:
            yield client
        finally:
            close = getattr(client, "close", None)
            if callable(close):
                try:
                    close()
                except Exception:  # the client has given its answers, and a failed close loses none
                    pass

    def _read(self, service: str, subscription: str,
              read: Callable[[_Open, Any, Counter], Iterator[Evidence]]) -> list[Evidence]:
        found: list[Evidence] = []
        usable = _fits(subscription, _NAME, _MAX_TEXT)
        # An ID that is no name stays out of the label, which goes into a report line.
        where = _where("azure", service, subscription if usable else None)
        odd: Counter = Counter()  # entries that could not be read, by the list they came from
        try:
            if not usable:
                raise _Stop("the subscription id is not usable")
            for ev in read(self._client, subscription, odd):
                found.append(ev)
        except _Stop as stop:
            found.append(_gap(service, where, str(stop)))
        # After the stop as well, so a count is never lost to a failure that comes later.
        found.extend(_unread(service, where, count, what, _UNREAD[what])
                     for what, count in odd.items())
        return found
