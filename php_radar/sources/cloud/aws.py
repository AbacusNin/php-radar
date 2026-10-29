"""Reads an AWS account, read-only, and reports where PHP runs.

AwsSource(session).inventory() looks at the Elastic Beanstalk environments, the Lambda functions,
and the ECR images of a region and returns one CLOUD Evidence for each that runs or holds PHP. It
makes four calls and every one is a read: DescribeEnvironments, ListFunctions, DescribeRepositories,
and ListImages. A policy that allows those four is all the access it uses.

The session is the way in. Its default credential chain supplies credentials when a call goes
out, so this module takes no key as an argument and never asks the session for one. From each
answer it copies the few fields it names, because a Lambda function record carries the values of
its environment variables. A failed call is recorded by the class of its error and the service's
error code. The message stays out. It can name the caller's ARN or repeat part of the request.

No service reports a PHP build, so PHP is found by name, and each find carries what the name gave.
A Beanstalk platform called "PHP 8.3 running on 64bit Amazon Linux 2023/4.3.0" gives the branch,
8.3. The 4.3.0 is the platform's own version and is never read as PHP's. A Lambda layer called
php-83 marks a PHP runtime and gives no version. An ECR tag gives a version when it names one. In
a repository called php, the official image's tags do (8.3.12-fpm). Anywhere else the tag has to
say php (php8.3, php-8.3.12).

Only a full 8.3.12 hands the grader a build to compare. A branch, or the mark of PHP alone, grades
INDETERMINATE. The PHP2Shell fix landed in a patch release of each branch, so a branch cannot say
whether it is in, and a packaged PHP can carry the fix under an older number. For the same reason
a full number counts unless what follows it reads as a distro revision or a pre-release, by the
grader's own test. 8.3.12-1ubuntu2.28 could be a Ubuntu build, and a tag like it gives the branch
alone.

Every tag of an ECR repository carries the repository's ARN, so the tags of one repository fold
into one asset whose verdict is the worst of them, and each tag keeps its own evidence line. A
Beanstalk find carries the environment's DNS name in hostname (its CNAME, or the load balancer's
name when there is none), so a host read or a network probe of that name merges with it. A single
instance has an address and no load balancer. The address goes in ip, which merges nothing.

Nothing is skipped quietly. A failed call, a listing that runs past its page limit, and an entry
that cannot be read each leave a row. The row has the reason in note and kind skipped, as the repo
scan marks its own, and with no PHP in it the row grades INDETERMINATE at LOW. A failure inside a
repository that already showed PHP leaves a row that says PHP is there, so a repository read only
in part is never cleared by the part that was read. Three repositories in a row that cannot be
listed end the ECR read. A credential that expired midway would otherwise cost a slow failure for
every repository left.

Limits. A run reads one region, the session's own unless regions says otherwise. PHP that does not
say so by name goes unseen: a Docker or ECS Beanstalk platform, a Lambda container image, a zip
with PHP inside it, an image whose tags never say php. An ECR tag is a label somebody typed. The
image behind it may never run, and a tag that can be pushed again may point at another build
tomorrow. boto3's own timeouts and retries apply.
"""
from collections import Counter
from typing import Any, Callable, Iterable, Iterator, NamedTuple, Optional, Union

from php_radar.model import Evidence, Sapi, Source
from php_radar.sources.cloud._common import (
    _BRANCH, _MAX_MISSES, _MAX_PAGES, _MAX_TAG, _NAME, _PATH, _Stop, _dns, _fits, _gap, _number,
    _repo_gap, _tag_note, _tag_version, _unread, _where)
# The network source tells a name from an address, and the repo scan reads a SAPI out of an image
# tag. Using theirs keeps a cloud read in step with the other sources.
from php_radar.sources.network import _identity
from php_radar.sources.repo import _sapi

# The page size asked of ECR, its largest. Beanstalk and Lambda choose their own.
_PAGE = 1000

# The longest value of each kind taken from an answer. An ARN is 2048 characters at most. An AWS
# error code is far shorter than 64.
_MAX_ARN = 2048
_MAX_CODE = 64
_MAX_TEXT = 256

# What an entry of each list lacks when it cannot be read. The row that counts the entries says so,
# because a dropped environment is a puzzle otherwise. A non-ASCII application name is one cause.
_UNREAD = {"environments": "no usable ARN", "functions": "no usable ARN",
           "repositories": "no usable ARN or name", "images": "no usable tag"}

# A person meets these two first, and the class name alone says too little.
_KNOWN = {"NoCredentialsError": "no AWS credentials were found",
          "NoRegionError": "no AWS region is configured"}


class _Repo(NamedTuple):
    arn: str
    name: str
    uri: str  # what docker pulls from, or the name when the answer gave no usable URI
    official: bool  # php is the last part of the name, as in a mirror of the official image


def _arn(value: object, spaces: bool = False) -> Optional[str]:
    # Printable ASCII, because the ARN becomes the identity of an asset and goes into a report
    # line. A space is allowed only where AWS allows one. A Beanstalk environment ARN holds the
    # application name, as in environment/My First Elastic Beanstalk Application/Test.
    ok = (isinstance(value, str) and value.startswith("arn:") and len(value) <= _MAX_ARN
          and value.isascii() and value.isprintable() and (spaces or " " not in value))
    return value if ok else None


def _printable(value: str) -> bool:
    return 0 < len(value) <= _MAX_TEXT and value.isascii() and value.isprintable()


def _why(exc: Exception) -> str:
    """What to record about a failed call: the error's class and, for a service error, its code.

    The message is left out. It can name the caller's ARN or account, or repeat part of the request.
    """
    name = type(exc).__name__
    if name in _KNOWN:
        return f"{_KNOWN[name]} ({name})"
    response = getattr(exc, "response", None)
    error = response.get("Error") if isinstance(response, dict) else None
    code = error.get("Code") if isinstance(error, dict) else None
    return f"{name} ({code})" if _fits(code, _NAME, _MAX_CODE) and code != name else name


def _listing(call: Callable[..., Any], items: str, into: str, out_of: str,
             **fixed: Any) -> Iterator[object]:
    """Each item on every page that call returns.

    The continuation comes back in the answer field out_of and goes into the next call as the
    parameter into. A call that fails, or an answer that is not the shape the service documents,
    ends the listing with _Stop, once the items already read have been handed over.
    """
    params = dict(fixed)
    for _ in range(_MAX_PAGES):
        try:
            page = call(**params)
        except Exception as exc:  # botocore is optional here, so its error classes cannot be named
            raise _Stop(_why(exc)) from None
        if not isinstance(page, dict):
            raise _Stop("the answer is not understood")
        found = page.get(items)
        if found is None:
            found = []  # a service may leave out a list that is empty
        if not isinstance(found, list):
            raise _Stop("the answer is not understood")
        yield from found
        after = page.get(out_of)
        if not after:
            return
        if not isinstance(after, str):
            raise _Stop("the answer is not understood")
        params[into] = after
    raise _Stop(f"the list runs past {_MAX_PAGES} pages")


# --- Elastic Beanstalk ---

def _php_platform(env: dict) -> Optional[tuple[str, str]]:
    """(platform name, PHP number) when the environment runs a platform that names PHP."""
    arn, stack = env.get("PlatformArn"), env.get("SolutionStackName")
    names = []
    if isinstance(arn, str):
        # The name follows the first slash: ...::platform/PHP 8.3 running on 64bit Amazon Linux.
        names.append(arn.partition("/")[2])
    if isinstance(stack, str):
        names.append(stack)
    for name in names:
        words = name.split()
        for word, after in zip(words, words[1:]):
            number = _number(after) if word.lower() == "php" else None
            if number:
                return name, number
    return None


def _environment(arn: str, env: dict) -> Optional[Evidence]:
    found = _php_platform(env)
    if found is None:
        return None
    name, number = found
    signals = {"resource": arn, "service": "elasticbeanstalk", "php_present": "true"}
    named = "the platform"
    if _printable(name):
        signals["platform"] = name
        # The platform version ends the name and fixes which PHP release the environment runs,
        # so the note gives a reader the whole name.
        named = "platform " + name
    host = _dns(env.get("CNAME")) or _dns(env.get("EndpointURL"))
    if host:
        signals.update(_identity(host))
    note = "" if number.count(".") == 2 else _BRANCH.format(named)
    return Evidence(Source.CLOUD, arn, number, Sapi.UNKNOWN, signals, note)


def _beanstalk(client: Any, odd: Counter) -> Iterator[Evidence]:
    for env in _listing(client.describe_environments, "Environments", "NextToken", "NextToken"):
        arn = _arn(env.get("EnvironmentArn"), spaces=True) if isinstance(env, dict) else None
        if arn is None:
            odd["environments"] += 1
        elif env.get("Status") != "Terminated":
            ev = _environment(arn, env)
            if ev is not None:
                yield ev


# --- Lambda ---

def _layer_name(arn: object) -> Optional[str]:
    # arn:aws:lambda:us-east-1:534081306603:layer:php-83:20, with or without the version.
    parts = arn.split(":") if isinstance(arn, str) else []
    ok = len(parts) >= 7 and parts[2] == "lambda" and parts[5] == "layer"
    return parts[6] if ok and _fits(parts[6], _NAME, _MAX_TEXT) else None


def _says_php(name: str) -> bool:
    # A word of the name is php, or php and a number: php-83, php83, my-php-runtime. Not phpunit.
    words = name.lower().replace("_", "-").split("-")
    return any(w == "php" or (w.startswith("php") and w[3:].isdigit()) for w in words)


def _php_function(fn: dict) -> str:
    """Why the function runs PHP, in words for a note, or "" when nothing says it does."""
    runtime = fn.get("Runtime")
    # AWS offers no PHP runtime today. A custom one, with PHP in a layer, is how PHP gets here.
    if _fits(runtime, _NAME, _MAX_TEXT) and runtime.lower().startswith("php"):
        return f"runtime {runtime} names PHP, and the build is not read"
    layers = fn.get("Layers")
    for layer in layers if isinstance(layers, list) else []:
        name = _layer_name(layer.get("Arn") if isinstance(layer, dict) else None)
        if name is not None and _says_php(name):
            return f"layer {name} marks a PHP runtime, and the build is not read"
    return ""


def _lambda(client: Any, odd: Counter) -> Iterator[Evidence]:
    for fn in _listing(client.list_functions, "Functions", "Marker", "NextMarker"):
        arn = _arn(fn.get("FunctionArn")) if isinstance(fn, dict) else None
        if arn is None:
            odd["functions"] += 1
            continue
        why = _php_function(fn)
        if why:
            signals = {"resource": arn, "service": "lambda", "php_present": "true"}
            yield Evidence(Source.CLOUD, arn, None, Sapi.UNKNOWN, signals, why)


# --- ECR ---

def _repository(item: object) -> Optional[_Repo]:
    if not isinstance(item, dict):
        return None
    arn, name = _arn(item.get("repositoryArn")), item.get("repositoryName")
    if arn is None or not _fits(name, _PATH, _MAX_TEXT):
        return None
    uri = item.get("repositoryUri")
    return _Repo(arn, name, uri if _fits(uri, _PATH, _MAX_ARN) else name,
                 name.rpartition("/")[2] == "php")


def _image(repo: _Repo, tag: str) -> Optional[Evidence]:
    number = _tag_version(tag, repo.official)
    if number is None:
        return None
    signals = {"resource": repo.arn, "service": "ecr", "php_present": "true"}
    return Evidence(Source.CLOUD, f"{repo.uri}:{tag}", number, _sapi(tag.lower()), signals,
                    _tag_note(number))


def _ecr(client: Any, odd: Counter) -> Iterator[Evidence]:
    misses = 0
    for item in _listing(client.describe_repositories, "repositories", "nextToken", "nextToken",
                         maxResults=_PAGE):
        repo = _repository(item)
        if repo is None:
            odd["repositories"] += 1
            continue
        saw_php = False
        try:
            for image in _listing(client.list_images, "imageIds", "nextToken", "nextToken",
                                  repositoryName=repo.name, filter={"tagStatus": "TAGGED"},
                                  maxResults=_PAGE):
                tag = image.get("imageTag") if isinstance(image, dict) else None
                if not _fits(tag, _NAME, _MAX_TAG):
                    odd["images"] += 1
                    continue
                ev = _image(repo, tag)
                if ev is not None:
                    saw_php = True
                    yield ev
        except _Stop as stop:
            misses += 1
            yield _repo_gap("ecr", repo.arn, repo.uri, str(stop), saw_php)
            if misses == _MAX_MISSES:
                raise _Stop(f"{_MAX_MISSES} repositories in a row could not be read") from None
        else:
            misses = 0


_READERS = (("elasticbeanstalk", _beanstalk), ("lambda", _lambda), ("ecr", _ecr))


class AwsSource:
    """The PHP in an AWS account, read through a boto3 session.

    session is a boto3 Session, or anything with its region_name and client(). regions is the
    region to read as a name, or several as a list, a tuple, or any iterator of names. It is the
    session's own by default and when it is empty. The regions read are kept in regions, so a
    caller can say what was covered. inventory() reads afresh each time it is called.
    """

    def __init__(self, session: Any,
                 regions: Union[str, Iterable[Optional[str]], None] = None) -> None:
        self._session = session
        if isinstance(regions, str):
            # One name is one region. Read as a sequence it would be one region for each letter.
            # An empty name is no region, so it leaves the session's own.
            regions = [regions] if regions else None
        self.regions = tuple(regions or ()) or (session.region_name,)

    def inventory(self) -> list[Evidence]:
        """One Evidence for each Beanstalk environment, Lambda function, and ECR image tag that
        names PHP. Whatever could not be read leaves a row in the same list."""
        found: list[Evidence] = []
        for region in self.regions:
            for service, read in _READERS:
                found += self._read(service, region, read)
        return found

    def _client(self, service: str, region: Optional[str]) -> Any:
        try:
            return self._session.client(service, region_name=region)
        except Exception as exc:  # a missing profile or region, and anything else boto3 raises
            raise _Stop(_why(exc)) from None

    def _read(self, service: str, region: Optional[str],
              read: Callable[[Any, Counter], Iterator[Evidence]]) -> list[Evidence]:
        found: list[Evidence] = []
        where = _where("aws", service, region)
        odd: Counter = Counter()  # entries that could not be read, by the list they came from
        try:
            for ev in read(self._client(service, region), odd):
                found.append(ev)
        except _Stop as stop:
            found.append(_gap(service, where, str(stop)))
        # After the stop as well, so a count is never lost to a failure that comes later.
        found.extend(_unread(service, where, count, what, _UNREAD[what])
                     for what, count in odd.items())
        return found
