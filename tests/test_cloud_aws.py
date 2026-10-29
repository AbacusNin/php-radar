import ast
import importlib.util
import itertools
import json
import pathlib
import random
import re
import subprocess
import sys
from typing import NamedTuple

import pytest

from php_radar.knowledge import DATA_PATH, grade, grade_evidence, load_matrix
from php_radar.model import AssetInventory, Confidence, Evidence, Sapi, Source, Verdict
from php_radar.report import render_console, render_json, render_sarif
from php_radar.sources import cloud
from php_radar.sources.cloud import CloudSource, aws, get_cloud_source
from php_radar.sources.cloud.aws import AwsSource

MATRIX = load_matrix(DATA_PATH)
ROOT = pathlib.Path(__file__).resolve().parent.parent

# Stands for anything a response holds that the source has no business copying: a Lambda
# environment variable, an exception message. It is not token-shaped, so the report's redactor
# would let it through if it ever got that far.
SECRET = "hunter2-" + "CANARY-aws"

# Characters outside ASCII, by name, so that this file stays plain ASCII.
E_ACUTE = "\N{LATIN SMALL LETTER E WITH ACUTE}"
O_ACUTE = "\N{LATIN SMALL LETTER O WITH ACUTE}"
BIDI = "\N{RIGHT-TO-LEFT OVERRIDE}"
DASHES_AND_QUOTES = ("\N{EM DASH}\N{EN DASH}\N{LEFT SINGLE QUOTATION MARK}"
                     "\N{RIGHT SINGLE QUOTATION MARK}\N{LEFT DOUBLE QUOTATION MARK}"
                     "\N{RIGHT DOUBLE QUOTATION MARK}")

ACCOUNT = "123456789012"
ENV_ARN = f"arn:aws:elasticbeanstalk:us-east-1:{ACCOUNT}:environment/shop/shop-prod"
# The example ARN in the Beanstalk documentation. An application name may hold spaces.
SPACED_ARN = ("arn:aws:elasticbeanstalk:us-east-2:123456789012:"
              "environment/My First Elastic Beanstalk Application/Test")
CNAME = "shop-prod.eba-abc123xy.us-east-1.elasticbeanstalk.com"
PLATFORM = "arn:aws:elasticbeanstalk:us-east-1::platform/"  # how an AWS platform ARN starts
FN_ARN = f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:legacy-api"
LAYER = "arn:aws:lambda:us-east-1:534081306603:layer:"  # Bref publishes its layers from here
BREF_FPM = LAYER + "php-83-fpm:20"
REPO_ARN = f"arn:aws:ecr:us-east-1:{ACCOUNT}:repository/php"
REPO_URI = f"{ACCOUNT}.dkr.ecr.us-east-1.amazonaws.com/php"

# The only calls the source may make. Each one reads.
READS = {"describe_environments", "list_functions", "describe_repositories", "list_images"}

SIGNAL_KEYS = {"resource", "hostname", "ip", "service", "platform", "php_present", "kind"}


# --- stand-ins ---
# The errors keep the class names botocore gives them, because the source records a class name
# and nothing it can import.

class ClientError(Exception):
    def __init__(self, code, message="denied"):
        super().__init__(f"An error occurred ({code}) when calling Operation: {message}")
        self.response = {"Error": {"Code": code, "Message": message}}


class NoCredentialsError(Exception):
    pass


class NoRegionError(Exception):
    pass


class EndpointConnectionError(Exception):
    pass


class ProfileNotFound(Exception):
    pass


class Call(NamedTuple):
    service: str
    region: object
    operation: str
    kwargs: dict


META = {"RequestId": "r-1", "HTTPStatusCode": 200, "RetryAttempts": 0,
        "HTTPHeaders": {"x-amzn-requestid": "r-1", "x-amz-security-token": SECRET}}

_EMPTY = {"describe_environments": "Environments", "list_functions": "Functions",
          "describe_repositories": "repositories", "list_images": "imageIds"}

# What a scripted operation hands back once its answers run out.
_END = object()


class FakeClient:
    """One service client of a FakeSession. Only the four reads the source may use exist."""

    def __init__(self, session, service, region):
        self._session, self._service, self._region = session, service, region

    def __getattr__(self, name):
        self._session.touched.append(f"{self._service}.{name}")
        raise AttributeError(name)

    def describe_environments(self, **kw):
        return self._read("describe_environments", kw, {"NextToken"}, "NextToken", "NextToken",
                          lambda: self._session._env.get(self._region, []))

    def list_functions(self, **kw):
        return self._read("list_functions", kw, {"Marker"}, "Marker", "NextMarker",
                          lambda: self._session._fn.get(self._region, []))

    def describe_repositories(self, **kw):
        self._limit(kw)
        repos = self._session._repo.get(self._region, {})
        return self._read("describe_repositories", kw, {"maxResults", "nextToken"}, "nextToken",
                          "nextToken", lambda: [record for record, _ in repos.values()])

    def list_images(self, **kw):
        self._limit(kw)
        name = kw.get("repositoryName")
        repos = self._session._repo.get(self._region, {})
        # An untagged image is not a tag, so the source has to ask for tagged ones only. The
        # source catches every error from a call, so a wrong filter is noted here, not raised.
        if kw.get("filter") != {"tagStatus": "TAGGED"}:
            self._session.touched.append("list_images without the TAGGED filter")
        for rule in self._session._fail_images.get(name, []):
            if rule[1] > 0:
                rule[1] -= 1
            else:
                self._record("list_images", kw)
                raise rule[0]

        def images():
            if name not in repos:
                raise ClientError("RepositoryNotFoundException")
            return [{"imageDigest": "sha256:" + "0" * 64, "imageTag": tag}
                    for tag in repos[name][1]]

        allowed = {"repositoryName", "filter", "maxResults", "nextToken"}
        return self._read("list_images", kw, allowed, "nextToken", "nextToken", images)

    @staticmethod
    def _limit(kw):
        # ECR rejects a page size outside 1 to 1000.
        size = kw.get("maxResults", 1)
        if not (type(size) is int and 1 <= size <= 1000):
            raise ClientError("InvalidParameterException")

    def _record(self, operation, kw):
        self._session.calls.append(Call(self._service, self._region, operation, dict(kw)))

    def _read(self, operation, kw, allowed, ask, back, items):
        session = self._session
        self._record(operation, kw)
        if set(kw) - allowed:
            raise TypeError(f"{operation} does not take {sorted(set(kw) - allowed)}")
        key = _EMPTY[operation]
        scripted = session._script.get(operation)
        if scripted is not None:
            answer = next(scripted, _END)
            if isinstance(answer, BaseException):
                raise answer
            return {key: [], "ResponseMetadata": META} if answer is _END else answer
        for rule in session._fail:
            if rule[0] == self._service and rule[1] in (None, operation):
                if rule[3] > 0:
                    rule[3] -= 1
                else:
                    raise rule[2]
        everything = items()
        start = int(kw[ask]) if ask in kw else 0
        size = session.page or len(everything) or 1
        page = {key: everything[start:start + size], "ResponseMetadata": META}
        if start + size < len(everything):
            page[back] = str(start + size)
        return page


class FakeSession:
    """Stands in for a boto3 Session and answers from what a test stubbed.

    region_name and client() are all the source may use. Anything else it touches on the session
    or a client, get_credentials() above all, lands in touched and raises, so a test can see it.
    page is how many items one page holds, or None for a single page.
    """

    def __init__(self, region="us-east-1", page=None):
        self.region_name = region
        self.page = page
        self.calls = []  # every call made on a client, in order
        self.clients = []  # (service, region, extra keyword names) for each client() call
        self.touched = []
        self._env, self._fn, self._repo = {}, {}, {}
        self._script = {}  # operation -> iterator of raw answers, or exceptions to raise
        self._fail = []  # [service, operation or None, exception, calls to let through first]
        self._fail_images = {}  # repository name -> [[exception, calls to let through first]]
        self._no_client = {}

    def __getattr__(self, name):
        self.touched.append(name)
        raise AttributeError(name)

    def client(self, service, region_name=None, **kw):
        region = region_name or self.region_name
        self.clients.append((service, region_name, tuple(sorted(kw))))
        if kw:
            self.touched.append("client " + ",".join(sorted(kw)))
        if service in self._no_client:
            raise self._no_client[service]
        return FakeClient(self, service, region)

    # What a test can stub.

    def stub_environment(self, arn, region=None, **fields):
        record = {"EnvironmentName": "shop-prod", "EnvironmentId": "e-abc123",
                  "ApplicationName": "shop", "EnvironmentArn": arn, "Status": "Ready",
                  "Health": "Green", "Description": SECRET, "OperationsRole": SECRET}
        record.update(fields)
        self._env.setdefault(region or self.region_name, []).append(record)
        return record

    def stub_beanstalk_php(self, branch, arn, region=None, cname=CNAME, **fields):
        region = region or self.region_name
        name = f"PHP {branch} running on 64bit Amazon Linux 2023/4.3.0"
        fields.setdefault("PlatformArn", f"arn:aws:elasticbeanstalk:{region}::platform/{name}")
        fields.setdefault("SolutionStackName",
                          f"64bit Amazon Linux 2023 v4.3.0 running PHP {branch}")
        if cname is not None:
            fields["CNAME"] = cname
        return self.stub_environment(arn, region, **fields)

    def stub_lambda(self, name, layers=(), runtime="provided.al2", region=None, **fields):
        region = region or self.region_name
        variables = {"DB_PASSWORD": SECRET, "AWS_SECRET_ACCESS_KEY": SECRET}
        record = {"FunctionName": name, "Runtime": runtime, "Handler": "index.handler",
                  "FunctionArn": f"arn:aws:lambda:{region}:{ACCOUNT}:function:{name}",
                  "Description": SECRET, "Environment": {"Variables": variables}}
        if layers:
            record["Layers"] = [{"Arn": arn, "CodeSize": 1} for arn in layers]
        record.update(fields)
        self._fn.setdefault(region, []).append(record)
        return record

    def stub_repository(self, name, tags, region=None):
        region = region or self.region_name
        record = {"repositoryArn": f"arn:aws:ecr:{region}:{ACCOUNT}:repository/{name}",
                  "registryId": ACCOUNT, "repositoryName": name,
                  "repositoryUri": f"{ACCOUNT}.dkr.ecr.{region}.amazonaws.com/{name}",
                  "encryptionConfiguration": {"encryptionType": "KMS", "kmsKey": SECRET}}
        self._repo.setdefault(region, {})[name] = (record, list(tags))
        return record

    def script(self, operation, answers):
        """Answers calls to operation from answers, in order, with no paging of their own.

        A BaseException in the list is raised. After the last answer a call gets an empty page.
        """
        self._script[operation] = iter(answers)

    def fail(self, service, exc, operation=None, skip=0):
        self._fail.append([service, operation, exc, skip])

    def fail_images(self, repository, exc, skip=0):
        self._fail_images.setdefault(repository, []).append([exc, skip])

    def fail_client(self, service, exc):
        self._no_client[service] = exc


@pytest.fixture
def fake_session():
    return FakeSession()


def inventory(session, **kw):
    return AwsSource(session, **kw).inventory()


def only(session, **kw):
    (found,) = inventory(session, **kw)
    return found


def only_one(evs):
    (ev,) = evs
    return ev


def text_of(evidence):
    return repr(evidence)


def rendered(evs):
    inv = AssetInventory()
    for ev in evs:
        inv.add(ev)
    assets = inv.assets()
    return [render_console(assets, MATRIX), render_json(assets, MATRIX),
            render_sarif(assets, MATRIX)]


def stubbed_everything(session):
    session.stub_beanstalk_php("8.3", ENV_ARN)
    session.stub_lambda("legacy-api", layers=[BREF_FPM])
    session.stub_repository("php", ["8.3.36-fpm"])


# --- a Beanstalk find, and the extra that is not installed ---

def test_beanstalk_php_platform_becomes_evidence(fake_session):
    fake_session.stub_beanstalk_php("8.3", "arn:aws:...:env/web1")
    evs = AwsSource(fake_session).inventory()
    assert any(e.source == Source.CLOUD and e.signals["resource"].startswith("arn:")
               for e in evs)


def test_missing_extra_gives_clear_error():
    with pytest.raises(RuntimeError, match='pip install "php-radar\\[aws\\]"'):
        get_cloud_source("aws", _boto3=None)


# --- the optional extra ---

def test_a_real_import_that_fails_gives_the_same_error(monkeypatch):
    # None in sys.modules makes an import of boto3 raise ImportError, installed or not.
    monkeypatch.setitem(sys.modules, "boto3", None)
    with pytest.raises(RuntimeError, match='pip install "php-radar\\[aws\\]"') as caught:
        get_cloud_source("aws")
    assert "boto3" in str(caught.value)


@pytest.mark.skipif(importlib.util.find_spec("boto3") is not None, reason="boto3 is installed")
def test_boto3_is_absent_here_and_the_plain_call_says_so():
    with pytest.raises(RuntimeError, match='pip install "php-radar\\[aws\\]"'):
        get_cloud_source("aws")


class FakeBoto3:
    """Stands in for the boto3 module: Session() hands back the session it was given."""

    def __init__(self, session=None, error=None):
        self.session, self.error, self.opened = session, error, []

    def Session(self, *args, **kwargs):
        self.opened.append((args, kwargs))
        if self.error is not None:
            raise self.error
        return self.session


def test_an_injected_boto3_gives_a_source_over_a_session_made_with_no_arguments(fake_session):
    fake_session.stub_beanstalk_php("8.3", ENV_ARN)
    sdk = FakeBoto3(fake_session)
    source = get_cloud_source("aws", _boto3=sdk)
    assert isinstance(source, AwsSource)
    # A session built with no arguments reads credentials only from boto3's default chain.
    assert sdk.opened == [((), {})]
    assert [e.signals["resource"] for e in source.inventory()] == [ENV_ARN]


def test_a_boto3_that_imports_is_used_when_nothing_is_injected(fake_session, monkeypatch):
    sdk = FakeBoto3(fake_session)
    monkeypatch.setitem(sys.modules, "boto3", sdk)
    source = get_cloud_source("aws")
    assert isinstance(source, AwsSource)
    assert sdk.opened == [((), {})]


def test_none_still_means_not_installed_when_a_boto3_could_be_imported(fake_session, monkeypatch):
    monkeypatch.setitem(sys.modules, "boto3", FakeBoto3(fake_session))
    with pytest.raises(RuntimeError, match='pip install "php-radar\\[aws\\]"'):
        get_cloud_source("aws", _boto3=None)


def test_a_session_that_cannot_start_is_a_runtime_error_without_its_message():
    sdk = FakeBoto3(error=ProfileNotFound(f"The config profile ({SECRET}) could not be found"))
    with pytest.raises(RuntimeError) as caught:
        get_cloud_source("aws", _boto3=sdk)
    assert "ProfileNotFound" in str(caught.value)
    assert SECRET not in str(caught.value)


def test_an_unknown_provider_is_refused_and_the_known_ones_are_named():
    with pytest.raises(ValueError, match="aws, gcp, azure"):
        get_cloud_source("bogus")


def test_the_source_satisfies_the_protocol(fake_session):
    assert isinstance(AwsSource(fake_session), CloudSource)
    assert not isinstance(object(), CloudSource)


def test_importing_the_package_does_not_import_boto3():
    code = ("import sys\n"
            "import php_radar.sources.cloud, php_radar.sources.cloud.aws\n"
            "bad = [m for m in sys.modules if m.split('.')[0] in ('boto3', 'botocore')]\n"
            "assert not bad, bad\n")
    done = subprocess.run([sys.executable, "-c", code], cwd=str(ROOT), capture_output=True,
                          text=True, timeout=60)
    assert done.returncode == 0, done.stderr


# --- a Beanstalk environment ---

def test_an_environment_carries_its_arn_dns_name_and_php_branch(fake_session):
    fake_session.stub_beanstalk_php("8.3", ENV_ARN)
    ev = only(fake_session)
    assert ev.source is Source.CLOUD
    assert ev.location == ENV_ARN
    assert ev.detected_version == "8.3"
    assert ev.sapi is Sapi.UNKNOWN
    assert ev.signals == {
        "resource": ENV_ARN, "hostname": CNAME, "service": "elasticbeanstalk",
        "php_present": "true", "platform": "PHP 8.3 running on 64bit Amazon Linux 2023/4.3.0"}
    assert ev.note == ("platform PHP 8.3 running on 64bit Amazon Linux 2023/4.3.0 names only the "
                       "PHP branch, so the build is not read")


def test_inventory_can_run_twice_and_gives_the_same_answer(fake_session):
    stubbed_everything(fake_session)
    source = AwsSource(fake_session)
    assert source.inventory() == source.inventory()


# (field, value, branch). The value of a PlatformArn row is the name after platform/.
PLATFORMS = [
    ("PlatformArn", "PHP 8.3 running on 64bit Amazon Linux 2023/4.3.0", "8.3"),
    ("PlatformArn", "PHP 7.4 running on 64bit Amazon Linux 2/3.5.1", "7.4"),
    ("PlatformArn", "PHP 5.6 running on 64bit Amazon Linux/2.9.9", "5.6"),
    ("SolutionStackName", "64bit Amazon Linux 2018.03 v2.9.17 running PHP 7.3", "7.3"),
    ("SolutionStackName", "64bit Amazon Linux 2 v3.3.1 running PHP 8.0", "8.0"),
    # A platform's own version is no PHP version, whatever it looks like.
    ("PlatformArn", "PHP 8.2 running on 64bit Amazon Linux 2023/8.1.2", "8.2"),
    ("PlatformArn", "php 8.4 running on 64bit Amazon Linux 2023/4.5.0", "8.4"),
    ("PlatformArn", "PHP 08.3 running on x/1.0.0", "8.3"),
    ("PlatformArn", "PHP 9.0 running on x/1.0.0", "9.0"),
]

NOT_PHP_PLATFORMS = [
    ("PlatformArn", "Docker running on 64bit Amazon Linux 2023/4.2.0"),
    ("PlatformArn", "Node.js 20 running on 64bit Amazon Linux 2023/6.1.0"),
    ("PlatformArn", "Python 3.12 running on 64bit Amazon Linux 2023/4.0.0"),
    ("PlatformArn", "Tomcat 9 with Corretto 11 running on 64bit Amazon Linux 2/4.3.0"),
    ("PlatformArn", "MyPHPPlatform/1.0.0"),
    ("SolutionStackName", "64bit Amazon Linux 2023 v4.3.0 running Ruby 3.3"),
    # PHP named without a number, or with one that is no PHP branch.
    ("PlatformArn", "PHP running on 64bit Amazon Linux 2023/4.3.0"),
    ("PlatformArn", "PHP 8 running on 64bit Amazon Linux 2023/4.3.0"),
    ("PlatformArn", "PHP 4.4 running on x/1.0.0"),
    ("PlatformArn", "PHP 10.0 running on x/1.0.0"),
    ("PlatformArn", "PHP 1.4 running on x/1.0.0"),
    ("PlatformArn", "PHP 8.3, running on x/1.0.0"),
    ("PlatformArn", 42),
    ("PlatformArn", None),
]


def platform_record(field, value):
    if field == "PlatformArn" and isinstance(value, str):
        value = PLATFORM + value
    return {field: value}


@pytest.mark.parametrize("field,value,branch", PLATFORMS)
def test_a_php_platform_gives_its_branch_never_the_platform_version(
        fake_session, field, value, branch):
    fake_session.stub_environment(ENV_ARN, **platform_record(field, value))
    assert only(fake_session).detected_version == branch


@pytest.mark.parametrize("field,value", NOT_PHP_PLATFORMS)
def test_an_environment_whose_platform_is_not_php_leaves_no_evidence(
        fake_session, field, value):
    fake_session.stub_environment(ENV_ARN, **platform_record(field, value))
    assert inventory(fake_session) == []


def test_a_custom_platform_arn_is_read_like_the_others(fake_session):
    arn = f"arn:aws:elasticbeanstalk:us-east-1:{ACCOUNT}:platform/PHP 8.3 custom/1.0.0"
    fake_session.stub_environment(ENV_ARN, PlatformArn=arn)
    assert only(fake_session).detected_version == "8.3"


@pytest.mark.parametrize("name,kept", [
    ("PHP 8.3 running on " + "x" * (256 - len("PHP 8.3 running on ")), True),
    ("PHP 8.3 running on " + "x" * (257 - len("PHP 8.3 running on ")), False),
    ("PHP 8.3 running on caf" + E_ACUTE, False),
    ("PHP 8.3 running on a\nb", False),
])
def test_a_platform_name_is_a_signal_only_when_short_printable_ascii(fake_session, name, kept):
    fake_session.stub_environment(ENV_ARN, SolutionStackName=name)
    ev = only(fake_session)
    assert ev.detected_version == "8.3"
    assert ("platform" in ev.signals) is kept
    # The note names the platform when the signal does, and says "the platform" when it does not.
    assert ev.note.startswith("platform PHP 8.3 running on") is kept
    assert ev.note.endswith("names only the PHP branch, so the build is not read")
    assert (name in ev.note) is kept


def test_a_platform_that_names_a_patch_release_is_graded_on_it(fake_session):
    stack = "64bit Amazon Linux 2023 v4.3.0 running PHP 8.3.12"
    fake_session.stub_environment(ENV_ARN, SolutionStackName=stack)
    ev = only(fake_session)
    assert (ev.detected_version, ev.note) == ("8.3.12", "")
    assert grade_evidence(ev, MATRIX)[0] is Verdict.EXPOSED


@pytest.mark.parametrize("status", ["Ready", "Launching", "Updating", "Terminating", None])
def test_an_environment_in_any_state_but_terminated_is_read(fake_session, status):
    fake_session.stub_beanstalk_php("8.3", ENV_ARN, Status=status)
    assert len(inventory(fake_session)) == 1


def test_a_terminated_environment_runs_nothing(fake_session):
    fake_session.stub_beanstalk_php("8.3", ENV_ARN, Status="Terminated")
    assert inventory(fake_session) == []


def test_the_platform_arn_is_tried_before_the_solution_stack(fake_session):
    fake_session.stub_environment(
        ENV_ARN, PlatformArn=PLATFORM + "PHP 8.3 running on x/1.0.0",
        SolutionStackName="64bit Amazon Linux 2018.03 v2.9.17 running PHP 7.3")
    assert only(fake_session).detected_version == "8.3"


def test_the_solution_stack_is_read_when_the_platform_arn_names_no_php(fake_session):
    fake_session.stub_environment(
        ENV_ARN, PlatformArn=PLATFORM + "Docker running on x/1.0.0",
        SolutionStackName="64bit Amazon Linux 2018.03 v2.9.17 running PHP 7.3")
    assert only(fake_session).detected_version == "7.3"


ELB = "awseb-e-x-AWSEBLoa-1.us-east-1.elb.amazonaws.com"


@pytest.mark.parametrize("fields,expected", [
    ({"CNAME": CNAME}, {"hostname": CNAME}),
    ({"CNAME": CNAME, "EndpointURL": ELB}, {"hostname": CNAME}),
    # No CNAME: the load balancer's name stands in, and a bare address goes in ip.
    ({"EndpointURL": ELB}, {"hostname": ELB}),
    ({"CNAME": "", "EndpointURL": "54.1.2.3"}, {"ip": "54.1.2.3"}),
    ({"EndpointURL": "54.1.2.3"}, {"ip": "54.1.2.3"}),
    # A value that is no DNS name is left out, and the next one is tried.
    ({"CNAME": "http://evil.example/x", "EndpointURL": "lb.example.com"},
     {"hostname": "lb.example.com"}),
    ({"CNAME": "a b.example.com"}, {}),
    ({"CNAME": ".example.com"}, {}),
    ({"CNAME": "-x.example.com"}, {}),
    ({"CNAME": "a" * 253}, {"hostname": "a" * 253}),
    ({"CNAME": "a" * 254}, {}),
    ({"CNAME": "x" * 300}, {}),
    ({"CNAME": "caf" + E_ACUTE + ".example.com"}, {}),
    ({"CNAME": "ok.example.com\nINJECTED"}, {}),
    ({"CNAME": 7, "EndpointURL": ["x"]}, {}),
    ({}, {}),
])
def test_the_environments_dns_name_goes_in_hostname_when_it_is_one(
        fake_session, fields, expected):
    fake_session.stub_beanstalk_php("8.3", ENV_ARN, cname=None, **fields)
    ev = only(fake_session)
    assert {k: v for k, v in ev.signals.items() if k in ("hostname", "ip")} == expected
    assert ev.signals["resource"] == ENV_ARN


def test_a_host_read_of_the_same_dns_name_merges_with_the_environment(fake_session):
    # The name differs in case and in a trailing dot. The model folds both.
    fake_session.stub_beanstalk_php(
        "8.3", ENV_ARN, cname="Shop-Prod.EBA-abc123xy.us-east-1.elasticbeanstalk.com.")
    host = Evidence(Source.HOST, "shop-prod", "8.3.36", Sapi.FPM,
                    {"hostname": CNAME, "php_present": "true"}, "")
    inv = AssetInventory()
    for ev in inventory(fake_session) + [host]:
        inv.add(ev)
    (asset,) = inv.assets()
    assert len(asset.evidence) == 2
    assert asset.kind == "host"
    assert asset.key == ENV_ARN


def test_an_environment_under_an_application_name_with_spaces_is_read(fake_session):
    fake_session.stub_beanstalk_php("8.3", SPACED_ARN)
    ev = only(fake_session)
    assert ev.location == SPACED_ARN
    assert ev.signals["resource"] == SPACED_ARN
    assert ev.detected_version == "8.3"
    assert grade_evidence(ev, MATRIX) == (Verdict.INDETERMINATE, Confidence.MEDIUM)
    inv = AssetInventory()
    inv.add(ev)
    (asset,) = inv.assets()
    assert asset.key == SPACED_ARN


def test_an_environment_with_spaces_in_its_arn_grades_on_its_patch_release(fake_session):
    stack = "64bit Amazon Linux 2023 v4.13.12 running PHP 8.3.35"
    fake_session.stub_environment(SPACED_ARN, SolutionStackName=stack)
    assert grade_evidence(only(fake_session), MATRIX)[0] is Verdict.EXPOSED


def test_the_report_prints_an_arn_with_spaces_whole(fake_session):
    fake_session.stub_beanstalk_php("8.3", SPACED_ARN)
    for out in rendered(inventory(fake_session)):
        assert SPACED_ARN in out


SPACED_ODD = [
    SPACED_ARN.replace("First", "F" + E_ACUTE + "rst"),  # a non-ASCII application name
    SPACED_ARN.replace("First", "First\n"),
    SPACED_ARN.replace("First", "First\t"),
    SPACED_ARN.replace("First", "First" + chr(0)),
    "ARN:" + SPACED_ARN[4:],
    "My First Elastic Beanstalk Application",
    "arn:" + "a b" * 1000,
]


@pytest.mark.parametrize("arn", SPACED_ODD)
def test_a_beanstalk_arn_may_hold_spaces_and_still_has_to_be_printable_ascii(fake_session, arn):
    fake_session.stub_beanstalk_php("8.3", arn)
    gap = only(fake_session)
    assert gap.note == ("not inventoried: 1 entry in the list of environments could not be read "
                        "(no usable ARN)")


def test_two_environments_stay_two_assets(fake_session):
    other = f"arn:aws:elasticbeanstalk:us-east-1:{ACCOUNT}:environment/shop/shop-stage"
    fake_session.stub_beanstalk_php("8.3", ENV_ARN)
    fake_session.stub_beanstalk_php(
        "8.3", other, cname="shop-stage.eba-abc123xy.us-east-1.elasticbeanstalk.com")
    inv = AssetInventory()
    for ev in inventory(fake_session):
        inv.add(ev)
    assert len(inv.assets()) == 2


# --- a Lambda function ---

def test_a_function_with_a_php_layer_runs_php_and_the_build_is_unknown(fake_session):
    fake_session.stub_lambda("legacy-api", layers=[BREF_FPM])
    ev = only(fake_session)
    assert ev.source is Source.CLOUD
    assert ev.location == FN_ARN
    assert ev.detected_version is None
    assert ev.sapi is Sapi.UNKNOWN
    assert ev.signals == {"resource": FN_ARN, "service": "lambda", "php_present": "true"}
    assert ev.note == "layer php-83-fpm marks a PHP runtime, and the build is not read"


@pytest.mark.parametrize("layer,php", [
    ("php-83", True), ("php-83-fpm", True), ("php83", True), ("php_83", True), ("PHP-74", True),
    ("php", True), ("php8", True), ("my-php-runtime", True), ("amqp-php-83", True),
    ("phpunit", False), ("phpmyadmin", False), ("phplayer", False), ("composer", False),
    ("node-modules", False), ("xphp-83", False), ("bref-extra", False),
])
def test_a_layer_marks_php_by_a_word_of_its_name(fake_session, layer, php):
    fake_session.stub_lambda("fn", layers=[f"{LAYER}{layer}:3"])
    assert bool(inventory(fake_session)) is php


def test_a_layer_arn_with_no_version_still_names_the_layer(fake_session):
    fake_session.stub_lambda("fn", layers=[LAYER + "php-82"])
    assert "layer php-82 marks" in only(fake_session).note


def test_the_first_php_layer_is_the_one_named(fake_session):
    fake_session.stub_lambda("fn", layers=[
        "arn:aws:lambda:us-east-1:1:layer:logging:1", "arn:aws:lambda:us-east-1:1:layer:php-84:2",
        "arn:aws:lambda:us-east-1:1:layer:php-84-fpm:2"])
    assert only(fake_session).note.startswith("layer php-84 marks")


@pytest.mark.parametrize("layers", [
    None, [], "php-83", 7, [None], ["php-83"], [{"Arn": None}],
    [{"Arn": "arn:aws:lambda:us-east-1:1:layer"}],
    [{"Arn": "arn:aws:s3:::php-83"}],
    [{"Arn": "arn:aws:lambda:us-east-1:1:function:php-83:1"}],
    [{"Arn": "arn:aws:ec2:us-east-1:1:layer:php-83:1"}],
    [{"Arn": "arn:aws:lambda:us-east-1:1:layer:php-83 x:1"}],
    [{"Arn": "arn:aws:lambda:us-east-1:1:layer:ph" + O_ACUTE + "p-83:1"}],
    [{"Arn": "arn:aws:lambda:us-east-1:1:layer:" + "php-" * 100 + ":1"}],
])
def test_a_layer_list_that_names_no_php_layer_leaves_no_evidence(fake_session, layers):
    fake_session.stub_lambda("fn", Layers=layers)
    assert inventory(fake_session) == []


def test_a_runtime_that_names_php_counts_though_aws_offers_none(fake_session):
    fake_session.stub_lambda("fn", runtime="php8.3")
    ev = only(fake_session)
    assert ev.note == "runtime php8.3 names PHP, and the build is not read"
    assert ev.detected_version is None


@pytest.mark.parametrize("runtime", [
    "provided.al2", "provided.al2023", "python3.12", "nodejs20.x", None, 5, "x-php8.3", "nophp"])
def test_a_runtime_that_does_not_name_php_counts_for_nothing(fake_session, runtime):
    fake_session.stub_lambda("fn", runtime=runtime)
    assert inventory(fake_session) == []


# --- an ECR repository ---

def tags_read(session, repo, *tags):
    session.stub_repository(repo, tags)
    return inventory(session)


def test_an_image_tag_in_the_php_repository_gives_its_version_and_sapi(fake_session):
    ev = only_one(tags_read(fake_session, "php", "8.3.12-fpm"))
    assert ev.source is Source.CLOUD
    assert ev.location == REPO_URI + ":8.3.12-fpm"
    assert ev.detected_version == "8.3.12"
    assert ev.sapi is Sapi.FPM
    assert ev.signals == {"resource": REPO_ARN, "service": "ecr", "php_present": "true"}
    assert ev.note == "version read from the image tag"


# (repository, tag, version it names or None, SAPI)
TAGS = [
    # The official image's tags, in a repository called php.
    ("php", "8.3.12", "8.3.12", Sapi.UNKNOWN),
    ("php", "8.3.12-fpm", "8.3.12", Sapi.FPM),
    ("php", "8.3.12-apache", "8.3.12", Sapi.MOD_PHP),
    ("php", "8.3.12-cli-alpine3.20", "8.3.12", Sapi.CLI),
    ("php", "8.3.12-fpm-alpine", "8.3.12", Sapi.FPM),
    ("php", "8.2.35-zts-bookworm", "8.2.35", Sapi.CLI),
    ("php", "5.6.40-apache", "5.6.40", Sapi.MOD_PHP),
    ("php", "9.0.1", "9.0.1", Sapi.UNKNOWN),
    ("php", "4.4.9", None, None),
    ("php", "8.3", "8.3", Sapi.UNKNOWN),
    ("php", "8.3-fpm", "8.3", Sapi.FPM),
    ("docker-hub/library/php", "8.4.2-cli", "8.4.2", Sapi.CLI),
    ("mirror/php", "8.3.12-fpm", "8.3.12", Sapi.FPM),
    # A tag with no version, or one that is no PHP version.
    ("php", "latest", None, None),
    ("php", "fpm", None, None),
    ("php", "8-fpm", None, None),
    ("php", "8", None, None),
    ("php", "8.3.12RC1", None, None),
    ("php", "8.3.12.1", None, None),
    ("php", "main", None, None),
    # An app's own version in a repository called php is no PHP version.
    ("php", "1.4.2", None, None),
    ("php", "2.0", None, None),
    ("php", "2024.10.1", None, None),
    ("php", "10.1.2", None, None),
    # A full number counts unless what follows it reads as a distro revision, which is the
    # grader's own test. Then the tag gives the branch alone.
    ("php", "8.3.12-1ubuntu2.28", "8.3", Sapi.UNKNOWN),
    ("php", "8.3.12-20240101", "8.3", Sapi.UNKNOWN),
    ("php", "8.3.12-1deb12u1", "8.3", Sapi.UNKNOWN),
    ("php", "8.3.12-r1", "8.3", Sapi.UNKNOWN),
    ("php", "8.3.36-rc1", "8.3", Sapi.UNKNOWN),
    ("php", "8.3.36-dev", "8.3", Sapi.UNKNOWN),
    ("php", "8.3.12-fpm-prod", "8.3.12", Sapi.FPM),
    ("php", "8.3.12-v2", "8.3.12", Sapi.UNKNOWN),
    # Elsewhere a tag has to say php.
    ("shop", "php8.3", "8.3", Sapi.UNKNOWN),
    ("shop", "php8.3.12", "8.3.12", Sapi.UNKNOWN),
    ("shop", "php8.3.12-fpm", "8.3.12", Sapi.FPM),
    ("shop", "php-8.3.12", "8.3.12", Sapi.UNKNOWN),
    ("shop", "php-8.3-apache", "8.3", Sapi.MOD_PHP),
    ("shop", "PHP-8.3.12-FPM", "8.3.12", Sapi.FPM),
    ("shop", "php_8.3.12", "8.3.12", Sapi.UNKNOWN),
    ("shop", "PHP-8.3.12", "8.3.12", Sapi.UNKNOWN),
    ("shop", "bookworm-php8.3.12", "8.3.12", Sapi.UNKNOWN),
    ("shop", "app-php8.2-1.4.0", "8.2", Sapi.UNKNOWN),
    ("shop", "php8.3.12-1.4.0", "8.3", Sapi.UNKNOWN),
    ("shop", "php-8.3.12-r1", "8.3", Sapi.UNKNOWN),
    ("shop", "php7.4.33-fpm-v2", "7.4.33", Sapi.FPM),
    ("shop", "phpunit-php8.3", "8.3", Sapi.UNKNOWN),
    ("shop", "phpunit-9.5.1", None, None),
    ("shop", "1.2.3", None, None),
    ("shop", "8.3.12-fpm", None, None),
    ("shop", "latest", None, None),
    ("shop", "php-fpm", None, None),
    ("shop", "php", None, None),
    ("shop", "php83", None, None),
    ("shop", "php7", None, None),
    ("shop", "php-fpm-8.3.12", None, None),
    ("shop", "myphp8.3", None, None),
    ("shop", "php1.4", None, None),
    # A repository only counts as the official one when php is its last path part.
    ("php-app", "8.3.12-fpm", None, None),
    ("phpmyadmin", "5.2.1", None, None),
    ("myphp", "8.3.12", None, None),
    ("php/app", "8.3.12", None, None),
]


@pytest.mark.parametrize("repo,tag,version,sapi", TAGS, ids=[f"{r}:{t}" for r, t, _, _ in TAGS])
def test_an_image_tag_names_a_php_version_or_it_does_not(fake_session, repo, tag, version, sapi):
    evs = tags_read(fake_session, repo, tag)
    if version is None:
        assert evs == []
    else:
        ev = only_one(evs)
        assert ev.detected_version == version
        assert ev.sapi is sapi
        assert ev.location.endswith(":" + tag)


def test_a_branch_tag_says_the_build_is_unread(fake_session):
    ev = only_one(tags_read(fake_session, "php", "8.3-fpm"))
    assert ev.note == "the tag names only the PHP branch, so the build is not read"


def test_every_tag_of_a_repository_carries_its_arn_and_folds_into_one_asset(fake_session):
    evs = tags_read(fake_session, "php", "7.4.33-fpm", "8.3.36-fpm", "8.3.36-apache", "latest")
    assert {e.signals["resource"] for e in evs} == {REPO_ARN}
    assert len(evs) == 3
    inv = AssetInventory()
    for ev in evs:
        inv.add(ev)
    (asset,) = inv.assets()
    assert len(asset.evidence) == 3
    assert asset.key == REPO_ARN
    assert grade(asset, MATRIX)[0] is Verdict.EXPOSED


def test_repositories_with_no_php_tag_leave_nothing(fake_session):
    fake_session.stub_repository("web", ["1.0.0", "latest", "main-abc123"])
    fake_session.stub_repository("empty", [])
    assert inventory(fake_session) == []


# --- how the grader reads what the source writes ---

@pytest.mark.parametrize("repo,tag,verdict,confidence", [
    ("php", "8.3.36-fpm", Verdict.LIKELY_PATCHED, Confidence.HIGH),
    ("php", "8.3.35-fpm", Verdict.EXPOSED, Confidence.HIGH),
    ("php", "7.4.33-cli", Verdict.EXPOSED, Confidence.HIGH),
    ("php", "8.3-fpm", Verdict.INDETERMINATE, Confidence.MEDIUM),
    ("php", "8.3.12-1ubuntu2.28", Verdict.INDETERMINATE, Confidence.MEDIUM),
])
def test_ecr_evidence_grades_as_the_version_it_names(
        fake_session, repo, tag, verdict, confidence):
    ev = only_one(tags_read(fake_session, repo, tag))
    assert grade_evidence(ev, MATRIX) == (verdict, confidence)


def test_a_beanstalk_branch_grades_indeterminate_and_never_a_verdict_on_a_guess(fake_session):
    for branch in ("8.3", "7.4"):
        fake_session.stub_beanstalk_php(branch, ENV_ARN + branch, cname=None)
    for ev in inventory(fake_session):
        assert grade_evidence(ev, MATRIX) == (Verdict.INDETERMINATE, Confidence.MEDIUM)


def test_a_lambda_function_with_a_php_layer_grades_indeterminate(fake_session):
    fake_session.stub_lambda("fn", layers=[BREF_FPM])
    assert grade_evidence(only(fake_session), MATRIX) == (Verdict.INDETERMINATE, Confidence.MEDIUM)


# --- pages ---

def test_every_page_of_every_listing_is_read(fake_session):
    fake_session.page = 2
    arns = [f"{ENV_ARN}-{i}" for i in range(5)]
    for i, arn in enumerate(arns):
        fake_session.stub_beanstalk_php("8.3", arn, cname=f"env{i}.example.com")
    for i in range(5):
        fake_session.stub_lambda(f"fn{i}", layers=[BREF_FPM])
    for i in range(5):
        fake_session.stub_repository(f"r{i}", [f"php8.{n}" for n in range(1, 6)])
    evs = inventory(fake_session)
    resources = [e.signals["resource"] for e in evs]
    assert {a for a in resources if "environment" in a} == set(arns)
    assert len({a for a in resources if ":function:" in a}) == 5
    assert len([e for e in evs if e.signals["service"] == "ecr"]) == 25
    assert {r for r in resources if ":repository/" in r} == {
        f"arn:aws:ecr:us-east-1:{ACCOUNT}:repository/r{i}" for i in range(5)}


def test_each_call_asks_for_the_next_page_with_the_parameter_the_service_names(fake_session):
    fake_session.page = 1
    fake_session.stub_beanstalk_php("8.3", ENV_ARN + "1", cname=None)
    fake_session.stub_beanstalk_php("8.3", ENV_ARN + "2", cname=None)
    fake_session.stub_lambda("a", layers=[BREF_FPM])
    fake_session.stub_lambda("b", layers=[BREF_FPM])
    fake_session.stub_repository("php", ["8.3.1", "8.3.2"])
    inventory(fake_session)
    by_op = {}
    for call in fake_session.calls:
        by_op.setdefault(call.operation, []).append(set(call.kwargs))
    first = {"repositoryName", "filter", "maxResults"}
    assert by_op["describe_environments"] == [set(), {"NextToken"}]
    assert by_op["list_functions"] == [set(), {"Marker"}]
    assert by_op["describe_repositories"] == [{"maxResults"}]
    assert by_op["list_images"] == [first, first | {"nextToken"}]
    # ECR takes up to 1000 to a page, and the source asks for all of them.
    sizes = {c.kwargs["maxResults"] for c in fake_session.calls if "maxResults" in c.kwargs}
    assert sizes == {1000}


def test_a_listing_that_never_ends_is_cut_and_says_so(fake_session):
    fn = fake_session.stub_lambda("fn", layers=[BREF_FPM])
    page = {"Functions": [fn], "NextMarker": "again", "ResponseMetadata": META}
    fake_session.script("list_functions", itertools.repeat(page))
    evs = inventory(fake_session)
    calls = [c for c in fake_session.calls if c.operation == "list_functions"]
    assert len(calls) == aws._MAX_PAGES
    *found, gap = evs
    assert len(found) == aws._MAX_PAGES
    assert gap.note == f"not inventoried: the list runs past {aws._MAX_PAGES} pages"
    assert gap.location == "aws lambda us-east-1"


# --- what goes wrong ---

SERVICES = [("elasticbeanstalk", "describe_environments"), ("lambda", "list_functions"),
            ("ecr", "describe_repositories")]


@pytest.mark.parametrize("service,operation", SERVICES)
def test_a_failed_listing_is_a_row_and_the_other_services_still_read(
        fake_session, service, operation):
    stubbed_everything(fake_session)
    fake_session.fail(service, ClientError("AccessDeniedException", f"User {SECRET} may not"),
                      operation)
    evs = inventory(fake_session)
    gaps = [e for e in evs if e.note.startswith("not inventoried")]
    assert len(gaps) == 1
    gap = gaps[0]
    assert gap.source is Source.CLOUD
    assert gap.location == f"aws {service} us-east-1"
    assert gap.detected_version is None
    assert gap.sapi is Sapi.UNKNOWN
    assert gap.signals == {"service": service, "kind": "skipped"}
    assert gap.note == "not inventoried: ClientError (AccessDeniedException)"
    assert {e.signals["service"] for e in evs} == {"elasticbeanstalk", "lambda", "ecr"}
    assert len([e for e in evs if e is not gap]) == 2
    assert SECRET not in text_of(evs)


def test_a_gap_row_grades_indeterminate_at_low_confidence(fake_session):
    stubbed_everything(fake_session)
    fake_session.fail("lambda", ClientError("AccessDeniedException"), "list_functions")
    gap = next(e for e in inventory(fake_session) if e.signals.get("kind") == "skipped")
    assert grade_evidence(gap, MATRIX) == (Verdict.INDETERMINATE, Confidence.LOW)
    inv = AssetInventory()
    inv.add(gap)
    (asset,) = inv.assets()
    assert grade(asset, MATRIX) == (Verdict.INDETERMINATE, Confidence.LOW)


@pytest.mark.parametrize("exc,why", [
    (ClientError("AccessDeniedException"), "ClientError (AccessDeniedException)"),
    (ClientError("UnrecognizedClientException"), "ClientError (UnrecognizedClientException)"),
    (ClientError("ThrottlingException"), "ClientError (ThrottlingException)"),
    (ClientError("ExpiredToken"), "ClientError (ExpiredToken)"),
    (ClientError("bad code with spaces"), "ClientError"),
    (ClientError("c" * 64), "ClientError (" + "c" * 64 + ")"),
    (ClientError("c" * 65), "ClientError"),
    (ClientError("x" * 200), "ClientError"),
    (ClientError(None), "ClientError"),
    (NoCredentialsError("Unable to locate credentials"),
     "no AWS credentials were found (NoCredentialsError)"),
    (NoRegionError("You must specify a region."), "no AWS region is configured (NoRegionError)"),
    (EndpointConnectionError(f"Could not connect to https://{SECRET}.example"),
     "EndpointConnectionError"),
    (ValueError(SECRET), "ValueError"),
    (OSError(SECRET), "OSError"),
])
def test_a_failure_is_recorded_by_class_and_code_and_never_by_message(fake_session, exc, why):
    fake_session.stub_lambda("fn", layers=[BREF_FPM])
    fake_session.fail("lambda", exc)
    gap = only(fake_session)
    assert gap.note == "not inventoried: " + why
    assert SECRET not in text_of(gap)


def test_a_modeled_error_whose_class_is_its_code_is_named_once(fake_session):
    class ThrottlingException(Exception):
        response = {"Error": {"Code": "ThrottlingException"}}

    fake_session.fail("lambda", ThrottlingException(SECRET))
    assert only(fake_session).note == "not inventoried: ThrottlingException"


def test_an_error_whose_response_is_odd_still_records_its_class(fake_session):
    class Odd(Exception):
        response = "not a dict"

    fake_session.fail("lambda", Odd(SECRET))
    assert only(fake_session).note == "not inventoried: Odd"


def test_a_client_that_cannot_be_made_is_a_row_for_its_service_alone(fake_session):
    stubbed_everything(fake_session)
    fake_session.fail_client("lambda", NoRegionError(SECRET))
    evs = inventory(fake_session)
    gap = next(e for e in evs if e.signals.get("kind") == "skipped")
    assert gap.signals["service"] == "lambda"
    assert gap.note == "not inventoried: no AWS region is configured (NoRegionError)"
    assert len(evs) == 3
    assert SECRET not in text_of(evs)


def test_a_session_with_no_region_gives_a_row_per_service_named_without_one():
    session = FakeSession(region=None)
    services = ("elasticbeanstalk", "lambda", "ecr")
    for service in services:
        session.fail_client(service, NoRegionError("You must specify a region."))
    source = AwsSource(session)
    assert source.regions == (None,)
    assert [(e.location, e.note) for e in source.inventory()] == [
        (f"aws {service}", "not inventoried: no AWS region is configured (NoRegionError)")
        for service in services]


def test_pages_read_before_a_failure_are_kept_and_the_failure_is_a_row(fake_session):
    fake_session.page = 2
    for i in range(5):
        fake_session.stub_beanstalk_php("8.3", f"{ENV_ARN}-{i}", cname=None)
    fake_session.fail("elasticbeanstalk", ClientError("ThrottlingException"), skip=1)
    *found, gap = inventory(fake_session)
    assert len(found) == 2
    assert gap.note == "not inventoried: ClientError (ThrottlingException)"


def test_a_failing_repository_is_a_row_and_the_others_are_still_read(fake_session):
    for name in ("a", "b", "c"):
        fake_session.stub_repository(name, ["php8.3.36"])
    fake_session.fail_images("b", ClientError("ThrottlingException", SECRET))
    evs = inventory(fake_session)
    (gap,) = [e for e in evs if e.note.startswith("not fully inventoried")]
    assert gap.location == f"{ACCOUNT}.dkr.ecr.us-east-1.amazonaws.com/b"
    assert gap.detected_version is None
    # Nothing in b was read, so nothing says it holds PHP.
    assert gap.signals == {"resource": f"arn:aws:ecr:us-east-1:{ACCOUNT}:repository/b",
                           "service": "ecr", "kind": "skipped"}
    assert gap.note == "not fully inventoried: ClientError (ThrottlingException)"
    assert {e.signals["resource"].rpartition("/")[2] for e in evs if e is not gap} == {"a", "c"}
    assert SECRET not in text_of(evs)


def test_a_repository_read_only_in_part_stays_indeterminate_whatever_it_showed(fake_session):
    fake_session.page = 1
    fake_session.stub_repository("php", ["8.3.36-fpm", "7.4.33-fpm", "8.2.35-fpm"])
    fake_session.fail_images("php", ClientError("ThrottlingException"), skip=1)
    seen, gap = inventory(fake_session)
    assert grade_evidence(seen, MATRIX)[0] is Verdict.LIKELY_PATCHED
    assert gap.signals == {"resource": REPO_ARN, "service": "ecr", "kind": "skipped",
                           "php_present": "true"}
    inv = AssetInventory()
    for ev in (seen, gap):
        inv.add(ev)
    (asset,) = inv.assets()
    assert grade(asset, MATRIX)[0] is Verdict.INDETERMINATE


def test_a_repository_read_in_full_with_no_failure_is_not_held_back(fake_session):
    fake_session.stub_repository("php", ["8.3.36-fpm", "8.2.35-fpm"])
    inv = AssetInventory()
    for ev in inventory(fake_session):
        inv.add(ev)
    (asset,) = inv.assets()
    assert grade(asset, MATRIX)[0] is Verdict.LIKELY_PATCHED


def test_the_ecr_read_stops_after_repositories_fail_in_a_row(fake_session):
    for i in range(6):
        fake_session.stub_repository(f"r{i}", ["php8.3.36"])
        fake_session.fail_images(f"r{i}", ClientError("ThrottlingException"))
    evs = inventory(fake_session)
    asked = [c.kwargs["repositoryName"] for c in fake_session.calls
             if c.operation == "list_images"]
    assert asked == [f"r{i}" for i in range(aws._MAX_MISSES)]
    *repos, stop = evs
    assert len(repos) == aws._MAX_MISSES
    assert stop.location == "aws ecr us-east-1"
    assert stop.signals == {"service": "ecr", "kind": "skipped"}
    assert stop.note == (
        f"not inventoried: {aws._MAX_MISSES} repositories in a row could not be read")


def test_a_repository_that_reads_ends_the_run_of_failures(fake_session):
    names = ["a", "b", "c", "d", "e", "f"]
    for name in names:
        fake_session.stub_repository(name, ["php8.3.36"])
    # Two fail, one reads, two fail, one reads. No run reaches the limit.
    for name in ("a", "b", "d", "e"):
        fake_session.fail_images(name, ClientError("ThrottlingException"))
    evs = inventory(fake_session)
    asked = [c.kwargs["repositoryName"] for c in fake_session.calls
             if c.operation == "list_images"]
    assert asked == names
    assert len([e for e in evs if e.note.startswith("not fully")]) == 4
    assert not [e for e in evs if "in a row" in e.note]


@pytest.mark.parametrize("bad", [
    None, 5, "x", [], [{}], {"Functions": "no"}, {"Functions": 5}, {"Functions": {}},
    {"Functions": {"a": 1}}, {"Functions": "[]"}])
def test_an_answer_that_is_not_the_documented_shape_ends_the_listing_with_a_row(
        fake_session, bad):
    fake_session.script("list_functions", [bad])
    gap = only(fake_session)
    assert gap.note == "not inventoried: the answer is not understood"


@pytest.mark.parametrize("operation,key", sorted(_EMPTY.items()))
@pytest.mark.parametrize("empty", ["missing", "null", "list"])
def test_a_list_the_service_leaves_out_or_nulls_is_an_empty_listing(
        fake_session, operation, key, empty):
    # A service is free to leave out a list that is empty, so that is no failure.
    answer = {"ResponseMetadata": META}
    if empty != "missing":
        answer[key] = None if empty == "null" else []
    fake_session.stub_repository("php", [])
    fake_session.script(operation, [answer])
    assert inventory(fake_session) == []


def test_an_empty_continuation_token_ends_the_listing(fake_session):
    fn = fake_session.stub_lambda("fn", layers=[BREF_FPM])
    fake_session.script("list_functions", [{"Functions": [fn], "NextMarker": ""}])
    assert len(inventory(fake_session)) == 1
    assert len([c for c in fake_session.calls if c.operation == "list_functions"]) == 1


@pytest.mark.parametrize("token", [5, ["x"], {"a": 1}])
def test_a_continuation_token_that_is_no_string_ends_the_listing_with_a_row(fake_session, token):
    fn = fake_session.stub_lambda("fn", layers=[BREF_FPM])
    fake_session.script("list_functions", [{"Functions": [fn], "NextMarker": token}])
    found, gap = inventory(fake_session)
    assert found.signals["service"] == "lambda"
    assert gap.note == "not inventoried: the answer is not understood"


# The note of the row that counts the entries of a list that could not be read, with its reason.
FUNCTION_UNREAD = ("not inventoried: 1 entry in the list of functions could not be read "
                   "(no usable ARN)")
REPOSITORY_UNREAD = ("not inventoried: 1 entry in the list of repositories could not be read "
                     "(no usable ARN or name)")
IMAGE_UNREAD = "not inventoried: 1 entry in the list of images could not be read (no usable tag)"


def test_unreadable_entries_are_still_counted_when_the_listing_then_fails(fake_session):
    good = fake_session.stub_lambda("good", layers=[BREF_FPM])
    fake_session.script("list_functions", [{"Functions": [None, good], "NextMarker": "more"},
                                           ClientError("ThrottlingException")])
    found, stop, unread = inventory(fake_session)
    assert found.location == good["FunctionArn"]
    assert stop.note == "not inventoried: ClientError (ThrottlingException)"
    assert unread.note == FUNCTION_UNREAD


FN_ODD = [
    None, 42, "arn:aws:lambda:x", [], {}, {"FunctionName": "x"}, {"FunctionArn": ""},
    {"FunctionArn": 42}, {"FunctionArn": "not-an-arn"}, {"FunctionArn": "ARN:aws:lambda:x"},
    {"FunctionArn": "arn"}, {"FunctionArn": "arn-aws-lambda"},
    {"FunctionArn": "arn:aws:lambda:x y"}, {"FunctionArn": "arn:aws:lambda:x\nINJECTED"},
    {"FunctionArn": f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:my function"},
    {"FunctionArn": "arn:aws:lambda:caf" + E_ACUTE}, {"FunctionArn": "arn:" + "a" * 3000},
]


@pytest.mark.parametrize("entry", FN_ODD)
def test_an_entry_with_no_usable_arn_is_counted_and_never_emitted(fake_session, entry):
    good = fake_session.stub_lambda("good", layers=[BREF_FPM])
    if isinstance(entry, dict):
        entry = dict(entry, Layers=[{"Arn": BREF_FPM}])
    fake_session.script("list_functions", [{"Functions": [entry, good]}])
    found, gap = inventory(fake_session)
    assert found.location == good["FunctionArn"]
    assert gap.note == FUNCTION_UNREAD


def test_an_arn_of_the_longest_allowed_length_reads_and_one_longer_does_not(fake_session):
    prefix = f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:"
    ok = prefix + "f" * (2048 - len(prefix))
    layers = [{"Arn": BREF_FPM}]
    fake_session.script("list_functions", [{"Functions": [
        {"FunctionArn": ok + "f", "Layers": layers}, {"FunctionArn": ok, "Layers": layers}]}])
    found, gap = inventory(fake_session)
    assert found.location == ok and len(ok) == 2048
    assert gap.note == FUNCTION_UNREAD


def test_a_tag_of_128_characters_reads_and_one_of_129_does_not(fake_session):
    ok = "php8.3-" + "a" * 121
    assert len(ok) == 128
    fake_session.stub_repository("shop", [])
    fake_session.script("list_images", [{"imageIds": [{"imageTag": ok + "a"}, {"imageTag": ok}]}])
    found, gap = inventory(fake_session)
    assert found.detected_version == "8.3"
    assert gap.note == IMAGE_UNREAD


def test_the_count_of_unreadable_entries_is_plural_when_it_should_be(fake_session):
    fake_session.script("describe_environments",
                        [{"Environments": [None, 5, {"EnvironmentArn": ""}]}])
    fake_session.script("describe_repositories",
                        [{"repositories": [None, {"repositoryArn": ENV_ARN}]}])
    gaps = {e.signals["service"]: e.note for e in inventory(fake_session)}
    assert gaps == {
        "elasticbeanstalk": ("not inventoried: 3 entries in the list of environments could not "
                             "be read (no usable ARN)"),
        "ecr": ("not inventoried: 2 entries in the list of repositories could not be read "
                "(no usable ARN or name)")}


@pytest.mark.parametrize("record", [
    {"repositoryArn": REPO_ARN, "repositoryName": "Php Bad"},
    {"repositoryArn": REPO_ARN, "repositoryName": "ph" + O_ACUTE + "p"},
    {"repositoryArn": REPO_ARN, "repositoryName": ""},
    {"repositoryArn": REPO_ARN, "repositoryName": 5},
    {"repositoryArn": REPO_ARN, "repositoryName": "php:8.3"},
    {"repositoryArn": REPO_ARN + " x", "repositoryName": "php"},
    {"repositoryArn": REPO_ARN},
    {"repositoryName": "php"},
    {"repositoryArn": "nope", "repositoryName": "php"},
])
def test_a_repository_record_with_no_usable_identity_is_counted(fake_session, record):
    fake_session.script("describe_repositories", [{"repositories": [record]}])
    gap = only(fake_session)
    assert gap.note == REPOSITORY_UNREAD


@pytest.mark.parametrize("uri", [
    "bad uri", "registry.example.com:5000/php", "", None, 5, "caf" + E_ACUTE + "/php"])
def test_a_repository_with_no_usable_uri_is_named_by_its_repository_name(fake_session, uri):
    record = {"repositoryArn": REPO_ARN, "repositoryName": "php", "repositoryUri": uri}
    fake_session.script("describe_repositories", [{"repositories": [record]}])
    fake_session.stub_repository("php", ["8.3.36-fpm"])
    ev = only(fake_session)
    assert ev.location == "php:8.3.36-fpm"


@pytest.mark.parametrize("image", [
    None, 5, "php8.3", {}, {"imageDigest": "sha256:x"}, {"imageTag": None}, {"imageTag": 5},
    {"imageTag": ""}, {"imageTag": "php8.3 "}, {"imageTag": "php8.3\n"}, {"imageTag": "php8.3/x"},
    {"imageTag": "php" + E_ACUTE + "8.3"}, {"imageTag": "p" * 200},
])
def test_an_image_entry_that_is_no_tag_is_counted_and_never_emitted(fake_session, image):
    fake_session.stub_repository("php", [])
    fake_session.script("list_images", [{"imageIds": [image, {"imageTag": "8.3.36"}]}])
    found, gap = inventory(fake_session)
    assert found.detected_version == "8.3.36"
    assert gap.note == IMAGE_UNREAD


# --- regions ---

def test_the_default_region_is_the_sessions_and_every_client_is_made_there(fake_session):
    stubbed_everything(fake_session)
    source = AwsSource(fake_session)
    assert source.regions == ("us-east-1",)
    source.inventory()
    assert fake_session.clients == [("elasticbeanstalk", "us-east-1", ()),
                                    ("lambda", "us-east-1", ()), ("ecr", "us-east-1", ())]


def test_each_region_given_is_read_and_a_row_names_the_one_that_failed():
    session = FakeSession()
    eu = f"arn:aws:elasticbeanstalk:eu-west-1:{ACCOUNT}:environment/shop/shop-eu"
    session.stub_beanstalk_php("8.3", ENV_ARN)
    session.stub_beanstalk_php("7.4", eu, region="eu-west-1",
                               cname="shop-eu.eba-1.eu-west-1.elasticbeanstalk.com")
    session.stub_lambda("fn", layers=[BREF_FPM], region="ap-south-1")
    session.fail("lambda", ClientError("AccessDeniedException"))
    regions = ["us-east-1", "eu-west-1", "ap-south-1"]
    source = AwsSource(session, regions=regions)
    assert source.regions == ("us-east-1", "eu-west-1", "ap-south-1")
    evs = source.inventory()
    assert {e.signals["resource"] for e in evs if "resource" in e.signals} == {ENV_ARN, eu}
    assert sorted(e.location for e in evs if e.note.startswith("not inventoried")) == [
        "aws lambda ap-south-1", "aws lambda eu-west-1", "aws lambda us-east-1"]
    assert {(s, r) for s, r, _ in session.clients} == {
        (s, r) for s in ("elasticbeanstalk", "lambda", "ecr") for r in regions}


@pytest.mark.parametrize("regions", [[], (), None, iter(()), ""])
def test_no_regions_given_reads_the_sessions_own(fake_session, regions):
    assert AwsSource(fake_session, regions=regions).regions == ("us-east-1",)


def test_an_empty_region_name_makes_every_client_in_the_sessions_region(fake_session):
    stubbed_everything(fake_session)
    AwsSource(fake_session, regions="").inventory()
    assert {region for _, region, _ in fake_session.clients} == {"us-east-1"}


def test_regions_may_come_from_a_generator(fake_session):
    source = AwsSource(fake_session, regions=(r for r in ["eu-west-1", "ap-south-1"]))
    assert source.regions == ("eu-west-1", "ap-south-1")


def test_a_region_given_as_a_string_is_one_region():
    # A bare name read as a sequence would be one region for each of its letters.
    session = FakeSession()
    eu = f"arn:aws:elasticbeanstalk:eu-west-1:{ACCOUNT}:environment/shop/shop-eu"
    session.stub_beanstalk_php("8.3", eu, region="eu-west-1",
                               cname="shop-eu.eba-1.eu-west-1.elasticbeanstalk.com")
    session.stub_beanstalk_php("8.3", ENV_ARN)
    source = AwsSource(session, regions="eu-west-1")
    assert source.regions == ("eu-west-1",)
    assert [e.signals["resource"] for e in source.inventory()] == [eu]
    made = sorted(session.clients)
    assert made == [("ecr", "eu-west-1", ()), ("elasticbeanstalk", "eu-west-1", ()),
                    ("lambda", "eu-west-1", ())]


@pytest.mark.parametrize("regions", [["eu-west-1"], ("eu-west-1",), iter(["eu-west-1"])])
def test_one_region_in_a_list_a_tuple_or_an_iterator_is_still_one_region(fake_session, regions):
    assert AwsSource(fake_session, regions=regions).regions == ("eu-west-1",)


# --- read-only, and nothing taken from the credentials ---

def test_only_the_four_reads_are_called_and_the_session_is_touched_for_nothing_else(
        fake_session):
    stubbed_everything(fake_session)
    inventory(fake_session)
    assert {c.operation for c in fake_session.calls} == READS
    assert fake_session.touched == []


def test_clients_are_made_with_a_region_and_never_a_key(fake_session):
    stubbed_everything(fake_session)
    inventory(fake_session)
    assert fake_session.clients
    assert all(extra == () for _, _, extra in fake_session.clients)
    assert fake_session.touched == []


def test_a_response_field_the_source_does_not_name_never_reaches_the_evidence(fake_session):
    stubbed_everything(fake_session)
    fake_session.fail("ecr", ClientError("AccessDeniedException", SECRET), "list_images")
    evs = inventory(fake_session)
    # The environment, the function, and the repository whose images could not be listed.
    assert len(evs) == 3
    for ev in evs:
        assert SECRET not in text_of(ev)
    for out in rendered(evs):
        assert SECRET not in out


def test_the_source_never_names_an_operation_but_the_four_reads():
    tree = ast.parse(source_of(aws), feature_version=(3, 9))
    used = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)
            and isinstance(n.value, ast.Name) and n.value.id == "client"}
    assert used == READS


# --- what the report makes of it ---

def test_the_report_prints_arns_and_names_whole_whatever_they_are_called(fake_session):
    arn = f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:token-key-auth-password"
    fake_session.stub_lambda("token-key-auth-password", layers=[BREF_FPM])
    fake_session.stub_repository("keycloak-php", ["php8.3.36"])
    fake_session.stub_beanstalk_php(
        "8.3", f"arn:aws:elasticbeanstalk:us-east-1:{ACCOUNT}:environment/auth/auth-prod")
    console, as_json, sarif = rendered(inventory(fake_session))
    for out in (console, as_json, sarif):
        assert arn in out
        assert "repository/keycloak-php" in out
        assert "environment/auth/auth-prod" in out
        assert out.isascii()
    assert "layer php-83-fpm marks a PHP runtime, and the build is not read" in console
    assert "PHP 8.3" in console
    assert json.loads(as_json)["summary"]["total"] == 3
    json.loads(sarif)


def test_a_failed_service_reads_as_a_row_in_the_report(fake_session):
    fake_session.fail("lambda", NoCredentialsError("Unable to locate credentials"))
    console = rendered(inventory(fake_session))[0]
    assert "aws lambda us-east-1" in console
    assert "not inventoried: no AWS credentials were found (NoCredentialsError)" in console
    assert "INDETERMINATE" in console


# --- nothing a service sends can crash the source ---

def check(ev):
    assert isinstance(ev, Evidence) and ev.source is Source.CLOUD and isinstance(ev.sapi, Sapi)
    for value in [ev.location, ev.note] + list(ev.signals.values()):
        assert isinstance(value, str) and value.isascii() and value.isprintable()
        assert len(value) <= 2300
    assert set(ev.signals) <= SIGNAL_KEYS
    resource = ev.signals.get("resource")
    # Only a Beanstalk ARN may hold a space, because it holds the application name.
    spaced = ev.signals.get("service") == "elasticbeanstalk"
    assert resource is None or (resource.startswith("arn:") and (spaced or " " not in resource))
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


POOL = [None, True, 0, -7, 2 ** 70, 1.5, "", " ", "x", "arn:", "arn:aws:x:y:z", "a\nb",
        "caf" + E_ACUTE, BIDI, "php", "PHP 8.3", "8.3", "8.3.12", "x" * 3000, [], {}, [None],
        {"a": 1}, ["arn:aws:x"]]
ARNS = [ENV_ARN, FN_ARN, REPO_ARN, "arn:aws:...:env/web1", "arn:a", "arn:" + "z" * 2044]
PLATFORMS_AND_STACKS = [
    PLATFORM + "PHP 8.3 running on 64bit Amazon Linux 2023/4.3.0",
    "64bit Amazon Linux 2018.03 v2.9.17 running PHP 7.3", "PHP 8.3", "PHP 8.3.12", "PHP",
    "php 9.9", "PHP 4.4"]
HOSTS = [CNAME, "lb.example.com", "54.1.2.3", "a b", ".x", "x.", "A.B.C", "h" * 300]
LAYER_ARNS = [BREF_FPM, LAYER + "php-83", LAYER + "x:1", "arn:aws:lambda:us-east-1:1:layer",
              "arn:aws:lambda:::layer:php-83 x:1"]
REPO_NAMES = ["php", "docker-hub/library/php", "shop", "Php", "a b", "x" * 300]
TAG_NAMES = ["8.3.12-fpm", "8.3-apache", "php8.3", "php-8.3.12", "latest", "8.3.12-1ubuntu2.28",
             "1.2.3", "8.3.12RC1", "PHP-5.6.40-cli", "php\n8.3", "x" * 200, "8.3.12-"]


def pick(rng, pool):
    """A value from pool, or from the odd values, which are all of POOL when pool is empty."""
    return rng.choice(pool + POOL) if rng.random() < 0.6 or not pool else rng.choice(pool)


def junk_environment(rng):
    return {"EnvironmentArn": pick(rng, ARNS + [SPACED_ARN]),
            "Status": pick(rng, ["Ready", "Terminated"]),
            "PlatformArn": pick(rng, PLATFORMS_AND_STACKS),
            "SolutionStackName": pick(rng, PLATFORMS_AND_STACKS),
            "CNAME": pick(rng, HOSTS), "EndpointURL": pick(rng, HOSTS)}


def junk_function(rng):
    layers = [{"Arn": pick(rng, LAYER_ARNS)} for _ in range(rng.randrange(4))]
    runtime = pick(rng, ["provided.al2", "php8.3", "python3.12"])
    return {"FunctionArn": pick(rng, ARNS), "Runtime": runtime,
            "Layers": layers if rng.random() < 0.8 else pick(rng, [])}


def junk_repository(rng):
    uri = pick(rng, ["h.example.com/php", "h.example.com/shop", "a b", "x" * 600])
    return {"repositoryArn": pick(rng, ARNS), "repositoryName": pick(rng, REPO_NAMES),
            "repositoryUri": uri}


def junk_image(rng):
    return {"imageTag": pick(rng, TAG_NAMES)}


def junk_page(rng, key, make, token):
    items = [make(rng) if rng.random() < 0.85 else pick(rng, []) for _ in range(rng.randrange(5))]
    page = {key: items if rng.random() < 0.95 else pick(rng, [])}
    if rng.random() < 0.2:
        page[token] = pick(rng, ["next"])
    return page


@pytest.mark.parametrize("seed", range(8))
def test_nothing_a_service_sends_crashes_the_source_or_slips_past_a_bound(seed):
    rng = random.Random(seed)
    for _ in range(150):
        session = FakeSession()
        session.script("describe_environments", [
            junk_page(rng, "Environments", junk_environment, "NextToken") for _ in range(2)])
        session.script("list_functions", [
            junk_page(rng, "Functions", junk_function, "NextMarker") for _ in range(2)])
        session.script("describe_repositories", [
            junk_page(rng, "repositories", junk_repository, "nextToken") for _ in range(2)])
        session.script("list_images", [
            junk_page(rng, "imageIds", junk_image, "nextToken") for _ in range(6)])
        # Some pages are not pages at all, and some calls fail.
        for op in list(session._script):
            if rng.random() < 0.15:
                session._script[op] = iter([pick(rng, []), ClientError("ThrottlingException")])
        evs = inventory(session)
        for ev in evs:
            check(ev)
        assert {c.operation for c in session.calls} <= READS
        assert session.touched == []


# --- the source ---

def source_of(module):
    return pathlib.Path(module.__file__).read_text(encoding="utf-8")


def imports_of(tree):
    """(top-level module, inside a function) for every import in a tree."""
    found = []

    def walk(node, inside):
        for child in ast.iter_child_nodes(node):
            fn = inside or isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
            if isinstance(child, ast.Import):
                found.extend((a.name.split(".")[0], inside) for a in child.names)
            elif isinstance(child, ast.ImportFrom):
                found.append(((child.module or "").split(".")[0], inside))
            walk(child, fn)

    walk(tree, False)
    return found


def test_the_modules_are_standard_library_only_and_boto3_is_imported_in_one_function():
    pkg = ast.parse(source_of(cloud), feature_version=(3, 9))
    mod = ast.parse(source_of(aws), feature_version=(3, 9))
    assert {m for m, _ in imports_of(mod)} <= {"collections", "string", "typing", "php_radar"}
    assert {m for m, inside in imports_of(pkg) if not inside} <= {"os", "typing", "php_radar"}
    lazy = [(m, inside) for m, inside in imports_of(pkg) if m in ("boto3", "botocore")]
    assert lazy == [("boto3", True)]


def test_the_source_has_no_way_to_read_credentials_the_environment_or_a_file():
    tree = ast.parse(source_of(aws), feature_version=(3, 9))
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    names |= {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    assert not names & {
        "get_credentials", "access_key", "secret_key", "token", "environ", "getenv", "os", "open",
        "profile_name", "available_profiles", "get_available_regions", "boto3", "botocore",
        "print", "logging", "eval", "exec", "compile", "__import__", "subprocess", "socket",
        "urllib"}
    session_uses = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)
                    and isinstance(n.value, ast.Attribute) and n.value.attr == "_session"}
    assert session_uses == {"client"}
    on_session = [n for n in ast.walk(tree) if isinstance(n, ast.Attribute)
                  and isinstance(n.value, ast.Name) and n.value.id == "session"]
    assert {n.attr for n in on_session} <= {"region_name"}


@pytest.mark.parametrize("module", [cloud, aws], ids=["cloud/__init__", "cloud/aws"])
def test_the_source_is_plain_ascii_with_no_dash_or_curly_quote(module):
    source = source_of(module)
    assert source.isascii()
    assert not set(source) & set(DASHES_AND_QUOTES)
    assert not [c for c in source if ord(c) < 32 and c != "\n"]
