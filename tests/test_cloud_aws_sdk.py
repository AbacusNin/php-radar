"""AwsSource against the real botocore, with no network and no credentials.

test_cloud_aws.py answers from stand-ins written by hand, and a stand-in can drift from what AWS
really sends. These tests check the source against the service models that ship with botocore:
the calls it makes and the fields it reads have to exist there. botocore's Stubber then answers
each call and checks every request and every canned answer against the same models.

They need boto3, which the aws extra installs, and are skipped without it. Nothing here opens a
socket or reads a credential: the environment is cleared first, and a guard fails any attempt to
connect or to resolve a name.
"""
import os
import socket
import types

import pytest

from php_radar.knowledge import DATA_PATH, grade, load_matrix
from php_radar.model import AssetInventory
from php_radar.sources.cloud import aws, get_cloud_source
from php_radar.sources.cloud.aws import AwsSource

boto3 = pytest.importorskip("boto3")
# botocore ships with boto3, so the imports below are safe once the skip has passed.
from botocore.exceptions import (
    ClientError, NoCredentialsError, NoRegionError, ProfileNotFound)
from botocore.stub import Stubber

MATRIX = load_matrix(DATA_PATH)

ACCOUNT = "123456789012"
# The example ARN in the Beanstalk documentation. An application name may hold spaces.
SPACED = ("arn:aws:elasticbeanstalk:us-east-2:123456789012:"
          "environment/My First Elastic Beanstalk Application/Test")
# Stands for anything a response holds that the source has no business copying: a Lambda
# environment variable, an exception message.
CANARY = "hunter2-" + "CANARY-sdk"
FILTER = {"tagStatus": "TAGGED"}
LISTING = {"repositoryName": "php", "filter": FILTER, "maxResults": 1000}

# What the stubbed account answers, service by service and in call order. A step is (kind,
# operation, body, expected parameters), where an "error" step takes the keywords of
# Stubber.add_client_error as its body.
PLAN = {
    "elasticbeanstalk": [
        ("ok", "describe_environments", {"Environments": [{
            "EnvironmentName": "shop-prod", "EnvironmentId": "e-abc123",
            "ApplicationName": "My First Elastic Beanstalk Application",
            "EnvironmentArn": SPACED, "Status": "Ready", "Health": "Green",
            "PlatformArn": "arn:aws:elasticbeanstalk:us-east-2::platform/"
                           "PHP 8.3 running on 64bit Amazon Linux 2023/4.13.12",
            "SolutionStackName": "64bit Amazon Linux 2023 v4.13.12 running PHP 8.3",
            "CNAME": "shop-prod.eba-abc123.us-east-2.elasticbeanstalk.com",
            "Description": CANARY}], "NextToken": "t1"}, {}),
        ("ok", "describe_environments", {"Environments": [{
            "EnvironmentName": "api-prod",
            "EnvironmentArn": "arn:aws:elasticbeanstalk:us-east-2:123456789012:"
                              "environment/api/api-prod",
            "Status": "Ready",
            "PlatformArn": "arn:aws:elasticbeanstalk:us-east-2::platform/"
                           "Docker running on 64bit Amazon Linux 2023/4.2.0",
            "SolutionStackName": "64bit Amazon Linux 2023 v4.2.0 running Docker"}]},
         {"NextToken": "t1"}),
    ],
    "lambda": [
        ("ok", "list_functions", {"Functions": [{
            "FunctionName": "legacy-api",
            "FunctionArn": f"arn:aws:lambda:us-east-2:{ACCOUNT}:function:legacy-api",
            "Runtime": "provided.al2", "Handler": "index.handler",
            "Layers": [{"Arn": "arn:aws:lambda:us-east-2:534081306603:layer:php-83-fpm:20",
                        "CodeSize": 1}],
            "Environment": {"Variables": {"DB_PASSWORD": CANARY}}}], "NextMarker": "m1"}, {}),
        ("ok", "list_functions", {"Functions": []}, {"Marker": "m1"}),
    ],
    "ecr": [
        ("ok", "describe_repositories", {"repositories": [
            {"repositoryArn": f"arn:aws:ecr:us-east-2:{ACCOUNT}:repository/php",
             "registryId": ACCOUNT, "repositoryName": "php",
             "repositoryUri": f"{ACCOUNT}.dkr.ecr.us-east-2.amazonaws.com/php"},
            {"repositoryArn": f"arn:aws:ecr:us-east-2:{ACCOUNT}:repository/worker",
             "registryId": ACCOUNT, "repositoryName": "worker",
             "repositoryUri": f"{ACCOUNT}.dkr.ecr.us-east-2.amazonaws.com/worker"},
            {"repositoryArn": f"arn:aws:ecr:us-east-2:{ACCOUNT}:repository/gone",
             "registryId": ACCOUNT, "repositoryName": "gone",
             "repositoryUri": f"{ACCOUNT}.dkr.ecr.us-east-2.amazonaws.com/gone"}]},
         {"maxResults": 1000}),
        ("ok", "list_images", {"imageIds": [
            {"imageDigest": "sha256:" + "0" * 64, "imageTag": "8.3.35-fpm"},
            {"imageDigest": "sha256:" + "1" * 64, "imageTag": "latest"}], "nextToken": "n1"},
         LISTING),
        ("ok", "list_images", {"imageIds": [
            {"imageDigest": "sha256:" + "2" * 64, "imageTag": "8.3.36-apache"}]},
         dict(LISTING, nextToken="n1")),
        ("error", "list_images", {
            "service_error_code": "AccessDeniedException", "http_status_code": 400,
            "service_message": "User: arn:aws:iam::123456789012:user/alice may not " + CANARY},
         None),
        ("error", "list_images", {
            "service_error_code": "RepositoryNotFoundException", "http_status_code": 400,
            "service_message": CANARY}, None),
    ],
}


@pytest.fixture(scope="module", autouse=True)
def offline(tmp_path_factory):
    """A clean AWS environment for the whole module, and a guard on the network."""
    where = tmp_path_factory.mktemp("aws")

    def refuse(*args, **kwargs):
        raise AssertionError("the network was touched")

    with pytest.MonkeyPatch.context() as patch:
        for name in [name for name in os.environ if name.startswith("AWS_")]:
            patch.delenv(name)
        # Nothing on the machine that runs the tests may supply a profile, a key, or a region.
        patch.setenv("AWS_CONFIG_FILE", str(where / "config"))
        patch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(where / "credentials"))
        # Without this the default credential chain asks the instance metadata service, and
        # asking is a connection.
        patch.setenv("AWS_EC2_METADATA_DISABLED", "true")
        patch.setattr(socket.socket, "connect", refuse)
        patch.setattr(socket, "getaddrinfo", refuse)
        yield


# --- 1. the service models say what the source assumes ---

@pytest.fixture(scope="module")
def clients():
    session = boto3.Session(region_name="us-east-1")
    return {name: session.client(name) for name in ("elasticbeanstalk", "lambda", "ecr")}


def shapes(client, operation):
    model = client.meta.service_model.operation_model(operation)
    return model.input_shape, model.output_shape


def members(shape):
    return set(shape.members) if shape is not None else set()


def test_beanstalk_describe_environments_has_the_fields_the_source_reads(clients):
    request, answer = shapes(clients["elasticbeanstalk"], "DescribeEnvironments")
    assert {"NextToken", "MaxRecords"} <= members(request)
    assert {"Environments", "NextToken"} <= members(answer)
    env = answer.members["Environments"].member
    assert {"EnvironmentArn", "PlatformArn", "SolutionStackName", "CNAME", "EndpointURL",
            "Status"} <= members(env)
    # The source skips these, so the service has to have a name for them.
    assert "Terminated" in env.members["Status"].enum


def test_lambda_list_functions_has_the_fields_the_source_reads(clients):
    request, answer = shapes(clients["lambda"], "ListFunctions")
    assert "Marker" in members(request)
    assert {"Functions", "NextMarker"} <= members(answer)
    fn = answer.members["Functions"].member
    assert {"FunctionArn", "Runtime", "Layers", "Environment"} <= members(fn)
    assert "Arn" in members(fn.members["Layers"].member)
    # The record carries the values of the function's environment variables, which is why the
    # source copies a few named fields and never the record.
    assert "Variables" in members(fn.members["Environment"])


def test_no_lambda_runtime_the_sdk_lists_is_mistaken_for_php_or_missed(clients):
    # AWS lists no PHP runtime today. Whether that changes or not, the source has to call a
    # runtime PHP when its name says so and for no other reason.
    fn = shapes(clients["lambda"], "ListFunctions")[1].members["Functions"].member
    runtimes = fn.members["Runtime"].enum
    assert runtimes
    for runtime in runtimes:
        says_php = runtime.lower().startswith("php")
        assert bool(aws._php_function({"Runtime": runtime})) == says_php, runtime


def test_ecr_describe_repositories_and_list_images_have_what_the_source_uses(clients):
    repos_in, repos_out = shapes(clients["ecr"], "DescribeRepositories")
    assert {"maxResults", "nextToken"} <= members(repos_in)
    # The source asks for pages of aws._PAGE, a size the service has to accept.
    size = repos_in.members["maxResults"].metadata
    assert size["min"] <= aws._PAGE <= size["max"]
    assert {"repositories", "nextToken"} <= members(repos_out)
    assert {"repositoryArn", "repositoryName", "repositoryUri"} <= members(
        repos_out.members["repositories"].member)

    images_in, images_out = shapes(clients["ecr"], "ListImages")
    assert {"repositoryName", "filter", "maxResults", "nextToken"} <= members(images_in)
    assert "TAGGED" in images_in.members["filter"].members["tagStatus"].enum
    assert "imageTag" in members(images_out.members["imageIds"].member)


def test_the_error_classes_keep_the_names_the_source_records():
    # The source cannot import botocore, so it matches an error by the name of its class.
    names = {cls.__name__ for cls in (ClientError, NoCredentialsError, NoRegionError,
                                      ProfileNotFound)}
    assert names == {"ClientError", "NoCredentialsError", "NoRegionError", "ProfileNotFound"}
    assert set(aws._KNOWN) <= names


# --- 2. AwsSource over real clients answered by the Stubber ---

class StubbedSession:
    """A real boto3 Session whose clients answer from botocore's Stubber, in order."""

    def __init__(self, plan, region):
        self._real = boto3.Session(region_name=region)
        self.region_name = self._real.region_name
        self._plan, self.stubbers, self.seen = plan, [], []

    def client(self, service, region_name=None, **kw):
        client = self._real.client(service, region_name=region_name, **kw)
        stub = Stubber(client)
        for kind, operation, body, expected in self._plan.get(service, []):
            if kind == "ok":
                stub.add_response(operation, body, expected)
            else:
                stub.add_client_error(operation, **body)
        stub.activate()
        # Records the parameters of each call as the source built them.
        client.meta.events.register(
            "before-parameter-build.*.*",
            lambda params, model, **_: self.seen.append((model.name, dict(params))))
        self.stubbers.append(stub)
        return client


@pytest.fixture(scope="module")
def stubbed():
    session = StubbedSession(PLAN, "us-east-2")
    return types.SimpleNamespace(session=session, found=AwsSource(session).inventory())


def test_every_stubbed_call_was_made_in_order_with_parameters_the_models_accept(stubbed):
    # A call the Stubber refuses is caught by the source and recorded as a gap, so the proof
    # that none was refused is that no stubbed answer is left over.
    for stub in stubbed.session.stubbers:
        stub.assert_no_pending_responses()


def test_the_parameters_sent_are_exactly_the_ones_the_source_means_to_send(stubbed):
    sent = {}
    for operation, params in stubbed.session.seen:
        sent.setdefault(operation, []).append(sorted(params))
    assert sent == {
        "DescribeEnvironments": [[], ["NextToken"]],
        "ListFunctions": [[], ["Marker"]],
        "DescribeRepositories": [["maxResults"]],
        "ListImages": [["filter", "maxResults", "repositoryName"],
                       ["filter", "maxResults", "nextToken", "repositoryName"],
                       ["filter", "maxResults", "repositoryName"],
                       ["filter", "maxResults", "repositoryName"]],
    }


def test_only_the_four_reads_were_called(stubbed):
    called = {operation for operation, _ in stubbed.session.seen}
    assert called == {"DescribeEnvironments", "ListFunctions", "DescribeRepositories",
                      "ListImages"}


def test_the_beanstalk_environment_under_a_spaced_application_name_is_found(stubbed):
    resources = [ev.signals.get("resource") for ev in stubbed.found]
    assert SPACED in resources
    assert not [r for r in resources if r and "api-prod" in r]  # the Docker environment is not


def test_the_lambda_function_with_the_php_layer_is_found(stubbed):
    resources = [ev.signals.get("resource") for ev in stubbed.found]
    assert any(r and r.endswith("function:legacy-api") for r in resources)


def test_both_ecr_tags_that_name_php_are_found_and_latest_is_not(stubbed):
    tags = sorted(ev.location.rpartition(":")[2] for ev in stubbed.found
                  if ev.signals.get("service") == "ecr" and ev.detected_version)
    assert tags == ["8.3.35-fpm", "8.3.36-apache"]


def test_a_repository_that_cannot_be_listed_is_a_row_named_by_class_and_code(stubbed):
    notes = {ev.location.rpartition("/")[2]: ev.note for ev in stubbed.found
             if ev.signals.get("kind") == "skipped"}
    # AccessDeniedException is not modeled for ECR, so botocore raises a plain ClientError.
    assert notes["worker"] == "not fully inventoried: ClientError (AccessDeniedException)"
    # A modeled error has a class of its own named for its code, so the name is said once.
    assert notes["gone"] == "not fully inventoried: RepositoryNotFoundException"


def test_no_canary_reaches_an_evidence(stubbed):
    assert CANARY not in repr(stubbed.found)
    assert "alice" not in repr(stubbed.found)


def test_the_assets_grade_and_the_ecr_repository_with_an_old_tag_is_exposed(stubbed):
    inventory = AssetInventory()
    for ev in stubbed.found:
        inventory.add(ev)
    verdicts = sorted((asset.key.rpartition("/")[2], grade(asset, MATRIX)[0].name)
                      for asset in inventory.assets())
    assert ("php", "EXPOSED") in verdicts


# --- 3. errors the real SDK raises, with no stub and no network ---

def test_no_credentials_gives_three_rows_named_by_class():
    rows = AwsSource(boto3.Session(region_name="us-east-1")).inventory()
    assert [row.note for row in rows] == [
        "not inventoried: no AWS credentials were found (NoCredentialsError)"] * 3
    assert [row.signals["service"] for row in rows] == ["elasticbeanstalk", "lambda", "ecr"]


def test_a_session_with_no_region_gives_three_rows_named_by_class():
    bare = boto3.Session()
    assert bare.region_name is None
    rows = AwsSource(bare).inventory()
    assert [row.note for row in rows] == [
        "not inventoried: no AWS region is configured (NoRegionError)"] * 3


def test_get_cloud_source_imports_the_real_boto3_and_reads_the_region_from_the_environment():
    source = get_cloud_source("aws")
    assert isinstance(source, AwsSource)
    assert source.regions == (None,)


def test_a_profile_that_does_not_exist_is_a_runtime_error_naming_the_class_and_nothing_else(
        monkeypatch):
    monkeypatch.setenv("AWS_PROFILE", "no-such-profile")
    with pytest.raises(RuntimeError) as caught:
        get_cloud_source("aws")
    assert str(caught.value) == "boto3 could not start a session (ProfileNotFound)"
