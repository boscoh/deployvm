"""Unit tests for the Bedrock IAM role and instance-profile propagation retry.

These use fakes and never touch AWS.
"""

import pytest
from botocore.exceptions import ClientError

from deployvm.providers import BEDROCK_POLICY_ARN, AWSProvider

IAM_ROLE = "deploy-vm-bedrock"


def _client_error(code: str, message: str, operation: str = "Op") -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": message}}, operation)


class FakeIam:
    """Minimal IAM client: no role exists, so the create path runs."""

    def __init__(self, attach_error: ClientError | None = None):
        self.attached: list[tuple[str, str]] = []
        self.attach_error = attach_error

    def get_role(self, RoleName: str) -> dict:
        raise _client_error("NoSuchEntity", "no such role", "GetRole")

    def create_role(self, **kwargs) -> dict:
        return {}

    def attach_role_policy(self, RoleName: str, PolicyArn: str) -> None:
        if self.attach_error:
            raise self.attach_error
        self.attached.append((RoleName, PolicyArn))

    def create_instance_profile(self, **kwargs) -> dict:
        return {}

    def add_role_to_instance_profile(self, **kwargs) -> None:
        return None

    def get_instance_profile(self, InstanceProfileName: str) -> dict:
        return {"InstanceProfile": {"Roles": [{"RoleName": InstanceProfileName}]}}


def _provider_with(iam: FakeIam) -> AWSProvider:
    provider = object.__new__(AWSProvider)
    provider._get_iam_client = lambda: iam  # type: ignore[method-assign]
    return provider


def test_attaches_bedrock_policy():
    iam = FakeIam()
    profile = _provider_with(iam)._ensure_iam_role_and_profile(IAM_ROLE)
    assert profile == IAM_ROLE
    assert iam.attached == [(IAM_ROLE, BEDROCK_POLICY_ARN)]


def test_missing_attach_permission_warns_but_continues():
    iam = FakeIam(_client_error("AccessDenied", "denied", "AttachRolePolicy"))
    profile = _provider_with(iam)._ensure_iam_role_and_profile(IAM_ROLE)
    assert profile == IAM_ROLE
    assert iam.attached == []


PROPAGATION_ERROR = _client_error(
    "InvalidParameterValue",
    "Value (deploy-vm-bedrock) for parameter iamInstanceProfile.name is invalid. "
    "Invalid IAM Instance Profile name",
    "RunInstances",
)

RUN_PARAMS = {"IamInstanceProfile": {"Name": IAM_ROLE}}


class FakeEc2:
    def __init__(self, fail_times: int, error: ClientError):
        self.fail_times = fail_times
        self.error = error
        self.calls = 0

    def run_instances(self, **kwargs) -> dict:
        self.calls += 1
        if self.calls <= self.fail_times:
            raise self.error
        return {"Instances": [{"InstanceId": "i-123"}]}


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr("deployvm.providers.time.sleep", lambda _seconds: None)


def test_run_instances_retries_until_profile_is_visible():
    ec2 = FakeEc2(fail_times=2, error=PROPAGATION_ERROR)
    response = object.__new__(AWSProvider)._run_instances(ec2, RUN_PARAMS)
    assert response["Instances"][0]["InstanceId"] == "i-123"
    assert ec2.calls == 3


def test_run_instances_gives_up_after_six_attempts():
    ec2 = FakeEc2(fail_times=99, error=PROPAGATION_ERROR)
    with pytest.raises(ClientError):
        object.__new__(AWSProvider)._run_instances(ec2, RUN_PARAMS)
    assert ec2.calls == 6


def test_run_instances_does_not_retry_other_errors():
    ec2 = FakeEc2(
        fail_times=99, error=_client_error("InvalidParameterValue", "bad subnet")
    )
    with pytest.raises(ClientError):
        object.__new__(AWSProvider)._run_instances(ec2, RUN_PARAMS)
    assert ec2.calls == 1
