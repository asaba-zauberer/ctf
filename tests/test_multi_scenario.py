import time

import pytest

from app import create_app


@pytest.fixture
def client():
    app = create_app()
    app.config.update(TESTING=True)
    with app.test_client() as client:
        yield client


def get_session_id(client, slug):
    response = client.get(f"/c/{slug}/api/meta")
    assert response.status_code == 200
    data = response.get_json()
    return data["sessionId"]


def execute(client, slug, session_id, command):
    response = client.post(
        f"/c/{slug}/api/execute",
        json={"sessionId": session_id, "command": command},
    )
    return response


def test_state_isolated_across_scenarios(client):
    slug_public = "01-easy"
    slug_sqs = "02-easy"
    slug_rds = "03-medium"
    slug_iam = "04-medium"
    slug_kms = "05-hard"
    slug_ecs = "06-hard"

    session_public = get_session_id(client, slug_public)
    session_iam = get_session_id(client, slug_iam)
    session_sqs = get_session_id(client, slug_sqs)
    session_kms = get_session_id(client, slug_kms)
    session_rds = get_session_id(client, slug_rds)
    session_ecs = get_session_id(client, slug_ecs)

    resp = execute(client, slug_iam, session_iam, "aws iam list-roles")
    body = resp.get_json()
    assert body["ok"] is False
    assert body["errorCode"] == "UnknownOperation"

    resp = execute(
        client,
        slug_iam,
        session_iam,
        "aws configure set region us-east-1",
    )
    assert resp.status_code == 200
    assert resp.get_json()["ok"] is True

    resp = execute(client, slug_iam, session_iam, "aws iam list-attached-role-policies --role-name audit-role")
    body = resp.get_json()
    assert body["ok"] is True
    attached = body["json"]["AttachedPolicies"][0]
    assert attached["PolicyName"] == "legacy-assume-audit"

    policy_arn = attached["PolicyArn"]
    resp = execute(client, slug_iam, session_iam, f"aws iam get-policy --policy-arn {policy_arn}")
    body = resp.get_json()
    assert body["ok"] is True
    assert body["json"]["Policy"]["DefaultVersionId"] == "v2"

    resp = execute(client, slug_iam, session_iam, f"aws iam list-policy-versions --policy-arn {policy_arn}")
    body = resp.get_json()
    assert body["ok"] is True
    versions = {v["VersionId"]: v for v in body["json"]["Versions"]}
    assert versions["v2"]["IsDefaultVersion"] is True
    assert versions["v1"]["IsDefaultVersion"] is False

    time.sleep(1.05)
    resp = execute(client, slug_iam, session_iam, f"aws iam get-policy-version --policy-arn {policy_arn} --version-id v1")
    body = resp.get_json()
    assert body["ok"] is True
    assert "AssumeAudit" in body["json"]["PolicyVersion"]["Document"]

    resp = execute(client, slug_iam, session_iam, "aws secretsmanager get-secret-value --secret-id prod/db/password")
    body = resp.get_json()
    assert body["ok"] is False
    assert body["errorCode"] == "AccessDenied"

    assume_resp = execute(
        client,
        slug_iam,
        session_iam,
        "aws sts assume-role --role-arn arn:aws:iam::123456789012:role/audit-role --role-session-name ctf",
    )
    assert assume_resp.status_code == 200
    assert assume_resp.get_json()["ok"] is True

    resp = execute(client, slug_iam, session_iam, "aws secretsmanager get-secret-value --secret-id prod/db/password")
    body = resp.get_json()
    assert body["ok"] is True
    assert body["json"]["SecretString"].startswith("flag{")

    resp = execute(client, slug_public, session_public, "aws sts get-caller-identity")
    body = resp.get_json()
    assert body["ok"] is True
    assert body["json"]["Arn"].endswith("user/userA")

    resp = execute(client, slug_sqs, session_sqs, "aws sqs list-queues")
    body = resp.get_json()
    assert body["ok"] is False
    assert body["errorCode"] == "UnknownOperation"

    execute(client, slug_sqs, session_sqs, "aws configure set region us-east-1")
    resp = execute(client, slug_sqs, session_sqs, "aws sqs receive-message --queue-url https://sqs.us-east-1.123456789012.amazonaws.com/123456789012/public-queue")
    body = resp.get_json()
    assert body["ok"] is True
    assert body["json"]["Messages"][0]["Body"].startswith("flag{")

    resp = execute(client, slug_kms, session_kms, "aws kms decrypt --ciphertext-blob fileb://cipher.bin --key-id arn:aws:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555")
    body = resp.get_json()
    assert body["ok"] is False
    assert body["errorCode"] == "UnknownOperation"

    execute(client, slug_kms, session_kms, "aws configure set region us-east-1")
    execute(client, slug_kms, session_kms, "aws s3 cp s3://kms-lab-bucket/cipher.bin .")
    resp = execute(client, slug_kms, session_kms, "aws kms decrypt --ciphertext-blob fileb://cipher.bin --key-id arn:aws:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555")
    body = resp.get_json()
    assert body["ok"] is True
    assert (
        body["json"]["Plaintext"]
        == "ZmxhZ3trbXMtZGVjcnlwdC1wZXJtaXNzaXZlLXBvbGljeS0xMjN9"
    )

    resp = execute(client, slug_rds, session_rds, "aws rds describe-db-snapshots --include-public")
    body = resp.get_json()
    assert body["ok"] is False
    assert body["errorCode"] == "UnknownOperation"

    execute(client, slug_rds, session_rds, "aws configure set region us-east-1")
    resp = execute(client, slug_rds, session_rds, "aws rds list-tags-for-resource --resource-name arn:aws:rds:us-east-1:123456789012:snapshot:ctf-public-snap")
    body = resp.get_json()
    assert body["ok"] is True
    tags = {tag["Key"]: tag["Value"] for tag in body["json"]["TagList"]}
    assert tags["flag"] == "flag{rds-public-snapshot-123}"

    execute(client, slug_ecs, session_ecs, "aws configure set region us-east-1")
    execute(client, slug_ecs, session_ecs, "aws ssm describe-parameters")

    resp = execute(client, slug_ecs, session_ecs, "aws ssm get-parameter --name /prod/app/flag --with-decryption")
    body = resp.get_json()
    assert body["ok"] is False
    assert body["errorCode"] == "AccessDenied"

    disallowed = client.get(
        "/c/06-hard/api/fetch",
        query_string={
            "sessionId": session_ecs,
            "url": "http://example.com",
        },
    )
    assert disallowed.status_code == 403
    assert disallowed.get_json()["error"].startswith("Fetcher only")

    allowed = client.get(
        "/c/06-hard/api/fetch",
        query_string={
            "sessionId": session_ecs,
            "url": "http://169.254.170.2/v2/credentials/2ff1c6a2-7a46-4d8d-9e59-1a2b3c4d5e6f",
        },
    )
    assert allowed.status_code == 200
    assert allowed.get_json()["RoleArn"].endswith("role/ecsTaskRole")

    resp = execute(client, slug_ecs, session_ecs, "aws ssm get-parameter --name /prod/app/flag --with-decryption")
    body = resp.get_json()
    assert body["ok"] is True
    assert body["json"]["Parameter"]["Value"] == "flag{ecs-metadata-to-ssm-123}"


def test_rate_limit_isolated(client):
    slug_public = "01-easy"
    slug_iam = "04-medium"

    session_public = get_session_id(client, slug_public)
    session_iam = get_session_id(client, slug_iam)

    responses = []
    for _ in range(6):
        responses.append(
            execute(client, slug_public, session_public, "aws sts get-caller-identity")
        )
    status_codes = [resp.status_code for resp in responses]
    assert status_codes[-1] == 429

    resp = execute(client, slug_iam, session_iam, "aws sts get-caller-identity")
    assert resp.status_code == 200
    assert resp.get_json()["ok"] is True
