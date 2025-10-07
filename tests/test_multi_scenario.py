import time

import pytest

from app import create_app


@pytest.fixture
def client():
    app = create_app()
    app.config.update(TESTING=True)
    with app.test_client() as client:
        yield client


def get_session_id(client):
    response = client.get("/cli/api/meta")
    assert response.status_code == 200
    data = response.get_json()
    return data["sessionId"]


def execute(client, slug, session_id, command):
    response = client.post(
        "/cli/api/execute",
        json={
            "sessionId": session_id,
            "scenarioSlug": slug,
            "command": command,
        },
    )
    return response


def test_state_isolated_across_scenarios(client):
    slug_public = "01-easy"
    slug_sqs = "02-easy"
    slug_rds = "03-medium"
    slug_iam = "04-medium"
    slug_kms = "05-hard"
    slug_ecs = "06-hard"

    session_id = get_session_id(client)

    resp = execute(client, slug_iam, session_id, "aws iam list-roles")
    body = resp.get_json()
    assert body["ok"] is True
    assert body["json"]["Roles"][0]["RoleName"] == "iamassume-audit-role"

    resp = execute(
        client,
        slug_iam,
        session_id,
        "aws configure set region us-east-1",
    )
    assert resp.status_code == 200
    assert resp.get_json()["ok"] is True

    resp = execute(
        client,
        slug_iam,
        session_id,
        "aws iam list-attached-role-policies --role-name iamassume-audit-role",
    )
    body = resp.get_json()
    assert body["ok"] is True
    attached = body["json"]["AttachedPolicies"][0]
    assert attached["PolicyName"] == "iamassume-legacy-assume"

    policy_arn = attached["PolicyArn"]
    resp = execute(
        client,
        slug_iam,
        session_id,
        f"aws iam get-policy --policy-arn {policy_arn}",
    )
    body = resp.get_json()
    assert body["ok"] is True
    assert body["json"]["Policy"]["DefaultVersionId"] == "v2"

    resp = execute(
        client,
        slug_iam,
        session_id,
        f"aws iam list-policy-versions --policy-arn {policy_arn}",
    )
    body = resp.get_json()
    assert body["ok"] is True
    versions = {v["VersionId"]: v for v in body["json"]["Versions"]}
    assert versions["v2"]["IsDefaultVersion"] is True
    assert versions["v1"]["IsDefaultVersion"] is False

    time.sleep(1.05)
    resp = execute(
        client,
        slug_iam,
        session_id,
        f"aws iam get-policy-version --policy-arn {policy_arn} --version-id v1",
    )
    body = resp.get_json()
    assert body["ok"] is True
    assert "AssumeAudit" in body["json"]["PolicyVersion"]["Document"]

    resp = execute(
        client,
        slug_iam,
        session_id,
        "aws secretsmanager get-secret-value --secret-id prod/iamassume/db/password",
    )
    body = resp.get_json()
    assert body["ok"] is False
    assert body["errorCode"] == "AccessDenied"

    assume_resp = execute(
        client,
        slug_iam,
        session_id,
        "aws sts assume-role --role-arn arn:aws:iam::666666666666:role/iamassume-audit-role --role-session-name ctf",
    )
    assert assume_resp.status_code == 200
    assert assume_resp.get_json()["ok"] is True

    resp = execute(
        client,
        slug_iam,
        session_id,
        "aws secretsmanager get-secret-value --secret-id prod/iamassume/db/password",
    )
    body = resp.get_json()
    assert body["ok"] is True
    assert body["json"]["SecretString"].startswith("flag{")

    resp = execute(client, slug_public, session_id, "aws sts get-caller-identity")
    body = resp.get_json()
    assert body["ok"] is True
    assert body["json"]["Arn"].endswith("user/appsec.emi.tanaka")

    resp = execute(client, slug_sqs, session_id, "aws sqs list-queues")
    body = resp.get_json()
    assert body["ok"] is True
    queues = set(body["json"]["QueueUrls"])
    assert "https://sqs.us-east-1.222222222222.amazonaws.com/222222222222/sqsopen-notify-dev" in queues

    execute(client, slug_sqs, session_id, "aws configure set region us-east-1")
    resp = execute(
        client,
        slug_sqs,
        session_id,
        "aws sqs receive-message --queue-url https://sqs.us-east-1.222222222222.amazonaws.com/222222222222/sqsopen-notify-dev",
    )
    body = resp.get_json()
    assert body["ok"] is True
    assert body["json"]["Messages"][0]["Body"].startswith("flag{")

    resp = execute(
        client,
        slug_kms,
        session_id,
        "aws kms decrypt --ciphertext-blob fileb://cipher.bin --key-id arn:aws:kms:us-east-1:333333333333:key/0f1e2d3c-4b5a-6978-8877-665544332211",
    )
    body = resp.get_json()
    assert body["ok"] is False
    assert body["errorCode"] == "UnknownOperation"

    execute(client, slug_kms, session_id, "aws configure set region us-east-1")
    execute(client, slug_kms, session_id, "aws s3 cp s3://kmsper-crypto-prod-202510-c4d2/cipher.bin .")
    resp = execute(
        client,
        slug_kms,
        session_id,
        "aws kms decrypt --ciphertext-blob fileb://cipher.bin --key-id arn:aws:kms:us-east-1:333333333333:key/0f1e2d3c-4b5a-6978-8877-665544332211",
    )
    body = resp.get_json()
    assert body["ok"] is True
    assert (
        body["json"]["Plaintext"]
        == "ZmxhZ3trbXMtZGVjcnlwdC1wZXJtaXNzaXZlLXBvbGljeS0xMjN9"
    )

    resp = execute(
        client,
        slug_rds,
        session_id,
        "aws rds describe-db-snapshots --include-public",
    )
    body = resp.get_json()
    assert body["ok"] is True
    snapshots = body["json"]["DBSnapshots"]
    assert snapshots[0]["DBSnapshotIdentifier"] == "rdsnap-appdb-20251001"

    execute(client, slug_rds, session_id, "aws configure set region us-east-1")
    resp = execute(
        client,
        slug_rds,
        session_id,
        "aws rds list-tags-for-resource --resource-name arn:aws:rds:us-east-1:444444444444:snapshot:rdsnap-appdb-20251001",
    )
    body = resp.get_json()
    assert body["ok"] is True
    tags = {tag["Key"]: tag["Value"] for tag in body["json"]["TagList"]}
    assert tags["flag"] == "flag{rds-public-snapshot-123}"

    execute(client, slug_ecs, session_id, "aws configure set region us-east-1")
    execute(client, slug_ecs, session_id, "aws ssm describe-parameters")

    resp = execute(
        client,
        slug_ecs,
        session_id,
        "aws ssm get-parameter --name /prod/app/flag --with-decryption",
    )
    body = resp.get_json()
    assert body["ok"] is False
    assert body["errorCode"] == "AccessDenied"

    disallowed = client.get(
        "/cli/api/fetch",
        query_string={
            "sessionId": session_id,
            "scenarioSlug": slug_ecs,
            "url": "http://example.com",
        },
    )
    assert disallowed.status_code == 403
    assert disallowed.get_json()["error"].startswith("Fetcher only")

    allowed = client.get(
        "/cli/api/fetch",
        query_string={
            "sessionId": session_id,
            "scenarioSlug": slug_ecs,
            "url": "http://169.254.170.2/v2/credentials/2ff1c6a2-7a46-4d8d-9e59-1a2b3c4d5e6f",
        },
    )
    assert allowed.status_code == 200
    assert allowed.get_json()["RoleArn"].endswith("role/ecsTaskRole")

    resp = execute(
        client,
        slug_ecs,
        session_id,
        "aws ssm get-parameter --name /prod/app/flag --with-decryption",
    )
    body = resp.get_json()
    assert body["ok"] is True
    assert body["json"]["Parameter"]["Value"] == "flag{ecs-metadata-to-ssm-123}"


def test_rate_limit_isolated(client):
    slug_public = "01-easy"
    slug_iam = "04-medium"

    session_id = get_session_id(client)

    responses = []
    for _ in range(6):
        responses.append(
            execute(client, slug_public, session_id, "aws sts get-caller-identity")
        )
    status_codes = [resp.status_code for resp in responses]
    assert status_codes[-1] == 429

    resp = execute(client, slug_iam, session_id, "aws sts get-caller-identity")
    assert resp.status_code == 200
    assert resp.get_json()["ok"] is True
