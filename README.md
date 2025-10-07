# AWS CLI CTF Simulator

Python + Flask based capture-the-flag training app that mimics a subset of the AWS CLI. All responses are fully offline and driven by declarative `CommandSpec` JSON scenarios.

## Features
- Self-contained terminal-like web UI (no external CDN dependency)
- Per-session state tied to a cookie-backed `sessionId`
- Multi-scenario routing under `/c/<slug>/` with isolated session+rate state
- Scenario loader (`POST /c/<slug>/api/load-spec`) for hot-swapping `CommandSpec` JSON
- In-memory rate limiting (5 requests/sec per session)
- Logging with flag masking
- Dockerized runtime (`docker-compose up --build`)

## Getting Started

### Local Environment
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
flask --app app run --debug
```
Visit <http://localhost:5000> (debug server) or <http://localhost:8000> when using gunicorn.
The landing page lists available challenge slugs; e.g.:

- 01-easy → <http://localhost:8000/c/01-easy/>
- 02-easy → <http://localhost:8000/c/02-easy/>
- 03-medium → <http://localhost:8000/c/03-medium/>
- 04-medium → <http://localhost:8000/c/04-medium/>
- 05-hard → <http://localhost:8000/c/05-hard/>
- 06-hard → <http://localhost:8000/c/06-hard/>

### Docker Compose
```bash
docker-compose up --build
```
The UI will be available at <http://localhost:8000>.

## API Endpoints
- `GET /c/<slug>/api/health` – Health probe for a scenario
- `GET /c/<slug>/api/meta` – Scenario name, default render mode, sessionId
- `POST /c/<slug>/api/execute` – Execute a command against a scenario
- `POST /c/<slug>/api/load-spec` – Load/replace a scenario (loopback only)
- Legacy `/api/*` endpoints remain mapped to the default scenario for compatibility

## Scenario Format
Scenario JSON must follow the `CommandSpec v1.1` contract. See the bundled examples in `specs/` (e.g. `01-easy.json`, `02-easy.json`, `03-medium.json`, `04-medium.json`, `05-hard.json`, `06-hard.json`). Files placed under `specs/` are auto-loaded on startup with their filename (minus `.json`) used as the slug.

## Capability Reference

### 01-easy
| Policy Action | Representative Command |
| --- | --- |
| `iam:GetUser` | `aws iam get-user` |
| `iam:GetPolicyVersion` | `aws iam get-policy-version --policy-arn arn:aws:iam::123456789012:policy/S3PublicAccessHint --version-id v1` |
| `s3:GetObject` | `aws s3 cp s3://ctf-public-bucket/flag.txt -` |

### 02-easy
| Policy Action | Representative Command |
| --- | --- |
| `iam:ListGroupsForUser` | `aws iam list-groups-for-user --user-name userA` |
| `iam:GetPolicyVersion` | `aws iam get-policy-version --policy-arn arn:aws:iam::123456789012:policy/QueueReceivePublic --version-id v1` |
| `sqs:GetQueueAttributes` | `aws sqs get-queue-attributes --queue-url https://sqs.us-east-1.123456789012.amazonaws.com/123456789012/public-queue --attribute-names All` |

### 03-medium
| Policy Action | Representative Command |
| --- | --- |
| `iam:GetUserPolicy` | `aws iam get-user-policy --user-name userA --policy-name RDSPublicSnapshotAudit` |
| `rds:DescribeDBSnapshots` | `aws rds describe-db-snapshots --include-public` |
| `rds:ListTagsForResource` | `aws rds list-tags-for-resource --resource-name arn:aws:rds:us-east-1:123456789012:snapshot:ctf-public-snap` |

### 04-medium
| Policy Action | Representative Command |
| --- | --- |
| `iam:ListRoles` | `aws iam list-roles` |
| `iam:ListAttachedRolePolicies` | `aws iam list-attached-role-policies --role-name audit-role` |
| `sts:AssumeRole` | `aws sts assume-role --role-arn arn:aws:iam::123456789012:role/audit-role --role-session-name ctf` |

### 05-hard
| Policy Action | Representative Command |
| --- | --- |
| `iam:GetUserPolicy` | `aws iam get-user-policy --user-name userA --policy-name KMSDecryptNotes` |
| `kms:GetKeyPolicy` | `aws kms get-key-policy --key-id arn:aws:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555 --policy-name default` |
| `s3:GetObject` | `aws s3 cp s3://kms-lab-bucket/cipher.bin ./` |

### 06-hard
| Policy Action | Representative Command |
| --- | --- |
| `iam:GetRolePolicy` | `aws iam get-role-policy --role-name ecsTaskRole --policy-name TaskDiagnosticsAccess` |
| `ssm:DescribeParameters` | `aws ssm describe-parameters` |
| `ssm:GetParameter` | `aws ssm get-parameter --name /prod/app/flag --with-decryption` |

## Testing
Pytest covers core matcher behaviour:
```bash
pytest
```

## Logging
Command executions are logged to `logs/app.log` with flag-like data masked (`flag{***}`).

## Notes
- All state is stored in-memory; restarting the process clears sessions.
- The application never connects to real AWS services; every response is static JSON defined in the active `CommandSpec`.
