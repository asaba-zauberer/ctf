"""シナリオJSON用の補助関数群。"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple

from .json_loader import load_json_strict

ScenarioItem = Dict[str, object]

# サービスごとの既知コマンドを小さく定義。将来拡張しやすい形で保持する。
KNOWN_COMMANDS: Dict[str, Set[str]] = {
    "sts": {"get-caller-identity"},
    "s3": {"ls", "cp"},
    "iam": {
        "list-users",
        "get-user",
        "list-attached-user-policies",
        "list-user-policies",
        "get-user-policy",
        "list-roles",
        "get-role",
        "list-attached-role-policies",
        "simulate-principal-policy",
    },
    "sqs": {
        "list-queues",
        "get-queue-url",
        "get-queue-attributes",
        "receive-message",
    },
    "kms": {
        "list-keys",
        "describe-key",
        "get-key-policy",
        "decrypt",
    },
    "lambda": {
        "list-functions",
        "get-function-configuration",
        "update-function-configuration",
        "update-function-code",
        "invoke",
    },
    "secretsmanager": {
        "get-secret-value",
    },
    "s3api": {
        "list-object-versions",
    },
}


def iter_scenario_files(spec_dir: Path) -> Iterator[Path]:
    """credentials.json 以外のシナリオJSONをソートして返す。"""
    files = [p for p in spec_dir.glob("*.json") if p.name != "credentials.json"]
    for path in sorted(files, key=_scenario_sort_key):
        yield path


def _scenario_sort_key(path: Path) -> Tuple[int, str]:
    prefix = extract_numeric_prefix(path.name)
    numeric = prefix if prefix is not None else 10 ** 9
    return numeric, path.name


def extract_numeric_prefix(name: str) -> Optional[int]:
    match = re.match(r"(\d+)", name)
    if not match:
        return None
    return int(match.group(1))


def load_scenario(path: Path) -> List[ScenarioItem]:
    data = load_json_strict(path)
    if not isinstance(data, list):
        raise TypeError(
            f"{path}: シナリオJSONのトップは配列である必要があります。配列に修正してください。"
        )
    return data


def iter_requests(scenario: Sequence[ScenarioItem]) -> Iterator[Tuple[int, Dict[str, object]]]:
    for idx, item in enumerate(scenario):
        request = item.get("request")
        if not isinstance(request, dict):
            continue
        yield idx, request


def iter_responses(scenario: Sequence[ScenarioItem]) -> Iterator[Tuple[int, Dict[str, object]]]:
    for idx, item in enumerate(scenario):
        response = item.get("response")
        if not isinstance(response, dict):
            continue
        yield idx, response


def request_signature(request: Dict[str, object]) -> Tuple[str, str]:
    if "equals" in request:
        value = request.get("equals")
        return "equals", str(value)
    if "regex" in request:
        value = request.get("regex")
        return "regex", str(value)
    return "unknown", ""


def split_aws_command(command: str) -> Optional[Tuple[str, str]]:
    tokens = command.strip().split()
    if len(tokens) < 3:
        return None
    if tokens[0] != "aws":
        return None
    return tokens[1], tokens[2]


def is_known_command(service: str, operation: str) -> bool:
    return operation in KNOWN_COMMANDS.get(service, set())


AWS_COMMAND_PATTERN = re.compile(r"^aws\s+", re.ASCII)


def starts_with_aws(command: str) -> bool:
    return AWS_COMMAND_PATTERN.match(command) is not None


def list_credentials(spec_dir: Path) -> List[Dict[str, object]]:
    path = spec_dir / "credentials.json"
    raw = load_json_strict(path)
    if not isinstance(raw, dict):
        raise TypeError(
            f"{path}: credentials.json のトップはオブジェクトである必要があります。オブジェクト形式に修正してください。"
        )
    credentials = raw.get("credentials")
    if not isinstance(credentials, list):
        raise TypeError(
            f"{path}: 'credentials' キーは配列である必要があります。配列を設定してください。"
        )
    return credentials
