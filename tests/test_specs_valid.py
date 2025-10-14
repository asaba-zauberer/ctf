from __future__ import annotations

import re
from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

from typing import Dict, Iterable, Iterator, List, Sequence, Set, Tuple

import pytest

from tests.helpers.json_loader import JsonLoaderError, load_json_strict
from tests.helpers.spec_utils import (
    KNOWN_COMMANDS,
    extract_numeric_prefix,
    is_known_command,
    iter_requests,
    iter_responses,
    iter_scenario_files,
    list_credentials,
    load_scenario,
    request_signature,
    split_aws_command,
    starts_with_aws,
)

ACCOUNT_ID = "123456789012"
ARN_PREFIX = f"arn:aws:iam::{ACCOUNT_ID}:"


@pytest.fixture(scope="module")
def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def spec_dir(project_root: Path) -> Path:
    path = project_root / "spec"
    if not path.exists():
        pytest.fail("spec ディレクトリが見つかりません。spec/ を作成し JSON を配置してください。")
    if not path.is_dir():
        pytest.fail("spec がディレクトリではありません。ディレクトリに修正してください。")
    return path


@pytest.fixture(scope="module")
def credentials(spec_dir: Path) -> List[Dict[str, object]]:
    path = spec_dir / "credentials.json"
    if not path.exists():
        pytest.fail("spec/credentials.json が存在しません。必要なクレデンシャルを追加してください。")
    creds = list_credentials(spec_dir)
    return creds


@pytest.fixture(scope="module")
def credential_users(credentials: Sequence[Dict[str, object]]) -> Set[str]:
    return {
        str(item.get("user"))
        for item in credentials
        if isinstance(item.get("user"), str)
    }


@pytest.fixture(scope="module")
def scenario_files(spec_dir: Path) -> List[Path]:
    files = list(iter_scenario_files(spec_dir))
    return files


@pytest.fixture(scope="module")
def scenarios(scenario_files: Sequence[Path]) -> List[Tuple[Path, List[Dict[str, object]]]]:
    loaded: List[Tuple[Path, List[Dict[str, object]]]] = []
    for path in scenario_files:
        loaded.append((path, load_scenario(path)))
    return loaded


def _iter_scenario_items(
    scenarios: Sequence[Tuple[Path, List[Dict[str, object]]]]
) -> Iterator[Tuple[Path, int, Dict[str, object]]]:
    for path, items in scenarios:
        for index, item in enumerate(items):
            if not isinstance(item, dict):
                pytest.fail(f"{path}: インデックス{index}がオブジェクトではありません。辞書形式に修正してください。")
            yield path, index, item


# credentials.json 関連

def test_credentials_structure(credentials: Sequence[Dict[str, object]]) -> None:
    required_keys = {"access_key", "secret_key", "user", "description"}
    for idx, entry in enumerate(credentials):
        assert isinstance(entry, dict), f"credentials.json: インデックス{idx}がオブジェクトではありません。辞書に修正してください。"
        missing = required_keys - entry.keys()
        assert not missing, f"credentials.json: インデックス{idx}で {missing} が未設定です。必須キーを追加してください。"
        for key in required_keys:
            value = entry.get(key)
            assert isinstance(value, str) and value, (
                f"credentials.json: インデックス{idx}の '{key}' は非空の文字列である必要があります。値を見直してください。"
            )


def test_credentials_access_key_format(credentials: Sequence[Dict[str, object]]) -> None:
    pattern = re.compile(r"^AKIA0[1-9]CTF[A-Z0-9]{11}$")
    for idx, entry in enumerate(credentials):
        access_key = str(entry.get("access_key"))
        assert pattern.fullmatch(access_key), (
            f"credentials.json: インデックス{idx}の access_key が 'AKIA0xCTF' プレフィックスの20文字英大数字に一致しません。"
        )


def test_credentials_secret_key_format(credentials: Sequence[Dict[str, object]]) -> None:
    for idx, entry in enumerate(credentials):
        secret_key = str(entry.get("secret_key"))
        assert secret_key.startswith("ctf0"), (
            f"credentials.json: インデックス{idx}の secret_key は 'ctf0' で始まる必要があります。"
        )
        assert secret_key[4].isdigit() and secret_key[4] != '0', (
            f"credentials.json: インデックス{idx}の secret_key のバージョン桁が不正です。"
        )
        suffix = secret_key[5:]
        assert suffix.isalnum(), (
            f"credentials.json: インデックス{idx}の secret_key が英数字以外の文字を含んでいます。"
        )
        assert len(secret_key) in {38, 40, 41}, (
            f"credentials.json: インデックス{idx}の secret_key の長さが想定外です。"
        )


def test_credentials_access_key_uniqueness(credentials: Sequence[Dict[str, object]]) -> None:
    seen: Set[str] = set()
    for idx, entry in enumerate(credentials):
        access_key = str(entry.get("access_key"))
        assert access_key not in seen, (
            f"credentials.json: access_key '{access_key}' が重複しています。ユニークになるよう修正してください。"
        )
        seen.add(access_key)


def test_credentials_user_uniqueness(credentials: Sequence[Dict[str, object]]) -> None:
    seen: Set[str] = set()
    for idx, entry in enumerate(credentials):
        user = str(entry.get("user"))
        assert user not in seen, (
            f"credentials.json: user '{user}' が重複しています。別のユーザー名に修正してください。"
        )
        seen.add(user)


# シナリオファイル関連

def test_scenario_numeric_prefix_unique(scenario_files: Sequence[Path]) -> None:
    prefixes: Dict[int, Path] = {}
    for path in scenario_files:
        prefix = extract_numeric_prefix(path.name)
        if prefix is None:
            continue
        if prefix in prefixes:
            pytest.fail(
                f"{path}: 数字プリフィックス {prefix} が {prefixes[prefix]} と重複しています。一意な番号に変更してください。"
            )
        prefixes[prefix] = path


def test_scenarios_contain_valid_items(scenarios: Sequence[Tuple[Path, List[Dict[str, object]]]]) -> None:
    if not scenarios:
        pytest.skip("シナリオJSONが存在しません。準備ができたら追加してください。")
    for path, items in scenarios:
        assert items, f"{path}: 要素が空です。少なくとも1件のシナリオを追加してください。"
        for index, item in enumerate(items):
            assert "role" in item, f"{path}: インデックス{index}で role が欠落しています。role を追加してください。"
            assert isinstance(item["role"], str) and item["role"], (
                f"{path}: インデックス{index}の role は非空の文字列である必要があります。"
            )
            assert "request" in item, f"{path}: インデックス{index}で request が欠落しています。request を追加してください。"
            assert isinstance(item["request"], dict), (
                f"{path}: インデックス{index}の request がオブジェクトではありません。辞書形式に修正してください。"
            )
            assert "response" in item, f"{path}: インデックス{index}で response が欠落しています。response を追加してください。"
            assert isinstance(item["response"], dict), (
                f"{path}: インデックス{index}の response がオブジェクトではありません。辞書形式に修正してください。"
            )


def test_request_exclusive_fields(scenarios: Sequence[Tuple[Path, List[Dict[str, object]]]]) -> None:
    if not scenarios:
        pytest.skip("シナリオJSONが存在しません。")
    for path, items in scenarios:
        for index, request in iter_requests(items):
            has_equals = "equals" in request
            has_regex = "regex" in request
            assert has_equals ^ has_regex, (
                f"{path}: インデックス{index}の request は equals と regex のどちらか一方のみ指定してください。"
            )
            if has_equals:
                value = request["equals"]
                assert isinstance(value, str) and value.strip(), (
                    f"{path}: インデックス{index}の request.equals は非空の文字列にしてください。"
                )
            if has_regex:
                value = request["regex"]
                assert isinstance(value, str) and value.strip(), (
                    f"{path}: インデックス{index}の request.regex は非空の文字列にしてください。"
                )


def test_request_equals_command_format(scenarios: Sequence[Tuple[Path, List[Dict[str, object]]]]) -> None:
    if not scenarios:
        pytest.skip("シナリオJSONが存在しません。")
    for path, items in scenarios:
        for index, request in iter_requests(items):
            if "equals" not in request:
                continue
            command = str(request["equals"])
            assert starts_with_aws(command), (
                f"{path}: インデックス{index}のコマンド '{command}' は 'aws ' で始めてください。"
            )
            split = split_aws_command(command)
            assert split is not None, (
                f"{path}: インデックス{index}のコマンド '{command}' は 'aws <サービス> <オペレーション>' 形式にしてください。"
            )
            if split is None:
                continue
            service, operation = split
            assert is_known_command(service, operation), (
                f"{path}: インデックス{index}のコマンド '{service} {operation}' はホワイトリストにありません。KNOWN_COMMANDS を更新するか、コマンドを見直してください。"
            )


def test_request_regex_format_and_compile(scenarios: Sequence[Tuple[Path, List[Dict[str, object]]]]) -> None:
    if not scenarios:
        pytest.skip("シナリオJSONが存在しません。")
    for path, items in scenarios:
        for index, request in iter_requests(items):
            if "regex" not in request:
                continue
            pattern_text = str(request["regex"])
            assert pattern_text.startswith("^"), (
                f"{path}: インデックス{index}の request.regex は '^' で始めてください。"
            )
            assert pattern_text.startswith(r"^aws\s+"), (
                f"{path}: インデックス{index}の request.regex は '^aws\\s+' で始める必要があります。"
            )
            try:
                re.compile(pattern_text)
            except re.error as exc:
                pytest.fail(
                    f"{path}: インデックス{index}の request.regex '{pattern_text}' が正規表現エラー ({exc}) です。修正してください。"
                )


def test_request_no_duplicates(scenarios: Sequence[Tuple[Path, List[Dict[str, object]]]]) -> None:
    if not scenarios:
        pytest.skip("シナリオJSONが存在しません。")
    for path, items in scenarios:
        signatures: Set[Tuple[str, str]] = set()
        for index, request in iter_requests(items):
            signature = request_signature(request)
            assert signature[0] != "unknown", (
                f"{path}: インデックス{index}の request に equals/regex がありません。"
            )
            assert signature not in signatures, (
                f"{path}: インデックス{index}の request {signature} が重複しています。一意なリクエストにしてください。"
            )
            signatures.add(signature)


def test_response_exclusive_fields(scenarios: Sequence[Tuple[Path, List[Dict[str, object]]]]) -> None:
    if not scenarios:
        pytest.skip("シナリオJSONが存在しません。")
    for path, items in scenarios:
        for index, response in iter_responses(items):
            has_text = "text" in response
            has_render = "render" in response
            has_json = "json" in response
            assert has_text ^ (has_render and has_json), (
                f"{path}: インデックス{index}の response は text か render/json のどちらか一方のみ指定してください。"
            )
            if has_text:
                value = response.get("text")
                assert isinstance(value, str), (
                    f"{path}: インデックス{index}の response.text は文字列にしてください。"
                )
            if has_render or has_json:
                assert response.get("render") == "json", (
                    f"{path}: インデックス{index}の response.render は 'json' のみ許可されます。"
                )
                assert "json" in response, (
                    f"{path}: インデックス{index}の response は json ペイロードを含めてください。"
                )


def _iter_json_payloads(scenarios: Sequence[Tuple[Path, List[Dict[str, object]]]]) -> Iterator[Tuple[Path, int, object]]:
    for path, items in scenarios:
        for index, response in iter_responses(items):
            if response.get("render") == "json" and "json" in response:
                yield path, index, response["json"]


def _walk_json(value: object) -> Iterator[Tuple[List[str], object]]:
    stack: List[Tuple[List[str], object]] = [([], value)]
    while stack:
        path, current = stack.pop()
        yield path, current
        if isinstance(current, dict):
            for key, child in current.items():
                stack.append((path + [str(key)], child))
        elif isinstance(current, list):
            for idx, child in enumerate(current):
                stack.append((path + [str(idx)], child))


def test_json_response_account_and_arn(scenarios: Sequence[Tuple[Path, List[Dict[str, object]]]]) -> None:
    payloads = list(_iter_json_payloads(scenarios))
    if not payloads:
        pytest.skip("JSONレスポンスが存在しません。")
    for path, index, payload in payloads:
        for json_path, value in _walk_json(payload):
            if json_path and json_path[-1] == "Account" and isinstance(value, str):
                assert value == ACCOUNT_ID, (
                    f"{path}: インデックス{index}の JSON Account 値 '{value}' が {ACCOUNT_ID} と一致しません。Account ID を修正してください。"
                )
            if isinstance(value, str) and value.startswith("arn:aws:iam::"):
                assert value.startswith(ARN_PREFIX), (
                    f"{path}: インデックス{index}の Arn '{value}' が {ARN_PREFIX} で始まりません。アカウントIDを揃えてください。"
                )


def test_roles_exist_in_credentials(
    scenarios: Sequence[Tuple[Path, List[Dict[str, object]]]], credential_users: Set[str]
) -> None:
    if not scenarios:
        pytest.skip("シナリオJSONが存在しません。")
    missing: List[str] = []
    for path, items in scenarios:
        for index, item in enumerate(items):
            role = item.get("role")
            if not isinstance(role, str):
                continue
            if role not in credential_users:
                missing.append(f"{path.name}#idx{index}:{role}")
    assert not missing, (
        "シナリオの role に未登録ユーザーがあります: "
        + ", ".join(missing)
        + "。credentials.json に対応する user を追加してください。"
    )


def test_s3_commands_have_targets(scenarios: Sequence[Tuple[Path, List[Dict[str, object]]]]) -> None:
    commands: List[Tuple[Path, int, str]] = []
    for path, items in scenarios:
        for index, request in iter_requests(items):
            command = request.get("equals")
            if not isinstance(command, str):
                continue
            split = split_aws_command(command)
            if not split:
                continue
            service, operation = split
            if service != "s3":
                continue
            commands.append((path, index, command))
            tokens = command.split()
            if operation == "ls":
                if len(tokens) == 3:
                    continue
                min_tokens = 4
            elif operation == "cp":
                min_tokens = 4
            else:
                min_tokens = 5
            assert len(tokens) >= min_tokens, (
                f"{path}: インデックス{index}の S3 コマンド '{command}' が短すぎます。対象バケット/パスを明示してください。"
            )
    if not commands:
        pytest.skip("S3 コマンドが存在しません。追加時に再実行してください。")


# 追加の整合性チェック

def test_credentials_json_is_valid_utf8(spec_dir: Path) -> None:
    path = spec_dir / "credentials.json"
    try:
        load_json_strict(path)
    except JsonLoaderError as exc:
        pytest.fail(str(exc))


def test_scenario_files_are_valid_utf8(scenario_files: Sequence[Path]) -> None:
    for path in scenario_files:
        try:
            load_json_strict(path)
        except JsonLoaderError as exc:
            pytest.fail(str(exc))


def test_known_commands_not_empty() -> None:
    assert KNOWN_COMMANDS, "KNOWN_COMMANDS が空です。最低1サービスは登録してください。"
