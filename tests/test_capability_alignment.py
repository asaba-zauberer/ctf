import json
import re
from pathlib import Path

import pytest

from server.spec_loader import CAPABILITY_MAP

SPECS_DIR = Path(__file__).resolve().parents[1] / "specs"
SPEC_PATHS = sorted(SPECS_DIR.glob("*.json"))


def load_spec(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def collect_actions_from_identities(spec):
    actions = set()
    for identity in spec.get("initialState", {}).get("identities", []) or []:
        for action in identity.get("policies", []) or []:
            actions.add(action)
    return actions


def collect_actions_from_commands(spec):
    actions = set()
    for command in spec.get("commands", []) or []:
        requires = command.get("requires") or {}
        for action in requires.get("hasPoliciesAny", []) or []:
            actions.add(action)
    return actions


def command_match_strings(spec):
    strings = []
    for command in spec.get("commands", []) or []:
        match = command.get("match", {})
        if "regex" in match and isinstance(match["regex"], str):
            strings.append(match["regex"])
        if "equals" in match and isinstance(match["equals"], str):
            strings.append(match["equals"])
    return strings


def pattern_matches(pattern: str, matcher: str) -> bool:
    return normalise(pattern) in normalise(matcher) if pattern else False


def normalise(value: str) -> str:
    value = value.replace("^", " ").replace("$", " ")
    value = re.sub(r"\\s\*", " ", value)
    value = re.sub(r"\\s\+", " ", value)
    value = value.replace("\\", "")
    value = re.sub(r"\s+", " ", value)
    return value.strip().lower()


@pytest.mark.parametrize("spec_path", SPEC_PATHS)
def test_actions_in_commands_are_granted(spec_path):
    spec = load_spec(spec_path)
    granted = collect_actions_from_identities(spec)
    required = collect_actions_from_commands(spec)
    assert required.issubset(granted), f"{spec_path.name}: requires {required - granted}"


@pytest.mark.parametrize("spec_path", SPEC_PATHS)
def test_major_actions_have_commands(spec_path):
    spec = load_spec(spec_path)
    granted = collect_actions_from_identities(spec)
    matchers = command_match_strings(spec)
    for action in granted:
        if action in CAPABILITY_MAP:
            patterns = CAPABILITY_MAP[action]
            assert any(
                pattern_matches(pattern, matcher)
                for pattern in patterns
                for matcher in matchers
            ), f"{spec_path.name}: action {action} has no representative command"


@pytest.mark.parametrize("spec_path", SPEC_PATHS)
def test_capability_commands_require_region(spec_path):
    spec = load_spec(spec_path)
    matchers = command_match_strings(spec)
    for command in spec.get("commands", []) or []:
        match = command.get("match", {})
        matcher_strings = []
        if "regex" in match and isinstance(match["regex"], str):
            matcher_strings.append(match["regex"])
        if "equals" in match and isinstance(match["equals"], str):
            matcher_strings.append(re.escape(match["equals"]))
        requires = command.get("requires") or {}
        for action, patterns in CAPABILITY_MAP.items():
            if any(pattern_matches(pattern, m) for pattern in patterns for m in matcher_strings):
                assert requires.get("regionSet") is True, (
                    f"{spec_path.name}: command {match} for action {action} must require region"
                )
