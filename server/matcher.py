"""Command matching and execution against a CommandSpec."""
from __future__ import annotations

import copy
import json
from typing import Any, Dict, Optional

from .spec_loader import Scenario


def execute_command(
    scenario: Scenario, session_state: Dict[str, Any], raw_command: str
) -> Dict[str, Any]:
    command_spec = _find_matching_command(scenario, raw_command)
    if command_spec is None:
        return _build_error_response(scenario, scenario.spec.get("fallbackError"))

    requires = command_spec.get("requires")
    if requires and not _requires_satisfied(requires, session_state):
        error_on_fail = command_spec.get("errorOnFail")
        if error_on_fail:
            return _build_error_response(scenario, error_on_fail)
        return _build_error_response(scenario, scenario.spec.get("fallbackError"))

    new_state = copy.deepcopy(session_state)
    for mutation in command_spec.get("mutateState", []) or []:
        _apply_mutation(new_state, mutation)

    response_spec = command_spec.get("response", {}) or {}
    render = response_spec.get("render") or scenario.default_render
    stdout = response_spec.get("text", "")
    json_body = response_spec.get("json")

    if render == "json" and json_body is not None and not stdout:
        stdout = json.dumps(json_body, indent=2, sort_keys=True) + "\n"

    exit_code = response_spec.get("exitCode", 0)

    return {
        "ok": True,
        "render": render,
        "stdout": stdout,
        "json": json_body if json_body is not None else {},
        "exitCode": exit_code,
        "state": new_state,
    }


def _find_matching_command(scenario: Scenario, raw_command: str) -> Optional[Dict[str, Any]]:
    regex_candidates = []
    for command in scenario.commands:
        match = command.get("match", {})
        if match.get("equals") == raw_command:
            return command
        if "regex" in match and match.get("_compiled_regex") is not None:
            regex_candidates.append(command)
    for command in regex_candidates:
        matcher = command["match"]["_compiled_regex"]
        if matcher.fullmatch(raw_command):
            return command
    return None


def _requires_satisfied(requires: Dict[str, Any], state: Dict[str, Any]) -> bool:
    if requires.get("regionSet") and not state.get("region"):
        return False

    if env := requires.get("env"):
        env_state = state.get("env") or {}
        for key, expected in env.items():
            if env_state.get(key) != expected:
                return False

    if raw_state := requires.get("state"):
        for path, expected in raw_state.items():
            actual = _get_path(state, path)
            if actual != expected:
                return False

    active_identity = state.get("activeIdentity")
    identities = state.get("identities") or []
    identity_record = next(
        (identity for identity in identities if identity.get("id") == active_identity),
        None,
    )

    if requires.get("activeIdentity") and requires["activeIdentity"] != active_identity:
        return False

    policies = set(identity_record.get("policies", [])) if identity_record else set()

    if any_required := requires.get("hasPoliciesAny"):
        if not policies.intersection(set(any_required)):
            return False

    if all_required := requires.get("hasPoliciesAll"):
        if not set(all_required).issubset(policies):
            return False

    return True


def _apply_mutation(state: Dict[str, Any], mutation: Dict[str, Any]) -> None:
    op = mutation.get("op")
    path = mutation.get("path")
    if not op or not path:
        return

    parent, key = _resolve_parent(state, path)
    if parent is None:
        return

    if op == "set":
        _set_value(parent, key, mutation.get("value"))
    elif op == "unset":
        _unset_value(parent, key)
    elif op == "push":
        _push_value(parent, key, mutation.get("value"))


def _resolve_parent(state: Dict[str, Any], path: str):
    parts = path.split(".")
    if len(parts) == 1:
        return state, parts[0]
    current = state
    for part in parts[:-1]:
        if isinstance(current, dict):
            if part not in current or current[part] is None:
                current[part] = {}
            current = current[part]
        elif isinstance(current, list):
            try:
                index = int(part)
            except ValueError:
                raise TypeError(
                    f"Cannot traverse non-numeric list index at segment '{part}'"
                ) from None
            while index >= len(current):
                current.append({})
            current = current[index]
        else:
            raise TypeError(f"Cannot traverse non-container at segment '{part}'")
    return current, parts[-1]


def _get_path(state: Dict[str, Any], path: str) -> Any:
    current: Any = state
    for segment in path.split("."):
        if isinstance(current, dict):
            current = current.get(segment)
        elif isinstance(current, list):
            try:
                index = int(segment)
                current = current[index]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return current


def _build_error_response(scenario: Scenario, error_spec: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    error_code = "AccessDenied"
    message = "An error occurred"
    exit_code = 255
    if error_spec:
        error_code = error_spec.get("errorCode", error_code)
        message = error_spec.get("message", message)
        exit_code = error_spec.get("exitCode", exit_code)
    return {
        "ok": False,
        "errorCode": error_code,
        "message": message,
        "exitCode": exit_code,
    }


def _set_value(container: Any, key: str, value: Any) -> None:
    if isinstance(container, dict):
        container[key] = copy.deepcopy(value)
    elif isinstance(container, list):
        index = _safe_index(key)
        if index is None:
            raise TypeError(f"List path segment '{key}' is not an integer")
        while index >= len(container):
            container.append(None)
        container[index] = copy.deepcopy(value)
    else:
        raise TypeError("Unsupported container type for set operation")


def _unset_value(container: Any, key: str) -> None:
    if isinstance(container, dict):
        container.pop(key, None)
    elif isinstance(container, list):
        index = _safe_index(key)
        if index is None:
            return
        if 0 <= index < len(container):
            container.pop(index)


def _push_value(container: Any, key: str, value: Any) -> None:
    if isinstance(container, dict):
        target = container.get(key)
        if target is None:
            container[key] = [copy.deepcopy(value)]
        elif isinstance(target, list):
            target.append(copy.deepcopy(value))
        else:
            raise TypeError(f"Cannot push into non-list at key '{key}'")
    elif isinstance(container, list):
        index = _safe_index(key)
        if index is None:
            raise TypeError(f"List path segment '{key}' is not an integer")
        while index >= len(container):
            container.append([])
        if not isinstance(container[index], list):
            raise TypeError(f"Cannot push into non-list at index '{key}'")
        container[index].append(copy.deepcopy(value))


def _safe_index(segment: str) -> Optional[int]:
    try:
        return int(segment)
    except (ValueError, TypeError):
        return None
