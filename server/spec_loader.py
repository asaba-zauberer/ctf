"""Utilities for loading and validating CommandSpec scenarios."""
from __future__ import annotations

import copy
import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


logger = logging.getLogger(__name__)

CAPABILITY_MAP: Dict[str, List[str]] = {
    "s3:ListAllMyBuckets": ["aws s3 ls"],
    "s3:ListBucket": ["aws s3 ls s3://"],
    "s3:GetObject": ["aws s3 cp s3://"],
    "sqs:ListQueues": ["aws sqs list-queues"],
    "sqs:GetQueueAttributes": ["aws sqs get-queue-attributes"],
    "kms:ListKeys": ["aws kms list-keys"],
    "kms:DescribeKey": ["aws kms describe-key"],
    "kms:GetKeyPolicy": ["aws kms get-key-policy"],
    "kms:Decrypt": ["aws kms decrypt"],
    "rds:DescribeDBSnapshots": ["aws rds describe-db-snapshots"],
    "rds:ListTagsForResource": ["aws rds list-tags-for-resource"],
    "iam:GetUser": ["aws iam get-user"],
    "iam:ListAttachedUserPolicies": ["aws iam list-attached-user-policies"],
    "iam:GetPolicy": ["aws iam get-policy"],
    "iam:ListPolicyVersions": ["aws iam list-policy-versions"],
    "iam:GetPolicyVersion": ["aws iam get-policy-version"],
    "iam:ListUserPolicies": ["aws iam list-user-policies"],
    "iam:GetUserPolicy": ["aws iam get-user-policy"],
    "iam:ListGroupsForUser": ["aws iam list-groups-for-user"],
    "iam:GetGroup": ["aws iam get-group"],
    "iam:ListAttachedGroupPolicies": ["aws iam list-attached-group-policies"],
    "iam:ListRoles": ["aws iam list-roles"],
    "iam:GetRole": ["aws iam get-role"],
    "iam:ListAttachedRolePolicies": ["aws iam list-attached-role-policies"],
    "iam:ListRolePolicies": ["aws iam list-role-policies"],
    "iam:GetRolePolicy": ["aws iam get-role-policy"],
    "sts:AssumeRole": ["aws sts assume-role"],
    "secretsmanager:ListSecrets": ["aws secretsmanager list-secrets"],
    "secretsmanager:GetSecretValue": ["aws secretsmanager get-secret-value"],
    "ssm:DescribeParameters": ["aws ssm describe-parameters"],
    "ssm:GetParameter": ["aws ssm get-parameter"],
}


class SpecValidationError(Exception):
    """Raised when the provided CommandSpec fails validation."""


@dataclass
class Scenario:
    """In-memory representation of a CommandSpec scenario."""

    slug: str
    name: str
    spec: Dict[str, Any]
    commands: List[Dict[str, Any]]
    default_render: str = "text"

    def fresh_state(self) -> Dict[str, Any]:
        """Return a deep copy of the initial state for a new session."""
        initial = self.spec.get("initialState") or {}
        # Ensure optional containers exist to simplify downstream logic.
        clone = copy.deepcopy(initial)
        clone.setdefault("env", {})
        clone.setdefault("custom", {})
        clone.setdefault("identities", [])
        clone.setdefault("region", None)
        return clone


class ScenarioManager:
    """Manage loaded scenarios addressed by slug."""

    def __init__(self) -> None:
        self._scenarios: Dict[str, Scenario] = {}
        self._default_slug: Optional[str] = None

    @property
    def default_slug(self) -> Optional[str]:
        return self._default_slug

    def load_from_file(self, path: Path, slug: Optional[str] = None) -> Scenario:
        data = json.loads(path.read_text(encoding="utf-8"))
        effective_slug = slug or path.stem
        return self.load_spec(effective_slug, data)

    def load_spec(self, slug: str, spec: Dict[str, Any]) -> Scenario:
        if not slug:
            raise SpecValidationError("Scenario slug is required")
        validated = validate_spec(spec, slug)
        scenario = Scenario(
            slug=slug,
            name=validated.get("meta", {}).get("name") or slug,
            spec=validated,
            commands=_compile_commands(validated.get("commands", [])),
            default_render=validated.get("meta", {}).get("defaultOutput", "text"),
        )
        self._scenarios[slug] = scenario
        if self._default_slug is None:
            self._default_slug = slug
        return scenario

    def load_directory(self, directory: Path) -> Dict[str, Scenario]:
        loaded: Dict[str, Scenario] = {}
        if not directory.exists():
            return loaded
        for path in sorted(directory.glob("*.json")):
            scenario = self.load_from_file(path, slug=path.stem)
            loaded[path.stem] = scenario
        return loaded

    def get(self, slug: str) -> Optional[Scenario]:
        return self._scenarios.get(slug)

    def all(self) -> Dict[str, Scenario]:
        return dict(self._scenarios)

    def reset_slug(self, slug: str) -> None:
        self._scenarios.pop(slug, None)
        if self._default_slug == slug:
            self._default_slug = next(iter(self._scenarios), None)

    def reset_all(self) -> None:
        self._scenarios.clear()
        self._default_slug = None


def validate_spec(spec: Dict[str, Any], slug: Optional[str] = None) -> Dict[str, Any]:
    if not isinstance(spec, dict):
        raise SpecValidationError("CommandSpec must be a JSON object")

    meta = spec.get("meta")
    if not isinstance(meta, dict):
        raise SpecValidationError("CommandSpec.meta must be an object")

    version = meta.get("version")
    if version != "1.1":
        raise SpecValidationError("CommandSpec.meta.version must be '1.1'")

    commands = spec.get("commands")
    if not isinstance(commands, list) or not commands:
        raise SpecValidationError("CommandSpec.commands must be a non-empty array")

    for index, command in enumerate(commands):
        if not isinstance(command, dict):
            raise SpecValidationError(f"commands[{index}] must be an object")
        match = command.get("match")
        if not isinstance(match, dict):
            raise SpecValidationError(f"commands[{index}].match must be an object")
        equals = match.get("equals")
        regex = match.get("regex")
        if equals is None and regex is None:
            raise SpecValidationError(
                f"commands[{index}].match must define 'equals' or 'regex'"
            )
        if equals is not None and not isinstance(equals, str):
            raise SpecValidationError(
                f"commands[{index}].match.equals must be a string when provided"
            )
        if regex is not None:
            if not isinstance(regex, str):
                raise SpecValidationError(
                    f"commands[{index}].match.regex must be a string when provided"
                )
            try:
                re.compile(regex)
            except re.error as exc:
                raise SpecValidationError(
                    f"commands[{index}].match.regex is invalid: {exc}"
                ) from exc

    fallback = spec.get("fallbackError")
    if fallback is not None and not isinstance(fallback, dict):
        raise SpecValidationError("fallbackError must be an object when provided")

    validated_spec = copy.deepcopy(spec)

    _run_capability_checks(validated_spec, slug)

    return validated_spec


def _compile_commands(commands: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    compiled: List[Dict[str, Any]] = []
    for command in commands:
        cmd_copy = copy.deepcopy(command)
        match = cmd_copy.get("match", {})
        regex = match.get("regex")
        if regex:
            match["_compiled_regex"] = re.compile(regex)
        compiled.append(cmd_copy)
    return compiled


def _run_capability_checks(spec: Dict[str, Any], slug: Optional[str]) -> None:
    actions_in_commands = _collect_actions_from_commands(spec)
    actions_in_identities = _collect_actions_from_identities(spec)

    missing_actions = actions_in_commands - actions_in_identities
    if missing_actions:
        logger.warning(
            "Scenario %s: actions required by commands but not granted: %s",
            slug or "<unknown>",
            ", ".join(sorted(missing_actions)),
        )

    command_matchers = _collect_command_matchers(spec)
    for action in sorted(actions_in_identities.intersection(CAPABILITY_MAP)):
        patterns = CAPABILITY_MAP[action]
        if not any(_pattern_matches(pattern, matcher) for pattern in patterns for matcher in command_matchers):
            logger.warning(
                "Scenario %s: no representative command found for action %s",
                slug or "<unknown>",
                action,
            )


def _collect_actions_from_commands(spec: Dict[str, Any]) -> Set[str]:
    actions: Set[str] = set()
    for command in spec.get("commands", []):
        requires = command.get("requires") or {}
        for action in requires.get("hasPoliciesAny", []) or []:
            actions.add(action)
    return actions


def _collect_actions_from_identities(spec: Dict[str, Any]) -> Set[str]:
    actions: Set[str] = set()
    identities = ((spec.get("initialState") or {}).get("identities") or [])
    for identity in identities:
        for action in identity.get("policies", []) or []:
            actions.add(action)
    return actions


def _collect_command_matchers(spec: Dict[str, Any]) -> List[str]:
    matchers: List[str] = []
    for command in spec.get("commands", []):
        match = command.get("match", {})
        if "regex" in match and isinstance(match["regex"], str):
            matchers.append(match["regex"])
        if "equals" in match and isinstance(match["equals"], str):
            matchers.append(match["equals"])
    return matchers


def _pattern_matches(pattern: str, matcher: str) -> bool:
    norm_pattern = _normalise_command_string(pattern)
    norm_matcher = _normalise_command_string(matcher)
    return norm_pattern in norm_matcher if norm_pattern else False


def _normalise_command_string(value: str) -> str:
    value = value.replace("^", " ").replace("$", " ")
    value = re.sub(r"\\s\*", " ", value)
    value = re.sub(r"\\s\+", " ", value)
    value = value.replace("\\", "")
    value = re.sub(r"\s+", " ", value)
    return value.strip().lower()
