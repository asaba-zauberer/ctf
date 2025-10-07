import copy

import pytest

from server.matcher import execute_command
from server.spec_loader import ScenarioManager


@pytest.fixture
def basic_scenario():
    spec = {
        "meta": {"name": "test", "version": "1.1", "defaultOutput": "text"},
        "commands": [
            {
                "match": {"regex": "^aws s3 ls$"},
                "response": {"text": "regex match\n"},
            },
            {
                "match": {"equals": "aws s3 ls"},
                "response": {"text": "equals match\n"},
            },
        ],
        "fallbackError": {
            "errorCode": "AccessDenied",
            "message": "Denied",
            "exitCode": 255,
        },
    }
    manager = ScenarioManager()
    scenario = manager.load_spec("test", spec)
    return scenario


def test_equals_priority_over_regex(basic_scenario):
    state = basic_scenario.fresh_state()
    result = execute_command(basic_scenario, state, "aws s3 ls")
    assert result["ok"] is True
    assert result["stdout"].strip() == "equals match"


def test_requires_region_set():
    spec = {
        "meta": {"name": "region-test", "version": "1.1"},
        "initialState": {"region": None},
        "commands": [
            {
                "match": {"equals": "aws ec2 describe-instances"},
                "requires": {"regionSet": True},
                "errorOnFail": {
                    "errorCode": "ValidationError",
                    "message": "region must be set",
                },
                "response": {"text": "instances"},
            }
        ],
    }
    manager = ScenarioManager()
    scenario = manager.load_spec("region-test", spec)
    state = scenario.fresh_state()

    # Fails because region is not set
    result = execute_command(scenario, copy.deepcopy(state), "aws ec2 describe-instances")
    assert result["ok"] is False
    assert result["errorCode"] == "ValidationError"

    # After setting region the command succeeds
    state["region"] = "us-east-1"
    success = execute_command(scenario, state, "aws ec2 describe-instances")
    assert success["ok"] is True
    assert success["stdout"].strip() == "instances"


def test_fallback_error_triggered(basic_scenario):
    result = execute_command(basic_scenario, basic_scenario.fresh_state(), "aws unknown")
    assert result["ok"] is False
    assert result["errorCode"] == "AccessDenied"
