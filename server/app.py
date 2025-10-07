"""Flask application factory for the AWS CLI themed CTF app."""
from __future__ import annotations

import re
import uuid
from pathlib import Path
from typing import Any, Dict

from flask import (
    Flask,
    abort,
    jsonify,
    make_response,
    request,
    send_from_directory,
)

from .logging_utils import configure_logging, mask_sensitive
from .matcher import execute_command
from .rate_limit import RateLimitExceeded, RateLimiter
from .spec_loader import ScenarioManager, SpecValidationError
from .state_store import SessionStateStore

APP_ROOT = Path(__file__).resolve().parent.parent
FRONTEND_DIR = APP_ROOT / "frontend"
SPECS_DIR = APP_ROOT / "specs"
LOG_DIR = APP_ROOT / "logs"
SESSION_COOKIE_PREFIX = "sessionId"
CLI_COOKIE_NAME = f"{SESSION_COOKIE_PREFIX}_cli"
RATE_LIMIT_PER_SECOND = 5


def create_app() -> Flask:
    app = Flask(
        __name__,
        static_folder=None,
    )

    logger = configure_logging(LOG_DIR, enable=app.debug)
    scenario_manager = ScenarioManager()
    state_store = SessionStateStore()
    rate_limiter = RateLimiter(limit=RATE_LIMIT_PER_SECOND, interval_seconds=1.0)

    loaded = scenario_manager.load_directory(SPECS_DIR)
    if loaded:
        logger.info("Loaded scenarios: %s", ", ".join(sorted(loaded.keys())))
    else:
        logger.warning("No CommandSpec scenarios found in %s", SPECS_DIR)

    def _require_scenario(slug: str):
        scenario = scenario_manager.get(slug)
        if scenario is None:
            abort(404, description=f"Scenario '{slug}' not found")
        return scenario

    def _get_or_create_cli_session_id() -> str:
        session_id = request.cookies.get(CLI_COOKIE_NAME)
        if not session_id:
            session_id = _generate_session_id()
        default_slug = scenario_manager.default_slug
        if default_slug:
            scenario = scenario_manager.get(default_slug)
            if scenario is not None:
                state_store.ensure_session(default_slug, session_id, scenario)
        return session_id

    def _scenario_listing() -> Dict[str, Any]:
        scenarios = scenario_manager.all()
        ordered = sorted(scenarios.items(), key=lambda item: item[1].name)
        return {
            slug: {
                "name": scenario.name,
                "defaultOutput": scenario.default_render,
            }
            for slug, scenario in ordered
        }

    @app.after_request
    def add_cors_headers(response):  # type: ignore[override]
        # Local development convenience; adjust as needed.
        response.headers.setdefault("Cache-Control", "no-store")
        return response

    @app.route("/")
    def index() -> Any:
        scenarios = scenario_manager.all()
        if not scenarios:
            return (
                "<h1>No scenarios available</h1><p>Add CommandSpec JSON files under /specs.</p>",
                503,
            )
        scenario_links = "".join(
            f"<li><a href='/intro/{slug}/'>{scenario.name}</a></li>"
            for slug, scenario in sorted(
                scenarios.items(), key=lambda item: item[1].name
            )
        )
        return (
            "<h1>CTF Challenges</h1>"
            "<p><a href='/cli/'>Shared CLI Terminal</a></p>"
            f"<h2>Introductions</h2><ul>{scenario_links}</ul>"
        )

    @app.route("/cli/")
    def cli_index() -> Any:
        if not scenario_manager.all():
            return (
                "<h1>No scenarios available</h1><p>Add CommandSpec JSON files under /specs.</p>",
                503,
            )
        response = make_response(send_from_directory(FRONTEND_DIR, "index.html"), 200)
        session_id = request.cookies.get(CLI_COOKIE_NAME)
        if not session_id:
            session_id = _generate_session_id()
        response.set_cookie(
            CLI_COOKIE_NAME,
            session_id,
            max_age=1800,
            httponly=True,
            samesite="Lax",
            path="/cli/",
        )
        return response

    @app.route("/cli/main.js")
    def cli_js() -> Any:
        return send_from_directory(FRONTEND_DIR, "main.js")

    @app.route("/cli/api/health", methods=["GET"])
    def cli_health() -> Any:
        if not scenario_manager.all():
            return jsonify({"error": "scenario_not_loaded"}), 503
        return jsonify({"status": "ok"})

    @app.route("/cli/api/meta", methods=["GET"])
    def cli_meta() -> Any:
        scenarios = _scenario_listing()
        if not scenarios:
            return jsonify({"error": "scenario_not_loaded"}), 503

        session_id = _get_or_create_cli_session_id()
        payload = {
            "cliName": "Shared CLI Terminal",
            "sessionId": session_id,
            "scenarios": [
                {
                    "slug": slug,
                    "name": data["name"],
                    "defaultOutput": data["defaultOutput"],
                }
                for slug, data in scenarios.items()
            ],
            "defaultScenario": scenario_manager.default_slug,
        }
        response = jsonify(payload)
        response.set_cookie(
            CLI_COOKIE_NAME,
            session_id,
            max_age=1800,
            httponly=True,
            samesite="Lax",
            path="/cli/",
        )
        return response

    @app.route("/cli/api/execute", methods=["POST"])
    def cli_execute() -> Any:
        payload = request.get_json(silent=True) or {}
        command = payload.get("command")
        session_id = payload.get("sessionId")
        scenario_slug = payload.get("scenarioSlug")

        if not isinstance(session_id, str) or not isinstance(command, str):
            return (
                jsonify({"ok": False, "message": "Invalid request payload"}),
                400,
            )
        if not isinstance(scenario_slug, str):
            return (
                jsonify({"ok": False, "message": "scenarioSlug is required"}),
                400,
            )

        cookie_session = request.cookies.get(CLI_COOKIE_NAME)
        if cookie_session and cookie_session != session_id:
            return jsonify({"ok": False, "message": "Session mismatch"}), 403

        scenario = _require_scenario(scenario_slug)

        try:
            rate_limiter.hit(f"{scenario_slug}:{session_id}")
        except RateLimitExceeded:
            return jsonify({"ok": False, "message": "Too Many Requests"}), 429

        state = state_store.get_state(scenario_slug, session_id, scenario)
        result = execute_command(scenario, state, command.strip())

        log_payload: Dict[str, Any] = {
            "slug": scenario_slug,
            "sessionId": session_id,
            "command": command,
            "ok": result.get("ok"),
            "exitCode": result.get("exitCode"),
        }

        if result.get("ok"):
            state_store.update_state(scenario_slug, session_id, scenario, result["state"])
            log_payload["stdout"] = mask_sensitive(result.get("stdout"))
            logger.info("command ok %s", log_payload)
            return jsonify(
                {
                    "ok": True,
                    "render": result.get("render"),
                    "stdout": result.get("stdout", ""),
                    "json": result.get("json", {}),
                    "exitCode": result.get("exitCode", 0),
                }
            )

        log_payload["errorCode"] = result.get("errorCode")
        log_payload["message"] = mask_sensitive(result.get("message"))
        logger.info("command error %s", log_payload)
        payload = {
            "ok": False,
            "errorCode": result.get("errorCode"),
            "message": result.get("message"),
            "exitCode": result.get("exitCode", 255),
        }
        return jsonify(payload)

    @app.route("/cli/api/fetch", methods=["GET"])
    def cli_fetch() -> Any:
        scenario_slug = request.args.get("scenarioSlug")
        session_id = request.args.get("sessionId")
        url = request.args.get("url")

        if not isinstance(session_id, str) or not session_id:
            return jsonify({"error": "sessionId is required"}), 400
        if not isinstance(scenario_slug, str) or not scenario_slug:
            return jsonify({"error": "scenarioSlug is required"}), 400
        if not isinstance(url, str) or not url:
            return jsonify({"error": "url is required"}), 400

        cookie_session = request.cookies.get(CLI_COOKIE_NAME)
        if cookie_session and cookie_session != session_id:
            return jsonify({"error": "Session mismatch"}), 403

        scenario = _require_scenario(scenario_slug)

        rate_key = f"{scenario_slug}:{session_id}:fetch"
        try:
            rate_limiter.hit(rate_key)
        except RateLimitExceeded:
            return jsonify({"error": "Too Many Requests"}), 429

        ecs_pattern = re.compile(
            r"^http://169\.254\.170\.2(?:/latest)?/v2/credentials/[A-Za-z0-9\-]+$"
        )

        if not ecs_pattern.fullmatch(url):
            return (
                jsonify({"error": "Fetcher only supports ECS task metadata endpoints"}),
                403,
            )

        state = state_store.get_state(scenario_slug, session_id, scenario)
        state["activeIdentity"] = "ecsmeta-task-role"
        state_store.update_state(scenario_slug, session_id, scenario, state)

        credentials = {
            "RoleArn": "arn:aws:iam::123456789012:role/ecsTaskRole",
            "AccessKeyId": "ASIAECSDEMOEXAMPLE",
            "SecretAccessKey": "abc123example/secretkey",
            "Token": "IQoJb3JpZ2luX2VjE...truncated...",
            "LastUpdated": "2025-10-04T00:00:02Z",
            "Expiration": "2025-10-04T06:00:00Z",
        }
        logger.info(
            "fetch ok %s",
            {
                "slug": scenario_slug,
                "sessionId": session_id,
                "url": url,
                "identity": "ecsmeta-task-role",
            },
        )
        return jsonify(credentials)

    @app.route("/cli/api/load-spec", methods=["POST"])
    def cli_load_spec() -> Any:
        if request.remote_addr not in {"127.0.0.1", "::1"}:
            return jsonify({"error": "forbidden"}), 403

        payload = request.get_json(silent=True) or {}
        spec = payload.get("spec")
        slug = payload.get("slug") or payload.get("scenarioSlug")
        if not isinstance(spec, dict) or not isinstance(slug, str):
            return jsonify({"error": "spec and slug are required"}), 400
        try:
            scenario = scenario_manager.load_spec(slug, spec)
            state_store.reset_slug(slug)
            logger.info("Loaded scenario '%s' via CLI API", scenario.name)
        except SpecValidationError as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify({"status": "ok", "scenarioName": scenario.name, "slug": slug})

    @app.route("/intro/<slug>/")
    def intro_page(slug: str) -> Any:
        _require_scenario(slug)
        intro_path = FRONTEND_DIR / slug / "intro.html"
        if not intro_path.exists():
            abort(404)
        return send_from_directory(FRONTEND_DIR / slug, "intro.html")

    @app.route("/intro/<slug>/<path:asset>")
    def intro_static(slug: str, asset: str) -> Any:
        _require_scenario(slug)
        static_root = FRONTEND_DIR / slug
        requested = static_root / asset
        if not requested.exists() or not requested.is_file():
            abort(404)
        return send_from_directory(static_root, asset)

    return app


def _generate_session_id() -> str:
    return uuid.uuid4().hex
