"""Flask application factory for the AWS CLI themed CTF app."""
from __future__ import annotations

import re
import uuid
from pathlib import Path
from typing import Any, Dict, Optional

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
RATE_LIMIT_PER_SECOND = 5


def create_app() -> Flask:
    app = Flask(
        __name__,
        static_folder=None,
    )

    logger = configure_logging(LOG_DIR)
    scenario_manager = ScenarioManager()
    state_store = SessionStateStore()
    rate_limiter = RateLimiter(limit=RATE_LIMIT_PER_SECOND, interval_seconds=1.0)

    loaded = scenario_manager.load_directory(SPECS_DIR)
    if loaded:
        logger.info("Loaded scenarios: %s", ", ".join(sorted(loaded.keys())))
    else:
        logger.warning("No CommandSpec scenarios found in %s", SPECS_DIR)

    def _cookie_name(slug: str) -> str:
        return f"{SESSION_COOKIE_PREFIX}_{slug}"

    def _require_scenario(slug: str):
        scenario = scenario_manager.get(slug)
        if scenario is None:
            abort(404, description=f"Scenario '{slug}' not found")
        return scenario

    def _get_or_create_session_id(slug: str) -> str:
        scenario = _require_scenario(slug)
        cookie_name = _cookie_name(slug)
        session_id = request.cookies.get(cookie_name)
        if not session_id:
            session_id = _generate_session_id()
        state_store.ensure_session(slug, session_id, scenario)
        return session_id

    def _default_slug() -> Optional[str]:
        return scenario_manager.default_slug

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
        links = "".join(
            f"<li><a href='/c/{slug}/'>{scenario.name}</a></li>"
            for slug, scenario in sorted(
                scenarios.items(), key=lambda item: item[1].name
            )
        )
        return f"<h1>Challenges</h1><ul>{links}</ul>"

    @app.route("/c/<slug>/")
    def scenario_index(slug: str) -> Any:
        _require_scenario(slug)
        session_id = _get_or_create_session_id(slug)
        response = make_response(send_from_directory(FRONTEND_DIR, "index.html"), 200)
        response.set_cookie(
            _cookie_name(slug),
            session_id,
            max_age=1800,
            httponly=True,
            samesite="Lax",
            path=f"/c/{slug}/",
        )
        return response

    @app.route("/c/<slug>/main.js")
    def scenario_js(slug: str) -> Any:
        _require_scenario(slug)
        return send_from_directory(FRONTEND_DIR, "main.js")

    @app.route("/c/<slug>/<path:asset>")
    def scenario_static(slug: str, asset: str) -> Any:
        _require_scenario(slug)
        static_root = FRONTEND_DIR / slug
        requested = static_root / asset
        if not requested.exists() or not requested.is_file():
            abort(404)
        return send_from_directory(static_root, asset)

    @app.route("/c/<slug>/api/health", methods=["GET"])
    def scenario_health(slug: str) -> Any:
        _require_scenario(slug)
        return jsonify({"status": "ok"})

    @app.route("/c/<slug>/api/meta", methods=["GET"])
    def scenario_meta(slug: str) -> Any:
        scenario = _require_scenario(slug)
        session_id = _get_or_create_session_id(slug)
        response = jsonify(
            {
                "scenarioName": scenario.name,
                "defaultOutput": scenario.default_render,
                "sessionId": session_id,
                "slug": slug,
            }
        )
        response.set_cookie(
            _cookie_name(slug),
            session_id,
            max_age=1800,
            httponly=True,
            samesite="Lax",
            path=f"/c/{slug}/",
        )
        return response

    @app.route("/c/<slug>/api/execute", methods=["POST"])
    def scenario_execute(slug: str) -> Any:
        scenario = _require_scenario(slug)
        payload = request.get_json(silent=True) or {}
        command = payload.get("command")
        session_id = payload.get("sessionId")

        if not isinstance(session_id, str) or not isinstance(command, str):
            return (
                jsonify({"ok": False, "message": "Invalid request payload"}),
                400,
            )

        cookie_session = request.cookies.get(_cookie_name(slug))
        if cookie_session and cookie_session != session_id:
            return jsonify({"ok": False, "message": "Session mismatch"}), 403

        try:
            rate_limiter.hit(f"{slug}:{session_id}")
        except RateLimitExceeded:
            return jsonify({"ok": False, "message": "Too Many Requests"}), 429

        state = state_store.get_state(slug, session_id, scenario)
        result = execute_command(scenario, state, command.strip())

        log_payload: Dict[str, Any] = {
            "slug": slug,
            "sessionId": session_id,
            "command": command,
            "ok": result.get("ok"),
            "exitCode": result.get("exitCode"),
        }

        if result.get("ok"):
            state_store.update_state(slug, session_id, scenario, result["state"])
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

    @app.route("/c/<slug>/api/fetch", methods=["GET"])
    def scenario_fetch(slug: str) -> Any:
        scenario = _require_scenario(slug)
        session_id = request.args.get("sessionId")
        url = request.args.get("url")

        if not session_id or not isinstance(session_id, str):
            return jsonify({"error": "sessionId is required"}), 400
        if not url or not isinstance(url, str):
            return jsonify({"error": "url is required"}), 400

        cookie_session = request.cookies.get(_cookie_name(slug))
        if cookie_session and cookie_session != session_id:
            return jsonify({"error": "Session mismatch"}), 403

        rate_key = f"{slug}:{session_id}:fetch"
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

        state = state_store.get_state(slug, session_id, scenario)
        state["activeIdentity"] = "taskRole"
        state_store.update_state(slug, session_id, scenario, state)

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
                "slug": slug,
                "sessionId": session_id,
                "url": url,
                "identity": "taskRole",
            },
        )
        return jsonify(credentials)

    @app.route("/c/<slug>/api/load-spec", methods=["POST"])
    def scenario_load_spec(slug: str) -> Any:
        if request.remote_addr not in {"127.0.0.1", "::1"}:
            return jsonify({"error": "forbidden"}), 403

        payload = request.get_json(silent=True) or {}
        spec = payload.get("spec")
        if not isinstance(spec, dict):
            return jsonify({"error": "spec must be an object"}), 400
        try:
            scenario = scenario_manager.load_spec(slug, spec)
            state_store.reset_slug(slug)
            logger.info("Loaded scenario '%s' via API", scenario.name)
        except SpecValidationError as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify({"status": "ok", "scenarioName": scenario.name, "slug": slug})

    @app.route("/api/health", methods=["GET"])
    def legacy_health() -> Any:
        slug = _default_slug()
        if not slug:
            return jsonify({"error": "scenario_not_loaded"}), 503
        return scenario_health(slug)

    @app.route("/api/meta", methods=["GET"])
    def legacy_meta() -> Any:
        slug = _default_slug()
        if not slug:
            return jsonify({"error": "scenario_not_loaded"}), 503
        return scenario_meta(slug)

    @app.route("/api/execute", methods=["POST"])
    def legacy_execute() -> Any:
        slug = _default_slug()
        if not slug:
            return jsonify({"ok": False, "message": "Scenario not loaded"}), 503
        return scenario_execute(slug)

    @app.route("/api/load-spec", methods=["POST"])
    def legacy_load_spec() -> Any:
        if request.remote_addr not in {"127.0.0.1", "::1"}:
            return jsonify({"error": "forbidden"}), 403

        payload = request.get_json(silent=True) or {}
        spec = payload.get("spec")
        slug = (
            payload.get("slug")
            or payload.get("scenarioSlug")
            or payload.get("scenarioName")
        )
        if not isinstance(spec, dict) or not isinstance(slug, str):
            return jsonify({"error": "spec and slug are required"}), 400
        try:
            scenario = scenario_manager.load_spec(slug, spec)
            state_store.reset_slug(slug)
            logger.info("Loaded scenario '%s' via legacy API", scenario.name)
        except SpecValidationError as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify({"status": "ok", "scenarioName": scenario.name, "slug": slug})

    return app


def _generate_session_id() -> str:
    return uuid.uuid4().hex
