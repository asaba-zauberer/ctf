# routes.py (snippet for /06-hard/search)
from flask import request, jsonify
from urllib.parse import urlsplit
import posixpath

_ECS_METADATA = {
    "v2": {
        "metadata": {
            "Cluster": "training-cluster",
            "TaskARN": "arn:aws:ecs:us-east-1:123456789012:task/06-web-frontend",
            "Family": "06-hard-web",
        },
        "credentials": {
            "AccessKeyId": "AKIA06CTF8Q2L9X5D7M3",
            "SecretAccessKey": "ctf06aB3dE6gH9jK2mN5pQ8rS1tV4wX7yZ0L2nC5q",
            "Token": "IQoJb3JpZ2luX2VjE...dummy...",
            "Expiration": "2025-10-12T12:34:56Z",
        },
    }
}

def _is_ecs_metadata_url(text: str) -> bool:
    try:
        u = urlsplit(text or "")
    except Exception:
        return False
    return (
        u.scheme == "http"
        and u.hostname == "169.254.170.2"
        and u.port in (None, 80)
    )

def _ecs_path_to_payload(url: str):
    u = urlsplit(url or "")
    norm = posixpath.normpath(u.path or "/").lstrip("/")
    if norm == "v2/metadata":
        return _ECS_METADATA["v2"]["metadata"], 200
    if norm == "v2/credentials":
        return _ECS_METADATA["v2"]["credentials"], 200
    return {"error": "Resource not found"}, 404

@app.route("/06-hard/search", methods=["POST"])
def search_06_hard():
    query = (request.form.get("query") or "").strip()
    if len(query) > 4096:
        return jsonify({"message": "Maintenance: no results found"})
    if not query:
        return jsonify({"message": "Maintenance: no results found"})

    if _is_ecs_metadata_url(query):
        payload, status = _ecs_path_to_payload(query)
        response = jsonify({"data": payload}) if status == 200 else jsonify(payload)
        response.status_code = status
        return response

    return jsonify({"message": "Maintenance: no results found"})






# routes.py (05-hard routes snippet)
import os
from flask import render_template, request, send_file, abort

DIST_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dist", "05-hard")

ALLOWED = {
    "leaky-repo.tar.gz": (
        os.path.join(DIST_DIR, "leaky-repo.tar.gz"),
        "application/gzip",
    ),
    "leaky-repo.bundle": (
        os.path.join(DIST_DIR, "leaky-repo.bundle"),
        "application/x-git-bundle",
    ),
    "README.md": (
        os.path.join(DIST_DIR, "README.md"),
        "text/markdown; charset=utf-8",
    ),
}


@app.route("/05-hard", methods=["GET"])
def page_05_hard() -> str:
    return render_template("05-hard.html")


@app.route("/05-hard/download", methods=["GET"])
def download_05_hard():
    name = (request.args.get("file") or "").strip()
    entry = ALLOWED.get(name)
    if not entry:
        abort(404)

    path, mimetype = entry
    if not os.path.isfile(path):
        abort(404)

    return send_file(path, mimetype=mimetype, as_attachment=True, download_name=name)