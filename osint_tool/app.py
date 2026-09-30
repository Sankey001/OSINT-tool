"""Flask web server exposing the modules as a small JSON API plus the UI."""

from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

from . import __version__
from .detect import TYPES, normalize
from .modules import REGISTRY, modules_for, run_module

STATIC = Path(__file__).parent / "static"


def create_app():
    app = Flask(__name__, static_folder=None)

    @app.get("/")
    def index():
        return send_from_directory(STATIC, "index.html")

    @app.get("/static/<path:path>")
    def static_files(path):
        return send_from_directory(STATIC, path)

    @app.get("/api/meta")
    def meta():
        return jsonify({
            "version": __version__,
            "types": TYPES,
            "modules": [{"name": m.name, "title": m.title, "types": m.types,
                         "description": m.description} for m in REGISTRY.values()],
        })

    @app.get("/api/detect")
    def detect():
        try:
            kind, value = normalize(request.args.get("q", ""), request.args.get("type") or None)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify({
            "type": kind,
            "target": value,
            "modules": [{"name": m.name, "title": m.title, "description": m.description}
                        for m in modules_for(kind)],
        })

    @app.get("/api/run/<name>")
    def run(name):
        target = request.args.get("q", "").strip()
        if not target:
            return jsonify({"error": "Missing q"}), 400
        if name not in REGISTRY:
            return jsonify({"error": f"Unknown module {name}"}), 404
        return jsonify(run_module(name, target))

    return app
