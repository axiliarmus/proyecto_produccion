import os
import secrets
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, redirect, request, session, url_for
from pymongo import MongoClient
from werkzeug.middleware.proxy_fix import ProxyFix

from core.helpers import reporting as reporting_helpers
from core.helpers.date_utils import now_cl
from core.routes.registry import register_all_routes


def _get_project_root():
    return Path(__file__).resolve().parent.parent


def _get_or_create_csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_hex(32)
        session["_csrf_token"] = token
    return token


def _build_log_audit():
    def log_audit(accion, detalle):
        user = session.get("username", "Desconocido")
        timestamp = now_cl().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[AUDIT] {timestamp} | USER: {user} | ACTION: {accion} | DETAILS: {detalle}")

    return log_audit


def _configure_app(app, secret_key, enable_seed):
    app.secret_key = secret_key
    app.config["ENABLE_SEED"] = enable_seed
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=1,
        x_proto=1,
        x_host=1,
        x_port=1,
    )
    app.config.update(
        SESSION_COOKIE_SECURE=False,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )


def _register_security_hooks(app, runtime_state):
    @app.after_request
    def add_security_headers(response):
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://unpkg.com blob: data: https://translate.googleapis.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://www.gstatic.com https://unpkg.com; "
            "img-src 'self' data: blob: https://www.gstatic.com; "
            "font-src 'self' data: https://cdn.jsdelivr.net https://unpkg.com; "
            "media-src 'self' https://cdn.freesound.org; "
            "connect-src 'self' https://cdn.jsdelivr.net https://translate.googleapis.com;"
        )
        response.headers["Content-Security-Policy"] = csp
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        return response

    @app.context_processor
    def inject_globals():
        return {
            "csrf_token": session.get("_csrf_token") or _get_or_create_csrf_token(),
            "tunnel_url": runtime_state["tunnel_url"],
        }

    @app.before_request
    def csrf_protect():
        if request.method == "POST":
            token = request.form.get("_csrf_token") or request.headers.get("X-CSRFToken")
            expected = session.get("_csrf_token") or _get_or_create_csrf_token()
            if not token or token != expected:
                return "CSRF token inválido", 400

    @app.route("/favicon.ico")
    def favicon():
        return redirect(url_for("static", filename="img/logo.svg"), code=302)


def create_app():
    project_root = _get_project_root()
    load_dotenv(project_root / ".env")

    secret_key = os.getenv("SECRET_KEY")
    if not secret_key:
        raise RuntimeError("SECRET_KEY no definida en .env")

    mongo_uri = os.getenv("MONGO_URI")
    if not mongo_uri:
        raise RuntimeError("MONGO_URI no definida en .env")

    app = Flask(
        __name__,
        template_folder=str(project_root / "templates"),
        static_folder=str(project_root / "static"),
    )
    _configure_app(
        app,
        secret_key=secret_key,
        enable_seed=os.getenv("ENABLE_SEED", "false").lower() == "true",
    )

    client = MongoClient(mongo_uri)
    db = client["miBase"]
    runtime_state = {
        "tunnel_url": None,
        "login_attempts": {},
    }
    log_audit = _build_log_audit()

    app.extensions["mongo_client"] = client
    app.extensions["mongo_db"] = db
    app.extensions["runtime_state"] = runtime_state
    app.extensions["log_audit"] = log_audit

    _register_security_hooks(app, runtime_state)
    register_all_routes(app, db, runtime_state, log_audit)
    ensure_mongo_indexes(app)
    return app



def get_db(app):
    return app.extensions["mongo_db"]


def ensure_mongo_indexes(app):
    return reporting_helpers.ensure_mongo_indexes(get_db(app))


def set_tunnel_url(app, url):
    app.extensions["runtime_state"]["tunnel_url"] = url


def get_tunnel_url(app):
    return app.extensions["runtime_state"]["tunnel_url"]


app = create_app()
