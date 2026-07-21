from datetime import datetime

from bson import ObjectId
from flask import flash, redirect, render_template, request, session, url_for

from core.helpers import auth as auth_helpers


def register_auth_routes(app, db, login_required, login_attempts):
    """Registra hooks y rutas de autenticación manteniendo endpoints históricos."""

    @app.before_request
    def ensure_seed():
        if request.endpoint not in ("static",) and app.config.get("ENABLE_SEED", False):
            auth_helpers.seed_default_users(db)

    @app.route("/", methods=["GET"])
    def index():
        if "user_id" in session:
            role = session.get("role")

            user = db.usuarios.find_one({"_id": ObjectId(session["user_id"])})
            if user and auth_helpers.is_password_expired(user.get("password_changed_at")):
                return redirect(url_for("cambiar_password"))

            return redirect(url_for(auth_helpers.get_role_home_endpoint(role)))

        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            ip = request.remote_addr
            now = datetime.now()

            remaining = auth_helpers.get_blocked_login_remaining(login_attempts, ip, now=now)
            if remaining is not None:
                flash(f"Demasiados intentos fallidos. Inténtalo de nuevo en {remaining} minutos.", "danger")
                return render_template("login.html")

            usuario = request.form.get("usuario", "").strip()
            password = request.form.get("password")

            user = auth_helpers.authenticate_user(db, usuario, password)
            if user:
                auth_helpers.clear_login_attempts(login_attempts, ip)

                session["user_id"] = str(user["_id"])
                session["username"] = user["usuario"]
                session["nombre"] = user.get("nombre", user["usuario"])
                session["role"] = user["tipo"]
                
                # Cachear password_changed_at en sesión
                dt = user.get("password_changed_at")
                session["password_changed_at"] = dt.isoformat() if dt else ""

                if auth_helpers.is_password_expired(dt):
                    flash("Debes cambiar tu contraseña antes de continuar.", "warning")
                    return redirect(url_for("cambiar_password"))

                flash(f"Bienvenido, {session['nombre']}", "success")
                return redirect(url_for("index"))

            auth_helpers.record_failed_login(login_attempts, ip, now=now)
            flash("Usuario o contraseña inválidos", "danger")

        return render_template("login.html")

    @app.route("/logout")
    @login_required()
    def logout():
        session.clear()
        flash("Sesión cerrada correctamente", "info")
        return redirect(url_for("login"))

    @app.route("/cambiar-password", methods=["GET", "POST"])
    @login_required()
    def cambiar_password():
        if request.method == "POST":
            nueva = request.form.get("password_nueva")
            repetir = request.form.get("password_repetir")

            if nueva != repetir:
                flash("Las contraseñas no coinciden.", "danger")
                return redirect(url_for("cambiar_password"))

            if len(nueva) < 6:
                flash("La contraseña debe tener al menos 6 caracteres.", "warning")
                return redirect(url_for("cambiar_password"))

            auth_helpers.update_user_password(db, session["user_id"], nueva)
            session["password_changed_at"] = auth_helpers.now_cl().isoformat()
            flash("Contraseña actualizada correctamente 👌", "success")
            return redirect(url_for("index"))

        return render_template("cambiar_password.html")
