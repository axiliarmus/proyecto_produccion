from datetime import datetime, timedelta
from functools import wraps

from bson import ObjectId
from flask import flash, redirect, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from core.helpers.date_utils import now_cl, to_cl


PASSWORD_MAX_AGE_DAYS = 30
LOGIN_MAX_ATTEMPTS = 5
LOGIN_BLOCK_MINUTES = 15


def get_role_home_endpoint(role):
    """Resuelve la ruta principal a la que debe volver cada rol."""
    if role == "administrador":
        return "admin_dashboard"
    if role == "supervisor":
        return "supervisor_home"
    if role == "soporte":
        return "soporte_dashboard"
    if role == "cliente":
        return "admin_informes"
    return "operador_home"


def is_password_expired(password_changed_at, max_age_days=PASSWORD_MAX_AGE_DAYS):
    """Indica si la contraseña debe renovarse por antigüedad o falta de fecha."""
    pw_date = to_cl(password_changed_at)
    if not pw_date:
        return True
    return (now_cl() - pw_date) > timedelta(days=max_age_days)


def build_login_required(db):
    """Construye el decorador login_required con acceso a la base de datos actual."""

    def login_required(roles=None):
        if isinstance(roles, str):
            roles = [roles]

        def wrapper(fn):
            @wraps(fn)
            def _wrapped(*args, **kwargs):
                if "user_id" not in session:
                    flash("Inicia sesión para continuar", "warning")
                    return redirect(url_for("login"))

                if request.endpoint == "cambiar_password":
                    return fn(*args, **kwargs)

                pw_changed_raw = session.get("password_changed_at")
                if pw_changed_raw is None:
                    user = db.usuarios.find_one({"_id": ObjectId(session["user_id"])})
                    if user:
                        dt = user.get("password_changed_at")
                        session["password_changed_at"] = dt.isoformat() if dt else ""
                        pw_changed_raw = session["password_changed_at"]
                    else:
                        pw_changed_raw = ""

                if pw_changed_raw == "":
                    flash("Debes cambiar tu contraseña antes de continuar.", "warning")
                    return redirect(url_for("cambiar_password"))
                else:
                    try:
                        password_changed_at = datetime.fromisoformat(pw_changed_raw)
                    except Exception:
                        password_changed_at = None

                    if is_password_expired(password_changed_at):
                        flash("Tu contraseña ha expirado. Debes cambiarla.", "warning")
                        return redirect(url_for("cambiar_password"))


                user_role = session.get("role")
                if roles and user_role not in roles:
                    flash("No tienes permisos para acceder a esta sección.", "danger")
                    return redirect(url_for(get_role_home_endpoint(user_role)))

                return fn(*args, **kwargs)

            return _wrapped

        return wrapper

    return login_required


def seed_default_users(db):
    """Crea usuarios base si no existen y el seed está habilitado."""
    default_users = [
        {
            "usuario": "admin",
            "nombre": "Administrador",
            "tipo": "administrador",
            "password": "admin123",
            "label": "admin / admin123",
        },
        {
            "usuario": "soporte",
            "nombre": "Soporte",
            "tipo": "soporte",
            "password": "soporte123",
            "label": "soporte / soporte123",
        },
    ]

    for item in default_users:
        if db.usuarios.find_one({"usuario": item["usuario"]}):
            continue
        db.usuarios.insert_one(
            {
                "usuario": item["usuario"],
                "nombre": item["nombre"],
                "tipo": item["tipo"],
                "password": generate_password_hash(item["password"]),
                "password_changed_at": datetime.utcnow(),
            }
        )
        print(f"> Usuario {item['usuario']} creado ({item['label']})")


def get_blocked_login_remaining(login_attempts, ip, now=None):
    """Devuelve minutos restantes de bloqueo o None si la IP puede intentar login."""
    now = now or datetime.now()
    if ip not in login_attempts:
        return None

    attempts, last_time = login_attempts[ip]
    if attempts < LOGIN_MAX_ATTEMPTS:
        return None

    elapsed = now - last_time
    if elapsed >= timedelta(minutes=LOGIN_BLOCK_MINUTES):
        login_attempts[ip] = (0, now)
        return None

    remaining = LOGIN_BLOCK_MINUTES - (elapsed.seconds // 60)
    return max(remaining, 1)


def clear_login_attempts(login_attempts, ip):
    """Limpia el contador de intentos para una IP."""
    login_attempts.pop(ip, None)


def record_failed_login(login_attempts, ip, now=None):
    """Incrementa el contador de intentos fallidos para una IP."""
    now = now or datetime.now()
    attempts, _ = login_attempts.get(ip, (0, now))
    login_attempts[ip] = (attempts + 1, now)


def authenticate_user(db, usuario, password):
    """Busca y valida credenciales de usuario."""
    user = db.usuarios.find_one({"usuario": usuario})
    if user and check_password_hash(user["password"], password):
        return user
    return None


def update_user_password(db, user_id, new_password):
    """Actualiza contraseña y fecha de cambio de un usuario."""
    db.usuarios.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"password": generate_password_hash(new_password), "password_changed_at": now_cl()}},
    )
