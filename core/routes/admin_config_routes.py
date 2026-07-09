from flask import flash, redirect, render_template, request, url_for

from core.helpers.config_store import get_config_value, get_label_print_confirm_limit, set_config_value


def register_admin_config_routes(app, db, login_required, default_label_print_confirm_limit):
    """Registra la configuración administrativa manteniendo el endpoint histórico."""

    @app.route("/admin/configuracion", methods=["GET", "POST"])
    @login_required(["administrador"])
    def admin_configuracion():
        if request.method == "POST":
            limite_raw = (request.form.get("label_print_confirm_limit") or "").strip()

            try:
                limite = max(1, int(limite_raw))
            except (TypeError, ValueError):
                flash("Ingresa un numero valido mayor o igual a 1.", "warning")
                return redirect(url_for("admin_configuracion"))

            set_config_value(db.config, "label_print_confirm_limit", limite)
            flash("Configuracion guardada correctamente.", "success")
            return redirect(url_for("admin_configuracion"))

        valor_guardado = get_config_value(db.config, "label_print_confirm_limit", None)
        return render_template(
            "admin_configuracion.html",
            label_print_confirm_limit=get_label_print_confirm_limit(db.config, default_label_print_confirm_limit),
            label_print_confirm_limit_default=default_label_print_confirm_limit,
            label_print_confirm_limit_source="Personalizado" if valor_guardado not in (None, "") else "Predeterminado",
        )
