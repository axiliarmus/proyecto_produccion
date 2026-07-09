from bson import ObjectId
from flask import flash, redirect, render_template, request, url_for


def register_soporte_archivados_routes(
    app,
    db,
    login_required,
    normalize_page,
    build_pagination,
    default_per_page,
    log_audit,
):
    """Registra rutas de soporte para edición de datos históricos."""

    @app.route("/soporte/archivados/usuarios", methods=["GET"])
    @login_required("soporte")
    def soporte_archivados_usuarios():
        cortes = list(db.cortes.find().sort("inicio", -1))
        corte_sel = request.args.get("corte_id")
        page = normalize_page(request.args.get("page", 1))
        usuarios = []

        if corte_sel:
            try:
                filtro = {"corte_id": ObjectId(corte_sel)}
                total_registros = db.usuarios_historicos.count_documents(filtro)
                total_pages = max((total_registros + default_per_page - 1) // default_per_page, 1)
                page = min(page, total_pages)
                skip = (page - 1) * default_per_page
                usuarios = list(
                    db.usuarios_historicos.find(filtro)
                    .sort("usuario", 1)
                    .skip(skip)
                    .limit(default_per_page)
                )
            except Exception:
                total_registros = 0
        else:
            total_registros = 0

        return render_template(
            "soporte_archivados_usuarios.html",
            cortes=cortes,
            corte_sel=corte_sel,
            usuarios=usuarios,
            pagination=build_pagination("soporte_archivados_usuarios", page, total_registros, corte_id=corte_sel),
        )

    @app.route("/soporte/archivados/usuarios/editar", methods=["POST"])
    @login_required("soporte")
    def soporte_archivados_usuarios_editar():
        user_id = request.form.get("user_id")
        corte_id = request.form.get("corte_id")

        update_data = {
            "precio_metro_armado": float(request.form.get("precio_metro_armado", 0)),
            "precio_metro_remate": float(request.form.get("precio_metro_remate", 0)),
            "precio_avo_armado": float(request.form.get("precio_avo_armado", 0)),
            "precio_avo_remate": float(request.form.get("precio_avo_remate", 0)),
        }

        db.usuarios_historicos.update_one({"_id": ObjectId(user_id)}, {"$set": update_data})
        log_audit("EDIT_USER_HIST", f"ID: {user_id}, Data: {update_data}")
        flash("Usuario histórico actualizado.", "success")
        return redirect(
            url_for(
                "soporte_archivados_usuarios",
                corte_id=corte_id,
                page=normalize_page(request.form.get("page") or 1),
            )
        )

    @app.route("/soporte/archivados/produccion", methods=["GET"])
    @login_required("soporte")
    def soporte_archivados_produccion():
        cortes = list(db.cortes.find().sort("inicio", -1))
        corte_sel = request.args.get("corte_id")
        codigo_sel = request.args.get("codigo")
        page = normalize_page(request.args.get("page", 1))
        produccion = []

        if corte_sel:
            try:
                filtro = {"corte_id": ObjectId(corte_sel)}
                if codigo_sel:
                    filtro["codigo_pieza"] = codigo_sel.strip()

                total_registros = db.produccion_historica.count_documents(filtro)
                total_pages = max((total_registros + default_per_page - 1) // default_per_page, 1)
                page = min(page, total_pages)
                skip = (page - 1) * default_per_page
                produccion = list(
                    db.produccion_historica.find(filtro)
                    .sort("fecha", -1)
                    .skip(skip)
                    .limit(default_per_page)
                )
            except Exception:
                total_registros = 0
        else:
            total_registros = 0

        return render_template(
            "soporte_archivados_produccion.html",
            cortes=cortes,
            corte_sel=corte_sel,
            produccion=produccion,
            codigo_sel=codigo_sel,
            pagination=build_pagination(
                "soporte_archivados_produccion",
                page,
                total_registros,
                corte_id=corte_sel,
                codigo=codigo_sel,
            ),
        )

    @app.route("/soporte/archivados/produccion/editar", methods=["POST"])
    @login_required("soporte")
    def soporte_archivados_produccion_editar():
        prod_id = request.form.get("prod_id")
        corte_id = request.form.get("corte_id")
        codigo = request.form.get("codigo") or ""
        page = normalize_page(request.form.get("page") or 1)

        update_data = {
            "codigo_pieza": request.form.get("codigo_pieza"),
            "usuario": request.form.get("usuario"),
            "modo": request.form.get("modo"),
        }
        if update_data.get("modo") not in ("armador", "rematador"):
            flash("Modo inválido.", "danger")
            return redirect(url_for("soporte_archivados_produccion", corte_id=corte_id, codigo=codigo, page=page))

        db.produccion_historica.update_one({"_id": ObjectId(prod_id)}, {"$set": update_data})
        log_audit("EDIT_PROD_HIST", f"ID: {prod_id}, Data: {update_data}")
        flash("Registro de producción histórico actualizado.", "success")
        return redirect(url_for("soporte_archivados_produccion", corte_id=corte_id, codigo=codigo, page=page))

    @app.route("/soporte/archivados/produccion/eliminar", methods=["POST"])
    @login_required("soporte")
    def soporte_archivados_produccion_eliminar():
        prod_id = request.form.get("prod_id")
        corte_id = request.form.get("corte_id")
        codigo = request.form.get("codigo") or ""
        page = normalize_page(request.form.get("page") or 1)

        db.produccion_historica.delete_one({"_id": ObjectId(prod_id)})
        log_audit("DELETE_PROD_HIST", f"ID: {prod_id}")
        flash("Registro histórico eliminado.", "info")
        return redirect(url_for("soporte_archivados_produccion", corte_id=corte_id, codigo=codigo, page=page))

    @app.route("/soporte/archivados/piezas", methods=["GET"])
    @login_required("soporte")
    def soporte_archivados_piezas():
        cortes = list(db.cortes.find().sort("inicio", -1))
        corte_sel = request.args.get("corte_id")
        codigo_sel = request.args.get("codigo")
        page = normalize_page(request.args.get("page", 1))
        piezas = []

        if corte_sel:
            try:
                filtro = {"corte_id": ObjectId(corte_sel)}
                if codigo_sel:
                    filtro["codigo"] = int(codigo_sel) if codigo_sel.isdigit() else codigo_sel

                total_registros = db.piezas_historicas.count_documents(filtro)
                total_pages = max((total_registros + default_per_page - 1) // default_per_page, 1)
                page = min(page, total_pages)
                skip = (page - 1) * default_per_page
                piezas = list(
                    db.piezas_historicas.find(filtro)
                    .sort("codigo", 1)
                    .skip(skip)
                    .limit(default_per_page)
                )
            except Exception:
                total_registros = 0
        else:
            total_registros = 0

        return render_template(
            "soporte_archivados_piezas.html",
            cortes=cortes,
            corte_sel=corte_sel,
            piezas=piezas,
            codigo_sel=codigo_sel,
            pagination=build_pagination(
                "soporte_archivados_piezas",
                page,
                total_registros,
                corte_id=corte_sel,
                codigo=codigo_sel,
            ),
        )

    @app.route("/soporte/archivados/piezas/editar", methods=["POST"])
    @login_required("soporte")
    def soporte_archivados_piezas_editar():
        pieza_id = request.form.get("pieza_id")
        corte_id = request.form.get("corte_id")
        codigo = request.form.get("codigo") or ""
        page = normalize_page(request.form.get("page") or 1)

        update_data = {
            "kilo_pieza": float(request.form.get("kilo_pieza", 0)),
            "tipo_precio": request.form.get("tipo_precio"),
            "marco": request.form.get("marco"),
            "tramo": request.form.get("tramo"),
        }
        if update_data.get("tipo_precio") not in ("metro", "avo"):
            flash("Tipo de precio inválido.", "danger")
            return redirect(url_for("soporte_archivados_piezas", corte_id=corte_id, codigo=codigo, page=page))

        db.piezas_historicas.update_one({"_id": ObjectId(pieza_id)}, {"$set": update_data})
        log_audit("EDIT_PIEZA_HIST", f"ID: {pieza_id}, Data: {update_data}")
        flash("Pieza histórica actualizada.", "success")
        return redirect(url_for("soporte_archivados_piezas", corte_id=corte_id, codigo=codigo, page=page))
