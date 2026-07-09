from datetime import datetime, timezone

from bson import ObjectId
from flask import flash, redirect, render_template, request, url_for

from core.helpers.date_utils import CL, now_cl


def register_supervisor_routes(app, db, login_required, normalize_page, paginate_list):
    """Registra las rutas del supervisor manteniendo los endpoints históricos."""

    @app.route("/supervisor", methods=["GET", "POST"])
    @login_required("supervisor")
    def supervisor_home():
        today = now_cl().date()
        start_cl = datetime.combine(today, datetime.min.time()).replace(tzinfo=CL)
        end_cl = datetime.combine(today, datetime.max.time()).replace(tzinfo=CL)
        start_today = start_cl.astimezone(timezone.utc)
        end_today = end_cl.astimezone(timezone.utc)
        page = normalize_page(request.args.get("page", 1))

        if request.method == "POST":
            codigo = (request.form.get("codigo") or "").strip()
            fecha_inicio = request.form.get("fecha_inicio") or ""
            fecha_fin = request.form.get("fecha_fin") or ""
            estado_sel = request.form.get("estado") or "todos"
            return redirect(
                url_for(
                    "supervisor_home",
                    codigo=codigo,
                    fecha_inicio=fecha_inicio,
                    fecha_fin=fecha_fin,
                    estado=estado_sel,
                    page=1,
                )
            )

        codigo = (request.args.get("codigo") or "").strip()
        fecha_inicio = request.args.get("fecha_inicio") or ""
        fecha_fin = request.args.get("fecha_fin") or ""
        estado_sel = request.args.get("estado") or "todos"

        filtro = {"modo": "rematador"}
        if codigo:
            filtro["codigo_pieza"] = codigo

        if fecha_inicio and fecha_fin:
            try:
                d1 = datetime.strptime(fecha_inicio, "%Y-%m-%d").date()
                d2 = datetime.strptime(fecha_fin, "%Y-%m-%d").date()
                start_cl = datetime.combine(d1, datetime.min.time()).replace(tzinfo=CL)
                end_cl = datetime.combine(d2, datetime.max.time()).replace(tzinfo=CL)
                filtro["fecha"] = {"$gte": start_cl.astimezone(timezone.utc), "$lte": end_cl.astimezone(timezone.utc)}
            except ValueError:
                flash("Fechas inválidas (usa formato AAAA-MM-DD).", "warning")
        else:
            filtro["fecha"] = {"$gte": start_today, "$lte": end_today}

        if estado_sel and estado_sel != "todos":
            filtro["calidad_status"] = estado_sel

        piezas_activas = list(db.produccion.find(filtro).sort("fecha", -1))
        piezas_historicas = list(db.produccion_historica.find(filtro).sort("fecha", -1))

        for pieza in piezas_activas:
            pieza["is_historico"] = False
        for pieza in piezas_historicas:
            pieza["is_historico"] = True

        piezas = piezas_activas + piezas_historicas
        piezas.sort(key=lambda item: item.get("fecha"), reverse=True)
        piezas_pagina, pagination = paginate_list(
            piezas,
            "supervisor_home",
            page=page,
            codigo=codigo,
            fecha_inicio=fecha_inicio,
            fecha_fin=fecha_fin,
            estado=estado_sel,
        )

        return render_template(
            "supervisor.html",
            piezas=piezas_pagina,
            codigo=codigo,
            fecha_inicio=fecha_inicio,
            fecha_fin=fecha_fin,
            estado_sel=estado_sel,
            pagination=pagination,
        )

    @app.route("/supervisor/informes")
    @login_required("supervisor")
    def supervisor_informes():
        return render_template("supervisor_informes.html")

    @app.route("/supervisor/piezas/<id>/validar", methods=["POST"])
    @login_required("supervisor")
    def supervisor_validar_pieza(id):
        decision = request.form.get("decision") or "aprobado"
        cuerda_interna = request.form.get("cuerda_interna")
        cuerda_externa = request.form.get("cuerda_externa")
        flecha = request.form.get("flecha")
        comentario = request.form.get("comentario")
        codigo = (request.form.get("codigo") or "").strip()
        fecha_inicio = request.form.get("fecha_inicio") or ""
        fecha_fin = request.form.get("fecha_fin") or ""
        estado_sel = request.form.get("estado") or "todos"
        page = normalize_page(request.form.get("page") or 1)

        update = {
            "calidad_status": decision,
            "cuerda_interna": cuerda_interna,
            "cuerda_externa": cuerda_externa,
            "flecha": flecha,
            "comentario_supervisor": comentario,
        }

        res = db.produccion.update_one({"_id": ObjectId(id)}, {"$set": update})
        if res.matched_count == 0:
            db.produccion_historica.update_one({"_id": ObjectId(id)}, {"$set": update})

        flash(f"Pieza actualizada como {decision}", "success")
        return redirect(
            url_for(
                "supervisor_home",
                codigo=codigo,
                fecha_inicio=fecha_inicio,
                fecha_fin=fecha_fin,
                estado=estado_sel,
                page=page,
            )
        )
