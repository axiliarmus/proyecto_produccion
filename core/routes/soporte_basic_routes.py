import json
import os
import time
import urllib.request

from bson import ObjectId
from flask import flash, redirect, render_template, request, url_for


# #region debug-point helpers:vps-flecha-label
def _debug_report_vps_flecha_label(hypothesis_id, location, msg, data=None, run_id="pre"):
    try:
        debug_url = "http://127.0.0.1:7777/event"
        debug_session_id = "vps-flecha-label"
        env_path = os.path.join(".dbg", "vps-flecha-label.env")
        if os.path.exists(env_path):
            with open(env_path, encoding="utf-8") as env_file:
                for raw_line in env_file:
                    line = raw_line.strip()
                    if line.startswith("DEBUG_SERVER_URL="):
                        debug_url = line.split("=", 1)[1] or debug_url
                    elif line.startswith("DEBUG_SESSION_ID="):
                        debug_session_id = line.split("=", 1)[1] or debug_session_id

        payload = {
            "sessionId": debug_session_id,
            "runId": run_id,
            "hypothesisId": hypothesis_id,
            "location": location,
            "msg": f"[DEBUG] {msg}",
            "data": data or {},
            "ts": int(time.time() * 1000),
        }
        request_obj = urllib.request.Request(
            debug_url,
            data=json.dumps(payload, default=str).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        urllib.request.urlopen(request_obj, timeout=1).read()
    except Exception:
        pass


# #endregion


def register_soporte_basic_routes(
    app,
    db,
    login_required,
    normalize_page,
    paginate_list,
    get_piece_status_sets,
    get_latest_production_map,
    build_codigo_lookup_keys,
    build_codigo_query_values,
    get_label_print_confirm_limit,
    default_label_print_confirm_limit,
):
    """Registra rutas básicas del área de soporte manteniendo endpoints históricos."""

    @app.route("/soporte")
    @login_required("soporte")
    def soporte_dashboard():
        return render_template("soporte_dashboard.html")

    @app.route("/soporte/piezas/duplicadas", methods=["GET", "POST"])
    @login_required("soporte")
    def soporte_piezas_duplicadas():
        pipeline = [
            {"$match": {"codigo": {"$ne": None}}},
            {"$group": {"_id": "$codigo", "count": {"$sum": 1}}},
            {"$match": {"count": {"$gt": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 20},
        ]

        try:
            raw_duplicados = list(db.piezas.aggregate(pipeline, allowDiskUse=True))
        except Exception as exc:
            flash(f"Error al procesar duplicados: {str(exc)}", "danger")
            return render_template("soporte_piezas_duplicadas.html", duplicados=[])

        resultado = []
        if raw_duplicados:
            codigos_problematicos = [item["_id"] for item in raw_duplicados]
            detalles = list(db.piezas.find({"codigo": {"$in": codigos_problematicos}}))
            grupos = {codigo: [] for codigo in codigos_problematicos}
            for pieza in detalles:
                codigo = pieza.get("codigo")
                if codigo in grupos:
                    grupos[codigo].append(pieza)

            for item in raw_duplicados:
                codigo = item["_id"]
                resultado.append(
                    {
                        "_id": str(codigo),
                        "count": item["count"],
                        "docs": grupos.get(codigo, []),
                    }
                )

        return render_template("soporte_piezas_duplicadas.html", duplicados=resultado)

    @app.route("/soporte/piezas/duplicadas/eliminar/<id_pieza>", methods=["POST"])
    @login_required("soporte")
    def soporte_eliminar_duplicado(id_pieza):
        try:
            db.piezas.delete_one({"_id": ObjectId(id_pieza)})
            flash("Pieza duplicada eliminada correctamente.", "success")
        except Exception as exc:
            flash(f"Error al eliminar: {str(exc)}", "danger")
        return redirect(url_for("soporte_piezas_duplicadas"))

    @app.route("/soporte/piezas/masivas", methods=["GET", "POST"])
    @login_required("soporte")
    def soporte_piezas_masivas():
        page = normalize_page(request.args.get("page", 1))
        filtro = {}
        search_query = request.args.get("search", "")
        estado_filter = request.args.get("estado", "todos")

        if request.method == "POST":
            search_query = (request.form.get("search") or "").strip()
            estado_filter = request.form.get("estado") or "todos"
            return redirect(url_for("soporte_piezas_masivas", search=search_query, estado=estado_filter))

        if search_query:
            filtro["$or"] = [
                {"codigo": {"$regex": search_query, "$options": "i"}},
                {"empresa": {"$regex": search_query, "$options": "i"}},
                {"marco": {"$regex": search_query, "$options": "i"}},
            ]

        if estado_filter != "todos":
            modo_buscado = "rematador" if estado_filter == "Rematado" else "armador" if estado_filter == "Armado" else None
            if modo_buscado:
                codigos_con_estado = db.produccion.distinct("codigo_pieza", {"modo": modo_buscado})
                codigos_estado_lookup = build_codigo_query_values(codigos_con_estado)
                if codigos_estado_lookup:
                    filtro["codigo"] = {"$in": codigos_estado_lookup}

        piezas = list(db.piezas.find(filtro).limit(5000).sort("_id", -1))

        if piezas:
            codigos_en_pantalla = [pieza.get("codigo") for pieza in piezas if pieza.get("codigo")]
            set_armado, set_remate = get_piece_status_sets(db, codigos_en_pantalla)
            latest_prod_map = get_latest_production_map(db, codigos_en_pantalla)

            piezas_finales = []
            for pieza in piezas:
                codigo = pieza.get("codigo")
                codigo_keys = build_codigo_lookup_keys(codigo)
                estado = "Sin producción"
                if codigo_keys & set_remate:
                    estado = "Rematado"
                elif codigo_keys & set_armado:
                    estado = "Armado"
                pieza["estado_prod"] = estado

                prod_info = None
                for key in codigo_keys:
                    prod_info = latest_prod_map.get(key)
                    if prod_info:
                        break

                if prod_info:
                    pieza["cuerda_interna"] = (
                        prod_info.get("cuerda_interna")
                        if prod_info.get("cuerda_interna") is not None
                        else pieza.get("cuerda_interna")
                    )
                    pieza["cuerda_externa"] = (
                        prod_info.get("cuerda_externa")
                        if prod_info.get("cuerda_externa") is not None
                        else pieza.get("cuerda_externa")
                    )
                    pieza["flecha"] = (
                        prod_info.get("flecha")
                        if prod_info.get("flecha") is not None
                        else pieza.get("flecha")
                    )

                if estado_filter == "Sin producción" and estado != "Sin producción":
                    continue
                if estado_filter == "Armado" and estado != "Armado":
                    continue
                if estado_filter == "Rematado" and estado != "Rematado":
                    continue

                piezas_finales.append(pieza)
        else:
            piezas_finales = []

        piezas_pagina, pagination = paginate_list(
            piezas_finales,
            "soporte_piezas_masivas",
            page=page,
            search=search_query,
            estado=estado_filter,
        )

        return render_template(
            "soporte_piezas_masivas.html",
            piezas=piezas_pagina,
            search=search_query,
            estado_sel=estado_filter,
            total_registros=len(piezas_finales),
            pagination=pagination,
        )

    @app.route("/soporte/piezas/masivas/eliminar", methods=["POST"])
    @login_required("soporte")
    def soporte_eliminar_masivo():
        ids_to_delete = request.form.getlist("ids[]")
        if not ids_to_delete:
            flash("No seleccionaste ninguna pieza para eliminar.", "warning")
            return redirect(url_for("soporte_piezas_masivas"))

        try:
            object_ids = [ObjectId(uid) for uid in ids_to_delete]
            result = db.piezas.delete_many({"_id": {"$in": object_ids}})
            flash(f"✅ Se eliminaron {result.deleted_count} piezas correctamente.", "success")
        except Exception as exc:
            flash(f"Error al eliminar piezas: {str(exc)}", "danger")

        return redirect(url_for("soporte_piezas_masivas"))

    @app.route("/soporte/etiquetas", methods=["GET", "POST"])
    @login_required(["soporte", "administrador", "supervisor"])
    def soporte_etiquetas():
        page = normalize_page(request.args.get("page", 1))
        filtro = {}

        cliente_sel = request.args.get("cliente", "")
        marco_sel = request.args.get("marco", "")
        tramo_sel = request.args.get("tramo", "")
        estado_filter = request.args.get("estado", "todos")

        if request.method == "POST":
            cliente_sel = request.form.get("cliente") or ""
            marco_sel = request.form.get("marco") or ""
            tramo_sel = request.form.get("tramo") or ""
            estado_filter = request.form.get("estado") or "todos"
            return redirect(
                url_for(
                    "soporte_etiquetas",
                    cliente=cliente_sel,
                    marco=marco_sel,
                    tramo=tramo_sel,
                    estado=estado_filter,
                )
            )

        if cliente_sel and cliente_sel != "todos":
            filtro["empresa"] = cliente_sel
        if marco_sel and marco_sel != "todos":
            filtro["marco"] = marco_sel
        if tramo_sel and tramo_sel != "todos":
            filtro["tramo"] = tramo_sel

        if estado_filter != "todos":
            modo_buscado = "rematador" if estado_filter == "Rematado" else "armador" if estado_filter == "Armado" else None
            if modo_buscado:
                codigos_con_estado = db.produccion.distinct("codigo_pieza", {"modo": modo_buscado})
                codigos_estado_lookup = build_codigo_query_values(codigos_con_estado)
                if codigos_estado_lookup:
                    filtro["codigo"] = {"$in": codigos_estado_lookup}

        try:
            clientes = sorted([x for x in db.piezas.distinct("empresa") if x], key=str)
            marcos = sorted([x for x in db.piezas.distinct("marco") if x], key=str)
            tramos = sorted([x for x in db.piezas.distinct("tramo") if x], key=str)
        except Exception as exc:
            print(f"Error obteniendo filtros: {exc}")
            clientes, marcos, tramos = [], [], []

        piezas = list(db.piezas.find(filtro).limit(5000).sort("_id", -1))
        piezas_finales = []

        if piezas:
            codigos_en_pantalla = [pieza.get("codigo") for pieza in piezas if pieza.get("codigo")]
            set_armado, set_remate = get_piece_status_sets(db, codigos_en_pantalla)

            for pieza in piezas:
                codigo = pieza.get("codigo")
                codigo_keys = build_codigo_lookup_keys(codigo)
                estado = "Sin producción"
                if codigo_keys & set_remate:
                    estado = "Rematado"
                elif codigo_keys & set_armado:
                    estado = "Armado"
                pieza["estado_prod"] = estado

                if estado_filter == "Sin producción" and estado != "Sin producción":
                    continue
                if estado_filter == "Armado" and estado != "Armado":
                    continue
                if estado_filter == "Rematado" and estado != "Rematado":
                    continue

                piezas_finales.append(pieza)

        piezas_pagina, pagination = paginate_list(
            piezas_finales,
            "soporte_etiquetas",
            page=page,
            cliente=cliente_sel,
            marco=marco_sel,
            tramo=tramo_sel,
            estado=estado_filter,
        )

        piezas_impresion = [
            {
                "codigo": str(pieza.get("codigo", "")),
                "empresa": pieza.get("empresa", ""),
                "marco": pieza.get("marco", ""),
                "tramo": pieza.get("tramo", ""),
                "cuerda_interna": pieza.get("cuerda_interna") if pieza.get("cuerda_interna") is not None else "N/A",
                "cuerda_externa": pieza.get("cuerda_externa") if pieza.get("cuerda_externa") is not None else "N/A",
                "flecha": pieza.get("flecha") if pieza.get("flecha") is not None else "N/A",
            }
            for pieza in piezas_finales
        ]
        # #region debug-point A:vps-piece-master-data
        _debug_report_vps_flecha_label(
            "A",
            "soporte_basic_routes.py:soporte_etiquetas",
            "Dataset etiquetas generado",
            {
                "total_piezas": len(piezas_finales),
                "sample": [
                    {
                        "codigo": pieza.get("codigo"),
                        "pieza_master_flecha": pieza.get("flecha"),
                        "pieza_master_cuerda_interna": pieza.get("cuerda_interna"),
                        "pieza_master_cuerda_externa": pieza.get("cuerda_externa"),
                        "estado_prod": pieza.get("estado_prod"),
                    }
                    for pieza in piezas_finales[:5]
                ],
                "sample_impresion": piezas_impresion[:5],
            },
        )
        # #endregion

        return render_template(
            "soporte_etiquetas.html",
            piezas=piezas_pagina,
            clientes=clientes,
            marcos=marcos,
            tramos=tramos,
            cliente_sel=cliente_sel,
            marco_sel=marco_sel,
            tramo_sel=tramo_sel,
            estado_sel=estado_filter,
            pagination=pagination,
            total_registros=len(piezas_finales),
            piezas_impresion=piezas_impresion,
            print_confirm_limit=get_label_print_confirm_limit(db.config, default_label_print_confirm_limit),
        )
