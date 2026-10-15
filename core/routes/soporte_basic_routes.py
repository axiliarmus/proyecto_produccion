import json
import os
import time
import urllib.request

from bson import ObjectId
from flask import flash, redirect, render_template, request, session, url_for

from core.helpers.reporting import (
    build_piece_master_measure_map,
    piece_matches_status_filter,
    resolve_piece_production_status,
)
from core.helpers.soft_delete import soft_delete_one, soft_delete_many


# #endregion


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
        from datetime import datetime, timedelta, timezone
        from core.helpers.date_utils import CL, now_cl

        total_piezas = db.piezas.count_documents({})
        total_produccion = db.produccion.count_documents({})
        total_usuarios = db.usuarios.count_documents({})

        # Duplicados (rápido):
        pipeline_dup = [
            {"$match": {"codigo": {"$ne": None}}},
            {"$group": {"_id": "$codigo", "count": {"$sum": 1}}},
            {"$match": {"count": {"$gt": 1}}},
            {"$count": "cantidad"},
        ]
        dup_result = list(db.piezas.aggregate(pipeline_dup, allowDiskUse=True))
        total_duplicados = dup_result[0]["cantidad"] if dup_result else 0

        # Papelera:
        from core.helpers.soft_delete import COLLECTION_PAPELERA
        total_papelera = db[COLLECTION_PAPELERA].count_documents({})

        # Producción HOY:
        today = now_cl().date()
        start_today = datetime.combine(today, datetime.min.time()).replace(tzinfo=CL)
        end_today = datetime.combine(today, datetime.max.time()).replace(tzinfo=CL)
        prod_hoy = list(db.produccion.find(
            {"fecha": {"$gte": start_today.astimezone(timezone.utc), "$lte": end_today.astimezone(timezone.utc)}},
            {"kilo_pieza": 1, "tipo_precio": 1, "_id": 0},
        ))
        kilos_hoy = {"avo": 0.0, "metro": 0.0}
        for r in prod_hoy:
            p = float(r.get("kilo_pieza") or 0)
            t = r.get("tipo_precio") or "metro"
            if t == "avo":
                kilos_hoy["avo"] += p
            else:
                kilos_hoy["metro"] += p

        return render_template(
            "soporte_dashboard.html",
            total_piezas=total_piezas,
            total_produccion=total_produccion,
            total_usuarios=total_usuarios,
            total_duplicados=total_duplicados,
            total_papelera=total_papelera,
            kilos_hoy=kilos_hoy,
        )

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
            ok, msg = soft_delete_one(
                db,
                collection_origen="piezas",
                filtro_doc={"_id": ObjectId(id_pieza)},
                deleted_by_user_id=session.get("user_id"),
                deleted_by_user_name=session.get("nombre"),
                deleted_by_ip=request.remote_addr,
                motivo="soporte eliminar pieza duplicada",
            )
            flash(msg, "success" if ok else "danger")
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

        piezas = list(db.piezas.find(filtro).limit(5000).sort("_id", -1))

        if piezas:
            codigos_en_pantalla = [pieza.get("codigo") for pieza in piezas if pieza.get("codigo")]
            set_armado, set_remate = get_piece_status_sets(db, codigos_en_pantalla)
            master_measure_map = build_piece_master_measure_map(db, codigos_en_pantalla)

            piezas_finales = []
            for pieza in piezas:
                codigo = pieza.get("codigo")
                codigo_keys = build_codigo_lookup_keys(codigo)
                estado = resolve_piece_production_status(codigo, set_armado, set_remate)
                pieza["estado_prod"] = estado

                for key in codigo_keys:
                    master_info = master_measure_map.get(key)
                    if master_info:
                        if pieza.get("cuerda_interna") is None:
                            pieza["cuerda_interna"] = master_info.get("cuerda_interna")
                        if pieza.get("cuerda_externa") is None:
                            pieza["cuerda_externa"] = master_info.get("cuerda_externa")
                        if pieza.get("flecha") is None:
                            pieza["flecha"] = master_info.get("flecha")
                        break

                if not piece_matches_status_filter(estado, estado_filter):
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
            cantidad, msg = soft_delete_many(
                db,
                collection_origen="piezas",
                filtro_docs={"_id": {"$in": object_ids}},
                deleted_by_user_id=session.get("user_id"),
                deleted_by_user_name=session.get("nombre"),
                deleted_by_ip=request.remote_addr,
                motivo="soporte eliminación masiva piezas",
            )
            flash(msg, "success" if cantidad > 0 else "danger")
        except Exception as exc:
            flash(f"Error al eliminar piezas: {str(exc)}", "danger")

        return redirect(url_for("soporte_piezas_masivas"))

    @app.route("/soporte/etiquetas", methods=["GET", "POST"])
    @login_required(["soporte", "administrador", "supervisor"])
    def soporte_etiquetas():
        from core.helpers.date_utils import to_cl

        page = normalize_page(request.args.get("page", 1))
        filtro = {}

        corte_sel = request.args.get("corte", "")
        cliente_sel = request.args.get("cliente", "")
        marco_sel = request.args.get("marco", "")
        tramo_sel = request.args.get("tramo", "")
        estado_filter = request.args.get("estado", "todos")

        if request.method == "POST":
            corte_sel = request.form.get("corte") or ""
            cliente_sel = request.form.get("cliente") or ""
            marco_sel = request.form.get("marco") or ""
            tramo_sel = request.form.get("tramo") or ""
            estado_filter = request.form.get("estado") or "todos"
            return redirect(
                url_for(
                    "soporte_etiquetas",
                    corte=corte_sel,
                    cliente=cliente_sel,
                    marco=marco_sel,
                    tramo=tramo_sel,
                    estado=estado_filter,
                )
            )

        cortes_disponibles = list(
            db.cortes.find({}, {"nombre": 1, "inicio": 1, "fin": 1, "creado_en": 1}).sort("creado_en", -1)
        )
        for c in cortes_disponibles:
            if c.get("creado_en"):
                c["creado_en"] = to_cl(c["creado_en"])

        corte_activo = None
        es_corte_historico = False
        corte_id = None

        if corte_sel and corte_sel != "actual":
            corte_activo = db.cortes.find_one({"nombre": corte_sel})
            if not corte_activo:
                try:
                    corte_activo = db.cortes.find_one({"_id": ObjectId(corte_sel)})
                except Exception:
                    corte_activo = None
            if corte_activo:
                es_corte_historico = True
                corte_id = corte_activo["_id"]
                filtro["corte_id"] = corte_id

        if cliente_sel and cliente_sel != "todos":
            filtro["empresa"] = cliente_sel
        if marco_sel and marco_sel != "todos":
            filtro["marco"] = marco_sel
        if tramo_sel and tramo_sel != "todos":
            filtro["tramo"] = tramo_sel

        if es_corte_historico:
            try:
                all_piezas_corte = list(
                    db.piezas_historicas.find({"corte_id": corte_id}, {"empresa": 1, "marco": 1, "tramo": 1})
                )
                clientes = sorted(list(set(p.get("empresa", "") for p in all_piezas_corte if p.get("empresa"))), key=str)
                marcos = sorted(list(set(p.get("marco", "") for p in all_piezas_corte if p.get("marco"))), key=str)
                tramos = sorted(list(set(p.get("tramo", "") for p in all_piezas_corte if p.get("tramo"))), key=str)
            except Exception:
                clientes, marcos, tramos = [], [], []

            piezas = list(db.piezas_historicas.find(filtro).limit(5000).sort("_id", -1))
            codigos_en_pantalla = [pieza.get("codigo") for pieza in piezas if pieza.get("codigo")]
            set_armado, set_remate = get_piece_status_sets(db, codigos_en_pantalla)
            master_measure_map = build_piece_master_measure_map(
                db, codigos_en_pantalla, corte_id=corte_id
            )
        else:
            try:
                clientes = sorted([x for x in db.piezas.distinct("empresa") if x], key=str)
                marcos = sorted([x for x in db.piezas.distinct("marco") if x], key=str)
                tramos = sorted([x for x in db.piezas.distinct("tramo") if x], key=str)
            except Exception as exc:
                print(f"Error obteniendo filtros: {exc}")
                clientes, marcos, tramos = [], [], []

            piezas = list(db.piezas.find(filtro).limit(5000).sort("_id", -1))
            codigos_en_pantalla = [pieza.get("codigo") for pieza in piezas if pieza.get("codigo")]
            set_armado, set_remate = get_piece_status_sets(db, codigos_en_pantalla)
            master_measure_map = build_piece_master_measure_map(
                db, codigos_en_pantalla
            )

        piezas_finales = []
        if piezas:
            for pieza in piezas:
                codigo = pieza.get("codigo")
                codigo_keys = build_codigo_lookup_keys(codigo)
                estado = resolve_piece_production_status(codigo, set_armado, set_remate)
                pieza["estado_prod"] = estado

                for key in codigo_keys:
                    master_info = master_measure_map.get(key)
                    if master_info:
                        if pieza.get("cuerda_interna") is None:
                            pieza["cuerda_interna"] = master_info.get("cuerda_interna")
                        if pieza.get("cuerda_externa") is None:
                            pieza["cuerda_externa"] = master_info.get("cuerda_externa")
                        if pieza.get("flecha") is None:
                            pieza["flecha"] = master_info.get("flecha")
                        break

                if not piece_matches_status_filter(estado, estado_filter):
                    continue

                piezas_finales.append(pieza)

        piezas_pagina, pagination = paginate_list(
            piezas_finales,
            "soporte_etiquetas",
            page=page,
            corte=corte_sel,
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

        return render_template(
            "soporte_etiquetas.html",
            piezas=piezas_pagina,
            cortes=cortes_disponibles,
            corte_sel=corte_sel,
            corte_activo=corte_activo,
            es_corte_historico=es_corte_historico,
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
