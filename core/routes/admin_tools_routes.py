import re
from datetime import datetime, timezone

from bson import ObjectId
from flask import flash, redirect, render_template, request, session, url_for

from core.helpers.date_utils import to_cl


def register_admin_tools_routes(app, db, login_required, normalize_page, paginate_list, send_excel_file):
    """Registra buscador administrativo, exporte archivado y herramienta de picking."""

    @app.route("/admin/buscador", methods=["GET", "POST"])
    @login_required(["administrador", "soporte", "supervisor"])
    def admin_buscador_piezas():
        codigo = request.args.get("codigo") or None
        page = normalize_page(request.args.get("page", 1))
        pieza_activa = None
        piezas_historicas = []

        if request.method == "POST":
            return redirect(
                url_for(
                    "admin_buscador_piezas",
                    codigo=(request.form.get("codigo") or "").strip(),
                    page=1,
                )
            )

        if codigo:
            codigo = codigo.strip()
            query_str = {"codigo": codigo}
            query_int = {"codigo": int(codigo)} if codigo.isdigit() else None

            pieza_activa_db = db.piezas.find_one(query_str)
            if not pieza_activa_db and query_int:
                pieza_activa_db = db.piezas.find_one(query_int)

            prod_query = [{"codigo_pieza": codigo}, {"codigo_pieza": str(codigo)}]
            if codigo.isdigit():
                prod_query.append({"codigo_pieza": int(codigo)})
            prod_recs = list(db.produccion.find({"$or": prod_query}).sort("fecha", -1))
            for record in prod_recs:
                if record.get("fecha"):
                    record["fecha"] = to_cl(record.get("fecha"))

            if pieza_activa_db or prod_recs:
                data_activa = pieza_activa_db or {
                    "codigo": codigo,
                    "empresa": prod_recs[0].get("empresa", "Sin Cliente") if prod_recs else "Sin Cliente",
                    "marco": prod_recs[0].get("marco", "Sin Marco") if prod_recs else "Sin Marco",
                    "tramo": prod_recs[0].get("tramo", "Sin Tramo") if prod_recs else "Sin Tramo",
                    "kilo_pieza": prod_recs[0].get("kilo_pieza", 0) if prod_recs else 0,
                    "tipo_precio": prod_recs[0].get("tipo_precio", "metro") if prod_recs else "metro",
                }
                pieza_activa = {
                    "data": data_activa,
                    "produccion": prod_recs,
                    "estado_actual": "En Proceso" if prod_recs else "Sin Producción",
                }

                has_armado = any(record["modo"] == "armador" for record in prod_recs)
                has_remate = any(record["modo"] == "rematador" for record in prod_recs)
                if has_remate:
                    pieza_activa["estado_actual"] = "Rematado (Finalizado)"
                elif has_armado:
                    pieza_activa["estado_actual"] = "Armado (Pendiente Remate)"

            hist_cursor = db.piezas_historicas.find(
                {"$or": [{"codigo": codigo}, {"codigo": int(codigo) if codigo.isdigit() else "###"}]}
            ).sort("_id", -1)

            for pieza_hist in hist_cursor:
                corte_id = pieza_hist.get("corte_id")
                corte_info = db.cortes.find_one({"_id": corte_id})
                corte_nombre = corte_info.get("nombre") if corte_info else "Desconocido"

                prod_hist_recs = list(
                    db.produccion_historica.find({"codigo_pieza": str(pieza_hist.get("codigo")), "corte_id": corte_id}).sort(
                        "fecha", -1
                    )
                )

                for record in prod_hist_recs:
                    if record.get("fecha"):
                        record["fecha"] = to_cl(record.get("fecha"))

                estado_hist = "Sin Producción"
                has_armado_h = any(record["modo"] == "armador" for record in prod_hist_recs)
                has_remate_h = any(record["modo"] == "rematador" for record in prod_hist_recs)
                if has_remate_h:
                    estado_hist = "Rematado"
                elif has_armado_h:
                    estado_hist = "Armado"

                piezas_historicas.append(
                    {
                        "data": pieza_hist,
                        "produccion": prod_hist_recs,
                        "corte_nombre": corte_nombre,
                        "estado_cierre": estado_hist,
                    }
                )

        piezas_historicas_pagina, pagination = paginate_list(
            piezas_historicas,
            "admin_buscador_piezas",
            page=page,
            codigo=codigo,
        )

        return render_template(
            "admin_buscador.html",
            codigo=codigo,
            pieza_activa=pieza_activa,
            piezas_historicas=piezas_historicas_pagina,
            pagination=pagination,
        )

    @app.route("/admin/piezas/archivadas/export", methods=["POST"])
    @login_required(["administrador", "soporte", "supervisor"])
    def exportar_piezas_archivadas_excel():
        corte_nombre = request.form.get("corte_nombre")
        cliente_sel = request.form.get("cliente")
        marco_sel = request.form.get("marco")
        tramo_sel = request.form.get("tramo")
        estado_filter = request.form.get("estado")

        corte = db.cortes.find_one({"nombre": corte_nombre})
        if not corte:
            flash("Corte no encontrado", "danger")
            return redirect(url_for("admin_produccion_archivada"))

        corte_id = corte.get("_id")
        filtro = {"corte_id": corte_id}

        if cliente_sel and cliente_sel != "todos":
            filtro["empresa"] = cliente_sel
        if marco_sel and marco_sel != "todos":
            filtro["marco"] = marco_sel
        if tramo_sel and tramo_sel != "todos":
            filtro["tramo"] = tramo_sel

        if estado_filter and estado_filter != "todos":
            modo_buscado = "rematador" if estado_filter == "Rematado" else "armador" if estado_filter == "Armado" else None
            if modo_buscado:
                codigos_con_estado = db.produccion_historica.distinct(
                    "codigo_pieza", {"modo": modo_buscado, "corte_id": corte_id}
                )
                filtro["codigo"] = {"$in": codigos_con_estado}

        piezas = list(db.piezas_historicas.find(filtro).sort("_id", -1))
        codigos_en_lista = [pieza.get("codigo") for pieza in piezas]
        set_armado = set(
            db.produccion_historica.distinct(
                "codigo_pieza", {"codigo_pieza": {"$in": codigos_en_lista}, "modo": "armador", "corte_id": corte_id}
            )
        )
        set_remate = set(
            db.produccion_historica.distinct(
                "codigo_pieza", {"codigo_pieza": {"$in": codigos_en_lista}, "modo": "rematador", "corte_id": corte_id}
            )
        )

        data = []
        for pieza in piezas:
            codigo = pieza.get("codigo")
            estado = "Sin producción"
            if codigo in set_remate:
                estado = "Rematado"
            elif codigo in set_armado:
                estado = "Armado"

            if estado_filter == "Sin producción" and estado != "Sin producción":
                continue
            if estado_filter == "Armado" and estado != "Armado":
                continue
            if estado_filter == "Rematado" and estado != "Rematado":
                continue

            data.append(
                {
                    "Código": codigo,
                    "Cliente": pieza.get("empresa", ""),
                    "Marco": pieza.get("marco", ""),
                    "Tramo": pieza.get("tramo", ""),
                    "Kilo Pieza": pieza.get("kilo_pieza", 0),
                    "Cuerda Int.": pieza.get("cuerda_interna", ""),
                    "Cuerda Ext.": pieza.get("cuerda_externa", ""),
                    "Flecha": pieza.get("flecha", ""),
                    "Tipo Precio": pieza.get("tipo_precio", ""),
                    "Estado al Corte": estado,
                }
            )

        return send_excel_file(data, "PiezasArchivadas", f"piezas_corte_{corte_nombre.replace(' ', '_')}.xlsx")

    @app.route("/admin/picking")
    @login_required(["administrador", "soporte", "supervisor"])
    def admin_picking():
        registros = list(db.picking.find().sort("fecha", -1))
        data = {}
        scanned_codes = set()
        rejected_details = []

        for registro in registros:
            empresa = registro.get("empresa")
            marco = registro.get("marco")
            tramo = registro.get("tramo")
            estado = registro.get("estado")
            calidad = registro.get("calidad")
            code = registro.get("codigo")

            scanned_codes.add(code)

            if empresa not in data:
                data[empresa] = {}
            if marco not in data[empresa]:
                data[empresa][marco] = {}
            if tramo not in data[empresa][marco]:
                data[empresa][marco][tramo] = {"armado": 0, "validado": 0, "rechazado": 0, "sin_prod": 0, "total": 0}

            data[empresa][marco][tramo]["total"] += 1

            if estado == "Armado":
                data[empresa][marco][tramo]["armado"] += 1
            elif estado == "Rematado":
                if calidad == "aprobado":
                    data[empresa][marco][tramo]["validado"] += 1
                elif calidad == "rechazado":
                    data[empresa][marco][tramo]["rechazado"] += 1
                    rejected_details.append({"codigo": code, "empresa": empresa, "marco": marco, "tramo": tramo})
                else:
                    data[empresa][marco][tramo]["validado"] += 1
            else:
                data[empresa][marco][tramo]["sin_prod"] += 1

        historial = list(db.picking_historial.find({}, {"piezas": 0}).sort("fecha_cierre", -1).limit(50))
        for h in historial:
            if h.get("fecha_cierre"):
                h["fecha_cl"] = to_cl(h.get("fecha_cierre"))

        return render_template(
            "admin_picking.html",
            initial_data=data,
            scanned_codes=list(scanned_codes),
            initial_rejected=rejected_details,
            historial=historial,
        )

    @app.route("/api/picking/scan", methods=["POST"])
    @login_required(["administrador", "soporte", "supervisor"])
    def api_picking_scan():
        try:
            data = request.json
            codigo = data.get("codigo", "").strip()

            if not codigo:
                return {"success": False, "message": "Código vacío"}, 400

            filtro_regex = re.compile(f"^{re.escape(codigo)}$", re.IGNORECASE)

            if db.picking.find_one({"codigo": filtro_regex}):
                return {"success": False, "message": f"Pieza {codigo} YA fue escaneada previamente"}, 400

            pieza = db.piezas.find_one({"codigo": filtro_regex})
            if not pieza:
                pieza = db.piezas_historicas.find_one({"codigo": filtro_regex}, sort=[("_id", -1)])

            last_prod_active = db.produccion.find_one({"codigo_pieza": filtro_regex}, sort=[("fecha", -1)])
            last_prod_hist = db.produccion_historica.find_one({"codigo_pieza": filtro_regex}, sort=[("fecha", -1)])

            last_prod = None
            if last_prod_active and last_prod_hist:
                last_prod = last_prod_active if last_prod_active["fecha"] >= last_prod_hist["fecha"] else last_prod_hist
            elif last_prod_active:
                last_prod = last_prod_active
            elif last_prod_hist:
                last_prod = last_prod_hist

            if not pieza:
                if last_prod:
                    codigo_encontrado = str(last_prod.get("codigo_pieza", codigo))
                    pieza = {
                        "codigo": codigo_encontrado,
                        "empresa": last_prod.get("empresa", "Desconocido"),
                        "marco": last_prod.get("marco", "Desconocido"),
                        "tramo": last_prod.get("tramo", "Desconocido"),
                        "kilo_pieza": last_prod.get("kilo_pieza", 0) or last_prod.get("peso_calculado", 0),
                    }
                else:
                    return {"success": False, "message": f"Pieza {codigo} no encontrada en sistema ni históricos"}, 404

            codigo_final = pieza.get("codigo")
            estado = "Sin Producción"
            calidad_status = None
            prod_id = None

            if last_prod:
                modo = last_prod.get("modo")
                prod_id = str(last_prod.get("_id"))
                if modo == "armador":
                    estado = "Armado"
                elif modo == "rematador":
                    estado = "Rematado"
                    calidad_status = last_prod.get("calidad_status")

            if estado != "Rematado":
                scan_entry = {
                    "codigo": codigo_final,
                    "empresa": pieza.get("empresa", "Desconocido"),
                    "marco": pieza.get("marco", "Desconocido"),
                    "tramo": pieza.get("tramo", "Desconocido"),
                    "estado": estado,
                    "calidad": None,
                    "fecha": datetime.now(timezone.utc),
                    "usuario": session.get("nombre"),
                }
                db.picking.insert_one(scan_entry)

            return {
                "success": True,
                "pieza": {
                    "codigo": codigo_final,
                    "empresa": pieza.get("empresa", "Desconocido"),
                    "marco": pieza.get("marco", "Desconocido"),
                    "tramo": pieza.get("tramo", "Desconocido"),
                },
                "estado": estado,
                "calidad_status": calidad_status,
                "prod_id": prod_id,
            }
        except Exception as exc:
            print(f"Error picking scan: {exc}")
            return {"success": False, "message": "Error interno"}, 500

    @app.route("/api/picking/validar", methods=["POST"])
    @login_required(["administrador", "soporte", "supervisor"])
    def api_picking_validar():
        try:
            data = request.json
            codigo = data.get("codigo")
            prod_id = data.get("prod_id")
            decision = data.get("decision")
            comentario = data.get("comentario")
            pieza_data = data.get("pieza")

            if prod_id:
                res = db.produccion.update_one(
                    {"_id": ObjectId(prod_id)},
                    {
                        "$set": {
                            "calidad_status": decision,
                            "comentario_supervisor": comentario,
                            "fecha_validacion": datetime.now(timezone.utc),
                        }
                    },
                )
                if res.matched_count == 0:
                    db.produccion_historica.update_one(
                        {"_id": ObjectId(prod_id)},
                        {
                            "$set": {
                                "calidad_status": decision,
                                "comentario_supervisor": comentario,
                                "fecha_validacion": datetime.now(timezone.utc),
                            }
                        },
                    )

            scan_entry = {
                "codigo": codigo,
                "empresa": pieza_data.get("empresa"),
                "marco": pieza_data.get("marco"),
                "tramo": pieza_data.get("tramo"),
                "estado": "Rematado",
                "calidad": decision,
                "fecha": datetime.now(timezone.utc),
                "usuario": session.get("nombre"),
            }
            db.picking.insert_one(scan_entry)

            return {"success": True}
        except Exception as exc:
            print(f"Error validar picking: {exc}")
            return {"success": False, "message": str(exc)}, 500

    @app.route("/api/picking/reset", methods=["POST"])
    @login_required(["administrador", "soporte", "supervisor"])
    def api_picking_reset():
        try:
            payload = request.get_json(silent=True) or {}
            nombre_sesion = (payload.get("nombre") or "").strip()
            nota = (payload.get("nota") or "").strip()

            registros = list(db.picking.find().sort("fecha", 1))
            historial_id = None

            if registros:
                now_dt = datetime.now(timezone.utc)
                now_cl_dt = to_cl(now_dt)
                default_nombre = f"Picking {now_cl_dt.strftime('%d/%m/%Y %H:%M')}"
                if not nombre_sesion:
                    nombre_sesion = default_nombre

                total_piezas = len(registros)
                total_armadas = sum(1 for r in registros if r.get("estado") == "Armado")
                total_rematadas = sum(1 for r in registros if r.get("estado") == "Rematado")
                total_validadas = sum(
                    1
                    for r in registros
                    if r.get("calidad") == "aprobado"
                    or (r.get("estado") == "Rematado" and r.get("calidad") != "rechazado")
                )
                total_rechazadas = sum(1 for r in registros if r.get("calidad") == "rechazado")
                total_sin_prod = sum(1 for r in registros if r.get("estado") not in ("Armado", "Rematado"))

                resumen_grupos = {}
                piezas_detalle = []
                for r in registros:
                    emp = r.get("empresa") or "Sin Cliente"
                    mrc = r.get("marco") or "Sin Marco"
                    trm = r.get("tramo") or "Sin Tramo"
                    est = r.get("estado") or "Sin Producción"
                    cal = r.get("calidad")
                    cod = r.get("codigo")

                    resumen_grupos.setdefault(emp, {}).setdefault(mrc, {}).setdefault(
                        trm, {"armado": 0, "validado": 0, "rechazado": 0, "sin_prod": 0, "total": 0}
                    )
                    resumen_grupos[emp][mrc][trm]["total"] += 1
                    if est == "Armado":
                        resumen_grupos[emp][mrc][trm]["armado"] += 1
                    elif est == "Rematado":
                        if cal == "rechazado":
                            resumen_grupos[emp][mrc][trm]["rechazado"] += 1
                        else:
                            resumen_grupos[emp][mrc][trm]["validado"] += 1
                    else:
                        resumen_grupos[emp][mrc][trm]["sin_prod"] += 1

                    piezas_detalle.append(
                        {
                            "codigo": cod,
                            "empresa": emp,
                            "marco": mrc,
                            "tramo": trm,
                            "estado": est,
                            "calidad": cal,
                            "fecha": r.get("fecha"),
                            "usuario": r.get("usuario"),
                        }
                    )

                hist_doc = {
                    "nombre": nombre_sesion,
                    "nota": nota,
                    "fecha_cierre": now_dt,
                    "usuario": session.get("nombre") or session.get("usuario") or "Usuario",
                    "usuario_id": session.get("user_id"),
                    "total": total_piezas,
                    "armadas": total_armadas,
                    "rematadas": total_rematadas,
                    "validadas": total_validadas,
                    "rechazadas": total_rechazadas,
                    "sin_prod": total_sin_prod,
                    "resumen_grupos": resumen_grupos,
                    "piezas": piezas_detalle,
                }
                res_ins = db.picking_historial.insert_one(hist_doc)
                historial_id = str(res_ins.inserted_id)

            db.picking.delete_many({})
            return {"success": True, "saved_to_history": bool(historial_id), "historial_id": historial_id}
        except Exception as exc:
            return {"success": False, "message": str(exc)}, 500

    @app.route("/api/picking/historial/<hist_id>", methods=["GET"])
    @login_required(["administrador", "soporte", "supervisor"])
    def api_picking_historial_detalle(hist_id):
        try:
            if not ObjectId.is_valid(hist_id):
                return {"success": False, "message": "ID inválido"}, 400
            hist = db.picking_historial.find_one({"_id": ObjectId(hist_id)})
            if not hist:
                return {"success": False, "message": "Picking no encontrado"}, 404

            hist["_id"] = str(hist["_id"])
            if hist.get("fecha_cierre"):
                hist["fecha_cierre_str"] = to_cl(hist["fecha_cierre"]).strftime("%d/%m/%Y %H:%M")
            for p in hist.get("piezas", []):
                if p.get("fecha"):
                    p["fecha_str"] = to_cl(p["fecha"]).strftime("%d/%m/%Y %H:%M")

            return {"success": True, "data": hist}
        except Exception as exc:
            return {"success": False, "message": str(exc)}, 500

    @app.route("/admin/picking/historial/<hist_id>/export", methods=["GET"])
    @login_required(["administrador", "soporte", "supervisor"])
    def exportar_picking_historial_excel(hist_id):
        if not ObjectId.is_valid(hist_id):
            flash("ID de picking inválido", "danger")
            return redirect(url_for("admin_picking"))

        hist = db.picking_historial.find_one({"_id": ObjectId(hist_id)})
        if not hist:
            flash("Picking histórico no encontrado", "danger")
            return redirect(url_for("admin_picking"))

        piezas = hist.get("piezas", [])
        data_excel = []
        for p in piezas:
            data_excel.append(
                {
                    "Código": p.get("codigo", ""),
                    "Cliente": p.get("empresa", ""),
                    "Marco": p.get("marco", ""),
                    "Tramo": p.get("tramo", ""),
                    "Estado": p.get("estado", ""),
                    "Calidad": p.get("calidad", "") or ("Aprobado" if p.get("estado") == "Rematado" else ""),
                    "Usuario": p.get("usuario", ""),
                    "Fecha": to_cl(p.get("fecha")).strftime("%d/%m/%Y %H:%M") if p.get("fecha") else "",
                }
            )

        nombre_archivo = f"picking_{hist.get('nombre', 'sesion')}".replace(" ", "_").replace("/", "-")
        return send_excel_file(data_excel, "DetallePicking", f"{nombre_archivo}.xlsx")

    @app.route("/admin/picking/historial/<hist_id>/eliminar", methods=["POST"])
    @login_required(["administrador"])
    def eliminar_picking_historial(hist_id):
        if ObjectId.is_valid(hist_id):
            db.picking_historial.delete_one({"_id": ObjectId(hist_id)})
            flash("Registro histórico de picking eliminado.", "success")
        return redirect(url_for("admin_picking"))
