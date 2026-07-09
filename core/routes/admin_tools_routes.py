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

            if pieza_activa_db:
                prod_recs = list(db.produccion.find({"codigo_pieza": str(pieza_activa_db.get("codigo"))}).sort("fecha", -1))
                for record in prod_recs:
                    if record.get("fecha"):
                        record["fecha"] = to_cl(record.get("fecha"))

                pieza_activa = {
                    "data": pieza_activa_db,
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

        return render_template(
            "admin_picking.html",
            initial_data=data,
            scanned_codes=list(scanned_codes),
            initial_rejected=rejected_details,
        )

    @app.route("/api/picking/scan", methods=["POST"])
    @login_required(["administrador", "soporte", "supervisor"])
    def api_picking_scan():
        try:
            data = request.json
            codigo = data.get("codigo", "").strip()

            if not codigo:
                return {"success": False, "message": "Código vacío"}, 400

            patron_regex = f"^{re.escape(codigo)}$"
            filtro_regex = {"$regex": patron_regex, "$options": "i"}

            if db.picking.find_one({"codigo": filtro_regex}):
                return {"success": False, "message": f"Pieza {codigo} YA fue escaneada previamente"}, 400

            pieza = db.piezas.find_one({"codigo": filtro_regex})
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
                        "kilo_pieza": last_prod.get("peso_calculado", 0),
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
            db.picking.delete_many({})
            return {"success": True}
        except Exception as exc:
            return {"success": False, "message": str(exc)}, 500
