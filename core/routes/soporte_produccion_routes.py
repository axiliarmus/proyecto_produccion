from datetime import datetime, timezone

from bson import ObjectId
from flask import flash, redirect, render_template, request, session, url_for
from pymongo.errors import BulkWriteError

from core.helpers.date_utils import CL, to_cl
from core.helpers.soft_delete import soft_delete_one


def register_soporte_produccion_routes(app, db, login_required):
    """Registra rutas de soporte para gestión de producción activa."""

    def _build_filtro_from_form():
        codigo = (request.form.get("codigo_pieza") or "").strip()
        operador_sel = request.form.get("operador")
        fecha_inicio = request.form.get("fecha_inicio")
        fecha_fin = request.form.get("fecha_fin")
        filtro = {}

        if codigo:
            filtro["codigo_pieza"] = {"$regex": f"^{str(codigo).strip()}$", "$options": "i"}

        if operador_sel and operador_sel != "todos":
            filtro["usuario"] = operador_sel

        if fecha_inicio or fecha_fin:
            start_cl = None
            end_cl = None
            if fecha_inicio:
                d1 = datetime.strptime(fecha_inicio, "%Y-%m-%d").date()
                start_cl = datetime.combine(d1, datetime.min.time()).replace(tzinfo=CL)
            if fecha_fin:
                d2 = datetime.strptime(fecha_fin, "%Y-%m-%d").date()
                end_cl = datetime.combine(d2, datetime.max.time()).replace(tzinfo=CL)
            rango = {}
            if start_cl:
                rango["$gte"] = start_cl.astimezone(timezone.utc)
            if end_cl:
                rango["$lte"] = end_cl.astimezone(timezone.utc)
            if rango:
                filtro["fecha"] = rango

        return filtro, codigo, operador_sel, fecha_inicio, fecha_fin

    @app.route("/soporte/produccion", methods=["GET", "POST"])
    @login_required("soporte")
    def soporte_produccion_list():
        codigo = None
        operador_sel = None
        fecha_inicio = None
        fecha_fin = None
        filtro = {}

        if request.method == "POST":
            filtro, codigo, operador_sel, fecha_inicio, fecha_fin = _build_filtro_from_form()

        registros = list(db.produccion.find(filtro).sort("fecha", -1))
        operadores = db.produccion.distinct("usuario")
        cortes = list(db.cortes.find().sort("creado_en", -1))

        for registro in registros:
            if registro.get("fecha"):
                registro["fecha"] = to_cl(registro.get("fecha"))

        return render_template(
            "crud_produccion.html",
            registros=registros,
            codigo_sel=codigo,
            operadores=sorted(operadores),
            operador_sel=operador_sel,
            fecha_inicio=fecha_inicio,
            fecha_fin=fecha_fin,
            cortes=cortes,
        )

    @app.route("/soporte/produccion/asignar-corte-masivo", methods=["POST"])
    @login_required("soporte")
    def soporte_produccion_asignar_corte_masivo():
        corte_id_raw = request.form.get("corte_id") or ""
        scope = (request.form.get("scope") or "filtrados").strip()

        if not ObjectId.is_valid(str(corte_id_raw)):
            flash("Debes seleccionar un corte válido.", "warning")
            return redirect(url_for("soporte_produccion_list"))

        corte_id = ObjectId(corte_id_raw)
        corte = db.cortes.find_one({"_id": corte_id})
        if not corte:
            flash("Corte no encontrado.", "warning")
            return redirect(url_for("soporte_produccion_list"))

        filtro, _, _, _, _ = _build_filtro_from_form()
        if scope != "filtrados":
            filtro = {}

        registros = list(db.produccion.find(filtro))
        if not registros:
            flash("No hay registros para asignar al corte.", "info")
            return redirect(url_for("soporte_produccion_list"))

        codigos = set()
        for r in registros:
            if r.get("codigo_pieza"):
                codigos.add(r.get("codigo_pieza"))
                codigos.add(str(r.get("codigo_pieza")))

        piezas_cache = {}
        for codigo in codigos:
            try:
                cod_int = int(codigo)
            except Exception:
                cod_int = codigo
            pieza = db.piezas.find_one({"$or": [{"codigo": codigo}, {"codigo": str(codigo)}, {"codigo": cod_int}]})
            if not pieza:
                pieza = db.piezas_historicas.find_one(
                    {"$or": [{"codigo": codigo}, {"codigo": str(codigo)}, {"codigo": cod_int}]},
                    sort=[("_id", -1)],
                )
            if pieza:
                piezas_cache[codigo] = pieza
                piezas_cache[str(codigo)] = pieza

        historicos = []
        ids = []
        for r in registros:
            ids.append(r["_id"])
            pieza_ref = piezas_cache.get(r.get("codigo_pieza")) or piezas_cache.get(str(r.get("codigo_pieza")))
            r["empresa"] = r.get("empresa") or (pieza_ref.get("empresa") if pieza_ref else "")
            r["marco"] = r.get("marco") or (pieza_ref.get("marco") if pieza_ref else "")
            r["tramo"] = r.get("tramo") or (pieza_ref.get("tramo") if pieza_ref else "")
            r["tipo_precio"] = r.get("tipo_precio") or (pieza_ref.get("tipo_precio") if pieza_ref else "metro")
            r["corte_id"] = corte_id
            historicos.append(r)

        try:
            db.produccion_historica.insert_many(historicos, ordered=False)
        except BulkWriteError:
            pass

        for codigo in codigos:
            if db.piezas_historicas.find_one({"corte_id": corte_id, "$or": [{"codigo": codigo}, {"codigo": str(codigo)}]}):
                continue
            pieza_ref = piezas_cache.get(codigo) or piezas_cache.get(str(codigo))
            if not pieza_ref:
                continue
            p_copy = dict(pieza_ref)
            p_copy.pop("_id", None)
            p_copy["corte_id"] = corte_id
            try:
                db.piezas_historicas.insert_one(p_copy)
            except Exception:
                pass

        db.produccion.delete_many({"_id": {"$in": ids}})
        flash(f"✅ Se asignaron {len(ids)} registros al corte: {corte.get('nombre')}", "success")
        return redirect(url_for("soporte_produccion_list"))

    @app.route("/soporte/produccion/<id>/editar")
    @login_required("soporte")
    def soporte_produccion_editar_form(id):
        reg = db.produccion.find_one({"_id": ObjectId(id)})
        if not reg:
            flash("Registro no encontrado", "warning")
            return redirect(url_for("soporte_produccion_list"))
        cortes = list(db.cortes.find().sort("creado_en", -1))
        return render_template("produccion_form.html", modo="editar", reg=reg, cortes=cortes)

    @app.route("/soporte/produccion/<id>/editar", methods=["POST"])
    @login_required("soporte")
    def soporte_produccion_editar_post(id):
        empresa = request.form.get("empresa", "").strip()
        marco = request.form.get("marco", "").strip()
        tramo = request.form.get("tramo", "").strip()
        usuario = request.form.get("usuario", "").strip()
        modo = request.form.get("modo", "").strip()
        codigo_pieza = request.form.get("codigo_pieza", "").strip()
        calidad_status = request.form.get("calidad_status", "").strip() or "pendiente"
        cuerda_interna = request.form.get("cuerda_interna")
        cuerda_externa = request.form.get("cuerda_externa")
        flecha = request.form.get("flecha")
        fecha_str = request.form.get("fecha")

        fecha_dt = None
        if fecha_str:
            try:
                dt_local = datetime.strptime(fecha_str, "%Y-%m-%dT%H:%M").replace(tzinfo=CL)
                fecha_dt = dt_local.astimezone(timezone.utc)
            except Exception:
                fecha_dt = None

        update = {
            "empresa": empresa,
            "marco": marco,
            "tramo": tramo,
            "usuario": usuario,
            "modo": modo,
            "codigo_pieza": codigo_pieza,
            "calidad_status": calidad_status,
            "cuerda_interna": cuerda_interna,
            "cuerda_externa": cuerda_externa,
            "flecha": flecha,
        }
        if fecha_dt:
            update["fecha"] = fecha_dt

        db.produccion.update_one({"_id": ObjectId(id)}, {"$set": update})

        asignar_corte_id = request.form.get("asignar_corte_id")
        if asignar_corte_id:
            try:
                corte = db.cortes.find_one({"_id": ObjectId(asignar_corte_id)})
                if corte:
                    reg_actualizado = db.produccion.find_one({"_id": ObjectId(id)})
                    if reg_actualizado:
                        reg_historico = dict(reg_actualizado)
                        reg_historico.pop("_id", None)
                        reg_historico["corte_id"] = corte["_id"]
                        db.produccion_historica.insert_one(reg_historico)

                        cod_pieza = reg_actualizado.get("codigo_pieza")
                        pieza_hist = None
                        if cod_pieza:
                            pieza_hist = db.piezas_historicas.find_one(
                                {"corte_id": corte["_id"], "$or": [{"codigo": cod_pieza}, {"codigo": str(cod_pieza)}]}
                            )
                            if not pieza_hist:
                                try:
                                    cod_int = int(cod_pieza)
                                except Exception:
                                    cod_int = cod_pieza

                                pieza_activa = db.piezas.find_one(
                                    {"$or": [{"codigo": cod_pieza}, {"codigo": str(cod_pieza)}, {"codigo": cod_int}]}
                                )
                                if not pieza_activa:
                                    pieza_activa = db.piezas_historicas.find_one(
                                        {"$or": [{"codigo": cod_pieza}, {"codigo": str(cod_pieza)}, {"codigo": cod_int}]},
                                        sort=[("_id", -1)],
                                    )

                                if pieza_activa:
                                    p_copy = dict(pieza_activa)
                                    p_copy.pop("_id", None)
                                    p_copy["corte_id"] = corte["_id"]
                                    db.piezas_historicas.insert_one(p_copy)

                        db.produccion.delete_one({"_id": ObjectId(id)})
                        flash(f'Registro actualizado y asignado al corte: {corte["nombre"]} ✔', "success")
                        return redirect(url_for("soporte_produccion_list"))
            except Exception as exc:
                flash(f"Error al asignar el corte: {str(exc)}", "danger")

        flash("Registro actualizado ✔", "success")
        return redirect(url_for("soporte_produccion_list"))

    @app.route("/soporte/produccion/<id>/delete", methods=["POST"])
    @login_required("soporte")
    def soporte_produccion_delete(id):
        ok, msg = soft_delete_one(
            db,
            collection_origen="produccion",
            filtro_doc={"_id": ObjectId(id)},
            deleted_by_user_id=session.get("user_id"),
            deleted_by_user_name=session.get("nombre"),
            deleted_by_ip=request.remote_addr,
            motivo="soporte botón eliminar registro producción",
        )
        flash(msg, "success" if ok else "danger")
        return redirect(url_for("soporte_produccion_list"))
