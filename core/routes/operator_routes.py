import hashlib
import json
import os
import time
import urllib.request
from datetime import datetime, timedelta, timezone

from bson import ObjectId
from flask import flash, redirect, render_template, request, session, url_for
from pymongo.errors import DuplicateKeyError

from core.helpers.date_utils import CL, build_date_range_utc, now_cl, to_cl


# #region debug-point helpers:operator-armado-duplicate
def _debug_report_operator_armado(hypothesis_id, location, msg, data=None, run_id="post-fix"):
    try:
        debug_url = "http://127.0.0.1:7777/event"
        debug_session_id = "operator-armado-duplicate"
        env_path = os.path.join(".dbg", "operator-armado-duplicate.env")
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


def _build_submission_guard_id(user_id, modo, box, codigo_pieza, cuerda_interna_raw, cuerda_externa_raw, flecha_raw):
    raw_key = "|".join(
        [
            str(user_id or ""),
            str(modo or "").strip().lower(),
            str(box or "").strip().lower(),
            str(codigo_pieza or "").strip().lower(),
            str(cuerda_interna_raw or "").strip(),
            str(cuerda_externa_raw or "").strip(),
            str(flecha_raw or "").strip(),
        ]
    )
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def register_operator_routes(app, db, login_required, normalize_page, paginate_list, get_tunnel_url):
    """Registra rutas del dominio operador."""

    @app.route("/operador", methods=["GET", "POST"])
    @login_required("operador")
    def operador_home():
        user_id = session.get("user_id")
        nombre = session.get("nombre")
        page = normalize_page(request.args.get("page", 1))

        fecha_inicio = request.args.get("fecha_inicio")
        fecha_fin = request.args.get("fecha_fin")
        filtro = {"user_id": user_id}

        start_cl = None
        end_cl = None

        if request.method == "POST":
            return redirect(
                url_for(
                    "operador_home",
                    fecha_inicio=request.form.get("fecha_inicio") or "",
                    fecha_fin=request.form.get("fecha_fin") or "",
                    page=1,
                )
            )

        if fecha_inicio or fecha_fin:
            start_utc, end_utc = build_date_range_utc(fecha_inicio, fecha_fin)
            if start_utc:
                start_cl = start_utc.astimezone(CL)
            if end_utc:
                end_cl = end_utc.astimezone(CL)
        else:
            today = now_cl().date()
            start_cl = datetime.combine(today, datetime.min.time()).replace(tzinfo=CL)
            end_cl = datetime.combine(today, datetime.max.time()).replace(tzinfo=CL)
            fecha_inicio = today.strftime("%Y-%m-%d")
            fecha_fin = today.strftime("%Y-%m-%d")

        rango = {}
        if start_cl:
            rango["$gte"] = start_cl.astimezone(timezone.utc)
        if end_cl:
            rango["$lte"] = end_cl.astimezone(timezone.utc)
        if rango:
            filtro["fecha"] = rango

        active_recs = list(db.produccion.find(filtro))
        archived_recs = list(db.produccion_historica.find(filtro))
        piezas_produccion = active_recs + archived_recs
        piezas_produccion.sort(key=lambda x: x.get("fecha", datetime.min), reverse=True)

        usuario_obj = db.usuarios.find_one({"_id": ObjectId(user_id)})
        piezas_db = list(db.piezas.find())
        mapa_piezas_active = {str(p["codigo"]): p for p in piezas_db}
        cache_users_hist = {}
        cache_piezas_hist = {}

        boxes = list(db.boxes.find().sort("codigo", 1))
        total_general = 0

        for pieza in piezas_produccion:
            pieza["fecha"] = to_cl(pieza.get("fecha"))

            codigo = str(pieza.get("codigo_pieza"))
            modo = pieza.get("modo")
            corte_id = pieza.get("corte_id")

            peso = 0.0
            tipo_precio = "metro"

            if not corte_id:
                pieza_doc = mapa_piezas_active.get(codigo)
                if pieza_doc:
                    try:
                        peso = float(pieza_doc.get("kilo_pieza") or 0)
                    except Exception:
                        peso = 0.0
                    tipo_precio = pieza_doc.get("tipo_precio", "metro")
                else:
                    peso = float(pieza.get("kilo_pieza") or 0)
                    tipo_precio = pieza.get("tipo_precio", "metro")
            else:
                if "kilo_pieza" in pieza:
                    try:
                        peso = float(pieza["kilo_pieza"])
                    except Exception:
                        peso = 0.0
                if "tipo_precio" in pieza:
                    tipo_precio = pieza["tipo_precio"]

                if peso == 0 or "tipo_precio" not in pieza:
                    if (corte_id, codigo) not in cache_piezas_hist:
                        pieza_hist = db.piezas_historicas.find_one({"corte_id": corte_id, "codigo": codigo})
                        if not pieza_hist and codigo.isdigit():
                            pieza_hist = db.piezas_historicas.find_one({"corte_id": corte_id, "codigo": int(codigo)})
                        cache_piezas_hist[(corte_id, codigo)] = pieza_hist

                    pieza_doc = cache_piezas_hist[(corte_id, codigo)]
                    if pieza_doc:
                        if peso == 0:
                            try:
                                peso = float(pieza_doc.get("kilo_pieza") or 0)
                            except Exception:
                                peso = 0.0
                        if "tipo_precio" not in pieza:
                            tipo_precio = pieza_doc.get("tipo_precio", "metro")

            user_vals = usuario_obj
            if corte_id:
                usuario_nombre = pieza.get("usuario")
                if (corte_id, usuario_nombre) not in cache_users_hist:
                    user_hist = db.usuarios_historicos.find_one({"corte_id": corte_id, "usuario": usuario_nombre})
                    cache_users_hist[(corte_id, usuario_nombre)] = user_hist
                if cache_users_hist[(corte_id, usuario_nombre)]:
                    user_vals = cache_users_hist[(corte_id, usuario_nombre)]

            valor = 0.0
            if pieza.get("precio_unitario") not in (None, ""):
                try:
                    valor = float(pieza.get("precio_unitario") or 0)
                except Exception:
                    valor = 0.0
            elif user_vals:
                val_raw = 0
                if modo == "armador":
                    val_raw = (
                        user_vals.get("precio_metro_armado", 0)
                        if tipo_precio == "metro"
                        else user_vals.get("precio_avo_armado", 0)
                    )
                elif modo == "rematador":
                    val_raw = (
                        user_vals.get("precio_metro_remate", 0)
                        if tipo_precio == "metro"
                        else user_vals.get("precio_avo_remate", 0)
                    )

                try:
                    valor = float(val_raw or 0)
                except Exception:
                    valor = 0.0

            total = peso * valor
            pieza["peso_calculado"] = peso
            pieza["valor_calculado"] = valor
            pieza["total_calculado"] = total
            total_general += total

        piezas_pagina, pagination = paginate_list(
            piezas_produccion,
            "operador_home",
            page=page,
            fecha_inicio=fecha_inicio,
            fecha_fin=fecha_fin,
        )

        today_real = now_cl().date()
        start_today = datetime.combine(today_real, datetime.min.time()).replace(tzinfo=CL).astimezone(timezone.utc)
        end_today = datetime.combine(today_real, datetime.max.time()).replace(tzinfo=CL).astimezone(timezone.utc)

        jornada = db.jornadas.find_one({"user_id": user_id, "fecha": {"$gte": start_today, "$lte": end_today}})
        if jornada:
            if jornada.get("fecha"):
                jornada["fecha"] = to_cl(jornada.get("fecha"))
            if jornada.get("ingreso"):
                jornada["ingreso"] = to_cl(jornada.get("ingreso"))
            if jornada.get("salida"):
                jornada["salida"] = to_cl(jornada.get("salida"))

        return render_template(
            "operador.html",
            nombre=nombre,
            boxes=boxes,
            piezas_hoy=piezas_pagina,
            jornada=jornada,
            fecha_inicio=fecha_inicio,
            fecha_fin=fecha_fin,
            total_general=total_general,
            tunnel_url=get_tunnel_url(),
            pagination=pagination,
        )

    @app.route("/operador/jornada/ingreso", methods=["POST"])
    @login_required("operador")
    def operador_ingreso():
        user_id = session.get("user_id")
        today = now_cl().date()

        start_cl = datetime.combine(today, datetime.min.time()).replace(tzinfo=CL)
        end_cl = datetime.combine(today, datetime.max.time()).replace(tzinfo=CL)
        start = start_cl.astimezone(timezone.utc)
        end = end_cl.astimezone(timezone.utc)

        existe = db.jornadas.find_one({"user_id": user_id, "fecha": {"$gte": start, "$lte": end}})

        if existe and existe.get("ingreso"):
            flash("La jornada ya fue iniciada", "info")
        else:
            db.jornadas.update_one(
                {"user_id": user_id, "fecha": {"$gte": start, "$lte": end}},
                {"$set": {"user_id": user_id, "fecha": datetime.utcnow(), "ingreso": datetime.utcnow()}},
                upsert=True,
            )
            flash("Ingreso registrado", "success")

        return redirect(url_for("operador_home"))

    @app.route("/operador/jornada/salida", methods=["POST"])
    @login_required("operador")
    def operador_salida():
        user_id = session.get("user_id")
        today = now_cl().date()

        start_cl = datetime.combine(today, datetime.min.time()).replace(tzinfo=CL)
        end_cl = datetime.combine(today, datetime.max.time()).replace(tzinfo=CL)
        start = start_cl.astimezone(timezone.utc)
        end = end_cl.astimezone(timezone.utc)

        upd = db.jornadas.update_one(
            {"user_id": user_id, "fecha": {"$gte": start, "$lte": end}},
            {"$set": {"salida": datetime.utcnow()}},
        )

        if upd.matched_count:
            flash("Salida registrada", "success")
        else:
            flash("No hay jornada iniciada", "warning")

        return redirect(url_for("operador_home"))

    @app.route("/operador/registrar", methods=["POST"])
    @login_required("operador")
    def operador_registrar():
        user_id = session.get("user_id")
        usuario = session.get("nombre")
        role = session.get("role")

        if role == "operador":
            usuario_db = db.usuarios.find_one({"_id": ObjectId(user_id)})
            sin_restriccion = usuario_db.get("sin_restriccion", False) if usuario_db else False

            if not sin_restriccion:
                ultimo_registro = db.produccion.find_one({"user_id": user_id}, sort=[("fecha", -1)])
                if ultimo_registro:
                    ultima_fecha = ultimo_registro.get("fecha")
                    if ultima_fecha:
                        if ultima_fecha.tzinfo is None:
                            ultima_fecha = ultima_fecha.replace(tzinfo=timezone.utc)

                        ahora_utc = datetime.now(timezone.utc)
                        diferencia = ahora_utc - ultima_fecha
                        if diferencia.total_seconds() < 120:
                            tiempo_restante = int(120 - diferencia.total_seconds())
                            min_rest = tiempo_restante // 60
                            seg_rest = tiempo_restante % 60
                            flash(f"⏳ Debes esperar {min_rest}m {seg_rest}s para registrar otra pieza.", "warning")
                            return redirect(url_for("operador_home"))

        modo = request.form["modo"]
        box = request.form["box"]
        codigo_pieza = request.form["codigo_pieza"].strip().lower()
        cuerda_interna_raw = request.form.get("cuerda_interna")
        cuerda_externa_raw = request.form.get("cuerda_externa")
        flecha_raw = request.form.get("flecha")
        # #region debug-point A:request-entry
        _debug_report_operator_armado(
            "A",
            "core/routes/operator_routes.py:operador_registrar",
            "Entrada a operador_registrar",
            {
                "user_id": user_id,
                "usuario": usuario,
                "modo": modo,
                "box": box,
                "codigo_pieza": codigo_pieza,
                "cuerda_interna_raw": cuerda_interna_raw,
                "cuerda_externa_raw": cuerda_externa_raw,
                "flecha_raw": flecha_raw,
            },
        )
        # #endregion
        submission_guard_id = _build_submission_guard_id(
            user_id,
            modo,
            box,
            codigo_pieza,
            cuerda_interna_raw,
            cuerda_externa_raw,
            flecha_raw,
        )
        guard_acquired = True

        def release_submission_guard():
            pass

        if not codigo_pieza:
            flash("Debes ingresar un código de pieza", "warning")
            return redirect(url_for("operador_home"))

        pieza_data = db.piezas.find_one({"codigo": codigo_pieza})
        if not pieza_data and codigo_pieza.isdigit():
            try:
                pieza_data = db.piezas.find_one({"codigo": int(codigo_pieza)})
            except Exception:
                pass

        es_historico = False
        corte_id_historico = None

        if not pieza_data:
            pieza_historica = db.piezas_historicas.find_one({"codigo": codigo_pieza}, sort=[("_id", -1)])
            if not pieza_historica and codigo_pieza.isdigit():
                try:
                    pieza_historica = db.piezas_historicas.find_one({"codigo": int(codigo_pieza)}, sort=[("_id", -1)])
                except Exception:
                    pass

            if pieza_historica:
                pieza_data = pieza_historica
                es_historico = True
                corte_id_historico = pieza_historica.get("corte_id")

        if not pieza_data:
            release_submission_guard()
            flash(f"❌ No existe una pieza con código {codigo_pieza}", "danger")
            return redirect(url_for("operador_home"))

        if es_historico:
            collection_prod = db.produccion_historica
            filtro_base = {"codigo_pieza": codigo_pieza, "corte_id": corte_id_historico}
        else:
            collection_prod = db.produccion
            filtro_base = {"codigo_pieza": codigo_pieza}

        armado_count = collection_prod.count_documents({**filtro_base, "modo": "armador"})
        remate_count = collection_prod.count_documents({**filtro_base, "modo": "rematador"})
        # #region debug-point B:counts
        _debug_report_operator_armado(
            "B",
            "core/routes/operator_routes.py:count_documents",
            "Conteos previos al registro",
            {
                "codigo_pieza": codigo_pieza,
                "modo": modo,
                "es_historico": es_historico,
                "corte_id_historico": str(corte_id_historico or ""),
                "collection": "produccion_historica" if es_historico else "produccion",
                "filtro_base": filtro_base,
                "armado_count": armado_count,
                "remate_count": remate_count,
                "pieza_codigo": str(pieza_data.get("codigo")),
            },
        )
        # #endregion

        if modo == "armador":

            def safe_float(value):
                try:
                    return float(value)
                except Exception:
                    return None

            if armado_count >= 2:
                # #region debug-point A:blocked-by-armado-count
                _debug_report_operator_armado(
                    "A",
                    "core/routes/operator_routes.py:armado_limit",
                    "Bloqueo por limite de armados",
                    {"codigo_pieza": codigo_pieza, "armado_count": armado_count, "remate_count": remate_count},
                )
                # #endregion
                release_submission_guard()
                flash(f"❌ La pieza {codigo_pieza} ya fue armada 2 veces", "danger")
                return redirect(url_for("operador_home"))

            cuerda_interna = safe_float(cuerda_interna_raw)
            cuerda_externa = safe_float(cuerda_externa_raw)
            flecha = safe_float(flecha_raw)

            if cuerda_interna is None or cuerda_externa is None or flecha is None:
                release_submission_guard()
                flash("❌ Debes ingresar valores numéricos para cuerdas interna, externa y flecha.", "danger")
                return redirect(url_for("operador_home"))

            base_interna = safe_float(pieza_data.get("cuerda_interna"))
            base_externa = safe_float(pieza_data.get("cuerda_externa"))
            base_flecha = safe_float(pieza_data.get("flecha"))

            if base_interna is not None:
                margen_interna_min = base_interna * 0.90
                margen_interna_max = base_interna * 1.10
                if not (margen_interna_min <= cuerda_interna <= margen_interna_max):
                    release_submission_guard()
                    flash(
                        f"❌ Cuerda interna fuera de rango permitido: {margen_interna_min:.2f} - {margen_interna_max:.2f}",
                        "danger",
                    )
                    return redirect(url_for("operador_home"))

            if base_externa is not None:
                margen_externa_min = base_externa * 0.90
                margen_externa_max = base_externa * 1.10
                if not (margen_externa_min <= cuerda_externa <= margen_externa_max):
                    release_submission_guard()
                    flash(
                        f"❌ Cuerda externa fuera de rango permitido: {margen_externa_min:.2f} - {margen_externa_max:.2f}",
                        "danger",
                    )
                    return redirect(url_for("operador_home"))

            if base_flecha is not None:
                margen_flecha_min = base_flecha * 0.90
                margen_flecha_max = base_flecha * 1.10
                if not (margen_flecha_min <= flecha <= margen_flecha_max):
                    release_submission_guard()
                    flash(
                        f"❌ Flecha fuera de rango permitido: {margen_flecha_min:.2f} - {margen_flecha_max:.2f}",
                        "danger",
                    )
                    return redirect(url_for("operador_home"))

        if modo == "rematador":
            if remate_count >= 1:
                # #region debug-point E:blocked-by-remate-count
                _debug_report_operator_armado(
                    "E",
                    "core/routes/operator_routes.py:remate_limit",
                    "Bloqueo por pieza ya rematada",
                    {"codigo_pieza": codigo_pieza, "armado_count": armado_count, "remate_count": remate_count},
                )
                # #endregion
                release_submission_guard()
                flash(f"❌ La pieza {codigo_pieza} ya fue rematada", "danger")
                return redirect(url_for("operador_home"))

            if armado_count < 1:
                release_submission_guard()
                flash(f"⚠ La pieza {codigo_pieza} aún no tiene armado registrado.", "warning")
                return redirect(url_for("operador_home"))

            cuerda_interna = None
            cuerda_externa = None
            flecha = None

        registro = {
            "user_id": user_id,
            "usuario": usuario,
            "modo": modo,
            "box": box,
            "codigo_pieza": codigo_pieza,
            "empresa": pieza_data.get("empresa", ""),
            "marco": pieza_data.get("marco", ""),
            "tramo": pieza_data.get("tramo", ""),
            "kilo_pieza": pieza_data.get("kilo_pieza", 0),
            "tipo_precio": pieza_data.get("tipo_precio", "metro"),
            "cuerda_interna": cuerda_interna,
            "cuerda_externa": cuerda_externa,
            "flecha": flecha,
            "fecha": datetime.utcnow(),
            "calidad_status": "pendiente",
        }

        usuario_valores = db.usuarios.find_one({"_id": ObjectId(user_id)}) or {}
        tipo_precio_registro = registro.get("tipo_precio", "metro")
        if modo == "armador":
            registro["precio_unitario"] = (
                float(usuario_valores.get("precio_metro_armado", 0) or 0)
                if tipo_precio_registro == "metro"
                else float(usuario_valores.get("precio_avo_armado", 0) or 0)
            )
        else:
            registro["precio_unitario"] = (
                float(usuario_valores.get("precio_metro_remate", 0) or 0)
                if tipo_precio_registro == "metro"
                else float(usuario_valores.get("precio_avo_remate", 0) or 0)
            )

        if es_historico:
            registro["corte_id"] = corte_id_historico
            try:
                db.produccion_historica.insert_one(registro)
            except Exception:
                release_submission_guard()
                flash("❌ No se pudo registrar la pieza. Intenta nuevamente.", "danger")
                return redirect(url_for("operador_home"))
            flash(f"✔ Pieza {codigo_pieza} registrada en ARCHIVO HISTÓRICO como {modo} (Corte cerrado)", "warning")
        else:
            try:
                db.produccion.insert_one(registro)
            except Exception:
                release_submission_guard()
                flash("❌ No se pudo registrar la pieza. Intenta nuevamente.", "danger")
                return redirect(url_for("operador_home"))
            flash(f"✔ Pieza {codigo_pieza} registrada correctamente como {modo}", "success")

        # #region debug-point D:insert-success
        _debug_report_operator_armado(
            "D",
            "core/routes/operator_routes.py:insert",
            "Registro insertado correctamente",
            {
                "codigo_pieza": codigo_pieza,
                "modo": modo,
                "es_historico": es_historico,
                "registro_fecha": registro.get("fecha"),
            },
        )
        # #endregion

        return redirect(url_for("operador_home"))
