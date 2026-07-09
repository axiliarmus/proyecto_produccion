import string
from datetime import datetime, timedelta, timezone

from flask import flash, redirect, render_template, request, url_for

from core.helpers.date_utils import CL, now_cl


def register_admin_dashboard_routes(app, db, login_required):
    """Registra dashboard principal y corte mensual administrativo."""

    @app.route("/admin")
    @login_required(["administrador", "soporte"])
    def admin_dashboard():
        total_usuarios = db.usuarios.count_documents({})
        total_boxes = db.boxes.count_documents({})
        total_piezas = db.piezas.count_documents({})
        total_produccion = db.produccion.count_documents({})

        today = now_cl().date()
        start_today = datetime.combine(today, datetime.min.time()).replace(tzinfo=CL)
        end_today = datetime.combine(today, datetime.max.time()).replace(tzinfo=CL)

        start_month = today.replace(day=1)
        next_month = (start_month + timedelta(days=32)).replace(day=1)
        end_month = datetime.combine(next_month, datetime.min.time()).replace(tzinfo=CL)
        start_month_dt = datetime.combine(start_month, datetime.min.time()).replace(tzinfo=CL)

        prod_hoy = list(
            db.produccion.find(
                {"fecha": {"$gte": start_today.astimezone(timezone.utc), "$lte": end_today.astimezone(timezone.utc)}},
                {"codigo_pieza": 1, "kilo_pieza": 1, "tipo_precio": 1, "_id": 0},
            )
        )
        prod_mes = list(
            db.produccion.find(
                {"fecha": {"$gte": start_month_dt.astimezone(timezone.utc), "$lt": end_month.astimezone(timezone.utc)}},
                {"codigo_pieza": 1, "kilo_pieza": 1, "tipo_precio": 1, "_id": 0},
            )
        )

        all_piezas = list(db.piezas.find({}, {"codigo": 1, "kilo_pieza": 1, "tipo_precio": 1, "_id": 0}))
        mapa_piezas = {str(pieza["codigo"]): pieza for pieza in all_piezas}

        def calcular_kilos(registros):
            resultado = {"avo": 0.0, "metro": 0.0}
            for registro in registros:
                codigo = str(registro.get("codigo_pieza"))
                pieza = mapa_piezas.get(codigo)
                if pieza:
                    peso = float(pieza.get("kilo_pieza", 0) or 0)
                    tipo = pieza.get("tipo_precio", "metro")
                else:
                    peso = float(registro.get("kilo_pieza", 0) or 0)
                    tipo = registro.get("tipo_precio", "metro")

                if tipo == "avo":
                    resultado["avo"] += peso
                else:
                    resultado["metro"] += peso
            return resultado

        kilos_hoy = calcular_kilos(prod_hoy)
        kilos_mes = calcular_kilos(prod_mes)

        total_p = len(all_piezas)
        pipeline_estado = [{"$sort": {"fecha": 1}}, {"$group": {"_id": "$codigo_pieza", "ultimo_modo": {"$last": "$modo"}}}]
        estados_prod = list(db.produccion.aggregate(pipeline_estado))

        codigos_totales = set(mapa_piezas.keys())
        real_rematado = 0
        real_armado = 0

        for estado in estados_prod:
            if estado["_id"] in codigos_totales:
                if estado["ultimo_modo"] == "rematador":
                    real_rematado += 1
                else:
                    real_armado += 1

        real_sin_prod = total_p - (real_rematado + real_armado)
        stats_piezas = {
            "sin_produccion": max(0, real_sin_prod),
            "armado": real_armado,
            "rematado": real_rematado,
            "total": total_p,
        }

        return render_template(
            "admin_dashboard.html",
            total_usuarios=total_usuarios,
            total_boxes=total_boxes,
            total_piezas=total_piezas,
            total_produccion=total_produccion,
            kilos_hoy=kilos_hoy,
            kilos_mes=kilos_mes,
            stats_piezas=stats_piezas,
        )

    @app.route("/admin/corte_mensual", methods=["POST"])
    @login_required(["administrador", "soporte"])
    def admin_corte_mensual():
        nombre_custom = request.form.get("nombre")
        mes = request.form.get("mes")
        fecha_inicio = request.form.get("fecha_inicio")
        fecha_fin = request.form.get("fecha_fin")

        try:
            if mes:
                y, m = map(int, mes.split("-"))
                start_date = datetime(y, m, 1)
                end_date = datetime(y + (1 if m == 12 else 0), 1 if m == 12 else m + 1, 1)
                start_utc = start_date.replace(tzinfo=CL).astimezone(timezone.utc)
                end_utc = end_date.replace(tzinfo=CL).astimezone(timezone.utc)
                nombre = start_date.strftime("%B %Y")
            elif fecha_inicio and fecha_fin:
                d1 = datetime.strptime(fecha_inicio, "%Y-%m-%d").date()
                d2 = datetime.strptime(fecha_fin, "%Y-%m-%d").date()
                start_utc = datetime.combine(d1, datetime.min.time()).replace(tzinfo=CL).astimezone(timezone.utc)
                end_utc = datetime.combine(d2, datetime.max.time()).replace(tzinfo=CL).astimezone(timezone.utc)
                nombre = f"{d1.strftime('%d/%m/%Y')} - {d2.strftime('%d/%m/%Y')}"
            else:
                flash("Debes seleccionar un mes o rango de fechas", "warning")
                return redirect(url_for("admin_dashboard"))

            if nombre_custom and nombre_custom.strip():
                nombre = nombre_custom.strip()

            filtro = {"fecha": {"$gte": start_utc, "$lt": end_utc}}
            registros = list(db.produccion.find(filtro))
            count = len(registros)

            if count > 0:
                corte_doc = {"nombre": nombre, "inicio": start_utc, "fin": end_utc, "creado_en": datetime.utcnow()}
                res = db.cortes.insert_one(corte_doc)
                corte_id = res.inserted_id

                piezas_map = {}
                for pieza in db.piezas.find(
                    {},
                    {
                        "codigo": 1,
                        "empresa": 1,
                        "marco": 1,
                        "tramo": 1,
                        "kilo_pieza": 1,
                        "tipo_precio": 1,
                    },
                ):
                    piezas_map[pieza.get("codigo")] = pieza
                    piezas_map[str(pieza.get("codigo"))] = pieza

                usuarios_map = {u.get("usuario"): u for u in db.usuarios.find()}

                for registro in registros:
                    pieza_ref = piezas_map.get(registro.get("codigo_pieza"))
                    usuario_ref = usuarios_map.get(registro.get("usuario"))

                    registro["empresa"] = registro.get("empresa") or (pieza_ref.get("empresa") if pieza_ref else "")
                    registro["marco"] = registro.get("marco") or (pieza_ref.get("marco") if pieza_ref else "")
                    registro["tramo"] = registro.get("tramo") or (pieza_ref.get("tramo") if pieza_ref else "")
                    registro["kilo_pieza"] = registro.get("kilo_pieza")
                    if registro["kilo_pieza"] in (None, "") and pieza_ref:
                        registro["kilo_pieza"] = pieza_ref.get("kilo_pieza", 0)

                    tipo_precio = registro.get("tipo_precio") or (pieza_ref.get("tipo_precio", "metro") if pieza_ref else "metro")
                    registro["tipo_precio"] = tipo_precio

                    if registro.get("precio_unitario") in (None, "") and usuario_ref:
                        if registro.get("modo") == "armador":
                            registro["precio_unitario"] = (
                                float(usuario_ref.get("precio_metro_armado", 0) or 0)
                                if tipo_precio == "metro"
                                else float(usuario_ref.get("precio_avo_armado", 0) or 0)
                            )
                        else:
                            registro["precio_unitario"] = (
                                float(usuario_ref.get("precio_metro_remate", 0) or 0)
                                if tipo_precio == "metro"
                                else float(usuario_ref.get("precio_avo_remate", 0) or 0)
                            )

                    registro["corte_id"] = corte_id
                if registros:
                    db.produccion_historica.insert_many(registros)

                piezas_activas = list(db.piezas.find({}))
                piezas_a_insertar = []
                for pieza in piezas_activas:
                    pieza_copy = pieza.copy()
                    pieza_copy.pop("_id", None)
                    pieza_copy["corte_id"] = corte_id
                    piezas_a_insertar.append(pieza_copy)
                if piezas_a_insertar:
                    db.piezas_historicas.insert_many(piezas_a_insertar)

                usuarios_activos = list(db.usuarios.find())
                usuarios_a_insertar = []
                for usuario in usuarios_activos:
                    usuario_copy = usuario.copy()
                    usuario_copy.pop("_id", None)
                    usuario_copy["corte_id"] = corte_id
                    usuarios_a_insertar.append(usuario_copy)
                if usuarios_a_insertar:
                    db.usuarios_historicos.insert_many(usuarios_a_insertar)

                db.produccion.delete_many(filtro)
                db.piezas.delete_many({})

                conf = db.config.find_one({"key": "ciclo_actual"}) or {"key": "ciclo_actual", "value": "a"}
                letra = conf.get("value", "a")
                abecedario = list(string.ascii_lowercase)
                try:
                    idx = abecedario.index(letra)
                    nueva = abecedario[idx + 1] if idx + 1 < len(abecedario) else "a"
                except Exception:
                    nueva = "a"
                db.config.update_one({"key": "ciclo_actual"}, {"$set": {"value": nueva}}, upsert=True)

                flash(f"✅ Corte realizado. {count} registros archivados.", "success")
            else:
                flash("No se encontraron registros para el mes seleccionado.", "info")
        except Exception as exc:
            flash(f"Error al realizar el corte: {str(exc)}", "danger")

        return redirect(url_for("admin_dashboard"))
