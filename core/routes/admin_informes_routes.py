import re
from datetime import datetime, timedelta, timezone

from flask import abort, jsonify, render_template, request, session

from core.helpers.date_utils import CL, build_date_range_utc, now_cl
from core.helpers.reporting import build_marcos_anual, get_marcos_anual_years, merge_status_maps


def _get_ciclo_actual(db):
    conf = db.config.find_one({"key": "ciclo_actual"}) or {"value": "a"}
    return str(conf.get("value") or "a")


def register_admin_informes_routes(app, db, login_required, get_production_status_map, build_tarjetas_grupos, send_excel_file=None):
    """Registra rutas aisladas del menú e informes resumidos."""

    @app.route("/admin/informes")
    @login_required(["administrador", "soporte", "cliente", "supervisor"])
    def admin_informes():
        return render_template("admin_informes.html", is_cliente=(session.get("role") == "cliente"), role=session.get("role"))

    @app.route("/admin/informes/piezas/tarjetas", methods=["GET"])
    @login_required(["administrador", "supervisor", "soporte", "cliente"])
    def informe_piezas_tarjetas():
        ciclo = _get_ciclo_actual(db)
        filtro_ciclo_piezas = {"codigo": {"$regex": f"^{re.escape(ciclo)}"}}
        filtro_ciclo_produccion = {"codigo_pieza": {"$regex": f"^{re.escape(ciclo)}"}}

        production_status_map = merge_status_maps(
            get_production_status_map(db, db.produccion_historica, filtro_ciclo_produccion),
            get_production_status_map(db, db.produccion, filtro_ciclo_produccion),
        )
        piezas = list(db.piezas.find(filtro_ciclo_piezas, {"codigo": 1, "empresa": 1, "marco": 1, "tramo": 1, "_id": 0}))
        grupos = build_tarjetas_grupos(piezas, production_status_map, include_orphans=True)
        return render_template("informe_piezas_tarjetas.html", grupos=grupos)

    def _resolve_anio_marcos():
        raw = (request.values.get("anio") or "").strip()
        anio_actual = now_cl().year
        if not raw:
            return anio_actual
        try:
            anio = int(raw)
        except ValueError:
            abort(400)
        if anio < 2000 or anio > anio_actual + 1:
            abort(400)
        return anio

    def _datos_marcos_anual(anio):
        start_utc, end_utc = build_date_range_utc(f"{anio}-01-01", f"{anio}-12-31")
        return build_marcos_anual(db, anio, start_utc, end_utc)

    def _payload_marcos_anual(anio):
        filas, totales, sin_fecha = _datos_marcos_anual(anio)
        return {"anio": anio, "filas": filas, "totales": totales, "sin_fecha": sin_fecha}

    @app.route("/admin/informes/marcos/anual", methods=["GET"])
    @login_required(["administrador", "supervisor", "soporte", "cliente"])
    def informe_marcos_anual():
        anio = _resolve_anio_marcos()
        anios = sorted(set(get_marcos_anual_years(db)) | {anio}, reverse=True)
        return render_template(
            "informe_marcos_anual.html",
            anio=anio,
            anios=anios,
            payload=_payload_marcos_anual(anio),
            puede_exportar=send_excel_file is not None,
        )

    @app.route("/admin/informes/marcos/anual/data", methods=["GET"])
    @login_required(["administrador", "supervisor", "soporte", "cliente"])
    def informe_marcos_anual_data():
        return jsonify(_payload_marcos_anual(_resolve_anio_marcos()))

    @app.route("/admin/informes/marcos/anual/export", methods=["GET"])
    @login_required(["administrador", "supervisor", "soporte", "cliente"])
    def informe_marcos_anual_export():
        if send_excel_file is None:
            abort(404)
        anio = _resolve_anio_marcos()
        filas, totales, _ = _datos_marcos_anual(anio)
        data = []
        for fila in filas:
            for tramo in fila["tramos"]:
                data.append({
                    "Marco": fila["marco"],
                    "Tramo": tramo["tramo"],
                    "Ingresado": tramo["ingresado"],
                    "Producido (rematadas)": tramo["producido"],
                    "Pendiente": tramo["pendiente"],
                    "Estado": "Completo" if tramo["completo"] else "Falta",
                })
        data.append({
            "Marco": "TOTAL",
            "Tramo": "",
            "Ingresado": totales["ingresado"],
            "Producido (rematadas)": totales["producido"],
            "Pendiente": totales["pendiente"],
            "Estado": "",
        })
        return send_excel_file(data, f"Marcos {anio}", f"informe_marcos_{anio}.xlsx")

    @app.route("/admin/informes/resumen-produccion", methods=["GET"])
    @login_required(["administrador", "cliente", "soporte"])
    def informe_resumen_produccion():
        today_real = now_cl().date()
        start_today = datetime.combine(today_real, datetime.min.time()).replace(tzinfo=CL).astimezone(timezone.utc)
        end_today = datetime.combine(today_real, datetime.max.time()).replace(tzinfo=CL).astimezone(timezone.utc)
        start_month = datetime(today_real.year, today_real.month, 1).replace(tzinfo=CL).astimezone(timezone.utc)
        date_6m = today_real - timedelta(days=180)
        start_6m = datetime.combine(date_6m, datetime.min.time()).replace(tzinfo=CL).astimezone(timezone.utc)

        def calcular_kilos(query):
            query_final = query.copy()
            query_final["modo"] = "rematador"
            pipeline = [
                {"$match": query_final},
                {"$group": {"_id": "$tipo_precio", "total_kilos": {"$sum": "$kilo_pieza"}}},
            ]
            res = list(db.produccion.aggregate(pipeline))
            datos = {"metro": 0.0, "avo": 0.0}
            for row in res:
                raw_tipo = row["_id"]
                tipo = "metro" if not raw_tipo else str(raw_tipo).lower().strip()
                if tipo not in ["metro", "avo"]:
                    tipo = "metro"
                datos[tipo] = datos.get(tipo, 0.0) + (row.get("total_kilos") or 0.0)
            return datos

        kilos_hoy = calcular_kilos({"fecha": {"$gte": start_today, "$lte": end_today}})
        kilos_mes = calcular_kilos({"fecha": {"$gte": start_month}})

        res_total = list(db.piezas.aggregate([{"$group": {"_id": None, "total": {"$sum": "$kilo_pieza"}}}]))
        total_programado = res_total[0]["total"] if res_total else 0.0

        res_armados = list(db.produccion.aggregate([
            {"$match": {"modo": "armador"}},
            {"$group": {"_id": None, "total": {"$sum": "$kilo_pieza"}}},
        ]))
        raw_armados = res_armados[0]["total"] if res_armados else 0.0
        kilos_armados = raw_armados / 2.0

        res_rematados = list(db.produccion.aggregate([
            {"$match": {"modo": "rematador"}},
            {"$group": {"_id": None, "total": {"$sum": "$kilo_pieza"}}},
        ]))
        kilos_rematados = res_rematados[0]["total"] if res_rematados else 0.0

        pipeline_hist = [
            {"$match": {"fecha": {"$gte": start_6m}}},
            {"$project": {
                "year": {"$year": {"date": "$fecha", "timezone": "America/Santiago"}},
                "month": {"$month": {"date": "$fecha", "timezone": "America/Santiago"}},
                "tipo_precio": 1,
                "kilo_pieza": 1,
            }},
            {"$group": {
                "_id": {"year": "$year", "month": "$month", "tipo": "$tipo_precio"},
                "total": {"$sum": "$kilo_pieza"},
            }},
            {"$sort": {"_id.year": 1, "_id.month": 1}},
        ]

        raw_active = list(db.produccion.aggregate(pipeline_hist))
        raw_archived = list(db.produccion_historica.aggregate(pipeline_hist))
        data_map = {}

        def process_agg(rows):
            for row in rows:
                y = row["_id"]["year"]
                m = row["_id"]["month"]
                raw_t = row["_id"].get("tipo")
                t = "metro" if not raw_t else str(raw_t).lower().strip()
                if t not in ["avo", "metro"]:
                    t = "metro"
                key = f"{y}-{m:02d}"
                if key not in data_map:
                    data_map[key] = {"avo": 0.0, "metro": 0.0}
                data_map[key][t] += row.get("total") or 0.0

        process_agg(raw_active)
        process_agg(raw_archived)

        sorted_keys = sorted(data_map.keys())
        meses_es = ["", "Ene", "Feb", "Mar", "Abr", "May", "Jun", "Jul", "Ago", "Sep", "Oct", "Nov", "Dic"]
        chart_labels = []
        chart_avo = []
        chart_metro = []

        for key in sorted_keys:
            year, month = map(int, key.split("-"))
            chart_labels.append(f"{meses_es[month]} {year}")
            chart_avo.append(round(data_map[key]["avo"], 2))
            chart_metro.append(round(data_map[key]["metro"], 2))

        return render_template(
            "informe_resumen_produccion.html",
            kilos_hoy=kilos_hoy,
            kilos_mes=kilos_mes,
            chart_labels=chart_labels,
            chart_avo=chart_avo,
            chart_metro=chart_metro,
            total_programado=total_programado,
            kilos_armados=kilos_armados,
            kilos_rematados=kilos_rematados,
        )
