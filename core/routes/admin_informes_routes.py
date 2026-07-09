from datetime import datetime, timedelta, timezone

from flask import render_template, session

from core.helpers.date_utils import CL, now_cl


def register_admin_informes_routes(app, db, login_required, get_production_status_map, build_tarjetas_grupos):
    """Registra rutas aisladas del menú e informes resumidos."""

    @app.route("/admin/informes")
    @login_required(["administrador", "soporte", "cliente", "supervisor"])
    def admin_informes():
        return render_template("admin_informes.html", is_cliente=(session.get("role") == "cliente"), role=session.get("role"))

    @app.route("/admin/informes/piezas/tarjetas", methods=["GET"])
    @login_required(["administrador", "supervisor", "soporte", "cliente"])
    def informe_piezas_tarjetas():
        production_status_map = get_production_status_map(db, db.produccion, {})
        piezas = list(db.piezas.find({}, {"codigo": 1, "empresa": 1, "marco": 1, "tramo": 1, "_id": 0}))
        grupos = build_tarjetas_grupos(piezas, production_status_map, include_orphans=True)
        return render_template("informe_piezas_tarjetas.html", grupos=grupos)

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
