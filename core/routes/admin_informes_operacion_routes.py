from flask import flash, redirect, render_template, request, url_for

from core.helpers.date_utils import apply_date_range_filter, to_cl


def register_admin_informes_operacion_routes(
    app,
    db,
    login_required,
    normalize_page,
    build_pagination,
    paginate_list,
    default_per_page,
    send_excel_file,
    get_operator_report_rows,
):
    """Registra informes de horarios y producción por operador."""

    @app.route("/admin/informes/horarios", methods=["GET", "POST"])
    @login_required(["administrador", "soporte"])
    def informe_horarios():
        operadores = list(db.usuarios.find({"tipo": "operador"}))
        operador_sel = request.args.get("operador") or None
        page = normalize_page(request.args.get("page", 1))
        filtro = {}

        if request.method == "POST":
            return redirect(url_for("informe_horarios", operador=request.form.get("operador") or "", page=1))

        if operador_sel and operador_sel != "todos":
            filtro["user_id"] = operador_sel

        total_registros = db.jornadas.count_documents(filtro)
        total_pages = max((total_registros + default_per_page - 1) // default_per_page, 1)
        page = min(page, total_pages)
        skip = (page - 1) * default_per_page

        jornadas = list(
            db.jornadas.find(filtro).sort("fecha", -1).skip(skip).limit(default_per_page)
        )
        usuarios_map = {str(usuario["_id"]): usuario["nombre"] for usuario in operadores}

        for jornada in jornadas:
            jornada["nombre"] = usuarios_map.get(jornada["user_id"], "Desconocido")
            if jornada.get("fecha"):
                jornada["fecha"] = to_cl(jornada.get("fecha"))
            if jornada.get("ingreso"):
                jornada["ingreso"] = to_cl(jornada.get("ingreso"))
            if jornada.get("salida"):
                jornada["salida"] = to_cl(jornada.get("salida"))

        return render_template(
            "informe_horarios.html",
            jornadas=jornadas,
            operadores=operadores,
            operador_sel=operador_sel,
            pagination=build_pagination("informe_horarios", page, total_registros, operador=operador_sel),
        )

    @app.route("/admin/informes/horarios/export", methods=["POST"])
    @login_required("administrador")
    def exportar_horarios_excel():
        operador_sel = request.form.get("operador")
        filtro = {}
        if operador_sel and operador_sel != "todos":
            filtro["user_id"] = operador_sel

        jornadas = list(db.jornadas.find(filtro).sort("fecha", -1))
        operadores = list(db.usuarios.find({"tipo": "operador"}))
        usuarios_map = {str(usuario["_id"]): usuario["nombre"] for usuario in operadores}

        data = []
        for jornada in jornadas:
            fecha = to_cl(jornada.get("fecha")) if jornada.get("fecha") else None
            ingreso = to_cl(jornada.get("ingreso")) if jornada.get("ingreso") else None
            salida = to_cl(jornada.get("salida")) if jornada.get("salida") else None
            data.append(
                {
                    "Operador": usuarios_map.get(jornada["user_id"], "Desconocido"),
                    "Fecha": fecha.strftime("%d-%m-%Y") if fecha else "",
                    "Ingreso": ingreso.strftime("%H:%M") if ingreso else "",
                    "Salida": salida.strftime("%H:%M") if salida else "",
                }
            )

        if not data:
            flash("No hay datos para exportar", "warning")
            return redirect(url_for("informe_horarios"))

        return send_excel_file(data, "Horarios", "informe_horarios.xlsx")

    @app.route("/admin/informes/operadores", methods=["GET", "POST"])
    @login_required(["administrador", "soporte"])
    def informe_operadores():
        operadores = list(db.usuarios.find({"tipo": "operador"}, {"nombre": 1}))
        operador_sel = request.args.get("operador") or None
        fecha_inicio = request.args.get("fecha_inicio") or None
        fecha_fin = request.args.get("fecha_fin") or None
        page = normalize_page(request.args.get("page", 1))
        filtro = {}

        if request.method == "POST":
            return redirect(
                url_for(
                    "informe_operadores",
                    operador=request.form.get("operador") or "",
                    fecha_inicio=request.form.get("fecha_inicio") or "",
                    fecha_fin=request.form.get("fecha_fin") or "",
                    page=1,
                )
            )

        if operador_sel and operador_sel != "todos":
            filtro["user_id"] = operador_sel
        if fecha_inicio or fecha_fin:
            apply_date_range_filter(filtro, fecha_inicio, fecha_fin)

        produccion = list(
            db.produccion.find(
                filtro,
                {
                    "fecha": 1,
                    "codigo_pieza": 1,
                    "user_id": 1,
                    "modo": 1,
                    "marco": 1,
                    "tramo": 1,
                    "_id": 0,
                },
            ).sort("fecha", -1)
        )

        datos_tabla, total_general = get_operator_report_rows(db, produccion)
        datos_pagina, pagination = paginate_list(
            datos_tabla,
            "informe_operadores",
            page=page,
            operador=operador_sel,
            fecha_inicio=fecha_inicio,
            fecha_fin=fecha_fin,
        )

        return render_template(
            "informe_operadores.html",
            operadores=operadores,
            operador_sel=operador_sel,
            fecha_inicio=fecha_inicio,
            fecha_fin=fecha_fin,
            datos_tabla=datos_pagina,
            total_general=total_general,
            pagination=pagination,
        )

    @app.route("/admin/informes/operadores/export", methods=["POST"])
    @login_required(["administrador", "soporte"])
    def exportar_operadores_excel():
        operador_sel = request.form.get("operador")
        fecha_inicio = request.form.get("fecha_inicio")
        fecha_fin = request.form.get("fecha_fin")
        filtro = {}

        if operador_sel and operador_sel != "todos":
            filtro["user_id"] = operador_sel
        if fecha_inicio or fecha_fin:
            apply_date_range_filter(filtro, fecha_inicio, fecha_fin)

        produccion = list(
            db.produccion.find(
                filtro,
                {
                    "fecha": 1,
                    "codigo_pieza": 1,
                    "user_id": 1,
                    "modo": 1,
                    "marco": 1,
                    "tramo": 1,
                    "_id": 0,
                },
            ).sort("fecha", -1)
        )

        rows, total_general = get_operator_report_rows(db, produccion)
        data = []
        for row in rows:
            data.append(
                {
                    "Fecha": row["fecha"].strftime("%d-%m-%Y") if row.get("fecha") else "",
                    "Código": row.get("codigo", ""),
                    "Operador": row.get("operador", ""),
                    "Modo": row.get("modo"),
                    "Marco": row.get("marco", ""),
                    "Tramo": row.get("tramo", ""),
                    "Cantidad": row.get("cantidad", 1),
                    "Peso": row.get("peso", 0),
                    "Precio Unit.": row.get("valor_unitario", 0),
                    "Tipo": row.get("tipo_precio", ""),
                    "Total": row.get("total", 0),
                }
            )

        if not data:
            flash("No hay datos", "warning")
            return redirect(url_for("informe_operadores"))

        data.append(
            {
                "Fecha": "TOTAL",
                "Código": "",
                "Operador": "",
                "Modo": "",
                "Marco": "",
                "Tramo": "",
                "Cantidad": "",
                "Peso": "",
                "Precio Unit.": "",
                "Tipo": "",
                "Total": total_general,
            }
        )

        return send_excel_file(data, "Operadores", "informe_valor_operador.xlsx")
