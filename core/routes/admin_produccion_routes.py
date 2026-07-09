from datetime import datetime, timezone

from flask import flash, redirect, render_template, request, url_for

from core.helpers.date_utils import CL, apply_date_range_filter, to_cl


def register_admin_produccion_routes(
    app,
    db,
    login_required,
    normalize_page,
    build_pagination,
    paginate_list,
    default_per_page,
    send_excel_file,
):
    """Registra rutas administrativas relacionadas a producción activa e histórica."""

    @app.route("/admin/produccion", methods=["GET", "POST"])
    @login_required(["administrador", "cliente", "soporte", "supervisor"])
    def admin_produccion_list():
        page = normalize_page(request.args.get("page", 1))
        filtro = {}
        fecha_inicio = request.args.get("fecha_inicio") or None
        fecha_fin = request.args.get("fecha_fin") or None
        operador_sel = request.args.get("operador") or None
        codigo_sel = request.args.get("codigo") or None

        if request.method == "POST":
            return redirect(
                url_for(
                    "admin_produccion_list",
                    operador=request.form.get("operador") or "",
                    codigo=(request.form.get("codigo") or "").strip(),
                    fecha_inicio=request.form.get("fecha_inicio") or "",
                    fecha_fin=request.form.get("fecha_fin") or "",
                    page=1,
                )
            )

        if operador_sel and operador_sel != "todos":
            filtro["usuario"] = operador_sel
        if codigo_sel:
            filtro["codigo_pieza"] = codigo_sel.strip()
        if fecha_inicio or fecha_fin:
            apply_date_range_filter(filtro, fecha_inicio, fecha_fin)

        total_registros = db.produccion.count_documents(filtro)
        total_pages = max((total_registros + default_per_page - 1) // default_per_page, 1)
        page = min(page, total_pages)
        skip = (page - 1) * default_per_page

        registros = list(
            db.produccion.find(filtro).sort("fecha", -1).skip(skip).limit(default_per_page)
        )
        operadores = db.produccion.distinct("usuario")

        for registro in registros:
            if registro.get("fecha"):
                registro["fecha"] = to_cl(registro.get("fecha"))

        return render_template(
            "crud_produccion_admin.html",
            registros=registros,
            operadores=sorted(operadores),
            operador_sel=operador_sel,
            codigo_sel=codigo_sel,
            fecha_inicio=fecha_inicio,
            fecha_fin=fecha_fin,
            pagination=build_pagination(
                "admin_produccion_list",
                page,
                total_registros,
                operador=operador_sel,
                codigo=codigo_sel,
                fecha_inicio=fecha_inicio,
                fecha_fin=fecha_fin,
            ),
        )

    @app.route("/admin/produccion/export", methods=["POST"])
    @login_required(["administrador", "soporte", "supervisor"])
    def exportar_produccion_excel():
        filtro = {}
        operador_sel = request.form.get("operador")
        codigo_sel = request.form.get("codigo")
        fecha_inicio = request.form.get("fecha_inicio")
        fecha_fin = request.form.get("fecha_fin")

        if operador_sel and operador_sel != "todos":
            filtro["usuario"] = operador_sel
        if codigo_sel:
            filtro["codigo_pieza"] = codigo_sel.strip()
        if fecha_inicio or fecha_fin:
            apply_date_range_filter(filtro, fecha_inicio, fecha_fin)

        registros = list(db.produccion.find(filtro).sort("fecha", -1))
        data = []
        for registro in registros:
            fecha = to_cl(registro.get("fecha")).strftime("%d-%m-%Y %H:%M") if registro.get("fecha") else ""
            data.append(
                {
                    "Fecha": fecha,
                    "Modo": registro.get("modo", ""),
                    "Operador": registro.get("usuario", ""),
                    "Box": registro.get("box", ""),
                    "Código": registro.get("codigo_pieza", ""),
                    "Cliente": registro.get("empresa", ""),
                    "Marco": registro.get("marco", ""),
                    "Tramo": registro.get("tramo", ""),
                    "Cuerda Int.": registro.get("cuerda_interna", ""),
                    "Cuerda Ext.": registro.get("cuerda_externa", ""),
                    "Flecha": registro.get("flecha", ""),
                    "Estado": registro.get("calidad_status", ""),
                }
            )

        return send_excel_file(data, "Produccion", "registro_produccion.xlsx")

    @app.route("/admin/archivados/menu")
    @login_required(["administrador", "soporte", "supervisor"])
    def admin_archivados_menu():
        cortes = list(db.cortes.find().sort("creado_en", -1))
        for corte in cortes:
            if corte.get("creado_en"):
                corte["creado_en"] = to_cl(corte["creado_en"])
        return render_template("admin_archivados.html", cortes=cortes)

    @app.route("/admin/produccion/archivada", methods=["GET", "POST"])
    @login_required(["administrador", "soporte", "supervisor"])
    def admin_produccion_archivada():
        page = normalize_page(request.args.get("page", 1))
        filtro = {}
        fecha_inicio = request.args.get("fecha_inicio") or None
        fecha_fin = request.args.get("fecha_fin") or None
        operador_sel = request.args.get("operador") or None
        codigo_sel = request.args.get("codigo") or None
        mes_sel = request.args.get("mes") or None
        corte_nombre = request.args.get("corte_nombre") or None

        if request.method == "POST":
            return redirect(
                url_for(
                    "admin_produccion_archivada",
                    operador=request.form.get("operador") or "",
                    codigo=(request.form.get("codigo") or "").strip(),
                    fecha_inicio=request.form.get("fecha_inicio") or "",
                    fecha_fin=request.form.get("fecha_fin") or "",
                    mes=request.form.get("mes") or "",
                    corte_nombre=request.form.get("corte_nombre") or "",
                    page=1,
                )
            )

        if operador_sel and operador_sel != "todos":
            filtro["usuario"] = operador_sel
        if codigo_sel:
            filtro["codigo_pieza"] = codigo_sel.strip()

        if not corte_nombre:
            if mes_sel:
                try:
                    y, m = map(int, mes_sel.split("-"))
                    start_date = datetime(y, m, 1)
                    end_date = datetime(y + 1, 1, 1) if m == 12 else datetime(y, m + 1, 1)
                    start_utc = start_date.replace(tzinfo=CL).astimezone(timezone.utc)
                    end_utc = end_date.replace(tzinfo=CL).astimezone(timezone.utc)
                    filtro["fecha"] = {"$gte": start_utc, "$lt": end_utc}
                except Exception:
                    pass
            elif fecha_inicio or fecha_fin:
                apply_date_range_filter(filtro, fecha_inicio, fecha_fin)
        else:
            corte = db.cortes.find_one({"nombre": corte_nombre})
            if corte:
                filtro["corte_id"] = corte.get("_id")

        total_registros = db.produccion_historica.count_documents(filtro)
        total_pages = max((total_registros + default_per_page - 1) // default_per_page, 1)
        page = min(page, total_pages)
        skip = (page - 1) * default_per_page

        registros = list(
            db.produccion_historica.find(filtro).sort("fecha", -1).skip(skip).limit(default_per_page)
        )
        operadores = db.produccion_historica.distinct("usuario")

        for registro in registros:
            if registro.get("fecha"):
                registro["fecha"] = to_cl(registro.get("fecha"))

        return render_template(
            "crud_produccion_admin.html",
            registros=registros,
            operadores=sorted(operadores),
            operador_sel=operador_sel,
            codigo_sel=codigo_sel,
            fecha_inicio=fecha_inicio,
            fecha_fin=fecha_fin,
            mes_sel=mes_sel,
            archived_view=True,
            corte_nombre=corte_nombre,
            pagination=build_pagination(
                "admin_produccion_archivada",
                page,
                total_registros,
                operador=operador_sel,
                codigo=codigo_sel,
                fecha_inicio=fecha_inicio,
                fecha_fin=fecha_fin,
                mes=mes_sel,
                corte_nombre=corte_nombre,
            ),
        )

    @app.route("/admin/piezas/archivadas", methods=["GET", "POST"])
    @login_required(["administrador", "soporte", "supervisor"])
    def admin_piezas_archivadas():
        page = normalize_page(request.args.get("page", 1))
        corte_nombre = request.args.get("corte_nombre")
        if not corte_nombre:
            flash("Debes seleccionar un corte para ver sus piezas.", "warning")
            return redirect(url_for("admin_produccion_archivada"))

        corte = db.cortes.find_one({"nombre": corte_nombre})
        if not corte:
            flash("Corte no encontrado.", "danger")
            return redirect(url_for("admin_produccion_archivada"))

        corte_id = corte.get("_id")
        filtro = {"corte_id": corte_id}
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
                    "admin_piezas_archivadas",
                    corte_nombre=corte_nombre,
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
                codigos_con_estado = db.produccion_historica.distinct(
                    "codigo_pieza", {"modo": modo_buscado, "corte_id": corte_id}
                )
                filtro["codigo"] = {"$in": codigos_con_estado}

        piezas = list(db.piezas_historicas.find(filtro).sort("_id", -1))

        try:
            all_piezas_corte = list(
                db.piezas_historicas.find({"corte_id": corte_id}, {"empresa": 1, "marco": 1, "tramo": 1})
            )
            clientes = sorted(list(set(p.get("empresa", "") for p in all_piezas_corte if p.get("empresa"))))
            marcos = sorted(list(set(p.get("marco", "") for p in all_piezas_corte if p.get("marco"))))
            tramos = sorted(list(set(p.get("tramo", "") for p in all_piezas_corte if p.get("tramo"))))
        except Exception:
            clientes, marcos, tramos = [], [], []

        piezas_finales = []
        if piezas:
            codigos_en_pantalla = [p.get("codigo") for p in piezas if p.get("codigo")]
            set_armado = set(
                db.produccion_historica.distinct(
                    "codigo_pieza",
                    {"codigo_pieza": {"$in": codigos_en_pantalla}, "modo": "armador", "corte_id": corte_id},
                )
            )
            set_remate = set(
                db.produccion_historica.distinct(
                    "codigo_pieza",
                    {"codigo_pieza": {"$in": codigos_en_pantalla}, "modo": "rematador", "corte_id": corte_id},
                )
            )

            for pieza in piezas:
                codigo = pieza.get("codigo")
                estado = "Sin producción"
                if codigo in set_remate:
                    estado = "Rematado"
                elif codigo in set_armado:
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
            "admin_piezas_archivadas",
            page=page,
            corte_nombre=corte_nombre,
            cliente=cliente_sel,
            marco=marco_sel,
            tramo=tramo_sel,
            estado=estado_filter,
        )

        return render_template(
            "admin_piezas_archivadas.html",
            piezas=piezas_pagina,
            corte_nombre=corte_nombre,
            clientes=clientes,
            marcos=marcos,
            tramos=tramos,
            cliente_sel=cliente_sel,
            marco_sel=marco_sel,
            tramo_sel=tramo_sel,
            estado_sel=estado_filter,
            pagination=pagination,
            total_registros=len(piezas_finales),
        )

    @app.route("/admin/produccion/archivada/export", methods=["POST"])
    @login_required(["administrador", "soporte", "supervisor"])
    def exportar_produccion_archivada_excel():
        filtro = {}
        operador_sel = request.form.get("operador")
        codigo_sel = request.form.get("codigo")
        fecha_inicio = request.form.get("fecha_inicio")
        fecha_fin = request.form.get("fecha_fin")
        mes_sel = request.form.get("mes")
        corte_nombre = request.form.get("corte_nombre")

        if operador_sel and operador_sel != "todos":
            filtro["usuario"] = operador_sel
        if codigo_sel:
            filtro["codigo_pieza"] = codigo_sel.strip()

        if corte_nombre:
            corte = db.cortes.find_one({"nombre": corte_nombre})
            if corte:
                corte_id = corte.get("_id")
                corte_inicio = corte.get("inicio")
                corte_fin = corte.get("fin")

                filtro_hibrido = []
                if corte_id:
                    filtro_hibrido.append({"corte_id": corte_id})
                if corte_inicio and corte_fin:
                    filtro_hibrido.append({"fecha": {"$gte": corte_inicio, "$lt": corte_fin}})

                if filtro_hibrido:
                    if len(filtro_hibrido) > 1:
                        filtro["$or"] = filtro_hibrido
                    else:
                        filtro.update(filtro_hibrido[0])
                elif corte_id:
                    filtro["corte_id"] = corte_id
        else:
            if mes_sel:
                try:
                    y, m = map(int, mes_sel.split("-"))
                    start_date = datetime(y, m, 1)
                    end_date = datetime(y + 1, 1, 1) if m == 12 else datetime(y, m + 1, 1)
                    start_utc = start_date.replace(tzinfo=CL).astimezone(timezone.utc)
                    end_utc = end_date.replace(tzinfo=CL).astimezone(timezone.utc)
                    filtro["fecha"] = {"$gte": start_utc, "$lt": end_utc}
                except Exception:
                    pass
            elif fecha_inicio or fecha_fin:
                apply_date_range_filter(filtro, fecha_inicio, fecha_fin)

        registros = list(db.produccion_historica.find(filtro).sort("fecha", -1))
        data = []
        for registro in registros:
            fecha = to_cl(registro.get("fecha")).strftime("%d-%m-%Y %H:%M") if registro.get("fecha") else ""
            data.append(
                {
                    "Fecha": fecha,
                    "Modo": registro.get("modo", ""),
                    "Operador": registro.get("usuario", ""),
                    "Box": registro.get("box", ""),
                    "Código": registro.get("codigo_pieza", ""),
                    "Cliente": registro.get("empresa", ""),
                    "Marco": registro.get("marco", ""),
                    "Tramo": registro.get("tramo", ""),
                    "Cuerda Int.": registro.get("cuerda_interna", ""),
                    "Cuerda Ext.": registro.get("cuerda_externa", ""),
                    "Flecha": registro.get("flecha", ""),
                    "Estado": registro.get("calidad_status", ""),
                }
            )

        return send_excel_file(data, "ProduccionArchivada", "registro_produccion_archivada.xlsx")
