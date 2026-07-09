from bson import ObjectId
from flask import flash, redirect, render_template, request, url_for

from core.helpers.date_utils import apply_date_range_filter, to_cl


def register_admin_informes_avanzados_routes(
    app,
    db,
    login_required,
    normalize_page,
    paginate_list,
    build_piezas_map,
    build_codigo_lookup_keys,
    get_estado_piezas_dataset,
    apply_exact_codigo_filter,
    get_production_status_map,
    build_tarjetas_grupos,
    send_excel_file,
):
    """Registra informes avanzados de valor, estado y tarjetas archivadas."""

    @app.route("/admin/archivados/valor-operador", methods=["GET", "POST"])
    @login_required(["administrador", "soporte"])
    def archivados_valor_operador():
        corte_nombre = request.args.get("corte_nombre")
        operador_sel = request.args.get("operador") or None
        fecha_inicio = request.args.get("fecha_inicio") or None
        fecha_fin = request.args.get("fecha_fin") or None
        page = normalize_page(request.args.get("page", 1))
        filtro = {}

        if request.method == "POST":
            return redirect(
                url_for(
                    "archivados_valor_operador",
                    corte_nombre=request.form.get("corte_nombre") or corte_nombre or "",
                    operador=request.form.get("operador") or "",
                    fecha_inicio=request.form.get("fecha_inicio") or "",
                    fecha_fin=request.form.get("fecha_fin") or "",
                    page=1,
                )
            )

        if operador_sel and operador_sel != "todos":
            filtro["usuario"] = operador_sel
        if fecha_inicio and fecha_fin:
            try:
                apply_date_range_filter(filtro, fecha_inicio, fecha_fin)
            except Exception:
                pass

        piezas = []
        total_general = 0
        operadores = sorted(db.produccion_historica.distinct("usuario"))

        corte_id = None
        if corte_nombre and "corte_id" not in filtro:
            corte = db.cortes.find_one({"nombre": corte_nombre})
            if not corte:
                try:
                    corte = db.cortes.find_one({"_id": ObjectId(corte_nombre)})
                except Exception:
                    pass

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

        if corte_id:
            operadores = sorted(db.produccion_historica.distinct("usuario", {"corte_id": corte_id}))
        if not operadores:
            operadores = sorted(db.produccion_historica.distinct("usuario"))

        produccion = list(db.produccion_historica.find(filtro).sort("fecha", -1))

        users_map = {}
        if corte_id:
            users_hist = list(db.usuarios_historicos.find({"corte_id": corte_id}))
            if users_hist:
                users_map = {u.get("usuario"): u for u in users_hist}
        if not users_map:
            users_db = list(db.usuarios.find())
            users_map = {u.get("usuario"): u for u in users_db}

        codigos_necesarios = set()
        for prod in produccion:
            codigo = prod.get("codigo_pieza")
            if codigo:
                codigos_necesarios.add(codigo)
                if isinstance(codigo, str) and codigo.isdigit():
                    codigos_necesarios.add(int(codigo))
                elif isinstance(codigo, int):
                    codigos_necesarios.add(str(codigo))

        piezas_hist_corte_map = {}
        piezas_hist_gen_map = {}
        piezas_actuales_map = {}

        if codigos_necesarios:
            lista_codigos = list(codigos_necesarios)
            if corte_id:
                h_corte = list(db.piezas_historicas.find({"codigo": {"$in": lista_codigos}, "corte_id": corte_id}))
                for pieza in h_corte:
                    piezas_hist_corte_map[pieza.get("codigo")] = pieza

            h_gen = list(db.piezas_historicas.find({"codigo": {"$in": lista_codigos}}))
            for pieza in h_gen:
                if pieza.get("codigo") not in piezas_hist_gen_map:
                    piezas_hist_gen_map[pieza.get("codigo")] = pieza

            act = list(db.piezas.find({"codigo": {"$in": lista_codigos}}))
            for pieza in act:
                piezas_actuales_map[pieza.get("codigo")] = pieza

        for prod in produccion:
            codigo = prod.get("codigo_pieza")
            modo = prod.get("modo")
            if not codigo:
                continue

            pieza_info = None
            codigos_probar = [codigo]
            if isinstance(codigo, str) and codigo.isdigit():
                codigos_probar.append(int(codigo))
            elif isinstance(codigo, int):
                codigos_probar.append(str(codigo))

            if corte_id:
                for codigo_lookup in codigos_probar:
                    pieza_info = piezas_hist_corte_map.get(codigo_lookup)
                    if pieza_info:
                        break
            if not pieza_info:
                for codigo_lookup in codigos_probar:
                    pieza_info = piezas_hist_gen_map.get(codigo_lookup)
                    if pieza_info:
                        break
            if not pieza_info:
                for codigo_lookup in codigos_probar:
                    pieza_info = piezas_actuales_map.get(codigo_lookup)
                    if pieza_info:
                        break

            empresa_val = (pieza_info.get("empresa") if pieza_info else None) or prod.get("empresa") or "Desconocido"
            marco_val = (pieza_info.get("marco") if pieza_info else None) or prod.get("marco") or "-"
            tramo_val = (pieza_info.get("tramo") if pieza_info else None) or prod.get("tramo") or "-"

            peso_val = prod.get("kilo_pieza")
            if peso_val in (None, ""):
                peso_val = pieza_info.get("kilo_pieza", 0) if pieza_info else 0

            user = users_map.get(prod.get("usuario"))
            tipo_precio = prod.get("tipo_precio") or (pieza_info.get("tipo_precio", "metro") if pieza_info else "metro")
            precio_unitario_snapshot = prod.get("precio_unitario")
            valor_unit = float(precio_unitario_snapshot or 0)
            if precio_unitario_snapshot in (None, "") and user:
                if modo == "armador":
                    valor_unit = (
                        user.get("precio_metro_armado", 0) if tipo_precio == "metro" else user.get("precio_avo_armado", 0)
                    )
                else:
                    valor_unit = (
                        user.get("precio_metro_remate", 0) if tipo_precio == "metro" else user.get("precio_avo_remate", 0)
                    )

            total = (peso_val or 0) * (valor_unit or 0)
            piezas.append(
                {
                    "fecha": to_cl(prod.get("fecha")) if prod.get("fecha") else None,
                    "codigo": codigo,
                    "empresa": empresa_val,
                    "operador": prod.get("usuario"),
                    "marco": marco_val,
                    "tramo": tramo_val,
                    "modo": modo,
                    "peso": peso_val,
                    "precio_kilo": valor_unit,
                    "valor": total,
                }
            )
            total_general += total

        piezas_pagina, pagination = paginate_list(
            piezas,
            "archivados_valor_operador",
            page=page,
            corte_nombre=corte_nombre,
            operador=operador_sel,
            fecha_inicio=fecha_inicio,
            fecha_fin=fecha_fin,
        )

        return render_template(
            "informe_valor_operador_archivado.html",
            piezas=piezas_pagina,
            operadores=operadores,
            operador_sel=operador_sel,
            fecha_inicio=fecha_inicio,
            fecha_fin=fecha_fin,
            total_general=total_general,
            corte_nombre=corte_nombre,
            pagination=pagination,
        )

    @app.route("/admin/archivados/piezas-cliente")
    @login_required(["administrador", "soporte", "supervisor"])
    def archivados_piezas_cliente():
        corte_nombre = request.args.get("corte_nombre")
        filtro_prod = {}
        filtro_piezas = {}
        if corte_nombre:
            corte = db.cortes.find_one({"nombre": corte_nombre})
            if corte:
                corte_id = corte.get("_id")
                corte_inicio = corte.get("inicio")
                corte_fin = corte.get("fin")

                filtro_hibrido_prod = []
                if corte_id:
                    filtro_hibrido_prod.append({"corte_id": corte_id})
                if corte_inicio and corte_fin:
                    filtro_hibrido_prod.append({"fecha": {"$gte": corte_inicio, "$lt": corte_fin}})

                if filtro_hibrido_prod:
                    if len(filtro_hibrido_prod) > 1:
                        filtro_prod["$or"] = filtro_hibrido_prod
                    else:
                        filtro_prod.update(filtro_hibrido_prod[0])
                elif corte_id:
                    filtro_prod["corte_id"] = corte_id

                if corte_id:
                    filtro_piezas = {"corte_id": corte_id}

        production_status_map = get_production_status_map(db, db.produccion_historica, filtro_prod)
        piezas = []
        if filtro_piezas:
            piezas = list(
                db.piezas_historicas.find(
                    filtro_piezas, {"codigo": 1, "empresa": 1, "marco": 1, "tramo": 1, "_id": 0}
                )
            )

        if not piezas:
            piezas = list(db.piezas.find({}, {"codigo": 1, "empresa": 1, "marco": 1, "tramo": 1, "_id": 0}))

        grupos = build_tarjetas_grupos(piezas, production_status_map, include_orphans=False)
        return render_template("informe_piezas_tarjetas_archivado.html", grupos=grupos, corte_nombre=corte_nombre)

    @app.route("/admin/archivados/pendientes")
    @login_required(["administrador", "soporte", "supervisor"])
    def archivados_pendientes_mes():
        return archivados_piezas_cliente()

    @app.route("/admin/informes/valor-operador", methods=["GET", "POST"])
    @login_required(["administrador", "soporte"])
    def informe_piezas_operador():
        operadores = sorted([u for u in db.produccion.distinct("usuario") if u], key=str)
        operador_sel = request.args.get("operador") or None
        fecha_inicio = request.args.get("fecha_inicio") or None
        fecha_fin = request.args.get("fecha_fin") or None
        page = normalize_page(request.args.get("page", 1))
        filtro = {}

        if request.method == "POST":
            return redirect(
                url_for(
                    "informe_piezas_operador",
                    operador=request.form.get("operador") or "",
                    fecha_inicio=request.form.get("fecha_inicio") or "",
                    fecha_fin=request.form.get("fecha_fin") or "",
                    page=1,
                )
            )

        if operador_sel and operador_sel != "todos":
            filtro["usuario"] = operador_sel
        if fecha_inicio or fecha_fin:
            try:
                apply_date_range_filter(filtro, fecha_inicio, fecha_fin)
            except Exception:
                flash("Fechas inválidas", "warning")

        produccion = list(db.produccion.find(filtro).sort("fecha", -1))
        users_db = list(db.usuarios.find())
        users_map = {u["usuario"]: u for u in users_db}
        piezas_map = build_piezas_map(db, [p.get("codigo_pieza") for p in produccion])

        resumen = []
        total_general = 0
        for prod in produccion:
            codigo = prod.get("codigo_pieza")
            modo = prod.get("modo")
            usuario_nombre = prod.get("usuario")
            if not codigo:
                continue

            pieza_info = None
            for key in build_codigo_lookup_keys(codigo):
                pieza_info = piezas_map.get(key)
                if pieza_info:
                    break
            if not pieza_info:
                continue

            peso = float(pieza_info.get("kilo_pieza", 0))
            user_info = users_map.get(usuario_nombre, {})
            tipo_precio = pieza_info.get("tipo_precio", "metro")

            rate = 0.0
            if tipo_precio == "metro":
                rate = (
                    float(user_info.get("precio_metro_armado", 0))
                    if modo == "armador"
                    else float(user_info.get("precio_metro_remate", 0))
                )
            else:
                rate = (
                    float(user_info.get("precio_avo_armado", 0))
                    if modo == "armador"
                    else float(user_info.get("precio_avo_remate", 0))
                )

            valor = peso * rate
            total_general += valor
            resumen.append(
                {
                    "fecha": to_cl(prod.get("fecha")),
                    "codigo": codigo,
                    "operador": usuario_nombre,
                    "empresa": pieza_info.get("empresa"),
                    "marco": pieza_info.get("marco"),
                    "tramo": pieza_info.get("tramo"),
                    "modo": modo.capitalize(),
                    "peso": peso,
                    "valor": valor,
                }
            )

        resumen_pagina, pagination = paginate_list(
            resumen,
            "informe_piezas_operador",
            page=page,
            operador=operador_sel,
            fecha_inicio=fecha_inicio,
            fecha_fin=fecha_fin,
        )

        return render_template(
            "informe_valor_operador.html",
            piezas=resumen_pagina,
            total_general=total_general,
            operadores=operadores,
            operador_sel=operador_sel,
            fecha_inicio=fecha_inicio,
            fecha_fin=fecha_fin,
            pagination=pagination,
        )

    @app.route("/admin/informes/valor-operador/export", methods=["POST"])
    @login_required(["administrador", "soporte"])
    def exportar_valor_operador_excel():
        operador_sel = request.form.get("operador")
        fecha_inicio = request.form.get("fecha_inicio")
        fecha_fin = request.form.get("fecha_fin")
        filtro = {}

        if operador_sel and operador_sel != "todos":
            filtro["usuario"] = operador_sel

        users_db = list(db.usuarios.find())
        users_map = {u["usuario"]: u for u in users_db}

        if fecha_inicio or fecha_fin:
            try:
                apply_date_range_filter(filtro, fecha_inicio, fecha_fin)
            except Exception:
                pass

        produccion = list(db.produccion.find(filtro).sort("fecha", -1))
        codigos_raw = set()
        for prod in produccion:
            codigo = prod.get("codigo_pieza")
            if codigo:
                codigos_raw.add(codigo)
                if str(codigo).isdigit():
                    codigos_raw.add(int(codigo))
                codigos_raw.add(str(codigo))

        map_piezas = {}
        if codigos_raw:
            piezas_db = list(db.piezas.find({"codigo": {"$in": list(codigos_raw)}}))
            for pieza in piezas_db:
                map_piezas[pieza.get("codigo")] = pieza
                codigo_val = pieza.get("codigo")
                map_piezas[str(codigo_val)] = pieza
                if isinstance(codigo_val, (int, float)):
                    map_piezas[int(codigo_val)] = pieza

        data = []
        for prod in produccion:
            codigo = prod.get("codigo_pieza")
            modo = prod.get("modo")
            if not codigo:
                continue

            pieza_info = map_piezas.get(codigo)
            if not pieza_info and str(codigo).isdigit():
                pieza_info = map_piezas.get(int(codigo))
            if not pieza_info:
                continue

            peso = float(pieza_info.get("kilo_pieza", 0))
            user_info = users_map.get(prod.get("usuario"), {})
            tipo_precio = pieza_info.get("tipo_precio", "metro")

            rate = 0.0
            if tipo_precio == "metro":
                rate = (
                    float(user_info.get("precio_metro_armado", 0))
                    if modo == "armador"
                    else float(user_info.get("precio_metro_remate", 0))
                )
            else:
                rate = (
                    float(user_info.get("precio_avo_armado", 0))
                    if modo == "armador"
                    else float(user_info.get("precio_avo_remate", 0))
                )

            valor = peso * rate
            fecha = to_cl(prod.get("fecha"))
            fecha_str = fecha.strftime("%d-%m-%Y %H:%M") if fecha else "—"

            data.append(
                {
                    "Fecha": fecha_str,
                    "Código pieza": codigo,
                    "Operador": prod.get("usuario"),
                    "Modo": modo.capitalize(),
                    "Peso (kg)": peso,
                    "Valor ($)": valor,
                }
            )

        if not data:
            flash("No hay datos para exportar con esos filtros", "warning")
            return redirect(url_for("informe_piezas_operador"))

        return send_excel_file(data, "ValorOperador", "valor_por_operador.xlsx")

    @app.route("/admin/archivados/valor-operador/export", methods=["POST"])
    @login_required(["administrador", "soporte"])
    def exportar_valor_operador_archivado():
        operador_sel = request.form.get("operador")
        fecha_inicio = request.form.get("fecha_inicio")
        fecha_fin = request.form.get("fecha_fin")
        corte_nombre = request.form.get("corte_nombre")

        filtro = {}
        if operador_sel and operador_sel != "todos":
            filtro["usuario"] = operador_sel

        corte_id = None
        if corte_nombre and "corte_id" not in filtro:
            corte = db.cortes.find_one({"nombre": corte_nombre})
            if not corte:
                try:
                    corte = db.cortes.find_one({"_id": ObjectId(corte_nombre)})
                except Exception:
                    pass

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

        if not corte_nombre and (fecha_inicio or fecha_fin):
            try:
                apply_date_range_filter(filtro, fecha_inicio, fecha_fin)
            except Exception:
                pass

        produccion = list(db.produccion_historica.find(filtro).sort("fecha", -1))

        users_map = {}
        if corte_id:
            users_hist = list(db.usuarios_historicos.find({"corte_id": corte_id}))
            if users_hist:
                users_map = {u.get("usuario"): u for u in users_hist}
        if not users_map:
            users_db = list(db.usuarios.find())
            users_map = {u.get("usuario"): u for u in users_db}

        codigos_necesarios = set()
        for prod in produccion:
            codigo = prod.get("codigo_pieza")
            if codigo:
                codigos_necesarios.add(codigo)
                if isinstance(codigo, str) and codigo.isdigit():
                    codigos_necesarios.add(int(codigo))
                elif isinstance(codigo, int):
                    codigos_necesarios.add(str(codigo))

        piezas_hist_corte_map = {}
        piezas_hist_gen_map = {}
        piezas_actuales_map = {}

        if codigos_necesarios:
            lista_codigos = list(codigos_necesarios)
            if corte_id:
                h_corte = list(db.piezas_historicas.find({"codigo": {"$in": lista_codigos}, "corte_id": corte_id}))
                for pieza in h_corte:
                    piezas_hist_corte_map[pieza.get("codigo")] = pieza

            h_gen = list(db.piezas_historicas.find({"codigo": {"$in": lista_codigos}}))
            for pieza in h_gen:
                if pieza.get("codigo") not in piezas_hist_gen_map:
                    piezas_hist_gen_map[pieza.get("codigo")] = pieza

            act = list(db.piezas.find({"codigo": {"$in": lista_codigos}}))
            for pieza in act:
                piezas_actuales_map[pieza.get("codigo")] = pieza

        data = []
        total_general = 0
        for prod in produccion:
            codigo = prod.get("codigo_pieza")
            modo = prod.get("modo")

            pieza_info = None
            codigos_probar = [codigo]
            if isinstance(codigo, str) and codigo.isdigit():
                codigos_probar.append(int(codigo))
            elif isinstance(codigo, int):
                codigos_probar.append(str(codigo))

            if corte_id:
                for codigo_lookup in codigos_probar:
                    pieza_info = piezas_hist_corte_map.get(codigo_lookup)
                    if pieza_info:
                        break
            if not pieza_info:
                for codigo_lookup in codigos_probar:
                    pieza_info = piezas_hist_gen_map.get(codigo_lookup)
                    if pieza_info:
                        break
            if not pieza_info:
                for codigo_lookup in codigos_probar:
                    pieza_info = piezas_actuales_map.get(codigo_lookup)
                    if pieza_info:
                        break

            marco_val = (pieza_info.get("marco") if pieza_info else None) or prod.get("marco") or ""
            tramo_val = (pieza_info.get("tramo") if pieza_info else None) or prod.get("tramo") or ""
            peso_val = prod.get("kilo_pieza")
            if peso_val in (None, ""):
                peso_val = pieza_info.get("kilo_pieza", 0) if pieza_info else 0

            tipo_precio = prod.get("tipo_precio") or (pieza_info.get("tipo_precio", "metro") if pieza_info else "metro")
            user = users_map.get(prod.get("usuario"))
            precio_unitario_snapshot = prod.get("precio_unitario")
            valor_unitario = float(precio_unitario_snapshot or 0)
            if precio_unitario_snapshot in (None, "") and user:
                if modo == "armador":
                    valor_unitario = (
                        user.get("precio_metro_armado", 0) if tipo_precio == "metro" else user.get("precio_avo_armado", 0)
                    )
                else:
                    valor_unitario = (
                        user.get("precio_metro_remate", 0) if tipo_precio == "metro" else user.get("precio_avo_remate", 0)
                    )

            total = (peso_val or 0) * (valor_unitario or 0)
            fecha_str = to_cl(prod.get("fecha")).strftime("%d-%m-%Y %H:%M") if prod.get("fecha") else ""

            data.append(
                {
                    "Fecha": fecha_str,
                    "Código": codigo,
                    "Operador": prod.get("usuario", ""),
                    "Modo": modo,
                    "Marco": marco_val,
                    "Tramo": tramo_val,
                    "Cantidad": 1,
                    "Peso": peso_val,
                    "Precio Unit.": valor_unitario,
                    "Tipo": tipo_precio,
                    "Total": total,
                }
            )
            total_general += total

        if data:
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

        return send_excel_file(data, "ValorOperadorArchivado", "valor_por_operador_archivado.xlsx")

    @app.route("/admin/informes/piezas/estado", methods=["GET", "POST"])
    @login_required(["administrador", "supervisor", "soporte", "cliente"])
    def informe_estado_piezas():
        page = normalize_page(request.args.get("page", 1))

        if request.method == "POST":
            return redirect(
                url_for(
                    "informe_estado_piezas",
                    empresa=request.form.get("empresa") or "todos",
                    marco=request.form.get("marco") or "todos",
                    tramo=request.form.get("tramo") or "todos",
                    codigo_pieza=(request.form.get("codigo_pieza") or "").strip(),
                    estado=request.form.get("estado") or "todos",
                    page=1,
                )
            )

        empresa = request.args.get("empresa")
        marco = request.args.get("marco")
        tramo = request.args.get("tramo")
        codigo = request.args.get("codigo_pieza")
        estado_filter = request.args.get("estado")

        filtros = {}
        if empresa and empresa != "todos":
            filtros["empresa"] = empresa
        if marco and marco != "todos":
            filtros["marco"] = marco
        if tramo and tramo != "todos":
            filtros["tramo"] = tramo
        apply_exact_codigo_filter(filtros, codigo)

        stats, listado = get_estado_piezas_dataset(db, filtros, estado_filter)
        piezas_pagina, pagination = paginate_list(
            listado,
            "informe_estado_piezas",
            page=page,
            empresa=empresa,
            marco=marco,
            tramo=tramo,
            codigo_pieza=codigo,
            estado=estado_filter,
        )

        empresas = sorted([value for value in db.piezas.distinct("empresa") if value], key=str)
        marcos = sorted([value for value in db.piezas.distinct("marco") if value], key=str)
        tramos = sorted([value for value in db.piezas.distinct("tramo") if value], key=str)

        return render_template(
            "informe_estado_piezas.html",
            piezas=piezas_pagina,
            stats=stats,
            empresas=empresas,
            marcos=marcos,
            tramos=tramos,
            empresa_sel=empresa,
            marco_sel=marco,
            tramo_sel=tramo,
            codigo_sel=codigo,
            estado_sel=estado_filter,
            pagination=pagination,
        )

    @app.route("/admin/informes/piezas/estado/export", methods=["POST"])
    @login_required(["administrador", "supervisor", "soporte"])
    def exportar_estado_piezas_excel():
        empresa = request.form.get("empresa")
        marco = request.form.get("marco")
        tramo = request.form.get("tramo")
        codigo = request.form.get("codigo_pieza")
        estado_filter = request.form.get("estado")

        filtros = {}
        if empresa and empresa != "todos":
            filtros["empresa"] = empresa
        if marco and marco != "todos":
            filtros["marco"] = marco
        if tramo and tramo != "todos":
            filtros["tramo"] = tramo
        apply_exact_codigo_filter(filtros, codigo)

        _, listado = get_estado_piezas_dataset(db, filtros, estado_filter)
        data = []
        for pieza in listado:
            visto_bueno = "OK" if pieza.get("estado") == "Rematado" else ""
            data.append(
                {
                    "Código": pieza.get("codigo"),
                    "Cliente": pieza.get("cliente"),
                    "Marco": pieza.get("marco"),
                    "Tramo": pieza.get("tramo"),
                    "Cuerda Int.": pieza.get("cuerda_interna", ""),
                    "Cuerda Ext.": pieza.get("cuerda_externa", ""),
                    "Flecha": pieza.get("flecha", ""),
                    "Estado": pieza.get("estado"),
                    "Visto Bueno": visto_bueno,
                }
            )

        if not data:
            flash("No hay datos para exportar con esos filtros.", "warning")
            return redirect(url_for("informe_estado_piezas"))

        return send_excel_file(data, "EstadoPiezas", "informe_estado_piezas.xlsx")
