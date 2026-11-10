import math
import re
import json
from datetime import datetime

from bson import ObjectId
from flask import flash, redirect, render_template, request, session, url_for
from pymongo import ReturnDocument
from werkzeug.security import generate_password_hash

from core.helpers.soft_delete import soft_delete_one, soft_delete_many


def _parse_optional_measure(raw_value):
    """Normaliza medidas opcionales de piezas a float o None."""
    value = str(raw_value or "").strip()
    if not value:
        return None

    value = value.replace(",", ".")
    return float(value)


def _parse_required_measure(raw_value):
    value = str(raw_value or "").strip()
    if not value:
        raise ValueError("required numeric value missing")
    return float(value.replace(",", "."))


def _parse_optional_measure_from_form(form_data, field_name, fallback_value=None):
    if field_name not in form_data:
        return fallback_value
    return _parse_optional_measure(form_data.get(field_name))


def _normalize_massive_field(raw_field):
    value = str(raw_field or "").strip().lower()
    aliases = {
        "cliente": "empresa",
        "empresa": "empresa",
        "marco": "marco",
        "tramo": "tramo",
        "peso": "kilo_pieza",
        "peso (kg)": "kilo_pieza",
        "kilo por pieza": "kilo_pieza",
        "kilo_pieza": "kilo_pieza",
        "cuerda interna": "cuerda_interna",
        "cuerda_interna": "cuerda_interna",
        "cuerda externa": "cuerda_externa",
        "cuerda_externa": "cuerda_externa",
        "flecha": "flecha",
        "tipo de precio": "tipo_precio",
        "tipo de precio (metro/avo)": "tipo_precio",
        "tipo_precio": "tipo_precio",
    }
    return aliases.get(value, value)



ROLES_VALIDOS = {"operador", "supervisor", "soporte", "administrador", "cliente", "invitado"}
PRECIO_CAMPOS = ("precio_metro_armado", "precio_metro_remate", "precio_avo_armado", "precio_avo_remate")


def _leer_precios(form):
    """Lee los precios del formulario; devuelve None si alguno no es un numero valido >= 0."""
    precios = {}
    for campo in PRECIO_CAMPOS:
        raw = (form.get(campo) or "0").strip().replace(",", ".")
        try:
            valor = float(raw)
        except ValueError:
            return None
        if not math.isfinite(valor) or valor < 0:
            return None
        precios[campo] = valor
    return precios


def register_admin_crud_routes(
    app,
    db,
    login_required,
    normalize_page,
    build_pagination,
    default_per_page,
):
    """Registra CRUD administrativos residuales de usuarios, boxes y piezas."""

    @app.route("/admin/usuarios")
    @login_required(["administrador", "soporte"])
    def usuarios_list():
        usuarios = list(db.usuarios.find({"usuario": {"$ne": "soporte"}}))
        return render_template("crud_usuarios.html", usuarios=usuarios)

    @app.route("/admin/usuarios/nuevo")
    @login_required(["administrador", "soporte"])
    def usuarios_nuevo_form():
        return render_template("usuario_form.html", modo="nuevo")

    @app.route("/admin/usuarios/nuevo", methods=["POST"])
    @login_required(["administrador", "soporte"])
    def usuarios_nuevo_post():
        usuario = request.form["usuario"].strip()
        nombre = request.form["nombre"].strip()
        tipo = request.form["tipo"]

        if tipo not in ROLES_VALIDOS:
            flash("Tipo de usuario inválido", "danger")
            return redirect(url_for("usuarios_list"))
        if tipo == "administrador" and session.get("role") != "administrador":
            flash("Solo un administrador puede crear administradores", "danger")
            return redirect(url_for("usuarios_list"))

        precios = _leer_precios(request.form)
        if precios is None:
            flash("Los precios deben ser números válidos mayores o iguales a 0", "danger")
            return redirect(url_for("usuarios_list"))
        precio_metro_armado = precios["precio_metro_armado"]
        precio_metro_remate = precios["precio_metro_remate"]
        precio_avo_armado = precios["precio_avo_armado"]
        precio_avo_remate = precios["precio_avo_remate"]
        sin_restriccion = bool(request.form.get("sin_restriccion"))
        puede_editar_planificacion = bool(request.form.get("puede_editar_planificacion")) if tipo == "supervisor" else False

        password = generate_password_hash(request.form["password"])

        if db.usuarios.find_one({"usuario": usuario}):
            flash("El usuario ya existe", "warning")
            return redirect(url_for("usuarios_list"))

        db.usuarios.insert_one(
            {
                "usuario": usuario,
                "nombre": nombre,
                "tipo": tipo,
                "precio_metro_armado": precio_metro_armado,
                "precio_metro_remate": precio_metro_remate,
                "precio_avo_armado": precio_avo_armado,
                "precio_avo_remate": precio_avo_remate,
                "sin_restriccion": sin_restriccion,
                "puede_editar_planificacion": puede_editar_planificacion,
                "password": password,
            }
        )

        flash("Usuario creado correctamente ✔", "success")
        return redirect(url_for("usuarios_list"))

    @app.route("/admin/usuarios/<id>/editar")
    @login_required(["administrador", "soporte"])
    def usuarios_editar_form(id):
        usuario = db.usuarios.find_one({"_id": ObjectId(id)})
        if not usuario:
            flash("Usuario no encontrado", "danger")
            return redirect(url_for("usuarios_list"))

        return render_template("usuario_form.html", modo="editar", usuario=usuario)

    @app.route("/admin/usuarios/<id>/editar", methods=["POST"])
    @login_required(["administrador", "soporte"])
    def usuarios_editar_post(id):
        nombre = request.form["nombre"].strip()
        tipo = request.form["tipo"]

        if tipo not in ROLES_VALIDOS:
            flash("Tipo de usuario inválido", "danger")
            return redirect(url_for("usuarios_list"))
        if session.get("role") != "administrador":
            objetivo = db.usuarios.find_one({"_id": ObjectId(id)}, {"tipo": 1})
            if tipo == "administrador" or (objetivo or {}).get("tipo") == "administrador":
                flash("Solo un administrador puede editar administradores", "danger")
                return redirect(url_for("usuarios_list"))

        precios = _leer_precios(request.form)
        if precios is None:
            flash("Los precios deben ser números válidos mayores o iguales a 0", "danger")
            return redirect(url_for("usuarios_list"))
        precio_metro_armado = precios["precio_metro_armado"]
        precio_metro_remate = precios["precio_metro_remate"]
        precio_avo_armado = precios["precio_avo_armado"]
        precio_avo_remate = precios["precio_avo_remate"]
        sin_restriccion = bool(request.form.get("sin_restriccion"))
        puede_editar_planificacion = bool(request.form.get("puede_editar_planificacion")) if tipo == "supervisor" else False

        pwd = request.form.get("password", "").strip()

        update = {
            "nombre": nombre,
            "tipo": tipo,
            "precio_metro_armado": precio_metro_armado,
            "precio_metro_remate": precio_metro_remate,
            "precio_avo_armado": precio_avo_armado,
            "precio_avo_remate": precio_avo_remate,
            "sin_restriccion": sin_restriccion,
            "puede_editar_planificacion": puede_editar_planificacion,
        }
        if pwd:
            update["password"] = generate_password_hash(pwd)

        db.usuarios.update_one({"_id": ObjectId(id)}, {"$set": update})
        flash("Usuario actualizado ✔", "success")
        return redirect(url_for("usuarios_list"))

    @app.route("/admin/usuarios/<id>/delete", methods=["POST"])
    @login_required(["administrador", "soporte"])
    def usuarios_delete(id):
        if str(session.get("user_id")) == id:
            flash("No puedes eliminar tu propio usuario", "warning")
            return redirect(url_for("usuarios_list"))

        ok, msg = soft_delete_one(
            db,
            collection_origen="usuarios",
            filtro_doc={"_id": ObjectId(id)},
            deleted_by_user_id=session.get("user_id"),
            deleted_by_user_name=session.get("nombre"),
            deleted_by_ip=request.remote_addr,
            motivo="admin/soporte botón eliminar usuario",
        )
        flash(msg, "success" if ok else "danger")
        return redirect(url_for("usuarios_list"))

    @app.route("/admin/boxes")
    @login_required(["administrador", "soporte"])
    def boxes_list():
        boxes = list(db.boxes.find())
        return render_template("crud_boxes.html", boxes=boxes)

    @app.route("/admin/boxes/nuevo")
    @login_required(["administrador", "soporte"])
    def boxes_nuevo_form():
        return render_template("box_form.html", modo="nuevo")

    @app.route("/admin/boxes/nuevo", methods=["POST"])
    @login_required(["administrador", "soporte"])
    def boxes_nuevo_post():
        codigo = request.form["codigo"].strip()
        descripcion = request.form["descripcion"].strip()

        if db.boxes.find_one({"codigo": codigo}):
            flash("El código del box ya existe", "warning")
            return redirect(url_for("boxes_list"))

        db.boxes.insert_one(
            {
                "codigo": codigo,
                "descripcion": descripcion,
                "created_at": datetime.utcnow(),
            }
        )

        flash("Box creado ✔", "success")
        return redirect(url_for("boxes_list"))

    @app.route("/admin/boxes/<id>/editar")
    @login_required(["administrador", "soporte"])
    def boxes_editar_form(id):
        box = db.boxes.find_one({"_id": ObjectId(id)})
        if not box:
            flash("Box no encontrado", "danger")
            return redirect(url_for("boxes_list"))

        return render_template("box_form.html", modo="editar", box=box)

    @app.route("/admin/boxes/<id>/editar", methods=["POST"])
    @login_required(["administrador", "soporte"])
    def boxes_editar_post(id):
        codigo = request.form["codigo"].strip()
        descripcion = request.form["descripcion"].strip()

        db.boxes.update_one(
            {"_id": ObjectId(id)},
            {"$set": {"codigo": codigo, "descripcion": descripcion}},
        )

        flash("Box actualizado ✔", "success")
        return redirect(url_for("boxes_list"))

    @app.route("/admin/boxes/<id>/delete", methods=["POST"])
    @login_required(["administrador", "soporte"])
    def boxes_delete(id):
        ok, msg = soft_delete_one(
            db,
            collection_origen="boxes",
            filtro_doc={"_id": ObjectId(id)},
            deleted_by_user_id=session.get("user_id"),
            deleted_by_user_name=session.get("nombre"),
            deleted_by_ip=request.remote_addr,
            motivo="admin/soporte botón eliminar box",
        )
        flash(msg, "success" if ok else "danger")
        return redirect(url_for("boxes_list"))

    @app.route("/admin/piezas")
    @login_required(["administrador", "soporte"])
    def piezas_list():
        page = normalize_page(request.args.get("page", 1))
        codigo = request.args.get("codigo", "").strip()
        filtro = {}

        if codigo:
            filtro["codigo"] = {"$regex": re.escape(codigo), "$options": "i"}

        total_registros = db.piezas.count_documents(filtro)
        total_pages = max((total_registros + default_per_page - 1) // default_per_page, 1)
        page = min(page, total_pages)
        skip = (page - 1) * default_per_page

        piezas = list(
            db.piezas.find(filtro)
            .sort("codigo", 1)
            .skip(skip)
            .limit(default_per_page)
        )
        # #region debug-point C:listado
        # #endregion
        pagination = build_pagination("piezas_list", page, total_registros, codigo=codigo)
        return render_template(
            "crud_piezas.html",
            piezas=piezas,
            codigo_sel=codigo,
            pagination=pagination,
        )

    @app.route("/api/piezas/filtros-dinamicos", methods=["GET"])
    @login_required(["administrador", "soporte"])
    def api_piezas_filtros():
        try:
            cliente = request.args.get("cliente")
            marco = request.args.get("marco")

            match = {}
            if cliente:
                match["empresa"] = cliente
            if marco:
                match["marco"] = marco

            data = {
                "marcos": sorted(db.piezas.distinct("marco", match)) if cliente else [],
                "tramos": sorted(db.piezas.distinct("tramo", match)) if marco else [],
            }

            if not cliente:
                data["empresas"] = sorted(db.piezas.distinct("empresa"))

            return data
        except Exception as exc:
            return {"error": "No se pudieron cargar los filtros"}, 500

    @app.route("/admin/piezas/eliminar-masivo")
    @login_required(["administrador", "soporte"])
    def piezas_eliminar_masivo():
        empresas = sorted(db.piezas.distinct("empresa"))
        return render_template("piezas_eliminar_masivo.html", empresas=empresas)

    @app.route("/api/piezas/filtrar-eliminar", methods=["POST"])
    @login_required(["administrador", "soporte"])
    def api_filtrar_eliminar():
        try:
            data = request.json
            cliente = data.get("cliente")
            marco = data.get("marco")
            tramo = data.get("tramo")
            estado_filtro = data.get("estado")

            match_query = {}
            if cliente:
                match_query["empresa"] = cliente
            if marco:
                match_query["marco"] = marco
            if tramo:
                match_query["tramo"] = tramo

            piezas_candidatas = list(
                db.piezas.find(
                    match_query,
                    {"_id": 0, "codigo": 1, "empresa": 1, "marco": 1, "tramo": 1},
                )
            )

            if not piezas_candidatas:
                return {"piezas": []}

            codigos_candidatos = [pieza["codigo"] for pieza in piezas_candidatas]

            pipeline = [
                {"$match": {"codigo_pieza": {"$in": codigos_candidatos}}},
                {"$sort": {"fecha": 1}},
                {
                    "$group": {
                        "_id": "$codigo_pieza",
                        "ultimo_modo": {"$last": "$modo"},
                        "fecha": {"$last": "$fecha"},
                    }
                },
            ]

            produccion_status = {
                doc["_id"]: doc["ultimo_modo"]
                for doc in db.produccion.aggregate(pipeline)
            }

            resultados = []
            for pieza in piezas_candidatas:
                codigo_pieza = pieza["codigo"]
                modo = produccion_status.get(codigo_pieza)

                estado = "Sin Producción"
                if modo == "armador":
                    estado = "Armado"
                elif modo == "rematador":
                    estado = "Rematado"

                if estado_filtro and estado_filtro != "todos":
                    if estado_filtro == "sin_produccion" and estado != "Sin Producción":
                        continue
                    if estado_filtro == "armado" and estado != "Armado":
                        continue
                    if estado_filtro == "rematado" and estado != "Rematado":
                        continue

                pieza["estado"] = estado
                resultados.append(pieza)

            return {"piezas": resultados}
        except Exception as exc:
            print(f"Error filtrar eliminar: {exc}")
            return {"piezas": []}, 500

    @app.route("/admin/piezas/eliminar-confirmar", methods=["POST"])
    @login_required(["administrador", "soporte"])
    def piezas_eliminar_confirmar():
        try:
            data = request.get_json(silent=True)
            codigos = data.get("codigos") if isinstance(data, dict) else None
            if not isinstance(codigos, list) or not codigos or any(
                not isinstance(codigo, (str, int)) for codigo in codigos
            ):
                return {"success": False, "message": "No se seleccionaron piezas"}, 400

            cantidad, msg = soft_delete_many(
                db,
                collection_origen="piezas",
                filtro_docs={"codigo": {"$in": codigos}},
                deleted_by_user_id=session.get("user_id"),
                deleted_by_user_name=session.get("nombre"),
                deleted_by_ip=request.remote_addr,
                motivo="admin eliminación masiva piezas (códigos)",
            )
            return {"success": cantidad > 0 and not msg.startswith("ADVERTENCIA"),
                    "deleted_count": cantidad, "message": msg}
        except Exception as exc:
            return {"success": False, "message": "Error interno al eliminar las piezas"}, 500

    @app.route("/admin/piezas/nuevo")
    @login_required(["administrador", "soporte"])
    def piezas_nuevo_form():
        return render_template("pieza_form.html", modo="nuevo", pieza=None)

    @app.route("/admin/piezas/nuevo", methods=["POST"])
    @login_required(["administrador", "soporte"])
    def piezas_nuevo_post():
        empresa = request.form["empresa"].strip()
        marco = request.form["marco"].strip()
        tramo = request.form["tramo"].strip()
        tipo_precio = request.form["tipo_precio"]

        try:
            kilo_pieza = _parse_required_measure(request.form.get("kilo_pieza"))
            cuerda_interna = _parse_optional_measure(request.form.get("cuerda_interna"))
            cuerda_externa = _parse_optional_measure(request.form.get("cuerda_externa"))
            flecha = _parse_optional_measure(request.form.get("flecha"))
            cantidad = int(request.form["cantidad"])
        except ValueError:
            flash("Peso y medidas de la pieza deben ser numéricos.", "danger")
            return redirect(url_for("piezas_nuevo_form"))

        conf = db.config.find_one({"key": "ciclo_actual"}) or {"value": "a"}
        prefijo = conf.get("value", "a")

        counter_id = f"piezas_seq_{prefijo}"
        if not db.counters.find_one({"_id": counter_id}):
            max_seq = 0
            existentes = list(db.piezas.find({"codigo": {"$regex": f"^{re.escape(prefijo)}"}}))
            for pieza in existentes:
                try:
                    num_part = int(pieza["codigo"][len(prefijo) :])
                    if num_part > max_seq:
                        max_seq = num_part
                except Exception:
                    continue

            db.counters.insert_one({"_id": counter_id, "seq": max_seq})

        docs = []
        counter_doc = db.counters.find_one_and_update(
            {"_id": counter_id},
            {"$inc": {"seq": cantidad}},
            return_document=ReturnDocument.AFTER,
        )

        end_seq = counter_doc["seq"]
        start_seq = end_seq - cantidad + 1

        for index in range(cantidad):
            current_seq = start_seq + index
            docs.append(
                {
                    "codigo": f"{prefijo}{current_seq}",
                    "empresa": empresa,
                    "marco": marco,
                    "tramo": tramo,
                    "tipo_precio": tipo_precio,
                    "kilo_pieza": kilo_pieza,
                    "cuerda_interna": cuerda_interna,
                    "cuerda_externa": cuerda_externa,
                    "flecha": flecha,
                    "created_at": datetime.utcnow(),
                }
            )

        if docs:
            db.piezas.insert_many(docs)

        flash(
            f"✅ Se crearon {cantidad} piezas correctamente (desde código {prefijo}{start_seq}).",
            "success",
        )
        return redirect(url_for("piezas_list"))

    @app.route("/admin/piezas/<id>/editar")
    @login_required(["administrador", "soporte"])
    def piezas_editar_form(id):
        pieza = db.piezas.find_one({"_id": ObjectId(id)})
        if not pieza:
            flash("Pieza no encontrada", "warning")
            return redirect(url_for("piezas_list"))
        return render_template("pieza_form.html", modo="editar", pieza=pieza)

    @app.route("/admin/piezas/<id>/editar", methods=["POST"])
    @login_required(["administrador", "soporte"])
    def piezas_editar_post(id):
        empresa = request.form["empresa"].strip()
        marco = request.form["marco"].strip()
        tramo = request.form["tramo"].strip()
        tipo_precio = request.form["tipo_precio"]
        pieza_actual = db.piezas.find_one({"_id": ObjectId(id)})
        if not pieza_actual:
            flash("Pieza no encontrada", "warning")
            return redirect(url_for("piezas_list"))

        try:
            kilo_pieza = _parse_required_measure(request.form.get("kilo_pieza"))
            cuerda_interna = _parse_optional_measure_from_form(
                request.form, "cuerda_interna", pieza_actual.get("cuerda_interna")
            )
            cuerda_externa = _parse_optional_measure_from_form(
                request.form, "cuerda_externa", pieza_actual.get("cuerda_externa")
            )
            flecha = _parse_optional_measure_from_form(
                request.form, "flecha", pieza_actual.get("flecha")
            )
        except ValueError:
            # #region debug-point D:edit-parse-error
            # #endregion
            flash("Peso y medidas de la pieza deben ser numéricos.", "danger")
            return redirect(url_for("piezas_editar_form", id=id))

        # #region debug-point A:edit-before-update
        # #endregion

        update_result = db.piezas.update_one(
            {"_id": ObjectId(id)},
            {
                "$set": {
                    "empresa": empresa,
                    "marco": marco,
                    "tramo": tramo,
                    "tipo_precio": tipo_precio,
                    "kilo_pieza": kilo_pieza,
                    "cuerda_interna": cuerda_interna,
                    "cuerda_externa": cuerda_externa,
                    "flecha": flecha,
                }
            },
        )
        pieza_actualizada = db.piezas.find_one({"_id": ObjectId(id)}, {"codigo": 1, "flecha": 1, "cuerda_interna": 1, "cuerda_externa": 1})
        # #region debug-point B:edit-after-update
        # #endregion

        if pieza_actual and pieza_actual.get("codigo"):
            db.produccion.update_many(
                {"codigo_pieza": pieza_actual["codigo"]},
                {"$set": {"tipo_precio": tipo_precio}},
            )
            db.produccion_historica.update_many(
                {"codigo_pieza": pieza_actual["codigo"]},
                {"$set": {"tipo_precio": tipo_precio}},
            )

        flash("✅ Pieza actualizada con éxito", "success")
        return redirect(url_for("piezas_list"))

    @app.route("/admin/piezas/<id>/delete", methods=["POST"])
    @login_required(["administrador", "soporte"])
    def piezas_delete(id):
        ok, msg = soft_delete_one(
            db,
            collection_origen="piezas",
            filtro_doc={"_id": ObjectId(id)},
            deleted_by_user_id=session.get("user_id"),
            deleted_by_user_name=session.get("nombre"),
            deleted_by_ip=request.remote_addr,
            motivo="admin/soporte botón eliminar pieza",
        )
        flash(msg, "success" if ok else "danger")
        return redirect(url_for("piezas_list"))

    @app.route("/api/marcos/<empresa>")
    @login_required(["administrador", "supervisor", "soporte"])
    def api_marcos(empresa):
        marcos = db.piezas.distinct("marco", {"empresa": empresa})
        return {"marcos": marcos}

    @app.route("/api/tramos/<empresa>/<marco>")
    @login_required(["administrador", "supervisor", "soporte"])
    def api_tramos(empresa, marco):
        tramos = db.piezas.distinct("tramo", {"empresa": empresa, "marco": marco})
        return {"tramos": tramos}

    @app.route("/admin/piezas/masivo", methods=["GET", "POST"])
    @login_required(["administrador", "soporte"])
    def piezas_masivo():
        filtros = {}
        piezas = []
        empresas = db.piezas.distinct("empresa")

        if request.method == "POST":
            empresa = request.form.get("empresa")
            marco = request.form.get("marco")
            tramo = request.form.get("tramo")

            if empresa:
                filtros["empresa"] = empresa
            if marco:
                filtros["marco"] = marco
            if tramo:
                filtros["tramo"] = tramo

            piezas = list(db.piezas.find(filtros).sort("codigo", 1))

            if not piezas:
                flash("No se encontraron piezas con esos filtros.", "warning")

        return render_template(
            "piezas_masivo.html",
            piezas=piezas,
            filtros=json.dumps(filtros),
            empresas=empresas,
        )

    @app.route("/admin/piezas/masivo/confirmar", methods=["POST"])
    @login_required(["administrador", "soporte"])
    def piezas_masivo_confirmar():
        filtros = json.loads(request.form.get("filtros"))
        campo = _normalize_massive_field(request.form.get("campo"))
        valor = str(request.form.get("valor") or "").strip()

        permitidos = [
            "empresa",
            "marco",
            "tramo",
            "kilo_pieza",
            "cuerda_interna",
            "cuerda_externa",
            "flecha",
            "tipo_precio",
        ]
        if campo not in permitidos:
            # #region debug-point B:massive-not-allowed
            # #endregion
            flash("Campo no permitido para edición masiva.", "danger")
            return redirect(url_for("piezas_masivo"))

        if not campo or not valor:
            flash("Debes indicar el campo y el valor a modificar.", "warning")
            return redirect(url_for("piezas_masivo"))

        if campo == "kilo_pieza":
            try:
                valor = _parse_required_measure(valor)
            except Exception:
                flash("El valor debe ser numérico para este campo.", "danger")
                return redirect(url_for("piezas_masivo"))

        if campo in ["cuerda_interna", "cuerda_externa", "flecha"]:
            try:
                valor = _parse_optional_measure(valor)
            except ValueError:
                # #region debug-point D:massive-parse-error
                # #endregion
                flash("El valor debe ser numérico para este campo.", "danger")
                return redirect(url_for("piezas_masivo"))

        if campo == "tipo_precio":
            valor = valor.strip().lower()
            if valor not in ["metro", "avo"]:
                flash("El tipo de precio debe ser 'metro' o 'avo'.", "danger")
                return redirect(url_for("piezas_masivo"))

            piezas_afectadas = list(db.piezas.find(filtros, {"codigo": 1}))
            codigos = [pieza["codigo"] for pieza in piezas_afectadas if "codigo" in pieza]

            if codigos:
                db.produccion.update_many(
                    {"codigo_pieza": {"$in": codigos}},
                    {"$set": {"tipo_precio": valor}},
                )
                db.produccion_historica.update_many(
                    {"codigo_pieza": {"$in": codigos}},
                    {"$set": {"tipo_precio": valor}},
                )

        # #region debug-point B:massive-before-update
        # #endregion
        resultado = db.piezas.update_many(filtros, {"$set": {campo: valor}})
        # #region debug-point B:massive-after-update
        # #endregion

        flash(f"Se actualizaron {resultado.modified_count} piezas correctamente.", "success")
        return redirect(url_for("piezas_masivo"))
