from datetime import datetime, timezone

from bson import ObjectId
from flask import flash, redirect, render_template, request, session, url_for


COLLECTION_PLANIFICACIONES = "planificaciones"


def _now_utc():
    return datetime.now(timezone.utc)


def _get_ciclo_actual(db):
    conf = db.config.find_one({"key": "ciclo_actual"}) or {"value": "a"}
    return str(conf.get("value") or "a")


def _normalize_grupo(raw):
    empresa = (raw.get("empresa") or "").strip()
    marco = (raw.get("marco") or "").strip()
    tramo = (raw.get("tramo") or "").strip()
    return {
        "empresa": empresa,
        "marco": marco,
        "tramo": tramo,
    }


def _group_filter(grupo):
    return {
        "grupo.empresa": grupo.get("empresa", ""),
        "grupo.marco": grupo.get("marco", ""),
    }


def _mode_key(modo):
    if modo == "armador":
        return "armador"
    if modo == "rematador":
        return "rematador"
    return None


def _split_even(total, operadores):
    total = max(0, int(total or 0))
    n = len(operadores)
    if n <= 0:
        return []
    base = total // n
    rem = total % n
    asignaciones = []
    for i, op in enumerate(operadores):
        asignaciones.append(
            {
                "user_id": ObjectId(op["_id"]) if not isinstance(op["_id"], ObjectId) else op["_id"],
                "user_name": op.get("nombre") or op.get("usuario") or "Operador",
                "objetivo": base + (1 if i < rem else 0),
                "producido": 0,
            }
        )
    return asignaciones


def _rebalanced_set_objetivo(modo_doc, target_user_id, new_objetivo):
    asignaciones = modo_doc.get("asignaciones") or []
    if not asignaciones:
        return modo_doc

    target_user_id = ObjectId(target_user_id) if not isinstance(target_user_id, ObjectId) else target_user_id

    total_global = int(modo_doc.get("total") or 0)
    new_objetivo = max(0, int(new_objetivo or 0))

    idx = None
    for i, a in enumerate(asignaciones):
        if a.get("user_id") == target_user_id:
            idx = i
            break
    if idx is None:
        return modo_doc

    producido_target = int(asignaciones[idx].get("producido") or 0)
    new_objetivo = max(new_objetivo, producido_target)

    sum_otros = 0
    for i, a in enumerate(asignaciones):
        if i == idx:
            continue
        sum_otros += int(a.get("objetivo") or 0)

    max_target = total_global - sum_otros
    max_target = max(max_target, producido_target)
    if new_objetivo > max_target:
        new_objetivo = max_target

    old_obj = int(asignaciones[idx].get("objetivo") or 0)
    delta = new_objetivo - old_obj
    asignaciones[idx]["objetivo"] = new_objetivo

    if delta == 0:
        modo_doc["asignaciones"] = asignaciones
        return modo_doc

    if delta > 0:
        remaining = delta
        donors = []
        for i, a in enumerate(asignaciones):
            if i == idx:
                continue
            prod = int(a.get("producido") or 0)
            obj = int(a.get("objetivo") or 0)
            slack = max(obj - prod, 0)
            if slack <= 0:
                continue
            donors.append((prod, -slack, i))
        donors.sort()

        for _, __, i in donors:
            if remaining <= 0:
                break
            prod = int(asignaciones[i].get("producido") or 0)
            obj = int(asignaciones[i].get("objetivo") or 0)
            slack = max(obj - prod, 0)
            take = min(slack, remaining)
            asignaciones[i]["objetivo"] = obj - take
            remaining -= take

        if remaining > 0:
            asignaciones[idx]["objetivo"] = new_objetivo - remaining

    if delta < 0:
        extra = -delta
        receivers = []
        for i, a in enumerate(asignaciones):
            if i == idx:
                continue
            prod = int(a.get("producido") or 0)
            receivers.append((prod, i))
        receivers.sort()
        for _, i in receivers:
            if extra <= 0:
                break
            asignaciones[i]["objetivo"] = int(asignaciones[i].get("objetivo") or 0) + 1
            extra -= 1
        while extra > 0:
            for _, i in receivers:
                if extra <= 0:
                    break
                asignaciones[i]["objetivo"] = int(asignaciones[i].get("objetivo") or 0) + 1
                extra -= 1

    modo_doc["asignaciones"] = asignaciones
    return modo_doc


def register_admin_planificacion_routes(app, db, login_required, get_production_status_map, build_tarjetas_grupos):
    @app.route("/admin/planificacion", methods=["GET"])
    @login_required(["administrador", "soporte"])
    def admin_planificacion_home():
        production_status_map = get_production_status_map(db, db.produccion, {})
        piezas = list(db.piezas.find({}, {"codigo": 1, "empresa": 1, "marco": 1, "tramo": 1, "_id": 0}))
        grupos = build_tarjetas_grupos(piezas, production_status_map, include_orphans=True)

        selected = _normalize_grupo(
            {
                "empresa": request.args.get("empresa") or "",
                "marco": request.args.get("marco") or "",
                "tramo": "",
            }
        )
        selected_active = bool(selected["empresa"] or selected["marco"])

        ciclo = _get_ciclo_actual(db)
        plan = None
        tramos_info = []
        pendientes_armador = {}
        pendientes_rematador = {}
        operador_ids_armador = set()
        operador_ids_rematador = set()
        if selected_active:
            plan = db[COLLECTION_PLANIFICACIONES].find_one({"ciclo": ciclo, **_group_filter(selected)})
            if plan:
                modos = plan.get("modos") or {}
                for modo_key in ("armador", "rematador"):
                    modo_doc = modos.get(modo_key) or {}
                    tramos_doc = modo_doc.get("tramos") or {}
                    for _, tramo_doc in tramos_doc.items():
                        for a in (tramo_doc.get("asignaciones") or []):
                            if a.get("user_id"):
                                if modo_key == "armador":
                                    operador_ids_armador.add(a["user_id"])
                                else:
                                    operador_ids_rematador.add(a["user_id"])
            for g in grupos:
                if str(g.get("cliente")) != str(selected.get("empresa")):
                    continue
                for m in g.get("marcos", []):
                    if str(m.get("marco")) != str(selected.get("marco")):
                        continue
                    for t in m.get("tramos", []):
                        tramo_key = str(t.get("tramo") or "")
                        total = int(t.get("total") or 0)
                        armadas = int(t.get("armadas") or 0)
                        rematadas = int(t.get("rematadas") or 0)
                        faltan_arm = max(total - armadas, 0)
                        faltan_rem = max(total - rematadas, 0)
                        tramos_info.append(
                            {
                                "tramo": tramo_key,
                                "total": total,
                                "armadas": armadas,
                                "rematadas": rematadas,
                                "faltan_arm": faltan_arm,
                                "faltan_rem": faltan_rem,
                            }
                        )
                        pendientes_armador[tramo_key] = faltan_arm
                        pendientes_rematador[tramo_key] = faltan_rem
                    break
                break

        operadores = list(db.usuarios.find({"tipo": "operador"}, {"nombre": 1, "usuario": 1}).sort("nombre", 1))

        return render_template(
            "admin_planificacion.html",
            grupos=grupos,
            selected=selected if selected_active else None,
            plan=plan,
            ciclo=ciclo,
            operadores=operadores,
            tramos_info=sorted(tramos_info, key=lambda x: str(x.get("tramo"))),
            pendientes_armador=pendientes_armador,
            pendientes_rematador=pendientes_rematador,
            operador_ids_armador=operador_ids_armador,
            operador_ids_rematador=operador_ids_rematador,
        )

    @app.route("/admin/planificacion/crear", methods=["POST"])
    @login_required("administrador")
    def admin_planificacion_crear():
        modo = request.form.get("modo")
        modo_key = _mode_key(modo)
        if not modo_key:
            flash("Modo inválido.", "danger")
            return redirect(url_for("admin_planificacion_home"))

        grupo = _normalize_grupo(
            {
                "empresa": request.form.get("empresa") or "",
                "marco": request.form.get("marco") or "",
                "tramo": "",
            }
        )
        if not (grupo["empresa"] and grupo["marco"]):
            flash("Debes seleccionar un grupo (empresa/marco).", "warning")
            return redirect(url_for("admin_planificacion_home"))

        user_ids = request.form.getlist("operadores[]")
        valid_ids = [ObjectId(uid) for uid in user_ids if ObjectId.is_valid(str(uid))]
        if not valid_ids:
            flash("Debes seleccionar al menos un operador.", "warning")
            return redirect(url_for("admin_planificacion_home", **grupo))

        operadores = list(
            db.usuarios.find({"_id": {"$in": valid_ids}, "tipo": "operador"}, {"nombre": 1, "usuario": 1})
        )
        if not operadores:
            flash("No se encontraron operadores válidos.", "danger")
            return redirect(url_for("admin_planificacion_home", **grupo))

        production_status_map = get_production_status_map(db, db.produccion, {})
        piezas = list(db.piezas.find({}, {"codigo": 1, "empresa": 1, "marco": 1, "tramo": 1, "_id": 0}))
        grupos = build_tarjetas_grupos(piezas, production_status_map, include_orphans=True)

        pendientes_armador = {}
        pendientes_rematador = {}
        for g in grupos:
            if str(g.get("cliente")) != str(grupo.get("empresa")):
                continue
            for m in g.get("marcos", []):
                if str(m.get("marco")) != str(grupo.get("marco")):
                    continue
                for t in m.get("tramos", []):
                    tramo_key = str(t.get("tramo") or "")
                    total_tramo = int(t.get("total") or 0)
                    armadas = int(t.get("armadas") or 0)
                    rematadas = int(t.get("rematadas") or 0)
                    pendientes_armador[tramo_key] = max(total_tramo - armadas, 0)
                    pendientes_rematador[tramo_key] = max(total_tramo - rematadas, 0)
                break
            break

        pendientes = pendientes_armador if modo_key == "armador" else pendientes_rematador
        tramos_doc = {}
        total_global = 0
        for tramo_key, total_tramo in pendientes.items():
            total_tramo = max(0, int(total_tramo or 0))
            if total_tramo <= 0:
                continue
            total_global += total_tramo
            tramos_doc[tramo_key] = {
                "total": total_tramo,
                "asignaciones": _split_even(
                    total_tramo,
                    [{"_id": o["_id"], "nombre": o.get("nombre"), "usuario": o.get("usuario")} for o in operadores],
                ),
            }

        ciclo = _get_ciclo_actual(db)
        now = _now_utc()

        base = db[COLLECTION_PLANIFICACIONES].find_one({"ciclo": ciclo, **_group_filter(grupo)})
        if not base:
            base = {
                "ciclo": ciclo,
                "grupo": grupo,
                "created_at": now,
                "created_by_user_id": session.get("user_id"),
                "created_by_user_name": session.get("nombre"),
                "modos": {
                    "armador": {"total": 0, "tramos": {}},
                    "rematador": {"total": 0, "tramos": {}},
                },
            }
            res = db[COLLECTION_PLANIFICACIONES].insert_one(base)
            base["_id"] = res.inserted_id

        db[COLLECTION_PLANIFICACIONES].update_one(
            {"_id": base["_id"]},
            {
                "$set": {
                    f"modos.{modo_key}.total": total_global,
                    f"modos.{modo_key}.tramos": tramos_doc,
                    "updated_at": now,
                }
            },
        )

        flash("Planificación guardada (por marco, distribuida por tramo).", "success")
        return redirect(url_for("admin_planificacion_home", **grupo))

    @app.route("/admin/planificacion/ajustar", methods=["POST"])
    @login_required("administrador")
    def admin_planificacion_ajustar():
        plan_id = request.form.get("plan_id")
        modo = request.form.get("modo")
        modo_key = _mode_key(modo)
        tramo = (request.form.get("tramo") or "").strip()
        user_id = request.form.get("user_id")
        new_objetivo = request.form.get("objetivo")

        if not (ObjectId.is_valid(str(plan_id)) and modo_key and tramo and ObjectId.is_valid(str(user_id))):
            flash("Datos inválidos.", "danger")
            return redirect(url_for("admin_planificacion_home"))

        try:
            new_objetivo = int(new_objetivo)
        except Exception:
            new_objetivo = 0

        plan = db[COLLECTION_PLANIFICACIONES].find_one({"_id": ObjectId(plan_id)})
        if not plan:
            flash("Planificación no encontrada.", "warning")
            return redirect(url_for("admin_planificacion_home"))

        modo_doc = ((plan.get("modos") or {}).get(modo_key) or {"total": 0, "tramos": {}})
        tramos = modo_doc.get("tramos") or {}
        tramo_doc = tramos.get(tramo)
        if not tramo_doc:
            flash("Tramo no encontrado en la planificación.", "warning")
            return redirect(url_for("admin_planificacion_home", **_normalize_grupo(plan.get("grupo") or {})))

        tramo_doc = _rebalanced_set_objetivo(tramo_doc, ObjectId(user_id), new_objetivo)
        tramos[tramo] = tramo_doc
        modo_doc["tramos"] = tramos

        db[COLLECTION_PLANIFICACIONES].update_one(
            {"_id": ObjectId(plan_id)},
            {"$set": {f"modos.{modo_key}": modo_doc, "updated_at": _now_utc()}},
        )

        grupo = (plan.get("grupo") or {})
        return redirect(url_for("admin_planificacion_home", **_normalize_grupo(grupo)))

    @app.route("/admin/planificacion/eliminar", methods=["POST"])
    @login_required("administrador")
    def admin_planificacion_eliminar():
        empresa = request.form.get("empresa") or ""
        marco = request.form.get("marco") or ""
        grupo = _normalize_grupo({"empresa": empresa, "marco": marco, "tramo": ""})

        try:
            ciclo = _get_ciclo_actual(db)
            res = db[COLLECTION_PLANIFICACIONES].delete_one({"ciclo": ciclo, **_group_filter(grupo)})
            if res.deleted_count == 1:
                flash("Planificación eliminada. La pieza queda liberada para todos.", "success")
            else:
                flash("No se encontró planificación para eliminar.", "warning")
        except Exception as exc:
            flash(f"Error al eliminar planificación: {str(exc)}", "danger")
        return redirect(url_for("admin_planificacion_home", **grupo))
