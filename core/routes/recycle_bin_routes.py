"""
Rutas para Papelera de Reciclaje (7 días de retención).
Permite listar, restaurar y eliminar permanentemente documentos borrados.
"""

from datetime import datetime, timedelta, timezone

from bson.objectid import ObjectId
from flask import flash, redirect, render_template, request, session, url_for

from core.helpers.soft_delete import (
    COLLECTION_PAPELERA,
    DAYS_RETAIN,
    purge_expired_manual,
    restore_from_bin,
)
from core.helpers.date_utils import to_cl


def register_recycle_bin_routes(app, db, login_required, normalize_page, paginate_list):
    """Registra rutas de la papelera de reciclaje."""

    # ------------------------------------------------------------------
    # UI: Listar papelera / buscar / filtrar
    # ------------------------------------------------------------------
    @app.route("/papelera", methods=["GET", "POST"])
    @login_required(["administrador", "soporte"])
    def papelera_list():
        page = normalize_page(request.args.get("page", 1))
        filtro = {}
        tipo_sel = request.args.get("tipo", "todos")
        search_query = request.args.get("search", "")

        if request.method == "POST":
            return redirect(
                url_for(
                    "papelera_list",
                    tipo=request.form.get("tipo") or "todos",
                    search=(request.form.get("search") or "").strip(),
                    page=1,
                )
            )

        if tipo_sel and tipo_sel != "todos":
            filtro["collection_origen"] = tipo_sel

        if search_query:
            # Buscar por código de pieza, nombre operador, IP, etc. dentro del documento o metadata
            filtro["$or"] = [
                {"documento_original.codigo": {"$regex": search_query, "$options": "i"}},
                {"documento_original.codigo_pieza": {"$regex": search_query, "$options": "i"}},
                {"documento_original.usuario": {"$regex": search_query, "$options": "i"}},
                {"documento_original.empresa": {"$regex": search_query, "$options": "i"}},
                {"documento_original.nombre": {"$regex": search_query, "$options": "i"}},
                {"deleted_by_user_name": {"$regex": search_query, "$options": "i"}},
                {"tipo_documento": {"$regex": search_query, "$options": "i"}},
            ]

        documentos = list(
            db[COLLECTION_PAPELERA].find(filtro).sort("deleted_at", -1).limit(10000)
        )

        # Calcular tiempo restante para cada documento
        ahora = datetime.now(timezone.utc)
        for d in documentos:
            expira = d.get("expire_at") or ahora
            if isinstance(expira, datetime):
                if expira.tzinfo is None:
                    expira = expira.replace(tzinfo=timezone.utc)
                delta = expira - ahora
                if delta.total_seconds() > 0:
                    dias = delta.days
                    horas = delta.seconds // 3600
                    minutos = (delta.seconds % 3600) // 60
                    if dias > 0:
                        d["restante"] = f"{dias}d {horas}h"
                    elif horas > 0:
                        d["restante"] = f"{horas}h {minutos}m"
                    else:
                        d["restante"] = f"{minutos}m"
                else:
                    d["restante"] = "Expirado (se borrará pronto)"
            d["deleted_at_cl"] = to_cl(d.get("deleted_at")) if d.get("deleted_at") else None
            d["doc_preview"] = _build_preview(d.get("collection_origen"), d.get("documento_original", {}))

        docs_pagina, pagination = paginate_list(
            documentos,
            "papelera_list",
            page=page,
            tipo=tipo_sel,
            search=search_query,
        )

        # Conteos rápidos por categoría
        categorias_counts = {}
        for cat in ["piezas", "produccion", "usuarios", "boxes"]:
            categorias_counts[cat] = db[COLLECTION_PAPELERA].count_documents({"collection_origen": cat})

        total_en_papelera = db[COLLECTION_PAPELERA].count_documents({})

        return render_template(
            "papelera_reciclaje.html",
            documentos=docs_pagina,
            pagination=pagination,
            tipo_sel=tipo_sel,
            search_query=search_query,
            categorias_counts=categorias_counts,
            total_en_papelera=total_en_papelera,
            days_retain=DAYS_RETAIN,
        )

    # ------------------------------------------------------------------
    # UI: Restaurar desde papelera
    # ------------------------------------------------------------------
    @app.route("/papelera/<id>/restaurar", methods=["POST"])
    @login_required(["administrador", "soporte"])
    def papelera_restaurar(id):
        ok, msg = restore_from_bin(db, id)
        flash(msg, "success" if ok else "danger")
        return redirect(url_for("papelera_list", **_keep_filters(request)))

    # ------------------------------------------------------------------
    # UI: Eliminar PERMANENTEMENTE un documento de la papelera (no reversible)
    # ------------------------------------------------------------------
    @app.route("/papelera/<id>/eliminar-permanente", methods=["POST"])
    @login_required("administrador")  # Sólo administrador puede hacer hard delete
    def papelera_eliminar_permanente(id):
        if not ObjectId.is_valid(str(id)):
            flash("ID inválido.", "warning")
            return redirect(url_for("papelera_list", **_keep_filters(request)))

        doc = db[COLLECTION_PAPELERA].find_one({"_id": ObjectId(id)})
        res = db[COLLECTION_PAPELERA].delete_one({"_id": ObjectId(id)})
        if res.deleted_count == 1:
            tipo = doc.get("tipo_documento", "Documento") if doc else "Documento"
            flash(f"🗑️ {tipo} eliminado permanentemente (NO RECUPERABLE).", "warning")
        else:
            flash("No se encontró el documento en papelera.", "info")
        return redirect(url_for("papelera_list", **_keep_filters(request)))

    # ------------------------------------------------------------------
    # UI: Purgar expirados manualmente (limpia los pasados 7 días antes del TTL)
    # ------------------------------------------------------------------
    @app.route("/papelera/purgar-expirados", methods=["POST"])
    @login_required("administrador")
    def papelera_purgar_expirados():
        cantidad = purge_expired_manual(db)
        flash(f"✅ Se purgaron {cantidad} documentos expirados de la papelera.", "success")
        return redirect(url_for("papelera_list"))

    # ------------------------------------------------------------------
    # API: Obtener detalle documento original en papelera (modal preview)
    # ------------------------------------------------------------------
    @app.route("/api/papelera/<id>", methods=["GET"])
    @login_required(["administrador", "soporte"])
    def api_papelera_detalle(id):
        if not ObjectId.is_valid(str(id)):
            return {"error": "ID inválido"}, 400
        d = db[COLLECTION_PAPELERA].find_one({"_id": ObjectId(id)})
        if not d:
            return {"error": "No encontrado en papelera"}, 404
        # Convertir ObjectIds y datetimes a JSON serializable
        return {
            "_id": str(d["_id"]),
            "tipo_documento": d.get("tipo_documento"),
            "collection_origen": d.get("collection_origen"),
            "documento_id_original": str(d.get("documento_id_original")) if d.get("documento_id_original") else None,
            "deleted_at_cl": to_cl(d["deleted_at"]).isoformat() if d.get("deleted_at") else None,
            "expire_at_cl": to_cl(d["expire_at"]).isoformat() if d.get("expire_at") else None,
            "deleted_by_user_name": d.get("deleted_by_user_name"),
            "deleted_by_ip": d.get("deleted_by_ip"),
            "motivo": d.get("motivo"),
            "documento_original": _sanitize_for_json(d.get("documento_original", {})),
        }


# ------------------------------------------------------------------
# Helpers privados
# ------------------------------------------------------------------
def _keep_filters(request) -> dict:
    params = {}
    for k in ["tipo", "search", "page"]:
        v = request.args.get(k) or request.form.get(k)
        if v:
            params[k] = v
    return params


def _build_preview(collection_origen: str, doc: dict) -> str:
    """Pequeño resumen humano de qué contiene el documento."""
    if not doc:
        return "(sin datos)"
    if collection_origen == "piezas":
        partes = [
            f"Cod: {doc.get('codigo', '')}",
            doc.get("empresa") or "",
            doc.get("marco") or "",
            f"T{doc.get('tramo', '')}" if doc.get("tramo") else "",
        ]
        return " | ".join(p for p in partes if p)
    if collection_origen == "produccion":
        partes = [
            f"Cod: {doc.get('codigo_pieza', '')}",
            doc.get("usuario") or "(sin operador)",
            doc.get("modo") or "",
            f"box {doc.get('box')}" if doc.get("box") else "",
        ]
        return " | ".join(p for p in partes if p)
    if collection_origen == "usuarios":
        return f"{doc.get('nombre', '')} ({doc.get('usuario', '')}) - {doc.get('tipo', '')}"
    if collection_origen == "boxes":
        return f"Cod Box: {doc.get('codigo', '')} - {doc.get('descripcion', '')}"
    return f"{len(doc)} campos"


def _sanitize_for_json(obj: any) -> any:
    if isinstance(obj, ObjectId):
        return str(obj)
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, dict):
        return {str(k): _sanitize_for_json(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sanitize_for_json(x) for x in obj]
    return obj
