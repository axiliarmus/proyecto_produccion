from bson import ObjectId

from core.helpers.codigo import build_codigo_lookup_keys, build_codigo_query_values
from core.helpers.date_utils import to_cl


def get_piece_status_sets(db, codigos, collection=None):
    """Obtiene sets de piezas armadas y rematadas para un conjunto de codigos."""
    if collection is None:
        collection = db.produccion
    lookup_values = build_codigo_query_values(codigos)
    if not lookup_values:
        return set(), set()

    set_armado = set()
    set_remate = set()

    for codigo in collection.distinct("codigo_pieza", {"codigo_pieza": {"$in": lookup_values}, "modo": "armador"}):
        set_armado.update(build_codigo_lookup_keys(codigo))

    for codigo in collection.distinct("codigo_pieza", {"codigo_pieza": {"$in": lookup_values}, "modo": "rematador"}):
        set_remate.update(build_codigo_lookup_keys(codigo))

    return set_armado, set_remate


def get_latest_production_map(db, codigos, collection=None):
    """Trae el ultimo registro de produccion por codigo para evitar consultas N+1."""
    if collection is None:
        collection = db.produccion
    lookup_values = build_codigo_query_values(codigos)
    if not lookup_values:
        return {}

    pipeline = [
        {"$match": {"codigo_pieza": {"$in": lookup_values}}},
        {"$sort": {"codigo_pieza": 1, "fecha": -1}},
        {"$group": {
            "_id": "$codigo_pieza",
            "cuerda_interna": {"$first": "$cuerda_interna"},
            "cuerda_externa": {"$first": "$cuerda_externa"},
            "flecha": {"$first": "$flecha"},
            "modo": {"$first": "$modo"},
            "fecha": {"$first": "$fecha"}
        }}
    ]

    latest_map = {}
    for item in collection.aggregate(pipeline):
        for key in build_codigo_lookup_keys(item.get("_id")):
            latest_map[key] = item
    return latest_map


def build_piezas_map(db, codigos, collection=None):
    """Precarga piezas en memoria para evitar find_one repetidos por codigo."""
    if collection is None:
        collection = db.piezas
    lookup_values = build_codigo_query_values(codigos)
    if not lookup_values:
        return {}

    piezas_map = {}
    for pieza in collection.find({"codigo": {"$in": lookup_values}}):
        for key in build_codigo_lookup_keys(pieza.get("codigo")):
            piezas_map[key] = pieza
    return piezas_map


def ensure_mongo_indexes(db):
    """Crea indices no destructivos para mejorar consultas frecuentes."""
    index_specs = [
        (db.config, [("key", 1)], "idx_config_key"),
        (db.usuarios, [("usuario", 1)], "idx_usuarios_usuario"),
        (db.boxes, [("codigo", 1)], "idx_boxes_codigo"),
        (db.piezas, [("codigo", 1)], "idx_piezas_codigo"),
        (db.piezas, [("empresa", 1), ("marco", 1), ("tramo", 1), ("codigo", 1)], "idx_piezas_filtros_codigo"),
        (db.produccion, [("codigo_pieza", 1), ("fecha", -1)], "idx_produccion_codigo_fecha"),
        (db.produccion, [("usuario", 1), ("fecha", -1)], "idx_produccion_usuario_fecha"),
        (db.produccion, [("user_id", 1), ("fecha", -1)], "idx_produccion_userid_fecha"),
        (db.produccion, [("modo", 1), ("codigo_pieza", 1)], "idx_produccion_modo_codigo"),
        (db.produccion, [("modo", 1), ("calidad_status", 1), ("fecha", -1)], "idx_produccion_supervisor"),
        (db.produccion_historica, [("corte_id", 1), ("fecha", -1)], "idx_produccion_hist_corte_fecha"),
        (db.produccion_historica, [("corte_id", 1), ("codigo_pieza", 1), ("fecha", -1)], "idx_produccion_hist_corte_codigo_fecha"),
        (db.produccion_historica, [("corte_id", 1), ("modo", 1), ("codigo_pieza", 1)], "idx_produccion_hist_corte_modo_codigo"),
        (db.piezas_historicas, [("corte_id", 1), ("codigo", 1)], "idx_piezas_hist_corte_codigo"),
        (db.piezas_historicas, [("corte_id", 1), ("empresa", 1), ("marco", 1), ("tramo", 1)], "idx_piezas_hist_filtros"),
        (db.usuarios_historicos, [("corte_id", 1), ("usuario", 1)], "idx_usuarios_hist_corte_usuario"),
        (db.jornadas, [("user_id", 1), ("fecha", -1)], "idx_jornadas_userid_fecha"),
        (db.cortes, [("nombre", 1)], "idx_cortes_nombre"),
        (db.cortes, [("creado_en", -1)], "idx_cortes_creado_en"),
        (db.cortes, [("inicio", -1)], "idx_cortes_inicio"),
        (db.picking, [("codigo", 1)], "idx_picking_codigo"),
        (db.picking, [("fecha", -1)], "idx_picking_fecha"),
        (db.operator_submission_guards, [("expireAt", 1)], "idx_operator_submit_guard_expire"),
    ]

    for collection, keys, name in index_specs:
        try:
            kwargs = {"name": name}
            if collection == db.operator_submission_guards and name == "idx_operator_submit_guard_expire":
                kwargs["expireAfterSeconds"] = 0
            collection.create_index(keys, **kwargs)
        except Exception as exc:
            print(f"[WARN] No se pudo crear el indice {name}: {exc}")


def build_users_map_by_object_ids(db, user_ids):
    """Precarga usuarios por ObjectId serializado para evitar consultas repetidas."""
    object_ids = []
    for user_id in set(user_ids or []):
        if not user_id:
            continue
        try:
            object_ids.append(ObjectId(str(user_id)))
        except Exception:
            continue

    if not object_ids:
        return {}

    return {str(user["_id"]): user for user in db.usuarios.find({"_id": {"$in": object_ids}})}


def get_operator_report_rows(db, produccion):
    """Construye filas y total del informe de operadores usando precarga en bloque."""
    users_map = build_users_map_by_object_ids(db, [p.get("user_id") for p in produccion])
    piezas_map = build_piezas_map(db, [p.get("codigo_pieza") for p in produccion])

    rows = []
    total_general = 0.0

    for prod in produccion:
        user = users_map.get(str(prod.get("user_id")))
        pieza = None
        for key in build_codigo_lookup_keys(prod.get("codigo_pieza")):
            pieza = piezas_map.get(key)
            if pieza:
                break

        modo = prod.get("modo")
        peso = float(prod.get("kilo_pieza", 0) or 0)
        if not peso:
            peso = float((pieza or {}).get("kilo_pieza", 0) or 0)

        tipo_precio = prod.get("tipo_precio") or (pieza or {}).get("tipo_precio", "metro")
        precio_unitario_snapshot = prod.get("precio_unitario")
        valor_unitario = float(precio_unitario_snapshot or 0)

        if precio_unitario_snapshot in (None, "") and pieza and user:
            tipo_precio = prod.get("tipo_precio") or pieza.get("tipo_precio", "metro")
            if modo == "armador":
                valor_unitario = float(user.get("precio_metro_armado", 0) or 0) if tipo_precio == "metro" else float(user.get("precio_avo_armado", 0) or 0)
            elif modo == "rematador":
                valor_unitario = float(user.get("precio_metro_remate", 0) or 0) if tipo_precio == "metro" else float(user.get("precio_avo_remate", 0) or 0)

        total = peso * valor_unitario
        total_general += total

        rows.append({
            "fecha": to_cl(prod.get("fecha")) if prod.get("fecha") else None,
            "codigo": str(prod.get("codigo_pieza") or ""),
            "operador": user.get("nombre", "—") if user else "—",
            "modo": modo,
            "marco": prod.get("marco", "—"),
            "tramo": prod.get("tramo", "—"),
            "cantidad": 1,
            "peso": peso,
            "valor_unitario": valor_unitario,
            "total": total,
            "tipo_precio": tipo_precio
        })

    return rows, total_general


def apply_exact_codigo_filter(filtros, codigo, field_name="codigo"):
    """Aplica filtro exacto tolerante a codigo como entero o string."""
    codigo = (codigo or "").strip()
    if not codigo:
        return filtros

    codigo_values = build_codigo_query_values([codigo])
    if codigo_values:
        filtros[field_name] = {"$in": codigo_values}
    return filtros


def get_estado_piezas_dataset(db, filtros, estado_filter=None):
    """Construye stats y listado del informe estado de piezas reutilizando sets de estado."""
    piezas = list(
        db.piezas.find(
            filtros,
            {
                "codigo": 1,
                "empresa": 1,
                "marco": 1,
                "tramo": 1,
                "cuerda_interna": 1,
                "cuerda_externa": 1,
                "flecha": 1,
                "_id": 0
            }
        ).sort("codigo", 1)
    )

    codigos = [pieza.get("codigo") for pieza in piezas if pieza.get("codigo") not in (None, "")]
    set_armado, set_remate = get_piece_status_sets(db, codigos)

    stats = {
        "total": len(piezas),
        "sin_produccion": 0,
        "armado": 0,
        "rematado": 0
    }
    listado = []

    for pieza in piezas:
        codigo = pieza.get("codigo")
        codigo_keys = build_codigo_lookup_keys(codigo)
        if codigo_keys & set_remate:
            estado = "Rematado"
            stats["rematado"] += 1
        elif codigo_keys & set_armado:
            estado = "Armado"
            stats["armado"] += 1
        else:
            estado = "Sin producción"
            stats["sin_produccion"] += 1

        if estado_filter and estado_filter != "todos" and estado != estado_filter:
            continue

        listado.append({
            "codigo": codigo,
            "cliente": pieza.get("empresa"),
            "marco": pieza.get("marco"),
            "tramo": pieza.get("tramo"),
            "cuerda_interna": pieza.get("cuerda_interna", ""),
            "cuerda_externa": pieza.get("cuerda_externa", ""),
            "flecha": pieza.get("flecha", ""),
            "estado": estado
        })

    return stats, listado


def get_production_status_map(db, collection=None, match_filter=None):
    """Resume producción por código con flags de armado/remate y datos base para agrupación."""
    if collection is None:
        collection = db.produccion
    match_filter = match_filter or {}

    pipeline = [
        {"$match": match_filter},
        {"$sort": {"fecha": -1}},
        {"$group": {
            "_id": "$codigo_pieza",
            "empresa": {"$first": "$empresa"},
            "marco": {"$first": "$marco"},
            "tramo": {"$first": "$tramo"},
            "armadas": {"$max": {"$cond": [{"$eq": ["$modo", "armador"]}, 1, 0]}},
            "rematadas": {"$max": {"$cond": [{"$eq": ["$modo", "rematador"]}, 1, 0]}}
        }}
    ]

    status_map = {}
    for item in collection.aggregate(pipeline):
        normalized = build_codigo_lookup_keys(item.get("_id"))
        payload = {
            "empresa": item.get("empresa") or "Sin Cliente",
            "marco": item.get("marco") or "Sin Marco",
            "tramo": item.get("tramo") or "Sin Tramo",
            "armadas": int(item.get("armadas") or 0),
            "rematadas": int(item.get("rematadas") or 0)
        }
        for key in normalized:
            status_map[key] = payload
    return status_map


def build_tarjetas_grupos(piezas, production_status_map, include_orphans=False):
    """Agrupa piezas por cliente/marco/tramo para las tarjetas de resumen."""
    grupos_map = {}
    existing_keys = set()

    def ensure_bucket(cliente, marco, tramo):
        cliente = cliente or "Sin Cliente"
        marco = marco or "Sin Marco"
        tramo = tramo or "Sin Tramo"
        key_marco = (cliente, marco)
        grupos_map.setdefault(cliente, {})
        grupos_map[cliente].setdefault(key_marco, {})
        grupos_map[cliente][key_marco].setdefault(tramo, {"total": 0, "armadas": 0, "rematadas": 0})
        return grupos_map[cliente][key_marco][tramo]

    for pieza in piezas:
        bucket = ensure_bucket(pieza.get("empresa"), pieza.get("marco"), pieza.get("tramo"))
        bucket["total"] += 1

        status_info = None
        normalized_keys = build_codigo_lookup_keys(pieza.get("codigo"))
        for key in normalized_keys:
            existing_keys.add(key)
            status_info = production_status_map.get(key)
            if status_info:
                break

        if status_info:
            bucket["armadas"] += status_info.get("armadas", 0)
            bucket["rematadas"] += status_info.get("rematadas", 0)

    if include_orphans:
        for codigo_key, status_info in production_status_map.items():
            if codigo_key in existing_keys:
                continue
            bucket = ensure_bucket(status_info.get("empresa"), status_info.get("marco"), status_info.get("tramo"))
            bucket["total"] += 1
            bucket["armadas"] += status_info.get("armadas", 0)
            bucket["rematadas"] += status_info.get("rematadas", 0)

    grupos = []
    for cliente, marcos in grupos_map.items():
        grupo = {"cliente": cliente, "marcos": []}
        for (_, marco), tramos in marcos.items():
            grupo["marcos"].append({
                "marco": marco,
                "tramos": [{
                    "tramo": tramo,
                    "total": values["total"],
                    "armadas": values["armadas"],
                    "rematadas": values["rematadas"],
                    "en_armado": max(values["armadas"] - values["rematadas"], 0),
                    "pendientes": values["total"] - values["rematadas"],
                } for tramo, values in sorted(tramos.items(), key=lambda item: str(item[0]))]
            })
        grupo["marcos"] = sorted(grupo["marcos"], key=lambda item: str(item["marco"]))
        grupos.append(grupo)

    return sorted(grupos, key=lambda item: str(item["cliente"]))
