"""
Sistema de Papelera de Reciclaje con retención de 7 días.
- En lugar de borrar documentos físicamente (hard delete), se mueven a la colección `papelera`.
- Índice TTL en `expire_at` purga automáticamente después de 7 días.
- Funciones: soft_delete_one, soft_delete_many, restore_from_bin, init_recycle_bin_indexes.
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from bson.objectid import ObjectId
from pymongo.collection import Collection


DAYS_RETAIN = 7
COLLECTION_PAPELERA = "papelera"

NOMBRE_AMIGABLE = {
    "piezas": "Pieza Maestra",
    "produccion": "Registro de Producción",
    "usuarios": "Usuario",
    "boxes": "Box / Caja",
    "cortes": "Corte Mensual",
}


def _doc_type_name(collection_origen: str) -> str:
    return NOMBRE_AMIGABLE.get(collection_origen, collection_origen.capitalize())


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _build_papelera_doc(
    collection_origen: str,
    doc_original: Dict[str, Any],
    deleted_by_user_id: Optional[str] = None,
    deleted_by_user_name: Optional[str] = None,
    deleted_by_ip: Optional[str] = None,
    motivo: str = "eliminación manual",
) -> Dict[str, Any]:
    """Construye el documento que se guardará en la colección `papelera`."""
    doc_id_original = doc_original.get("_id")
    doc_copia = dict(doc_original)
    # Normalizamos _id a string si es ObjectId para prevenir problemas
    deleted_at = _now_utc()
    expire_at = deleted_at + timedelta(days=DAYS_RETAIN)

    return {
        "tipo_documento": _doc_type_name(collection_origen),
        "collection_origen": collection_origen,
        "documento_id_original": doc_id_original,
        "documento_original": doc_copia,
        "deleted_at": deleted_at,
        "expire_at": expire_at,
        "deleted_by_user_id": (
            ObjectId(deleted_by_user_id)
            if deleted_by_user_id and ObjectId.is_valid(str(deleted_by_user_id))
            else deleted_by_user_id
        ),
        "deleted_by_user_name": deleted_by_user_name,
        "deleted_by_ip": deleted_by_ip,
        "motivo": motivo,
        "days_retain": DAYS_RETAIN,
    }


def init_recycle_bin_indexes(db) -> None:
    """Crea índices necesarios para la colección papelera. Llamar al arrancar la app."""
    col: Collection = db[COLLECTION_PAPELERA]

    existing_indexes = {idx["name"] for idx in col.list_indexes()}

    # Índice TTL: MongoDB purgará automáticamente los documentos pasados expire_at
    if "idx_papelera_expire_ttl" not in existing_indexes:
        try:
            col.create_index(
                [("expire_at", 1)],
                expireAfterSeconds=0,
                name="idx_papelera_expire_ttl",
                background=True,
            )
        except Exception as exc:
            print(f"[WARN] No se pudo crear índice TTL papelera: {exc}")

    # Índice para buscar rápido por tipo/colección/usuario que borró
    secondary = [
        (("collection_origen", 1), "idx_papelera_collection"),
        (("deleted_by_user_id", 1), "idx_papelera_user"),
        (("deleted_at", -1), "idx_papelera_deleted_at"),
    ]
    for key_spec, name in secondary:
        if name not in existing_indexes:
            try:
                col.create_index([key_spec], name=name, background=True)
            except Exception:
                pass


def soft_delete_one(
    db,
    collection_origen: str,
    filtro_doc: Dict[str, Any],
    deleted_by_user_id: Optional[str] = None,
    deleted_by_user_name: Optional[str] = None,
    deleted_by_ip: Optional[str] = None,
    motivo: str = "eliminación manual",
) -> Tuple[bool, str]:
    """
    Mueve UN documento de la colección origen a la papelera.
    Returns: (exito, mensaje)
    """
    col_origen: Collection = db[collection_origen]
    col_papelera: Collection = db[COLLECTION_PAPELERA]

    doc = col_origen.find_one(filtro_doc)
    if not doc:
        return False, "Documento no encontrado en la colección origen."

    papelera_doc = _build_papelera_doc(
        collection_origen=collection_origen,
        doc_original=doc,
        deleted_by_user_id=deleted_by_user_id,
        deleted_by_user_name=deleted_by_user_name,
        deleted_by_ip=deleted_by_ip,
        motivo=motivo,
    )

    insert_result = col_papelera.insert_one(papelera_doc)
    if not insert_result.inserted_id:
        return False, "No se pudo guardar copia en papelera."

    delete_result = col_origen.delete_one(filtro_doc)
    if delete_result.deleted_count != 1:
        # Rollback: quitamos de la papelera porque no se eliminó de origen
        col_papelera.delete_one({"_id": insert_result.inserted_id})
        return False, "Se guardó en papelera pero no se eliminó del origen (rollback)."

    tipo = papelera_doc["tipo_documento"]
    return True, f"✅ {tipo} movido a papelera. Eliminación permanente automática en {DAYS_RETAIN} días."


def soft_delete_many(
    db,
    collection_origen: str,
    filtro_docs: Dict[str, Any],
    deleted_by_user_id: Optional[str] = None,
    deleted_by_user_name: Optional[str] = None,
    deleted_by_ip: Optional[str] = None,
    motivo: str = "eliminación masiva",
) -> Tuple[int, str]:
    """
    Mueve MULTIPLES documentos de la colección origen a la papelera.
    Returns: (cantidad_eliminados, mensaje)
    """
    col_origen: Collection = db[collection_origen]
    col_papelera: Collection = db[COLLECTION_PAPELERA]

    docs = list(col_origen.find(filtro_docs))
    if not docs:
        return 0, "No se encontraron documentos coincidentes."

    papelera_bulk: List[Dict[str, Any]] = []
    for doc in docs:
        papelera_bulk.append(
            _build_papelera_doc(
                collection_origen=collection_origen,
                doc_original=doc,
                deleted_by_user_id=deleted_by_user_id,
                deleted_by_user_name=deleted_by_user_name,
                deleted_by_ip=deleted_by_ip,
                motivo=motivo,
            )
        )

    insert_result = col_papelera.insert_many(papelera_bulk, ordered=False)
    if not insert_result.inserted_ids:
        return 0, "No se pudo guardar copia en papelera."

    delete_result = col_origen.delete_many(filtro_docs)
    if delete_result.deleted_count != len(docs):
        return (
            delete_result.deleted_count,
            f"ADVERTENCIA: Se movieron {len(insert_result.inserted_ids)} a papelera pero se eliminaron {delete_result.deleted_count} del origen.",
        )

    tipo = _doc_type_name(collection_origen)
    return delete_result.deleted_count, f"✅ {delete_result.deleted_count} {tipo}(s) movidos a papelera. Permanencia {DAYS_RETAIN} días."


def restore_from_bin(db, papelera_id: str) -> Tuple[bool, str]:
    """
    Restaura un documento desde la papelera de vuelta a su colección original.
    """
    col_papelera: Collection = db[COLLECTION_PAPELERA]

    if not ObjectId.is_valid(str(papelera_id)):
        return False, "ID de papelera inválido."

    bin_doc = col_papelera.find_one({"_id": ObjectId(papelera_id)})
    if not bin_doc:
        return False, "Documento no encontrado en papelera (quizás ya expiró)."

    collection_origen = bin_doc.get("collection_origen")
    doc_original = bin_doc.get("documento_original", {})
    doc_id_original = bin_doc.get("documento_id_original")

    if not collection_origen or not doc_original:
        return False, "Documento en papelera corrupto (falta metadata)."

    col_origen: Collection = db[collection_origen]

    # Si el ID original ya existe de vuelta en origen, no pisamos, pero informamos
    if doc_id_original and col_origen.find_one({"_id": doc_id_original}):
        return False, f"El ID original ya existe nuevamente en {collection_origen}."

    insert_result = col_origen.insert_one(doc_original)
    if not insert_result.inserted_id:
        return False, "No se pudo restaurar al origen."

    col_papelera.delete_one({"_id": ObjectId(papelera_id)})

    tipo = bin_doc.get("tipo_documento") or collection_origen
    return True, f"✅ {tipo} restaurado exitosamente desde papelera."


def purge_expired_manual(db) -> int:
    """
    Purga manualmente documentos pasados expire_at (por si TTL index no ha corrido todavía).
    Retorna cantidad de documentos purgados.
    """
    col_papelera: Collection = db[COLLECTION_PAPELERA]
    result = col_papelera.delete_many({"expire_at": {"$lte": _now_utc()}})
    return result.deleted_count or 0
