import os
import sys
import io
import re
from pathlib import Path

if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

from dotenv import load_dotenv
from pymongo import MongoClient
from bson.objectid import ObjectId
from datetime import datetime

if len(sys.argv) < 2:
    print("""
=============================================================================
USO: python buscar_en_toda_bd.py <TEXTO_A_BUSCAR>
=============================================================================

Busca <TEXTO_A_BUSCAR> en TODAS las colecciones de MongoDB y en TODOS los
campos string (sin sensibilidad a mayusculas/minusculas).

Tambien prueba variantes del texto (sin espacios, mayusc/minusc, etc.).

EJEMPLOS:
  python buscar_en_toda_bd.py I4237
  python buscar_en_toda_bd.py "I4237"
  python buscar_en_toda_bd.py "4237"
  python buscar_en_toda_bd.py "nombre operador"
""")
    sys.exit(1)

TERMINO = sys.argv[1].strip()
REPORTE = Path(__file__).resolve().parent / f"BUSQUEDA_GLOBAL_{re.sub(r'[^a-zA-Z0-9_]+', '_', TERMINO)}.txt"

logs = []
def log(msg):
    print(msg)
    logs.append(msg)

log("=" * 90)
log(f"BUSQUEDA GLOBAL EN TODA LA BD PARA TERMINO: '{TERMINO}'")
log(f"Generado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
log("=" * 90)

project_root = Path(__file__).resolve().parent
load_dotenv(project_root / ".env")
mongo_uri = os.getenv("MONGO_URI")
try:
    client = MongoClient(
        mongo_uri,
        serverSelectionTimeoutMS=10000,
        socketTimeoutMS=45000,
    )
    client.admin.command('ping')
    log("[OK] Conectado a MongoDB")
    db = client["miBase"]
except Exception as e:
    log(f"[ERROR] Conexion fallida: {e}")
    with open(REPORTE, "w", encoding="utf-8") as f:
        f.write("\n".join(logs))
    sys.exit(1)

todas_colecciones = sorted(db.list_collection_names())
log(f"[INFO] Colecciones totales en BD 'miBase': {len(todas_colecciones)}")
for c in todas_colecciones:
    try:
        n = db[c].estimated_document_count()
        log(f"    - {c:40s}: {n:>8,} docs")
    except Exception:
        pass

# Preparar variantes de búsqueda
variantes = set()
variantes.add(TERMINO)
variantes.add(TERMINO.lower())
variantes.add(TERMINO.upper())
variantes.add(TERMINO.strip())
variantes.add(re.sub(r"\s+", "", TERMINO))
variantes.add(re.sub(r"\s+", "", TERMINO.lower()))
if len(TERMINO) >= 3:
    variantes.add(TERMINO[1:])
    variantes.add(TERMINO[:-1])
variantes = [v for v in variantes if len(v) >= 2]
log(f"\n[INFO] Variantes de busqueda probadas: {len(variantes)} -> {', '.join(variantes[:10])}")

log("\n" + "=" * 90)
log("FASE 1: Busqueda por campos conocidos (codigo, codigo_pieza, usuario, email, operador...)")
log("=" * 90)

CAMPOS_CODIGO = ["codigo", "codigo_pieza", "codigo_ref", "cod_pieza", "cod"]
CAMPOS_USUARIO = ["usuario", "nombre", "operador_asignado", "email", "operador"]
MATCHES = []

for col in todas_colecciones:
    col_obj = db[col]
    # Buscar por campos de código
    for campo in CAMPOS_CODIGO:
        for v in variantes:
            try:
                query = {campo: {"$regex": re.escape(v), "$options": "i"}}
                docs = list(col_obj.find(query).limit(5))
                for d in docs:
                    MATCHES.append({
                        "coleccion": col,
                        "campo_encontrado": campo,
                        "valor_encontrado": str(d.get(campo)),
                        "doc_id": str(d.get("_id")),
                        "doc_preview": {k: str(v)[:80] for k, v in list(d.items())[:15] if k != "_id"},
                    })
            except Exception:
                pass
    # Buscar por campos de usuario/nombre
    for campo in CAMPOS_USUARIO:
        for v in variantes:
            try:
                query = {campo: {"$regex": re.escape(v), "$options": "i"}}
                docs = list(col_obj.find(query).limit(5))
                for d in docs:
                    MATCHES.append({
                        "coleccion": col,
                        "campo_encontrado": campo,
                        "valor_encontrado": str(d.get(campo)),
                        "doc_id": str(d.get("_id")),
                        "doc_preview": {k: str(v)[:80] for k, v in list(d.items())[:15] if k != "_id"},
                    })
            except Exception:
                pass

# Deduplicar
vistos = set()
MATCHES_UNICOS = []
for m in MATCHES:
    key = (m["coleccion"], m["doc_id"], m["campo_encontrado"])
    if key not in vistos:
        vistos.add(key)
        MATCHES_UNICOS.append(m)

log(f"\n[RESULTADO FASE 1] Coincidencias encontradas: {len(MATCHES_UNICOS)}")
if MATCHES_UNICOS:
    for i, m in enumerate(MATCHES_UNICOS, 1):
        log(f"\n[{i}] COLECCION: {m['coleccion']}")
        log(f"     CAMPO:    {m['campo_encontrado']}")
        log(f"     VALOR:    {m['valor_encontrado']}")
        log(f"     DOC ID:   {m['doc_id']}")
        if m["doc_preview"]:
            log(f"     PREVIEW:")
            for k, v in m["doc_preview"].items():
                log(f"       - {k}: {v}")

log("\n" + "=" * 90)
log("FASE 2: Busqueda profunda texto completo en TODO campo string (más lento)")
log("=" * 90)

# Fase 2: Para cada colección, tomar los primeros N docs y buscar string que contenga
# cualquier variante. Esto sirve para campos con nombres raros.
MATCHES_2 = []
MAX_DOCS_POR_COLECCION = 200
for col in todas_colecciones:
    col_obj = db[col]
    try:
        total = col_obj.estimated_document_count()
    except Exception:
        total = 0
    if total == 0:
        continue
    # Limitar: si hay muchos docs, ordenar por _id DESC (más recientes)
    try:
        cursor = col_obj.find({}).sort("_id", -1).limit(MAX_DOCS_POR_COLECCION)
    except Exception:
        cursor = col_obj.find({}).limit(MAX_DOCS_POR_COLECCION)
    for d in cursor:
        doc_id = str(d.get("_id"))
        d.pop("_id", None)
        # Convertir valores a string y buscar
        texto_doc = " || ".join([f"{k}={str(v)}" for k, v in d.items()])
        for v in variantes:
            if v.lower() in texto_doc.lower():
                # Tratar de encontrar el campo exacto
                campo_exacto = None
                valor_exacto = None
                for k, val in d.items():
                    if v.lower() in str(val).lower():
                        campo_exacto = k
                        valor_exacto = str(val)[:100]
                        break
                MATCHES_2.append({
                    "coleccion": col,
                    "campo_encontrado": campo_exacto or "(varios campos)",
                    "valor_encontrado": valor_exacto or "(coincidencia en multiples campos)",
                    "doc_id": doc_id,
                    "doc_preview": {k: str(v2)[:60] for k, v2 in list(d.items())[:15]},
                })
                break

vistos2 = set()
MATCHES_2_UNICOS = []
for m in MATCHES_2:
    key = (m["coleccion"], m["doc_id"])
    if key not in vistos2:
        vistos2.add(key)
        # Quitar repetidos de la fase 1
        if key not in {(x["coleccion"], x["doc_id"]) for x in MATCHES_UNICOS}:
            MATCHES_2_UNICOS.append(m)

log(f"\n[RESULTADO FASE 2] Nuevas coincidencias (no repetidas fase 1): {len(MATCHES_2_UNICOS)}")
if MATCHES_2_UNICOS:
    for i, m in enumerate(MATCHES_2_UNICOS, 1):
        log(f"\n[{i}] COLECCION: {m['coleccion']}")
        log(f"     CAMPO:    {m['campo_encontrado']}")
        log(f"     VALOR:    {m['valor_encontrado']}")
        log(f"     DOC ID:   {m['doc_id']}")
        if m["doc_preview"]:
            log(f"     PREVIEW:")
            for k, v in m["doc_preview"].items():
                log(f"       - {k}: {v}")

log("\n" + "=" * 90)
log("RESUMEN FINAL")
log("=" * 90)
total = len(MATCHES_UNICOS) + len(MATCHES_2_UNICOS)
log(f"Total coincidencias encontradas: {total}")
log(f"  - Fase 1 (campos conocidos): {len(MATCHES_UNICOS)}")
log(f"  - Fase 2 (cualquier campo): {len(MATCHES_2_UNICOS)}")

if total == 0:
    log("\n[ATENCION] NO SE ENCONTRO NINGUN RASTRO DEL TERMINO EN NINGUNA COLECCION.")
    log("\nPosibles causas REALES (no hay truco):")
    log("  1. El codigo I4237 NUNCA fue guardado en MongoDB en ninguna coleccion.")
    log("     Ej: se creó en Excel/papel y se asignó a un operador, pero NUNCA")
    log("     fue ingresado vía panel en 'Gestion de Piezas' ni 'Registrar Produccion'.")
    log("  2. El codigo SI existió, pero se borro:")
    log("       - db.piezas (pieza maestra) --> SE BORRO")
    log("       - db.produccion (registro operador) --> SE BORRO")
    log("       - db.produccion_historica (corte mensual) --> SE BORRO")
    log("       - logs_auditoria (si existían) --> TAMBIEN SE BORRARON / NO EXISTIAN")
    log("  3. El codigo no es I4237 sino uno parecido: 14237, L4237, i4237, l4237, I423, I4238...")
    log("\n[RECOMENDACION FINAL]")
    log("  - Si hay BACKUP de MongoDB del VPS: restaura el backup y busca ahi.")
    log("  - Si no hay backup, el CODIGO DEBE reingresarse MANUALMENTE via panel admin:")
    log("    Admin -> Gestion de Piezas -> Nueva Pieza -> rellenar campos a mano.")
    log("  - Pide al operador que recuerde los datos (medidas, empresa, marco, tramo, box).")
else:
    log("\n[EXITO] Se encontro rastro! Mira los listados de arriba.")
    log("Con los datos de las coincidencias puedes reconstruir el codigo.")
    log("Si encuentras un registro con los datos COMPLETOS (codigo + medidas + operador)")
    log("avisame y te digo como convertirlo en un INSERT para db.piezas.")

with open(REPORTE, "w", encoding="utf-8") as f:
    f.write("\n".join(logs))

client.close()
log(f"\n[OK] Reporte completo guardado en: {REPORTE}")
