import os
import sys
import io
from pathlib import Path

if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

OUTPUT_FILE = Path(__file__).resolve().parent / "RESULTADO_CODIGOS_BORRADOS.txt"

from dotenv import load_dotenv
from pymongo import MongoClient
from bson.objectid import ObjectId
from datetime import datetime

project_root = Path(__file__).resolve().parent
load_dotenv(project_root / ".env")

mongo_uri = os.getenv("MONGO_URI")
if not mongo_uri:
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("ERROR: MONGO_URI no definida en .env\n")
    print("ERROR: MONGO_URI no definida")
    sys.exit(1)

salida = []
salida.append("=" * 90)
salida.append("RESULTADO - CODIGOS BORRADOS DETECTADOS (VERSION OPTIMIZADA VPS)")
salida.append("Generado: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
salida.append("BD: " + mongo_uri[:60] + ("..." if len(mongo_uri) > 60 else ""))
salida.append("=" * 90)

try:
    client = MongoClient(
        mongo_uri,
        serverSelectionTimeoutMS=10000,
        socketTimeoutMS=30000,
        connectTimeoutMS=10000,
        maxPoolSize=4,
    )
    client.admin.command('ping')
    salida.append("\n[OK] Conexion exitosa a MongoDB")
    db = client["miBase"]
except Exception as e:
    salida.append(f"\n[ERROR] Conexion fallida: {e}")
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(salida))
    print(f"ERROR conexion: {e}")
    sys.exit(1)

salida.append("\n" + "-" * 90)
salida.append("CANTIDAD DE DOCUMENTOS POR COLECCION")
salida.append("-" * 90)
for col in ["piezas", "produccion", "produccion_historica", "usuarios"]:
    try:
        n = db[col].estimated_document_count()
        salida.append(f"  {col}: {n:,}")
    except Exception as e:
        salida.append(f"  {col}: ERROR - {e}")

salida.append("\n" + "=" * 90)
salida.append("ANALISIS 1: CODIGOS EN PRODUCCION ACTIVA PERO FALTANTES EN PIEZAS")
salida.append("=" * 90)

codigos_en_piezas = set()
for d in db.piezas.find({}, {"codigo": 1}, batch_size=5000):
    if d.get("codigo"):
        codigos_en_piezas.add(d["codigo"])

salida.append(f"\n[INFO] Codigos en piezas (activas): {len(codigos_en_piezas):,}")

try:
    pipeline = [
        {"$match": {"codigo_pieza": {"$exists": True, "$ne": None}}},
        {"$sort": {"fecha": -1}},
        {"$group": {
            "_id": "$codigo_pieza",
            "fecha": {"$first": "$fecha"},
            "user_id": {"$first": "$user_id"},
            "usuario": {"$first": "$usuario"},
            "modo": {"$first": "$modo"},
            "box": {"$first": "$box"},
            "cuerda_interna": {"$first": "$cuerda_interna"},
            "cuerda_externa": {"$first": "$cuerda_externa"},
            "flecha": {"$first": "$flecha"},
        }},
        {"$sort": {"fecha": -1}},
        {"$limit": 5000},
    ]
    todos_prod = list(db.produccion.aggregate(pipeline, allowDiskUse=True, maxTimeMS=60000))
    salida.append(f"[INFO] Registros agrupados de produccion activa: {len(todos_prod):,}")
except Exception as e:
    todos_prod = []
    salida.append(f"[ERROR] Fallo agregacion produccion: {e}")

candidatos = []
cods_en_prod = set()
for row in todos_prod:
    cod = row["_id"]
    cods_en_prod.add(cod)
    if cod in codigos_en_piezas:
        continue
    candidatos.append({
        "codigo": cod,
        "fecha": row.get("fecha"),
        "user_id": row.get("user_id"),
        "usuario_reg": row.get("usuario") or "N/A",
        "modo": row.get("modo") or "N/A",
        "box": row.get("box") or "N/A",
        "ci": row.get("cuerda_interna"),
        "ce": row.get("cuerda_externa"),
        "flecha": row.get("flecha"),
        "coleccion": "produccion_activa",
    })

user_ids_pendientes = [ObjectId(c["user_id"]) for c in candidatos if c.get("user_id")]
usuario_map = {}
if user_ids_pendientes:
    for u in db.usuarios.find({"_id": {"$in": user_ids_pendientes}}, {"_id": 1, "rol": 1, "email": 1, "nombre": 1}):
        usuario_map[str(u["_id"])] = u

for c in candidatos:
    uid = str(c["user_id"]) if c.get("user_id") else None
    udata = usuario_map.get(uid)
    if udata:
        c["usuario_rol"] = udata.get("rol", "N/A")
        c["usuario_email"] = udata.get("email", "N/A")
        if c["usuario_reg"] in (None, "N/A", ""):
            c["usuario_reg"] = udata.get("nombre", "N/A")
    else:
        c["usuario_rol"] = "N/A"
        c["usuario_email"] = "N/A"

salida.append(f"[RESULTADO] CODIGOS BORRADOS EN PRODUCCION ACTIVA: {len(candidatos)}")

if candidatos:
    salida.append("\n--- LISTADO (MAS RECIENTES PRIMERO, TOP 100) ---")
    for i, c in enumerate(candidatos[:100], 1):
        fstr = c["fecha"].strftime("%Y-%m-%d %H:%M:%S") if c["fecha"] else "N/A"
        salida.append(f"\n[{i}] CODIGO: {c['codigo']}")
        salida.append(f"    FECHA ULTIMO REGISTRO: {fstr}")
        salida.append(f"    OPERADOR: {c['usuario_reg']}")
        salida.append(f"    ROL: {c['usuario_rol']}")
        if c["usuario_email"] and c["usuario_email"] != "N/A":
            salida.append(f"    EMAIL: {c['usuario_email']}")
        salida.append(f"    MODO: {c['modo']} | BOX: {c['box']}")
        if c["ci"] is not None or c["ce"] is not None:
            salida.append(f"    MEDIDAS - CI={c['ci']} | CE={c['ce']} | Flecha={c['flecha']}")

salida.append("\n" + "=" * 90)
salida.append("ANALISIS 2: CODIGOS SOLO EN PRODUCCION HISTORICA (NO EN PIEZAS)")
salida.append("=" * 90)

historicos = []
cods_ya = {c["codigo"] for c in candidatos}

try:
    pipeline_hist = [
        {"$match": {"codigo_pieza": {"$exists": True, "$ne": None}}},
        {"$sort": {"fecha": -1}},
        {"$group": {
            "_id": "$codigo_pieza",
            "fecha": {"$first": "$fecha"},
            "user_id": {"$first": "$user_id"},
            "usuario": {"$first": "$usuario"},
            "modo": {"$first": "$modo"},
            "box": {"$first": "$box"},
            "cuerda_interna": {"$first": "$cuerda_interna"},
            "cuerda_externa": {"$first": "$cuerda_externa"},
            "flecha": {"$first": "$flecha"},
        }},
        {"$sort": {"fecha": -1}},
        {"$limit": 5000},
    ]
    todos_hist = list(db.produccion_historica.aggregate(pipeline_hist, allowDiskUse=True, maxTimeMS=60000))
    salida.append(f"[INFO] Registros agrupados de produccion historica: {len(todos_hist):,}")
except Exception as e:
    todos_hist = []
    salida.append(f"[WARN] Fallo agregacion historica: {e}")

user_ids_h = []
for row in todos_hist:
    cod = row["_id"]
    if cod in codigos_en_piezas or cod in cods_ya or cod in cods_en_prod:
        continue
    item = {
        "codigo": cod,
        "fecha": row.get("fecha"),
        "user_id": row.get("user_id"),
        "usuario_reg": row.get("usuario") or "N/A",
        "modo": row.get("modo") or "N/A",
        "box": row.get("box") or "N/A",
        "ci": row.get("cuerda_interna"),
        "ce": row.get("cuerda_externa"),
        "flecha": row.get("flecha"),
        "coleccion": "produccion_historica",
    }
    historicos.append(item)
    if item.get("user_id"):
        user_ids_h.append(ObjectId(item["user_id"]))

usuario_map_h = {}
if user_ids_h:
    for u in db.usuarios.find({"_id": {"$in": list(set(user_ids_h))}}, {"_id": 1, "rol": 1, "email": 1, "nombre": 1}):
        usuario_map_h[str(u["_id"])] = u

for c in historicos:
    uid = str(c["user_id"]) if c.get("user_id") else None
    udata = usuario_map_h.get(uid)
    if udata:
        c["usuario_rol"] = udata.get("rol", "N/A")
        c["usuario_email"] = udata.get("email", "N/A")
        if c["usuario_reg"] in (None, "N/A", ""):
            c["usuario_reg"] = udata.get("nombre", "N/A")
    else:
        c["usuario_rol"] = "N/A"
        c["usuario_email"] = "N/A"

historicos.sort(key=lambda x: x["fecha"] or datetime.min, reverse=True)
salida.append(f"[RESULTADO] CODIGOS ADICIONALES EN HISTORICOS: {len(historicos)}")

if historicos:
    salida.append("\n--- TOP 80 HISTORICOS MAS RECIENTES ---")
    for i, c in enumerate(historicos[:80], 1):
        fstr = c["fecha"].strftime("%Y-%m-%d %H:%M:%S") if c["fecha"] else "N/A"
        salida.append(f"\n[{i}] CODIGO: {c['codigo']}")
        salida.append(f"    FECHA: {fstr}")
        salida.append(f"    OPERADOR: {c['usuario_reg']} | ROL: {c['usuario_rol']}")
        salida.append(f"    MODO: {c['modo']} | BOX: {c['box']}")
        if c["ci"] is not None or c["ce"] is not None:
            salida.append(f"    MEDIDAS - CI={c['ci']} | CE={c['ce']} | Flecha={c['flecha']}")

salida.append("\n" + "=" * 90)
salida.append("RESUMEN FINAL")
salida.append("=" * 90)
total = len(candidatos) + len(historicos)
salida.append(f"TOTAL CODIGOS BORRADOS DETECTADOS (RECUPERABLES): {total}")
salida.append(f"  - Produccion activa (recientes): {len(candidatos)}")
salida.append(f"  - Produccion historica: {len(historicos)}")

if total == 0:
    salida.append("\n[ATENCION] NO SE DETECTARON CODIGOS BORRADOS.")
    salida.append("Posibles causas:")
    salida.append("  1. El codigo fue borrado ANTES de ser registrado por algun operador.")
    salida.append("  2. Tanto el codigo en piezas COMO TODOS sus registros de produccion fueron eliminados.")
    salida.append("  3. Revisa MONGO_URI en .env - asegurate que apunte a la BD REAL del VPS.")
else:
    salida.append("\n[PASO FINAL] - Identifica el codigo en el listado y dime su nombre.")
    salida.append("Yo genero el comando MongoDB para reinsertarlo AUTOMATICAMENTE en db.piezas,")
    salida.append("con todos sus datos: codigo, medidas, estado, operador, etc.")

with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    f.write("\n".join(salida))

client.close()
print("=" * 70)
print("ANALISIS COMPLETADO. Archivo generado:")
print(f"  {OUTPUT_FILE}")
print("=" * 70)
print(f"\nResumen rapido:")
print(f"  - Codigos recientes (produccion activa): {len(candidatos)}")
print(f"  - Codigos historicos: {len(historicos)}")
print(f"  - TOTAL RECUPERABLES: {total}")
print("\nPara VER el resultado ejecuta:")
print("  cat RESULTADO_CODIGOS_BORRADOS.txt | head -n 100")
print("\nPara verlo COMPLETO usa 'less':")
print("  less RESULTADO_CODIGOS_BORRADOS.txt")
print("  (presiona ESPACIO para avanzar, Q para salir)")
