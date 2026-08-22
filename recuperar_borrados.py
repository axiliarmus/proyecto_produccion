import os
import sys
import io
from pathlib import Path

if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

OUTPUT_FILE = Path(__file__).resolve().parent / "RESULTADO_CODIGOS_BORRADOS.txt"

try:
    from dotenv import load_dotenv
except ImportError:
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("ERROR: Instala dotenv primero: pip install python-dotenv pymongo\n")
    print(f"ERROR: dotenv no instalado. Resultado escrito en: {OUTPUT_FILE}")
    sys.exit(1)

from pymongo import MongoClient
from bson.objectid import ObjectId
from datetime import datetime

project_root = Path(__file__).resolve().parent
load_dotenv(project_root / ".env")

mongo_uri = os.getenv("MONGO_URI")
if not mongo_uri:
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("ERROR: MONGO_URI no definida en .env\n")
    sys.exit(1)

salida = []
salida.append("=" * 90)
salida.append("RESULTADO AUTOMATICO - CODIGOS DE PIEZAS BORRADOS DETECTADOS")
salida.append("Generado: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
salida.append("BD conectada: " + mongo_uri)
salida.append("=" * 90)

try:
    client = MongoClient(mongo_uri, serverSelectionTimeoutMS=8000)
    client.admin.command('ping')
    salida.append("\n[OK] Conexion exitosa a MongoDB")
    db = client["miBase"]
except Exception as e:
    salida.append(f"\n[ERROR] No se pudo conectar a MongoDB: {e}")
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(salida))
    print(f"ERROR de conexion. Ver detalle en: {OUTPUT_FILE}")
    sys.exit(1)

salida.append("\n" + "-" * 90)
salida.append("CANTIDAD DE DOCUMENTOS POR COLECCION")
salida.append("-" * 90)
colecciones_info = {}
for col in ["piezas", "produccion", "produccion_historica", "usuarios"]:
    try:
        n = db[col].estimated_document_count()
        colecciones_info[col] = n
        salida.append(f"  {col}: {n}")
    except Exception as e:
        salida.append(f"  {col}: ERROR - {e}")

salida.append("\n" + "=" * 90)
salida.append("ANALISIS 1: CODIGOS EN PRODUCCION PERO FALTANTES EN PIEZAS (BORRADOS RECIENTES)")
salida.append("=" * 90)

codigos_en_piezas = set()
for d in db.piezas.find({}, {"codigo": 1}):
    if d.get("codigo"):
        codigos_en_piezas.add(d["codigo"])

salida.append(f"\nTotal codigos en piezas (activas): {len(codigos_en_piezas)}")

candidatos = []
try:
    cods_produccion = db.produccion.distinct("codigo_pieza")
except Exception as e:
    cods_produccion = []
    salida.append(f"[WARN] Error distinct produccion: {e}")

salida.append(f"Total codigos unicos en produccion activa: {len(cods_produccion)}")

for cod in cods_produccion:
    if not cod or cod in codigos_en_piezas:
        continue
    ult = db.produccion.find_one({"codigo_pieza": cod}, sort=[("fecha", -1)])
    if not ult:
        continue
    user_id = ult.get("user_id")
    udata = None
    if user_id:
        try:
            udata = db.usuarios.find_one({"_id": ObjectId(user_id)})
        except Exception:
            pass
    try:
        hist = db.produccion_historica.find_one({"codigo_pieza": cod})
    except Exception:
        hist = None
    candidatos.append({
        "codigo": cod,
        "fecha": ult.get("fecha"),
        "usuario_reg": ult.get("usuario", "N/A"),
        "usuario_rol": (udata.get("rol") if udata else "N/A"),
        "usuario_email": (udata.get("email") if udata else "N/A"),
        "modo": ult.get("modo", "N/A"),
        "box": ult.get("box", "N/A"),
        "ci": ult.get("cuerda_interna"),
        "ce": ult.get("cuerda_externa"),
        "flecha": ult.get("flecha"),
        "en_historico": hist is not None,
        "coleccion": "produccion_activa",
    })

candidatos.sort(key=lambda x: x["fecha"] or datetime.min, reverse=True)
salida.append(f"CODIGOS BORRADOS DETECTADOS EN PRODUCCION ACTIVA: {len(candidatos)}")

if candidatos:
    salida.append("\n--- LISTADO DETALLADO (ordenados por fecha MAS RECIENTE primero) ---")
    for i, c in enumerate(candidatos, 1):
        fstr = c["fecha"].strftime("%Y-%m-%d %H:%M:%S") if c["fecha"] else "N/A"
        salida.append(f"\n[{i}] CODIGO: {c['codigo']}")
        salida.append(f"    ULTIMO REGISTRO: {fstr}")
        salida.append(f"    OPERADOR: {c['usuario_reg']}")
        salida.append(f"    ROL OPERADOR: {c['usuario_rol']}")
        if c["usuario_email"] and c["usuario_email"] != "N/A":
            salida.append(f"    EMAIL OPERADOR: {c['usuario_email']}")
        salida.append(f"    MODO PRODUCCION: {c['modo']} | BOX: {c['box']}")
        if c["ci"] is not None or c["ce"] is not None:
            salida.append(f"    MEDIDAS - Cuerda Interna: {c['ci']} | Cuerda Externa: {c['ce']} | Flecha: {c['flecha']}")
        salida.append(f"    EXISTE EN HISTORICOS: {'SI' if c['en_historico'] else 'NO'}")
        salida.append(f"    COMO RECUPERAR: Reinsertar en piezas con codigo '{c['codigo']}' y los datos de arriba")

salida.append("\n" + "=" * 90)
salida.append("ANALISIS 2: CODIGOS SOLO EN PRODUCCION HISTORICA (NO ESTAN EN PIEZAS)")
salida.append("=" * 90)

historicos = []
cods_ya_listados = {c["codigo"] for c in candidatos}
try:
    cods_hist = db.produccion_historica.distinct("codigo_pieza")
except Exception as e:
    cods_hist = []
    salida.append(f"[WARN] Error distinct historica: {e}")

salida.append(f"Total codigos unicos en produccion historica: {len(cods_hist)}")

for cod in cods_hist:
    if not cod or cod in codigos_en_piezas or cod in cods_ya_listados:
        continue
    ult = db.produccion_historica.find_one({"codigo_pieza": cod}, sort=[("fecha", -1)])
    if not ult:
        continue
    user_id = ult.get("user_id")
    udata = None
    if user_id:
        try:
            udata = db.usuarios.find_one({"_id": ObjectId(user_id)})
        except Exception:
            pass
    historicos.append({
        "codigo": cod,
        "fecha": ult.get("fecha"),
        "usuario_reg": ult.get("usuario", "N/A"),
        "usuario_rol": (udata.get("rol") if udata else "N/A"),
        "usuario_email": (udata.get("email") if udata else "N/A"),
        "modo": ult.get("modo", "N/A"),
        "box": ult.get("box", "N/A"),
        "ci": ult.get("cuerda_interna"),
        "ce": ult.get("cuerda_externa"),
        "flecha": ult.get("flecha"),
        "coleccion": "produccion_historica",
    })

historicos.sort(key=lambda x: x["fecha"] or datetime.min, reverse=True)
salida.append(f"CODIGOS ADICIONALES EN HISTORICOS: {len(historicos)}")

if historicos:
    salida.append("\n--- LISTADO HISTORICOS (TOP 30 mas recientes) ---")
    for i, c in enumerate(historicos[:30], 1):
        fstr = c["fecha"].strftime("%Y-%m-%d %H:%M:%S") if c["fecha"] else "N/A"
        salida.append(f"\n[{i}] CODIGO: {c['codigo']}")
        salida.append(f"    ULTIMO REGISTRO: {fstr}")
        salida.append(f"    OPERADOR: {c['usuario_reg']} | ROL: {c['usuario_rol']}")
        salida.append(f"    MODO: {c['modo']} | BOX: {c['box']}")
        if c["ci"] is not None or c["ce"] is not None:
            salida.append(f"    MEDIDAS - CI={c['ci']} | CE={c['ce']} | Flecha={c['flecha']}")

salida.append("\n" + "=" * 90)
salida.append("RESUMEN FINAL")
salida.append("=" * 90)
total = len(candidatos) + len(historicos)
salida.append(f"Total codigos borrados detectados (recuperables): {total}")
salida.append(f"  - En produccion ACTIVA (mas probables/recientes): {len(candidatos)}")
salida.append(f"  - En produccion HISTORICA (cortes anteriores): {len(historicos)}")

if total == 0:
    salida.append("\n[ATENCION] NO SE DETECTARON CODIGOS BORRADOS EN LAS COLECCIONES ANALIZADAS.")
    salida.append("Posibles causas:")
    salida.append("  1. El codigo fue borrado ANTES de ser registrado por algun operador.")
    salida.append("  2. El codigo fue borrado y TAMBIEN se eliminaron sus registros de produccion.")
    salida.append("  3. ESTAS CONECTADO A LA BD INCORRECTA (verifica MONGO_URI en .env).")
    salida.append("  4. El codigo pertenece a un periodo muy antiguo sin historicos.")
else:
    salida.append("\n[PASO SIGUIENTE] Mira el listado de arriba y localiza el codigo.")
    salida.append("Una vez identificado, podemos:")
    salida.append("  A) Reinsertarlo AUTOMATICAMENTE en db.piezas con todos sus datos.")
    salida.append("  B) Generar un script SQL/Mongo especifico para copiar y pegar.")
    salida.append("Indica cual es el CODIGO que necesitas recuperar.")

with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    f.write("\n".join(salida))

client.close()
print("=" * 70)
print(f"ANALISIS COMPLETADO. Resultado guardado en:")
print(f"  {OUTPUT_FILE}")
print("=" * 70)
print(f"\nResumen rapido:")
print(f"  - Codigos borrados en produccion activa: {len(candidatos)}")
print(f"  - Codigos adicionales en historicos: {len(historicos)}")
print(f"  - Total recuperables detectados: {total}")
print("\nAbre el archivo .txt con cualquier editor de texto para ver el detalle.")
