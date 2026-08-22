import os
import sys
import io
from pathlib import Path
from dotenv import load_dotenv
from pymongo import MongoClient
from bson.objectid import ObjectId
from datetime import datetime, timedelta

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

project_root = Path(__file__).resolve().parent
load_dotenv(project_root / ".env")

mongo_uri = os.getenv("MONGO_URI")
if not mongo_uri:
    print("ERROR: MONGO_URI no definida en .env")
    sys.exit(1)

print("=" * 80)
print("BUSCADOR DE CODIGOS DE PIEZAS BORRADOS ACCIDENTALMENTE")
print("=" * 80)
print(f"Conectando a MongoDB: {mongo_uri}")

client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
try:
    client.admin.command('ping')
except Exception as e:
    print(f"\nERROR al conectar MongoDB: {e}")
    print("\nIMPORTANTE: Si el borrado fue en PRODUCCION (VPS),")
    print("necesitamos conectarnos a la base de datos del VPS.")
    print("La configuracion actual .env apunta a:")
    print(f"  MONGO_URI = {mongo_uri}")
    print("\nOpciones:")
    print("  1. Si MongoDB local tiene los datos: asegurate que el servicio este corriendo")
    print("  2. Si la BD esta en MongoDB Atlas: descomenta la linea MONGO_URI de Atlas en .env")
    print("  3. Si es VPS local o remoto: actualiza MONGO_URI con la IP del servidor")
    sys.exit(1)

db = client["miBase"]

print("\n[OK] Conexion exitosa.")
print("\n[RESUMEN] Colecciones disponibles:")
for col_name in ["piezas", "produccion", "produccion_historica", "operator_submission_guards", "usuarios"]:
    try:
        count = db[col_name].estimated_document_count()
        print(f"   - {col_name}: {count:,} documentos")
    except Exception as e:
        print(f"   - {col_name}: ERROR al consultar ({e})")

print("\n" + "=" * 80)
print("PASO 1: Codigos presentes en PRODUCCION ACTIVA pero AUSENTES en PIEZAS")
print("(Estos son candidatos a borrados accidentales recientes)")
print("=" * 80)

codigos_piezas = set()
for doc in db.piezas.find({}, {"codigo": 1, "_id": 0}):
    if doc.get("codigo"):
        codigos_piezas.add(doc["codigo"])

print(f"\n[INFO] Total codigos en piezas (activas): {len(codigos_piezas):,}")

candidatos_borrados = []
try:
    produccion_codigos_unicos = db.produccion.distinct("codigo_pieza")
except Exception as e:
    produccion_codigos_unicos = []
    print(f"[WARN] No se pudo consultar produccion.distinct: {e}")
print(f"[INFO] Total codigos unicos en produccion activa: {len(produccion_codigos_unicos):,}")

for codigo in produccion_codigos_unicos:
    if codigo and codigo not in codigos_piezas:
        ultimo_registro = db.produccion.find_one(
            {"codigo_pieza": codigo},
            sort=[("fecha", -1)]
        )
        if ultimo_registro:
            user_id = ultimo_registro.get("user_id")
            usuario_nombre = ultimo_registro.get("usuario", "N/A")
            usuario_data = None
            if user_id:
                try:
                    usuario_data = db.usuarios.find_one({"_id": ObjectId(user_id)})
                except Exception:
                    pass
            
            historico_ref = db.produccion_historica.find_one({"codigo_pieza": codigo})
            
            candidatos_borrados.append({
                "codigo": codigo,
                "ultima_fecha": ultimo_registro.get("fecha"),
                "modo": ultimo_registro.get("modo", "N/A"),
                "box": ultimo_registro.get("box", "N/A"),
                "user_id": str(user_id) if user_id else None,
                "usuario_nombre_registro": usuario_nombre,
                "usuario_rol": usuario_data.get("rol") if usuario_data else "N/A",
                "usuario_correo": usuario_data.get("email") if usuario_data else "N/A",
                "cuerda_interna": ultimo_registro.get("cuerda_interna"),
                "cuerda_externa": ultimo_registro.get("cuerda_externa"),
                "flecha": ultimo_registro.get("flecha"),
                "en_historico": historico_ref is not None,
            })

print(f"\n[RESULTADO] Codigos en produccion pero NO en piezas activas: {len(candidatos_borrados)}")

if candidatos_borrados:
    candidatos_borrados.sort(key=lambda x: x["ultima_fecha"] or datetime.min, reverse=True)
    print("\n" + "-" * 80)
    print("TOP 50 candidatos mas recientes:")
    print("-" * 80)
    for i, c in enumerate(candidatos_borrados[:50]):
        fecha_str = c["ultima_fecha"].strftime("%Y-%m-%d %H:%M:%S") if c["ultima_fecha"] else "N/A"
        print(f"\n{i+1:>3}. [PIEZA] Codigo: {c['codigo']}")
        print(f"     [FECHA] Ultimo registro produccion: {fecha_str}")
        print(f"     [OPERADOR] {c['usuario_nombre_registro']} (Rol: {c['usuario_rol']})")
        if c['usuario_correo'] and c['usuario_correo'] != 'N/A':
            print(f"     [CORREO] {c['usuario_correo']}")
        print(f"     [MODO] {c['modo']} | [BOX] {c['box']}")
        if c['cuerda_interna'] or c['cuerda_externa']:
            print(f"     [MEDIDAS] CI={c['cuerda_interna']} | CE={c['cuerda_externa']} | Flecha={c['flecha']}")
        print(f"     [HISTORICO] {'SI' if c['en_historico'] else 'NO'}")

print("\n" + "=" * 80)
print("PASO 2: Codigos presentes en PRODUCCION HISTORICA pero AUSENTES en PIEZAS")
print("=" * 80)

historicos_ausentes = []
try:
    historicos_codigos_unicos = db.produccion_historica.distinct("codigo_pieza")
except Exception as e:
    historicos_codigos_unicos = []
    print(f"[WARN] No se pudo consultar produccion_historica.distinct: {e}")
print(f"\n[INFO] Total codigos unicos en produccion historica: {len(historicos_codigos_unicos):,}")

for codigo in historicos_codigos_unicos:
    if codigo and codigo not in codigos_piezas and codigo not in [c["codigo"] for c in candidatos_borrados]:
        ultimo_registro = db.produccion_historica.find_one(
            {"codigo_pieza": codigo},
            sort=[("fecha", -1)]
        )
        if ultimo_registro:
            user_id = ultimo_registro.get("user_id")
            usuario_nombre = ultimo_registro.get("usuario", "N/A")
            usuario_data = None
            if user_id:
                try:
                    usuario_data = db.usuarios.find_one({"_id": ObjectId(user_id)})
                except Exception:
                    pass
            
            historicos_ausentes.append({
                "codigo": codigo,
                "ultima_fecha": ultimo_registro.get("fecha"),
                "modo": ultimo_registro.get("modo", "N/A"),
                "box": ultimo_registro.get("box", "N/A"),
                "user_id": str(user_id) if user_id else None,
                "usuario_nombre_registro": usuario_nombre,
                "usuario_rol": usuario_data.get("rol") if usuario_data else "N/A",
                "usuario_correo": usuario_data.get("email") if usuario_data else "N/A",
                "cuerda_interna": ultimo_registro.get("cuerda_interna"),
                "cuerda_externa": ultimo_registro.get("cuerda_externa"),
                "flecha": ultimo_registro.get("flecha"),
            })

print(f"\n[RESULTADO] Codigos adicionales solo en historicos (no en piezas): {len(historicos_ausentes)}")

if historicos_ausentes:
    historicos_ausentes.sort(key=lambda x: x["ultima_fecha"] or datetime.min, reverse=True)
    print("\n" + "-" * 80)
    print("TOP 20 historicos mas recientes:")
    print("-" * 80)
    for i, c in enumerate(historicos_ausentes[:20]):
        fecha_str = c["ultima_fecha"].strftime("%Y-%m-%d %H:%M:%S") if c["ultima_fecha"] else "N/A"
        print(f"\n{i+1:>3}. [PIEZA] Codigo: {c['codigo']}")
        print(f"     [FECHA] Ultimo registro: {fecha_str}")
        print(f"     [OPERADOR] {c['usuario_nombre_registro']} (Rol: {c['usuario_rol']})")
        if c['usuario_correo'] and c['usuario_correo'] != 'N/A':
            print(f"     [CORREO] {c['usuario_correo']}")
        print(f"     [MODO] {c['modo']} | [BOX] {c['box']}")
        if c['cuerda_interna'] or c['cuerda_externa']:
            print(f"     [MEDIDAS] CI={c['cuerda_interna']} | CE={c['cuerda_externa']} | Flecha={c['flecha']}")

print("\n" + "=" * 80)
print("PASO 3: Busqueda en operator_submission_guards (registros muy recientes)")
print("=" * 80)

guards_recientes = []
try:
    for guard in db.operator_submission_guards.find().sort("_id", -1).limit(100):
        guard_id = str(guard.get("_id"))
        if "_" in guard_id:
            parts = guard_id.rsplit("_", 1)
            if len(parts) == 2:
                codigo = parts[0]
                modo = parts[1]
                if codigo and codigo not in codigos_piezas:
                    guards_recientes.append({
                        "codigo": codigo,
                        "modo": modo,
                        "expireAt": guard.get("expireAt"),
                    })
except Exception as e:
    print(f"[WARN] No se pudo consultar submission_guards: {e}")

print(f"\n[RESULTADO] Guards recientes con codigos ausentes en piezas: {len(guards_recientes)}")
for g in guards_recientes[:10]:
    exp_str = g["expireAt"].strftime("%Y-%m-%d %H:%M:%S") if g["expireAt"] else "N/A"
    print(f"   - {g['codigo']} (modo: {g['modo']}, expiracion: {exp_str})")

print("\n" + "=" * 80)
print("[RESUMEN FINAL]")
print("=" * 80)
print(f"""
Candidatos totales encontrados:
   - Produccion activa: {len(candidatos_borrados)} codigos (recientes, mas probables)
   - Produccion historica: {len(historicos_ausentes)} codigos (cortes mensuales anteriores)
   - Guards recientes: {len(guards_recientes)} codigos (ultimos minutos)
""")

if len(candidatos_borrados) > 0 or len(historicos_ausentes) > 0:
    todos_candidatos = candidatos_borrados + historicos_ausentes
    todos_candidatos.sort(key=lambda x: x["ultima_fecha"] or datetime.min, reverse=True)
    
    print("\n[AYUDA] Para afinar la busqueda del codigo borrado, necesito que me digas:")
    print("   1. El codigo aproximado (si lo recuerdas parcialmente, ej: 'k3' o 'h27')")
    print("   2. Nombre del operador o empresa asociada")
    print("   3. Fecha aproximada de creacion o borrado (ej: 'hoy', 'ayer', '15 de agosto')")
    print("   4. Marco o tramo de la pieza")
    print("   5. Valores de medidas (cuerda interna/externa, flecha)")
    
    print("\n" + "=" * 80)
    print("[ESTRATEGIAS DE RECUPERACION DISPONIBLES]")
    print("=" * 80)
    print("""
OPCION 1 - Reingreso desde rastro de produccion (RECOMENDADA):
   Extraemos todos los campos disponibles desde el registro de produccion
   encontrado (codigo, medidas, operador, modo, box, etc.) y generamos
   el documento para reinsertarlo manualmente en db.piezas.

OPCION 2 - Restauracion desde backup (si existe):
   Si tienes backups automaticos de MongoDB en el VPS, podemos restaurar
   solo el documento especifico de la coleccion piezas sin afectar lo demas.

OPCION 3 - Verificacion en piezas archivadas:
   Si el codigo paso por un corte mensual, es posible que este en la
   coleccion de piezas archivadas (si existe mecanismo de archivado).
""")

else:
    print("[ATENCION] No se encontraron codigos hurfanos en las colecciones de produccion.")
    print("Esto podria significar:")
    print("   1. El codigo fue borrado antes de ser registrado por ningun operador")
    print("   2. El codigo fue registrado pero el registro de produccion tambien fue eliminado")
    print("   3. El codigo pertenece a un periodo muy antiguo sin historicos")
    print("   4. ESTAMOS CONECTADOS A LA BASE DE DATOS EQUIVOCADA (local vs VPS produccion)")
    print("\n[AYUDA] Si te acuerdas de algun dato del codigo (parte del nombre, operador, fecha),")
    print("   puedo hacer una busqueda mas acotada en la base de datos.")
    print("\n[IMPORTANTE] Si el borrado fue en PRODUCCION (VPS), asegurate que la")
    print("   variable MONGO_URI en .env apunte a la BD correcta del VPS.")

client.close()
print("\n[FIN] Analisis completado.")
