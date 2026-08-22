import os
import sys
import io
from pathlib import Path

if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

from dotenv import load_dotenv
from pymongo import MongoClient
from bson.objectid import ObjectId
from datetime import datetime

AYUDA = """
=============================================================================
USO: python restaurar_registro_produccion.py <CODIGO_DE_PIEZA> [opciones]
=============================================================================

BUSCA EL PRIMER REGISTRO DE PRODUCCION FALTANTE (borrado por error) de un
codigo de pieza que SIGUE EXISTIENDO en db.piezas, y lo RESTAURA
tomando los datos desde:
  1) produccion_historica (cortes mensuales cerrados) - fuente con mas datos
  2) pieza maestra en db.piezas (empresa, marco, tramo, medidas, box, etc.)
  3) usuario/operador por asociacion historica del codigo

MODOS:
  Solo lectura (recomendado PRIMERO):
    python restaurar_registro_produccion.py <CODIGO>

  Confirmar restauracion (inserta el registro en db.produccion):
    python restaurar_registro_produccion.py <CODIGO> --confirmar

  Especificar MODO (operador) manualmente (si no lo detecta):
    python restaurar_registro_produccion.py <CODIGO> --modo armador
    python restaurar_registro_produccion.py <CODIGO> --modo rematador

  Especificar USUARIO (operador) por ID o correo si no lo detecta:
    python restaurar_registro_produccion.py <CODIGO> --usuario <id_o_correo>

EJEMPLOS:
  python restaurar_registro_produccion.py h2785
  python restaurar_registro_produccion.py k3 --confirmar
  python restaurar_registro_produccion.py j102 --modo armador --confirmar
"""

if len(sys.argv) < 2:
    print(AYUDA)
    sys.exit(1)

CODIGO = sys.argv[1].strip()
CONFIRMAR = "--confirmar" in sys.argv
MODO_FORZADO = None
USUARIO_FORZADO = None

for i, arg in enumerate(sys.argv):
    if arg == "--modo" and i + 1 < len(sys.argv):
        MODO_FORZADO = sys.argv[i + 1].strip().lower()
    if arg == "--usuario" and i + 1 < len(sys.argv):
        USUARIO_FORZADO = sys.argv[i + 1].strip()

REPORTE = Path(__file__).resolve().parent / f"RESTORE_PROD_{CODIGO.replace('/', '_').replace(' ', '_')}.txt"

logs = []
def log(msg):
    print(msg)
    logs.append(msg)

log("=" * 90)
log(f"RESTAURAR REGISTRO DE PRODUCCION BORRADO PARA CODIGO: {CODIGO}")
log(f"Generado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
log(f"Modo: {'RESTAURACION CONFIRMADA' if CONFIRMAR else 'SOLO LECTURA'}")
log(f"Modo forzado operacion: {MODO_FORZADO or '(auto detect)'}")
log(f"Usuario forzado: {USUARIO_FORZADO or '(auto detect)'}")
log("=" * 90)

project_root = Path(__file__).resolve().parent
load_dotenv(project_root / ".env")
mongo_uri = os.getenv("MONGO_URI")
if not mongo_uri:
    log("[ERROR] MONGO_URI no definida en .env")
    sys.exit(1)

try:
    client = MongoClient(
        mongo_uri,
        serverSelectionTimeoutMS=10000,
        socketTimeoutMS=30000,
    )
    client.admin.command('ping')
    log("[OK] Conectado a MongoDB")
    db = client["miBase"]
except Exception as e:
    log(f"[ERROR] Conexion fallida: {e}")
    with open(REPORTE, "w", encoding="utf-8") as f:
        f.write("\n".join(logs))
    sys.exit(1)

log(f"\n[PASO 1] Verificando que el codigo '{CODIGO}' EXISTA en db.piezas...")
pieza = db.piezas.find_one({"codigo": CODIGO})
if not pieza:
    log(f"[ERROR] El codigo '{CODIGO}' NO EXISTE en db.piezas.")
    log("  Si la pieza MAESTRA fue borrada, usa 'python restaurar_codigo.py' en vez de este script.")
    log("  Si te equivocaste de nombre, revisa mayusculas/minusculas.")
    with open(REPORTE, "w", encoding="utf-8") as f:
        f.write("\n".join(logs))
    client.close()
    sys.exit(1)

log(f"  [OK] Pieza maestra encontrada en db.piezas. ID: {pieza['_id']}")
pieza_campos = [
    ("Empresa", pieza.get("empresa")),
    ("Marco", pieza.get("marco")),
    ("Tramo", pieza.get("tramo")),
    ("Cuerda Interna", pieza.get("cuerda_interna")),
    ("Cuerda Externa", pieza.get("cuerda_externa")),
    ("Flecha", pieza.get("flecha")),
    ("Estado", pieza.get("estado")),
    ("Box", pieza.get("box")),
    ("Kilo pieza", pieza.get("kilo_pieza")),
    ("Tipo precio", pieza.get("tipo_precio")),
    ("Fecha creacion", pieza.get("fecha_creacion")),
    ("Operador asignado", pieza.get("operador_asignado")),
]
for k, v in pieza_campos:
    if v is not None and v != "":
        if isinstance(v, datetime):
            v = v.strftime("%Y-%m-%d %H:%M:%S")
        log(f"    - {k:20s}: {v}")

log(f"\n[PASO 2] Buscando registros de producción ACTIVOS existentes para '{CODIGO}'...")
regs_activos = list(db.produccion.find({"codigo_pieza": CODIGO}).sort("fecha", -1))
log(f"  Registros ACTIVOS (produccion) encontrados: {len(regs_activos)}")

log(f"\n[PASO 3] Buscando registros de producción HISTÓRICOS para '{CODIGO}'...")
regs_historicos = list(db.produccion_historica.find({"codigo_pieza": CODIGO}).sort("fecha", -1))
log(f"  Registros HISTORICOS encontrados: {len(regs_historicos)}")

# Detectar de qué colección viene el borrado:
# Si no hay registros activos pero sí históricos -> probablemente el corte fue cerrado y todo está allá
# Si hay algunos activos pero faltan -> buscar si hay más históricos para el mismo código
# Si hay cero en ambas -> el registro fue borrado completamente de produccion_activa pero no pasó a historicos

fuente_restauracion = None
modelo_registro = None

if regs_historicos:
    log(f"\n  [INFO] Usando el REGISTRO HISTORICO MAS RECIENTE como plantilla.")
    fuente_restauracion = "produccion_historica"
    modelo_registro = dict(regs_historicos[0])
    # Eliminar campos específicos de históricos que no van en activa:
    modelo_registro.pop("_id", None)
    modelo_registro.pop("corte_id", None)
    # Actualizar con datos más frescos de la pieza maestra:
    for field in ["empresa", "marco", "tramo", "kilo_pieza", "tipo_precio",
                   "cuerda_interna", "cuerda_externa", "flecha", "box"]:
        val_pieza = pieza.get(field)
        if val_pieza is not None and val_pieza != "":
            modelo_registro[field] = val_pieza

elif regs_activos:
    log(f"\n  [INFO] Usando el REGISTRO ACTIVO MAS RECIENTE como plantilla (duplicado).")
    fuente_restauracion = "produccion_activa_existente"
    modelo_registro = dict(regs_activos[0])
    modelo_registro.pop("_id", None)
    for field in ["empresa", "marco", "tramo", "kilo_pieza", "tipo_precio",
                   "cuerda_interna", "cuerda_externa", "flecha", "box"]:
        val_pieza = pieza.get(field)
        if val_pieza is not None and val_pieza != "":
            modelo_registro[field] = val_pieza

else:
    log(f"\n  [INFO] No hay registros en NINGUNA colección. Creando desde pieza maestra.")
    fuente_restauracion = "solo_pieza_maestra"
    modelo_registro = {
        "codigo_pieza": CODIGO,
        "empresa": pieza.get("empresa", ""),
        "marco": pieza.get("marco", ""),
        "tramo": pieza.get("tramo", ""),
        "kilo_pieza": pieza.get("kilo_pieza", 0),
        "tipo_precio": pieza.get("tipo_precio", "metro"),
        "cuerda_interna": pieza.get("cuerda_interna"),
        "cuerda_externa": pieza.get("cuerda_externa"),
        "flecha": pieza.get("flecha"),
        "box": pieza.get("box"),
        "fecha": datetime.utcnow(),
        "calidad_status": "pendiente",
    }

log(f"  Fuente plantilla usada: {fuente_restauracion}")

# === Detectar usuario/operador correcto ===
log(f"\n[PASO 4] Detectando OPERADOR/USUARIO del registro...")
user_obj = None

if USUARIO_FORZADO:
    if ObjectId.is_valid(USUARIO_FORZADO):
        user_obj = db.usuarios.find_one({"_id": ObjectId(USUARIO_FORZADO)})
    else:
        user_obj = db.usuarios.find_one({"email": USUARIO_FORZADO}) or db.usuarios.find_one({"nombre": USUARIO_FORZADO})
    if user_obj:
        log(f"  [OK] Usuario cargado via --usuario: {user_obj.get('nombre')} (Rol: {user_obj.get('rol')})")
    else:
        log(f"  [WARN] Usuario --usuario '{USUARIO_FORZADO}' no encontrado.")

if not user_obj and modelo_registro.get("user_id"):
    try:
        user_obj = db.usuarios.find_one({"_id": ObjectId(modelo_registro["user_id"])})
    except Exception:
        pass
    if user_obj:
        log(f"  [OK] Usuario recuperado desde plantilla historica: {user_obj.get('nombre')}")

if not user_obj and pieza.get("operador_id"):
    try:
        if ObjectId.is_valid(str(pieza["operador_id"])):
            user_obj = db.usuarios.find_one({"_id": ObjectId(pieza["operador_id"])})
    except Exception:
        pass
    if user_obj:
        log(f"  [OK] Usuario recuperado desde campo 'operador_id' de pieza maestra: {user_obj.get('nombre')}")

if not user_obj and pieza.get("operador_asignado"):
    nombre = pieza["operador_asignado"]
    user_obj = db.usuarios.find_one({"nombre": nombre}) or db.usuarios.find_one({"nombre": {"$regex": nombre, "$options": "i"}})
    if user_obj:
        log(f"  [OK] Usuario por nombre 'operador_asignado': {user_obj.get('nombre')}")

if not user_obj and regs_historicos:
    # Buscar operador más frecuente para este código en históricos
    pipeline_user = [
        {"$match": {"codigo_pieza": CODIGO, "user_id": {"$exists": True}}},
        {"$group": {"_id": "$user_id", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 1},
    ]
    res = list(db.produccion_historica.aggregate(pipeline_user))
    if res and ObjectId.is_valid(str(res[0]["_id"])):
        user_obj = db.usuarios.find_one({"_id": ObjectId(res[0]["_id"])})
        if user_obj:
            log(f"  [OK] Usuario por mayoria de registros historicos: {user_obj.get('nombre')} ({res[0]['count']} regs)")

if not user_obj and regs_activos:
    user_obj = db.usuarios.find_one({"_id": ObjectId(regs_activos[0]["user_id"])})
    if user_obj:
        log(f"  [OK] Usuario desde ultimo registro activo: {user_obj.get('nombre')}")

if not user_obj:
    log(f"  [WARN] No se pudo detectar automaticamente ningun usuario.")
    log(f"         Si sabes quién era, re-lanza con --usuario 'Nombre o ID'")

# Actualizar modelo con datos de usuario
if user_obj:
    modelo_registro["user_id"] = user_obj["_id"]
    modelo_registro["usuario"] = user_obj.get("nombre") or modelo_registro.get("usuario", "")
else:
    # Si no se detectó usuario, conservar lo del modelo o dejar campos vacíos
    if "user_id" not in modelo_registro:
        modelo_registro["user_id"] = None
    if "usuario" not in modelo_registro or not modelo_registro["usuario"]:
        modelo_registro["usuario"] = pieza.get("operador_asignado") or "Operador no identificado"

# === Detectar modo armador/rematador ===
log(f"\n[PASO 5] Detectando MODO (armador / rematador)...")
MODO = MODO_FORZADO
if not MODO and modelo_registro.get("modo"):
    MODO = modelo_registro["modo"].lower()
    log(f"  [OK] Modo detectado desde plantilla: {MODO}")

if not MODO and regs_historicos:
    # Modo más frecuente para ese código
    pipeline_modo = [
        {"$match": {"codigo_pieza": CODIGO, "modo": {"$exists": True}}},
        {"$group": {"_id": "$modo", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 1},
    ]
    res = list(db.produccion_historica.aggregate(pipeline_modo))
    if res:
        MODO = res[0]["_id"].lower()
        log(f"  [OK] Modo por mayoria historica: {MODO} ({res[0]['count']} veces)")

if not MODO and pieza.get("estado") and "armado" in str(pieza["estado"]).lower():
    MODO = "armador"
    log(f"  [OK] Modo deducido por estado pieza '{pieza['estado']}': {MODO}")

if not MODO:
    MODO = "armador"
    log(f"  [INFO] No se pudo detectar. Asumido por defecto: {MODO}")
    log(f"         Si está mal, re-lanza con --modo armador o --modo rematador")

modelo_registro["modo"] = MODO

# === Calcular precio unitario según modo y valores del usuario ===
log(f"\n[PASO 6] Calculando precio unitario (si es posible)...")
precio = 0
tipo_precio_reg = modelo_registro.get("tipo_precio") or pieza.get("tipo_precio") or "metro"
if user_obj:
    if MODO == "armador":
        if tipo_precio_reg == "metro":
            precio = float(user_obj.get("precio_metro_armado", 0) or 0)
        else:
            precio = float(user_obj.get("precio_avo_armado", 0) or 0)
    else:
        if tipo_precio_reg == "metro":
            precio = float(user_obj.get("precio_metro_remate", 0) or 0)
        else:
            precio = float(user_obj.get("precio_avo_remate", 0) or 0)
    log(f"  [OK] Precio unitario calculado: ${precio} (tipo_precio={tipo_precio_reg})")
else:
    log(f"  [INFO] Precio no calculado (sin usuario detectado) - quedara en 0")
modelo_registro["precio_unitario"] = precio

# Asegurar campos mínimos requeridos
modelo_registro.setdefault("codigo_pieza", CODIGO)
modelo_registro.setdefault("fecha", datetime.utcnow())
modelo_registro.setdefault("calidad_status", "pendiente")
modelo_registro["tipo_precio"] = tipo_precio_reg
modelo_registro["empresa"] = modelo_registro.get("empresa") or pieza.get("empresa") or ""
modelo_registro["marco"] = modelo_registro.get("marco") or pieza.get("marco") or ""
modelo_registro["tramo"] = modelo_registro.get("tramo") or pieza.get("tramo") or ""
modelo_registro["kilo_pieza"] = modelo_registro.get("kilo_pieza") or pieza.get("kilo_pieza") or 0

# Metadata de restauración
modelo_registro["fecha_restauracion_registro"] = datetime.utcnow()
modelo_registro["restaurado_registro_desde"] = fuente_restauracion
modelo_registro["observacion_restauracion"] = (
    f"Registro de produccion restaurado automaticamente desde {fuente_restauracion}. "
    f"Codigo pieza: {CODIGO}. Modo: {MODO}."
)

log("\n" + "=" * 90)
log("DOCUMENTO QUE SERA INSERTADO EN db.produccion:")
log("=" * 90)
mostrar = dict(modelo_registro)
for k, v in list(mostrar.items()):
    if isinstance(v, ObjectId):
        mostrar[k] = f"ObjectId('{str(v)}')"
    elif isinstance(v, datetime):
        mostrar[k] = v.strftime("%Y-%m-%dT%H:%M:%SZ")
import pprint
pp = pprint.PrettyPrinter(indent=2, width=120)
log(pp.pformat(mostrar))

log("\n" + "-" * 90)
if CONFIRMAR:
    log("[MODO CONFIRMAR] Insertando registro en db.produccion ...")
    try:
        res = db.produccion.insert_one(modelo_registro)
        log(f"\n[EXITO] REGISTRO DE PRODUCCION RESTAURADO!")
        log(f"  Nuevo ID Mongo en produccion: {res.inserted_id}")
        log(f"  Codigo pieza: {CODIGO}")
        log(f"  Operador: {modelo_registro.get('usuario')}")
        log(f"  Modo: {modelo_registro.get('modo')}")
        log(f"  Fecha: {modelo_registro.get('fecha')}")
        log(f"\n  Ahora deberias ver el registro en:")
        log(f"    - Panel Soporte -> 'Gestion de Produccion'")
        log(f"    - Panel Admin -> 'Produccion (Admin)'")
        log(f"    - Reportes de operador y cierre mensual")
    except Exception as e:
        log(f"\n[ERROR] No se pudo insertar el registro: {e}")
else:
    log("[MODO SOLO LECTURA] - No se realizaron cambios en la BD.")
    log("\n[INSTRUCCION] Si los datos de arriba se ven CORRECTOS, ejecuta:")
    cmd = f"python restaurar_registro_produccion.py {CODIGO}"
    if MODO_FORZADO:
        cmd += f" --modo {MODO_FORZADO}"
    if USUARIO_FORZADO:
        cmd += f" --usuario {USUARIO_FORZADO}"
    cmd += " --confirmar"
    log(f"  {cmd}")
    log("\n[INSTRUCCION] Si faltan datos o son incorrectos:")
    log(f"  - Fuerza modo operacion: --modo armador  |  --modo rematador")
    log(f"  - Fuerza usuario/operador: --usuario 'Nombre'  o  --usuario ObjectId(...)")
    log(f"  - Ej: python restaurar_registro_produccion.py {CODIGO} --modo rematador --confirmar")

with open(REPORTE, "w", encoding="utf-8") as f:
    f.write("\n".join(logs))

client.close()
log(f"\n[OK] Reporte guardado en: {REPORTE}")
