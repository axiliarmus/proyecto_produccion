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

if len(sys.argv) < 2:
    print("=" * 80)
    print("USO: python restaurar_codigo.py <CODIGO_DE_PIEZA> [--confirmar]")
    print("=" * 80)
    print("\nEJEMPLOS:")
    print("  # Buscar informacion del codigo 'h2785' (solo muestra, NO restaura)")
    print("  python restaurar_codigo.py h2785")
    print("")
    print("  # Buscar y RESTAURAR AUTOMATICAMENTE el codigo 'h2785' en db.piezas")
    print("  python restaurar_codigo.py h2785 --confirmar")
    print("")
    print("  # Si el codigo tiene espacios o caracteres raros, usalo entre comillas")
    print('  python restaurar_codigo.py "K3 AB" --confirmar')
    print("\nPrimero ejecuta SIN --confirmar para revisar los datos,")
    print("luego con --confirmar para aplicar la restauracion.")
    sys.exit(1)

CODIGO = sys.argv[1].strip()
CONFIRMAR = "--confirmar" in sys.argv

REPORTE_FILE = Path(__file__).resolve().parent / f"RESTAURAR_{CODIGO.replace('/', '_').replace(' ', '_')}.txt"

log_lines = []
def log(msg):
    print(msg)
    log_lines.append(msg)

log("=" * 80)
log(f"BUSQUEDA Y RESTAURACION DE CODIGO: {CODIGO}")
log(f"Generado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
log(f"Modo: {'RESTAURACION CONFIRMADA' if CONFIRMAR else 'SOLO LECTURA (sin cambios)'}")
log("=" * 80)

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
        connectTimeoutMS=10000,
    )
    client.admin.command('ping')
    log("[OK] Conexion MongoDB exitosa")
    db = client["miBase"]
except Exception as e:
    log(f"[ERROR] Conexion fallida: {e}")
    with open(REPORTE_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(log_lines))
    sys.exit(1)

log(f"\n[PASO 1] Buscando codigo '{CODIGO}' en TODAS las colecciones...")

existe_en_piezas = db.piezas.find_one({"codigo": CODIGO})
if existe_en_piezas:
    log(f"  [ATENCION] El codigo '{CODIGO}' YA EXISTE en db.piezas. Nada que restaurar.")
    log(f"  ID Mongo: {existe_en_piezas['_id']}")
    campos_mostrar = ["codigo", "empresa", "marco", "tramo", "cuerda_interna", "cuerda_externa", "flecha", "estado", "box"]
    for k in campos_mostrar:
        if k in existe_en_piezas:
            log(f"  {k}: {existe_en_piezas[k]}")
    with open(REPORTE_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(log_lines))
    client.close()
    sys.exit(0)

log(f"  [OK] Codigo NO existe en db.piezas -> Podemos restaurarlo.")

produccion_reg = db.produccion.find_one(
    {"codigo_pieza": CODIGO},
    sort=[("fecha", -1)],
)

historico_reg = None
if not produccion_reg:
    historico_reg = db.produccion_historica.find_one(
        {"codigo_pieza": CODIGO},
        sort=[("fecha", -1)],
    )

fuente = None
registro_original = None
if produccion_reg:
    fuente = "produccion (ACTIVA)"
    registro_original = produccion_reg
elif historico_reg:
    fuente = "produccion_historica (CORTES MENSUALES)"
    registro_original = historico_reg

if not registro_original:
    log("\n[RESULTADO] CODIGO NO ENCONTRADO en produccion ni historicos.")
    log("\nPosibles causas:")
    log("  1. El codigo fue borrado ANTES de ser registrado por algun operador.")
    log("  2. El codigo y TODOS sus registros de produccion fueron eliminados.")
    log("  3. Te equivocaste de codigo? Revisa mayusculas/minusculas y espacios.")
    log("  4. El codigo pertenece a un periodo sin historicos.")
    log("\n[AYUDA] Prueba con una parte del codigo usando el script listar_codigos_borrados.py")
    with open(REPORTE_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(log_lines))
    client.close()
    sys.exit(0)

log(f"\n[OK] CODIGO ENCONTRADO! Fuente: {fuente}")
log("-" * 80)

campos = {
    "Codigo pieza": registro_original.get("codigo_pieza"),
    "Fecha ultimo registro": registro_original.get("fecha"),
    "Modo produccion": registro_original.get("modo"),
    "Box": registro_original.get("box"),
    "Cuerda Interna": registro_original.get("cuerda_interna"),
    "Cuerda Externa": registro_original.get("cuerda_externa"),
    "Flecha": registro_original.get("flecha"),
    "Estado reg prod": registro_original.get("estado"),
}
for k, v in campos.items():
    if isinstance(v, datetime):
        v = v.strftime("%Y-%m-%d %H:%M:%S")
    log(f"  {k:25s}: {v}")

user_id = registro_original.get("user_id")
usuario_reg = registro_original.get("usuario", "N/A")
usuario_data = None
if user_id:
    try:
        usuario_data = db.usuarios.find_one({"_id": ObjectId(user_id)})
    except Exception:
        pass

log("\n" + "-" * 80)
log("DATOS DEL OPERADOR / DUEÑO DEL CODIGO:")
if usuario_data:
    log(f"  Nombre operador (BD usuarios): {usuario_data.get('nombre', 'N/A')}")
    log(f"  Nombre operador (reg produccion): {usuario_reg}")
    log(f"  Rol: {usuario_data.get('rol', 'N/A')}")
    log(f"  Email: {usuario_data.get('email', 'N/A')}")
    log(f"  Tipo usuario: {usuario_data.get('tipo_usuario', 'N/A')}")
    log(f"  ID usuario Mongo: {usuario_data['_id']}")
else:
    log(f"  Nombre operador (del registro): {usuario_reg}")
    log(f"  ID usuario Mongo: {user_id}")
    log(f"  (No se encontraron datos adicionales en la coleccion 'usuarios')")

log("\n" + "=" * 80)
log("GENERANDO DOCUMENTO PARA REINSERTAR EN db.piezas:")
log("=" * 80)

nombre_operador = None
if usuario_data:
    nombre_operador = usuario_data.get("nombre") or usuario_reg
else:
    nombre_operador = usuario_reg
if not nombre_operador or nombre_operador == "N/A":
    nombre_operador = "Operador no identificado"

medidas = {
    "cuerda_interna": registro_original.get("cuerda_interna"),
    "cuerda_externa": registro_original.get("cuerda_externa"),
    "flecha": registro_original.get("flecha"),
}

doc_pieza_nuevo = {
    "codigo": CODIGO,
    "empresa": None,
    "marco": None,
    "tramo": None,
    "cuerda_interna": medidas["cuerda_interna"],
    "cuerda_externa": medidas["cuerda_externa"],
    "flecha": medidas["flecha"],
    "estado": "Sin Produccion",
    "box": registro_original.get("box"),
    "operador_asignado": nombre_operador,
    "operador_id": str(user_id) if user_id else None,
    "fecha_creacion": registro_original.get("fecha") or datetime.utcnow(),
    "fecha_restauracion": datetime.utcnow(),
    "restaurado_desde": fuente,
    "observacion_restauracion": f"Restaurado automaticamente desde {fuente}; codigo borrado por error.",
}

log("{\n  ")
log_items = []
for k, v in doc_pieza_nuevo.items():
    if isinstance(v, datetime):
        v = f'ISODate("{v.strftime("%Y-%m-%dT%H:%M:%SZ")}")'
        log_items.append(f'"{k}": {v}')
    elif isinstance(v, str):
        log_items.append(f'"{k}": "{v}"')
    elif v is None:
        log_items.append(f'"{k}": null')
    else:
        log_items.append(f'"{k}": {v}')
log(",\n  ".join(log_items))
log("\n}")

log("\n" + "-" * 80)
if CONFIRMAR:
    log("MODO: RESTAURACION ACTIVADA (--confirmar)")
    log("\n[PASO FINAL] Insertando documento en db.piezas...")
    try:
        res = db.piezas.insert_one(doc_pieza_nuevo)
        log(f"\n[EXITO] CODIGO RESTAURADO CORRECTAMENTE!")
        log(f"  Nuevo ID Mongo en piezas: {res.inserted_id}")
        log(f"  Codigo: {CODIGO}")
        log(f"  Operador asignado: {doc_pieza_nuevo['operador_asignado']}")
        log(f"  Estado inicial: {doc_pieza_nuevo['estado']}")
        log(f"\n  Ahora puedes verlo en el panel admin en: 'Gestion de Piezas'")
        log(f"  Si necesitas completar campos vacios (empresa, marco, tramo),")
        log(f"  usa la opcion EDITAR en el panel para rellenarlos.")
    except Exception as e:
        log(f"\n[ERROR] No se pudo insertar: {e}")
else:
    log("MODO: SOLO INFORMATIVO (sin cambios en BD)")
    log("\n[INSTRUCCION] Si los datos se ven correctos, EJECUTA NUEVAMENTE con:")
    log(f"  python restaurar_codigo.py {CODIGO} --confirmar")
    log("\nEsto insertara el documento anterior en db.piezas y el codigo")
    log("volvera a aparecer en todos los listados del sistema.")

with open(REPORTE_FILE, "w", encoding="utf-8") as f:
    f.write("\n".join(log_lines))

client.close()
log(f"\nReporte guardado en: {REPORTE_FILE}")
