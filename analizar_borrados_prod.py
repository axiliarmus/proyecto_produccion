import os
import sys
import io
from pathlib import Path
from collections import OrderedDict

if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

from dotenv import load_dotenv
from pymongo import MongoClient
from bson.objectid import ObjectId
from datetime import datetime

IDS_BUSCADOS = [
    "6a7fcb3780112718a8625646",
    "6a7a7a3fadb0e64515d155b0",
    "6a7a797171630e85573daa01",
    "6a7a7a4880112718a86252f7",
    "6a7a7981adb0e64515d155ae",
    "6a87a7ff80112718a862593e",
    "6a85bcba80112718a86257f6",
    "6a88e0ab7222c0f5f33a2d19",
    "6a88df4080112718a86259e5",
    "6a87a7895ce3a5d9847be9cf",
    "6a85bcd571630e85573daf16",
    "6a87a73a5ce3a5d9847be9cc",
    "6a85bcff71630e85573daf17",
    "6a87a6f1c71bd4a3dfb45b68",
    "6a85bd3271630e85573daf19",
    "6a89cfab5ce3a5d9847beaa7",
    "6a890096c71bd4a3dfb45c0e",
    "6a89007bc71bd4a3dfb45c0d",
    "6a87a769c71bd4a3dfb45b6a",
    "6a85bcc280112718a86257f7",
    "6a890b7480112718a8625a11",
    "6a890b7280112718a8625a10",
    "6a890a8b7222c0f5f33a2d35",
    "6a890a837222c0f5f33a2d34",
    "6a890acfc71bd4a3dfb45c1b",
    "6a890acd80112718a8625a09",
    "6a890ab05ce3a5d9847bea66",
    "6a890aae5ce3a5d9847bea65",
    "6a890ac580112718a8625a08",
    "6a890ac37222c0f5f33a2d37",
]

REPORTE = Path(__file__).resolve().parent / "BORRADOS_PRODUCCION_ORDENADOS.txt"

logs = []
def log(msg):
    print(msg)
    logs.append(msg)

log("=" * 100)
log("ANALISIS DE BORRADOS DE PRODUCCION - ORDENADOS POR FECHA")
log("=" * 100)
log(f"Total IDs a revisar: {len(IDS_BUSCADOS)}")
log(f"Generado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

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
    db = client["miBase"]
    log("[OK] MongoDB conectado")
except Exception as e:
    log(f"[ERROR] Conexion fallida: {e}")
    with open(REPORTE, "w", encoding="utf-8") as f:
        f.write("\n".join(logs))
    sys.exit(1)

log("\n" + "=" * 100)
log("METODOLOGIA DE BUSQUEDA POR CADA ID BORRADO:")
log("  1) Ver si aun EXISTE en db.produccion (quizas no se borro realmente)")
log("  2) Buscar en db.produccion_historica por _id (si fue movido al corte mensual)")
log("  3) Buscar en db.produccion_historica / db.produccion por OTROS campos similares")
log("  4) Extraer fecha del ObjectId (timestamp embebido en los primeros 4 bytes)")
log("=" * 100)

resultados = []

for id_str in IDS_BUSCADOS:
    info = OrderedDict()
    info["id_borrado"] = id_str

    # Fecha desde ObjectId
    try:
        oid = ObjectId(id_str)
        ts = oid.generation_time
        info["fecha_estimada_desde_ID"] = ts.strftime("%Y-%m-%d %H:%M:%S UTC")
        dt_local = ts
    except Exception:
        info["fecha_estimada_desde_ID"] = "N/A"
        dt_local = None

    # 1) Existe aun en produccion?
    try:
        reg_act = db.produccion.find_one({"_id": ObjectId(id_str)})
    except Exception:
        reg_act = None
    if reg_act:
        info["ubicacion_actual"] = "TODAVIA EXISTE en db.produccion (no se borro)"
        info["codigo_pieza"] = reg_act.get("codigo_pieza")
        info["usuario"] = reg_act.get("usuario")
        info["modo"] = reg_act.get("modo")
        info["box"] = reg_act.get("box")
        info["empresa"] = reg_act.get("empresa")
        info["marco"] = reg_act.get("marco")
        info["tramo"] = reg_act.get("tramo")
        info["ci"] = reg_act.get("cuerda_interna")
        info["ce"] = reg_act.get("cuerda_externa")
        info["flecha"] = reg_act.get("flecha")
        info["fecha_reg"] = reg_act.get("fecha")
    else:
        # 2) Buscar en produccion_historica por _id
        try:
            reg_hist = db.produccion_historica.find_one({"_id": ObjectId(id_str)})
        except Exception:
            reg_hist = None
        if reg_hist:
            info["ubicacion_actual"] = "EXISTE en db.produccion_historica (fue movido a corte mensual)"
            info["codigo_pieza"] = reg_hist.get("codigo_pieza")
            info["usuario"] = reg_hist.get("usuario")
            info["modo"] = reg_hist.get("modo")
            info["box"] = reg_hist.get("box")
            info["empresa"] = reg_hist.get("empresa")
            info["marco"] = reg_hist.get("marco")
            info["tramo"] = reg_hist.get("tramo")
            info["ci"] = reg_hist.get("cuerda_interna")
            info["ce"] = reg_hist.get("cuerda_externa")
            info["flecha"] = reg_hist.get("flecha")
            info["fecha_reg"] = reg_hist.get("fecha")
            info["corte_id"] = str(reg_hist.get("corte_id")) if reg_hist.get("corte_id") else None
        else:
            # 3) Borrado completamente - buscar solo datos desde ObjectId timestamp
            info["ubicacion_actual"] = "BORRADO COMPLETAMENTE (no esta en activa ni historica)"
            info["codigo_pieza"] = None
            info["usuario"] = None
            info["modo"] = None
            info["box"] = None

    # Convertir fechas a string
    for k in ["fecha_reg"]:
        if isinstance(info.get(k), datetime):
            info[k] = info[k].strftime("%Y-%m-%d %H:%M:%S UTC")

    info["_sort_key"] = dt_local or datetime.min
    resultados.append(info)

# Ordenar por fecha (mas antiguos primero, o mas recientes primero)
resultados.sort(key=lambda r: r["_sort_key"], reverse=True)  # MAS RECIENTES PRIMERO

log(f"\n" + "=" * 100)
log(f"RESULTADOS ORDENADOS - {len(resultados)} IDs analizados")
log("=" * 100)

# Contadores
contadores = {
    "todavia_existe": 0,
    "en_historico": 0,
    "borrado_total": 0,
}
codigos_borrados_real = []

for i, r in enumerate(resultados, 1):
    log("\n" + "-" * 100)
    titulo = f"[{i}] ID: {r['id_borrado']}"
    log(titulo)

    ubic = r.get("ubicacion_actual", "")
    if "TODAVIA EXISTE" in ubic:
        contadores["todavia_existe"] += 1
        log(f"  ESTADO:    🟢 {ubic}")
    elif "EXISTE en historica" in ubic:
        contadores["en_historico"] += 1
        log(f"  ESTADO:    🟡 {ubic}")
    else:
        contadores["borrado_total"] += 1
        codigos_borrados_real.append(r)
        log(f"  ESTADO:    🔴 {ubic}")

    log(f"  FECHA ID:  {r.get('fecha_estimada_desde_ID', 'N/A')}")
    log(f"  CODIGO:    {r.get('codigo_pieza', 'N/A')}")
    log(f"  USUARIO:   {r.get('usuario', 'N/A')}")
    log(f"  MODO:      {r.get('modo', 'N/A')}")
    log(f"  BOX:       {r.get('box', 'N/A')}")
    if r.get("empresa"):
        log(f"  EMPRESA:   {r.get('empresa')}")
    if r.get("marco"):
        log(f"  MARCO:     {r.get('marco')}")
    if r.get("tramo"):
        log(f"  TRAMO:     {r.get('tramo')}")
    if r.get("ci") is not None or r.get("ce") is not None:
        log(f"  MEDIDAS:   CI={r.get('ci')} | CE={r.get('ce')} | Flecha={r.get('flecha')}")
    if r.get("fecha_reg"):
        log(f"  FECHA REG: {r.get('fecha_reg')}")
    if r.get("corte_id"):
        log(f"  CORTE ID:  {r.get('corte_id')}")

log("\n" + "=" * 100)
log("RESUMEN")
log("=" * 100)
log(f"  IDs analizados:                         {len(resultados)}")
log(f"  🟢 Aun existen en db.produccion:         {contadores['todavia_existe']}")
log(f"  🟡 Están en db.produccion_historica:     {contadores['en_historico']}")
log(f"  🔴 BORRADOS COMPLETAMENTE (irrecuperables por BD): {contadores['borrado_total']}")

if codigos_borrados_real:
    log("\n" + "=" * 100)
    log("🔴 DETALLE DE BORRADOS COMPLETOS (irrecuperables sin backup)")
    log("=" * 100)
    log("Estos registros NO EXISTEN en produccion activa NI en historica.")
    log("Solo pueden ser recuperados desde un BACKUP de MongoDB.\n")
    for i, r in enumerate(codigos_borrados_real, 1):
        log(f"  [{i}] ID: {r['id_borrado']}")
        log(f"      Fecha estimada borrado: {r.get('fecha_estimada_desde_ID', 'N/A')}")
        if r.get('codigo_pieza'):
            log(f"      Codigo asociado (por otros campos): {r.get('codigo_pieza')}")
        if r.get('usuario'):
            log(f"      Operador: {r.get('usuario')}")
        log("")

log("\n📝 NOTA IMPORTANTE SOBRE EL i4237:")
log("El ID del registro de produccion BORRADO de i4237 no aparece en este listado,")
log("porque el grep de gunicorn_access.log solo trajo los ultimos 30 /delete.")
log("Para buscar SOLO los borrados del codigo i4237, tenemos que filtrar en los logs")
log("o revisar el rango horario exacto en que ocurrio.")

with open(REPORTE, "w", encoding="utf-8") as f:
    f.write("\n".join(logs))

client.close()
log(f"\n[OK] Reporte guardado en: {REPORTE}")
