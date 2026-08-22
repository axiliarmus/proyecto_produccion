import os
from pathlib import Path
from dotenv import load_dotenv
from pymongo import MongoClient
from datetime import datetime

project_root = Path(__file__).resolve().parent
load_dotenv(project_root / ".env")
mongo_uri = os.getenv("MONGO_URI")
client = MongoClient(mongo_uri)
db = client["miBase"]

print("=" * 70)
print("BD LOCAL - ESTADO para probar restaurar_registro_produccion.py")
print("=" * 70)

print("\nPiezas ACTIVAS en db.piezas:")
for p in db.piezas.find({}).sort("codigo", 1):
    regs = db.produccion.count_documents({"codigo_pieza": p.get("codigo")})
    regs_h = db.produccion_historica.count_documents({"codigo_pieza": p.get("codigo")})
    print(f"  codigo={p.get('codigo'):10s} | estado={str(p.get('estado','?')):20s} | regs_activos={regs} | regs_historicos={regs_h}")

print("\nBusco un codigo que tenga regs activos para probar:")
prueba_cod = None
for p in db.piezas.find({}).sort("codigo", 1):
    cod = p.get("codigo")
    if cod and db.produccion.count_documents({"codigo_pieza": cod}) > 0:
        prueba_cod = cod
        reg = db.produccion.find_one({"codigo_pieza": cod}, sort=[("fecha", -1)])
        print(f"  Usando codigo de prueba: {cod}")
        print(f"  Ultimo registro activo: _id={reg['_id']} fecha={reg.get('fecha')} usuario={reg.get('usuario')} modo={reg.get('modo')}")
        # Guardo el ID para simular el borrado
        id_borrar = reg["_id"]
        print(f"\nSIMULANDO BORRADO ACCIDENTAL: db.produccion.delete_one(_id={id_borrar})")
        db.produccion.delete_one({"_id": id_borrar})
        regs_despues = db.produccion.count_documents({"codigo_pieza": cod})
        print(f"  Registros activos DESPUES del borrado: {regs_despues}")
        print(f"\nAHORA EJECUTA:")
        print(f"  python restaurar_registro_produccion.py {cod}")
        print(f"\nY luego para confirmar:")
        print(f"  python restaurar_registro_produccion.py {cod} --confirmar")
        break

if not prueba_cod:
    print("  No hay codigos con registros activos para probar.")

client.close()
