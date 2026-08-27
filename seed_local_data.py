from datetime import datetime

from core.app_factory import create_app, get_db
from werkzeug.security import generate_password_hash


def main():
    app = create_app()
    db = get_db(app)

    db.config.update_one(
        {"key": "ciclo_actual"},
        {"$set": {"key": "ciclo_actual", "value": "a"}},
        upsert=True,
    )

    for b in [
        {"codigo": "1", "nombre": "Box 1"},
        {"codigo": "2", "nombre": "Box 2"},
        {"codigo": "3", "nombre": "Box 3"},
    ]:
        db.boxes.update_one({"codigo": b["codigo"]}, {"$setOnInsert": b}, upsert=True)

    for usuario, nombre in [
        ("op1", "Operador Uno"),
        ("op2", "Operador Dos"),
        ("op3", "Operador Tres"),
    ]:
        if db.usuarios.find_one({"usuario": usuario}):
            continue
        db.usuarios.insert_one(
            {
                "usuario": usuario,
                "nombre": nombre,
                "tipo": "operador",
                "password": generate_password_hash("op123"),
                "password_changed_at": datetime.utcnow(),
                "precio_metro_armado": 1.0,
                "precio_metro_remate": 1.0,
                "precio_avo_armado": 1.0,
                "precio_avo_remate": 1.0,
                "sin_restriccion": True,
            }
        )

    def upsert_pieza(codigo, empresa, marco, tramo):
        db.piezas.update_one(
            {"codigo": codigo},
            {
                "$setOnInsert": {
                    "codigo": codigo,
                    "empresa": empresa,
                    "marco": marco,
                    "tramo": tramo,
                    "kilo_pieza": 1.2,
                    "tipo_precio": "metro",
                    "cuerda_interna": 10.0,
                    "cuerda_externa": 12.0,
                    "flecha": 3.5,
                    "estado_prod": "Sin producción",
                }
            },
            upsert=True,
        )

    for c in range(1001, 1011):
        upsert_pieza(c, "avo", "th1", "t1")
    for c in range(1011, 1016):
        upsert_pieza(c, "avo", "th1", "t2")
    for c in range(2001, 2009):
        upsert_pieza(c, "metro", "mh2", "t1")

    tramos_3_carriles = ["TH1", "TH2", "TH3", "TH4", "TH5", "TH6"]
    start_codigo = 3001
    for idx_tramo, tramo in enumerate(tramos_3_carriles):
        base = start_codigo + (idx_tramo * 20)
        for c in range(base, base + 20):
            upsert_pieza(c, "AVO", "3 CARRILES", tramo)

    print(
        "Seed OK:",
        "piezas=",
        db.piezas.count_documents({}),
        "operadores=",
        db.usuarios.count_documents({"tipo": "operador"}),
        "boxes=",
        db.boxes.count_documents({}),
    )


if __name__ == "__main__":
    main()
