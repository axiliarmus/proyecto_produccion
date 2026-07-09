import json
import os
import re
import sys
from pathlib import Path

from dotenv import load_dotenv
from pymongo import MongoClient

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app import app


load_dotenv()
db = MongoClient(os.getenv("MONGO_URI"))["miBase"]
user = db.usuarios.find_one({"tipo": {"$in": ["soporte", "administrador"]}})
piece = db.piezas.find_one({"flecha": {"$ne": None}})
assert user and piece, "faltan user/piece"

client = app.test_client()
with client.session_transaction() as session_state:
    session_state["user_id"] = str(user["_id"])
    session_state["role"] = user["tipo"]
    session_state["nombre"] = user.get("nombre", user["usuario"])
    session_state["username"] = user["usuario"]

resp = client.get(
    "/soporte/etiquetas",
    query_string={
        "cliente": piece.get("empresa", ""),
        "marco": piece.get("marco", ""),
        "tramo": piece.get("tramo", ""),
        "estado": "todos",
    },
)
html = resp.get_data(as_text=True)

codigo = piece.get("codigo")
pattern = rf'data-codigo="{re.escape(str(codigo))}"[\s\S]*?data-flecha="([^"]*)"'
match = re.search(pattern, html)
js_match = re.search(r"const piezasImpresion = (\[.*?\]);", html, re.S)

payload_sample = None
if js_match:
    try:
        payload = json.loads(js_match.group(1))
        payload_sample = next((item for item in payload if str(item.get("codigo")) == str(codigo)), None)
    except Exception:
        payload_sample = "json_parse_error"

print(
    json.dumps(
        {
            "codigo": codigo,
            "pieza_db": {
                "empresa": piece.get("empresa"),
                "marco": piece.get("marco"),
                "tramo": piece.get("tramo"),
                "cuerda_interna": piece.get("cuerda_interna"),
                "cuerda_externa": piece.get("cuerda_externa"),
                "flecha": piece.get("flecha"),
            },
            "status": resp.status_code,
            "html_data_flecha": match.group(1) if match else None,
            "payload_sample": payload_sample,
        },
        default=str,
    )
)
