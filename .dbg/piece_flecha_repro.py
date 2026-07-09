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
piece = db.piezas.find_one()
assert user and piece, "faltan user/piece"

client = app.test_client()
with client.session_transaction() as session_state:
    session_state["user_id"] = str(user["_id"])
    session_state["role"] = user["tipo"]
    session_state["nombre"] = user.get("nombre", user["usuario"])
    session_state["username"] = user["usuario"]

edit_url = f"/admin/piezas/{piece['_id']}/editar"
resp = client.get(edit_url)
html = resp.get_data(as_text=True)
token = re.search(r'name="_csrf_token" value="([^"]+)"', html).group(1)
old_flecha = piece.get("flecha")
new_val = 98.76 if old_flecha != 98.76 else 87.65

payload = {
    "_csrf_token": token,
    "empresa": piece.get("empresa", ""),
    "marco": piece.get("marco", ""),
    "tramo": piece.get("tramo", ""),
    "tipo_precio": piece.get("tipo_precio", "metro"),
    "kilo_pieza": str(piece.get("kilo_pieza", 0)),
    "cuerda_interna": "" if piece.get("cuerda_interna") is None else str(piece.get("cuerda_interna")),
    "cuerda_externa": "" if piece.get("cuerda_externa") is None else str(piece.get("cuerda_externa")),
    "flecha": str(new_val),
}

post = client.post(edit_url, data=payload, follow_redirects=False)
updated = db.piezas.find_one({"_id": piece["_id"]})
list_resp = client.get("/admin/piezas")
list_html = list_resp.get_data(as_text=True)

masivo_get = client.get("/admin/piezas/masivo")
masivo_html = masivo_get.get_data(as_text=True)
masivo_token = re.search(r'name="_csrf_token" value="([^"]+)"', masivo_html).group(1)
masivo_search = client.post(
    "/admin/piezas/masivo",
    data={
        "_csrf_token": masivo_token,
        "empresa": piece.get("empresa", ""),
        "marco": piece.get("marco", ""),
        "tramo": piece.get("tramo", ""),
    },
    follow_redirects=True,
)
masivo_search_html = masivo_search.get_data(as_text=True)
masivo_search_token = re.search(r'name="_csrf_token" value="([^"]+)"', masivo_search_html).group(1)
mass_val = 77.77 if updated.get("flecha") != 77.77 else 66.66
mass_post = client.post(
    "/admin/piezas/masivo/confirmar",
    data={
        "_csrf_token": masivo_search_token,
        "filtros": json.dumps({"codigo": updated.get("codigo")}),
        "campo": "flecha",
        "valor": str(mass_val),
    },
    follow_redirects=False,
)
updated_after_mass = db.piezas.find_one({"_id": piece["_id"]})

print(
    json.dumps(
        {
            "piece_id": str(piece["_id"]),
            "codigo": updated.get("codigo"),
            "status_get": resp.status_code,
            "status_post": post.status_code,
            "location": post.headers.get("Location"),
            "old_flecha": old_flecha,
            "new_flecha_db": updated.get("flecha"),
            "list_contains_value": str(new_val) in list_html,
            "list_has_flecha_header": "Flecha" in list_html,
            "mass_status_get": masivo_get.status_code,
            "mass_search_status": masivo_search.status_code,
            "mass_status_post": mass_post.status_code,
            "mass_location": mass_post.headers.get("Location"),
            "mass_flecha_db": updated_after_mass.get("flecha"),
            "mass_has_flecha_option": '<option value=\"flecha\">Flecha</option>' in masivo_search_html,
        },
        default=str,
    )
)
