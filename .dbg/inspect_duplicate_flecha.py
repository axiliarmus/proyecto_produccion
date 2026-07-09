import json
import os
from collections import defaultdict

from dotenv import load_dotenv
from pymongo import MongoClient

load_dotenv()
db = MongoClient(os.getenv("MONGO_URI"))["miBase"]

rows = list(
    db.piezas.find(
        {},
        {
            "_id": 1,
            "codigo": 1,
            "empresa": 1,
            "marco": 1,
            "tramo": 1,
            "flecha": 1,
            "cuerda_interna": 1,
            "cuerda_externa": 1,
        },
    )
)

grouped = defaultdict(list)
for row in rows:
    if row.get("codigo"):
        grouped[row["codigo"]].append(row)

duplicates = []
for codigo, items in grouped.items():
    if len(items) > 1:
        duplicates.append(
            {
                "codigo": codigo,
                "count": len(items),
                "items": [
                    {
                        "_id": str(item.get("_id")),
                        "empresa": item.get("empresa"),
                        "marco": item.get("marco"),
                        "tramo": item.get("tramo"),
                        "flecha": item.get("flecha"),
                        "cuerda_interna": item.get("cuerda_interna"),
                        "cuerda_externa": item.get("cuerda_externa"),
                    }
                    for item in items
                ],
            }
        )

print(json.dumps({"duplicate_count": len(duplicates), "duplicates": duplicates[:20]}, default=str))
