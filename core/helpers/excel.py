from io import BytesIO

import pandas as pd
from flask import send_file


def send_excel_file(data, sheet_name, download_name):
    """Genera y retorna un archivo Excel a partir de una lista de diccionarios."""
    df = pd.DataFrame(data)
    output = BytesIO()
    with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
        df.to_excel(writer, index=False, sheet_name=sheet_name)
    output.seek(0)
    return send_file(
        output,
        download_name=download_name,
        as_attachment=True,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )
