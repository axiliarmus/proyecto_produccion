"""Generacion de archivos Excel con un formato comun y profesional para todos los informes."""
import re
from datetime import datetime
from io import BytesIO

import xlsxwriter
from flask import send_file

from core.helpers.date_utils import now_cl

MIMETYPE_XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

COLOR_TITULO = "#312E81"      # indigo oscuro
COLOR_ENCABEZADO = "#4F46E5"  # indigo
COLOR_ZEBRA = "#F3F4F6"
COLOR_TOTAL = "#E0E7FF"
COLOR_BORDE = "#D1D5DB"

# Columnas cuyo nombre indica dinero, medidas o cantidades (se detectan por el encabezado).
_DINERO = ("valor (", "precio", "total ($", "monto")
_MEDIDA = ("peso", "kilo", "cuerda", "flecha")
_CANTIDAD = ("cantidad", "ingresado", "producido", "pendiente", "solo armadas", "sin fabricar", "registros")
_ESTADO = ("estado", "calidad", "visto bueno")

_FECHAS = (
    (re.compile(r"^\d{2}-\d{2}-\d{4} \d{2}:\d{2}$"), "%d-%m-%Y %H:%M", "dd-mm-yyyy hh:mm", 16),
    (re.compile(r"^\d{2}/\d{2}/\d{4} \d{2}:\d{2}$"), "%d/%m/%Y %H:%M", "dd/mm/yyyy hh:mm", 16),
    (re.compile(r"^\d{2}-\d{2}-\d{4}$"), "%d-%m-%Y", "dd-mm-yyyy", 12),
    (re.compile(r"^\d{2}:\d{2}$"), "%H:%M", "hh:mm", 8),
)


def _nombre_hoja(nombre):
    limpio = re.sub(r"[\[\]:*?/\\]", "", str(nombre or "")).strip()
    return (limpio or "Informe")[:31]


def _titulo_desde_archivo(download_name):
    base = re.sub(r"\.xlsx$", "", str(download_name or ""), flags=re.I)
    texto = re.sub(r"[_\-]+", " ", base).strip()
    return texto[:1].upper() + texto[1:] if texto else "Informe"


def _es_total(fila):
    return any(isinstance(v, str) and v.strip().upper() == "TOTAL" for v in fila)


def _fecha(valor):
    """(datetime|time, formato_excel, ancho) si el texto es una fecha/hora conocida; si no, None."""
    if not isinstance(valor, str):
        return None
    for patron, formato_py, formato_xl, ancho in _FECHAS:
        if patron.match(valor):
            try:
                parsed = datetime.strptime(valor, formato_py)
            except ValueError:
                return None
            return (parsed.time() if formato_py == "%H:%M" else parsed), formato_xl, ancho
    return None


def _numero(valor):
    return isinstance(valor, (int, float)) and not isinstance(valor, bool)


def _es_codigo(encabezado):
    h = encabezado.lower()
    return any(p in h for p in ("código", "codigo", "tramo", "box", "marco", "cliente", "año"))


def build_excel_bytes(data, sheet_name, columns=None, title=None, subtitle=None):
    """Construye el libro Excel y devuelve su contenido en bytes."""
    filas = list(data or [])
    if columns:
        columnas = list(columns)
    else:
        columnas = []
        for fila in filas:
            for clave in fila:
                if clave not in columnas:
                    columnas.append(clave)

    output = BytesIO()
    libro = xlsxwriter.Workbook(output, {"in_memory": True, "nan_inf_to_errors": True})
    libro.set_properties({"title": title or sheet_name, "author": "Sistema de Producción", "created": datetime.now()})
    hoja = libro.add_worksheet(_nombre_hoja(sheet_name))
    hoja.hide_gridlines(2)

    cache = {}

    def fmt(**props):
        base = {"font_name": "Calibri", "font_size": 10, "valign": "vcenter"}
        base.update(props)
        clave = tuple(sorted(base.items()))
        if clave not in cache:
            cache[clave] = libro.add_format(base)
        return cache[clave]

    n_cols = max(len(columnas), 1)
    registros = sum(1 for f in filas if not _es_total(f.values()))

    # ---------- titulo ----------
    fila_actual = 0
    f_titulo = fmt(bold=True, font_size=16, font_color="#FFFFFF", bg_color=COLOR_TITULO, indent=1)
    f_sub = fmt(font_size=10, font_color="#E0E7FF", bg_color=COLOR_TITULO, indent=1, italic=True)
    texto_titulo = title or str(sheet_name)
    detalle = subtitle or ""
    generado = f"Generado el {now_cl():%d-%m-%Y %H:%M} · {registros:,} registro{'s' if registros != 1 else ''}".replace(",", ".")
    texto_sub = f"{detalle} · {generado}" if detalle else generado
    for texto, formato, alto in ((texto_titulo, f_titulo, 28), (texto_sub, f_sub, 18)):
        if n_cols > 1:
            hoja.merge_range(fila_actual, 0, fila_actual, n_cols - 1, texto, formato)
        else:
            hoja.write(fila_actual, 0, texto, formato)
        hoja.set_row(fila_actual, alto)
        fila_actual += 1
    fila_actual += 1  # separacion

    # ---------- encabezado ----------
    fila_encabezado = fila_actual
    f_head = fmt(bold=True, font_color="#FFFFFF", bg_color=COLOR_ENCABEZADO, align="center", text_wrap=True,
                 border=1, border_color=COLOR_BORDE)
    for c, nombre in enumerate(columnas):
        hoja.write(fila_encabezado, c, nombre, f_head)
    hoja.set_row(fila_encabezado, 30)

    # ---------- tipo de cada columna ----------
    info = []
    for nombre in columnas:
        h = str(nombre).lower()
        valores = [f.get(nombre) for f in filas if not _es_total(f.values())]
        no_vacios = [v for v in valores if v not in (None, "")]
        numericos = [v for v in no_vacios if _numero(v)]
        solo_numeros = bool(no_vacios) and len(numericos) == len(no_vacios)
        decimales = any(isinstance(v, float) and v != int(v) for v in numericos if v == v)
        tipo = "texto"
        formato_num = None
        if solo_numeros and not _es_codigo(h):
            if any(p in h for p in _DINERO) or (h.strip() in ("total", "total ($)") ):
                tipo, formato_num = "dinero", '"$"#,##0.00' if decimales else '"$"#,##0'
            elif any(p in h for p in _MEDIDA) or decimales:
                tipo, formato_num = "medida", "#,##0.00"
            elif any(p in h for p in _CANTIDAD):
                tipo, formato_num = "cantidad", "#,##0"
            else:
                tipo, formato_num = "numero", "General"
        elif solo_numeros:
            tipo, formato_num = "codigo", "0"
        info.append({"tipo": tipo, "num": formato_num, "ancho": max(len(str(nombre)) + 2, 8)})

    # ---------- datos ----------
    primera_fila_datos = fila_encabezado + 1
    for i, fila in enumerate(filas):
        r = primera_fila_datos + i
        total = _es_total(fila.values())
        zebra = (i % 2 == 1) and not total
        for c, nombre in enumerate(columnas):
            valor = fila.get(nombre)
            props = {"border": 1, "border_color": COLOR_BORDE}
            if zebra:
                props["bg_color"] = COLOR_ZEBRA
            if total:
                props.update(bold=True, bg_color=COLOR_TOTAL, top=2, top_color=COLOR_TITULO)
            tipo = info[c]["tipo"]

            if valor is None or (isinstance(valor, float) and valor != valor):
                hoja.write_blank(r, c, None, fmt(**props))
                continue
            if _numero(valor):
                formato = info[c]["num"] if tipo in ("dinero", "medida", "cantidad", "numero", "codigo") else "General"
                hoja.write_number(r, c, valor, fmt(num_format=formato, align="right", **props))
                info[c]["ancho"] = max(info[c]["ancho"], len(f"{valor:,.2f}") + (2 if tipo == "dinero" else 0))
                continue
            fecha = _fecha(valor)
            if fecha:
                dt, formato_xl, ancho = fecha
                hoja.write_datetime(r, c, dt, fmt(num_format=formato_xl, align="center", **props))
                info[c]["ancho"] = max(info[c]["ancho"], ancho)
                continue
            texto = str(valor)
            hoja.write_string(r, c, texto, fmt(align="left", **props))
            info[c]["ancho"] = max(info[c]["ancho"], min(len(texto) + 2, 48))

    ultima_fila = primera_fila_datos + max(len(filas), 1) - 1
    if not filas:
        f_vacio = fmt(italic=True, font_color="#6B7280", align="center")
        mensaje = "Sin registros"
        if n_cols > 1:
            hoja.merge_range(primera_fila_datos, 0, primera_fila_datos, n_cols - 1, mensaje, f_vacio)
        else:
            hoja.write(primera_fila_datos, 0, mensaje, f_vacio)

    # ---------- anchos, filtros, congelado, estados ----------
    anchos = [min(max(datos["ancho"], 9), 50) for datos in info]
    if anchos and sum(anchos) < 64:
        anchos[-1] += 64 - sum(anchos)   # el titulo y el subtitulo necesitan un minimo de ancho
    for c, ancho in enumerate(anchos):
        hoja.set_column(c, c, ancho)
    if filas:
        hoja.autofilter(fila_encabezado, 0, ultima_fila, n_cols - 1)
        verde = libro.add_format({"bg_color": "#D1FAE5", "font_color": "#065F46", "bold": True})
        ambar = libro.add_format({"bg_color": "#FEF3C7", "font_color": "#92400E", "bold": True})
        rojo = libro.add_format({"bg_color": "#FEE2E2", "font_color": "#991B1B", "bold": True})
        for c, nombre in enumerate(columnas):
            if not any(p in str(nombre).lower() for p in _ESTADO):
                continue
            rango = (primera_fila_datos, c, ultima_fila, c)
            for texto, formato in (("Sin producci", rojo), ("Rechazad", rojo), ("Malo", rojo), ("Falta", rojo),
                                   ("Rematad", verde), ("Aprobad", verde), ("Completo", verde), ("OK", verde),
                                   ("Armad", ambar), ("Por verificar", ambar), ("Pendiente", ambar)):
                hoja.conditional_format(*rango, {"type": "text", "criteria": "containing", "value": texto, "format": formato})
    hoja.freeze_panes(primera_fila_datos, 0)

    # ---------- impresion ----------
    hoja.set_landscape()
    hoja.set_paper(9)
    hoja.fit_to_pages(1, 0)
    hoja.repeat_rows(fila_encabezado)
    hoja.set_margins(left=0.4, right=0.4, top=0.6, bottom=0.6)
    hoja.set_footer("&LSistema de Producción&RPágina &P de &N")

    libro.close()
    return output.getvalue()


def send_excel_file(data, sheet_name, download_name, columns=None, title=None, subtitle=None):
    """Genera y retorna un archivo Excel formateado a partir de una lista de diccionarios.

    `title` y `subtitle` encabezan la hoja (por defecto el titulo sale del nombre del archivo).
    """
    contenido = build_excel_bytes(
        data, sheet_name, columns=columns, title=title or _titulo_desde_archivo(download_name), subtitle=subtitle)
    return send_file(
        BytesIO(contenido),
        download_name=download_name,
        as_attachment=True,
        mimetype=MIMETYPE_XLSX,
    )
