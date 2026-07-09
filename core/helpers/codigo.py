def build_codigo_query_values(codigos):
    """Genera variantes seguras de codigo para consultas donde hay mezcla int/str."""
    values = set()
    for codigo in codigos or []:
        if codigo in (None, ""):
            continue
        codigo_str = str(codigo).strip()
        if not codigo_str:
            continue
        values.add(codigo)
        values.add(codigo_str)
        if codigo_str.isdigit():
            try:
                values.add(int(codigo_str))
                values.add(str(int(codigo_str)))
            except (TypeError, ValueError):
                pass
    return list(values)


def build_codigo_lookup_keys(codigo):
    """Normaliza un codigo a una o mas claves comparables en memoria."""
    keys = set()
    if codigo in (None, ""):
        return keys
    codigo_str = str(codigo).strip()
    if not codigo_str:
        return keys
    keys.add(codigo_str)
    if codigo_str.isdigit():
        try:
            keys.add(str(int(codigo_str)))
        except (TypeError, ValueError):
            pass
    return keys
