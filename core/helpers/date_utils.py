from datetime import datetime, timezone
import zoneinfo


CL = zoneinfo.ZoneInfo("America/Santiago")


def now_cl():
    """Devuelve la fecha/hora actual en Chile, siempre timezone-aware."""
    return datetime.now(timezone.utc).astimezone(CL)


def to_cl(dt):
    """Convierte un datetime almacenado en UTC a la zona horaria de Chile."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(CL)


def build_date_range_utc(fecha_inicio=None, fecha_fin=None):
    """Convierte un rango de fechas local Chile a UTC para consultas Mongo."""
    start_utc = None
    end_utc = None

    if fecha_inicio:
        d1 = datetime.strptime(fecha_inicio, "%Y-%m-%d").date()
        start_cl = datetime.combine(d1, datetime.min.time()).replace(tzinfo=CL)
        start_utc = start_cl.astimezone(timezone.utc)

    if fecha_fin:
        d2 = datetime.strptime(fecha_fin, "%Y-%m-%d").date()
        end_cl = datetime.combine(d2, datetime.max.time()).replace(tzinfo=CL)
        end_utc = end_cl.astimezone(timezone.utc)

    return start_utc, end_utc


def apply_date_range_filter(filtro, fecha_inicio=None, fecha_fin=None, field_name="fecha", end_operator="$lte"):
    """Aplica un rango de fechas UTC a un filtro Mongo si hay valores informados."""
    start_utc, end_utc = build_date_range_utc(fecha_inicio, fecha_fin)
    rango = {}
    if start_utc:
        rango["$gte"] = start_utc
    if end_utc:
        rango[end_operator] = end_utc
    if rango:
        filtro[field_name] = rango
    return filtro
