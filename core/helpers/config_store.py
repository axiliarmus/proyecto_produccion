def get_config_value(config_collection, key, default=None):
    """Obtiene un valor persistente desde la colección de configuración."""
    conf = config_collection.find_one({"key": key}, {"value": 1, "_id": 0})
    if not conf:
        return default
    return conf.get("value", default)


def set_config_value(config_collection, key, value):
    """Guarda un valor persistente en la colección de configuración."""
    config_collection.update_one({"key": key}, {"$set": {"value": value}}, upsert=True)


def get_label_print_confirm_limit(config_collection, default_limit=100):
    """Resuelve el límite de confirmación para impresión de etiquetas."""
    value = get_config_value(config_collection, "label_print_confirm_limit", None)
    if value in (None, ""):
        return default_limit
    try:
        return max(1, int(value))
    except (TypeError, ValueError):
        return default_limit
