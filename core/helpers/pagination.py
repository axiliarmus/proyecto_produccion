from flask import request, url_for


DEFAULT_PER_PAGE = 50


def normalize_page(value):
    """Normaliza el numero de pagina recibido por querystring."""
    try:
        page = int(value)
    except (TypeError, ValueError):
        page = 1
    return max(page, 1)


def build_pagination(route_name, page, total_items, per_page=DEFAULT_PER_PAGE, **params):
    """Construye la metadata y URLs necesarias para paginar vistas."""
    total_pages = max((total_items + per_page - 1) // per_page, 1)
    page = min(max(page, 1), total_pages)
    clean_params = {k: v for k, v in params.items() if v is not None and v != ""}

    start_item = 0 if total_items == 0 else ((page - 1) * per_page) + 1
    end_item = min(page * per_page, total_items)

    window_start = max(1, page - 2)
    window_end = min(total_pages, page + 2)
    pages = []
    for number in range(window_start, window_end + 1):
        pages.append({
            "number": number,
            "url": url_for(route_name, page=number, **clean_params),
            "active": number == page
        })

    first_page_url = url_for(route_name, page=1, **clean_params) if window_start > 1 else None
    last_page_url = url_for(route_name, page=total_pages, **clean_params) if window_end < total_pages else None

    return {
        "page": page,
        "per_page": per_page,
        "total_items": total_items,
        "total_pages": total_pages,
        "start_item": start_item,
        "end_item": end_item,
        "pages": pages,
        "first_page_url": first_page_url,
        "last_page_url": last_page_url,
        "prev_url": url_for(route_name, page=page - 1, **clean_params) if page > 1 else None,
        "next_url": url_for(route_name, page=page + 1, **clean_params) if page < total_pages else None,
    }


def paginate_list(items, route_name, page=None, per_page=DEFAULT_PER_PAGE, **params):
    """Pagina listas construidas en memoria manteniendo filtros en la URL."""
    page = normalize_page(page if page is not None else request.args.get("page", 1))
    total_items = len(items)
    total_pages = max((total_items + per_page - 1) // per_page, 1)
    page = min(page, total_pages)
    start = (page - 1) * per_page
    end = start + per_page
    paginated_items = items[start:end]
    pagination = build_pagination(route_name, page, total_items, per_page=per_page, **params)
    return paginated_items, pagination
