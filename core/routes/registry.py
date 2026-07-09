import os

from core.helpers import auth as auth_helpers
from core.helpers import reporting as reporting_helpers
from core.helpers.codigo import build_codigo_lookup_keys, build_codigo_query_values
from core.helpers.config_store import get_label_print_confirm_limit
from core.helpers.excel import send_excel_file
from core.helpers.pagination import (
    DEFAULT_PER_PAGE,
    build_pagination,
    normalize_page as _normalize_page,
    paginate_list,
)
from core.routes.admin_config_routes import register_admin_config_routes
from core.routes.admin_crud_routes import register_admin_crud_routes
from core.routes.admin_dashboard_routes import register_admin_dashboard_routes
from core.routes.admin_informes_avanzados_routes import register_admin_informes_avanzados_routes
from core.routes.admin_informes_operacion_routes import register_admin_informes_operacion_routes
from core.routes.admin_informes_routes import register_admin_informes_routes
from core.routes.admin_produccion_routes import register_admin_produccion_routes
from core.routes.admin_tools_routes import register_admin_tools_routes
from core.routes.auth_routes import register_auth_routes
from core.routes.operator_routes import register_operator_routes
from core.routes.soporte_archivados_routes import register_soporte_archivados_routes
from core.routes.soporte_basic_routes import register_soporte_basic_routes
from core.routes.soporte_produccion_routes import register_soporte_produccion_routes
from core.routes.supervisor_routes import register_supervisor_routes


def _get_default_label_print_confirm_limit():
    try:
        return max(1, int(os.getenv("LABEL_PRINT_CONFIRM_LIMIT", "100")))
    except (TypeError, ValueError):
        return 100


def register_all_routes(app, db, runtime_state, log_audit):
    """Registra todos los modulos de rutas sobre la app Flask."""

    default_label_print_confirm_limit = _get_default_label_print_confirm_limit()
    login_required = auth_helpers.build_login_required(db)

    register_auth_routes(app, db, login_required, runtime_state["login_attempts"])
    register_admin_config_routes(app, db, login_required, default_label_print_confirm_limit)
    register_admin_crud_routes(
        app,
        db,
        login_required,
        _normalize_page,
        build_pagination,
        DEFAULT_PER_PAGE,
    )
    register_admin_informes_routes(
        app,
        db,
        login_required,
        reporting_helpers.get_production_status_map,
        reporting_helpers.build_tarjetas_grupos,
    )
    register_admin_informes_operacion_routes(
        app,
        db,
        login_required,
        _normalize_page,
        build_pagination,
        paginate_list,
        DEFAULT_PER_PAGE,
        send_excel_file,
        reporting_helpers.get_operator_report_rows,
    )
    register_admin_informes_avanzados_routes(
        app,
        db,
        login_required,
        _normalize_page,
        paginate_list,
        reporting_helpers.build_piezas_map,
        build_codigo_lookup_keys,
        reporting_helpers.get_estado_piezas_dataset,
        reporting_helpers.apply_exact_codigo_filter,
        reporting_helpers.get_production_status_map,
        reporting_helpers.build_tarjetas_grupos,
        send_excel_file,
    )
    register_admin_dashboard_routes(app, db, login_required)
    register_admin_produccion_routes(
        app,
        db,
        login_required,
        _normalize_page,
        build_pagination,
        paginate_list,
        DEFAULT_PER_PAGE,
        send_excel_file,
    )
    register_admin_tools_routes(
        app,
        db,
        login_required,
        _normalize_page,
        paginate_list,
        send_excel_file,
    )
    register_operator_routes(
        app,
        db,
        login_required,
        _normalize_page,
        paginate_list,
        lambda: runtime_state["tunnel_url"],
    )
    register_soporte_basic_routes(
        app,
        db,
        login_required,
        _normalize_page,
        paginate_list,
        reporting_helpers.get_piece_status_sets,
        reporting_helpers.get_latest_production_map,
        build_codigo_lookup_keys,
        build_codigo_query_values,
        get_label_print_confirm_limit,
        default_label_print_confirm_limit,
    )
    register_soporte_archivados_routes(
        app,
        db,
        login_required,
        _normalize_page,
        build_pagination,
        DEFAULT_PER_PAGE,
        log_audit,
    )
    register_soporte_produccion_routes(app, db, login_required)
    register_supervisor_routes(app, db, login_required, _normalize_page, paginate_list)
