"""Regresiones con rutas reales y Mongo simulado; nunca usa la base de produccion."""
import ast
import secrets
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from bson import ObjectId
from flask import Flask, redirect, request, session, url_for
from jinja2 import Environment, FileSystemLoader
from pymongo.errors import BulkWriteError, OperationFailure

from core.helpers.auth import authenticate_user
from core.helpers.date_utils import InvalidDateRange, build_date_range_utc
from core.helpers.reporting import build_marcos_anual, build_tarjetas_grupos, listar_piezas_marcos_anual
from core.helpers.soft_delete import soft_delete_many, soft_delete_selected_production
from core.routes.admin_planificacion_routes import (
    _build_asignaciones_armado,
    _get_marco_production_stats,
    _unidad_armado,
)
from core.routes.registry import register_all_routes


ROOT = Path(__file__).resolve().parent


class ProjectRegressionTests(unittest.TestCase):
    def setUp(self):
        self.db = MagicMock()
        self.app = Flask(__name__, template_folder=str(ROOT / "templates"))
        self.app.secret_key = "regression-tests-only"
        self.app.testing = True
        register_all_routes(self.app, self.db, {"tunnel_url": None, "login_attempts": {}}, MagicMock())
        tree = ast.parse((ROOT / "core/app_factory.py").read_text(encoding="utf-8"))
        nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                 and node.name in ("_register_security_hooks", "_get_or_create_csrf_token")]
        namespace = dict(secrets=secrets, request=request, session=session, redirect=redirect, url_for=url_for)
        exec(compile(ast.Module(body=nodes, type_ignores=[]), "security_hooks", "exec"), namespace)
        namespace["_register_security_hooks"](self.app, {"tunnel_url": None})
        self.client = self.app.test_client()
        self.login()

    def login(self, role="soporte"):
        with self.client.session_transaction() as sess:
            sess.update(user_id=str(ObjectId()), role=role, nombre="Prueba",
                        password_changed_at=datetime.now(timezone.utc).isoformat(), _csrf_token="token")

    def post(self, path, data=None, json=None):
        return self.client.post(path, data=data, json=json, headers={"X-CSRFToken": "token"})

    def test_delete_requires_csrf(self):
        response = self.client.delete("/api/picking/item/" + str(ObjectId()))
        self.assertEqual(response.status_code, 400)
        self.db.picking.delete_one.assert_not_called()

    def test_password_missing_fields_is_not_500(self):
        response = self.post("/cambiar-password", data={})
        self.assertEqual(response.status_code, 302)
        self.db.usuarios.update_one.assert_not_called()

    def test_login_missing_password_is_rejected(self):
        self.db.usuarios.find_one.return_value = {"password": "scrypt:32768:8:1$salt$hash"}
        self.assertIsNone(authenticate_user(self.db, "usuario", None))

    def test_invalid_session_id_redirects_to_login(self):
        with self.client.session_transaction() as sess:
            sess["user_id"] = "invalid"
            sess.pop("password_changed_at", None)
        response = self.client.get("/soporte/produccion")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.location)

    def test_invalid_individual_production_id_is_not_500(self):
        response = self.post("/soporte/produccion/invalid/delete")
        self.assertEqual(response.status_code, 302)
        self.db.produccion.delete_one.assert_not_called()

    def test_invalid_support_date_is_not_500(self):
        response = self.post("/soporte/produccion", data={"fecha_inicio": "not-a-date"})
        self.assertEqual(response.status_code, 302)
        self.db.produccion.find.assert_not_called()

    def test_code_filter_escapes_regex_characters(self):
        self.db.produccion.find.return_value.sort.return_value = []
        self.db.produccion.distinct.return_value = []
        self.db.cortes.find.return_value.sort.return_value = []
        with patch("core.routes.soporte_produccion_routes.render_template", return_value="ok"):
            response = self.post("/soporte/produccion", data={"codigo_pieza": "["})
        self.assertEqual(response.status_code, 200)
        query = self.db.produccion.find.call_args.args[0]
        self.assertEqual(query["codigo_pieza"]["$regex"], r"^\[$")

    def test_numeric_code_alias_is_only_counted_once(self):
        payload = dict(empresa="AVO", marco="M", tramo="T", armadas=1, rematadas=0)
        groups = build_tarjetas_grupos([], {"001": payload, "1": payload}, include_orphans=True)
        self.assertEqual(groups[0]["marcos"][0]["tramos"][0]["total"], 1)

    def test_numeric_master_alias_does_not_create_orphan(self):
        payload = dict(empresa="AVO", marco="M", tramo="T", armadas=1, rematadas=0)
        pieces = [dict(codigo="001", empresa="AVO", marco="M", tramo="T")]
        groups = build_tarjetas_grupos(pieces, {"001": payload, "1": payload}, include_orphans=True)
        self.assertEqual(groups[0]["marcos"][0]["tramos"][0]["total"], 1)

    def test_empty_archived_cut_never_uses_current_pieces(self):
        self.db.cortes.find_one.return_value = {"_id": ObjectId()}
        self.db.piezas_historicas.find.return_value = []
        with patch("core.routes.admin_informes_avanzados_routes.render_template", return_value="ok") as render:
            response = self.client.get("/admin/archivados/piezas-cliente?corte_nombre=vacio")
        self.assertEqual(response.status_code, 200)
        self.db.piezas.find.assert_not_called()
        self.assertEqual(render.call_args.kwargs["grupos"], [])

    def test_missing_archived_cut_is_not_current_report(self):
        self.db.cortes.find_one.return_value = None
        response = self.client.get("/admin/archivados/piezas-cliente?corte_nombre=inexistente")
        self.assertEqual(response.status_code, 404)
        self.db.piezas.find.assert_not_called()

    def test_picking_invalid_payloads_return_400(self):
        for path, payload in [
            ("/api/picking/scan", []),
            ("/api/picking/scan", {"codigo": 1}),
            ("/api/picking/validar", {}),
            ("/api/picking/validar", {"codigo": "j1", "decision": "arbitrary"}),
            ("/api/picking/reset", []),
        ]:
            with self.subTest(path=path, payload=payload):
                self.assertEqual(self.post(path, json=payload).status_code, 400)
        self.db.picking.insert_one.assert_not_called()

    def test_picking_mixed_timezones_can_be_compared(self):
        self.db.picking.find_one.return_value = None
        self.db.piezas.find_one.return_value = {"codigo": "j1", "empresa": "AVO", "marco": "M", "tramo": "T"}
        self.db.produccion.find_one.return_value = {
            "_id": ObjectId(), "modo": "armador", "fecha": datetime(2026, 1, 1),
        }
        self.db.produccion_historica.find_one.return_value = {
            "_id": ObjectId(), "modo": "rematador", "fecha": datetime(2026, 1, 2, tzinfo=timezone.utc),
        }
        response = self.post("/api/picking/scan", json={"codigo": "j1"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["estado"], "Rematado")

    def test_reset_only_deletes_archived_snapshot(self):
        uid = ObjectId()
        self.db.picking.find.return_value.sort.return_value = [{"_id": uid, "codigo": "j1"}]
        self.db.picking_historial.insert_one.return_value = SimpleNamespace(inserted_id=ObjectId())
        self.db.picking.delete_many.return_value = SimpleNamespace(deleted_count=1)
        self.db.picking.count_documents.return_value = 0
        response = self.post("/api/picking/reset", json={})
        self.assertEqual(response.status_code, 200)
        self.db.picking.delete_many.assert_called_once_with({"_id": {"$in": [uid]}})

    def test_failed_archive_never_deletes_active_production(self):
        corte_id = ObjectId()
        uid = ObjectId()
        self.db.cortes.find_one.return_value = {"_id": corte_id, "nombre": "Corte"}
        self.db.produccion.find.return_value = [{"_id": uid}]
        self.db.produccion_historica.insert_many.side_effect = BulkWriteError({
            "writeErrors": [{"index": 0, "code": 121, "errmsg": "Document failed validation"}],
            "writeConcernErrors": [], "nInserted": 0,
        })
        self.db.produccion_historica.find.return_value = []
        response = self.post("/soporte/produccion/asignar-corte-masivo",
                             data={"corte_id": str(corte_id), "scope": "todos"})
        self.assertEqual(response.status_code, 302)
        self.db.produccion.delete_many.assert_not_called()

    def test_generic_bulk_delete_uses_snapshot_ids(self):
        origin, recycle_bin = MagicMock(), MagicMock()
        db = MagicMock()
        db.__getitem__.side_effect = {"piezas": origin, "papelera": recycle_bin}.__getitem__
        uid = ObjectId()
        origin.find.return_value = [{"_id": uid}]
        recycle_bin.insert_many.return_value = SimpleNamespace(inserted_ids=[ObjectId()])
        origin.delete_many.return_value = SimpleNamespace(deleted_count=1)
        soft_delete_many(db, "piezas", {"empresa": "AVO"})
        origin.delete_many.assert_called_once_with({"_id": {"$in": [uid]}})

    def test_generic_bulk_database_failure_returns_message(self):
        self.db.__getitem__.return_value.find.side_effect = OperationFailure("offline")
        count, message = soft_delete_many(self.db, "piezas", {})
        self.assertEqual(count, 0)
        self.assertTrue(message)

    def test_all_templates_compile(self):
        env = Environment(loader=FileSystemLoader(ROOT / "templates"))
        for name in env.list_templates():
            with self.subTest(template=name):
                env.get_template(name)

    def test_picking_modals_are_siblings(self):
        source = (ROOT / "templates/admin_picking.html").read_text(encoding="utf-8")
        self.assertIn("  </div>\n</div>\n<!-- Modal Detalle Picking", source)

    def test_requirements_do_not_install_conflicting_bson(self):
        source = (ROOT / "requirements.txt").read_text(encoding="utf-8")
        self.assertFalse(any(line.startswith("bson==") for line in source.splitlines()))

    def test_mongo_failure_is_503_and_logs_details(self):
        self.db.produccion.find.side_effect = OperationFailure("private database details")
        with patch.object(self.app.logger, "exception") as log:
            response = self.client.get("/soporte/produccion")
        self.assertEqual(response.status_code, 503)
        self.assertNotIn(b"private database details", response.data)
        log.assert_called_once()

    def test_invalid_id_in_other_routes_returns_400(self):
        response = self.post("/admin/boxes/invalid/delete")
        self.assertEqual(response.status_code, 400)

    def test_invalid_admin_report_date_returns_400(self):
        response = self.client.get("/admin/produccion?fecha_inicio=invalid")
        self.assertEqual(response.status_code, 400)
        self.db.produccion.find.assert_not_called()

    def test_reversed_date_range_is_rejected(self):
        with self.assertRaises(InvalidDateRange):
            build_date_range_utc("2026-10-31", "2026-10-01")

    def test_empty_bulk_piece_payload_returns_400(self):
        for payload in ([], {}, {"codigos": "j1"}, {"codigos": [{}]}):
            self.assertEqual(self.post("/admin/piezas/eliminar-confirmar", json=payload).status_code, 400)

    def test_bulk_piece_failure_is_not_reported_as_success(self):
        with patch("core.routes.admin_crud_routes.soft_delete_many", return_value=(0, "Error")):
            response = self.post("/admin/piezas/eliminar-confirmar", json={"codigos": ["j1"]})
        self.assertFalse(response.json["success"])

    def test_validation_cannot_update_unrelated_production(self):
        self.db.produccion.update_one.return_value = SimpleNamespace(matched_count=0)
        self.db.produccion_historica.update_one.return_value = SimpleNamespace(matched_count=0)
        uid = str(ObjectId())
        response = self.post("/api/picking/validar", json={
            "codigo": "j1", "prod_id": uid, "decision": "aprobado", "pieza": {"codigo": "j1"},
        })
        self.assertEqual(response.status_code, 404)
        self.assertEqual(self.db.produccion.update_one.call_args.args[0]["modo"], "rematador")
        self.db.picking.insert_one.assert_not_called()

    def test_valid_picking_validation_persists_and_returns_item(self):
        uid = str(ObjectId())
        self.db.produccion.update_one.return_value = SimpleNamespace(matched_count=1)
        self.db.picking.find_one.return_value = None
        self.db.picking.insert_one.return_value = SimpleNamespace(inserted_id=ObjectId())
        response = self.post("/api/picking/validar", json={
            "codigo": "j1", "prod_id": uid, "decision": "aprobado",
            "pieza": {"codigo": "j1", "empresa": "AVO", "marco": "M", "tramo": "T"},
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["picking_item"]["calidad"], "aprobado")
        self.db.picking.insert_one.assert_called_once()

    def test_monthly_cut_deletes_only_archived_snapshot(self):
        production_id, piece_id, cut_id = ObjectId(), ObjectId(), ObjectId()
        self.db.produccion.find.return_value = [{"_id": production_id, "codigo_pieza": "j1"}]
        self.db.piezas.find.side_effect = [[], [{"_id": piece_id, "codigo": "j1"}]]
        self.db.usuarios.find.return_value = []
        self.db.planificaciones.find.return_value = []
        self.db.cortes.insert_one.return_value = SimpleNamespace(inserted_id=cut_id)
        self.db.config.find_one.return_value = {"value": "j"}
        response = self.post("/admin/corte_mensual", data={"mes": "2026-10"})
        self.assertEqual(response.status_code, 302)
        self.db.produccion.delete_many.assert_called_once_with({"_id": {"$in": [production_id]}})
        self.db.piezas.delete_many.assert_called_once_with({"_id": {"$in": [piece_id]}})

    def test_local_entrypoint_does_not_create_second_app(self):
        source = (ROOT / "app.py").read_text(encoding="utf-8")
        self.assertNotIn("create_app()", source)

    def test_alphanumeric_piece_counts_are_preserved(self):
        pieces = [dict(codigo=code, empresa="AVO", marco="M", tramo="T") for code in ("j1", "j2")]
        groups = build_tarjetas_grupos(pieces, {
            "j1": {"armadas": 1, "rematadas": 1},
            "j2": {"armadas": 1, "rematadas": 0},
        })
        tramo = groups[0]["marcos"][0]["tramos"][0]
        self.assertEqual((tramo["total"], tramo["armadas"], tramo["rematadas"], tramo["pendientes"]),
                         (2, 2, 1, 1))

    def test_archived_report_keeps_late_production(self):
        self.db.cortes.find_one.return_value = {"_id": ObjectId()}
        self.db.piezas_historicas.find.return_value = [
            dict(codigo="j1", empresa="AVO", marco="M", tramo="T"),
        ]
        self.db.produccion_historica.aggregate.return_value = [
            {"_id": "j1", "armadas": 1, "rematadas": 0},
        ]
        self.db.produccion.aggregate.return_value = [
            {"_id": "j1", "armadas": 0, "rematadas": 1},
        ]
        with patch("core.routes.admin_informes_avanzados_routes.render_template", return_value="ok") as render:
            response = self.client.get("/admin/archivados/piezas-cliente?corte_nombre=Anterior")
        self.assertEqual(response.status_code, 200)
        tramo = render.call_args.kwargs["grupos"][0]["marcos"][0]["tramos"][0]
        self.assertEqual((tramo["armadas"], tramo["rematadas"], tramo["pendientes"]), (1, 1, 0))

    def test_support_page_renders_selection_and_modal_with_real_layout(self):
        self.db.produccion.find.return_value.sort.return_value = [
            dict(_id=ObjectId(), codigo_pieza="j1", usuario="Operador", modo="armador",
                 fecha=datetime.now(timezone.utc)),
        ]
        self.db.produccion.distinct.return_value = ["Operador", None]
        self.db.cortes.find.return_value.sort.return_value = []
        response = self.client.get("/soporte/produccion")
        self.assertEqual(response.status_code, 200)
        for marker in (b"production-selection", b"selectAllProduction", b"deleteProductionModal"):
            self.assertIn(marker, response.data)

    def test_informe_marcos_anual_producido_nunca_supera_ingresado(self):
        utc = timezone.utc

        def dt(y, m, d):
            return datetime(y, m, d, tzinfo=utc)

        db = MagicMock()
        db.piezas.find.return_value = iter([
            {"codigo": "a1", "marco": "TH1", "tramo": "1", "created_at": dt(2026, 3, 1)},
            {"codigo": "a2", "marco": "th1 ", "tramo": "2", "created_at": dt(2026, 3, 1)},
            {"codigo": "a3", "marco": "3 CARRILES", "tramo": "1", "created_at": dt(2026, 4, 1)},
            # sin created_at: se ubica por la fecha del documento (2025 -> fuera del anio)
            {"_id": ObjectId.from_datetime(dt(2025, 5, 1)), "codigo": "a5", "marco": "TH1", "tramo": "1"},
        ])
        db.piezas_historicas.find.return_value = iter([
            {"codigo": "a1", "marco": "TH1", "tramo": "1", "created_at": dt(2026, 3, 1)},   # duplicada por corte
            {"codigo": "a4", "marco": "TH1", "tramo": "2", "created_at": dt(2026, 6, 1)},
        ])
        # a9 se remato pero es de otra cohorte (no esta en las piezas del anio)
        db.produccion.distinct.side_effect = lambda field, flt: ["a1", "a3", "a9"] if flt.get("modo") == "rematador" else []
        db.produccion_historica.distinct.side_effect = lambda field, flt: ["a1"] if flt.get("modo") == "rematador" else []

        filas, totales, sin_fecha = build_marcos_anual(db, 2026, dt(2026, 1, 1), dt(2026, 12, 31))

        por_marco = {f["marco"]: f for f in filas}
        self.assertEqual(por_marco["TH1"]["ingresado"], 3)   # a1 (una sola vez), a2, a4; a5 es de 2025
        self.assertEqual(por_marco["TH1"]["producido"], 1)   # solo a1
        self.assertEqual(por_marco["3 CARRILES"]["producido"], 1)
        self.assertEqual(totales["ingresado"], 4)
        self.assertEqual(totales["producido"], 2)
        self.assertEqual(sin_fecha, 0)
        for fila in filas:
            self.assertLessEqual(fila["producido"], fila["ingresado"])
            for tramo in fila["tramos"]:
                self.assertLessEqual(tramo["producido"], tramo["ingresado"])
        tramos = {t["tramo"]: t for t in por_marco["TH1"]["tramos"]}
        self.assertTrue(tramos["1"]["completo"])
        self.assertEqual(tramos["2"]["pendiente"], 2)
        self.assertEqual(por_marco["TH1"]["tramos_faltantes"], ["2"])

    def test_informe_marcos_anual_route_rejects_bad_year(self):
        self.assertEqual(self.client.get("/admin/informes/marcos/anual?anio=abc").status_code, 400)
        self.assertEqual(self.client.get("/admin/informes/marcos/anual/export?anio=1500").status_code, 400)
        self.assertEqual(self.client.get("/admin/informes/marcos/anual/data?anio=abc").status_code, 400)

    def test_informe_marcos_anual_data_devuelve_json(self):
        self.db.piezas.find.return_value = iter([])
        self.db.piezas_historicas.find.return_value = iter([])
        self.db.produccion.aggregate.return_value = []
        self.db.produccion_historica.aggregate.return_value = []
        response = self.client.get("/admin/informes/marcos/anual/data?anio=2026")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["anio"], 2026)
        self.assertEqual(set(data), {"anio", "filas", "totales", "sin_fecha"})

    def test_produccion_archivada_lista_borra_y_vuelve_a_activa(self):
        corte_id = ObjectId()
        reg_id = ObjectId()
        reg = {"_id": reg_id, "corte_id": corte_id, "codigo_pieza": "a1", "modo": "rematador",
               "usuario": "op", "fecha": datetime(2026, 1, 5, tzinfo=timezone.utc)}
        self.db.cortes.find.return_value.sort.return_value = [{"_id": corte_id, "nombre": "Enero",
                                                                 "inicio": datetime(2026, 1, 1), "fin": datetime(2026, 2, 1)}]
        self.db.produccion_historica.find.return_value.sort.return_value = [dict(reg)]
        self.db.produccion_historica.distinct.return_value = ["op"]

        response = self.client.get(f"/soporte/produccion?ubicacion={corte_id}")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Enero", response.data)
        self.assertIn(b'origen: "historica"', response.data)
        self.db.produccion_historica.find.assert_called_with({"corte_id": corte_id})
        self.db.produccion.find.assert_not_called()

        # Borrado masivo apunta a la coleccion historica
        with patch("core.routes.soporte_produccion_routes.soft_delete_selected_production",
                   return_value={"deleted_ids": [str(reg_id)], "problems": [], "uncertain_ids": []}) as bulk:
            response = self.client.post("/soporte/produccion/eliminar-masivo",
                                        json={"ids": [str(reg_id)], "origen": "historica"},
                                        headers={"X-CSRFToken": "token"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(bulk.call_args.kwargs["collection"], "produccion_historica")

        # Editar un registro archivado y devolverlo a produccion activa
        self.db.produccion_historica.find_one.return_value = dict(reg)
        response = self.post(f"/soporte/produccion/{reg_id}/editar",
                             data={"origen": "historica", "corte_destino": "activa", "modo": "rematador",
                                   "usuario": "op", "codigo_pieza": "a1"})
        self.assertEqual(response.status_code, 302)
        insertado = self.db.produccion.insert_one.call_args.args[0]
        self.assertNotIn("corte_id", insertado)
        self.assertNotIn("_id", insertado)
        self.db.produccion_historica.delete_one.assert_called_once_with({"_id": reg_id})

    def test_soft_delete_produccion_rechaza_coleccion_no_permitida(self):
        with self.assertRaises(ValueError):
            soft_delete_selected_production(MagicMock(), [ObjectId()], collection="usuarios")

    def _db_marcos_estados(self):
        utc = timezone.utc
        db = MagicMock()
        db.piezas.find.return_value = iter([
            {"codigo": "a1", "marco": "TH1", "tramo": "1", "empresa": "Cli", "created_at": datetime(2026, 2, 1, tzinfo=utc)},
            {"codigo": "a2", "marco": "TH1", "tramo": "2", "empresa": "Cli", "created_at": datetime(2026, 2, 1, tzinfo=utc)},
            {"codigo": "a3", "marco": "th1", "tramo": "2", "empresa": "Cli", "created_at": datetime(2026, 2, 1, tzinfo=utc)},
            {"codigo": "a4", "marco": "TH10", "tramo": "1", "empresa": "Cli", "created_at": datetime(2026, 2, 1, tzinfo=utc)},
        ])
        db.piezas_historicas.find.return_value = iter([])
        db.produccion.distinct.side_effect = lambda field, flt: (
            ["a1", "a2", "a4"] if flt.get("modo") == "armador" else ["a1"] if flt.get("modo") == "rematador" else [])
        db.produccion_historica.distinct.side_effect = lambda field, flt: []
        db.produccion.aggregate.side_effect = lambda pipe: (
            [{"_id": "a2", "usuarios": ["Ana"], "fecha": datetime(2026, 3, 5, tzinfo=utc), "registros": 2}]
            if pipe[0]["$match"].get("modo") == "armador" else [])
        db.produccion_historica.aggregate.side_effect = lambda pipe: []
        return db

    def test_informe_marcos_anual_separa_rematadas_armadas_y_sin_fabricar(self):
        db = self._db_marcos_estados()
        utc = timezone.utc
        filas, totales, _ = build_marcos_anual(db, 2026, datetime(2026, 1, 1, tzinfo=utc), datetime(2026, 12, 31, tzinfo=utc))
        por_marco = {f["marco"]: f for f in filas}
        self.assertEqual(totales["ingresado"], 4)
        self.assertEqual(totales["producido"], 1)
        self.assertEqual(totales["solo_armadas"], 2)
        self.assertEqual(totales["sin_fabricar"], 1)
        self.assertEqual(totales["ingresado"], totales["producido"] + totales["solo_armadas"] + totales["sin_fabricar"])
        self.assertEqual((por_marco["TH1"]["solo_armadas"], por_marco["TH1"]["sin_fabricar"]), (1, 1))

    def test_listar_piezas_marcos_anual_por_estado_y_marco(self):
        utc = timezone.utc
        rango = (datetime(2026, 1, 1, tzinfo=utc), datetime(2026, 12, 31, tzinfo=utc))

        def listar(estado, marco=None):
            db = self._db_marcos_estados()
            return listar_piezas_marcos_anual(db, *rango, estado, marco)

        columnas, filas = listar("armadas", "TH1")
        self.assertEqual([f["Código"] for f in filas], ["a2"])        # solo TH1; a4 es de TH10
        self.assertEqual(filas[0]["Armado por"], "Ana")
        self.assertEqual(filas[0]["Registros de armado"], 2)
        self.assertIn("Último armado", columnas)

        _, filas = listar("armadas")
        self.assertEqual(sorted(f["Código"] for f in filas), ["a2", "a4"])
        _, filas = listar("rematadas")
        self.assertEqual([f["Código"] for f in filas], ["a1"])
        _, filas = listar("sin_fabricar", "TH1")
        self.assertEqual([f["Código"] for f in filas], ["a3"])        # a3 llega como "th1": mismo marco
        with self.assertRaises(ValueError):
            listar("otro")

    def test_informe_marcos_anual_piezas_export_excel(self):
        response = self.client.get("/admin/informes/marcos/anual/piezas?anio=2026&estado=armadas&marco=TH1")
        self.assertEqual(response.status_code, 200)
        self.assertIn("spreadsheetml", response.mimetype)
        self.assertIn("piezas_armadas_TH1_2026.xlsx", response.headers["Content-Disposition"])
        self.assertEqual(self.client.get("/admin/informes/marcos/anual/piezas?anio=2026&estado=x").status_code, 400)

    def test_planificacion_armado_cuenta_una_vez_por_pieza(self):
        solo, otro = ObjectId(), ObjectId()
        d = lambda n: datetime(2026, 5, n, tzinfo=timezone.utc)
        docs = [
            {"user_id": str(solo), "tramo": "1", "codigo_pieza": "p1", "fecha": d(1)},
            {"user_id": str(solo), "tramo": "1", "codigo_pieza": "p1", "fecha": d(1), "armado_solo_extra": True},
            {"user_id": str(solo), "tramo": "1", "codigo_pieza": "p2", "fecha": d(2)},
            {"user_id": str(otro), "tramo": "1", "codigo_pieza": "p2", "fecha": d(3)},   # segundo armador de p2
            {"user_id": str(otro), "tramo": "1", "codigo_pieza": "p3", "fecha": d(4)},
            {"user_id": str(solo), "tramo": "1", "codigo_pieza": "p3", "fecha": d(5)},   # segundo armador de p3
        ]
        db = MagicMock()
        db.produccion.find.side_effect = lambda *a, **k: iter([dict(x) for x in docs])

        por_op, _, total = _get_marco_production_stats(db, "Cli", "TH1", modo="armador", armado_por_pieza=True)
        self.assertEqual(total, {"1": 3})                       # p1, p2 y p3: 3 piezas
        self.assertEqual(por_op[solo], 2)                       # p1 y p2: las armo primero
        self.assertEqual(por_op[otro], 1)                       # p3: la armo primero
        self.assertEqual(sum(por_op.values()), 3)               # la suma de cupos nunca supera las piezas

        _, _, total_registros = _get_marco_production_stats(db, "Cli", "TH1", modo="armador")
        self.assertEqual(total_registros, {"1": 6})             # criterio anterior: 6 registros

        self.assertEqual(_unidad_armado(None), 1)
        self.assertEqual(_unidad_armado({"modos": {"armador": {"unidad_armado": 1}}}), 1)
        self.assertEqual(_unidad_armado({"modos": {"armador": {"tramos": {}}}}), 2)   # plan anterior: sigue en 2

    def test_operador_piezas_armadas_primero(self):
        from core.routes.operator_routes import _piezas_armadas_primero
        ana, beto = ObjectId(), ObjectId()
        d = lambda n: datetime(2026, 5, n)
        # El pipeline ya agrupa por pieza y trae el primer armador (el sort lo hace Mongo)
        db = MagicMock()
        db.produccion.aggregate.return_value = [
            {"_id": "p1", "user": str(ana), "fecha": d(1)},
            {"_id": "p2", "user": str(beto), "fecha": d(2)},
        ]
        db.produccion_historica.aggregate.return_value = [
            {"_id": "p2", "user": str(ana), "fecha": d(1)},   # en el corte se armo antes: se la lleva Ana
        ]
        corte = [{"corte_id": ObjectId()}]
        self.assertEqual(_piezas_armadas_primero(db, [{"modo": "armador"}], ana, corte), {"p1", "p2"})
        self.assertEqual(_piezas_armadas_primero(db, [{"modo": "armador"}], beto, corte), set())
        pipeline = db.produccion.aggregate.call_args.args[0]
        self.assertIn({"armado_solo_extra": {"$ne": True}}, pipeline[0]["$match"]["$and"])
        self.assertEqual(pipeline[1], {"$sort": {"fecha": 1}})

    def test_planificacion_armado_duplica_y_respeta_operadores_solos(self):
        a, b, c = ObjectId(), ObjectId(), ObjectId()
        ops = [{"_id": a, "nombre": "Ana"}, {"_id": b, "nombre": "Beto"}, {"_id": c, "nombre": "Cami"}]

        # 10 piezas = 20 unidades; Ana arma sola: su objetivo es par y el total no cambia
        r = {x["user_id"]: x for x in _build_asignaciones_armado(20, ops, {}, {a})}
        self.assertEqual(sum(x["objetivo"] for x in r.values()), 20)
        self.assertEqual(r[a]["objetivo"] % 2, 0)
        self.assertTrue(r[a]["solo"])
        self.assertFalse(r[b]["solo"])

        # todos solos: todos pares y el total se mantiene
        r = _build_asignaciones_armado(20, ops, {}, {a, b, c})
        self.assertEqual(sum(x["objetivo"] for x in r), 20)
        self.assertTrue(all(x["objetivo"] % 2 == 0 for x in r))

        # sin solos: igual que el reparto parejo de siempre
        r = _build_asignaciones_armado(20, ops, {}, set())
        self.assertEqual(sorted(x["objetivo"] for x in r), [6, 7, 7])
        self.assertFalse(any(x["solo"] for x in r))

        # un solo que ya llevaba 7 registros no baja de lo producido (sube a 8) y se compensa con los demas
        r = {x["user_id"]: x for x in _build_asignaciones_armado(20, ops, {a: 7}, {a})}
        self.assertEqual(r[a]["objetivo"], 8)
        self.assertGreaterEqual(r[a]["objetivo"], r[a]["producido"])
        self.assertEqual(sum(x["objetivo"] for x in r.values()), 20)

    def test_planificacion_crear_armado_duplica_meta_y_guarda_solos(self):
        a, b, c = ObjectId(), ObjectId(), ObjectId()
        self.login("administrador")
        self.db.__getitem__.side_effect = lambda nombre: getattr(self.db, nombre)
        self.db.config.find_one.return_value = {"value": "a"}
        self.db.usuarios.find.return_value = [
            {"_id": a, "nombre": "Ana"}, {"_id": b, "nombre": "Beto"}, {"_id": c, "nombre": "Cami"}]
        self.db.planificaciones.find_one.return_value = None
        self.db.planificaciones.insert_one.return_value = MagicMock(inserted_id=ObjectId())
        self.db.produccion.find.return_value = iter([])
        self.db.produccion_historica.find.return_value = iter([])
        grupos = [{"cliente": "Cli", "marcos": [{"marco": "TH1", "tramos": [
            {"tramo": "1", "total": 10, "armadas": 0, "rematadas": 0}]}]}]
        with patch("core.routes.admin_planificacion_routes._get_planificacion_grupos_completos",
                   return_value=([], {}, grupos)):
            response = self.post("/admin/planificacion/crear", data={
                "modo": "armador", "empresa": "Cli", "marco": "TH1",
                "operadores[]": [str(a), str(b), str(c)], "solo[]": [str(a)]})
        self.assertEqual(response.status_code, 302)
        cambios = self.db.planificaciones.update_one.call_args.args[1]["$set"]
        tramo = cambios["modos.armador.tramos"]["1"]
        self.assertEqual(tramo["total_piezas"], 10)
        self.assertEqual(tramo["total"], 20)                      # 10 piezas = 20 armados
        self.assertEqual(cambios["modos.armador.unidad_armado"], 2)
        asign = {x["user_id"]: x for x in tramo["asignaciones"]}
        self.assertEqual(sum(x["objetivo"] for x in asign.values()), 20)
        self.assertTrue(asign[a]["solo"])
        self.assertEqual(asign[a]["objetivo"] % 2, 0)
        self.assertFalse(asign[b]["solo"])

    def test_listar_piezas_armadas_indica_el_corte_donde_se_armaron(self):
        utc = timezone.utc
        corte_id = ObjectId()
        db = self._db_marcos_estados()
        db.cortes.find.return_value = [{"_id": corte_id, "nombre": "Octubre 2026"}]
        # a2 sigue en produccion activa; a4 se armo y quedo archivada en el corte de octubre
        db.produccion.aggregate.side_effect = lambda pipe: (
            [{"_id": "a2", "usuarios": ["Ana"], "fecha": datetime(2026, 3, 5, tzinfo=utc), "registros": 1, "cortes": []}]
            if pipe[0]["$match"].get("modo") == "armador" else [])
        db.produccion_historica.aggregate.side_effect = lambda pipe: (
            [{"_id": "a4", "usuarios": ["Beto"], "fecha": datetime(2026, 9, 20, tzinfo=utc), "registros": 2, "cortes": [corte_id]}]
            if pipe[0]["$match"].get("modo") == "armador" else [])

        columnas, filas = listar_piezas_marcos_anual(
            db, datetime(2026, 1, 1, tzinfo=utc), datetime(2026, 12, 31, tzinfo=utc), "armadas")

        self.assertIn("Corte del armado", columnas)
        cortes = {f["Código"]: f["Corte del armado"] for f in filas}
        self.assertEqual(cortes, {"a2": "Producción activa (sin corte)", "a4": "Octubre 2026"})

    def test_informe_marcos_anual_piezas_data_json(self):
        response = self.client.get("/admin/informes/marcos/anual/piezas/data?anio=2026&estado=armadas&marco=TH1")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["estado"], "armadas")
        self.assertEqual(data["marco"], "TH1")
        self.assertIn("Corte del armado", data["columnas"])
        self.assertEqual(self.client.get("/admin/informes/marcos/anual/piezas/data?anio=2026&estado=x").status_code, 400)

    def test_excel_tiene_formato_profesional(self):
        import io
        import zipfile
        from core.helpers.excel import build_excel_bytes

        data = [
            {"Fecha": "05-10-2026", "Código": 1001, "Total": 1500.5},
            {"Fecha": "TOTAL", "Código": "", "Total": 1500.5},
        ]
        libro = zipfile.ZipFile(io.BytesIO(build_excel_bytes(data, "Operadores", title="Valor por operador")))
        hoja = libro.read("xl/worksheets/sheet1.xml").decode()
        textos = libro.read("xl/sharedStrings.xml").decode()
        self.assertIn("<autoFilter", hoja)               # filtros en el encabezado
        self.assertIn('state="frozen"', hoja)            # encabezado congelado
        self.assertIn("<mergeCell ", hoja)               # titulo combinado
        self.assertIn("Valor por operador", textos)
        self.assertIn("TOTAL", textos)
        self.assertNotIn("05-10-2026", textos)           # la fecha se guarda como fecha real, no como texto
        vacio = zipfile.ZipFile(io.BytesIO(build_excel_bytes([], "Vacio", columns=["Código", "Marco"])))
        self.assertIn("Sin registros", vacio.read("xl/sharedStrings.xml").decode())


if __name__ == "__main__":
    unittest.main()
