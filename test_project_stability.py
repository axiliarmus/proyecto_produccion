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
from core.helpers.reporting import build_marcos_anual, build_tarjetas_grupos
from core.helpers.soft_delete import soft_delete_many, soft_delete_selected_production
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

    def test_informe_marcos_anual_agrupa_sin_duplicados(self):
        utc = timezone.utc

        def dt(y, m, d):
            return datetime(y, m, d, tzinfo=utc)

        db = MagicMock()
        db.piezas.find.side_effect = lambda q, *a: iter(
            [{"codigo": "a1", "marco": "TH1"}, {"codigo": "a2", "marco": "th1 "}]
            if "created_at" in q and "$gte" in q["created_at"] else [])
        db.piezas_historicas.find.side_effect = lambda q, *a: iter(
            [{"codigo": "a1", "marco": "TH1"}, {"codigo": "a4", "marco": "TH1"}]
            if "created_at" in q and "$gte" in q["created_at"] else [])
        db.produccion.aggregate.return_value = [{"_id": "a1", "marco": "TH1"}, {"_id": "a3", "marco": "3 CARRILES"}]
        db.produccion_historica.aggregate.return_value = [{"_id": "a1", "marco": "TH1"}]

        filas, totales, sin_fecha = build_marcos_anual(db, 2026, dt(2026, 1, 1), dt(2026, 12, 31))

        por_marco = {f["marco"]: f for f in filas}
        self.assertEqual(por_marco["TH1"]["ingresado"], 3)   # a1 (duplicada), a2, a4
        self.assertEqual(por_marco["TH1"]["producido"], 1)   # a1 rematada en ambas colecciones
        self.assertEqual(por_marco["3 CARRILES"]["producido"], 1)
        self.assertEqual(totales["ingresado"], 3)
        self.assertEqual(totales["producido"], 2)

    def test_informe_marcos_anual_route_rejects_bad_year(self):
        self.assertEqual(self.client.get("/admin/informes/marcos/anual?anio=abc").status_code, 400)
        self.assertEqual(self.client.get("/admin/informes/marcos/anual/export?anio=1500").status_code, 400)

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


if __name__ == "__main__":
    unittest.main()
