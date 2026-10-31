"""Pruebas aisladas: no acceden a MongoDB ni eliminan datos reales."""
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

from core.helpers.auth import build_login_required
from core.helpers.soft_delete import soft_delete_selected_production
from core.routes.soporte_produccion_routes import register_soporte_produccion_routes


ROOT = Path(__file__).resolve().parent


class BulkProductionTests(unittest.TestCase):
    def setUp(self):
        self.db = MagicMock()
        self.origin = MagicMock()
        self.bin = MagicMock()
        self.db.__getitem__.side_effect = {
            "produccion": self.origin, "papelera": self.bin,
        }.__getitem__
        self.ids = [ObjectId(), ObjectId(), ObjectId()]
        self.origin.find.return_value = [{"_id": uid, "codigo_pieza": "j102"} for uid in self.ids]
        self.origin.delete_many.return_value = SimpleNamespace(deleted_count=3)

    def test_single_bulk_delete_and_complete_backups(self):
        result = soft_delete_selected_production(self.db, self.ids, deleted_by_user_name="Soporte")
        self.assertEqual(set(result["deleted_ids"]), set(map(str, self.ids)))
        self.assertEqual(result["problems"], [])
        self.origin.delete_many.assert_called_once()
        self.origin.delete_one.assert_not_called()
        self.bin.insert_many.assert_called_once()
        backups = self.bin.insert_many.call_args.args[0]
        self.assertEqual(len(backups), 3)
        self.assertTrue(all(doc["deleted_by_user_name"] == "Soporte" for doc in backups))
        self.assertTrue(all(doc["documento_original"]["codigo_pieza"] == "j102" for doc in backups))
        self.assertTrue(all((doc["expire_at"] - doc["deleted_at"]).days == 7 for doc in backups))

    def test_missing_records_are_reported(self):
        self.origin.find.return_value = [{"_id": self.ids[0]}]
        self.origin.delete_many.return_value = SimpleNamespace(deleted_count=1)
        result = soft_delete_selected_production(self.db, self.ids)
        self.assertEqual(len(result["deleted_ids"]), 1)
        self.assertEqual(len(result["problems"]), 2)

    def test_partial_backup_only_deletes_protected_records(self):
        self.bin.insert_many.side_effect = RuntimeError("partial write")
        self.bin.find.return_value = [{"documento_id_original": self.ids[0]}]
        self.origin.delete_many.return_value = SimpleNamespace(deleted_count=1)
        result = soft_delete_selected_production(self.db, self.ids)
        self.assertEqual(result["deleted_ids"], [str(self.ids[0])])
        self.assertEqual(len(result["problems"]), 2)
        self.origin.delete_many.assert_called_once_with({"_id": {"$in": [self.ids[0]]}})

    def test_failed_backups_never_delete_production(self):
        self.bin.insert_many.side_effect = RuntimeError("offline")
        self.bin.find.return_value = []
        result = soft_delete_selected_production(self.db, self.ids)
        self.assertEqual(len(result["problems"]), 3)
        self.origin.delete_many.assert_not_called()

    def test_partial_deletion_reports_remaining(self):
        self.origin.delete_many.return_value = SimpleNamespace(deleted_count=2)
        self.origin.find.side_effect = [
            [{"_id": uid} for uid in self.ids], [{"_id": self.ids[2]}],
        ]
        result = soft_delete_selected_production(self.db, self.ids)
        self.assertEqual(len(result["deleted_ids"]), 2)
        self.assertEqual(result["problems"][0]["id"], str(self.ids[2]))

    def test_failed_deletion_and_unknown_outcome(self):
        self.origin.delete_many.side_effect = RuntimeError("connection lost")
        self.origin.find.side_effect = [
            [{"_id": uid} for uid in self.ids], RuntimeError("offline"),
        ]
        result = soft_delete_selected_production(self.db, self.ids)
        self.assertEqual(result["deleted_ids"], [])
        self.assertEqual(len(result["uncertain_ids"]), 3)

    def test_large_batch_uses_one_delete_operation(self):
        ids = [ObjectId() for _ in range(1000)]
        self.origin.find.return_value = [{"_id": uid} for uid in ids]
        self.origin.delete_many.return_value = SimpleNamespace(deleted_count=len(ids))
        result = soft_delete_selected_production(self.db, ids)
        self.assertEqual(len(result["deleted_ids"]), 1000)
        self.origin.delete_many.assert_called_once()
        self.bin.insert_many.assert_called_once()


class SupportEndpointTests(unittest.TestCase):
    def setUp(self):
        self.db = MagicMock()
        self.app = Flask(__name__)
        self.app.secret_key = "test-only"
        register_soporte_produccion_routes(self.app, self.db, build_login_required(self.db))
        for endpoint in ("login", "cambiar_password", "admin_dashboard", "supervisor_home",
                         "operador_home", "admin_informes"):
            self.app.add_url_rule("/test/" + endpoint, endpoint, lambda: "home")

        # Cargar el hook real sin importar app_factory, que conecta a Mongo al importarse.
        tree = ast.parse((ROOT / "core/app_factory.py").read_text(encoding="utf-8"))
        functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                     and node.name in ("_register_security_hooks", "_get_or_create_csrf_token")]
        namespace = dict(secrets=secrets, session=session, request=request,
                         redirect=redirect, url_for=url_for)
        exec(compile(ast.Module(body=functions, type_ignores=[]), "security_hooks", "exec"), namespace)
        namespace["_register_security_hooks"](self.app, {"tunnel_url": None})
        self.client = self.app.test_client()
        self.ids = [str(ObjectId()), str(ObjectId())]

    def login_as(self, role):
        with self.client.session_transaction() as sess:
            sess["user_id"] = str(ObjectId())
            sess["role"] = role
            sess["nombre"] = "Soporte prueba"
            sess["password_changed_at"] = datetime.now(timezone.utc).isoformat()
            sess["_csrf_token"] = "test-token"

    def post(self, ids, csrf="test-token"):
        return self.client.post("/soporte/produccion/eliminar-masivo",
                                json={"ids": ids}, headers={"X-CSRFToken": csrf})

    @patch("core.routes.soporte_produccion_routes.soft_delete_selected_production")
    def test_support_success_and_duplicate_ids(self, delete):
        self.login_as("soporte")
        delete.return_value = {"deleted_ids": self.ids, "problems": [], "uncertain_ids": []}
        response = self.post(self.ids + [self.ids[0]])
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["deleted_count"], 2)
        self.assertEqual(len(delete.call_args.args[1]), 2)
        self.assertEqual(delete.call_args.kwargs["deleted_by_user_name"], "Soporte prueba")

    @patch("core.routes.soporte_produccion_routes.soft_delete_selected_production")
    def test_other_roles_and_anonymous_cannot_delete(self, delete):
        for role in ("administrador", "supervisor", "operador", "cliente"):
            self.login_as(role)
            self.assertEqual(self.post(self.ids).status_code, 302)
        with self.client.session_transaction() as sess:
            sess.clear()
            sess["_csrf_token"] = "test-token"
        self.assertEqual(self.post(self.ids).status_code, 302)
        delete.assert_not_called()

    @patch("core.routes.soporte_produccion_routes.soft_delete_selected_production")
    def test_csrf_and_empty_selection_are_rejected(self, delete):
        self.login_as("soporte")
        self.assertEqual(self.post(self.ids, csrf="wrong").status_code, 400)
        self.assertEqual(self.post([]).status_code, 400)
        self.assertEqual(self.post([{}]).status_code, 400)
        delete.assert_not_called()

    @patch("core.routes.soporte_produccion_routes.soft_delete_selected_production")
    def test_invalid_id_and_partial_result(self, delete):
        self.login_as("soporte")
        delete.return_value = {"deleted_ids": [self.ids[0]], "problems": [], "uncertain_ids": []}
        response = self.post([self.ids[0], "invalid"])
        self.assertFalse(response.json["success"])
        self.assertEqual(response.json["deleted_count"], 1)
        self.assertEqual(response.json["problem_count"], 1)
        self.assertEqual(response.json["problems"][0]["id"], "invalid")

    def test_template_compiles_and_contains_selection_and_modal(self):
        env = Environment(loader=FileSystemLoader(ROOT / "templates"))
        template = env.get_template("crud_produccion.html")
        self.assertIn("scripts", template.blocks)
        source = (ROOT / "templates/crud_produccion.html").read_text(encoding="utf-8")
        for marker in ("production-selection", "selectAllProduction", "disabled",
                       "deleteProductionModal", "confirmProductionCount", "X-CSRFToken"):
            self.assertIn(marker, source)


if __name__ == "__main__":
    unittest.main()
