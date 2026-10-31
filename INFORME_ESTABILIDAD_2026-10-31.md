# Revision de estabilidad y correcciones

Fecha: 2026-10-31.

## Resultado y alcance

Se revisaron todos los modulos Python de `core`, el arranque `app.py`, las dependencias y las 43 plantillas Jinja2. Se examinaron especialmente autenticacion, permisos, CSRF, produccion activa, cortes, recepcion, papelera e informes. No se modifico la logica de asignacion ni de cupos de planificacion.

Se corrigieron los problemas confirmados descritos abajo y se agregaron pruebas de regresion. Resultado local: **45 pruebas aprobadas**, compilacion Python correcta, 43 plantillas compiladas, JavaScript de recepcion y seleccion masiva validado y `git diff --check` sin errores de formato.

Esto NO acredita que el proyecto entero este libre de errores. La base de datos esta simulada en las pruebas. No se accedio al VPS, a MongoDB real ni a sus logs; no se hicieron cortes, restauraciones o borrados reales. Tampoco se midieron tiempos de produccion ni se realizaron pruebas visuales de navegador.

La revision conserva las modificaciones preexistentes de eliminacion masiva de soporte. `test_soporte_produccion_masiva.py` pertenece a esa funcionalidad anterior y se ejecuto nuevamente.

## Errores confirmados y corregidos

### 1. Borrado tras archivo parcial

- Severidad: alta. Tipo: integridad de datos y manejo de excepciones.
- Ubicacion: `core/routes/soporte_produccion_routes.py`, `soporte_produccion_asignar_corte_masivo`, bloque de `insert_many`.
- Sintoma: se ejecutaba `delete_many` sobre produccion activa incluso cuando el archivo fallaba parcialmente.
- Evidencia: prueba con `BulkWriteError` por `Document failed validation`, codigo MongoDB 121, `nInserted=0`. Antes se llamaba al borrado de originales; ahora no.
- Causa: `except BulkWriteError: pass` trataba cualquier fallo masivo como si todas las copias estuvieran guardadas.
- Correccion: verificar los IDs realmente archivados en el corte solicitado antes de continuar; conservar todos los originales si no se confirma el lote completo.
- Mensaje final: `No se pudo archivar todo el lote. Se conservaron los registros activos; revisa el historial antes de reintentar.`
- Prueba: `test_failed_archive_never_deletes_active_production`.
- Limite: una escritura parcial puede dejar copias historicas junto a originales. Se informa expresamente y no se promete rollback transaccional.

### 2. Borrado de registros concurrentes sin copia

- Severidad: alta. Tipo: concurrencia e integridad.
- Ubicaciones: `core/helpers/soft_delete.py:soft_delete_many`, `core/routes/admin_dashboard_routes.py:admin_corte_mensual`, `core/routes/admin_tools_routes.py:api_picking_reset`.
- Sintoma: nuevos registros coincidentes podian eliminarse despues de preparar el archivo, sin estar incluidos en este.
- Mensaje de excepcion: no aplica; es un error de logica silencioso.
- Causa: se repetia el filtro original o `delete_many({})` en vez de borrar los IDs leidos y copiados.
- Correccion: limitar el borrado a la instantanea de IDs archivados. Recepcion comprueba ademas que no queden registros de esa instantanea activos.
- Pruebas: `test_generic_bulk_delete_uses_snapshot_ids`, `test_monthly_cut_deletes_only_archived_snapshot`, `test_reset_only_deletes_archived_snapshot`.
- Limite: no impide cambios concurrentes del contenido de un documento ya leido ni hace atomicas las escrituras entre colecciones.

### 3. DELETE sin proteccion CSRF

- Severidad: alta. Tipo: seguridad.
- Ubicacion: `core/app_factory.py:_register_security_hooks`, `csrf_protect`.
- Sintoma: `DELETE /api/picking/item/<id>` llegaba al endpoint sin token CSRF.
- Mensaje de excepcion: no aplica; la peticion no se rechazaba como debia.
- Causa: el hook solo verificaba POST.
- Correccion: cubrir POST, PUT, PATCH y DELETE; comparar tokens con `secrets.compare_digest`; devolver JSON claro para peticiones API.
- Mensaje: `CSRF token invalido. Recarga la pagina.` Estado HTTP 400.
- Pruebas: `test_delete_requires_csrf` y pruebas previas de permisos/CSRF de soporte.

### 4. Contraseña nueva ausente

- Severidad: media. Tipo: ejecucion y validacion.
- Ubicacion: `core/routes/auth_routes.py:cambiar_password`.
- Error completo reproducido: `TypeError: object of type 'NoneType' has no len()`.
- Causa: ambos campos ausentes eran `None`; tras comparar igualdad se llamaba `len(None)`.
- Correccion: normalizar campos ausentes a cadenas vacias y utilizar la validacion de longitud existente.
- Prueba: `test_password_missing_fields_is_not_500`.

### 5. Login sin contraseña

- Severidad: media. Tipo: ejecucion y validacion.
- Ubicacion: `core/helpers/auth.py:authenticate_user`.
- Error completo reproducido: `AttributeError: 'NoneType' object has no attribute 'encode'`.
- Causa: se pasaba `None` a `check_password_hash`.
- Correccion: rechazar contraseñas ausentes o de tipo incorrecto antes de consultar/verificar; no fallar por hashes ausentes o invalidos.
- Prueba: `test_login_missing_password_is_rejected`.

### 6. Identificadores invalidos

- Severidad: media. Tipo: ejecucion y validacion.
- Ubicaciones: `core/helpers/auth.py:build_login_required`, `core/routes/auth_routes.py:index`, `core/routes/soporte_produccion_routes.py:soporte_produccion_delete`.
- Error completo reproducido: `bson.errors.InvalidId: 'invalid' is not a valid ObjectId, it must be a 12-byte input or a 24-character hex string`.
- Causa: conversion directa de identificadores sin validacion.
- Correccion: invalidar sesiones con ID incorrecto; validar el borrado individual de soporte; agregar manejador HTTP 400 para `InvalidId` en otras rutas.
- Pruebas: `test_invalid_session_id_redirects_to_login`, `test_invalid_individual_production_id_is_not_500`, `test_invalid_id_in_other_routes_returns_400`.

### 7. Fechas invalidas y rangos invertidos

- Severidad: media. Tipo: ejecucion y validacion.
- Ubicaciones: `core/helpers/date_utils.py:build_date_range_utc`, filtros en `core/routes/soporte_produccion_routes.py`, manejador en `core/app_factory.py`.
- Error completo reproducido: `ValueError: time data 'not-a-date' does not match format '%Y-%m-%d'`.
- Causa: parseo sin tratamiento de errores y falta de validacion del orden del rango.
- Correccion: excepcion especifica `InvalidDateRange`, comprobacion de inicio/final, respuesta HTTP 400 en rutas que usan el helper sin captura local; soporte muestra aviso y no ejecuta consultas con fechas invalidas.
- Pruebas: `test_invalid_support_date_is_not_500`, `test_invalid_admin_report_date_returns_400`, `test_reversed_date_range_is_rejected`.

### 8. Codigo interpretado como expresion regular

- Severidad: media. Tipo: logica y consulta.
- Ubicacion: `core/routes/soporte_produccion_routes.py:_build_filtro_from_form`.
- Sintoma: el codigo `[` generaba el patron invalido `^[$`; un punto podia coincidir con cualquier caracter.
- Mensaje MongoDB: no se recopilo de una base real. Se verifico el patron incorrecto en la prueba, sin inventar un mensaje de servidor.
- Causa: interpolacion directa del codigo en `$regex`.
- Correccion: `re.escape` antes de crear el filtro exacto.
- Prueba: `test_code_filter_escapes_regex_characters`.

### 9. Doble conteo de alias numericos

- Severidad: media. Tipo: logica de informes.
- Ubicacion: `core/helpers/reporting.py:build_tarjetas_grupos`.
- Sintoma reproducido: una pieza con claves `001` y `1` aparecia como total 2 en vez de 1; podia aparecer un falso huerfano incluso existiendo la pieza maestra.
- Mensaje de excepcion: no aplica; el resultado numerico era incorrecto.
- Causa: el mapa expone alias normalizados; el agrupador contaba cada clave y dejaba de registrar las variantes al encontrar el primer estado.
- Correccion: unificar alias en una clave canonica, combinar flags con maximo y registrar todas las claves de la pieza.
- Pruebas: `test_numeric_code_alias_is_only_counted_once`, `test_numeric_master_alias_does_not_create_orphan`.
- Se mantienen los totales de piezas maestras y el comportamiento de los codigos alfanumericos.

### 10. Corte vacio mostrado como produccion actual

- Severidad: media. Tipo: logica y aislamiento de informes.
- Ubicacion: `core/routes/admin_informes_avanzados_routes.py:archivados_piezas_cliente`.
- Sintoma: un corte sin piezas historicas recurria a `db.piezas`; un nombre de corte inexistente tambien mostraba datos activos.
- Mensaje de excepcion: no aplica; se mostraba el conjunto incorrecto.
- Correccion: corte vacio genera tarjetas vacias; corte inexistente devuelve `Corte no encontrado.` con HTTP 404.
- Se conserva la combinacion de produccion activa e historica para las piezas de un corte conocido, incluyendo trabajos realizados despues del cierre.
- Pruebas: `test_empty_archived_cut_never_uses_current_pieces`, `test_missing_archived_cut_is_not_current_report`.

### 11. Solicitudes de recepcion mal formadas

- Severidad: media. Tipo: ejecucion y validacion.
- Ubicacion: `core/routes/admin_tools_routes.py`, endpoints scan, validar y reset.
- Errores reproducidos en scan:
  - `Error picking scan: 'list' object has no attribute 'get'`
  - `Error picking scan: 'int' object has no attribute 'strip'`
- Causa: asumir que el JSON era un diccionario con campos validos. Validar permitia decisiones arbitrarias o referencias que no correspondian a la pieza.
- Correccion: validar tipos y campos antes de escribir; aceptar solo `aprobado`/`rechazado`; vincular ID, codigo y modo rematador al actualizar produccion; devolver 404 si esa produccion no existe.
- Pruebas: `test_picking_invalid_payloads_return_400`, `test_validation_cannot_update_unrelated_production`, `test_valid_picking_validation_persists_and_returns_item`.
- Los errores `MagicMock is not JSON serializable` de la ejecucion inicial de pruebas eran consecuencia de mocks tras aceptar entradas invalidas; no se atribuyen a los documentos reales del proyecto.

### 12. Comparacion de fechas con distinta zona horaria

- Severidad: media. Tipo: ejecucion.
- Ubicacion: `core/routes/admin_tools_routes.py:api_picking_scan`.
- Mensaje completo reproducido: `Error picking scan: can't compare offset-naive and offset-aware datetimes`.
- Causa: comparar directamente fecha activa e historica sin normalizar zonas.
- Correccion: convertir ambas con `to_cl` y contemplar fecha ausente.
- Prueba: `test_picking_mixed_timezones_can_be_compared`.

### 13. Modal de recepcion anidado accidentalmente

- Severidad: media. Tipo: HTML y estructura de interfaz.
- Ubicacion: `templates/admin_picking.html`, cierre de `qrModal`.
- Sintoma: faltaba un `</div>`; el modal de historial y el de reinicio quedaban dentro del modal de camara.
- Mensaje de excepcion: no aplica; HTML desequilibrado.
- Correccion: cerrar el contenedor de camara antes de los otros modales. Tambien se normaliza a String el codigo usado en la comprobacion de duplicados del frontend.
- Prueba estructural: `test_picking_modals_are_siblings`; sintaxis JavaScript comprobada con Node.
- No se afirma validacion visual de los modales en navegador.

### 14. Conflicto de dependencias BSON

- Severidad: alta en instalaciones nuevas. Tipo: empaquetado.
- Ubicacion: `requirements.txt`.
- Causa: instalar `bson==0.5.10` junto con PyMongo, que ya incluye el paquete `bson`, puede sobrescribir archivos incompatibles.
- Correccion: eliminar la dependencia independiente y documentar que BSON procede de PyMongo.
- Mensaje de importacion de una instalacion fallida: no recopilado; el entorno actual tiene BSON de PyMongo y no reproduce ese conflicto.
- Prueba: `test_requirements_do_not_install_conflicting_bson`.
- No se alteraron paquetes del entorno activo ni del VPS. Instalaciones ya contaminadas requieren reinstalar PyMongo en su entorno controlado.

### 15. Fallos de base de datos sin respuesta controlada

- Severidad: media. Tipo: ejecucion y resiliencia.
- Ubicaciones: `core/helpers/soft_delete.py:soft_delete_many`, `core/app_factory.py:_register_security_hooks`.
- Error completo simulado: `pymongo.errors.OperationFailure: offline`.
- Causa: las excepciones escapaban de helpers y rutas no protegidas.
- Correccion: el helper devuelve mensajes claros sin borrar si no se guardan copias; el manejador general de PyMongo devuelve HTTP 503 y registra el detalle completo en logs sin enviarlo al navegador. No reintenta escrituras automaticamente.
- Pruebas: `test_generic_bulk_database_failure_returns_message`, `test_mongo_failure_is_503_and_logs_details`.
- Las rutas con capturas locales conservan sus respuestas locales. No todos los fallos son convertidos a 503.

### 16. Exito falso en borrado masivo de piezas

- Severidad: media. Tipo: logica y contrato API.
- Ubicacion: `core/routes/admin_crud_routes.py:piezas_eliminar_confirmar`.
- Sintoma: la API devolvia `success: True` incluso si el helper devolvia 0 eliminados o advertencia; el JSON mal formado se trataba como fallo interno.
- Correccion: validar una lista no vacia de codigos; no marcar exito cuando no hay eliminados o el helper devuelve advertencia.
- Pruebas: `test_empty_bulk_piece_payload_returns_400`, `test_bulk_piece_failure_is_not_reported_as_success`.

### 17. Inicializacion duplicada en arranque local

- Severidad: baja/media. Tipo: arranque y recursos.
- Ubicacion: `app.py`.
- Causa: importar `core.app_factory.app` crea la aplicacion, pero ejecutar `app.py` volvia a llamar `create_app`, abriendo otra instancia y repitiendo inicializacion e indices.
- Correccion: reutilizar `app` tambien en el arranque local.
- Prueba: `test_local_entrypoint_does_not_create_second_app`.
- Adicional: `creado_en` del corte usa `datetime.now(timezone.utc)` para evitar la advertencia de deprecacion de `datetime.utcnow()` en esa ruta.

### 18. Ordenacion de operadores con valores nulos

- Severidad: media condicionada a datos. Tipo: ejecucion.
- Ubicaciones: listados en `core/routes/soporte_produccion_routes.py` y `core/routes/admin_produccion_routes.py`.
- Sintoma por analisis: `sorted` sobre una mezcla de `None` y nombres puede lanzar `TypeError`.
- Mensaje exacto del servidor: no recopilado; no se presenta como reproduccion de produccion.
- Correccion: excluir valores vacios y ordenar usando `key=str`.

## Archivos modificados en esta revision

| Archivo | Modificacion |
|---|---|
| `app.py` | Reutilizacion de la aplicacion en arranque local |
| `requirements.txt` | Retirada del BSON independiente |
| `core/app_factory.py` | CSRF ampliado, respuestas JSON y manejadores de errores |
| `core/helpers/auth.py` | Validacion de sesion y credenciales |
| `core/helpers/date_utils.py` | Error especifico para fechas y rangos invertidos |
| `core/helpers/reporting.py` | Conteo unico de alias de codigos |
| `core/helpers/soft_delete.py` | Instantanea de IDs y mensajes de fallo en borrado generico |
| `core/routes/auth_routes.py` | Campos ausentes e ID de sesion |
| `core/routes/soporte_produccion_routes.py` | Filtros, validacion y archivo protegido |
| `core/routes/admin_dashboard_routes.py` | Borrado limitado a instantaneas y fecha UTC |
| `core/routes/admin_tools_routes.py` | Validacion, fechas y reinicio protegido |
| `core/routes/admin_crud_routes.py` | Validacion y resultado real de borrado de piezas |
| `core/routes/admin_produccion_routes.py` | Operadores nulos en listados |
| `core/routes/admin_informes_avanzados_routes.py` | Aislamiento de cortes vacios/inexistentes |
| `templates/admin_picking.html` | Cierre de modal y normalizacion del codigo |
| `test_project_stability.py` | 33 pruebas de regresion nuevas |

`templates/crud_produccion.html`, la funcion de borrado seleccionado de produccion y `test_soporte_produccion_masiva.py` ya estaban modificados al iniciar la revision; no se revirtieron.

## Pruebas y resultados

Comando principal:

```powershell
python -m unittest test_project_stability test_soporte_produccion_masiva -v
```

Resultado: **45 pruebas aprobadas** en 3,205 segundos. Incluye 33 pruebas nuevas de estabilidad y 12 existentes de eliminacion masiva. Las nuevas pruebas registran todas las rutas del proyecto sobre una aplicacion Flask de prueba y usan el decorador real de permisos. Los hooks reales se cargan por AST para evitar que la importacion de `app_factory` conecte a MongoDB. Incluyen renderizado de la pantalla de soporte con su layout real, conteo alfanumerico y produccion posterior al corte reflejada en las tarjetas historicas.

Comprobaciones adicionales:

```powershell
python -m compileall -q core app.py test_project_stability.py test_soporte_produccion_masiva.py
git diff --check
```

- Compilacion Python: correcta.
- Plantillas Jinja2: 43 compiladas correctamente.
- JavaScript de recepcion y seleccion masiva: sintaxis valida con Node, sustituyendo interpolaciones Jinja.
- Pyflakes: sin nombres indefinidos; seis advertencias menores de elementos no utilizados.
- Prueba anterior de 1.000 registros: una operacion masiva de copia y una de borrado, con Mongo simulado. No es una medicion de rendimiento del VPS.
- No se ejecuto `unittest discover` indiscriminadamente: hay scripts antiguos de prueba/recuperacion fuera de estas suites cuyo acceso a datos no se garantiza inocuo.

## Advertencias y riesgos pendientes

1. **Operaciones no transaccionales entre colecciones.** Cortes, papelera y recepcion pueden dejar copias junto a originales si hay fallo parcial. Se evito borrar registros sin copia confirmada y se informa el problema, pero no se implementaron transacciones: hay que comprobar primero que MongoDB use una topologia compatible y definir recuperacion/migracion.
2. **Recepcion concurrente.** El patron comprobar-existencia y luego insertar de scan/validar no garantiza exclusividad entre trabajadores. Para garantizarla se necesita un indice unico normalizado o un mecanismo atomico, previa revision de duplicados existentes. No se crearon indices unicos ni se eliminaron datos para no romper instalaciones actuales.
3. **Datos enviados a HTML dinamico.** Recepcion y otras plantillas usan `innerHTML` con campos de usuario/base de datos. Es un riesgo de XSS que requiere escapado sistematico y pruebas de navegador. No se afirma que haya quedado resuelto por corregir CSRF.
4. **Reglas de planificacion y limites simultaneos.** La compilacion y registro de rutas no sustituyen pruebas de concurrencia de cupos, armado x2 o redistribucion con datos reales. No se cambiaron esas reglas.
5. **Avisos Pyflakes.** Variables no utilizadas en `admin_planificacion_routes.py` y imports no utilizados en `admin_produccion_routes.py`, `recycle_bin_routes.py` y `soporte_basic_routes.py`. No son errores de ejecucion ni nombres indefinidos; se conservaron para evitar una limpieza ajena a las correcciones funcionales.
6. **Versiones del entorno.** El Python local es 3.13 y PyMongo instalado es 4.9.2; `requirements.txt` fija PyMongo 4.6.1. Falta ejecutar las mismas suites con las versiones exactas de produccion y una instalacion limpia.
7. **Logs y estado historico reales.** Sin logs del VPS no se puede inventariar todos sus errores de ejecucion ni asegurar la consistencia de registros archivados previamente.

## Verificacion antes de desplegar

1. Guardar backup de MongoDB y confirmar que el despliegue incluya estos cambios; no hay commit ni push realizados por esta revision.
2. Probar en staging con las mismas versiones que el VPS y una copia anonimizada de datos.
3. Ejecutar las 45 pruebas y la compilacion.
4. Probar en navegador como soporte: seleccion masiva, cancelar/confirmar modal, resumen de errores, recepcion y sus modales, filtros y cambios de contraseña.
5. Hacer un corte solo en staging, producir despues una pieza del corte anterior y comprobar que sus tarjetas historicas actualizan pendientes sin mezclar piezas del periodo nuevo.
6. Probar envios simultaneos, perdida de conexion y reinicio durante cortes/archivos. Resolver los riesgos pendientes antes de prometer atomicidad o exclusividad.
7. Una vez aprobado staging, desplegar en VPS, reiniciar Gunicorn y revisar los logs de error/acceso. No ejecutar pruebas destructivas sobre registros reales.

## Prevencion de regresiones

- Ejecutar ambas suites antes de cada despliegue.
- Mantener los casos de fallos de copia, snapshot, CSRF, fechas y alias como requisito de regresion.
- No silenciar excepciones de escrituras masivas como si fueran exitosas.
- No reintentar automaticamente operaciones de escritura con resultado desconocido.
- Guardar detalles tecnicos en logs y devolver mensajes claros al usuario sin exponer datos internos.
- No presentar compilacion o mocks como verificacion de MongoDB, del VPS o de la interfaz visual.
