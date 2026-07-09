# Debug Session: piece-flecha-save
- **Status**: [OPEN]
- **Issue**: `flecha` no se muestra en el listado de piezas, la edicion simple no guarda cambios y la edicion masiva rechaza el campo.
- **Debug Server**: http://127.0.0.1:7777/event
- **Log File**: `.dbg/trae-debug-log-piece-flecha-save.ndjson`

## Reproduction Steps
1. Abrir una pieza en `/admin/piezas/<id>/editar`.
2. Cambiar `flecha` u otro valor simple y guardar.
3. Verificar si el listado de `/admin/piezas` refleja el cambio.
4. Probar edicion masiva sobre `flecha`.

## Hypotheses & Verification
| ID | Hypothesis | Likelihood | Effort | Evidence |
|----|------------|------------|--------|----------|
| A | El formulario de edicion no envia `flecha` o envia un valor inesperado. | High | Low | Pending |
| B | La ruta de edicion simple/masiva rechaza `flecha` por normalizacion o validacion. | High | Low | Pending |
| C | El dato si se guarda, pero el listado mostrado consulta otra fuente o una instancia vieja. | Medium | Medium | Pending |
| D | Hay una diferencia de tipo (`str`/`float`/`None`) que impide actualizar y no da feedback visible. | High | Low | Pending |
| E | La instancia local en ejecucion no corresponde al codigo actual del repo. | Medium | Low | Pending |

## Log Evidence
- `admin_crud_routes.py:piezas_editar_post` reporta que `flecha` llega en el formulario con valor `98.76`.
- `admin_crud_routes.py:piezas_list` reporta que el listado renderiza la pieza `k1` con `flecha=98.76`.
- Reproduccion automatizada con `test_client`:
  - `GET /admin/piezas/<id>/editar` -> `200`
  - `POST /admin/piezas/<id>/editar` -> `302`
  - Mongo queda con `new_flecha_db=98.76`
  - El HTML de `/admin/piezas` contiene el valor actualizado y el header `Flecha`
  - La edicion masiva tambien guarda `mass_flecha_db=77.77`
  - La vista con resultados de `/admin/piezas/masivo` contiene la opcion `Flecha`

## Verification Conclusion
- Hipotesis A: **Confirmada parcialmente**. El formulario si envia `flecha`.
- Hipotesis B: **Rechazada** para la app actual. Edicion simple y masiva guardan correctamente en reproduccion automatizada.
- Hipotesis C: **Confirmada** para la app actual. El listado si muestra `flecha`.
- Hipotesis D: **Rechazada** en la app actual con valores numericos validos.
- Hipotesis E: **Mas probable**. Lo que el usuario esta viendo no coincide con la instancia/ruta HTML reproducida por la app actual.
