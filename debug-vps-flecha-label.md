# Debug Session: vps-flecha-label
- **Status**: [OPEN]
- **Issue**: En la VPS, la impresion de etiquetas muestra `flecha` como `N/A`, mientras que en local funciona correctamente.
- **Debug Server**: http://127.0.0.1:7777/event
- **Log File**: `.dbg/trae-debug-log-vps-flecha-label.ndjson`

## Reproduction Steps
1. Abrir `/soporte/etiquetas` en la VPS.
2. Buscar una pieza que en local imprima `flecha`.
3. Imprimir la etiqueta.
4. Verificar si `flecha` sale como `N/A`.

## Hypotheses & Verification
| ID | Hypothesis | Likelihood | Effort | Evidence |
|----|------------|------------|--------|----------|
| A | En la VPS la pieza maestra no tiene `flecha` guardada en MongoDB. | High | Low | Pending |
| B | La VPS corre una version anterior del codigo de etiquetas. | High | Medium | Pending |
| C | La ruta de etiquetas en VPS arma `piezas_impresion` desde datos distintos a local. | Medium | Medium | Pending |
| D | El valor `flecha` existe pero llega nulo/vacio por inconsistencia de datos historicos o de carga. | High | Low | Pending |
| E | La VPS usa otra forma de arranque/instancia y no esta cargando el ultimo cambio. | Medium | Medium | Pending |

## Log Evidence
- Pending

## Verification Conclusion
- Pending
