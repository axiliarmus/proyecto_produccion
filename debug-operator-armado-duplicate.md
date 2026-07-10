# Debug Session: operator-armado-duplicate
- **Status**: [OPEN]
- **Issue**: El operador no puede ingresar dos veces en armado una pieza.
- **Debug Server**: http://127.0.0.1:7777/event
- **Log File**: .dbg/trae-debug-log-operator-armado-duplicate.ndjson

## Reproduction Steps
1. Iniciar sesión como operador.
2. Registrar una pieza en modo `armador`.
3. Intentar registrar nuevamente la misma pieza en modo `armador`.
4. Observar si el sistema bloquea el segundo registro y con qué mensaje.

## Hypotheses & Verification
| ID | Hypothesis | Likelihood | Effort | Evidence |
|----|------------|------------|--------|----------|
| A | La validación actual corta el segundo/tercer armado por la regla `armado_count >= 2`. | High | Low | Pending |
| B | El conteo `armado_count` está sumando registros históricos o duplicados que no debería considerar. | High | Med | Pending |
| C | El `submission_guard` temporal está bloqueando un envío válido y parece un error de negocio. | Med | Med | Pending |
| D | La normalización de `codigo_pieza` entre string/int provoca consultas inconsistentes. | Med | Med | Pending |
| E | El flujo cambia a colección histórica y aplica reglas diferentes al reintento. | Low | Med | Pending |

## Log Evidence
- **Pre-fix**:
  - `Submission guard duplicado; bloqueo temporal` para la misma pieza incluso después de esperar 16 segundos.
  - El segundo intento no llegaba a evaluar `armado_count >= 2`; el bloqueo ocurría antes, en la inserción del guard temporal.
  - El conteo previo del primer intento mostraba `armado_count=0`, y el primer insert se completaba correctamente.
- **Post-fix**:
  - `Submission guard expirado recuperado correctamente` después de superar los 15 segundos.
  - En el segundo intento, el conteo mostró `armado_count=1`.
  - El segundo insert de `armador` se completó correctamente y el total pasó de 1 a 2 registros.

## Verification Conclusion
- **Hypothesis A**: Rechazada como causa principal del problema reportado. La regla `armado_count >= 2` no era la que impedía el segundo registro.
- **Hypothesis B**: Rechazada para este caso reproducido. Los conteos fueron coherentes (`0` en el primer insert, `1` en el segundo post-fix).
- **Hypothesis C**: Confirmada. El `submission_guard` seguía ocupando la llave aunque ya hubiera expirado, porque el TTL de Mongo no limpia exactamente al segundo 15.
- **Hypothesis D**: Rechazada para el caso reproducido. El código de pieza se resolvió consistentemente.
- **Hypothesis E**: Rechazada para el caso reproducido. No intervino la colección histórica.

- **Comparación pre-fix vs post-fix**:
  - Pre-fix: segundo intento tras 16s -> bloqueado por guard temporal -> total registros `1`.
  - Post-fix: segundo intento tras 16s -> guard expirado recuperado -> total registros `2`.
