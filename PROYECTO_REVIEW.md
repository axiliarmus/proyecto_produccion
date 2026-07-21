# Reporte de Revisión y Auditoría de Código - Proyecto Producción

Este documento detalla los problemas de arquitectura, despliegue, seguridad y rendimiento identificados en el proyecto, así como propuestas concretas de mejora y soluciones a los errores reportados en las sesiones de depuración abiertas (`.dbg/*.md`).

---

## 🛑 Problemas Críticos Identificados

### 1. Desactivación Silenciosa de Índices en Producción
* **Archivo afectado:** [app.py](file:///c:/Users/Axiliarmu/Desktop/clone%20repo/proyecto_produccion/app.py)
* **Descripción:** 
  La línea que ejecuta `ensure_mongo_indexes(server_app)` se encuentra dentro del bloque `if __name__ == "__main__":`. 
  Cuando la aplicación se ejecuta en producción utilizando un servidor WSGI como **Gunicorn** (configurado en `start_production.sh`) o a través de **Phusion Passenger** (cPanel, mediante `passenger_wsgi.py`), este bloque **no se ejecuta**, ya que la aplicación se importa como módulo y no se corre directamente.
* **Impacto:** 
  - Las consultas se ejecutarán en producción sin índices a medida que crezca la base de datos, degradando críticamente el rendimiento.
  - El índice TTL (`expireAt`) necesario para que expire el guard de registros duplicados (`operator_submission_guards`) nunca se creará automáticamente en la base de datos de producción.
* **Solución recomendada:** 
  Mover la llamada `ensure_mongo_indexes(app)` al final del método `create_app()` en [app_factory.py](file:///c:/Users/Axiliarmu/Desktop/clone%20repo/proyecto_produccion/core/app_factory.py) para asegurar que siempre se ejecute al inicializarse el servidor, independientemente de cómo se arranque.

---

### 2. Conflicto y Caché de Despliegue en VPS (Passenger vs. Gunicorn)
* **Archivos afectados:** [.htaccess](file:///c:/Users/Axiliarmu/Desktop/clone%20repo/proyecto_produccion/.htaccess), [passenger_wsgi.py](file:///c:/Users/Axiliarmu/Desktop/clone%20repo/proyecto_produccion/passenger_wsgi.py), [GUIA_VPS.md](file:///c:/Users/Axiliarmu/Desktop/clone%20repo/proyecto_produccion/GUIA_VPS.md)
* **Descripción:** 
  Existe una inconsistencia en cómo está configurado el entorno de VPS:
  - `.htaccess` y `passenger_wsgi.py` configuran **Phusion Passenger** (típico en hostings compartidos/cPanel).
  - `GUIA_VPS.md` y `start_production.sh` instruyen desplegar usando **Caddy + Gunicorn**.
  Si el servidor tiene Passenger activo (debido al `.htaccess`), Apache interceptará las peticiones y ejecutará la aplicación usando `passenger_wsgi.py`. Los cambios realizados en el código no se reflejarán inmediatamente en el navegador porque Passenger mantiene los procesos de Python en caché.
* **Impacto:** 
  - Se explica por qué en local funciona la visualización y edición de campos como `flecha`, pero en la VPS el listado de etiquetas muestra `N/A`. La VPS está ejecutando código antiguo en memoria.
  - Conflictos de puertos o consumo de recursos redundantes si Gunicorn y Passenger se ejecutan al mismo tiempo.
* **Solución recomendada:**
  - Si se utiliza la configuración cPanel con Passenger, cada vez que se suba una actualización del código, es obligatorio reiniciar Passenger ejecutando:
    ```bash
    mkdir -p tmp && touch tmp/restart.txt
    ```
  - Si se utiliza la configuración de `GUIA_VPS.md` con Caddy, se recomienda eliminar o renombrar el archivo `.htaccess` para evitar que Apache intente arrancar su propia instancia.

---

### 3. Lógica Fallida del Guard de Doble Envío (`Submission Guard`)
* **Archivo afectado:** [operator_routes.py](file:///c:/Users/Axiliarmu/Desktop/clone%20repo/proyecto_produccion/core/routes/operator_routes.py)
* **Descripción:** 
  Para solucionar un bug donde el operador no podía registrar una misma pieza dos veces en modo `armador`, se desactivó por completo la validación del backend convirtiendo `release_submission_guard()` en un no-op (`pass`).
  El verdadero problema en el código original **no era que la base de datos TTL fallara**, sino que **el guard no se liberaba al finalizar un registro exitoso**. La función `release_submission_guard` solo se invocaba en caso de excepciones o fallas de validación. Al completarse correctamente, el documento del guard permanecía en la colección de MongoDB hasta que el proceso TTL de Mongo lo borrara (lo cual ocurre en ciclos de ~60 segundos), bloqueando segundos envíos legítimos durante ese lapso.
* **Impacto:**
  - El backend ha quedado desprotegido ante envíos duplicados concurrentes (causados por doble clic rápido, reintentos de red o scripts externos).
  - El bloqueo mediante JS introducido en `templates/operador.html` es una buena práctica visual, pero es eludible y no reemplaza la seguridad del servidor.
* **Solución recomendada:**
  Restaurar el backend del guard de envío, pero asegurando su correcta eliminación al final de la ruta:
  ```python
  # Definición correcta de liberación del guard
  def release_submission_guard():
      if guard_acquired:
          db.operator_submission_guards.delete_one({"_id": submission_guard_id})
  
  # Llamar SIEMPRE a release_submission_guard() justo antes de los redirects finales de éxito
  ```

---

## 🐛 Errores de Interfaz y Lógica Secundaria

### 4. Renderizado del texto "None" en los Formularios de Edición
* **Archivo afectado:** [pieza_form.html](file:///c:/Users/Axiliarmu/Desktop/clone%20repo/proyecto_produccion/templates/pieza_form.html)
* **Descripción:** 
  Al editar una pieza, los campos opcionales (`cuerda_interna`, `cuerda_externa`, `flecha`) que están guardados como `null` en MongoDB se cargan en Python como `None`. En la plantilla Jinja se evalúa:
  `value="{{ pieza.cuerda_interna if pieza and pieza.cuerda_interna is defined else '' }}"`
  Como la propiedad `cuerda_interna` **está definida** (aunque su valor sea `None`), la expresión devuelve `None`, renderizando literalmente la palabra `"None"` en la caja de texto del formulario.
* **Impacto:** 
  El usuario tiene que borrar manualmente la palabra "None" de los campos vacíos antes de poder guardar o corregir los datos.
* **Solución recomendada:** 
  Cambiar la comprobación en Jinja para validar explícitamente que no sea nulo:
  ```html
  value="{{ pieza.cuerda_interna if (pieza and pieza.cuerda_interna is not none) else '' }}"
  ```

---

### 5. Sobrecarga de Consultas a la Base de Datos en el Middleware de Sesión
* **Archivo afectado:** [auth.py](file:///c:/Users/Axiliarmu/Desktop/clone%20repo/proyecto_produccion/core/helpers/auth.py)
* **Descripción:** 
  El decorador `@login_required` realiza una consulta a la base de datos (`db.usuarios.find_one`) en **cada petición HTTP** que requiere login para comprobar si la contraseña del usuario ha expirado (`password_changed_at`).
* **Impacto:** 
  Carga innecesaria en MongoDB. Para un sistema con decenas de operarios registrando piezas concurrentemente, esto multiplica exponencialmente el número de operaciones de lectura sobre la colección `usuarios`.
* **Solución recomendada:**
  Guardar la fecha del último cambio de contraseña (`password_changed_at`) o una bandera `password_expired: False` en el objeto de `session` al momento del inicio de sesión (en la ruta `/login`). Solo revalidar contra la base de datos si expira el tiempo de sesión o si se actualizan credenciales.

---

## 🔒 Mejoras de Seguridad y Buenas Prácticas

### 6. Credenciales por Defecto Expuestas en Código (`seed_default_users`)
* **Archivo afectado:** [auth.py](file:///c:/Users/Axiliarmu/Desktop/clone%20repo/proyecto_produccion/core/helpers/auth.py)
* **Descripción:** 
  El método `seed_default_users` crea las cuentas `admin` con contraseña `admin123` y `soporte` con `soporte123` si no existen.
* **Impacto:** 
  Si el parámetro `ENABLE_SEED` se activa por error en producción, estas cuentas predeterminadas y vulnerables se crearán automáticamente, permitiendo accesos no autorizados si alguna vez se eliminaron las cuentas de producción o si es una base de datos nueva.
* **Solución recomendada:** 
  - Asegurarse de que `ENABLE_SEED` esté configurado en `false` en el `.env` de producción.
  - Opcionalmente, cambiar `seed_default_users` para que lea las contraseñas iniciales desde variables de entorno (`INITIAL_ADMIN_PASSWORD`), en lugar de escribirlas en texto plano en el código.

### 7. Uso de `'unsafe-inline'` y `'unsafe-eval'` en la directiva Content-Security-Policy (CSP)
* **Archivo afectado:** [app_factory.py](file:///c:/Users/Axiliarmu/Desktop/clone%20repo/proyecto_produccion/core/app_factory.py)
* **Descripción:** 
  Para permitir la ejecución de scripts embebidos en los HTML de las vistas (como el manejador del envío del formulario en `pieza_form.html`), se permite la directiva `'unsafe-inline'` y `'unsafe-eval'`.
* **Impacto:** 
  Debilita significativamente la protección contra ataques de Cross-Site Scripting (XSS).
* **Solución recomendada:** 
  Mover el código JavaScript en línea de las plantillas HTML a archivos estáticos `.js` dentro de `/static/js` y cargarlos de manera segura, permitiendo retirar `'unsafe-inline'` de la configuración de la CSP.

---

## 📝 Conclusiones sobre las Sesiones de Depuración Abiertas (`.dbg/*.md`)

1. **`debug-operator-armado-duplicate.md`**:
   * **Estado real**: El problema radica en que el backend guard de duplicados no se liberaba de inmediato al terminar un registro exitoso, obligando a esperar al proceso de limpieza periódico de MongoDB.
   * **Acción**: Volver a habilitar el guard pero con la llamada de liberación `release_submission_guard()` añadida al flujo de inserción exitosa.

2. **`debug-piece-flecha-save.md` y `debug-vps-flecha-label.md`**:
   * **Estado real**: Las pruebas unitarias confirman que el código local guarda y muestra el campo `flecha` correctamente. La discrepancia en la VPS (`N/A`) se debe casi con total seguridad a que **Phusion Passenger en la VPS tiene la aplicación antigua en caché** y no ha cargado los últimos cambios de base de datos/código.
   * **Acción**: Reiniciar el proceso de Passenger tocando `tmp/restart.txt` en la raíz de la VPS.
