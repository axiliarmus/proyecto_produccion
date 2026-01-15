# ==============================================================================
# 1. CONFIGURACIÓN E IMPORTACIONES
# ==============================================================================
# Importamos las librerías necesarias para el funcionamiento de la aplicación.
import os
import json
import secrets
from datetime import datetime, date, timedelta
from bson import ObjectId
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from io import BytesIO
import pandas as pd
from pymongo import MongoClient
from datetime import timezone
from werkzeug.middleware.proxy_fix import ProxyFix

# ==============================================================================
# 2. CARGA DE VARIABLES DE ENTORNO
# ==============================================================================
# Cargamos el archivo .env para obtener credenciales y configuraciones sensibles.
load_dotenv()

# ==============================================================================
# 3. INICIALIZACIÓN DE LA APP FLASK
# ==============================================================================
app = Flask(__name__)

# Configuración de la clave secreta para firmar sesiones y cookies.
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY no definida en .env")

app.secret_key = SECRET_KEY

# ==============================================================================
# 4. CONFIGURACIÓN DE PROXY (IMPORTANTE PARA PRODUCCIÓN)
# ==============================================================================
# Esto es necesario cuando la app corre detrás de un proxy inverso (como Nginx o Caddy).
# Asegura que Flask reciba la IP real del usuario y el protocolo correcto (HTTPS).
app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=1,
    x_proto=1,
    x_host=1,
    x_port=1
)

# ==============================================================================
# 5. SEGURIDAD DE COOKIES
# ==============================================================================
# Configuramos las cookies para que sean seguras (solo HTTPS, HttpOnly).
app.config.update(
    SESSION_COOKIE_SECURE=True,   # Solo enviar cookies sobre HTTPS
    SESSION_COOKIE_HTTPONLY=True, # No accesible via JavaScript
    SESSION_COOKIE_SAMESITE="Lax" # Protección contra CSRF
)

# ==============================================================================
# 6. PROTECCIÓN CSRF (Cross-Site Request Forgery)
# ==============================================================================
def _get_csrf_token():
    """Genera o recupera el token CSRF para la sesión actual."""
    token = session.get('_csrf_token')
    if not token:
        token = secrets.token_hex(32)
        session['_csrf_token'] = token
    return token

@app.context_processor
def inject_csrf():
    """Inyecta el token CSRF en todas las plantillas HTML automáticamente."""
    return {'csrf_token': session.get('_csrf_token') or _get_csrf_token()}

@app.before_request
def csrf_protect():
    """Verifica el token CSRF en cada petición POST para evitar ataques."""
    if request.method == 'POST':
        token = request.form.get('_csrf_token') or request.headers.get('X-CSRFToken')
        expected = session.get('_csrf_token') or _get_csrf_token()
        if not token or token != expected:
            return "CSRF token inválido", 400

# ==============================================================================
# 7. CONFIGURACIÓN REGIONAL (HORA CHILE)
# ==============================================================================
CL = timezone(timedelta(hours=-3))

# ==============================================================================
# 8. CONEXIÓN A BASE DE DATOS (MONGODB)
# ==============================================================================
client = MongoClient(os.getenv("MONGO_URI"))
db = client["miBase"]


# ==============================================================================
# 9. VARIABLES GLOBALES Y HELPERS DE SEGURIDAD
# ==============================================================================
# Variable para almacenar la URL del túnel (si se activa)
tunnel_url = None

# Diccionario para controlar intentos de login fallidos (Rate Limiting)
# Formato: { 'ip_address': (intentos, datetime_ultimo_intento) }
login_attempts = {}

def log_audit(accion, detalle):
    """
    Sistema de Auditoría Simple.
    Registra acciones críticas (como borrar/editar históricos) en la consola.
    Esto permite rastrear quién hizo qué cambios importantes.
    """
    user = session.get('username', 'Desconocido')
    timestamp = now_cl().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[AUDIT] {timestamp} | USER: {user} | ACTION: {accion} | DETAILS: {detalle}")



# ============================================================
#              IMPORTS NECESARIOS (asegúrate de tenerlos)
# ============================================================
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from bson import ObjectId

# ============================================================
#     MANEJO CENTRALIZADO DE FECHAS SIN DESFASES
# ============================================================

def now_cl():
    """Devuelve la fecha/hora actual en Chile (UTC-3), siempre aware."""
    return datetime.now(timezone.utc).astimezone(CL)

def to_cl(dt):
    """Convierte cualquier datetime de MongoDB a Chile."""
    if dt is None:
        return None

    # Si viene naive → asumir UTC
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt.astimezone(CL)

# ============================================================
#                     LOGIN REQUIRED
# ============================================================
def login_required(roles=None):
    """
    Protege rutas según uno o varios roles
    y obliga a cambiar contraseña si está expirada.
    
    roles puede ser:
        - None (cualquiera logeado)
        - 'administrador'
        - ['administrador', 'supervisor']
    """
    # Normalizamos roles
    if isinstance(roles, str):
        roles = [roles]

    def wrapper(fn):
        def _wrapped(*args, **kwargs):

            # ============================
            # 1) Usuario no logueado
            # ============================
            if 'user_id' not in session:
                flash('Inicia sesión para continuar', 'warning')
                return redirect(url_for('login'))

            # ============================
            # 2) Excepción: no verificar expiración en cambiar_password
            # ============================
            if request.endpoint == "cambiar_password":
                return fn(*args, **kwargs)

            # ============================
            # 3) Verificar expiración de contraseña
            # ============================
            user = db.usuarios.find_one({'_id': ObjectId(session['user_id'])})
            if user:
                ultimo_cambio = user.get('password_changed_at')

                if not ultimo_cambio:
                    return redirect(url_for('cambiar_password'))

                if datetime.utcnow() - ultimo_cambio > timedelta(days=30):
                    flash("Tu contraseña ha expirado. Debes cambiarla.", "warning")
                    return redirect(url_for('cambiar_password'))

            # ============================
            # 4) Validación de rol
            # ============================
            user_role = session.get('role')

            if roles and user_role not in roles:
                # No autorizado → redirigir a su página principal
                flash("No tienes permisos para acceder a esta sección.", "danger")

                if user_role == "administrador":
                    return redirect(url_for("admin_dashboard"))
                elif user_role == "supervisor":
                    return redirect(url_for("supervisor_home"))
                elif user_role == "soporte":
                    return redirect(url_for("soporte_dashboard"))
                elif user_role == "cliente":
                    return redirect(url_for("admin_informes"))
                else:
                    return redirect(url_for("operador_home"))

            # ============================
            # Si todo OK → permitir acceso
            # ============================
            return fn(*args, **kwargs)

        _wrapped.__name__ = fn.__name__
        return _wrapped
    return wrapper



# ============================================================
#                  CREAR ADMIN POR DEFECTO
# ============================================================
def seed_admin():
    """Crea un usuario admin por defecto si no existe."""
    if not db.usuarios.find_one({'usuario': 'admin'}):
        db.usuarios.insert_one({
            'usuario': 'admin',
            'nombre': 'Administrador',
            'tipo': 'administrador',
            'password': generate_password_hash('admin123'),
            'password_changed_at': datetime.utcnow()  # ← necesario para el control de expiración
        })
        print("> Usuario admin creado (admin / admin123)")


def seed_soporte():
    if not db.usuarios.find_one({'usuario': 'soporte'}):
        db.usuarios.insert_one({
            'usuario': 'soporte',
            'nombre': 'Soporte',
            'tipo': 'soporte',
            'password': generate_password_hash('soporte123'),
            'password_changed_at': datetime.utcnow()
        })
        print("> Usuario soporte creado (soporte / soporte123)")

@app.before_request
def ensure_seed():
    if os.getenv("ENABLE_SEED", "false").lower() == "true":
        if request.endpoint not in ('static',):
            seed_admin()
            seed_soporte()


# ============================================================
#                     LOGIN / LOGOUT
# ============================================================

@app.route('/', methods=['GET'])
def index():
    if 'user_id' in session:
        role = session.get('role')

        user = db.usuarios.find_one({'_id': ObjectId(session['user_id'])})
        if user:
            ultimo_cambio = to_cl(user.get("password_changed_at"))

            if not ultimo_cambio or (now_cl() - ultimo_cambio) > timedelta(days=30):
                return redirect(url_for('cambiar_password'))

        if role == 'administrador':
            return redirect(url_for('admin_dashboard'))
        elif role == 'supervisor':
            return redirect(url_for('supervisor_home'))
        elif role == 'soporte':
            return redirect(url_for('soporte_dashboard'))
        elif role == 'cliente':
            return redirect(url_for('admin_informes'))
        else:
            return redirect(url_for('operador_home'))

    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # ---------------------------------------------------------
        # SEGURIDAD: PROTECCIÓN CONTRA FUERZA BRUTA
        # ---------------------------------------------------------
        ip = request.remote_addr
        now = datetime.now()
        
        # Verificar si la IP está bloqueada temporalmente
        if ip in login_attempts:
            attempts, last_time = login_attempts[ip]
            if attempts >= 5:
                # Si falló 5 veces, bloquear por 15 minutos
                if now - last_time < timedelta(minutes=15):
                    remaining = 15 - (now - last_time).seconds // 60
                    flash(f"Demasiados intentos fallidos. Inténtalo de nuevo en {remaining} minutos.", "danger")
                    return render_template('login.html')
                else:
                    # Desbloquear si ya pasó el tiempo
                    login_attempts[ip] = (0, now)

        # ---------------------------------------------------------
        # PROCESO DE LOGIN
        # ---------------------------------------------------------
        usuario = request.form.get('usuario', '').strip()
        password = request.form.get('password')

        user = db.usuarios.find_one({'usuario': usuario})

        if user and check_password_hash(user['password'], password):
            # Login exitoso: limpiar contador de intentos fallidos para esta IP
            if ip in login_attempts:
                del login_attempts[ip]

            session['user_id'] = str(user['_id'])
            session['username'] = user['usuario']
            session['nombre'] = user.get('nombre', user['usuario'])
            session['role'] = user['tipo']

            # Verificar caducidad de contraseña (30 días)
            pw_date = to_cl(user.get("password_changed_at"))

            if not pw_date or (now_cl() - pw_date) > timedelta(days=30):
                flash("Debes cambiar tu contraseña antes de continuar.", "warning")
                return redirect(url_for("cambiar_password"))

            flash(f"Bienvenido, {session['nombre']}", 'success')
            return redirect(url_for('index'))

        # Login fallido: registrar intento
        attempts, _ = login_attempts.get(ip, (0, now))
        login_attempts[ip] = (attempts + 1, now)
        
        flash('Usuario o contraseña inválidos', 'danger')

    return render_template('login.html')




@app.route('/logout')
@login_required()
def logout():
    """Cierra sesión limpia."""
    session.clear()
    flash('Sesión cerrada correctamente', 'info')
    return redirect(url_for('login'))



# ============================================================
#               CAMBIAR CONTRASEÑA (OBLIGATORIO)
# ============================================================

@app.route('/cambiar-password', methods=['GET', 'POST'])
@login_required()
def cambiar_password():
    if request.method == 'POST':
        nueva = request.form.get("password_nueva")
        repetir = request.form.get("password_repetir")

        if nueva != repetir:
            flash("Las contraseñas no coinciden.", "danger")
            return redirect(url_for('cambiar_password'))

        if len(nueva) < 6:
            flash("La contraseña debe tener al menos 6 caracteres.", "warning")
            return redirect(url_for('cambiar_password'))

        db.usuarios.update_one(
            {"_id": ObjectId(session["user_id"])},
            {"$set": {
                "password": generate_password_hash(nueva),
                "password_changed_at": now_cl()
            }}
        )

        flash("Contraseña actualizada correctamente 👌", "success")
        return redirect(url_for('index'))

    return render_template("cambiar_password.html")



# ============================================================
#                     CRUD USUARIOS
# ============================================================

@app.route('/admin/usuarios')
@login_required(['administrador', 'soporte'])
def usuarios_list():
    usuarios = list(db.usuarios.find({"usuario": {"$ne": "soporte"}}))
    return render_template('crud_usuarios.html', usuarios=usuarios)


@app.route('/admin/usuarios/nuevo')
@login_required(['administrador', 'soporte'])
def usuarios_nuevo_form():
    return render_template('usuario_form.html', modo='nuevo')


@app.route('/admin/usuarios/nuevo', methods=['POST'])
@login_required(['administrador', 'soporte'])
def usuarios_nuevo_post():
    usuario = request.form['usuario'].strip()
    nombre = request.form['nombre'].strip()
    tipo = request.form['tipo']
    
    precio_metro_armado = float(request.form.get('precio_metro_armado', 0))
    precio_metro_remate = float(request.form.get('precio_metro_remate', 0))
    precio_avo_armado = float(request.form.get('precio_avo_armado', 0))
    precio_avo_remate = float(request.form.get('precio_avo_remate', 0))

    password = generate_password_hash(request.form['password'])

    if db.usuarios.find_one({'usuario': usuario}):
        flash('El usuario ya existe', 'warning')
        return redirect(url_for('usuarios_list'))

    db.usuarios.insert_one({
        'usuario': usuario,
        'nombre': nombre,
        'tipo': tipo,
        'precio_metro_armado': precio_metro_armado,
        'precio_metro_remate': precio_metro_remate,
        'precio_avo_armado': precio_avo_armado,
        'precio_avo_remate': precio_avo_remate,
        'password': password
    })

    flash('Usuario creado correctamente ✔', 'success')
    return redirect(url_for('usuarios_list'))


@app.route('/admin/usuarios/<id>/editar')
@login_required(['administrador', 'soporte'])
def usuarios_editar_form(id):
    usuario = db.usuarios.find_one({'_id': ObjectId(id)})
    if not usuario:
        flash('Usuario no encontrado', 'danger')
        return redirect(url_for('usuarios_list'))

    return render_template('usuario_form.html', modo='editar', usuario=usuario)


@app.route('/admin/usuarios/<id>/editar', methods=['POST'])
@login_required(['administrador', 'soporte'])
def usuarios_editar_post(id):
    nombre = request.form['nombre'].strip()
    tipo = request.form['tipo']
    
    precio_metro_armado = float(request.form.get('precio_metro_armado', 0))
    precio_metro_remate = float(request.form.get('precio_metro_remate', 0))
    precio_avo_armado = float(request.form.get('precio_avo_armado', 0))
    precio_avo_remate = float(request.form.get('precio_avo_remate', 0))

    pwd = request.form.get('password', '').strip()

    update = {
        'nombre': nombre, 
        'tipo': tipo,
        'precio_metro_armado': precio_metro_armado,
        'precio_metro_remate': precio_metro_remate,
        'precio_avo_armado': precio_avo_armado,
        'precio_avo_remate': precio_avo_remate
    }
    if pwd:
        update['password'] = generate_password_hash(pwd)

    db.usuarios.update_one({'_id': ObjectId(id)}, {'$set': update})
    flash('Usuario actualizado ✔', 'success')
    return redirect(url_for('usuarios_list'))


@app.route('/admin/usuarios/<id>/delete', methods=['POST'])
@login_required(['administrador', 'soporte'])
def usuarios_delete(id):
    if str(session.get('user_id')) == id:
        flash('No puedes eliminar tu propio usuario', 'warning')
        return redirect(url_for('usuarios_list'))

    db.usuarios.delete_one({'_id': ObjectId(id)})
    flash('Usuario eliminado', 'info')
    return redirect(url_for('usuarios_list'))


# ============================================================
#                     CRUD BOXES
# ============================================================

@app.route('/admin/boxes')
@login_required(['administrador', 'soporte'])
def boxes_list():
    boxes = list(db.boxes.find())
    return render_template('crud_boxes.html', boxes=boxes)


@app.route('/admin/boxes/nuevo')
@login_required(['administrador', 'soporte'])
def boxes_nuevo_form():
    return render_template('box_form.html', modo='nuevo')


@app.route('/admin/boxes/nuevo', methods=['POST'])
@login_required(['administrador', 'soporte'])
def boxes_nuevo_post():
    codigo = request.form['codigo'].strip()
    descripcion = request.form['descripcion'].strip()

    if db.boxes.find_one({'codigo': codigo}):
        flash('El código del box ya existe', 'warning')
        return redirect(url_for('boxes_list'))

    db.boxes.insert_one({
        'codigo': codigo,
        'descripcion': descripcion,
        'created_at': datetime.utcnow()
    })

    flash('Box creado ✔', 'success')
    return redirect(url_for('boxes_list'))


@app.route('/admin/boxes/<id>/editar')
@login_required(['administrador', 'soporte'])
def boxes_editar_form(id):
    box = db.boxes.find_one({'_id': ObjectId(id)})
    if not box:
        flash('Box no encontrado', 'danger')
        return redirect(url_for('boxes_list'))

    return render_template('box_form.html', modo='editar', box=box)


@app.route('/admin/boxes/<id>/editar', methods=['POST'])
@login_required(['administrador', 'soporte'])
def boxes_editar_post(id):
    codigo = request.form['codigo'].strip()
    descripcion = request.form['descripcion'].strip()

    db.boxes.update_one({'_id': ObjectId(id)}, {
        '$set': {'codigo': codigo, 'descripcion': descripcion}
    })

    flash('Box actualizado ✔', 'success')
    return redirect(url_for('boxes_list'))


@app.route('/admin/boxes/<id>/delete', methods=['POST'])
@login_required(['administrador', 'soporte'])
def boxes_delete(id):
    db.boxes.delete_one({'_id': ObjectId(id)})
    flash('Box eliminado', 'info')
    return redirect(url_for('boxes_list'))
# ============================================================
#                     CRUD PIEZAS (NUEVO MODELO)
# ============================================================

@app.route('/admin/piezas')
@login_required(['administrador', 'soporte'])
def piezas_list():
    piezas = list(db.piezas.find().sort('codigo', 1))
    return render_template('crud_piezas.html', piezas=piezas)


# ==================== NUEVA PIEZA ====================

@app.route('/admin/piezas/nuevo')
@login_required(['administrador', 'soporte'])
def piezas_nuevo_form():
    return render_template('pieza_form.html', modo='nuevo', pieza=None)


@app.route('/admin/piezas/nuevo', methods=['POST'])
@login_required(['administrador', 'soporte'])
def piezas_nuevo_post():
    empresa = request.form['empresa'].strip()
    marco = request.form['marco'].strip()
    tramo = request.form['tramo'].strip()
    kilo_pieza = float(request.form['kilo_pieza'])
    cantidad = int(request.form['cantidad'])

    cuerda_interna = request.form.get("cuerda_interna", "").strip()
    cuerda_externa = request.form.get("cuerda_externa", "").strip()

    # Prefijo de ciclo actual
    conf = db.config.find_one({"key": "ciclo_actual"}) or {"value": "a"}
    prefijo = conf.get("value", "a")
    # Calcular siguiente secuencia dentro del prefijo actual
    count_prefijo = db.piezas.count_documents({"codigo": {"$regex": f"^{prefijo}"}})
    next_seq = count_prefijo + 1

    docs = []
    for i in range(cantidad):
        docs.append({
            "codigo": f"{prefijo}{next_seq + i}",
            "empresa": empresa,
            "marco": marco,
            "tramo": tramo,
            "kilo_pieza": kilo_pieza,
            "cuerda_interna": cuerda_interna,
            "cuerda_externa": cuerda_externa,
            "created_at": datetime.utcnow()
        })

    if docs:
        db.piezas.insert_many(docs)

    flash(f'✅ Se crearon {cantidad} piezas correctamente (desde código {prefijo}{next_seq}).', 'success')
    return redirect(url_for('piezas_list'))


# ==================== EDITAR PIEZA ====================

@app.route('/admin/piezas/<id>/editar')
@login_required(['administrador', 'soporte'])
def piezas_editar_form(id):
    pieza = db.piezas.find_one({'_id': ObjectId(id)})
    if not pieza:
        flash('Pieza no encontrada', 'warning')
        return redirect(url_for('piezas_list'))
    return render_template('pieza_form.html', modo='editar', pieza=pieza)


@app.route('/admin/piezas/<id>/editar', methods=['POST'])
@login_required(['administrador', 'soporte'])
def piezas_editar_post(id):
    empresa = request.form['empresa'].strip()
    marco = request.form['marco'].strip()
    tramo = request.form['tramo'].strip()
    tipo_precio = request.form['tipo_precio']
    kilo_pieza = float(request.form['kilo_pieza'])
    
    cuerda_interna = request.form.get("cuerda_interna", "").strip()
    cuerda_externa = request.form.get("cuerda_externa", "").strip()

    db.piezas.update_one(
        {'_id': ObjectId(id)},
        {'$set': {
            "empresa": empresa,
            "marco": marco,
            "tramo": tramo,
            "tipo_precio": tipo_precio,
            "kilo_pieza": kilo_pieza,
            "cuerda_interna": cuerda_interna,
            "cuerda_externa": cuerda_externa
        }}
    )

    flash('✅ Pieza actualizada con éxito', 'success')
    return redirect(url_for('piezas_list'))


# ==================== ELIMINAR ====================

@app.route('/admin/piezas/<id>/delete', methods=['POST'])
@login_required(['administrador', 'soporte'])
def piezas_delete(id):
    db.piezas.delete_one({'_id': ObjectId(id)})
    flash('Pieza eliminada', 'info')
    return redirect(url_for('piezas_list'))

# ============================================================
#                API DINÁMICA PARA LISTAS DEPENDIENTES
# ============================================================

@app.route('/api/marcos/<empresa>')
@login_required(["administrador", "supervisor", "soporte"])
def api_marcos(empresa):
    marcos = db.piezas.distinct("marco", {"empresa": empresa})
    return {"marcos": marcos}


@app.route('/api/tramos/<empresa>/<marco>')
@login_required(["administrador", "supervisor", "soporte"])
def api_tramos(empresa, marco):
    tramos = db.piezas.distinct("tramo", {"empresa": empresa, "marco": marco})
    return {"tramos": tramos}



# ============================================================
#       EDICIÓN MASIVA — PASO 1: FILTRAR Y VISTA PREVIA
# ============================================================

@app.route('/admin/piezas/masivo', methods=['GET', 'POST'])
@login_required(['administrador', 'soporte'])
def piezas_masivo():
    filtros = {}
    piezas = []

    # 🔥 Cargar empresas disponibles para Jinja
    empresas = db.piezas.distinct("empresa")

    if request.method == "POST":
        empresa = request.form.get("empresa")
        marco = request.form.get("marco")
        tramo = request.form.get("tramo")

        if empresa:
            filtros["empresa"] = empresa
        if marco:
            filtros["marco"] = marco
        if tramo:
            filtros["tramo"] = tramo

        piezas = list(db.piezas.find(filtros).sort("codigo", 1))

        if not piezas:
            flash("No se encontraron piezas con esos filtros.", "warning")

    return render_template(
        "piezas_masivo.html",
        piezas=piezas,
        filtros=json.dumps(filtros),
        empresas=empresas   # 👈 NECESARIO
    )


# ============================================================
#       EDICIÓN MASIVA — PASO 2: CONFIRMAR CAMBIOS
# ============================================================

@app.route('/admin/piezas/masivo/confirmar', methods=['POST'])
@login_required(['administrador', 'soporte'])
def piezas_masivo_confirmar():
    filtros = json.loads(request.form.get("filtros"))
    campo = request.form.get("campo")
    valor = request.form.get("valor")

    permitidos = ["empresa", "marco", "tramo", "kilo_pieza", "cuerda_interna", "cuerda_externa", "tipo_precio"]
    if campo not in permitidos:
        flash("Campo no permitido para edición masiva.", "danger")
        return redirect(url_for("piezas_masivo"))

    if not campo or not valor:
        flash("Debes indicar el campo y el valor a modificar.", "warning")
        return redirect(url_for("piezas_masivo"))

    # Campos numéricos
    if campo in ["kilo_pieza"]:
        try:
            valor = float(valor)
        except:
            flash("El valor debe ser numérico para este campo.", "danger")
            return redirect(url_for("piezas_masivo"))

    # Campos nuevos: cadenas simples
    if campo in ["cuerda_interna", "cuerda_externa"]:
        valor = valor.strip()

    # Campo Tipo de Precio
    if campo == "tipo_precio":
        valor = valor.strip().lower()
        if valor not in ["metro", "avo"]:
            flash("El tipo de precio debe ser 'metro' o 'avo'.", "danger")
            return redirect(url_for("piezas_masivo"))

    resultado = db.piezas.update_many(filtros, {"$set": {campo: valor}})

    flash(f"Se actualizaron {resultado.modified_count} piezas correctamente.", "success")
    return redirect(url_for("piezas_masivo"))




# ============================================================
#                     ADMIN PANEL E INFORMES
# ============================================================

@app.route('/admin')
@login_required(["administrador", "soporte"])
def admin_dashboard():
    total_usuarios = db.usuarios.count_documents({})
    total_boxes = db.boxes.count_documents({})
    total_piezas = db.piezas.count_documents({})
    total_produccion = db.produccion.count_documents({})

    return render_template(
        'admin_dashboard.html',
        total_usuarios=total_usuarios,
        total_boxes=total_boxes,
        total_piezas=total_piezas,
        total_produccion=total_produccion
    )


# ============================================================
#                         SOPORTE
# ============================================================

@app.route('/soporte')
@login_required('soporte')
def soporte_dashboard():
    return render_template('soporte_dashboard.html')

@app.route('/soporte/produccion', methods=['GET', 'POST'])
@login_required('soporte')
def soporte_produccion_list():
    codigo = None
    filtro = {}
    if request.method == 'POST':
        codigo = (request.form.get('codigo_pieza') or '').strip()
        if codigo:
            filtro['codigo_pieza'] = str(codigo)

    registros = list(db.produccion.find(filtro).sort('fecha', -1))
    for r in registros:
        if r.get('fecha'):
            r['fecha'] = to_cl(r.get('fecha'))
    return render_template('crud_produccion.html', registros=registros, codigo_sel=codigo)

@app.route('/admin/corte_mensual', methods=['POST'])
@login_required(['administrador', 'soporte'])
def admin_corte_mensual():
    nombre_custom = request.form.get('nombre')
    mes = request.form.get('mes')  # YYYY-MM
    fecha_inicio = request.form.get('fecha_inicio')
    fecha_fin = request.form.get('fecha_fin')

    try:
        # Definir rango
        if mes:
            y, m = map(int, mes.split('-'))
            start_date = datetime(y, m, 1)
            end_date = datetime(y + (1 if m == 12 else 0), 1 if m == 12 else m + 1, 1)
            start_utc = start_date.replace(tzinfo=CL).astimezone(timezone.utc)
            end_utc = end_date.replace(tzinfo=CL).astimezone(timezone.utc)
            # Nombre automático para mes
            nombre = start_date.strftime('%B %Y')
        elif fecha_inicio and fecha_fin:
            d1 = datetime.strptime(fecha_inicio, "%Y-%m-%d").date()
            d2 = datetime.strptime(fecha_fin, "%Y-%m-%d").date()
            start_utc = datetime.combine(d1, datetime.min.time()).replace(tzinfo=CL).astimezone(timezone.utc)
            end_utc = datetime.combine(d2, datetime.max.time()).replace(tzinfo=CL).astimezone(timezone.utc)
            # Nombre automático para rango
            nombre = f"{d1.strftime('%d/%m/%Y')} - {d2.strftime('%d/%m/%Y')}"
        else:
            flash("Debes seleccionar un mes o rango de fechas", "warning")
            return redirect(url_for('admin_dashboard'))
        
        # Si el usuario ingresó un nombre manual, lo usamos
        if nombre_custom and nombre_custom.strip():
            nombre = nombre_custom.strip()
        
        filtro = {
            "fecha": {
                "$gte": start_utc,
                "$lt": end_utc
            }
        }
        
        registros = list(db.produccion.find(filtro))
        count = len(registros)
        
        if count > 0:
            # 1. Crear documento del corte
            corte_doc = {
                "nombre": nombre,
                "inicio": start_utc,
                "fin": end_utc,
                "creado_en": datetime.utcnow()
            }
            res = db.cortes.insert_one(corte_doc)
            corte_id = res.inserted_id

            # 2. Archivar Producción
            # Insertar en colección histórica con referencia al corte
            for r in registros:
                r["corte_id"] = corte_id
            if registros:
                db.produccion_historica.insert_many(registros)
            
            # 3. Archivar Piezas (SNAPSHOT COMPLETO)
            # Guardamos TODAS las piezas actuales tal cual están en este momento
            # Esto es vital para reconstruir los informes archivados
            piezas_activas = list(db.piezas.find({}))
            piezas_a_insertar = []
            for p in piezas_activas:
                p_copy = p.copy()
                p_copy.pop("_id", None) # Generar nuevo ID para histórico
                p_copy["corte_id"] = corte_id
                piezas_a_insertar.append(p_copy)
            
            if piezas_a_insertar:
                db.piezas_historicas.insert_many(piezas_a_insertar)

            # 4. Archivar Usuarios (Snapshot de precios/configuración)
            usuarios_activos = list(db.usuarios.find())
            usuarios_a_insertar = []
            for u in usuarios_activos:
                u_copy = u.copy()
                u_copy.pop("_id", None)
                u_copy["corte_id"] = corte_id
                usuarios_a_insertar.append(u_copy)
            
            if usuarios_a_insertar:
                db.usuarios_historicos.insert_many(usuarios_a_insertar)

            # 5. Limpieza (Borrar datos activos para nuevo ciclo)
            # Eliminar producción del rango archivado
            db.produccion.delete_many(filtro)
            
            # Eliminar todas las piezas (si el flujo es reiniciar piezas cada mes)
            # Si el usuario NO quiere borrar piezas, comentar esta línea.
            # Según el código anterior, se borraban. Mantenemos el comportamiento pero asegurando el backup primero.
            db.piezas.delete_many({})

            # Avanzar ciclo de prefijo (a -> b -> c ...)
            conf = db.config.find_one({"key": "ciclo_actual"}) or {"key": "ciclo_actual", "value": "a"}
            letra = conf.get("value", "a")
            import string
            abecedario = list(string.ascii_lowercase)
            try:
                idx = abecedario.index(letra)
                nueva = abecedario[idx + 1] if idx + 1 < len(abecedario) else "a"
            except:
                nueva = "a"
            db.config.update_one({"key": "ciclo_actual"}, {"$set": {"value": nueva}}, upsert=True)

            flash(f"✅ Corte realizado. {count} registros archivados.", "success")
        else:
            flash("No se encontraron registros para el mes seleccionado.", "info")
            
    except Exception as e:
        flash(f"Error al realizar el corte: {str(e)}", "danger")

    return redirect(url_for('admin_dashboard'))


@app.route('/admin/produccion', methods=['GET', 'POST'])
@login_required(['administrador', 'cliente', 'soporte', 'supervisor'])
def admin_produccion_list():
    filtro = {}
    fecha_inicio = None
    fecha_fin = None
    operador_sel = None
    codigo_sel = None

    if request.method == 'POST':
        operador_sel = request.form.get('operador')
        codigo_sel = request.form.get('codigo')
        fecha_inicio = request.form.get('fecha_inicio')
        fecha_fin = request.form.get('fecha_fin')

        if operador_sel and operador_sel != 'todos':
            filtro['usuario'] = operador_sel
        
        if codigo_sel:
            filtro['codigo_pieza'] = codigo_sel.strip()

        if fecha_inicio or fecha_fin:
            start_cl = None
            end_cl = None
            if fecha_inicio:
                d1 = datetime.strptime(fecha_inicio, "%Y-%m-%d").date()
                start_cl = datetime.combine(d1, datetime.min.time()).replace(tzinfo=CL)
            if fecha_fin:
                d2 = datetime.strptime(fecha_fin, "%Y-%m-%d").date()
                end_cl = datetime.combine(d2, datetime.max.time()).replace(tzinfo=CL)
            rango = {}
            if start_cl:
                rango["$gte"] = start_cl.astimezone(timezone.utc)
            if end_cl:
                rango["$lte"] = end_cl.astimezone(timezone.utc)
            if rango:
                filtro["fecha"] = rango

    registros = list(db.produccion.find(filtro).sort('fecha', -1))
    
    # Obtener lista de operadores para el filtro
    operadores = db.produccion.distinct("usuario")
    
    for r in registros:
        if r.get('fecha'):
            r['fecha'] = to_cl(r.get('fecha'))
            
    return render_template('crud_produccion_admin.html', 
                           registros=registros,
                           operadores=sorted(operadores),
                           operador_sel=operador_sel,
                           codigo_sel=codigo_sel,
                           fecha_inicio=fecha_inicio,
                           fecha_fin=fecha_fin)


@app.route('/admin/produccion/export', methods=['POST'])
@login_required(['administrador', 'soporte'])
def exportar_produccion_excel():
    filtro = {}
    operador_sel = request.form.get('operador')
    codigo_sel = request.form.get('codigo')
    fecha_inicio = request.form.get('fecha_inicio')
    fecha_fin = request.form.get('fecha_fin')

    if operador_sel and operador_sel != 'todos':
        filtro['usuario'] = operador_sel
    
    if codigo_sel:
        filtro['codigo_pieza'] = codigo_sel.strip()

    if fecha_inicio or fecha_fin:
        start_cl = None
        end_cl = None
        if fecha_inicio:
            d1 = datetime.strptime(fecha_inicio, "%Y-%m-%d").date()
            start_cl = datetime.combine(d1, datetime.min.time()).replace(tzinfo=CL)
        if fecha_fin:
            d2 = datetime.strptime(fecha_fin, "%Y-%m-%d").date()
            end_cl = datetime.combine(d2, datetime.max.time()).replace(tzinfo=CL)
        rango = {}
        if start_cl:
            rango["$gte"] = start_cl.astimezone(timezone.utc)
        if end_cl:
            rango["$lte"] = end_cl.astimezone(timezone.utc)
        if rango:
            filtro["fecha"] = rango

    registros = list(db.produccion.find(filtro).sort('fecha', -1))

    data = []
    for r in registros:
        fecha = to_cl(r.get('fecha')).strftime('%d-%m-%Y %H:%M') if r.get('fecha') else ''
        data.append({
            'Fecha': fecha,
            'Modo': r.get('modo', ''),
            'Operador': r.get('usuario', ''),
            'Box': r.get('box', ''),
            'Código': r.get('codigo_pieza', ''),
            'Cliente': r.get('empresa', ''),
            'Marco': r.get('marco', ''),
            'Tramo': r.get('tramo', ''),
            'Cuerda Int.': r.get('cuerda_interna', ''),
            'Cuerda Ext.': r.get('cuerda_externa', ''),
            'Estado': r.get('calidad_status', '')
        })

    df = pd.DataFrame(data)
    output = BytesIO()
    with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
        df.to_excel(writer, index=False, sheet_name="Produccion")
    output.seek(0)

    return send_file(
        output,
        download_name="registro_produccion.xlsx",
        as_attachment=True,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )

@app.route('/admin/produccion/archivada', methods=['GET', 'POST'])
@login_required(['administrador', 'soporte', 'supervisor'])
def admin_produccion_archivada():
    filtro = {}
    fecha_inicio = None
    fecha_fin = None
    operador_sel = None
    codigo_sel = None
    mes_sel = None
    corte_nombre = None

    if request.method == 'POST':
        operador_sel = request.form.get('operador')
        codigo_sel = request.form.get('codigo')
        fecha_inicio = request.form.get('fecha_inicio')
        fecha_fin = request.form.get('fecha_fin')
        mes_sel = request.form.get('mes')
        corte_nombre = request.form.get('corte_nombre')
    else:
        corte_nombre = request.args.get('corte_nombre')

        if operador_sel and operador_sel != 'todos':
            filtro['usuario'] = operador_sel
        
        if codigo_sel:
            filtro['codigo_pieza'] = codigo_sel.strip()

        if not corte_nombre:
            if mes_sel:
                try:
                    y, m = map(int, mes_sel.split('-'))
                    start_date = datetime(y, m, 1)
                    if m == 12:
                        end_date = datetime(y + 1, 1, 1)
                    else:
                        end_date = datetime(y, m + 1, 1)
                    start_utc = start_date.replace(tzinfo=CL).astimezone(timezone.utc)
                    end_utc = end_date.replace(tzinfo=CL).astimezone(timezone.utc)
                    filtro['fecha'] = {"$gte": start_utc, "$lt": end_utc}
                except:
                    pass
            elif fecha_inicio or fecha_fin:
                start_cl = None
                end_cl = None
                if fecha_inicio:
                    d1 = datetime.strptime(fecha_inicio, "%Y-%m-%d").date()
                    start_cl = datetime.combine(d1, datetime.min.time()).replace(tzinfo=CL)
                if fecha_fin:
                    d2 = datetime.strptime(fecha_fin, "%Y-%m-%d").date()
                    end_cl = datetime.combine(d2, datetime.max.time()).replace(tzinfo=CL)
                rango = {}
                if start_cl:
                    rango["$gte"] = start_cl.astimezone(timezone.utc)
                if end_cl:
                    rango["$lte"] = end_cl.astimezone(timezone.utc)
                if rango:
                    filtro["fecha"] = rango
        else:
            corte = db.cortes.find_one({'nombre': corte_nombre})
            if corte:
                filtro['corte_id'] = corte.get('_id')

    registros = list(db.produccion_historica.find(filtro).sort('fecha', -1))
    
    operadores = db.produccion_historica.distinct("usuario")
    
    for r in registros:
        if r.get('fecha'):
            r['fecha'] = to_cl(r.get('fecha'))
            
    return render_template('crud_produccion_admin.html', 
                           registros=registros,
                           operadores=sorted(operadores),
                           operador_sel=operador_sel,
                           codigo_sel=codigo_sel,
                           fecha_inicio=fecha_inicio,
                           fecha_fin=fecha_fin,
                           mes_sel=mes_sel,
                           archived_view=True,
                           corte_nombre=corte_nombre)

@app.route('/admin/produccion/archivada/export', methods=['POST'])
@login_required(['administrador', 'soporte'])
def exportar_produccion_archivada_excel():
    filtro = {}
    operador_sel = request.form.get('operador')
    codigo_sel = request.form.get('codigo')
    fecha_inicio = request.form.get('fecha_inicio')
    fecha_fin = request.form.get('fecha_fin')
    mes_sel = request.form.get('mes')
    corte_nombre = request.form.get('corte_nombre')

    if operador_sel and operador_sel != 'todos':
        filtro['usuario'] = operador_sel
    
    if codigo_sel:
        filtro['codigo_pieza'] = codigo_sel.strip()

    if corte_nombre:
        corte = db.cortes.find_one({'nombre': corte_nombre})
        if corte:
            corte_id = corte.get('_id')
            corte_inicio = corte.get('inicio')
            corte_fin = corte.get('fin')
            
            filtro_hibrido = []
            if corte_id:
                filtro_hibrido.append({"corte_id": corte_id})
            if corte_inicio and corte_fin:
                filtro_hibrido.append({"fecha": {"$gte": corte_inicio, "$lt": corte_fin}})
            
            if filtro_hibrido:
                if len(filtro_hibrido) > 1:
                    filtro["$or"] = filtro_hibrido
                else:
                    filtro.update(filtro_hibrido[0])
            elif corte_id:
                filtro['corte_id'] = corte_id
    else:
        if mes_sel:
            try:
                y, m = map(int, mes_sel.split('-'))
                start_date = datetime(y, m, 1)
                if m == 12:
                    end_date = datetime(y + 1, 1, 1)
                else:
                    end_date = datetime(y, m + 1, 1)
                start_utc = start_date.replace(tzinfo=CL).astimezone(timezone.utc)
                end_utc = end_date.replace(tzinfo=CL).astimezone(timezone.utc)
                filtro['fecha'] = {"$gte": start_utc, "$lt": end_utc}
            except:
                pass
        elif fecha_inicio or fecha_fin:
            start_cl = None
            end_cl = None
            if fecha_inicio:
                d1 = datetime.strptime(fecha_inicio, "%Y-%m-%d").date()
                start_cl = datetime.combine(d1, datetime.min.time()).replace(tzinfo=CL)
            if fecha_fin:
                d2 = datetime.strptime(fecha_fin, "%Y-%m-%d").date()
                end_cl = datetime.combine(d2, datetime.max.time()).replace(tzinfo=CL)
            rango = {}
            if start_cl:
                rango["$gte"] = start_cl.astimezone(timezone.utc)
            if end_cl:
                rango["$lte"] = end_cl.astimezone(timezone.utc)
            if rango:
                filtro["fecha"] = rango

    registros = list(db.produccion_historica.find(filtro).sort('fecha', -1))

    data = []
    for r in registros:
        fecha = to_cl(r.get('fecha')).strftime('%d-%m-%Y %H:%M') if r.get('fecha') else ''
        data.append({
            'Fecha': fecha,
            'Modo': r.get('modo', ''),
            'Operador': r.get('usuario', ''),
            'Box': r.get('box', ''),
            'Código': r.get('codigo_pieza', ''),
            'Cliente': r.get('empresa', ''),
            'Marco': r.get('marco', ''),
            'Tramo': r.get('tramo', ''),
            'Cuerda Int.': r.get('cuerda_interna', ''),
            'Cuerda Ext.': r.get('cuerda_externa', ''),
            'Estado': r.get('calidad_status', '')
        })

    df = pd.DataFrame(data)
    output = BytesIO()
    with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
        df.to_excel(writer, index=False, sheet_name="ProduccionArchivada")
    output.seek(0)

    return send_file(
        output,
        download_name="registro_produccion_archivada.xlsx",
        as_attachment=True,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )

@app.route('/admin/archivados/valor-operador', methods=['GET', 'POST'])
@login_required(['administrador', 'soporte'])
def archivados_valor_operador():
    corte_nombre = request.args.get('corte_nombre')
    operador_sel = None
    fecha_inicio = None
    fecha_fin = None
    filtro = {}

    if request.method == 'POST':
        operador_sel = request.form.get('operador')
        fecha_inicio = request.form.get('fecha_inicio')
        fecha_fin = request.form.get('fecha_fin')
        corte_nombre = request.form.get('corte_nombre') or corte_nombre
        if operador_sel and operador_sel != 'todos':
            filtro['usuario'] = operador_sel
        if fecha_inicio and fecha_fin:
            try:
                d1 = datetime.strptime(fecha_inicio, "%Y-%m-%d").date()
                d2 = datetime.strptime(fecha_fin, "%Y-%m-%d").date()
                start_cl = datetime.combine(d1, datetime.min.time()).replace(tzinfo=CL)
                end_cl = datetime.combine(d2, datetime.max.time()).replace(tzinfo=CL)
                filtro["fecha"] = {"$gte": start_cl.astimezone(timezone.utc), "$lte": end_cl.astimezone(timezone.utc)}
            except:
                pass

    piezas = []
    total_general = 0
    operadores = sorted(db.produccion_historica.distinct("usuario"))
    
    corte_id = None
    if corte_nombre and "corte_id" not in filtro:
        # Intentar buscar por nombre o por fecha convertida a string (si fuera el caso)
        corte = db.cortes.find_one({'nombre': corte_nombre})
        if not corte:
             # Si no encuentra por nombre, podría ser un ID de corte disfrazado o fecha
             try:
                 corte = db.cortes.find_one({'_id': ObjectId(corte_nombre)})
             except:
                 pass
                 
        if corte:
            corte_id = corte.get('_id')
            # Usar filtro híbrido: corte_id (nuevos) O rango de fechas (antiguos)
            corte_inicio = corte.get('inicio')
            corte_fin = corte.get('fin')
            
            filtro_hibrido = []
            if corte_id:
                filtro_hibrido.append({"corte_id": corte_id})
            if corte_inicio and corte_fin:
                filtro_hibrido.append({"fecha": {"$gte": corte_inicio, "$lt": corte_fin}})
            
            if filtro_hibrido:
                if len(filtro_hibrido) > 1:
                    filtro["$or"] = filtro_hibrido
                else:
                    filtro.update(filtro_hibrido[0])
            elif corte_id:
                filtro['corte_id'] = corte_id

    # Asegurar que traemos TODOS los operadores históricos para el filtro
    if corte_id:
         operadores = sorted(db.produccion_historica.distinct("usuario", {"corte_id": corte_id}))
    if not operadores:
         operadores = sorted(db.produccion_historica.distinct("usuario"))

    produccion = list(db.produccion_historica.find(filtro).sort("fecha", -1))
    
    # Cargar usuarios históricos si hay corte, sino actuales
    users_map = {}
    if corte_id:
        users_hist = list(db.usuarios_historicos.find({"corte_id": corte_id}))
        if users_hist:
            users_map = {u.get('usuario'): u for u in users_hist}
    
    # Fallback a usuarios actuales si no hay históricos (cortes antiguos)
    if not users_map:
        users_db = list(db.usuarios.find())
        users_map = {u.get('usuario'): u for u in users_db}

    # --- OPTIMIZACIÓN DE CARGA (Bulk Loading) ---
    # Recopilar todos los códigos necesarios para hacer pocas consultas
    codigos_necesarios = set()
    for p in produccion:
        c = p.get("codigo_pieza")
        if c:
            codigos_necesarios.add(c)
            # También añadir versión int/str por si acaso
            if isinstance(c, str) and c.isdigit():
                codigos_necesarios.add(int(c))
            elif isinstance(c, int):
                codigos_necesarios.add(str(c))
    
    piezas_hist_corte_map = {} # (codigo, corte_id) -> pieza
    piezas_hist_gen_map = {}   # codigo -> pieza
    piezas_actuales_map = {}   # codigo -> pieza

    if codigos_necesarios:
        lista_codigos = list(codigos_necesarios)
        
        # 1. Cargar Históricas del Corte (Prioridad Máxima)
        if corte_id:
            h_corte = list(db.piezas_historicas.find({
                "codigo": {"$in": lista_codigos},
                "corte_id": corte_id
            }))
            for h in h_corte:
                piezas_hist_corte_map[h.get("codigo")] = h

        # 2. Cargar Históricas Generales (Prioridad Media)
        # Solo traemos las que coincidan en código, luego filtraremos en memoria
        h_gen = list(db.piezas_historicas.find({
            "codigo": {"$in": lista_codigos}
        }))
        for h in h_gen:
            # Solo guardamos si no existe o sobrescribimos (la lógica de cual es "mejor" es difusa sin corte,
            # así que tomamos el primero que aparezca o el último)
            if h.get("codigo") not in piezas_hist_gen_map:
                piezas_hist_gen_map[h.get("codigo")] = h
        
        # 3. Cargar Actuales (Fallback)
        act = list(db.piezas.find({"codigo": {"$in": lista_codigos}}))
        for a in act:
            piezas_actuales_map[a.get("codigo")] = a
    # ---------------------------------------------

    for p in produccion:
        codigo = p.get("codigo_pieza")
        modo = p.get("modo")
        if not codigo:
            continue
        
        # Resolver pieza usando los mapas precargados
        pieza_info = None
        
        # Intentar variaciones de tipo (str/int)
        codigos_probar = [codigo]
        if isinstance(codigo, str) and codigo.isdigit():
            codigos_probar.append(int(codigo))
        elif isinstance(codigo, int):
            codigos_probar.append(str(codigo))
            
        # 1. Búsqueda en históricas del corte
        if corte_id:
            for c in codigos_probar:
                pieza_info = piezas_hist_corte_map.get(c)
                if pieza_info: break
        
        # 2. Búsqueda en históricas generales
        if not pieza_info:
            for c in codigos_probar:
                pieza_info = piezas_hist_gen_map.get(c)
                if pieza_info: break
                
        # 3. Búsqueda en actuales
        if not pieza_info:
            for c in codigos_probar:
                pieza_info = piezas_actuales_map.get(c)
                if pieza_info: break
            
        # Si no se encuentra info de pieza, intentar obtener datos del registro de producción (si existen)
        empresa_val = (pieza_info.get("empresa") if pieza_info else None) or p.get("empresa") or "Desconocido"
        marco_val = (pieza_info.get("marco") if pieza_info else None) or p.get("marco") or "-"
        tramo_val = (pieza_info.get("tramo") if pieza_info else None) or p.get("tramo") or "-"
        
        # PRIORIDAD: Obtener peso desde el registro histórico de producción
        # Si no existe en producción, usar el de la ficha de pieza (fallback)
        peso_val = p.get("kilo_pieza")
        if peso_val is None:
            peso_val = pieza_info.get("kilo_pieza", 0) if pieza_info else 0
        
        user = users_map.get(p.get("usuario"))
        valor_unit = 0
        if user:
            tipo_precio = pieza_info.get("tipo_precio", "metro") if pieza_info else "metro"
            if modo == "armador":
                valor_unit = user.get("precio_metro_armado", 0) if tipo_precio == "metro" else user.get("precio_avo_armado", 0)
            else:
                valor_unit = user.get("precio_metro_remate", 0) if tipo_precio == "metro" else user.get("precio_avo_remate", 0)
        
        total = (peso_val or 0) * (valor_unit or 0)
        
        piezas.append({
            "fecha": to_cl(p.get("fecha")) if p.get("fecha") else None,
            "codigo": codigo,
            "empresa": empresa_val,
            "operador": p.get("usuario"),
            "marco": marco_val,
            "tramo": tramo_val,
            "modo": modo,
            "peso": peso_val,
            "precio_kilo": valor_unit,
            "valor": total
        })
        total_general += total

    return render_template("informe_valor_operador_archivado.html",
                           piezas=piezas,
                           operadores=operadores,
                           operador_sel=operador_sel,
                           fecha_inicio=fecha_inicio,
                           fecha_fin=fecha_fin,
                           total_general=total_general,
                           corte_nombre=corte_nombre)

@app.route('/admin/archivados/piezas-cliente')
@login_required(['administrador', 'soporte', 'supervisor'])
def archivados_piezas_cliente():
    corte_nombre = request.args.get('corte_nombre')
    filtro_prod = {}
    filtro_piezas = {}
    if corte_nombre:
        corte = db.cortes.find_one({'nombre': corte_nombre})
        if corte:
            corte_id = corte.get('_id')
            corte_inicio = corte.get('inicio')
            corte_fin = corte.get('fin')
            
            # Filtro Producción Híbrido
            filtro_hibrido_prod = []
            if corte_id:
                filtro_hibrido_prod.append({"corte_id": corte_id})
            if corte_inicio and corte_fin:
                filtro_hibrido_prod.append({"fecha": {"$gte": corte_inicio, "$lt": corte_fin}})
            
            if filtro_hibrido_prod:
                if len(filtro_hibrido_prod) > 1:
                    filtro_prod["$or"] = filtro_hibrido_prod
                else:
                    filtro_prod.update(filtro_hibrido_prod[0])
            elif corte_id:
                filtro_prod['corte_id'] = corte_id
            
            # Filtro Piezas
            if corte_id:
                filtro_piezas = {'corte_id': corte_id}

    produccion_hist = list(db.produccion_historica.find(filtro_prod))
    # Manejar codigos como str para set
    cod_armadas = set()
    cod_remates = set()
    for p in produccion_hist:
        c = p.get("codigo_pieza")
        if c:
            cstr = str(c)
            if p.get("modo") == "armador":
                cod_armadas.add(cstr)
            elif p.get("modo") == "rematador":
                cod_remates.add(cstr)

    # Intentar cargar piezas históricas del corte
    piezas = []
    if filtro_piezas:
        piezas = list(db.piezas_historicas.find(filtro_piezas))
    
    # Si no hay piezas históricas (corte antiguo), usar piezas actuales como fallback
    if not piezas:
        piezas = list(db.piezas.find())

    grupos_map = {}
    for pi in piezas:
        cli = pi.get("empresa"); mar = pi.get("marco"); tr = pi.get("tramo")
        key_cli = cli
        key_mar = (cli, mar)
        if key_cli not in grupos_map:
            grupos_map[key_cli] = {}
        if key_mar not in grupos_map[key_cli]:
            grupos_map[key_cli][key_mar] = {}
        grupos_map[key_cli][key_mar].setdefault(tr, {"total": 0, "armadas": 0, "rematadas": 0})
        grupos_map[key_cli][key_mar][tr]["total"] += 1
        cstr = str(pi.get("codigo"))
        if cstr in cod_armadas:
            grupos_map[key_cli][key_mar][tr]["armadas"] += 1
        if cstr in cod_remates:
            grupos_map[key_cli][key_mar][tr]["rematadas"] += 1

    grupos = []
    for cli, marcos in grupos_map.items():
        obj = {"cliente": cli, "marcos": []}
        for (cli2, marco), tramos in marcos.items():
            obj["marcos"].append({
                "marco": marco,
                "tramos": [{"tramo": t, 
                            "total": v["total"], 
                            "armadas": v["armadas"], 
                            "rematadas": v["rematadas"], 
                            "en_armado": max(v["armadas"] - v["rematadas"], 0),
                            "pendientes": v["total"] - v["rematadas"]} for t, v in tramos.items()]
            })
        grupos.append(obj)

    return render_template("informe_piezas_tarjetas_archivado.html", grupos=grupos, corte_nombre=corte_nombre)

@app.route('/admin/archivados/pendientes')
@login_required(['administrador', 'soporte', 'supervisor'])
def archivados_pendientes_mes():
    return archivados_piezas_cliente()
@app.route('/soporte/produccion/<id>/editar')
@login_required('soporte')
def soporte_produccion_editar_form(id):
    reg = db.produccion.find_one({'_id': ObjectId(id)})
    if not reg:
        flash('Registro no encontrado', 'warning')
        return redirect(url_for('soporte_produccion_list'))
    return render_template('produccion_form.html', modo='editar', reg=reg)

@app.route('/soporte/produccion/<id>/editar', methods=['POST'])
@login_required('soporte')
def soporte_produccion_editar_post(id):
    empresa = request.form.get('empresa', '').strip()
    marco = request.form.get('marco', '').strip()
    tramo = request.form.get('tramo', '').strip()
    usuario = request.form.get('usuario', '').strip()
    modo = request.form.get('modo', '').strip()
    codigo_pieza = request.form.get('codigo_pieza', '').strip()
    calidad_status = request.form.get('calidad_status', '').strip() or 'pendiente'
    cuerda_interna = request.form.get('cuerda_interna')
    cuerda_externa = request.form.get('cuerda_externa')
    fecha_str = request.form.get('fecha')

    # convertir fecha de input datetime-local (zona local Chile) a UTC
    fecha_dt = None
    if fecha_str:
        try:
            # formato 'YYYY-MM-DDTHH:MM'
            dt_local = datetime.strptime(fecha_str, '%Y-%m-%dT%H:%M').replace(tzinfo=CL)
            fecha_dt = dt_local.astimezone(timezone.utc)
        except:
            fecha_dt = None

    update = {
        'empresa': empresa,
        'marco': marco,
        'tramo': tramo,
        'usuario': usuario,
        'modo': modo,
        'codigo_pieza': codigo_pieza,
        'calidad_status': calidad_status,
        'cuerda_interna': cuerda_interna,
        'cuerda_externa': cuerda_externa,
    }
    if fecha_dt:
        update['fecha'] = fecha_dt

    db.produccion.update_one({'_id': ObjectId(id)}, {'$set': update})
    flash('Registro actualizado ✔', 'success')
    return redirect(url_for('soporte_produccion_list'))

@app.route('/soporte/produccion/<id>/delete', methods=['POST'])
@login_required('soporte')
def soporte_produccion_delete(id):
    db.produccion.delete_one({'_id': ObjectId(id)})
    flash('Registro eliminado', 'info')
    return redirect(url_for('soporte_produccion_list'))

@app.route('/admin/informes')
@login_required(["administrador", "soporte", "cliente", "supervisor"])
def admin_informes():
    return render_template('admin_informes.html', is_cliente=(session.get('role') == 'cliente'), role=session.get('role'))

@app.route('/admin/archivados', methods=['GET', 'POST'])
@login_required(['administrador', 'soporte', 'supervisor'])
def admin_archivados_menu():
    corte_nombre = None
    if request.method == 'POST':
        corte_nombre = request.form.get('corte_nombre')
    else:
        corte_nombre = request.args.get('corte_nombre')
    cortes = list(db.cortes.find().sort('creado_en', -1))
    return render_template('admin_archivados.html', corte_nombre=corte_nombre, cortes=cortes)


# ============================================================
#                 INFORME DE HORARIOS + EXPORTACIÓN
# ============================================================

@app.route('/admin/informes/horarios', methods=['GET', 'POST'])
@login_required(['administrador', 'soporte'])
def informe_horarios():
    operadores = list(db.usuarios.find({'tipo': 'operador'}))
    operador_sel = None
    filtro = {}

    if request.method == 'POST':
        operador_sel = request.form.get('operador')
        if operador_sel and operador_sel != 'todos':
            filtro['user_id'] = operador_sel

    jornadas = list(db.jornadas.find(filtro).sort('fecha', -1))

    usuarios_map = {str(u['_id']): u['nombre'] for u in operadores}

    for j in jornadas:
        j['nombre'] = usuarios_map.get(j['user_id'], 'Desconocido')
        if j.get('fecha'):
            j['fecha'] = to_cl(j.get('fecha'))
        if j.get('ingreso'):
            j['ingreso'] = to_cl(j.get('ingreso'))
        if j.get('salida'):
            j['salida'] = to_cl(j.get('salida'))

    return render_template(
        'informe_horarios.html',
        jornadas=jornadas,
        operadores=operadores,
        operador_sel=operador_sel
    )


@app.route('/admin/informes/horarios/export', methods=['POST'])
@login_required('administrador')
def exportar_horarios_excel():
    operador_sel = request.form.get('operador')
    filtro = {}
    if operador_sel and operador_sel != 'todos':
        filtro['user_id'] = operador_sel

    jornadas = list(db.jornadas.find(filtro).sort('fecha', -1))

    operadores = list(db.usuarios.find({'tipo': 'operador'}))
    usuarios_map = {str(u['_id']): u['nombre'] for u in operadores}

    data = []
    for j in jornadas:
        fecha = to_cl(j.get('fecha')) if j.get('fecha') else None
        ingreso = to_cl(j.get('ingreso')) if j.get('ingreso') else None
        salida = to_cl(j.get('salida')) if j.get('salida') else None
        data.append({
            'Operador': usuarios_map.get(j['user_id'], 'Desconocido'),
            'Fecha': fecha.strftime('%d-%m-%Y') if fecha else '',
            'Ingreso': ingreso.strftime('%H:%M') if ingreso else '',
            'Salida': salida.strftime('%H:%M') if salida else ''
        })

    if not data:
        flash("No hay datos para exportar", "warning")
        return redirect(url_for('informe_horarios'))

    df = pd.DataFrame(data)

    output = BytesIO()
    with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
        df.to_excel(writer, index=False, sheet_name="Horarios")

    output.seek(0)

    return send_file(
        output,
        download_name="informe_horarios.xlsx",
        as_attachment=True,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )







# ============================================================
#         INFORME PRODUCCIÓN POR OPERADOR + EXPORTACIÓN
# ============================================================

@app.route('/admin/informes/operadores', methods=['GET', 'POST'])
@login_required(['administrador', 'soporte'])
def informe_operadores():
    operadores = list(db.usuarios.find({'tipo': 'operador'}))
    operador_sel = None
    fecha_inicio = None
    fecha_fin = None
    filtro = {}

    if request.method == "POST":
        operador_sel = request.form.get("operador")
        fecha_inicio = request.form.get("fecha_inicio")
        fecha_fin = request.form.get("fecha_fin")

        if operador_sel and operador_sel != "todos":
            filtro["user_id"] = operador_sel

        if fecha_inicio or fecha_fin:
            start_cl = None
            end_cl = None
            if fecha_inicio:
                d1 = datetime.strptime(fecha_inicio, "%Y-%m-%d").date()
                start_cl = datetime.combine(d1, datetime.min.time()).replace(tzinfo=CL)
            if fecha_fin:
                d2 = datetime.strptime(fecha_fin, "%Y-%m-%d").date()
                end_cl = datetime.combine(d2, datetime.max.time()).replace(tzinfo=CL)
            rango = {}
            if start_cl:
                rango["$gte"] = start_cl.astimezone(timezone.utc)
            if end_cl:
                rango["$lte"] = end_cl.astimezone(timezone.utc)
            if rango:
                filtro["fecha"] = rango

    produccion = list(db.produccion.find(filtro).sort("fecha", -1))
    
    # Pre-fetch datos para evitar N+1
    user_ids = []
    for p in produccion:
        uid = p.get("user_id")
        if uid and isinstance(uid, str) and len(uid) == 24:
            user_ids.append(uid)
    
    user_ids = list(set(user_ids))
    
    try:
        mapa_usuarios = {str(u["_id"]): u for u in db.usuarios.find({"_id": {"$in": [ObjectId(uid) for uid in user_ids]}})}
    except:
        mapa_usuarios = {}

    # El campo codigo_pieza en produccion es string (a veces), en piezas es int. Manejar ambos.
    mapa_piezas = {}
    piezas_db = list(db.piezas.find()) # Traer todas es más seguro si los tipos no coinciden
    for p in piezas_db:
        mapa_piezas[str(p["codigo"])] = p

    datos_tabla = []
    total_general = 0

    for p in produccion:
        uid = p.get("user_id")
        user = mapa_usuarios.get(uid)
        
        cod = str(p.get("codigo_pieza"))
        pieza = mapa_piezas.get(cod)
        
        modo = p.get("modo") # armador / rematador
        
        peso = 0
        valor_unitario = 0
        total = 0
        
        if pieza and user:
            peso = pieza.get("kilo_pieza")
            if peso is None:
                peso = 0
            
            tipo_precio = pieza.get("tipo_precio", "metro") # metro / avo
            
            # Determinar precio según modo y tipo
            if modo == "armador":
                if tipo_precio == "metro":
                    valor_unitario = user.get("precio_metro_armado", 0)
                else:
                    valor_unitario = user.get("precio_avo_armado", 0)
            elif modo == "rematador":
                if tipo_precio == "metro":
                    valor_unitario = user.get("precio_metro_remate", 0)
                else:
                    valor_unitario = user.get("precio_avo_remate", 0)
            
            if valor_unitario is None:
                valor_unitario = 0

            total = peso * valor_unitario
        
        total_general += total
        
        datos_tabla.append({
            "fecha": to_cl(p.get("fecha")) if p.get("fecha") else None,
            "codigo": cod,
            "operador": user.get("nombre", "—") if user else "—",
            "modo": modo,
            "marco": p.get("marco", "—"),
            "tramo": p.get("tramo", "—"),
            "cantidad": 1,
            "peso": peso,
            "valor_unitario": valor_unitario, # Valor por kilo/unidad
            "total": total,
            "tipo_precio": pieza.get("tipo_precio") if pieza else ""
        })

    return render_template(
        "informe_operadores.html",
        operadores=operadores,
        operador_sel=operador_sel,
        fecha_inicio=fecha_inicio,
        fecha_fin=fecha_fin,
        datos_tabla=datos_tabla,
        total_general=total_general
    )


@app.route('/admin/informes/operadores/export', methods=['POST'])
@login_required(['administrador', 'soporte'])
def exportar_operadores_excel():
    operador_sel = request.form.get("operador")
    fecha_inicio = request.form.get("fecha_inicio")
    fecha_fin = request.form.get("fecha_fin")

    filtro = {}

    if operador_sel and operador_sel != "todos":
        filtro["user_id"] = operador_sel

    if fecha_inicio or fecha_fin:
        start_cl = None
        end_cl = None
        if fecha_inicio:
            d1 = datetime.strptime(fecha_inicio, "%Y-%m-%d").date()
            start_cl = datetime.combine(d1, datetime.min.time()).replace(tzinfo=CL)
        if fecha_fin:
            d2 = datetime.strptime(fecha_fin, "%Y-%m-%d").date()
            end_cl = datetime.combine(d2, datetime.max.time()).replace(tzinfo=CL)
        rango = {}
        if start_cl:
            rango["$gte"] = start_cl.astimezone(timezone.utc)
        if end_cl:
            rango["$lte"] = end_cl.astimezone(timezone.utc)
        if rango:
            filtro["fecha"] = rango

    produccion = list(db.produccion.find(filtro).sort("fecha", -1))

    # Pre-fetch similar a la vista
    user_ids = []
    for p in produccion:
        uid = p.get("user_id")
        if uid and isinstance(uid, str) and len(uid) == 24:
            user_ids.append(uid)
    user_ids = list(set(user_ids))

    try:
        mapa_usuarios = {str(u["_id"]): u for u in db.usuarios.find({"_id": {"$in": [ObjectId(uid) for uid in user_ids]}})}
    except:
        mapa_usuarios = {}
    
    piezas_db = list(db.piezas.find())
    mapa_piezas = {str(p["codigo"]): p for p in piezas_db}

    data = []
    total_general = 0

    for p in produccion:
        uid = p.get("user_id")
        user = mapa_usuarios.get(uid)
        cod = str(p.get("codigo_pieza"))
        pieza = mapa_piezas.get(cod)
        modo = p.get("modo")
        
        peso = 0
        valor_unitario = 0
        total = 0
        
        if pieza and user:
            peso = pieza.get("kilo_pieza")
            if peso is None:
                peso = 0

            tipo_precio = pieza.get("tipo_precio", "metro")
            
            if modo == "armador":
                if tipo_precio == "metro":
                    valor_unitario = user.get("precio_metro_armado", 0)
                else:
                    valor_unitario = user.get("precio_avo_armado", 0)
            elif modo == "rematador":
                if tipo_precio == "metro":
                    valor_unitario = user.get("precio_metro_remate", 0)
                else:
                    valor_unitario = user.get("precio_avo_remate", 0)
            
            if valor_unitario is None:
                valor_unitario = 0
            
            total = peso * valor_unitario
            
        total_general += total

        data.append({
            "Fecha": to_cl(p.get("fecha")).strftime('%d-%m-%Y') if p.get("fecha") else "",
            "Código": cod,
            "Operador": user.get("nombre", "") if user else "",
            "Modo": modo,
            "Marco": p.get("marco", ""),
            "Tramo": p.get("tramo", ""),
            "Cantidad": 1,
            "Peso": peso,
            "Precio Unit.": valor_unitario,
            "Tipo": tipo_precio if pieza else "",
            "Total": total
        })

    # Fila final de total
    data.append({
        "Fecha": "TOTAL",
        "Código": "", "Operador": "", "Modo": "", "Marco": "", "Tramo": "", "Cantidad": "", "Peso": "", "Precio Unit.": "", "Tipo": "",
        "Total": total_general
    })

    if not data:
        flash("No hay datos", "warning")
        return redirect(url_for("informe_operadores"))

    df = pd.DataFrame(data)

    output = BytesIO()
    with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
        df.to_excel(writer, index=False, sheet_name="Operadores")

    output.seek(0)

    return send_file(
        output,
        download_name="informe_valor_operador.xlsx",
        as_attachment=True,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )


# ============================================================
#                 OPERADOR — REGISTRO DE PRODUCCIÓN
# ============================================================

@app.route('/operador', methods=['GET', 'POST'])
@login_required('operador')
def operador_home():
    user_id = session.get("user_id")
    nombre = session.get("nombre")
    
    # Manejo de filtros de fecha
    fecha_inicio = request.form.get("fecha_inicio")
    fecha_fin = request.form.get("fecha_fin")
    
    filtro = {"user_id": user_id}
    
    start_cl = None
    end_cl = None

    if fecha_inicio or fecha_fin:
        # Si hay filtro manual
        if fecha_inicio:
            d1 = datetime.strptime(fecha_inicio, "%Y-%m-%d").date()
            start_cl = datetime.combine(d1, datetime.min.time()).replace(tzinfo=CL)
        if fecha_fin:
            d2 = datetime.strptime(fecha_fin, "%Y-%m-%d").date()
            end_cl = datetime.combine(d2, datetime.max.time()).replace(tzinfo=CL)
    else:
        # Por defecto: HOY
        today = now_cl().date()
        start_cl = datetime.combine(today, datetime.min.time()).replace(tzinfo=CL)
        end_cl = datetime.combine(today, datetime.max.time()).replace(tzinfo=CL)
        # Para que el input date muestre hoy si no hay filtro (opcional)
        fecha_inicio = today.strftime("%Y-%m-%d")
        fecha_fin = today.strftime("%Y-%m-%d")

    rango = {}
    if start_cl:
        rango["$gte"] = start_cl.astimezone(timezone.utc)
    if end_cl:
        rango["$lte"] = end_cl.astimezone(timezone.utc)
    
    if rango:
        filtro["fecha"] = rango

    if rango:
        filtro["fecha"] = rango

    # ------------------ NUEVA LÓGICA UNIFICADA (ACTIVO + HISTÓRICO) ------------------
    
    # 1. Buscar en Producción Activa
    active_recs = list(db.produccion.find(filtro))
    
    # 2. Buscar en Producción Histórica
    archived_recs = list(db.produccion_historica.find(filtro))
    
    piezas_produccion = active_recs + archived_recs
    
    # Ordenar por fecha descendente
    piezas_produccion.sort(key=lambda x: x.get("fecha", datetime.min), reverse=True)
    
    # Preparar datos para cálculo
    usuario_obj = db.usuarios.find_one({"_id": ObjectId(user_id)})
    
    # Mapas para activos
    piezas_db = list(db.piezas.find())
    mapa_piezas_active = {str(p["codigo"]): p for p in piezas_db}
    
    # Cachés para históricos
    cache_users_hist = {}   # (corte_id, usuario_nombre) -> user_doc
    cache_piezas_hist = {}  # (corte_id, codigo_pieza) -> pieza_doc
    
    boxes = list(db.boxes.find().sort("codigo", 1))
    total_general = 0
    
    for p in piezas_produccion:
        p["fecha"] = to_cl(p.get("fecha"))
        
        # Datos básicos del registro
        cod = str(p.get("codigo_pieza"))
        modo = p.get("modo")
        corte_id = p.get("corte_id")
        
        # Determinar Peso y Tipo de Precio
        peso = 0.0
        tipo_precio = "metro" # Default
        
        # Intento 1: Leer del registro (si existen)
        if "kilo_pieza" in p:
             try: peso = float(p["kilo_pieza"])
             except: peso = 0.0
        
        if "tipo_precio" in p:
             tipo_precio = p["tipo_precio"]
        
        # Intento 2: Buscar en Piezas (Activas o Históricas) si falta info
        # Si ya tengo peso y tipo_precio del registro, no necesito buscar pieza, 
        # PERO records viejos no tienen tipo_precio.
        
        pieza_doc = None
        if peso == 0 or "tipo_precio" not in p:
            if corte_id:
                # Buscar en histórico
                if (corte_id, cod) not in cache_piezas_hist:
                    # Intenta string e int
                    pz = db.piezas_historicas.find_one({"corte_id": corte_id, "codigo": cod})
                    if not pz and cod.isdigit():
                         pz = db.piezas_historicas.find_one({"corte_id": corte_id, "codigo": int(cod)})
                    cache_piezas_hist[(corte_id, cod)] = pz
                pieza_doc = cache_piezas_hist[(corte_id, cod)]
            else:
                # Buscar en activo
                pieza_doc = mapa_piezas_active.get(cod)
            
            if pieza_doc:
                if peso == 0:
                    try: peso = float(pieza_doc.get("kilo_pieza") or 0)
                    except: peso = 0.0
                if "tipo_precio" not in p:
                    tipo_precio = pieza_doc.get("tipo_precio", "metro")

        # Determinar Precios del Usuario
        # Si es histórico, buscar snapshot de usuario. Si no, usar actual.
        user_vals = usuario_obj # Default to current
        
        if corte_id:
            u_name = p.get("usuario")
            if (corte_id, u_name) not in cache_users_hist:
                uh = db.usuarios_historicos.find_one({"corte_id": corte_id, "usuario": u_name})
                cache_users_hist[(corte_id, u_name)] = uh
            if cache_users_hist[(corte_id, u_name)]:
                user_vals = cache_users_hist[(corte_id, u_name)]
        
        # Calcular
        valor = 0.0
        if user_vals:
             val_raw = 0
             if modo == "armador":
                 val_raw = user_vals.get("precio_metro_armado", 0) if tipo_precio == "metro" else user_vals.get("precio_avo_armado", 0)
             elif modo == "rematador":
                 val_raw = user_vals.get("precio_metro_remate", 0) if tipo_precio == "metro" else user_vals.get("precio_avo_remate", 0)
             
             try: valor = float(val_raw or 0)
             except: valor = 0.0
        
        total = peso * valor
        
        p["peso_calculado"] = peso
        p["valor_calculado"] = valor
        p["total_calculado"] = total
        
        total_general += total

    # Jornada (solo se busca si estamos filtrando por HOY, o simplemente mostrar la del rango?)
    # El requerimiento original era mostrar la jornada de hoy.
    # Si filtra por rango, la "jornada actual" puede ser confusa. 
    # Mantendremos la lógica de buscar jornada solo si el rango coincide con hoy o simplemente la última jornada en ese rango?
    # El usuario pidió "filtro fecha desde hasta" en su producción.
    # La jornada es para marcar ingreso/salida. Eso siempre debería ser "hoy".
    
    today_real = now_cl().date()
    start_today = datetime.combine(today_real, datetime.min.time()).replace(tzinfo=CL).astimezone(timezone.utc)
    end_today = datetime.combine(today_real, datetime.max.time()).replace(tzinfo=CL).astimezone(timezone.utc)
    
    jornada = db.jornadas.find_one({
        "user_id": user_id,
        "fecha": {"$gte": start_today, "$lte": end_today}
    })

    if jornada:
        if jornada.get("fecha"):
            jornada["fecha"] = to_cl(jornada.get("fecha"))
        if jornada.get("ingreso"):
            jornada["ingreso"] = to_cl(jornada.get("ingreso"))
        if jornada.get("salida"):
            jornada["salida"] = to_cl(jornada.get("salida"))

    return render_template(
        "operador.html",
        nombre=nombre,
        boxes=boxes,
        piezas_hoy=piezas_produccion, # Ahora puede ser un rango
        jornada=jornada,
        fecha_inicio=fecha_inicio,
        fecha_fin=fecha_fin,
        total_general=total_general,
        tunnel_url=tunnel_url
    )


@app.route('/operador/jornada/ingreso', methods=['POST'])
@login_required('operador')
def operador_ingreso():
    user_id = session.get("user_id")
    today = now_cl().date()

    start_cl = datetime.combine(today, datetime.min.time()).replace(tzinfo=CL)
    end_cl = datetime.combine(today, datetime.max.time()).replace(tzinfo=CL)
    start = start_cl.astimezone(timezone.utc)
    end = end_cl.astimezone(timezone.utc)

    existe = db.jornadas.find_one({"user_id": user_id, "fecha": {"$gte": start, "$lte": end}})

    if existe and existe.get("ingreso"):
        flash("La jornada ya fue iniciada", "info")
    else:
        db.jornadas.update_one(
            {"user_id": user_id, "fecha": {"$gte": start, "$lte": end}},
            {"$set": {"user_id": user_id, "fecha": datetime.utcnow(), "ingreso": datetime.utcnow()}},
            upsert=True
        )
        flash("Ingreso registrado", "success")

    return redirect(url_for("operador_home"))


@app.route('/operador/jornada/salida', methods=['POST'])
@login_required('operador')
def operador_salida():
    user_id = session.get("user_id")
    today = now_cl().date()

    start_cl = datetime.combine(today, datetime.min.time()).replace(tzinfo=CL)
    end_cl = datetime.combine(today, datetime.max.time()).replace(tzinfo=CL)
    start = start_cl.astimezone(timezone.utc)
    end = end_cl.astimezone(timezone.utc)

    upd = db.jornadas.update_one(
        {"user_id": user_id, "fecha": {"$gte": start, "$lte": end}},
        {"$set": {"salida": datetime.utcnow()}}
    )

    if upd.matched_count:
        flash("Salida registrada", "success")
    else:
        flash("No hay jornada iniciada", "warning")

    return redirect(url_for("operador_home"))


# ============================================================
#              NUEVO REGISTRO DE PRODUCCIÓN (FINAL)
# ============================================================

@app.route('/operador/registrar', methods=['POST'])
@login_required('operador')
def operador_registrar():
    user_id = session.get("user_id")
    usuario = session.get("nombre")

    modo = request.form["modo"]                  # armador / rematador
    box = request.form["box"]
    codigo_pieza = request.form["codigo_pieza"].strip().lower()

    # Cuerdas ingresadas SOLO si es armador
    cuerda_interna_raw = request.form.get("cuerda_interna")
    cuerda_externa_raw = request.form.get("cuerda_externa")

    # ---------------------- VALIDACIÓN DE CÓDIGO ----------------------
    if not codigo_pieza:
        flash("Debes ingresar un código de pieza", "warning")
        return redirect(url_for("operador_home"))

    # Intentar buscar primero como string directo (alfanumérico)
    pieza_data = db.piezas.find_one({"codigo": codigo_pieza})

    # Si no encuentra, intentar como entero (compatibilidad)
    if not pieza_data and codigo_pieza.isdigit():
        try:
            pieza_data = db.piezas.find_one({"codigo": int(codigo_pieza)})
        except:
            pass

    if not pieza_data:
        flash(f"❌ No existe una pieza con código {codigo_pieza}", "danger")
        return redirect(url_for("operador_home"))

    # ------------------- CONTADORES PREVIOS -------------------

    armado_count = db.produccion.count_documents({
        "codigo_pieza": codigo_pieza,
        "modo": "armador"
    })

    remate_count = db.produccion.count_documents({
        "codigo_pieza": codigo_pieza,
        "modo": "rematador"
    })

    # ------------------- VALIDACIONES LÓGICAS -------------------

    if modo == "armador":

        # Máximo 2 armados
        if armado_count >= 2:
            flash(f"❌ La pieza {codigo_pieza} ya fue armada 2 veces", "danger")
            return redirect(url_for("operador_home"))

        # ===== VALIDAR CUERDAS INGRESADAS =====
        def safe_float(v):
            try:
                return float(v)
            except:
                return None

        cuerda_interna = safe_float(cuerda_interna_raw)
        cuerda_externa = safe_float(cuerda_externa_raw)

        if cuerda_interna is None or cuerda_externa is None:
            flash("❌ Debes ingresar valores numéricos para cuerdas interna y externa.", "danger")
            return redirect(url_for("operador_home"))

        # ===== VALIDACIÓN CONTRA BASE DE PIEZA =====
        base_interna = safe_float(pieza_data.get("cuerda_interna"))
        base_externa = safe_float(pieza_data.get("cuerda_externa"))

        # Si la pieza no tiene valores base → no validar cuerdas
        if base_interna is not None:
            margen_interna_min = base_interna * 0.90
            margen_interna_max = base_interna * 1.10

            if not (margen_interna_min <= cuerda_interna <= margen_interna_max):
                flash(f"❌ Cuerda interna fuera de rango permitido: {margen_interna_min:.2f} - {margen_interna_max:.2f}", "danger")
                return redirect(url_for("operador_home"))

        if base_externa is not None:
            margen_externa_min = base_externa * 0.90
            margen_externa_max = base_externa * 1.10

            if not (margen_externa_min <= cuerda_externa <= margen_externa_max):
                flash(f"❌ Cuerda externa fuera de rango permitido: {margen_externa_min:.2f} - {margen_externa_max:.2f}", "danger")
                return redirect(url_for("operador_home"))

    if modo == "rematador":

        # remate solo si existe armado
        if remate_count >= 1:
            flash(f"❌ La pieza {codigo_pieza} ya fue rematada", "danger")
            return redirect(url_for("operador_home"))

        if armado_count < 1:
            flash(f"⚠ La pieza {codigo_pieza} aún no tiene armado registrado.", "warning")
            return redirect(url_for("operador_home"))

        # rematador NO usa cuerdas
        cuerda_interna = None
        cuerda_externa = None

    # ------------------- GUARDAR REGISTRO -------------------

    registro = {
        "user_id": user_id,
        "usuario": usuario,
        "modo": modo,
        "box": box,
        "codigo_pieza": codigo_pieza,

        "empresa": pieza_data.get("empresa", ""),
        "marco": pieza_data.get("marco", ""),
        "tramo": pieza_data.get("tramo", ""),
        "kilo_pieza": pieza_data.get("kilo_pieza", 0),
        "tipo_precio": pieza_data.get("tipo_precio", "metro"),

        "cuerda_interna": cuerda_interna,
        "cuerda_externa": cuerda_externa,

        "fecha": datetime.utcnow(),
        "calidad_status": "pendiente"
    }

    db.produccion.insert_one(registro)

    flash(f"✔ Pieza {codigo_pieza} registrada correctamente como {modo}", "success")
    return redirect(url_for("operador_home"))


# ============================================================
#                         SUPERVISOR
# ============================================================

@app.route('/supervisor', methods=['GET', 'POST'])
@login_required('supervisor')
def supervisor_home():
    today = now_cl().date()
    start_cl = datetime.combine(today, datetime.min.time()).replace(tzinfo=CL)
    end_cl = datetime.combine(today, datetime.max.time()).replace(tzinfo=CL)
    start_today = start_cl.astimezone(timezone.utc)
    end_today = end_cl.astimezone(timezone.utc)

    # ------------ FILTROS ------------
    if request.method == 'POST':
        codigo = (request.form.get("codigo") or "").strip()
        fecha_inicio = request.form.get("fecha_inicio") or ""
        fecha_fin = request.form.get("fecha_fin") or ""
        estado_sel = request.form.get("estado") or "todos"
    else:
        codigo = ""
        fecha_inicio = ""
        fecha_fin = ""
        estado_sel = "todos"

    # Base: solo piezas rematadas
    filtro = {"modo": "rematador"}

    # Filtro por código de pieza
    if codigo:
        filtro["codigo_pieza"] = codigo

    # Filtro por rango de fechas
    if fecha_inicio and fecha_fin:
        try:
            d1 = datetime.strptime(fecha_inicio, "%Y-%m-%d").date()
            d2 = datetime.strptime(fecha_fin, "%Y-%m-%d").date()
            start_cl = datetime.combine(d1, datetime.min.time()).replace(tzinfo=CL)
            end_cl = datetime.combine(d2, datetime.max.time()).replace(tzinfo=CL)
            filtro["fecha"] = {"$gte": start_cl.astimezone(timezone.utc), "$lte": end_cl.astimezone(timezone.utc)}
        except ValueError:
            flash("Fechas inválidas (usa formato AAAA-MM-DD).", "warning")
    else:
        # por defecto, solo las de hoy
        filtro["fecha"] = {"$gte": start_today, "$lte": end_today}

    # Filtro por estado (aprobado / rechazado / pendiente)
    if estado_sel and estado_sel != "todos":
        filtro["calidad_status"] = estado_sel

    # ------------ CONSULTA ------------
    piezas = list(db.produccion.find(filtro).sort("fecha", -1))

    return render_template(
        "supervisor.html",
        piezas=piezas,
        codigo=codigo,
        fecha_inicio=fecha_inicio,
        fecha_fin=fecha_fin,
        estado_sel=estado_sel
    )

@app.route('/supervisor/informes')
@login_required('supervisor')
def supervisor_informes():
    return render_template("supervisor_informes.html")


# ============================================================
#                 VALIDACIÓN DE PIEZA (SUPERVISOR)
# ============================================================

@app.route('/supervisor/piezas/<id>/validar', methods=['POST'])
@login_required('supervisor')
def supervisor_validar_pieza(id):
    decision = request.form.get("decision")  # 'aprobado' o 'rechazado'
    cuerda_interna = request.form.get("cuerda_interna")
    cuerda_externa = request.form.get("cuerda_externa")
    comentario = request.form.get("comentario")

    update = {
        "calidad_status": decision,
        "cuerda_interna": cuerda_interna,
        "cuerda_externa": cuerda_externa,
        "comentario_supervisor": comentario
    }

    db.produccion.update_one(
        {"_id": ObjectId(id)},
        {"$set": update}
    )

    flash(f"Pieza actualizada como {decision}", "success")
    return redirect(url_for("supervisor_home"))

# ============================================================
#     INFORME – VALOR TOTAL POR OPERADOR
# ============================================================

@app.route('/admin/informes/valor-operador', methods=['GET', 'POST'])
@login_required(['administrador', 'soporte'])
def informe_piezas_operador():

    # Lista de operadores únicos
    operadores = sorted({p.get("usuario", "") for p in db.produccion.find() if p.get("usuario")})

    operador_sel = request.form.get("operador")
    fecha_inicio = request.form.get("fecha_inicio")
    fecha_fin = request.form.get("fecha_fin")

    # ---------- Filtros ----------
    filtro = {}

    if operador_sel and operador_sel != "todos":
        filtro["usuario"] = operador_sel

    if fecha_inicio or fecha_fin:
        try:
            start_cl = None
            end_cl = None
            if fecha_inicio:
                d1 = datetime.strptime(fecha_inicio, "%Y-%m-%d").date()
                start_cl = datetime.combine(d1, datetime.min.time()).replace(tzinfo=CL)
            if fecha_fin:
                d2 = datetime.strptime(fecha_fin, "%Y-%m-%d").date()
                end_cl = datetime.combine(d2, datetime.max.time()).replace(tzinfo=CL)
            rango = {}
            if start_cl:
                rango["$gte"] = start_cl.astimezone(timezone.utc)
            if end_cl:
                rango["$lte"] = end_cl.astimezone(timezone.utc)
            if rango:
                filtro["fecha"] = rango
        except:
            flash("Fechas inválidas", "warning")

    # Obtener producción filtrada
    produccion = list(db.produccion.find(filtro).sort("fecha", -1))

    # Cargar usuarios para obtener precios personalizados
    users_db = list(db.usuarios.find())
    users_map = {u['usuario']: u for u in users_db}

    resumen = []
    total_general = 0

    for p in produccion:
        codigo = p.get("codigo_pieza")
        modo = p.get("modo")
        usuario_nombre = p.get("usuario")

        if not codigo:
            continue

        try:
            codigo_int = int(codigo)
        except:
            continue

        # ------------------------
        # Buscar pieza original
        # ------------------------
        pieza_info = db.piezas.find_one({"codigo": codigo_int})
        if not pieza_info:
            continue

        # Cargar valores seguros
        peso = float(pieza_info.get("kilo_pieza", 0))   # el peso de la pieza
        
        # --- LÓGICA DE PRECIOS POR USUARIO (4 TIPOS) ---
        user_info = users_map.get(usuario_nombre, {})
        tipo_precio = pieza_info.get("tipo_precio", "metro") 

        rate = 0.0
        if tipo_precio == "metro":
            if modo == "armador":
                rate = float(user_info.get("precio_metro_armado", 0))
            else: # rematador
                rate = float(user_info.get("precio_metro_remate", 0))
        else: # avo
            if modo == "armador":
                rate = float(user_info.get("precio_avo_armado", 0))
            else: # rematador
                rate = float(user_info.get("precio_avo_remate", 0))

        valor = peso * rate

        total_general += valor

        resumen.append({
            "fecha": to_cl(p.get("fecha")),
            "codigo": codigo,
            "operador": usuario_nombre,
            "empresa": pieza_info.get("empresa"),
            "marco": pieza_info.get("marco"),
            "tramo": pieza_info.get("tramo"),
            "modo": modo.capitalize(),
            "peso": peso,
            "valor": valor
        })

    return render_template(
        "informe_valor_operador.html",
        piezas=resumen,
        total_general=total_general,
        operadores=operadores,
        operador_sel=operador_sel,
        fecha_inicio=fecha_inicio,
        fecha_fin=fecha_fin
    )



# ============================================================
#     EXPORTAR A EXCEL — VALOR POR OPERADOR
# ============================================================

@app.route('/admin/informes/valor-operador/export', methods=['POST'])
@login_required(['administrador', 'soporte'])
def exportar_valor_operador_excel():

    operador_sel = request.form.get("operador")
    fecha_inicio = request.form.get("fecha_inicio")
    fecha_fin = request.form.get("fecha_fin")

    filtro = {}

    if operador_sel and operador_sel != "todos":
        filtro["usuario"] = operador_sel

    # Cargar usuarios para obtener precios personalizados
    users_db = list(db.usuarios.find())
    users_map = {u['usuario']: u for u in users_db}

    if fecha_inicio and fecha_fin:
        try:
            d1 = datetime.strptime(fecha_inicio, "%Y-%m-%d").date()
            d2 = datetime.strptime(fecha_fin, "%Y-%m-%d").date()
            start_cl = datetime.combine(d1, datetime.min.time()).replace(tzinfo=CL)
            end_cl = datetime.combine(d2, datetime.max.time()).replace(tzinfo=CL)
            filtro["fecha"] = {"$gte": start_cl.astimezone(timezone.utc), "$lte": end_cl.astimezone(timezone.utc)}
        except:
            pass

    produccion = list(db.produccion.find(filtro).sort("fecha", -1))

    # --- OPTIMIZACIÓN: Precarga de piezas ---
    codigos_raw = set()
    for p in produccion:
        c = p.get("codigo_pieza")
        if c:
            codigos_raw.add(c)
            if str(c).isdigit():
                codigos_raw.add(int(c))
            codigos_raw.add(str(c))

    map_piezas = {}
    if codigos_raw:
        piezas_db = list(db.piezas.find({"codigo": {"$in": list(codigos_raw)}}))
        for pi in piezas_db:
            map_piezas[pi.get("codigo")] = pi
            c_val = pi.get("codigo")
            map_piezas[str(c_val)] = pi
            if isinstance(c_val, (int, float)):
                map_piezas[int(c_val)] = pi
    # ----------------------------------------

    data = []

    for p in produccion:
        codigo = p.get("codigo_pieza")
        modo = p.get("modo")

        if not codigo:
            continue

        # Buscar pieza optimizada
        pieza_info = map_piezas.get(codigo)
        if not pieza_info and str(codigo).isdigit():
            pieza_info = map_piezas.get(int(codigo))

        if not pieza_info:
            continue

        peso = float(pieza_info.get("kilo_pieza", 0))
        
        # --- LÓGICA DE PRECIOS POR USUARIO (4 TIPOS) ---
        user_info = users_map.get(p.get("usuario"), {})
        tipo_precio = pieza_info.get("tipo_precio", "metro")

        rate = 0.0
        if tipo_precio == "metro":
            if modo == "armador":
                rate = float(user_info.get("precio_metro_armado", 0))
            else: # rematador
                rate = float(user_info.get("precio_metro_remate", 0))
        else: # avo
            if modo == "armador":
                rate = float(user_info.get("precio_avo_armado", 0))
            else: # rematador
                rate = float(user_info.get("precio_avo_remate", 0))

        valor = peso * rate

        fecha = to_cl(p.get("fecha"))
        fecha_str = fecha.strftime("%d-%m-%Y %H:%M") if fecha else "—"

        data.append({
            "Fecha": fecha_str,
            "Código pieza": codigo,
            "Operador": p.get("usuario"),
            "Modo": modo.capitalize(),
            "Peso (kg)": peso,
            "Valor ($)": valor
        })

    if not data:
        flash("No hay datos para exportar con esos filtros", "warning")
        return redirect(url_for("informe_piezas_operador"))

    df = pd.DataFrame(data)

    output = BytesIO()
    with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
        df.to_excel(writer, index=False, sheet_name="ValorOperador")

    output.seek(0)

    return send_file(
        output,
        download_name="valor_por_operador.xlsx",
        as_attachment=True,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )

@app.route('/admin/archivados/valor-operador/export', methods=['POST'])
@login_required(['administrador', 'soporte'])
def exportar_valor_operador_archivado():
    operador_sel = request.form.get("operador")
    fecha_inicio = request.form.get("fecha_inicio")
    fecha_fin = request.form.get("fecha_fin")
    corte_nombre = request.form.get("corte_nombre")

    filtro = {}
    if operador_sel and operador_sel != "todos":
        filtro["usuario"] = operador_sel

    corte_id = None
    if corte_nombre and "corte_id" not in filtro:
        corte = db.cortes.find_one({'nombre': corte_nombre})
        if not corte:
             try:
                 corte = db.cortes.find_one({'_id': ObjectId(corte_nombre)})
             except:
                 pass
                 
        if corte:
            corte_id = corte.get('_id')
            corte_inicio = corte.get('inicio')
            corte_fin = corte.get('fin')
            
            filtro_hibrido = []
            if corte_id:
                filtro_hibrido.append({"corte_id": corte_id})
            if corte_inicio and corte_fin:
                filtro_hibrido.append({"fecha": {"$gte": corte_inicio, "$lt": corte_fin}})
            
            if filtro_hibrido:
                if len(filtro_hibrido) > 1:
                    filtro["$or"] = filtro_hibrido
                else:
                    filtro.update(filtro_hibrido[0])
            elif corte_id:
                filtro['corte_id'] = corte_id
    
    # Si no hay corte pero sí fechas manuales
    if not corte_nombre and fecha_inicio and fecha_fin:
        try:
            d1 = datetime.strptime(fecha_inicio, "%Y-%m-%d").date()
            d2 = datetime.strptime(fecha_fin, "%Y-%m-%d").date()
            start_cl = datetime.combine(d1, datetime.min.time()).replace(tzinfo=CL)
            end_cl = datetime.combine(d2, datetime.max.time()).replace(tzinfo=CL)
            filtro["fecha"] = {"$gte": start_cl.astimezone(timezone.utc), "$lte": end_cl.astimezone(timezone.utc)}
        except:
            pass

    produccion = list(db.produccion_historica.find(filtro).sort("fecha", -1))
    
    # Lógica de usuarios históricos (mismo que View)
    users_map = {}
    if corte_id:
        users_hist = list(db.usuarios_historicos.find({"corte_id": corte_id}))
        if users_hist:
            users_map = {u.get('usuario'): u for u in users_hist}
            
    if not users_map:
        users_db = list(db.usuarios.find())
        users_map = {u.get('usuario'): u for u in users_db}

    # --- OPTIMIZACIÓN DE CARGA (Bulk Loading) ---
    codigos_necesarios = set()
    for p in produccion:
        c = p.get("codigo_pieza")
        if c:
            codigos_necesarios.add(c)
            if isinstance(c, str) and c.isdigit():
                codigos_necesarios.add(int(c))
            elif isinstance(c, int):
                codigos_necesarios.add(str(c))
    
    piezas_hist_corte_map = {} 
    piezas_hist_gen_map = {}   
    piezas_actuales_map = {}   

    if codigos_necesarios:
        lista_codigos = list(codigos_necesarios)
        
        # 1. Cargar Históricas del Corte
        if corte_id:
            h_corte = list(db.piezas_historicas.find({
                "codigo": {"$in": lista_codigos},
                "corte_id": corte_id
            }))
            for h in h_corte:
                piezas_hist_corte_map[h.get("codigo")] = h

        # 2. Cargar Históricas Generales
        h_gen = list(db.piezas_historicas.find({
            "codigo": {"$in": lista_codigos}
        }))
        for h in h_gen:
            if h.get("codigo") not in piezas_hist_gen_map:
                piezas_hist_gen_map[h.get("codigo")] = h
        
        # 3. Cargar Actuales
        act = list(db.piezas.find({"codigo": {"$in": lista_codigos}}))
        for a in act:
            piezas_actuales_map[a.get("codigo")] = a

    data = []
    total_general = 0
    for p in produccion:
        codigo = p.get("codigo_pieza")
        modo = p.get("modo")
        
        pieza_info = None
        codigos_probar = [codigo]
        if isinstance(codigo, str) and codigo.isdigit():
            codigos_probar.append(int(codigo))
        elif isinstance(codigo, int):
            codigos_probar.append(str(codigo))
            
        # 1. Búsqueda en históricas del corte
        if corte_id:
            for c in codigos_probar:
                pieza_info = piezas_hist_corte_map.get(c)
                if pieza_info: break
        
        # 2. Búsqueda en históricas generales
        if not pieza_info:
            for c in codigos_probar:
                pieza_info = piezas_hist_gen_map.get(c)
                if pieza_info: break
                
        # 3. Búsqueda en actuales
        if not pieza_info:
            for c in codigos_probar:
                pieza_info = piezas_actuales_map.get(c)
                if pieza_info: break

        # Si no hay info de pieza, intentar obtener datos del registro de producción (snapshot)
        marco_val = (pieza_info.get("marco") if pieza_info else None) or p.get("marco") or ""
        tramo_val = (pieza_info.get("tramo") if pieza_info else None) or p.get("tramo") or ""
        
        peso_val = p.get("kilo_pieza")
        if peso_val is None:
            peso_val = pieza_info.get("kilo_pieza", 0) if pieza_info else 0

        tipo_precio = pieza_info.get("tipo_precio", "metro") if pieza_info else "metro"
        user = users_map.get(p.get("usuario"))
        
        valor_unitario = 0
        if user:
            if modo == "armador":
                valor_unitario = user.get("precio_metro_armado", 0) if tipo_precio == "metro" else user.get("precio_avo_armado", 0)
            else:
                valor_unitario = user.get("precio_metro_remate", 0) if tipo_precio == "metro" else user.get("precio_avo_remate", 0)
        
        total = (peso_val or 0) * (valor_unitario or 0)
        
        fecha_str = ""
        if p.get("fecha"):
            fecha_str = to_cl(p.get("fecha")).strftime('%d-%m-%Y %H:%M')
        
        data.append({
            "Fecha": fecha_str,
            "Código": codigo,
            "Operador": p.get("usuario", ""),
            "Modo": modo,
            "Marco": marco_val,
            "Tramo": tramo_val,
            "Cantidad": 1,
            "Peso": peso_val,
            "Precio Unit.": valor_unitario,
            "Tipo": tipo_precio,
            "Total": total
        })
        total_general += total
        
    if data:
        data.append({
            "Fecha": "TOTAL", "Código": "", "Operador": "", "Modo": "", "Marco": "", "Tramo": "",
            "Cantidad": "", "Peso": "", "Precio Unit.": "", "Tipo": "", "Total": total_general
        })

    df = pd.DataFrame(data)
    output = BytesIO()
    with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
        df.to_excel(writer, index=False, sheet_name="ValorOperadorArchivado")

    output.seek(0)

    return send_file(
        output,
        download_name="valor_por_operador_archivado.xlsx",
        as_attachment=True,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )




# ============================================================
#    INFORME – ESTADO DE PIEZAS (SIN/ARMADO/REMATADO)
# ============================================================

@app.route('/admin/informes/piezas/estado', methods=['GET', 'POST'])
@login_required(["administrador", "supervisor", "soporte", "cliente"])
def informe_estado_piezas():
    empresa = request.form.get("empresa")
    marco = request.form.get("marco")
    tramo = request.form.get("tramo")
    codigo = request.form.get("codigo_pieza")
    estado_filter = request.form.get("estado")  # Nuevo filtro

    filtros = {}
    if empresa and empresa != "todos":
        filtros["empresa"] = empresa
    if marco and marco != "todos":
        filtros["marco"] = marco
    if tramo and tramo != "todos":
        filtros["tramo"] = tramo
    if codigo:
        try:
            filtros["codigo"] = int(codigo)
        except:
            filtros["codigo"] = -1

    piezas = list(db.piezas.find(filtros).sort("codigo", 1))

    codigos_armado = set(db.produccion.distinct("codigo_pieza", {"modo": "armador"}))
    codigos_remate = set(db.produccion.distinct("codigo_pieza", {"modo": "rematador"}))

    listado = []
    for p in piezas:
        cstr = str(p.get("codigo"))
        if cstr in codigos_remate:
            estado = "Rematado"
        elif cstr in codigos_armado:
            estado = "Armado"
        else:
            estado = "Sin producción"

        # Aplicar filtro de estado si existe
        if estado_filter and estado_filter != "todos" and estado != estado_filter:
            continue

        listado.append({
            "codigo": p.get("codigo"),
            "cliente": p.get("empresa"),
            "marco": p.get("marco"),
            "tramo": p.get("tramo"),
            "cuerda_interna": p.get("cuerda_interna", ""),
            "cuerda_externa": p.get("cuerda_externa", ""),
            "estado": estado
        })

    empresas = sorted({pi.get("empresa") for pi in db.piezas.find()})
    marcos = sorted({pi.get("marco") for pi in db.piezas.find()})
    tramos = sorted({pi.get("tramo") for pi in db.piezas.find()})

    return render_template(
        "informe_estado_piezas.html",
        piezas=listado,
        empresas=empresas,
        marcos=marcos,
        tramos=tramos,
        empresa_sel=empresa,
        marco_sel=marco,
        tramo_sel=tramo,
        codigo_sel=codigo,
        estado_sel=estado_filter
    )


@app.route('/admin/informes/piezas/estado/export', methods=['POST'])
@login_required(["administrador", "supervisor", "soporte"])
def exportar_estado_piezas_excel():
    empresa = request.form.get("empresa")
    marco = request.form.get("marco")
    tramo = request.form.get("tramo")
    codigo = request.form.get("codigo_pieza")
    estado_filter = request.form.get("estado")

    filtros = {}
    if empresa and empresa != "todos":
        filtros["empresa"] = empresa
    if marco and marco != "todos":
        filtros["marco"] = marco
    if tramo and tramo != "todos":
        filtros["tramo"] = tramo
    if codigo:
        try:
            filtros["codigo"] = int(codigo)
        except:
            filtros["codigo"] = -1

    piezas = list(db.piezas.find(filtros).sort("codigo", 1))

    codigos_armado = set(db.produccion.distinct("codigo_pieza", {"modo": "armador"}))
    codigos_remate = set(db.produccion.distinct("codigo_pieza", {"modo": "rematador"}))

    data = []
    for p in piezas:
        cstr = str(p.get("codigo"))
        if cstr in codigos_remate:
            estado = "Rematado"
        elif cstr in codigos_armado:
            estado = "Armado"
        else:
            estado = "Sin producción"

        if estado_filter and estado_filter != "todos" and estado != estado_filter:
            continue

        visto_bueno = "OK" if estado == "Rematado" else ""

        data.append({
            "Código": p.get("codigo"),
            "Cliente": p.get("empresa"),
            "Marco": p.get("marco"),
            "Tramo": p.get("tramo"),
            "Cuerda Int.": p.get("cuerda_interna", ""),
            "Cuerda Ext.": p.get("cuerda_externa", ""),
            "Estado": estado,
            "Visto Bueno": visto_bueno
        })

    if not data:
        flash("No hay datos para exportar con esos filtros.", "warning")
        return redirect(url_for('informe_estado_piezas'))

    df = pd.DataFrame(data)
    output = BytesIO()
    with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
        df.to_excel(writer, index=False, sheet_name="EstadoPiezas")
    output.seek(0)

    return send_file(
        output,
        download_name="informe_estado_piezas.xlsx",
        as_attachment=True,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )

# ============================================================
# INFORME PIEZAS EN TARJETAS
# ============================================================


@app.route('/admin/informes/piezas/tarjetas', methods=['GET'])
@login_required(["administrador", "supervisor", "soporte", "cliente"])
def informe_piezas_tarjetas():
    clientes = db.piezas.distinct("empresa")
    resultado = []
    for cliente in clientes:
        marcos = db.piezas.distinct("marco", {"empresa": cliente})
        marcos_info = []
        for m in marcos:
            tramos = db.piezas.distinct("tramo", {"empresa": cliente, "marco": m})
            tramos_info = []
            for t in tramos:
                total = db.piezas.count_documents({"empresa": cliente, "marco": m, "tramo": t})
                rem = db.produccion.count_documents({"modo": "rematador", "empresa": cliente, "marco": m, "tramo": t})
                arm = db.produccion.count_documents({"modo": "armador", "empresa": cliente, "marco": m, "tramo": t})
                tramos_info.append({
                    "tramo": t, 
                    "total": total,
                    "rematadas": rem,
                    "armadas": arm,
                    "en_armado": max(arm - rem, 0),
                    "pendientes": max(total - rem, 0)
                })
            marcos_info.append({
                "marco": m,
                "tramos": sorted(tramos_info, key=lambda x: str(x["tramo"]))
            })
        resultado.append({
            "cliente": cliente,
            "marcos": sorted(marcos_info, key=lambda x: str(x["marco"]))
        })

    return render_template("informe_piezas_tarjetas.html", grupos=resultado)


# ============================================================
# INFORME RESUMEN PRODUCCIÓN (DASHBOARD CLIENTE/ADMIN)
# ============================================================

@app.route('/admin/informes/resumen-produccion', methods=['GET'])
@login_required(['administrador', 'cliente', 'soporte'])
def informe_resumen_produccion():
    today_real = now_cl().date()
    
    # ------------------ RANGOS DE FECHA ------------------
    # Hoy
    start_today = datetime.combine(today_real, datetime.min.time()).replace(tzinfo=CL).astimezone(timezone.utc)
    end_today = datetime.combine(today_real, datetime.max.time()).replace(tzinfo=CL).astimezone(timezone.utc)

    # Mes Actual
    start_month = datetime(today_real.year, today_real.month, 1).replace(tzinfo=CL).astimezone(timezone.utc)
    
    # Últimos 6 meses
    # Calculamos fecha de inicio: Hoy - 6 meses (aprox 180 días)
    date_6m = today_real - timedelta(days=180)
    start_6m = datetime.combine(date_6m, datetime.min.time()).replace(tzinfo=CL).astimezone(timezone.utc)
    
    # ------------------ CONSULTAS ------------------
    
    # Helper para sumar kilos por tipo
    def calcular_kilos(query):
        pipeline = [
            {"$match": query},
            {"$group": {
                "_id": "$tipo_precio", # "metro" o "avo"
                "total_kilos": {"$sum": "$kilo_pieza"}
            }}
        ]
        res = list(db.produccion.aggregate(pipeline))
        
        # Mapear resultado
        datos = {"metro": 0.0, "avo": 0.0}
        for r in res:
            tipo = r["_id"] or "metro"
            datos[tipo] = datos.get(tipo, 0.0) + (r.get("total_kilos") or 0.0)
        return datos

    # 1. Kilos Hoy
    kilos_hoy = calcular_kilos({"fecha": {"$gte": start_today, "$lte": end_today}})
    
    # 2. Kilos Mes Actual
    kilos_mes = calcular_kilos({"fecha": {"$gte": start_month}})
    
    # 3. Histórico 6 Meses (Activa + Histórica)
    pipeline_hist = [
        {"$match": {"fecha": {"$gte": start_6m}}},
        {"$project": {
            "year": {"$year": {"date": "$fecha", "timezone": "America/Santiago"}},
            "month": {"$month": {"date": "$fecha", "timezone": "America/Santiago"}},
            "tipo_precio": 1,
            "kilo_pieza": 1
        }},
        {"$group": {
            "_id": {"year": "$year", "month": "$month", "tipo": "$tipo_precio"},
            "total": {"$sum": "$kilo_pieza"}
        }},
        {"$sort": {"_id.year": 1, "_id.month": 1}}
    ]
    
    # Ejecutar en ambas colecciones
    raw_active = list(db.produccion.aggregate(pipeline_hist))
    raw_archived = list(db.produccion_historica.aggregate(pipeline_hist))
    
    # Unificar datos
    data_map = {} # "YYYY-MM" -> {"avo": 0, "metro": 0}
    
    def process_agg(rows):
        for r in rows:
            y = r["_id"]["year"]
            m = r["_id"]["month"]
            t = r["_id"].get("tipo") or "metro"
            k = r.get("total") or 0.0
            
            key = f"{y}-{m:02d}"
            if key not in data_map:
                data_map[key] = {"avo": 0.0, "metro": 0.0}
            
            if t not in ["avo", "metro"]: t = "metro"
            
            data_map[key][t] += k

    process_agg(raw_active)
    process_agg(raw_archived)
    
    # Ordenar claves cronológicamente
    sorted_keys = sorted(data_map.keys())
    
    chart_labels = []
    chart_avo = []
    chart_metro = []
    
    meses_es = ["", "Ene", "Feb", "Mar", "Abr", "May", "Jun", "Jul", "Ago", "Sep", "Oct", "Nov", "Dic"]
    
    for k in sorted_keys:
        y, m = map(int, k.split("-"))
        label = f"{meses_es[m]} {y}"
        chart_labels.append(label)
        chart_avo.append(round(data_map[k]["avo"], 2))
        chart_metro.append(round(data_map[k]["metro"], 2))

    return render_template(
        "informe_resumen_produccion.html",
        kilos_hoy=kilos_hoy,
        kilos_mes=kilos_mes,
        chart_labels=chart_labels,
        chart_avo=chart_avo,
        chart_metro=chart_metro
    )


# ==============================================================================
# 15. GESTIÓN DE ARCHIVOS HISTÓRICOS (SOLO SOPORTE)
# ==============================================================================
# Estas rutas permiten al rol 'soporte' modificar datos de cortes anteriores.
# Es útil para corregir errores en pagos o informes de meses pasados.
# Se trabaja sobre las colecciones: usuarios_historicos, produccion_historica, piezas_historicas.

@app.route('/soporte/archivados/usuarios', methods=['GET'])
@login_required('soporte')
def soporte_archivados_usuarios():
    """Muestra y filtra usuarios históricos por corte (fecha de cierre)."""
    cortes = list(db.cortes.find().sort("inicio", -1))
    corte_sel = request.args.get("corte_id")
    usuarios = []

    if corte_sel:
        try:
            usuarios = list(db.usuarios_historicos.find({"corte_id": ObjectId(corte_sel)}))
        except:
            pass
            
    return render_template('soporte_archivados_usuarios.html', cortes=cortes, corte_sel=corte_sel, usuarios=usuarios)

@app.route('/soporte/archivados/usuarios/editar', methods=['POST'])
@login_required('soporte')
def soporte_archivados_usuarios_editar():
    """Actualiza precios o datos de un usuario en un corte histórico."""
    user_id = request.form.get("user_id")
    corte_id = request.form.get("corte_id")
    
    # Recopilar datos a actualizar (precios históricos)
    update_data = {
        "precio_metro_armado": float(request.form.get("precio_metro_armado", 0)),
        "precio_metro_remate": float(request.form.get("precio_metro_remate", 0)),
        "precio_avo_armado": float(request.form.get("precio_avo_armado", 0)),
        "precio_avo_remate": float(request.form.get("precio_avo_remate", 0))
    }
    
    # Actualizar en BD y registrar auditoría
    db.usuarios_historicos.update_one({"_id": ObjectId(user_id)}, {"$set": update_data})
    log_audit("EDIT_USER_HIST", f"ID: {user_id}, Data: {update_data}")
    
    flash("Usuario histórico actualizado.", "success")
    return redirect(url_for('soporte_archivados_usuarios', corte_id=corte_id))


@app.route('/soporte/archivados/produccion', methods=['GET'])
@login_required('soporte')
def soporte_archivados_produccion():
    """Muestra y filtra registros de producción históricos."""
    cortes = list(db.cortes.find().sort("inicio", -1))

    corte_sel = request.args.get("corte_id")
    codigo_sel = request.args.get("codigo")
    produccion = []

    if corte_sel:
        filtro = {"corte_id": ObjectId(corte_sel)}
        if codigo_sel:
            filtro["codigo_pieza"] = codigo_sel.strip()
            
        produccion = list(db.produccion_historica.find(filtro).sort("fecha", -1))

    return render_template('soporte_archivados_produccion.html', cortes=cortes, corte_sel=corte_sel, produccion=produccion, codigo_sel=codigo_sel)

@app.route('/soporte/archivados/produccion/editar', methods=['POST'])
@login_required('soporte')
def soporte_archivados_produccion_editar():
    prod_id = request.form.get("prod_id")
    corte_id = request.form.get("corte_id")
    
    update_data = {
        "codigo_pieza": request.form.get("codigo_pieza"),
        "usuario": request.form.get("usuario"),
        "modo": request.form.get("modo")
    }
    m = update_data.get("modo")
    if m not in ("armador", "rematador"):
        flash("Modo inválido.", "danger")
        return redirect(url_for('soporte_archivados_produccion', corte_id=corte_id))
    
    db.produccion_historica.update_one({"_id": ObjectId(prod_id)}, {"$set": update_data})
    log_audit("EDIT_PROD_HIST", f"ID: {prod_id}, Data: {update_data}")
    flash("Registro de producción histórico actualizado.", "success")
    return redirect(url_for('soporte_archivados_produccion', corte_id=corte_id))

@app.route('/soporte/archivados/produccion/eliminar', methods=['POST'])
@login_required('soporte')
def soporte_archivados_produccion_eliminar():
    prod_id = request.form.get("prod_id")
    corte_id = request.form.get("corte_id")
    
    db.produccion_historica.delete_one({"_id": ObjectId(prod_id)})
    log_audit("DELETE_PROD_HIST", f"ID: {prod_id}")
    flash("Registro histórico eliminado.", "info")
    return redirect(url_for('soporte_archivados_produccion', corte_id=corte_id))


@app.route('/soporte/archivados/piezas', methods=['GET'])
@login_required('soporte')
def soporte_archivados_piezas():
    cortes = list(db.cortes.find().sort("inicio", -1))
    corte_sel = request.args.get("corte_id")
    codigo_sel = request.args.get("codigo")
    piezas = []

    if corte_sel:
        filtro = {"corte_id": ObjectId(corte_sel)}
        if codigo_sel:
            # Intentar buscar como número si es posible
            if codigo_sel.isdigit():
                filtro["codigo"] = int(codigo_sel)
            else:
                 # Fallback o si es string
                 filtro["codigo"] = codigo_sel
            
        piezas = list(db.piezas_historicas.find(filtro).sort("codigo", 1))

    return render_template('soporte_archivados_piezas.html', cortes=cortes, corte_sel=corte_sel, piezas=piezas, codigo_sel=codigo_sel)

@app.route('/soporte/archivados/piezas/editar', methods=['POST'])
@login_required('soporte')
def soporte_archivados_piezas_editar():
    pieza_id = request.form.get("pieza_id")
    corte_id = request.form.get("corte_id")
    
    update_data = {
        "kilo_pieza": float(request.form.get("kilo_pieza", 0)),
        "tipo_precio": request.form.get("tipo_precio"),
        "marco": request.form.get("marco"),
        "tramo": request.form.get("tramo")
    }
    tp = update_data.get("tipo_precio")
    if tp not in ("metro", "avo"):
        flash("Tipo de precio inválido.", "danger")
        return redirect(url_for('soporte_archivados_piezas', corte_id=corte_id))
    
    db.piezas_historicas.update_one({"_id": ObjectId(pieza_id)}, {"$set": update_data})
    log_audit("EDIT_PIEZA_HIST", f"ID: {pieza_id}, Data: {update_data}")
    flash("Pieza histórica actualizada.", "success")
    return redirect(url_for('soporte_archivados_piezas', corte_id=corte_id))


# ==============================================================================
# 16. EJECUCIÓN DE LA APLICACIÓN
# ==============================================================================

if __name__ == "__main__":
    import threading
    import subprocess
    import time
    import atexit
    import re
    import sys

    def start_secure_tunnel():
        """
        Inicia un túnel SSH reverso (Serveo/Localhost.run) para exponer el puerto 5000 a internet.
        Esto es necesario para probar funcionalidades que requieren HTTPS (como la cámara)
        desde dispositivos móviles sin desplegar en un servidor real.
        """
        global tunnel_url
        print("⏳ Intentando establecer túnel HTTPS seguro...")
        
        # Intentamos primero con Serveo (suele ser más estable)
        tunnel_cmd = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ServerAliveInterval=60", "-R", "80:127.0.0.1:5000", "serveo.net"]
        
        try:
            process = subprocess.Popen(
                tunnel_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                encoding='utf-8',
                errors='replace'
            )
            
            # Asegurar que el túnel se cierre al apagar la app
            atexit.register(lambda: process.terminate())

            start_t = time.time()
            while time.time() - start_t < 15:
                line = process.stdout.readline()
                if not line:
                    break
                
                # Patrón Serveo: "Forwarding HTTP traffic from https://xyz.serveo.net"
                if "Forwarding HTTP traffic from" in line:
                    match = re.search(r'(https://[a-zA-Z0-9.-]+)', line)
                    if match:
                        url = match.group(1)
                        tunnel_url = url
                        print("\n" + "▒"*60)
                        print(" ✅ TÚNEL HTTPS ACTIVO (Serveo)")
                        print(f" 🔗 URL SEGURA: {url}")
                        print(" 📱 ¡Usa este enlace en tu celular para activar la cámara!")
                        print("▒"*60 + "\n")
                        break
                        
                # Patrón localhost.run (fallback si cambiamos el comando)
                if "tunneled with tls termination" in line:
                    match = re.search(r'(https://[a-zA-Z0-9.-]+\.lhr\.life)', line)
                    if match:
                        url = match.group(1)
                        tunnel_url = url
                        print("\n" + "▒"*60)
                        print(" ✅ TÚNEL HTTPS ACTIVO (Localhost.run)")
                        print(f" 🔗 URL SEGURA: {url}")
                        print(" 📱 ¡Usa este enlace en tu celular para activar la cámara!")
                        print("▒"*60 + "\n")
                        break
        except Exception as e:
            print(f"⚠️ No se pudo iniciar el túnel automático: {e}")

    # Iniciar túnel solo si la variable de entorno lo permite (Seguridad)
    if os.getenv("ENABLE_TUNNEL") == "true":
        threading.Thread(target=start_secure_tunnel, daemon=True).start()

    print("================================================================")
    print(" INICIANDO SERVIDOR LOCAL")
    print(" Local: http://127.0.0.1:5000")
    print(" LAN:   http://0.0.0.0:5000")
    print("================================================================")
    
    # Ejecutar servidor Flask escuchando en todas las interfaces (0.0.0.0)
    app.run(host='0.0.0.0', port=5000)
