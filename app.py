import os
import json
from datetime import datetime, date, timedelta
from bson import ObjectId
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from io import BytesIO
import pandas as pd
from pymongo import MongoClient
from datetime import timezone, timedelta

# Zona horaria Chile (UTC-3)
CL = timezone(timedelta(hours=-3))

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY") or os.urandom(24)

client = MongoClient(os.getenv("MONGO_URI"))
db = client["miBase"]



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
    """Asegura que el admin siempre exista."""
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
        else:
            return redirect(url_for('operador_home'))

    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        usuario = request.form.get('usuario', '').strip()
        password = request.form.get('password')

        user = db.usuarios.find_one({'usuario': usuario})

        if user and check_password_hash(user['password'], password):

            session['user_id'] = str(user['_id'])
            session['username'] = user['usuario']
            session['nombre'] = user.get('nombre', user['usuario'])
            session['role'] = user['tipo']

            pw_date = to_cl(user.get("password_changed_at"))

            if not pw_date or (now_cl() - pw_date) > timedelta(days=30):
                flash("Debes cambiar tu contraseña antes de continuar.", "warning")
                return redirect(url_for("cambiar_password"))

            flash(f"Bienvenido, {session['nombre']}", 'success')
            return redirect(url_for('index'))

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
@login_required('administrador')
def usuarios_list():
    usuarios = list(db.usuarios.find({"usuario": {"$ne": "soporte"}}))
    return render_template('crud_usuarios.html', usuarios=usuarios)


@app.route('/admin/usuarios/nuevo')
@login_required('administrador')
def usuarios_nuevo_form():
    return render_template('usuario_form.html', modo='nuevo')


@app.route('/admin/usuarios/nuevo', methods=['POST'])
@login_required('administrador')
def usuarios_nuevo_post():
    usuario = request.form['usuario'].strip()
    nombre = request.form['nombre'].strip()
    tipo = request.form['tipo']
    password = generate_password_hash(request.form['password'])

    if db.usuarios.find_one({'usuario': usuario}):
        flash('El usuario ya existe', 'warning')
        return redirect(url_for('usuarios_list'))

    db.usuarios.insert_one({
        'usuario': usuario,
        'nombre': nombre,
        'tipo': tipo,
        'password': password
    })

    flash('Usuario creado correctamente ✔', 'success')
    return redirect(url_for('usuarios_list'))


@app.route('/admin/usuarios/<id>/editar')
@login_required('administrador')
def usuarios_editar_form(id):
    usuario = db.usuarios.find_one({'_id': ObjectId(id)})
    if not usuario:
        flash('Usuario no encontrado', 'danger')
        return redirect(url_for('usuarios_list'))

    return render_template('usuario_form.html', modo='editar', usuario=usuario)


@app.route('/admin/usuarios/<id>/editar', methods=['POST'])
@login_required('administrador')
def usuarios_editar_post(id):
    nombre = request.form['nombre'].strip()
    tipo = request.form['tipo']
    pwd = request.form.get('password', '').strip()

    update = {'nombre': nombre, 'tipo': tipo}
    if pwd:
        update['password'] = generate_password_hash(pwd)

    db.usuarios.update_one({'_id': ObjectId(id)}, {'$set': update})
    flash('Usuario actualizado ✔', 'success')
    return redirect(url_for('usuarios_list'))


@app.route('/admin/usuarios/<id>/delete', methods=['POST'])
@login_required('administrador')
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
@login_required('administrador')
def boxes_list():
    boxes = list(db.boxes.find())
    return render_template('crud_boxes.html', boxes=boxes)


@app.route('/admin/boxes/nuevo')
@login_required('administrador')
def boxes_nuevo_form():
    return render_template('box_form.html', modo='nuevo')


@app.route('/admin/boxes/nuevo', methods=['POST'])
@login_required('administrador')
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
@login_required('administrador')
def boxes_editar_form(id):
    box = db.boxes.find_one({'_id': ObjectId(id)})
    if not box:
        flash('Box no encontrado', 'danger')
        return redirect(url_for('boxes_list'))

    return render_template('box_form.html', modo='editar', box=box)


@app.route('/admin/boxes/<id>/editar', methods=['POST'])
@login_required('administrador')
def boxes_editar_post(id):
    codigo = request.form['codigo'].strip()
    descripcion = request.form['descripcion'].strip()

    db.boxes.update_one({'_id': ObjectId(id)}, {
        '$set': {'codigo': codigo, 'descripcion': descripcion}
    })

    flash('Box actualizado ✔', 'success')
    return redirect(url_for('boxes_list'))


@app.route('/admin/boxes/<id>/delete', methods=['POST'])
@login_required('administrador')
def boxes_delete(id):
    db.boxes.delete_one({'_id': ObjectId(id)})
    flash('Box eliminado', 'info')
    return redirect(url_for('boxes_list'))
# ============================================================
#                     CRUD PIEZAS (NUEVO MODELO)
# ============================================================

@app.route('/admin/piezas')
@login_required('administrador')
def piezas_list():
    piezas = list(db.piezas.find().sort('codigo', 1))
    return render_template('crud_piezas.html', piezas=piezas)


# ==================== NUEVA PIEZA ====================

@app.route('/admin/piezas/nuevo')
@login_required('administrador')
def piezas_nuevo_form():
    return render_template('pieza_form.html', modo='nuevo', pieza=None)


@app.route('/admin/piezas/nuevo', methods=['POST'])
@login_required('administrador')
def piezas_nuevo_post():
    empresa = request.form['empresa'].strip()
    marco = request.form['marco'].strip()
    tramo = request.form['tramo'].strip()
    kilo_pieza = float(request.form['kilo_pieza'])
    precio_armado = float(request.form['precio_armado'])
    precio_remate = float(request.form['precio_remate'])
    cantidad = int(request.form['cantidad'])

    cuerda_interna = request.form.get("cuerda_interna", "").strip()
    cuerda_externa = request.form.get("cuerda_externa", "").strip()

    # Obtener último código usado
    last = db.piezas.find_one(sort=[("codigo", -1)])
    next_codigo = last['codigo'] + 1 if last and 'codigo' in last else 1

    docs = []
    for i in range(cantidad):
        docs.append({
            "codigo": next_codigo + i,
            "empresa": empresa,
            "marco": marco,
            "tramo": tramo,
            "kilo_pieza": kilo_pieza,
            "precio_armado": precio_armado,
            "precio_remate": precio_remate,
            "cuerda_interna": cuerda_interna,
            "cuerda_externa": cuerda_externa,
            "created_at": datetime.utcnow()
        })

    if docs:
        db.piezas.insert_many(docs)

    flash(f'✅ Se crearon {cantidad} piezas correctamente (desde código {next_codigo}).', 'success')
    return redirect(url_for('piezas_list'))


# ==================== EDITAR PIEZA ====================

@app.route('/admin/piezas/<id>/editar')
@login_required('administrador')
def piezas_editar_form(id):
    pieza = db.piezas.find_one({'_id': ObjectId(id)})
    if not pieza:
        flash('Pieza no encontrada', 'warning')
        return redirect(url_for('piezas_list'))
    return render_template('pieza_form.html', modo='editar', pieza=pieza)


@app.route('/admin/piezas/<id>/editar', methods=['POST'])
@login_required('administrador')
def piezas_editar_post(id):
    empresa = request.form['empresa'].strip()
    marco = request.form['marco'].strip()
    tramo = request.form['tramo'].strip()
    kilo_pieza = float(request.form['kilo_pieza'])
    precio_armado = float(request.form['precio_armado'])
    precio_remate = float(request.form['precio_remate'])
    
    cuerda_interna = request.form.get("cuerda_interna", "").strip()
    cuerda_externa = request.form.get("cuerda_externa", "").strip()

    db.piezas.update_one(
        {'_id': ObjectId(id)},
        {'$set': {
            "empresa": empresa,
            "marco": marco,
            "tramo": tramo,
            "kilo_pieza": kilo_pieza,
            "precio_armado": precio_armado,
            "precio_remate": precio_remate,
            "cuerda_interna": cuerda_interna,
            "cuerda_externa": cuerda_externa
        }}
    )

    flash('✅ Pieza actualizada con éxito', 'success')
    return redirect(url_for('piezas_list'))


# ==================== ELIMINAR ====================

@app.route('/admin/piezas/<id>/delete', methods=['POST'])
@login_required('administrador')
def piezas_delete(id):
    db.piezas.delete_one({'_id': ObjectId(id)})
    flash('Pieza eliminada', 'info')
    return redirect(url_for('piezas_list'))

# ============================================================
#                API DINÁMICA PARA LISTAS DEPENDIENTES
# ============================================================

@app.route('/api/marcos/<empresa>')
@login_required(["administrador", "supervisor"])
def api_marcos(empresa):
    marcos = db.piezas.distinct("marco", {"empresa": empresa})
    return {"marcos": marcos}


@app.route('/api/tramos/<empresa>/<marco>')
@login_required(["administrador", "supervisor"])
def api_tramos(empresa, marco):
    tramos = db.piezas.distinct("tramo", {"empresa": empresa, "marco": marco})
    return {"tramos": tramos}



# ============================================================
#       EDICIÓN MASIVA — PASO 1: FILTRAR Y VISTA PREVIA
# ============================================================

@app.route('/admin/piezas/masivo', methods=['GET', 'POST'])
@login_required('administrador')
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
@login_required('administrador')
def piezas_masivo_confirmar():
    filtros = json.loads(request.form.get("filtros"))
    campo = request.form.get("campo")
    valor = request.form.get("valor")

    if not campo or not valor:
        flash("Debes indicar el campo y el valor a modificar.", "warning")
        return redirect(url_for("piezas_masivo"))

    # Campos numéricos
    if campo in ["kilo_pieza", "precio_armado", "precio_remate"]:
        try:
            valor = float(valor)
        except:
            flash("El valor debe ser numérico para este campo.", "danger")
            return redirect(url_for("piezas_masivo"))

    # Campos nuevos: cadenas simples
    if campo in ["cuerda_interna", "cuerda_externa"]:
        valor = valor.strip()

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
@login_required(["administrador", "soporte"])
def admin_informes():
    return render_template('admin_informes.html')


# ============================================================
#                 INFORME DE HORARIOS + EXPORTACIÓN
# ============================================================

@app.route('/admin/informes/horarios', methods=['GET', 'POST'])
@login_required('administrador')
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
#        INFORME — PIEZAS REMATADAS (GRÁFICOS + EXCEL)
# ============================================================

@app.route('/admin/informes/piezas/rematadas', methods=['GET', 'POST'])
@login_required(["administrador", "supervisor"])
def informe_piezas_rematadas():

    filtro = {"modo": "rematador"}  # solo piezas rematadas

    fecha_inicio = request.form.get("fecha_inicio")
    fecha_fin = request.form.get("fecha_fin")
    codigo = request.form.get("codigo_pieza")
    operador = request.form.get("operador")
    estado_sel = request.form.get("estado")

    # ===================== FILTROS =====================

    # Filtro por fechas (interpretar como horario Chile y convertir a UTC)
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

    # Código pieza
    if codigo:
        filtro["codigo_pieza"] = codigo.strip()

    # Estado
    if estado_sel and estado_sel != "todos":
        filtro["calidad_status"] = estado_sel

    # Operador
    if operador and operador != "todos":
        filtro["usuario"] = operador

    # ===================== CONSULTA PRINCIPAL =====================

    piezas = list(db.produccion.find(filtro).sort("fecha", -1))
    for p in piezas:
        p["fecha"] = to_cl(p.get("fecha"))

    # Para el select operador
    operadores = sorted({p["usuario"] for p in db.produccion.find({"modo": "rematador"})})

    # ===================== GRÁFICO DE ESTADOS =====================
    estado_counts = {"pendiente": 0, "aprobado": 0, "rechazado": 0}
    for p in piezas:
        e = p.get("calidad_status", "pendiente")
        if e in estado_counts:
            estado_counts[e] += 1

    return render_template(
        "informe_piezas_rematadas.html",
        piezas=piezas,
        fecha_inicio=fecha_inicio,
        fecha_fin=fecha_fin,
        codigo=codigo,
        operadores=operadores,
        operador_sel=operador,
        estado_sel=estado_sel,
        estado_counts=estado_counts
    )


# ============================================================
#     EXPORTAR INFORME - PIEZAS REMATADAS A EXCEL
# ============================================================

@app.route('/admin/informes/piezas_rematadas/export', methods=['POST'])
@login_required(["administrador", "supervisor"])
def exportar_piezas_rematadas_excel():
    # Leemos filtros desde el form (cuidando 'None')
    fecha_inicio = (request.form.get("fecha_inicio") or "").strip()
    fecha_fin = (request.form.get("fecha_fin") or "").strip()
    codigo = (request.form.get("codigo_pieza") or "").strip()
    operador_sel = (request.form.get("operador") or "todos").strip()
    estado_sel = (request.form.get("estado") or "todos").strip()

    filtro = {"modo": "rematador"}

    # Código pieza
    if codigo:
        filtro["codigo_pieza"] = codigo

    # Fechas – acepta inicio o fin por separado
    if fecha_inicio or fecha_fin:
        try:
            start_cl = None
            end_cl = None
            if fecha_inicio and fecha_inicio != "None":
                d1 = datetime.strptime(fecha_inicio, "%Y-%m-%d").date()
                start_cl = datetime.combine(d1, datetime.min.time()).replace(tzinfo=CL)
            if fecha_fin and fecha_fin != "None":
                d2 = datetime.strptime(fecha_fin, "%Y-%m-%d").date()
                end_cl = datetime.combine(d2, datetime.max.time()).replace(tzinfo=CL)

            rango = {}
            if start_cl:
                rango["$gte"] = start_cl.astimezone(timezone.utc)
            if end_cl:
                rango["$lte"] = end_cl.astimezone(timezone.utc)
            if rango:
                filtro["fecha"] = rango
        except ValueError:
            flash("Fechas inválidas (usa AAAA-MM-DD).", "warning")
            return redirect(url_for("informe_piezas_rematadas"))

    # Estado
    if estado_sel and estado_sel != "todos":
        filtro["calidad_status"] = estado_sel

    # Operador
    if operador_sel and operador_sel != "todos":
        filtro["usuario"] = operador_sel

    piezas = list(db.produccion.find(filtro).sort("fecha", -1))

    # Armar datos para Excel
    data = []
    for p in piezas:
        fecha = to_cl(p.get("fecha"))
        fecha_str = fecha.strftime("%d-%m-%Y %H:%M") if isinstance(fecha, datetime) else ""

        data.append({
            "Fecha": fecha_str,
            "Código pieza": p.get("codigo_pieza", "—"),
            "Empresa": p.get("empresa", "—"),
            "Operador": p.get("usuario", "—"),
            "Marco": p.get("marco", "—"),
            "Tramo": p.get("tramo", "—"),
            "Estado": p.get("calidad_status", "pendiente").capitalize(),
            "Cuerda interna": p.get("cuerda_interna", ""),
            "Cuerda externa": p.get("cuerda_externa", ""),
            "Comentario supervisor": p.get("comentario_supervisor", "")
        })

    if not data:
        flash("No hay datos para exportar con esos filtros.", "warning")
        return redirect(url_for("informe_piezas_rematadas"))

    df = pd.DataFrame(data)

    output = BytesIO()
    with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
        df.to_excel(writer, index=False, sheet_name="Piezas rematadas")

        # Formato de encabezado (opcional)
        workbook = writer.book
        worksheet = writer.sheets["Piezas rematadas"]
        header_format = workbook.add_format({
            "bold": True,
            "text_wrap": True,
            "valign": "middle",
            "fg_color": "#222222",
            "font_color": "white",
            "border": 1
        })
        for col_num, value in enumerate(df.columns.values):
            worksheet.write(0, col_num, value, header_format)

    output.seek(0)

    return send_file(
        output,
        download_name="informe_piezas_rematadas.xlsx",
        as_attachment=True,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )


# ============================================================
#   INFORME — PIEZAS ESPERANDO REMATE (ARMADAS SIN REMATAR)
# ============================================================

@app.route('/admin/informes/piezas/pendientes-remate', methods=['GET', 'POST'])
@login_required(["administrador", "supervisor"])
def informe_piezas_pendientes_remate():
    # Filtro base: solo registros de ARMADOR
    filtro_base = {"modo": "armador"}

    fecha_inicio = request.form.get("fecha_inicio")
    fecha_fin = request.form.get("fecha_fin")
    codigo = request.form.get("codigo_pieza")
    operador = request.form.get("operador")
    estado_sel = request.form.get("estado")

    # ---------------- FILTROS ----------------

    # Rango de fechas
    if fecha_inicio and fecha_fin:
        try:
            d1 = datetime.strptime(fecha_inicio, "%Y-%m-%d")
            d2 = datetime.strptime(fecha_fin, "%Y-%m-%d")
            d2 = datetime.combine(d2, datetime.max.time())
            filtro_base["fecha"] = {"$gte": d1, "$lte": d2}
        except:
            flash("Fechas inválidas", "warning")

    # Código pieza
    if codigo:
        filtro_base["codigo_pieza"] = codigo.strip()

    # Estado
    if estado_sel and estado_sel != "todos":
        filtro_base["calidad_status"] = estado_sel

    # Operador
    if operador and operador != "todos":
        filtro_base["usuario"] = operador

    # ---------------- CONSULTA BASE (ARMADOR) ----------------
    # Todas las producciones donde se ha ARMADO la pieza (según filtros)
    produccion_armador = list(db.produccion.find(filtro_base).sort("fecha", -1))

    # Códigos que YA tienen remate (en cualquier fecha)
    codigos_con_remate = set(db.produccion.distinct("codigo_pieza", {"modo": "rematador"}))

    # Nos quedamos SOLO con las piezas que NO tienen remate
    piezas_pendientes = []
    vistos = set()  # para no repetir código
    for p in produccion_armador:
        cod = p.get("codigo_pieza")
        if not cod:
            continue
        if cod in codigos_con_remate:
            continue
        # primera vez que vemos este código -> lo usamos como "representante" en la tabla
        if cod not in vistos:
            vistos.add(cod)
            piezas_pendientes.append(p)

    # Operadores disponibles (para el filtro select)
    operadores = sorted({p.get("usuario", "") for p in db.produccion.find({"modo": "armador"})})

    # ---------------- GRÁFICO DE ESTADOS ----------------
    for p in piezas_pendientes:
        p["fecha"] = to_cl(p.get("fecha"))
    estado_counts = {"pendiente": 0, "aprobado": 0, "rechazado": 0}
    for p in piezas_pendientes:
        e = p.get("calidad_status", "pendiente")
        if e in estado_counts:
            estado_counts[e] += 1

    return render_template(
        "informe_piezas_pendientes_remate.html",
        piezas=piezas_pendientes,
        fecha_inicio=fecha_inicio,
        fecha_fin=fecha_fin,
        codigo=codigo,
        operadores=operadores,
        operador_sel=operador,
        estado_sel=estado_sel,
        estado_counts=estado_counts
    )


# ============================================================
#   EXPORTAR A EXCEL — PIEZAS ESPERANDO REMATE
# ============================================================

@app.route('/admin/informes/piezas/pendientes-remate/export', methods=['POST'])
@login_required(["administrador", "supervisor"])
def exportar_piezas_pendientes_remate_excel():
    # Base: solo registros en modo "armador"
    filtro_base = {"modo": "armador"}

    # Leer filtros desde el formulario (cuidando None / strings vacías)
    fecha_inicio = (request.form.get("fecha_inicio") or "").strip()
    fecha_fin = (request.form.get("fecha_fin") or "").strip()
    codigo = (request.form.get("codigo_pieza") or "").strip()
    operador = (request.form.get("operador") or "todos").strip()
    estado_sel = (request.form.get("estado") or "todos").strip()

    # ---------- Filtro por rango de fechas (acepta solo inicio o solo fin) ----------
    if fecha_inicio or fecha_fin:
        try:
            start_cl = None
            end_cl = None
            if fecha_inicio and fecha_inicio.lower() != "none":
                d1 = datetime.strptime(fecha_inicio, "%Y-%m-%d").date()
                start_cl = datetime.combine(d1, datetime.min.time()).replace(tzinfo=CL)
            if fecha_fin and fecha_fin.lower() != "none":
                d2 = datetime.strptime(fecha_fin, "%Y-%m-%d").date()
                end_cl = datetime.combine(d2, datetime.max.time()).replace(tzinfo=CL)

            rango = {}
            if start_cl:
                rango["$gte"] = start_cl.astimezone(timezone.utc)
            if end_cl:
                rango["$lte"] = end_cl.astimezone(timezone.utc)
            if rango:
                filtro_base["fecha"] = rango
        except ValueError:
            flash("Fechas inválidas (usa formato AAAA-MM-DD).", "warning")
            return redirect(url_for("informe_piezas_pendientes_remate"))

    # ---------- Filtro por código ----------
    if codigo:
        filtro_base["codigo_pieza"] = codigo

    # ---------- Filtro por estado ----------
    if estado_sel and estado_sel != "todos":
        filtro_base["calidad_status"] = estado_sel

    # ---------- Filtro por operador ----------
    if operador and operador != "todos":
        filtro_base["usuario"] = operador

    # Registros de armador según filtros
    produccion_armador = list(db.produccion.find(filtro_base).sort("fecha", -1))

    # Códigos que YA tienen al menos un registro en rematador
    codigos_con_remate = set(
        db.produccion.distinct("codigo_pieza", {"modo": "rematador"})
    )

    # Filtrar solo las piezas que aún NO tienen remate (una fila por código)
    piezas_pendientes = []
    vistos = set()
    for p in produccion_armador:
        cod = p.get("codigo_pieza")
        if not cod:
            continue
        if cod in codigos_con_remate:
            continue
        if cod not in vistos:
            vistos.add(cod)
            piezas_pendientes.append(p)

    if not piezas_pendientes:
        flash("No hay datos para exportar con estos filtros.", "warning")
        return redirect(url_for("informe_piezas_pendientes_remate"))

    # ---------- Construir data para Excel ----------
    data = []
    for p in piezas_pendientes:
        fecha = to_cl(p.get("fecha"))
        fecha_str = fecha.strftime("%d-%m-%Y %H:%M") if isinstance(fecha, datetime) else "—"

        data.append({
            "Fecha": fecha_str,
            "Código": p.get("codigo_pieza", ""),
            "Empresa": p.get("empresa", ""),
            "Operador": p.get("usuario", ""),
            "Marco": p.get("marco", ""),
            "Tramo": p.get("tramo", ""),
            "Estado": p.get("calidad_status", "pendiente").capitalize(),
            "Cuerda interna": p.get("cuerda_interna", ""),
            "Cuerda externa": p.get("cuerda_externa", ""),
            "Comentario supervisor": p.get("comentario_supervisor", "")
        })

    df = pd.DataFrame(data)
    output = BytesIO()
    with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
        df.to_excel(writer, index=False, sheet_name="PendientesRemate")

        # (Opcional) Formato de encabezado bonito
        workbook = writer.book
        worksheet = writer.sheets["PendientesRemate"]
        header_format = workbook.add_format({
            "bold": True,
            "text_wrap": True,
            "valign": "middle",
            "fg_color": "#222222",
            "font_color": "white",
            "border": 1
        })
        for col_num, value in enumerate(df.columns.values):
            worksheet.write(0, col_num, value, header_format)

    output.seek(0)

    return send_file(
        output,
        as_attachment=True,
        download_name="informe_piezas_pendientes_remate.xlsx",
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )




# ============================================================
#         INFORME PRODUCCIÓN POR OPERADOR + EXPORTACIÓN
# ============================================================

@app.route('/admin/informes/operadores', methods=['GET', 'POST'])
@login_required('administrador')
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

    # Sin filtros de fecha: traer todos

    produccion = list(db.produccion.find(filtro))

    resumen = {}
    for p in produccion:
        key = (p.get("usuario", "—"), p.get("modo", "—"), p.get("marco", "—"), p.get("tramo", "—"))
        resumen[key] = resumen.get(key, 0) + 1

    datos_tabla = [
        {"usuario": u, "modo": m, "marco": ma, "tramo": t, "cantidad": c}
        for (u, m, ma, t), c in resumen.items()
    ]

    datos_tabla = sorted(datos_tabla, key=lambda x: x["usuario"])

    return render_template(
        "informe_operadores.html",
        operadores=operadores,
        operador_sel=operador_sel,
        fecha_inicio=fecha_inicio,
        fecha_fin=fecha_fin,
        datos_tabla=datos_tabla
    )


@app.route('/admin/informes/operadores/export', methods=['POST'])
@login_required('administrador')
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

    produccion = list(db.produccion.find(filtro))

    resumen = {}
    for p in produccion:
        key = (p.get("usuario", "—"), p.get("modo", "—"), p.get("marco", "—"), p.get("tramo", "—"))
        resumen[key] = resumen.get(key, 0) + 1

    data = []
    for (usuario, modo, marco, tramo), cantidad in resumen.items():
        data.append({
            "Operador": usuario,
            "Tipo": modo,
            "Marco": marco,
            "Tramo": tramo,
            "Cantidad": cantidad
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
        download_name="informe_produccion_operadores.xlsx",
        as_attachment=True,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )


# ============================================================
#                 OPERADOR — REGISTRO DE PRODUCCIÓN
# ============================================================

@app.route('/operador')
@login_required('operador')
def operador_home():
    user_id = session.get("user_id")
    nombre = session.get("nombre")

    boxes = list(db.boxes.find().sort("codigo", 1))

    today = now_cl().date()
    start_cl = datetime.combine(today, datetime.min.time()).replace(tzinfo=CL)
    end_cl = datetime.combine(today, datetime.max.time()).replace(tzinfo=CL)
    start = start_cl.astimezone(timezone.utc)
    end = end_cl.astimezone(timezone.utc)

    piezas_hoy = list(db.produccion.find({
        "user_id": user_id,
        "fecha": {"$gte": start, "$lte": end}
    }).sort("fecha", -1))

    jornada = db.jornadas.find_one({
        "user_id": user_id,
        "fecha": {"$gte": start, "$lte": end}
    })

    for p in piezas_hoy:
        p["fecha"] = to_cl(p.get("fecha"))

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
        piezas_hoy=piezas_hoy,
        jornada=jornada
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
    codigo_pieza = request.form["codigo_pieza"].strip()

    # Cuerdas ingresadas SOLO si es armador
    cuerda_interna_raw = request.form.get("cuerda_interna")
    cuerda_externa_raw = request.form.get("cuerda_externa")

    # ---------------------- VALIDACIÓN DE CÓDIGO ----------------------
    if not codigo_pieza:
        flash("Debes ingresar un código de pieza", "warning")
        return redirect(url_for("operador_home"))

    try:
        pieza_data = db.piezas.find_one({"codigo": int(codigo_pieza)})
    except:
        pieza_data = None

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

        "precio_armado": pieza_data.get("precio_armado", 0),
        "precio_remate": pieza_data.get("precio_remate", 0),

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
@login_required('administrador')
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

    resumen = []
    total_general = 0

    for p in produccion:
        codigo = p.get("codigo_pieza")
        modo = p.get("modo")

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
        precio_armado = float(pieza_info.get("precio_armado", 0))
        precio_remate = float(pieza_info.get("precio_remate", 0))

        # ------------------------
        # Cálculo final
        # ------------------------
        if modo == "armador":
            valor = peso * precio_armado
        elif modo == "rematador":
            valor = peso * precio_remate
        else:
            valor = 0

        total_general += valor

        resumen.append({
            "fecha": to_cl(p.get("fecha")),
            "codigo": codigo,
            "operador": p.get("usuario"),
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
@login_required('administrador')
def exportar_valor_operador_excel():

    operador_sel = request.form.get("operador")
    fecha_inicio = request.form.get("fecha_inicio")
    fecha_fin = request.form.get("fecha_fin")

    filtro = {}

    if operador_sel and operador_sel != "todos":
        filtro["usuario"] = operador_sel

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

    data = []

    for p in produccion:
        codigo = p.get("codigo_pieza")
        modo = p.get("modo")

        if not codigo:
            continue

        try:
            codigo_int = int(codigo)
        except:
            continue

        pieza_info = db.piezas.find_one({"codigo": codigo_int})
        if not pieza_info:
            continue

        peso = float(pieza_info.get("kilo_pieza", 0))
        precio_armado = float(pieza_info.get("precio_armado", 0))
        precio_remate = float(pieza_info.get("precio_remate", 0))

        if modo == "armador":
            valor = peso * precio_armado
        elif modo == "rematador":
            valor = peso * precio_remate
        else:
            valor = 0

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


# ============================================================
#    INFORME – PIEZAS SIN PRODUCCIÓN (NO ARMADAS/NO REMATADAS)
# ============================================================

@app.route('/admin/informes/piezas/sin-produccion', methods=['GET', 'POST'])
@login_required(["administrador", "supervisor"])
def informe_piezas_sin_produccion():

    empresa = request.form.get("empresa")
    marco = request.form.get("marco")
    tramo = request.form.get("tramo")

    # --- Todas las piezas creadas ---
    todas_piezas = list(db.piezas.find())

    # --- Obtener códigos con registros de producción (armador o rematador) ---
    codigos_producidos = set(
        db.produccion.distinct("codigo_pieza")
    )

    # --- Filtrar solo las piezas sin producción ---
    piezas_sin_produccion = []
    for p in todas_piezas:
        if str(p["codigo"]) not in codigos_producidos:

            # Aplicar filtros opcionales
            if empresa and empresa != "todos" and p.get("empresa") != empresa:
                continue
            if marco and marco != "todos" and p.get("marco") != marco:
                continue
            if tramo and tramo != "todos" and p.get("tramo") != tramo:
                continue

            piezas_sin_produccion.append(p)

    # --- Listas únicas para los filtros ---
    empresas = sorted({p.get("empresa") for p in todas_piezas})
    marcos = sorted({p.get("marco") for p in todas_piezas})
    tramos = sorted({p.get("tramo") for p in todas_piezas})

    return render_template(
        "informe_piezas_sin_produccion.html",
        piezas=piezas_sin_produccion,
        empresas=empresas,
        marcos=marcos,
        tramos=tramos,
        empresa_sel=empresa,
        marco_sel=marco,
        tramo_sel=tramo
    )


# ============================================================
#      EXPORTAR A EXCEL — PIEZAS SIN PRODUCCIÓN
# ============================================================

@app.route('/admin/informes/piezas/sin-produccion/export', methods=['POST'])
@login_required(["administrador", "supervisor"])
def exportar_piezas_sin_produccion_excel():

    empresa = request.form.get("empresa")
    marco = request.form.get("marco")
    tramo = request.form.get("tramo")

    # Todas las piezas creadas
    todas_piezas = list(db.piezas.find())

    # Códigos con producción registrada
    codigos_producidos = set(
        db.produccion.distinct("codigo_pieza")
    )

    piezas_sin_produccion = []
    for p in todas_piezas:
        if str(p["codigo"]) not in codigos_producidos:

            if empresa and empresa != "todos" and p.get("empresa") != empresa:
                continue
            if marco and marco != "todos" and p.get("marco") != marco:
                continue
            if tramo and tramo != "todos" and p.get("tramo") != tramo:
                continue

            piezas_sin_produccion.append(p)

    if not piezas_sin_produccion:
        flash("No hay datos para exportar con estos filtros.", "warning")
        return redirect(url_for('informe_piezas_sin_produccion'))

    # Preparar data para Excel
    data = []
    for p in piezas_sin_produccion:
        data.append({
            "Código": p.get("codigo", ""),
            "Empresa": p.get("empresa", ""),
            "Marco": p.get("marco", ""),
            "Tramo": p.get("tramo", "")
        })

    df = pd.DataFrame(data)
    output = BytesIO()

    with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
        df.to_excel(writer, index=False, sheet_name="SinProduccion")

    output.seek(0)

    return send_file(
        output,
        as_attachment=True,
        download_name="informe_piezas_sin_produccion.xlsx",
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )



# ============================================================
#    INFORME – ESTADO DE PIEZAS (SIN/ARMADO/REMATADO)
# ============================================================

@app.route('/admin/informes/piezas/estado', methods=['GET', 'POST'])
@login_required(["administrador", "supervisor"])
def informe_estado_piezas():
    empresa = request.form.get("empresa")
    marco = request.form.get("marco")
    tramo = request.form.get("tramo")
    codigo = request.form.get("codigo_pieza")

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

        listado.append({
            "codigo": p.get("codigo"),
            "cliente": p.get("empresa"),
            "marco": p.get("marco"),
            "tramo": p.get("tramo"),
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
        codigo_sel=codigo
    )

# ============================================================
#                       RUN APP
# ============================================================

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
