import os
from datetime import datetime, date, timedelta
from bson import ObjectId
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['MONGO_URI'] = os.getenv('MONGO_URI', 'mongodb://localhost:27017/produccion_db')
app.secret_key = os.getenv('SECRET_KEY', 'dev_secret_key')

mongo = PyMongo(app)
db = mongo.db

# ---------------------- Helpers ----------------------
def login_required(role=None):
    def wrapper(fn):
        def _wrapped(*args, **kwargs):
            if 'user_id' not in session:
                flash('Inicia sesión para continuar', 'warning')
                return redirect(url_for('login'))
            if role and session.get('role') != role:
                real_role = session.get('role')
                if real_role == 'administrador':
                    return redirect(url_for('admin_dashboard'))
                elif real_role == 'supervisor':
                    return redirect(url_for('supervisor_home'))
                else:
                    return redirect(url_for('operador_home'))
            return fn(*args, **kwargs)
        _wrapped.__name__ = fn.__name__
        return _wrapped
    return wrapper


def seed_admin():
    if not db.usuarios.find_one({'usuario': 'admin'}):
        db.usuarios.insert_one({
            'usuario': 'admin',
            'nombre': 'Administrador',
            'tipo': 'administrador',
            'password': generate_password_hash('admin123')
        })
        print('> Usuario admin creado: admin / admin123')


@app.before_request
def ensure_seed():
    if request.endpoint not in ('static',):
        seed_admin()

# ---------------------- Auth ----------------------
@app.route('/')
def index():
    if 'user_id' in session:
        role = session.get('role')
        if role == 'administrador':
            return redirect(url_for('admin_dashboard'))
        elif role == 'supervisor':
            return redirect(url_for('supervisor_home'))
        else:
            return redirect(url_for('operador_home'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        usuario = request.form.get('usuario', '').strip()
        password = request.form.get('password', '')
        user = db.usuarios.find_one({'usuario': usuario})
        if user and check_password_hash(user['password'], password):
            session['user_id'] = str(user['_id'])
            session['username'] = user.get('usuario')
            session['nombre'] = user.get('nombre', user.get('usuario'))
            session['role'] = user.get('tipo')
            flash(f"Bienvenido, {session['nombre']}", 'success')
            return redirect(url_for('index'))
        flash('Usuario o contraseña inválidos', 'danger')
    return render_template('login.html')


@app.route('/logout')
@login_required()
def logout():
    session.clear()
    flash('Sesión cerrada', 'info')
    return redirect(url_for('login'))

# ---- CRUD Usuarios (actualizado) ----
@app.route('/admin/usuarios')
@login_required('administrador')
def usuarios_list():
    usuarios = list(db.usuarios.find())
    return render_template('crud_usuarios.html', usuarios=usuarios)

# Crear usuario (formulario)
@app.route('/admin/usuarios/nuevo')
@login_required('administrador')
def usuarios_nuevo_form():
    return render_template('usuario_form.html', modo='nuevo')

# Guardar usuario nuevo
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
    db.usuarios.insert_one({'usuario': usuario, 'nombre': nombre, 'tipo': tipo, 'password': password})
    flash('✅ Usuario creado con éxito', 'success')
    return redirect(url_for('usuarios_list'))

# Editar usuario (formulario)
@app.route('/admin/usuarios/<id>/editar')
@login_required('administrador')
def usuarios_editar_form(id):
    usuario = db.usuarios.find_one({'_id': ObjectId(id)})
    if not usuario:
        flash('Usuario no encontrado', 'warning')
        return redirect(url_for('usuarios_list'))
    return render_template('usuario_form.html', modo='editar', usuario=usuario)

# Guardar edición
@app.route('/admin/usuarios/<id>/editar', methods=['POST'])
@login_required('administrador')
def usuarios_editar_post(id):
    nombre = request.form['nombre'].strip()
    tipo = request.form['tipo']
    update = {'nombre': nombre, 'tipo': tipo}
    pwd = request.form.get('password', '').strip()
    if pwd:
        update['password'] = generate_password_hash(pwd)
    db.usuarios.update_one({'_id': ObjectId(id)}, {'$set': update})
    flash('✅ Usuario actualizado con éxito', 'success')
    return redirect(url_for('usuarios_list'))

# Eliminar
@app.route('/admin/usuarios/<id>/delete', methods=['POST'])
@login_required('administrador')
def usuarios_delete(id):
    if str(session.get('user_id')) == id:
        flash('No puedes eliminar tu propio usuario activo', 'warning')
        return redirect(url_for('usuarios_list'))
    db.usuarios.delete_one({'_id': ObjectId(id)})
    flash('Usuario eliminado', 'info')
    return redirect(url_for('usuarios_list'))


# ---- CRUD Boxes (actualizado) ----
@app.route('/admin/boxes')
@login_required('administrador')
def boxes_list():
    boxes = list(db.boxes.find())
    return render_template('crud_boxes.html', boxes=boxes)

# Crear box (formulario)
@app.route('/admin/boxes/nuevo')
@login_required('administrador')
def boxes_nuevo_form():
    return render_template('box_form.html', modo='nuevo')

# Guardar nuevo box
@app.route('/admin/boxes/nuevo', methods=['POST'])
@login_required('administrador')
def boxes_nuevo_post():
    codigo = request.form['codigo'].strip()
    descripcion = request.form['descripcion'].strip()

    if db.boxes.find_one({'codigo': codigo}):
        flash('El código de box ya existe', 'warning')
        return redirect(url_for('boxes_list'))

    db.boxes.insert_one({'codigo': codigo, 'descripcion': descripcion, 'created_at': datetime.utcnow()})
    flash('✅ Box creado con éxito', 'success')
    return redirect(url_for('boxes_list'))

# Editar box (formulario)
@app.route('/admin/boxes/<id>/editar')
@login_required('administrador')
def boxes_editar_form(id):
    box = db.boxes.find_one({'_id': ObjectId(id)})
    if not box:
        flash('Box no encontrado', 'warning')
        return redirect(url_for('boxes_list'))
    return render_template('box_form.html', modo='editar', box=box)

# Guardar edición
@app.route('/admin/boxes/<id>/editar', methods=['POST'])
@login_required('administrador')
def boxes_editar_post(id):
    codigo = request.form['codigo'].strip()
    descripcion = request.form['descripcion'].strip()
    db.boxes.update_one({'_id': ObjectId(id)}, {'$set': {'codigo': codigo, 'descripcion': descripcion}})
    flash('✅ Box actualizado con éxito', 'success')
    return redirect(url_for('boxes_list'))

# Eliminar box
@app.route('/admin/boxes/<id>/delete', methods=['POST'])
@login_required('administrador')
def boxes_delete(id):
    db.boxes.delete_one({'_id': ObjectId(id)})
    flash('Box eliminado', 'info')
    return redirect(url_for('boxes_list'))


# ---- CRUD Piezas (actualizado) ----
@app.route('/admin/piezas')
@login_required('administrador')
def piezas_list():
    piezas = list(db.piezas.find().sort('created_at', -1))
    return render_template('crud_piezas.html', piezas=piezas)

# Crear pieza (formulario)
@app.route('/admin/piezas/nuevo')
@login_required('administrador')
def piezas_nuevo_form():
    return render_template('pieza_form.html', modo='nuevo')

# Guardar nueva pieza
@app.route('/admin/piezas/nuevo', methods=['POST'])
@login_required('administrador')
def piezas_nuevo_post():
    nombre = request.form['nombre'].strip()
    marco = request.form['marco'].strip()
    tramo = request.form['tramo'].strip()
    db.piezas.insert_one({
        'nombre': nombre,
        'marco': marco,
        'tramo': tramo,
        'created_at': datetime.utcnow(),
        'calidad_status': 'pendiente'
    })
    flash('✅ Pieza creada con éxito', 'success')
    return redirect(url_for('piezas_list'))

# Editar pieza (formulario)
@app.route('/admin/piezas/<id>/editar')
@login_required('administrador')
def piezas_editar_form(id):
    pieza = db.piezas.find_one({'_id': ObjectId(id)})
    if not pieza:
        flash('Pieza no encontrada', 'warning')
        return redirect(url_for('piezas_list'))
    return render_template('pieza_form.html', modo='editar', pieza=pieza)

# Guardar edición
@app.route('/admin/piezas/<id>/editar', methods=['POST'])
@login_required('administrador')
def piezas_editar_post(id):
    nombre = request.form['nombre'].strip()
    marco = request.form['marco'].strip()
    tramo = request.form['tramo'].strip()
    db.piezas.update_one({'_id': ObjectId(id)}, {'$set': {
        'nombre': nombre, 'marco': marco, 'tramo': tramo
    }})
    flash('✅ Pieza actualizada con éxito', 'success')
    return redirect(url_for('piezas_list'))

# Eliminar pieza
@app.route('/admin/piezas/<id>/delete', methods=['POST'])
@login_required('administrador')
def piezas_delete(id):
    db.piezas.delete_one({'_id': ObjectId(id)})
    flash('Pieza eliminada', 'info')
    return redirect(url_for('piezas_list'))

# ---------------------- ADMIN PANEL E INFORMES ----------------------
@app.route('/admin')
@login_required('administrador')
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

# Página principal de informes
@app.route('/admin/informes')
@login_required('administrador')
def admin_informes():
    return render_template('admin_informes.html')

# ---------------------- INFORME DE HORARIOS (con filtro y exportación) ----------------------
from io import BytesIO
import pandas as pd
from flask import send_file

@app.route('/admin/informes/horarios', methods=['GET', 'POST'])
@login_required('administrador')
def informe_horarios():
    # Obtener todos los usuarios tipo operador
    operadores = list(db.usuarios.find({'tipo': 'operador'}))
    operador_sel = None
    filtro = {}

    if request.method == 'POST':
        operador_sel = request.form.get('operador')
        if operador_sel and operador_sel != 'todos':
            filtro['user_id'] = operador_sel

    # Obtener jornadas filtradas
    jornadas = list(db.jornadas.find(filtro).sort('fecha', -1))

    # Enlazar nombres de usuarios
    usuarios_map = {str(u['_id']): u['nombre'] for u in operadores}
    for j in jornadas:
        j['nombre'] = usuarios_map.get(j['user_id'], 'Desconocido')

    return render_template(
        'informe_horarios.html',
        jornadas=jornadas,
        operadores=operadores,
        operador_sel=operador_sel
    )


# ---------------------- Exportar informe de horarios a Excel ----------------------
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
        data.append({
            'Operador': usuarios_map.get(j['user_id'], 'Desconocido'),
            'Fecha': j['fecha'].strftime('%d-%m-%Y'),
            'Ingreso': j.get('ingreso', '').strftime('%H:%M:%S') if j.get('ingreso') else '',
            'Salida': j.get('salida', '').strftime('%H:%M:%S') if j.get('salida') else ''
        })

    if not data:
        flash('No hay registros para exportar.', 'warning')
        return redirect(url_for('informe_horarios'))

    df = pd.DataFrame(data)
    output = BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name='Horarios')
    output.seek(0)

    return send_file(
        output,
        as_attachment=True,
        download_name='informe_horarios.xlsx',
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )


# ---------------------- INFORME PRODUCCIÓN DE PIEZAS ----------------------
@app.route('/admin/informes/piezas', methods=['GET', 'POST'])
@login_required('administrador')
def informe_piezas():
    fecha_inicio = None
    fecha_fin = None
    estado_sel = None
    filtro = {}

    if request.method == 'POST':
        fecha_inicio = request.form.get('fecha_inicio')
        fecha_fin = request.form.get('fecha_fin')
        estado_sel = request.form.get('estado')

        # Filtro por rango de fechas
        if fecha_inicio and fecha_fin:
            try:
                inicio = datetime.strptime(fecha_inicio, '%Y-%m-%d')
                fin = datetime.strptime(fecha_fin, '%Y-%m-%d')
                fin = datetime.combine(fin, datetime.max.time())
                filtro['fecha'] = {'$gte': inicio, '$lte': fin}
            except ValueError:
                flash('Fechas inválidas. Usa formato AAAA-MM-DD.', 'warning')

        # Filtro por estado
        if estado_sel and estado_sel != 'todos':
            filtro['calidad_status'] = estado_sel

    # Si no hay filtros, mostrar últimos 7 días
    if 'fecha' not in filtro:
        hoy = datetime.utcnow()
        hace_7_dias = hoy - timedelta(days=7)
        filtro['fecha'] = {'$gte': hace_7_dias, '$lte': hoy}

    # Consulta principal
    piezas = list(db.produccion.find(filtro).sort('fecha', -1))

    # Inicializar estado_counts (evita error de Jinja2)
    estado_counts = {'pendiente': 0, 'aprobado': 0, 'rechazado': 0}

    # Contar solo si hay piezas
    for p in piezas:
        estado = p.get('calidad_status', 'pendiente').lower()
        if estado in estado_counts:
            estado_counts[estado] += 1

    return render_template(
        'informe_piezas.html',
        piezas=piezas,
        fecha_inicio=fecha_inicio,
        fecha_fin=fecha_fin,
        estado_sel=estado_sel,
        estado_counts=estado_counts
    )



# ---------------------- EXPORTAR PRODUCCIÓN DE PIEZAS A EXCEL ----------------------
@app.route('/admin/informes/piezas/export', methods=['POST'])
@login_required('administrador')
def exportar_piezas_excel():
    fecha_inicio = request.form.get('fecha_inicio')
    fecha_fin = request.form.get('fecha_fin')
    estado_sel = request.form.get('estado')
    filtro = {}

    # --- Filtro por fechas ---
    if fecha_inicio and fecha_fin:
        try:
            inicio = datetime.strptime(fecha_inicio, '%Y-%m-%d')
            fin = datetime.strptime(fecha_fin, '%Y-%m-%d')
            fin = datetime.combine(fin, datetime.max.time())
            filtro['fecha'] = {'$gte': inicio, '$lte': fin}
        except ValueError:
            flash('Formato de fecha inválido. Usa AAAA-MM-DD.', 'warning')
            return redirect(url_for('informe_piezas'))

    # --- Filtro por estado ---
    if estado_sel and estado_sel != 'todos':
        filtro['calidad_status'] = estado_sel

    # --- Consultar piezas ---
    piezas = list(db.produccion.find(filtro).sort('fecha', -1))

    # --- Preparar datos para Excel ---
    data = []
    for p in piezas:
        fecha = p.get('fecha')
        if isinstance(fecha, datetime):
            fecha_str = fecha.strftime('%d-%m-%Y %H:%M')
        else:
            fecha_str = '—'

        data.append({
            'Fecha': fecha_str,
            'Operador': p.get('usuario', '—'),
            'Código': p.get('codigo_pieza', '—'),
            'Modo': p.get('modo', '—'),
            'Box': p.get('box', '—'),
            'Marco': p.get('marco', '—'),
            'Tramo': p.get('tramo', '—'),
            'Estado': p.get('calidad_status', 'pendiente').capitalize()
        })

    # --- Validar contenido ---
    if not data:
        flash('No hay datos para exportar.', 'warning')
        return redirect(url_for('informe_piezas'))

    # --- Crear archivo Excel ---
    df = pd.DataFrame(data)
    output = BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name='Producción de Piezas')

        # Opcional: estilo del encabezado
        workbook = writer.book
        worksheet = writer.sheets['Producción de Piezas']
        header_format = workbook.add_format({
            'bold': True,
            'text_wrap': True,
            'valign': 'middle',
            'fg_color': '#222222',
            'font_color': 'white',
            'border': 1
        })
        for col_num, value in enumerate(df.columns.values):
            worksheet.write(0, col_num, value, header_format)

    output.seek(0)

    # --- Enviar el archivo al usuario ---
    return send_file(
        output,
        as_attachment=True,
        download_name='informe_produccion_piezas.xlsx',
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )



# ---------------------- INFORME PRODUCCIÓN POR OPERADOR ----------------------
@app.route('/admin/informes/operadores', methods=['GET', 'POST'])
@login_required('administrador')
def informe_operadores():
    # Listado de operadores para el filtro
    operadores = list(db.usuarios.find({'tipo': 'operador'}))
    operador_sel = None
    fecha_inicio = None
    fecha_fin = None
    filtro = {}

    if request.method == 'POST':
        operador_sel = request.form.get('operador')
        fecha_inicio = request.form.get('fecha_inicio')
        fecha_fin = request.form.get('fecha_fin')

        if operador_sel and operador_sel != 'todos':
            filtro['user_id'] = operador_sel

        if fecha_inicio and fecha_fin:
            try:
                inicio = datetime.strptime(fecha_inicio, '%Y-%m-%d')
                fin = datetime.strptime(fecha_fin, '%Y-%m-%d')
                # incluir todo el día de la fecha fin
                fin = datetime.combine(fin, datetime.max.time())
                filtro['fecha'] = {'$gte': inicio, '$lte': fin}
            except ValueError:
                flash('Fechas inválidas. Usa el formato correcto (AAAA-MM-DD).', 'warning')

    # Si no hay fechas, se toman las últimas 2 semanas
    if 'fecha' not in filtro:
        hoy = datetime.utcnow()
        hace_15_dias = hoy.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=14)
        filtro['fecha'] = {'$gte': hace_15_dias, '$lte': hoy}

    # Consulta de producción filtrada
    produccion = list(db.produccion.find(filtro))

    # Agrupar por operador, modo, marco y tramo
    resumen = {}
    for p in produccion:
        key = (p.get('usuario', 'Desconocido'), p.get('modo', '—'), p.get('marco', '—'), p.get('tramo', '—'))
        resumen[key] = resumen.get(key, 0) + 1

    datos_tabla = []
    for (usuario, modo, marco, tramo), cantidad in resumen.items():
        datos_tabla.append({
            'usuario': usuario,
            'modo': modo,
            'marco': marco,
            'tramo': tramo,
            'cantidad': cantidad
        })

    # Ordenar alfabéticamente por operador
    datos_tabla = sorted(datos_tabla, key=lambda x: x['usuario'])

    return render_template(
        'informe_operadores.html',
        operadores=operadores,
        operador_sel=operador_sel,
        fecha_inicio=fecha_inicio,
        fecha_fin=fecha_fin,
        datos_tabla=datos_tabla
    )


# ---------------------- EXPORTAR PRODUCCIÓN POR OPERADOR A EXCEL ----------------------
@app.route('/admin/informes/operadores/export', methods=['POST'])
@login_required('administrador')
def exportar_operadores_excel():
    operador_sel = request.form.get('operador')
    fecha_inicio = request.form.get('fecha_inicio')
    fecha_fin = request.form.get('fecha_fin')
    filtro = {}

    if operador_sel and operador_sel != 'todos':
        filtro['user_id'] = operador_sel

    if fecha_inicio and fecha_fin:
        inicio = datetime.strptime(fecha_inicio, '%Y-%m-%d')
        fin = datetime.strptime(fecha_fin, '%Y-%m-%d')
        fin = datetime.combine(fin, datetime.max.time())
        filtro['fecha'] = {'$gte': inicio, '$lte': fin}

    produccion = list(db.produccion.find(filtro))
    resumen = {}
    for p in produccion:
        key = (p.get('usuario', 'Desconocido'), p.get('modo', '—'), p.get('marco', '—'), p.get('tramo', '—'))
        resumen[key] = resumen.get(key, 0) + 1

    data = []
    for (usuario, modo, marco, tramo), cantidad in resumen.items():
        data.append({
            'Operador': usuario,
            'Tipo': modo,
            'Marco': marco,
            'Tramo': tramo,
            'Cantidad': cantidad
        })

    if not data:
        flash('No hay datos para exportar.', 'warning')
        return redirect(url_for('informe_operadores'))

    df = pd.DataFrame(data)
    output = BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name='Producción Operador')
    output.seek(0)

    return send_file(
        output,
        as_attachment=True,
        download_name='informe_produccion_operadores.xlsx',
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )




# ---------------------- Operador (Actualizado) ----------------------
@app.route('/operador')
@login_required('operador')
def operador_home():
    user_id = session.get('user_id')
    nombre = session.get('nombre')

    # Datos para selects dinámicos
    boxes = list(db.boxes.find().sort('codigo', 1))
    marcos = sorted({p['marco'] for p in db.piezas.find() if p.get('marco')})
    tramos = sorted({p['tramo'] for p in db.piezas.find() if p.get('tramo')})

    # Piezas registradas hoy
    today = date.today()
    start = datetime.combine(today, datetime.min.time())
    end = datetime.combine(today, datetime.max.time())
    piezas_hoy = list(db.produccion.find({
        'user_id': user_id,
        'fecha': {'$gte': start, '$lte': end}
    }).sort('fecha', -1))

    jornada = db.jornadas.find_one({
        'user_id': user_id,
        'fecha': {'$gte': start, '$lte': end}
    })

    return render_template(
        'operador.html',
        nombre=nombre,
        boxes=boxes,
        marcos=marcos,
        tramos=tramos,
        piezas_hoy=piezas_hoy,
        jornada=jornada
    )

@app.route('/operador/jornada/ingreso', methods=['POST'])
@login_required('operador')
def operador_ingreso():
    user_id = session.get('user_id')
    today = date.today()
    start = datetime.combine(today, datetime.min.time())
    end = datetime.combine(today, datetime.max.time())
    existe = db.jornadas.find_one({'user_id': user_id, 'fecha': {'$gte': start, '$lte': end}})
    if existe and existe.get('ingreso'):
        flash('La jornada ya fue iniciada.', 'info')
    else:
        db.jornadas.update_one(
            {'user_id': user_id, 'fecha': {'$gte': start, '$lte': end}},
            {'$set': {'user_id': user_id, 'fecha': datetime.utcnow(), 'ingreso': datetime.utcnow()}},
            upsert=True
        )
        flash('Ingreso de jornada registrado', 'success')
    return redirect(url_for('operador_home'))

@app.route('/operador/jornada/salida', methods=['POST'])
@login_required('operador')
def operador_salida():
    user_id = session.get('user_id')
    today = date.today()
    start = datetime.combine(today, datetime.min.time())
    end = datetime.combine(today, datetime.max.time())
    updated = db.jornadas.update_one(
        {'user_id': user_id, 'fecha': {'$gte': start, '$lte': end}},
        {'$set': {'salida': datetime.utcnow()}}
    )
    if updated.matched_count:
        flash('Salida de jornada registrada', 'success')
    else:
        flash('No hay jornada iniciada hoy', 'warning')
    return redirect(url_for('operador_home'))

@app.route('/operador/registrar', methods=['POST'])
@login_required('operador')
def operador_registrar():
    user_id = session.get('user_id')
    usuario = session.get('nombre')
    modo = request.form['modo']
    box = request.form['box']
    marco = request.form['marco']
    tramo = request.form['tramo']
    codigo_pieza = request.form['codigo_pieza'].strip()

    if not codigo_pieza:
        flash('Debe ingresar un código de pieza.', 'warning')
        return redirect(url_for('operador_home'))

    pieza = {
        'user_id': user_id,
        'usuario': usuario,
        'modo': modo,
        'box': box,
        'marco': marco,
        'tramo': tramo,
        'codigo_pieza': codigo_pieza,
        'fecha': datetime.utcnow(),
        'calidad_status': 'pendiente'
    }
    db.produccion.insert_one(pieza)
    flash(f'Pieza {codigo_pieza} registrada correctamente.', 'success')
    return redirect(url_for('operador_home'))

# ---------------------- Supervisor ----------------------
@app.route('/supervisor', methods=['GET', 'POST'])
@login_required('supervisor')
def supervisor_home():
    today = date.today()
    start = datetime.combine(today, datetime.min.time())
    end = datetime.combine(today, datetime.max.time())

    # --- Filtros dinámicos ---
    filtro = {'fecha': {'$gte': start, '$lte': end}}
    operador = request.form.get('operador')
    box = request.form.get('box')
    modo = request.form.get('modo')

    if operador and operador != 'todos':
        filtro['usuario'] = operador
    if box and box != 'todos':
        filtro['box'] = box
    if modo and modo != 'todos':
        filtro['modo'] = modo

    # --- Consulta filtrada ---
    piezas_hoy = list(db.produccion.find(filtro).sort('fecha', -1))

    # --- Datos para selects ---
    operadores = sorted({p['usuario'] for p in db.produccion.find({'fecha': {'$gte': start, '$lte': end}})})
    boxes = sorted({p['box'] for p in db.produccion.find({'fecha': {'$gte': start, '$lte': end}})})
    modos = ['armador', 'rematador']

    # --- Contador total ---
    total_piezas = len(piezas_hoy)

    return render_template(
        'supervisor.html',
        piezas=piezas_hoy,
        operadores=operadores,
        boxes=boxes,
        modos=modos,
        operador_sel=operador,
        box_sel=box,
        modo_sel=modo,
        total_piezas=total_piezas
    )


@app.route('/supervisor/piezas/<id>/validar', methods=['POST'])
@login_required('supervisor')
def supervisor_validar_pieza(id):
    decision = request.form.get('decision')  # aprobado / rechazado
    db.produccion.update_one({'_id': ObjectId(id)}, {'$set': {'calidad_status': decision}})
    flash(f'Pieza marcada como {decision}', 'success')
    return redirect(url_for('supervisor_home'))


# ---------------------- Run ----------------------
if __name__ == '__main__':
    app.run(debug=True)
