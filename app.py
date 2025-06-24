# -*- coding: utf-8 -*-

from flask import Flask, request, render_template, g, redirect, url_for, make_response, flash
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta, timezone
from functools import wraps
import sqlite3
import os

# --- CONFIGURACIÓN DE LA APLICACIÓN ---
app = Flask(__name__, static_folder="static")
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'tu-clave-secreta-muy-dificil-de-adivinar')
DATABASE = "db.db"

# --- GESTIÓN DE LA BASE DE DATOS ---

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute("""CREATE TABLE IF NOT EXISTS usuarios(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario TEXT NOT NULL UNIQUE,
            contrasena_hash TEXT NOT NULL,
            rol TEXT NOT NULL CHECK(rol IN ('profesor', 'estudiante'))
        )""")
        cursor.execute("""CREATE TABLE IF NOT EXISTS tareas(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            titulo TEXT NOT NULL,
            descripcion TEXT NOT NULL,
            fecha_limite TEXT NOT NULL,
            id_profesor INTEGER,
            FOREIGN KEY (id_profesor) REFERENCES usuarios(id)
        )""")
        # *** NUEVO: Creación de la tabla de respuestas ***
        cursor.execute("""CREATE TABLE IF NOT EXISTS respuestas(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            respuesta TEXT NOT NULL,
            estado TEXT NOT NULL CHECK(estado IN ('pendiente', 'aprobado', 'suspendido')) DEFAULT 'pendiente',
            id_estudiante INTEGER NOT NULL,
            id_tarea INTEGER NOT NULL,
            FOREIGN KEY (id_estudiante) REFERENCES usuarios(id),
            FOREIGN KEY (id_tarea) REFERENCES tareas(id),
            UNIQUE(id_estudiante, id_tarea)
        )""")
        db.commit()
        print("Base de datos inicializada.")

init_db()

# --- DECORADORES DE AUTENTICACIÓN Y AUTORIZACIÓN ---

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('token')
        if not token:
            flash("Se requiere iniciar sesión para acceder a esta página.")
            return redirect(url_for('index'))
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            db = get_db()
            current_user = db.execute('SELECT * FROM usuarios WHERE id = ?', (data['id'],)).fetchone()
            if not current_user:
                 return redirect(url_for('index'))
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            flash("Tu sesión ha expirado. Por favor, inicia sesión de nuevo.")
            return redirect(url_for('index'))
        return f(current_user, *args, **kwargs)
    return decorated

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            current_user = args[0]
            if current_user['rol'] != role:
                flash(f"Acceso denegado. No tienes permisos de '{role}'.")
                if current_user['rol'] == 'profesor':
                    return redirect(url_for('profesor_dashboard'))
                else:
                    return redirect(url_for('estudiante_dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# --- RUTAS DE LA APLICACIÓN ---

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/register-page", methods=["GET"])
def register_page():
    return render_template("registro.html")

@app.route("/register", methods=["POST"])
def register_user():
    usuario = request.form.get("usuario")
    contrasena = request.form.get("contrasena")
    rol = request.form.get("rol")
    if not usuario or not contrasena or not rol:
        flash("Todos los campos son obligatorios.")
        return redirect(url_for('register_page'))
    contrasena_hash = generate_password_hash(contrasena, method='pbkdf2:sha256')
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            "INSERT INTO usuarios (usuario, contrasena_hash, rol) VALUES (?, ?, ?)",
            (usuario, contrasena_hash, rol)
        )
        db.commit()
        flash("Usuario registrado con éxito. Ahora puedes iniciar sesión.")
        return redirect(url_for('index'))
    except sqlite3.IntegrityError:
        flash("El nombre de usuario ya existe.")
        return redirect(url_for('register_page'))


@app.route("/login", methods=["POST"])
def login():
    usuario = request.form.get("usuario")
    contrasena = request.form.get("contrasena")
    if not usuario or not contrasena:
        flash("Usuario y contraseña son requeridos.")
        return redirect(url_for('index'))
    db = get_db()
    user_row = db.execute('SELECT * FROM usuarios WHERE usuario = ?', (usuario,)).fetchone()
    if not user_row or not check_password_hash(user_row['contrasena_hash'], contrasena):
        flash("Usuario o contraseña incorrectos.")
        return redirect(url_for('index'))
    payload = {
        'id': user_row['id'],
        'usuario': user_row['usuario'],
        'rol': user_row['rol'],
        'exp': datetime.now(timezone.utc) + timedelta(minutes=60)
    }
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm="HS256")
    if user_row['rol'] == 'profesor':
        response = make_response(redirect(url_for('profesor_dashboard')))
    else:
        response = make_response(redirect(url_for('estudiante_dashboard')))
    response.set_cookie('token', token, httponly=True, samesite='Lax')
    return response

@app.route('/logout')
def logout():
    flash("Has cerrado la sesión.")
    response = make_response(redirect(url_for('index')))
    response.set_cookie('token', '', expires=0)
    return response

# --- RUTAS PROTEGIDAS: PROFESOR ---

@app.route('/profesor-dashboard')
@token_required
@role_required('profesor')
def profesor_dashboard(current_user):
    return render_template("profesor.html", usuario=current_user['usuario'])

@app.route("/publicar-tarea", methods=["POST"])
@token_required
@role_required('profesor')
def publicar_tarea(current_user):
    titulo = request.form.get("titulo")
    descripcion = request.form.get("descripcion")
    fecha_limite = request.form.get("fecha_limite")
    if not titulo or not descripcion or not fecha_limite:
        flash("Todos los campos de la tarea son requeridos.")
        return redirect(url_for('profesor_dashboard'))
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "INSERT INTO tareas (titulo, descripcion, fecha_limite, id_profesor) VALUES (?, ?, ?, ?)",
        (titulo, descripcion, fecha_limite, current_user['id'])
    )
    db.commit()
    flash("Tarea publicada con éxito.")
    return redirect(url_for('profesor_dashboard'))

# *** NUEVO: Ruta para que el profesor vea y califique las respuestas ***
@app.route('/respuestas')
@token_required
@role_required('profesor')
def ver_respuestas(current_user):
    db = get_db()
    respuestas = db.execute("""
        SELECT r.id, r.respuesta, r.estado, t.descripcion as tarea_descripcion, u.usuario as estudiante_usuario
        FROM respuestas r
        JOIN usuarios u ON r.id_estudiante = u.id
        JOIN tareas t ON r.id_tarea = t.id
    """).fetchall()
    return render_template('respuestas.html', respuestas=respuestas, usuario=current_user['usuario'])

# *** NUEVO: Ruta para que el profesor califique una respuesta ***
@app.route('/calificar-respuesta/<int:id_respuesta>/<string:estado>', methods=['GET'])
@token_required
@role_required('profesor')
def calificar_respuesta(current_user, id_respuesta, estado):
    nuevo_estado = estado
    if nuevo_estado not in ['aprobado', 'suspendido']:
        flash("Estado de calificación no válido.")
        return redirect(url_for('ver_respuestas'))
    db = get_db()
    db.execute("UPDATE respuestas SET estado = ? WHERE id = ?", (nuevo_estado, id_respuesta))
    db.commit()
    flash("Respuesta calificada con éxito.")
    return redirect(url_for('ver_respuestas'))


# --- RUTAS PROTEGIDAS: ESTUDIANTE ---

@app.route('/estudiante-dashboard')
@token_required
@role_required('estudiante')
def estudiante_dashboard(current_user):
    # *** CAMBIO: La consulta ahora filtra por fecha límite y obtiene el estado de la respuesta ***
    db = get_db()
    # strftime('%Y-%m-%d', 'now') obtiene la fecha actual en el formato YYYY-MM-DD
    tareas_rows = db.execute("""
        SELECT 
            t.id, t.titulo, t.descripcion, t.fecha_limite, u.usuario as profesor,
            r.estado as estado_respuesta
        FROM tareas t
        JOIN usuarios u ON t.id_profesor = u.id
        LEFT JOIN respuestas r ON t.id = r.id_tarea AND r.id_estudiante = ?
        WHERE t.fecha_limite >= strftime('%Y-%m-%d', 'now') 
    """, (current_user['id'],)).fetchall()
    return render_template("tareas.html", usuario=current_user['usuario'], tareas=tareas_rows)

# *** NUEVO: Ruta para que el estudiante envíe una respuesta ***
@app.route('/enviar-respuesta/<int:id_tarea>', methods=['POST'])
@token_required
@role_required('estudiante')
def responder_tarea(current_user, id_tarea):
    respuesta_texto = request.form.get('respuesta')
    if not respuesta_texto:
        flash("La respuesta no puede estar vacía.")
        return redirect(url_for('estudiante_dashboard'))
    
    db = get_db()
    try:
        db.execute(
            "INSERT INTO respuestas (respuesta, id_estudiante, id_tarea) VALUES (?, ?, ?)",
            (respuesta_texto, current_user['id'], id_tarea)
        )
        db.commit()
        flash("Respuesta enviada con éxito.")
    except sqlite3.IntegrityError:
        # Esto ocurre si el estudiante intenta responder dos veces a la misma tarea
        flash("Ya has enviado una respuesta para esta tarea.")
    
    return redirect(url_for('estudiante_dashboard'))


# --- Punto de entrada de la aplicación ---
if __name__ == "__main__":
    app.run(debug=True, port=5000)