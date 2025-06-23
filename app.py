from flask import Flask, render_template, request, redirect
from sqlite3 import connect

app = Flask(__name__, static_folder="static")

def init_db():
    with connect("db.db") as conn:
        cursor = conn.cursor()
        cursor.execute("""CREATE TABLE IF NOT EXISTS usuarios(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario TEXT NOT NULL UNIQUE,
            contrasena TEXT NOT NULL,
            rol TEXT NOT NULL
        )""")
        cursor.execute("""CREATE TABLE IF NOT EXISTS tareas(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            titulo TEXT NOT NULL,
            descripcion TEXT NOT NULL,
            fecha_limite TEXT NOT NULL,
            id_usuario INTEGER,
            FOREIGN KEY (id_usuario) REFERENCES usuarios(id)
        )""")
        conn.commit()

init_db()

def connect_db():
    return connect("db.db")

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/register-page", methods=["GET"])
def register():
    return render_template("registro.html")

@app.route("/register", methods=["POST"])
def register_user():
    usuario = request.form.get("usuario")
    contrasena = request.form.get("contrasena")
    rol = request.form.get("rol")

    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO usuarios (usuario, contrasena, rol)
        VALUES (?, ?, ?)
    """, (usuario, contrasena, rol))
    conn.commit()
    conn.close()
    return redirect("/")

@app.route("/login", methods=["POST"])
def login():
    usuario = request.form.get("usuario")
    contrasena = request.form.get("contrasena")
    global id_usuario

    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM usuarios WHERE usuario = ? AND contrasena = ?", 
        (usuario, contrasena))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        id_usuario = user[0]
        if user[3]=="profesor":
            return render_template("profesor.html", usuario=usuario)
        else:
            return render_template("tareas.html", usuario=usuario)
    else:
        return {"Error": "Usuario no encontrado"}, 404
    
@app.route("/publicar-tarea", methods=["POST"])
def tarea():
    titulo = request.form.get("titulo")
    descripcion = request.form.get("descripcion")
    fecha = request.form.get("fecha_limite")

    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO tareas (titulo, descripcion, fecha_limite, id_usuario)
        VALUES (?, ?, ?, ?)
    """, (titulo, descripcion, fecha, id_usuario))
    conn.commit()
    conn.close()
    return redirect("/respuestas")

@app.route("/respuestas", methods=["GET"])
def respuestas():
    return render_template("respuestas.html")

if __name__=="__main__":
    app.run(debug=True)
