import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta
from functools import wraps

from flask import (Flask, render_template, request, redirect, url_for,
                   session, flash, abort, g, send_from_directory)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "pydesk.db")
KEY_PATH = os.path.join(BASE_DIR, "secret.key")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

PRIORIDADES = ("Baja", "Media", "Alta")
ESTADOS = ("Pendiente", "En proceso", "Resuelto")
MAX_INTENTOS = 5      # intentos fallidos permitidos
VENTANA_MIN = 10      # minutos de bloqueo

# Adjuntos
MAX_ARCHIVO = 5 * 1024 * 1024   # 5 MB por archivo
MAX_ADJUNTOS = 5                # archivos por ticket
EXTENSIONES = {
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "gif": "image/gif",
    "pdf": "application/pdf",
    "txt": "text/plain",
    "log": "text/plain",
}
IMAGENES = ("image/png", "image/jpeg", "image/gif")

# SLA: horas máximas de atención según prioridad
SLA_HORAS = {"Alta": 4, "Media": 24, "Baja": 72}

# Opciones para publicarlo en internet (se activan con variables de entorno)
EN_HTTPS = os.environ.get("ARTUR_HTTPS") == "1"
SETUP_CODE = os.environ.get("ARTUR_SETUP_CODE", "")


# ---------- Configuración segura ----------
def cargar_clave():
    """Genera una clave secreta una sola vez y la reutiliza."""
    if not os.path.exists(KEY_PATH):
        with open(KEY_PATH, "w") as f:
            f.write(secrets.token_hex(32))
    with open(KEY_PATH) as f:
        return f.read().strip()


app.secret_key = cargar_clave()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=EN_HTTPS,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
    MAX_CONTENT_LENGTH=6 * 1024 * 1024,
)

if EN_HTTPS:
    # Detrás del proxy del hosting: toma la IP real del visitante
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)


# ---------- Base de datos ----------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def cerrar_db(error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            titulo TEXT NOT NULL,
            descripcion TEXT NOT NULL,
            prioridad TEXT NOT NULL DEFAULT 'Media',
            estado TEXT NOT NULL DEFAULT 'Pendiente',
            fecha TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
        );
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            rol TEXT NOT NULL DEFAULT 'tecnico',
            creado TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
        );
        CREATE TABLE IF NOT EXISTS registros (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fecha TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
            usuario TEXT,
            evento TEXT NOT NULL,
            detalle TEXT,
            ip TEXT
        );
        CREATE TABLE IF NOT EXISTS adjuntos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id INTEGER NOT NULL,
            nombre_original TEXT NOT NULL,
            nombre_archivo TEXT NOT NULL,
            tipo TEXT NOT NULL,
            tamano INTEGER NOT NULL,
            subido_por TEXT,
            fecha TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
        );
        """
    )
    # Migración: agrega columnas nuevas a la tabla de tickets existente
    columnas = [c["name"] for c in db.execute("PRAGMA table_info(tickets)")]
    if "tecnico" not in columnas:
        db.execute("ALTER TABLE tickets ADD COLUMN tecnico TEXT")
    if "creado_por" not in columnas:
        db.execute("ALTER TABLE tickets ADD COLUMN creado_por TEXT")
    db.commit()


# ---------- Auditoría (SOC) ----------
def registrar(evento, detalle="", usuario=None):
    db = get_db()
    db.execute(
        "INSERT INTO registros (usuario, evento, detalle, ip) VALUES (?, ?, ?, ?)",
        (usuario or session.get("usuario"), evento, detalle, request.remote_addr),
    )
    db.commit()


# ---------- CSRF ----------
def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def proteger_csrf():
    if request.method == "POST":
        token = session.get("csrf", "")
        enviado = request.form.get("csrf", "")
        if not token or not secrets.compare_digest(token.encode(), enviado.encode()):
            registrar("CSRF_RECHAZADO", request.path)
            abort(400)


@app.after_request
def cabeceras_seguras(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self'; script-src 'self'; frame-ancestors 'none'"
    )
    if EN_HTTPS:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000"
    return resp


# ---------- Decoradores de acceso ----------
def login_requerido(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "usuario" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def admin_requerido(f):
    @wraps(f)
    @login_requerido
    def wrapper(*args, **kwargs):
        if session.get("rol") != "admin":
            registrar("ACCESO_DENEGADO", request.path)
            abort(403)
        return f(*args, **kwargs)
    return wrapper


# ---------- Validaciones ----------
def usuario_valido(nombre):
    return bool(re.fullmatch(r"[A-Za-z0-9_.-]{3,30}", nombre))


def password_valida(pw):
    return len(pw) >= 8 and re.search(r"[A-Za-z]", pw) and re.search(r"\d", pw)


MSG_PASSWORD = "La contraseña debe tener mínimo 8 caracteres, con letras y números."


def lista_tecnicos():
    filas = get_db().execute("SELECT usuario FROM usuarios ORDER BY usuario").fetchall()
    return [f["usuario"] for f in filas]


# ---------- SLA ----------
def formato_tiempo(segundos):
    segundos = int(abs(segundos))
    dias, resto = divmod(segundos, 86400)
    horas, resto = divmod(resto, 3600)
    minutos = resto // 60
    if dias:
        return f"{dias} d {horas} h"
    if horas:
        return f"{horas} h {minutos} min"
    return f"{minutos} min"


def calcular_sla(ticket):
    """Devuelve el estado del SLA: cerrado, vencido, por-vencer o en-tiempo."""
    horas = SLA_HORAS.get(ticket["prioridad"], 24)
    try:
        creado = datetime.strptime(ticket["fecha"], "%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return {"estado": "en-tiempo", "texto": "—", "limite": "—"}

    limite = creado + timedelta(hours=horas)
    limite_txt = limite.strftime("%Y-%m-%d %H:%M")

    if ticket["estado"] == "Resuelto":
        return {"estado": "cerrado", "texto": "Cerrado", "limite": limite_txt}

    restante = (limite - datetime.now()).total_seconds()
    if restante < 0:
        return {"estado": "vencido",
                "texto": f"Vencido hace {formato_tiempo(restante)}",
                "limite": limite_txt}
    estado = "por-vencer" if restante < horas * 3600 * 0.25 else "en-tiempo"
    return {"estado": estado,
            "texto": f"Vence en {formato_tiempo(restante)}",
            "limite": limite_txt}


# ---------- Archivos adjuntos ----------
def contenido_valido(ext, datos):
    """Comprueba que el contenido real coincida con la extensión."""
    if ext == "png":
        return datos.startswith(b"\x89PNG\r\n\x1a\n")
    if ext in ("jpg", "jpeg"):
        return datos.startswith(b"\xff\xd8\xff")
    if ext == "gif":
        return datos.startswith((b"GIF87a", b"GIF89a"))
    if ext == "pdf":
        return datos.startswith(b"%PDF-")
    if ext in ("txt", "log"):
        try:
            datos.decode("utf-8")
            return True
        except UnicodeDecodeError:
            return False
    return False


def borrar_archivo(nombre_archivo):
    try:
        os.remove(os.path.join(UPLOAD_DIR, nombre_archivo))
    except FileNotFoundError:
        pass


# ---------- Autenticación ----------
@app.route("/setup", methods=["GET", "POST"])
def setup():
    db = get_db()
    if db.execute("SELECT COUNT(*) FROM usuarios").fetchone()[0] > 0:
        return redirect(url_for("login"))

    if request.method == "POST":
        usuario = request.form.get("usuario", "").strip()
        pw = request.form.get("password", "")
        pw2 = request.form.get("password2", "")
        codigo = request.form.get("codigo", "")

        if SETUP_CODE and not secrets.compare_digest(codigo.encode(), SETUP_CODE.encode()):
            registrar("SETUP_RECHAZADO", "Código de instalación incorrecto")
            flash("Código de instalación incorrecto.", "error")
        elif not usuario_valido(usuario):
            flash("Usuario: 3 a 30 caracteres (letras, números, . _ -).", "error")
        elif pw != pw2:
            flash("Las contraseñas no coinciden.", "error")
        elif not password_valida(pw):
            flash(MSG_PASSWORD, "error")
        else:
            db.execute(
                "INSERT INTO usuarios (usuario, password_hash, rol) VALUES (?, ?, 'admin')",
                (usuario, generate_password_hash(pw)),
            )
            db.commit()
            registrar("USUARIO_CREADO", f"{usuario} (admin inicial)", usuario=usuario)
            flash("Administrador creado. Ya puedes iniciar sesión.", "ok")
            return redirect(url_for("login"))
    return render_template("setup.html", requiere_codigo=bool(SETUP_CODE))


@app.route("/login", methods=["GET", "POST"])
def login():
    db = get_db()
    if db.execute("SELECT COUNT(*) FROM usuarios").fetchone()[0] == 0:
        return redirect(url_for("setup"))
    if "usuario" in session:
        return redirect(url_for("inicio"))

    if request.method == "POST":
        usuario = request.form.get("usuario", "").strip()[:50]
        pw = request.form.get("password", "")

        fallos = db.execute(
            """SELECT COUNT(*) FROM registros
               WHERE evento = 'LOGIN_FALLIDO' AND usuario = ?
                 AND fecha >= datetime('now', 'localtime', ?)
                 AND id > (SELECT COALESCE(MAX(id), 0) FROM registros
                           WHERE evento = 'LOGIN_OK' AND usuario = ?)""",
            (usuario, f"-{VENTANA_MIN} minutes", usuario),
        ).fetchone()[0]

        if fallos >= MAX_INTENTOS:
            registrar("LOGIN_BLOQUEADO", "Demasiados intentos fallidos", usuario=usuario)
            flash(f"Demasiados intentos. Espera {VENTANA_MIN} minutos.", "error")
            return render_template("login.html"), 429

        fila = db.execute("SELECT * FROM usuarios WHERE usuario = ?", (usuario,)).fetchone()
        if fila and check_password_hash(fila["password_hash"], pw):
            session.clear()
            session.permanent = True
            session["usuario"] = fila["usuario"]
            session["rol"] = fila["rol"]
            registrar("LOGIN_OK", "Inicio de sesión")
            return redirect(url_for("inicio"))

        registrar("LOGIN_FALLIDO", "Credenciales incorrectas", usuario=usuario)
        flash("Usuario o contraseña incorrectos.", "error")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_requerido
def logout():
    registrar("LOGOUT", "Cierre de sesión")
    session.clear()
    return redirect(url_for("login"))


# ---------- Tickets ----------
@app.route("/")
@login_requerido
def inicio():
    db = get_db()
    filtros = {
        "q": request.args.get("q", "").strip()[:100],
        "estado": request.args.get("estado", ""),
        "prioridad": request.args.get("prioridad", ""),
        "tecnico": request.args.get("tecnico", ""),
        "sla": "vencido" if request.args.get("sla") == "vencido" else "",
    }

    sql = (
        "SELECT t.*, "
        "(SELECT COUNT(*) FROM adjuntos a WHERE a.ticket_id = t.id) AS n_adjuntos "
        "FROM tickets t WHERE 1 = 1"
    )
    params = []
    if filtros["estado"] in ESTADOS:
        sql += " AND t.estado = ?"
        params.append(filtros["estado"])
    if filtros["prioridad"] in PRIORIDADES:
        sql += " AND t.prioridad = ?"
        params.append(filtros["prioridad"])
    if filtros["tecnico"] == "sin_asignar":
        sql += " AND (t.tecnico IS NULL OR t.tecnico = '')"
    elif filtros["tecnico"]:
        sql += " AND t.tecnico = ?"
        params.append(filtros["tecnico"])
    if filtros["q"]:
        sql += " AND (t.titulo LIKE ? OR t.descripcion LIKE ?)"
        like = f"%{filtros['q']}%"
        params += [like, like]
    sql += " ORDER BY t.id DESC"

    tickets = []
    for fila in db.execute(sql, params).fetchall():
        t = dict(fila)
        t["sla"] = calcular_sla(fila)
        tickets.append(t)
    if filtros["sla"]:
        tickets = [t for t in tickets if t["sla"]["estado"] == "vencido"]

    # Contadores y SLA general (sobre todos los tickets)
    todos = db.execute("SELECT prioridad, estado, fecha FROM tickets").fetchall()
    conteo = {e: 0 for e in ESTADOS}
    vencidos = 0
    for fila in todos:
        conteo[fila["estado"]] = conteo.get(fila["estado"], 0) + 1
        if calcular_sla(fila)["estado"] == "vencido":
            vencidos += 1

    # Datos de las gráficas
    por_estado = [
        {"etiqueta": e, "valor": conteo[e], "clase": "g-" + e.lower().replace(" ", "-")}
        for e in ESTADOS
    ]
    prio_filas = {
        f["prioridad"]: f["n"]
        for f in db.execute("SELECT prioridad, COUNT(*) AS n FROM tickets GROUP BY prioridad")
    }
    por_prioridad = [
        {"etiqueta": p, "valor": prio_filas.get(p, 0), "clase": "g-" + p.lower()}
        for p in PRIORIDADES
    ]
    tec_filas = db.execute(
        "SELECT COALESCE(NULLIF(tecnico, ''), 'Sin asignar') AS nombre, COUNT(*) AS n "
        "FROM tickets GROUP BY nombre ORDER BY n DESC LIMIT 8"
    ).fetchall()
    por_tecnico = [
        {"etiqueta": f["nombre"], "valor": f["n"], "clase": "g-tecnico"} for f in tec_filas
    ]

    return render_template(
        "index.html",
        tickets=tickets,
        total=sum(conteo.values()),
        pendientes=conteo["Pendiente"],
        en_proceso=conteo["En proceso"],
        resueltos=conteo["Resuelto"],
        vencidos=vencidos,
        por_estado=por_estado,
        por_prioridad=por_prioridad,
        por_tecnico=por_tecnico,
        filtros=filtros,
        estados=ESTADOS,
        prioridades=PRIORIDADES,
        tecnicos=lista_tecnicos(),
    )


@app.route("/nuevo", methods=["POST"])
@login_requerido
def nuevo_ticket():
    titulo = request.form.get("titulo", "").strip()[:100]
    descripcion = request.form.get("descripcion", "").strip()[:2000]
    prioridad = request.form.get("prioridad", "Media")
    tecnico = request.form.get("tecnico", "")

    if prioridad not in PRIORIDADES:
        prioridad = "Media"
    if tecnico not in lista_tecnicos():
        tecnico = ""
    if not titulo or not descripcion:
        flash("El título y la descripción son obligatorios.", "error")
        return redirect(url_for("inicio"))

    db = get_db()
    cur = db.execute(
        "INSERT INTO tickets (titulo, descripcion, prioridad, tecnico, creado_por) "
        "VALUES (?, ?, ?, ?, ?)",
        (titulo, descripcion, prioridad, tecnico, session["usuario"]),
    )
    db.commit()
    registrar("TICKET_CREADO", f"#{cur.lastrowid} {titulo} [{prioridad}]")
    flash("Ticket registrado. Puedes abrirlo para adjuntar evidencias.", "ok")
    return redirect(url_for("inicio"))


@app.route("/ticket/<int:ticket_id>")
@login_requerido
def ver_ticket(ticket_id):
    db = get_db()
    ticket = db.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
    if ticket is None:
        abort(404)
    adjuntos = db.execute(
        "SELECT * FROM adjuntos WHERE ticket_id = ? ORDER BY id", (ticket_id,)
    ).fetchall()
    return render_template(
        "ticket.html",
        ticket=ticket,
        sla=calcular_sla(ticket),
        adjuntos=adjuntos,
        imagenes=IMAGENES,
        max_mb=MAX_ARCHIVO // (1024 * 1024),
        max_adjuntos=MAX_ADJUNTOS,
        formatos=", ".join(e.upper() for e in EXTENSIONES),
    )


@app.route("/editar/<int:ticket_id>", methods=["GET", "POST"])
@login_requerido
def editar_ticket(ticket_id):
    db = get_db()
    ticket = db.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
    if ticket is None:
        abort(404)

    if request.method == "POST":
        titulo = request.form.get("titulo", "").strip()[:100]
        descripcion = request.form.get("descripcion", "").strip()[:2000]
        prioridad = request.form.get("prioridad", "Media")
        estado = request.form.get("estado", "Pendiente")
        tecnico = request.form.get("tecnico", "")

        if prioridad not in PRIORIDADES:
            prioridad = "Media"
        if estado not in ESTADOS:
            estado = "Pendiente"
        if tecnico not in lista_tecnicos():
            tecnico = ""
        if not titulo or not descripcion:
            flash("El título y la descripción son obligatorios.", "error")
        else:
            db.execute(
                "UPDATE tickets SET titulo = ?, descripcion = ?, prioridad = ?, "
                "estado = ?, tecnico = ? WHERE id = ?",
                (titulo, descripcion, prioridad, estado, tecnico, ticket_id),
            )
            db.commit()
            registrar("TICKET_EDITADO", f"#{ticket_id} -> {estado}, {prioridad}, técnico: {tecnico or 'sin asignar'}")
            flash("Ticket actualizado.", "ok")
            return redirect(url_for("inicio"))

    return render_template(
        "editar.html", ticket=ticket, estados=ESTADOS,
        prioridades=PRIORIDADES, tecnicos=lista_tecnicos(),
    )


@app.route("/tomar/<int:ticket_id>", methods=["POST"])
@login_requerido
def tomar_ticket(ticket_id):
    db = get_db()
    db.execute(
        "UPDATE tickets SET tecnico = ?, estado = 'En proceso' "
        "WHERE id = ? AND estado = 'Pendiente'",
        (session["usuario"], ticket_id),
    )
    db.commit()
    registrar("TICKET_TOMADO", f"#{ticket_id}")
    return redirect(url_for("inicio"))


@app.route("/resolver/<int:ticket_id>", methods=["POST"])
@login_requerido
def resolver_ticket(ticket_id):
    db = get_db()
    db.execute("UPDATE tickets SET estado = 'Resuelto' WHERE id = ?", (ticket_id,))
    db.commit()
    registrar("TICKET_RESUELTO", f"#{ticket_id}")
    flash("Ticket marcado como resuelto.", "ok")
    return redirect(url_for("inicio"))


@app.route("/eliminar/<int:ticket_id>", methods=["POST"])
@admin_requerido
def eliminar_ticket(ticket_id):
    db = get_db()
    for adj in db.execute(
        "SELECT nombre_archivo FROM adjuntos WHERE ticket_id = ?", (ticket_id,)
    ).fetchall():
        borrar_archivo(adj["nombre_archivo"])
    db.execute("DELETE FROM adjuntos WHERE ticket_id = ?", (ticket_id,))
    db.execute("DELETE FROM tickets WHERE id = ?", (ticket_id,))
    db.commit()
    registrar("TICKET_ELIMINADO", f"#{ticket_id}")
    flash("Ticket eliminado.", "ok")
    return redirect(url_for("inicio"))


# ---------- Adjuntos ----------
@app.route("/ticket/<int:ticket_id>/adjuntar", methods=["POST"])
@login_requerido
def adjuntar(ticket_id):
    db = get_db()
    ticket = db.execute("SELECT id FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
    if ticket is None:
        abort(404)

    destino = redirect(url_for("ver_ticket", ticket_id=ticket_id))
    archivo = request.files.get("archivo")
    if not archivo or not archivo.filename:
        flash("Selecciona un archivo.", "error")
        return destino

    ext = os.path.splitext(archivo.filename)[1].lstrip(".").lower()
    nombre = (secure_filename(archivo.filename) or f"archivo.{ext}")[:80]

    if ext not in EXTENSIONES:
        registrar("ADJUNTO_RECHAZADO", f"#{ticket_id} {nombre} (extensión no permitida)")
        flash("Tipo de archivo no permitido.", "error")
        return destino

    cantidad = db.execute(
        "SELECT COUNT(*) FROM adjuntos WHERE ticket_id = ?", (ticket_id,)
    ).fetchone()[0]
    if cantidad >= MAX_ADJUNTOS:
        flash(f"Máximo {MAX_ADJUNTOS} archivos por ticket.", "error")
        return destino

    datos = archivo.read(MAX_ARCHIVO + 1)
    if len(datos) > MAX_ARCHIVO:
        registrar("ADJUNTO_RECHAZADO", f"#{ticket_id} {nombre} (supera el tamaño máximo)")
        flash(f"El archivo supera {MAX_ARCHIVO // (1024 * 1024)} MB.", "error")
        return destino
    if not datos or not contenido_valido(ext, datos):
        registrar("ADJUNTO_RECHAZADO", f"#{ticket_id} {nombre} (contenido no coincide con el tipo)")
        flash("El contenido del archivo no coincide con su tipo.", "error")
        return destino

    nombre_archivo = f"{secrets.token_hex(16)}.{ext}"
    with open(os.path.join(UPLOAD_DIR, nombre_archivo), "wb") as f:
        f.write(datos)

    db.execute(
        "INSERT INTO adjuntos (ticket_id, nombre_original, nombre_archivo, tipo, tamano, subido_por) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (ticket_id, nombre, nombre_archivo, EXTENSIONES[ext], len(datos), session["usuario"]),
    )
    db.commit()
    registrar("ADJUNTO_SUBIDO", f"#{ticket_id} {nombre} ({len(datos) // 1024} KB)")
    flash("Evidencia adjuntada.", "ok")
    return destino


@app.route("/adjunto/<int:adjunto_id>")
@login_requerido
def ver_adjunto(adjunto_id):
    fila = get_db().execute("SELECT * FROM adjuntos WHERE id = ?", (adjunto_id,)).fetchone()
    if fila is None:
        abort(404)
    return send_from_directory(
        UPLOAD_DIR,
        fila["nombre_archivo"],
        mimetype=fila["tipo"],
        as_attachment=fila["tipo"] not in IMAGENES,
        download_name=fila["nombre_original"],
    )


@app.route("/adjunto/eliminar/<int:adjunto_id>", methods=["POST"])
@login_requerido
def eliminar_adjunto(adjunto_id):
    db = get_db()
    fila = db.execute("SELECT * FROM adjuntos WHERE id = ?", (adjunto_id,)).fetchone()
    if fila is None:
        abort(404)
    if session.get("rol") != "admin" and fila["subido_por"] != session["usuario"]:
        registrar("ACCESO_DENEGADO", request.path)
        abort(403)
    borrar_archivo(fila["nombre_archivo"])
    db.execute("DELETE FROM adjuntos WHERE id = ?", (adjunto_id,))
    db.commit()
    registrar("ADJUNTO_ELIMINADO", f"#{fila['ticket_id']} {fila['nombre_original']}")
    flash("Archivo eliminado.", "ok")
    return redirect(url_for("ver_ticket", ticket_id=fila["ticket_id"]))


# ---------- Administración de usuarios ----------
@app.route("/usuarios")
@admin_requerido
def usuarios():
    filas = get_db().execute("SELECT * FROM usuarios ORDER BY id").fetchall()
    return render_template("usuarios.html", usuarios=filas)


@app.route("/usuarios/nuevo", methods=["POST"])
@admin_requerido
def usuario_nuevo():
    usuario = request.form.get("usuario", "").strip()
    pw = request.form.get("password", "")
    rol = request.form.get("rol", "tecnico")
    if rol not in ("admin", "tecnico"):
        rol = "tecnico"

    if not usuario_valido(usuario):
        flash("Usuario: 3 a 30 caracteres (letras, números, . _ -).", "error")
    elif not password_valida(pw):
        flash(MSG_PASSWORD, "error")
    else:
        try:
            db = get_db()
            db.execute(
                "INSERT INTO usuarios (usuario, password_hash, rol) VALUES (?, ?, ?)",
                (usuario, generate_password_hash(pw), rol),
            )
            db.commit()
            registrar("USUARIO_CREADO", f"{usuario} ({rol})")
            flash(f"Usuario {usuario} creado.", "ok")
        except sqlite3.IntegrityError:
            flash("Ese usuario ya existe.", "error")
    return redirect(url_for("usuarios"))


@app.route("/usuarios/eliminar/<int:user_id>", methods=["POST"])
@admin_requerido
def usuario_eliminar(user_id):
    db = get_db()
    fila = db.execute("SELECT * FROM usuarios WHERE id = ?", (user_id,)).fetchone()
    if fila is None:
        abort(404)
    if fila["usuario"] == session["usuario"]:
        flash("No puedes eliminar tu propio usuario.", "error")
    else:
        db.execute("DELETE FROM usuarios WHERE id = ?", (user_id,))
        db.commit()
        registrar("USUARIO_ELIMINADO", fila["usuario"])
        flash("Usuario eliminado.", "ok")
    return redirect(url_for("usuarios"))


# ---------- Panel de auditoría (SOC) ----------
@app.route("/registros")
@admin_requerido
def ver_registros():
    db = get_db()
    evento = request.args.get("evento", "")
    eventos = [f[0] for f in db.execute("SELECT DISTINCT evento FROM registros ORDER BY evento")]

    if evento in eventos:
        filas = db.execute(
            "SELECT * FROM registros WHERE evento = ? ORDER BY id DESC LIMIT 200", (evento,)
        ).fetchall()
    else:
        evento = ""
        filas = db.execute("SELECT * FROM registros ORDER BY id DESC LIMIT 200").fetchall()

    def ultimas_24h(ev):
        return db.execute(
            "SELECT COUNT(*) FROM registros WHERE evento = ? "
            "AND fecha >= datetime('now', 'localtime', '-1 day')", (ev,)
        ).fetchone()[0]

    return render_template(
        "registros.html", registros=filas, eventos=eventos, evento=evento,
        fallidos=ultimas_24h("LOGIN_FALLIDO"),
        bloqueos=ultimas_24h("LOGIN_BLOQUEADO"),
        denegados=ultimas_24h("ACCESO_DENEGADO"),
    )


# ---------- Errores ----------
@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(413)
def manejar_error(e):
    mensajes = {
        400: "Solicitud no válida o sesión expirada. Recarga la página e inténtalo de nuevo.",
        403: "No tienes permiso para entrar a esta sección.",
        404: "Página no encontrada.",
        413: "El archivo es demasiado grande (máximo 5 MB).",
    }
    return render_template("error.html", codigo=e.code, mensaje=mensajes.get(e.code, e.name)), e.code


with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(debug=True)