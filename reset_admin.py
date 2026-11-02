import getpass
import os
import re
import sqlite3
import sys

from werkzeug.security import generate_password_hash

DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pydesk.db")

conn = sqlite3.connect(DB)

admins = [r[0] for r in conn.execute("SELECT usuario FROM usuarios WHERE rol = 'admin'")]
print("Administradores:", ", ".join(admins) or "ninguno")

usuario = input("Usuario a restablecer: ").strip()
fila = conn.execute("SELECT id FROM usuarios WHERE usuario = ?", (usuario,)).fetchone()
if fila is None:
    sys.exit("Ese usuario no existe.")

pw = input("Nueva contraseña (se verá): ")
pw2 = input("Repite la contraseña (se verá): ")

if pw != pw2:
    sys.exit("Las contraseñas no coinciden.")
if len(pw) < 8 or not re.search(r"[A-Za-z]", pw) or not re.search(r"\d", pw):
    sys.exit("Mínimo 8 caracteres, con letras y números.")

conn.execute(
    "UPDATE usuarios SET password_hash = ? WHERE id = ?",
    (generate_password_hash(pw), fila[0]),
)
conn.execute(
    "INSERT INTO registros (usuario, evento, detalle, ip) VALUES (?, ?, ?, ?)",
    (usuario, "PASSWORD_RESTABLECIDA", "Restablecida desde el servidor", "local"),
)
conn.commit()
conn.close()
print("Listo. Ya puedes iniciar sesión con la nueva contraseña.")