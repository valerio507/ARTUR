# ARTUR · Sistema de Soporte Técnico

Aplicación web de **gestión de tickets de soporte técnico** desarrollada con **Python, Flask y SQLite**. Incluye autenticación segura, control de roles, **evidencias adjuntas con validación**, **control de tiempos de atención (SLA)**, gráficas en el panel y un **registro de auditoría de seguridad (SOC)**.

Proyecto personal de práctica en desarrollo web seguro y análisis de incidentes.

---

## Funciones

**Gestión de tickets**
- Registro de incidencias con título, descripción y prioridad (Baja, Media, Alta).
- Estados: Pendiente, En proceso y Resuelto.
- Asignación de técnico responsable y opción de **tomar** un ticket.
- Edición de tickets y vista de detalle.
- Buscador por título o descripción.
- Filtros por estado, prioridad, técnico y SLA vencido.

**Evidencias adjuntas**
- Subida de capturas y archivos al ticket (PNG, JPG, GIF, PDF, TXT y LOG).
- Máximo de 5 MB por archivo y 5 archivos por ticket.
- Vista previa de imágenes y descarga del resto de formatos.

**SLA (tiempo de atención)**
- Tiempo límite según la prioridad: Alta 4 h, Media 24 h y Baja 72 h.
- Indicador por ticket: en tiempo, por vencer, vencido o cerrado.
- Alerta en el panel y filtro para ver solo los tickets vencidos.

**Panel con gráficas**
- Contadores de total, pendientes, en proceso y resueltos.
- Gráficas de tickets por estado, por prioridad y por técnico.

**Usuarios y roles**
- Inicio y cierre de sesión.
- Dos roles: **administrador** y **técnico**.
- El administrador crea y elimina usuarios, elimina tickets y accede a la auditoría.
- El técnico registra, edita, toma y resuelve tickets, y sube evidencias.

**Auditoría SOC**
- Registro de eventos con fecha, usuario, evento, detalle e IP.
- Panel con filtros por tipo de evento.
- Indicadores de las últimas 24 horas: logins fallidos, bloqueos y accesos denegados.

---

## Tecnologías

| Componente | Tecnología |
|---|---|
| Lenguaje | Python 3 |
| Framework web | Flask |
| Base de datos | SQLite |
| Plantillas | Jinja2 |
| Interfaz | HTML5, CSS3 y gráficas SVG (diseño responsivo) |
| Seguridad de contraseñas | Werkzeug (`generate_password_hash`) |

---

## Estructura del proyecto

```
ARTUR/
├── app.py                # Aplicación Flask (rutas, seguridad y base de datos)
├── requirements.txt      # Dependencias
├── static/
│   ├── style.css         # Estilos
│   └── app.js            # Confirmaciones de formularios
└── templates/
    ├── base.html         # Plantilla base (encabezado y navegación)
    ├── login.html        # Inicio de sesión
    ├── setup.html        # Creación del primer administrador
    ├── index.html        # Panel: contadores, gráficas y lista de tickets
    ├── graficas.html     # Macro de gráficas de barras SVG
    ├── ticket.html       # Detalle del ticket y evidencias adjuntas
    ├── editar.html       # Edición de tickets
    ├── usuarios.html     # Gestión de usuarios (admin)
    ├── registros.html    # Auditoría SOC (admin)
    └── error.html        # Páginas de error
```

Al ejecutar la aplicación se generan automáticamente `pydesk.db` (base de datos), `secret.key` (clave de sesión) y la carpeta `uploads/` (evidencias). Los tres están excluidos del repositorio.

---

## Instalación y uso local

**Requisitos:** Python 3.10 o superior.

```powershell
# 1. Clonar el repositorio
git clone https://github.com/valerio507/ARTUR.git
cd ARTUR

# 2. Crear y activar el entorno virtual
python -m venv .venv
.venv\Scripts\Activate.ps1

# 3. Instalar dependencias
pip install -r requirements.txt

# 4. Ejecutar
python app.py
```

Abre `http://127.0.0.1:5000` en el navegador.

> En Linux o macOS, activa el entorno con `source .venv/bin/activate`.

### Primer uso

1. Al abrir la aplicación por primera vez se muestra la pantalla **Crear administrador**.
2. Elige un usuario y una contraseña (mínimo 8 caracteres, con letras y números).
3. Inicia sesión y crea los usuarios técnicos desde la sección **Usuarios**.

No hay credenciales por defecto: el administrador se crea en el primer arranque.

---

## Despliegue en internet

El proyecto se puede publicar en **PythonAnywhere** (plan gratuito) con una configuración WSGI como esta:

```python
import os
import sys

ruta = "/home/TU_USUARIO/ARTUR"
if ruta not in sys.path:
    sys.path.insert(0, ruta)

os.environ["ARTUR_HTTPS"] = "1"
os.environ["ARTUR_SETUP_CODE"] = "un-codigo-largo-y-secreto"

from app import app as application
```

Variables de entorno opcionales:

| Variable | Efecto |
|---|---|
| `ARTUR_HTTPS=1` | Cookie de sesión solo por HTTPS, cabecera HSTS y lectura de la IP real detrás del proxy |
| `ARTUR_SETUP_CODE` | Exige un código para crear el primer administrador, evitando que un tercero lo cree antes que tú |

---

## Medidas de seguridad

| Medida | Descripción |
|---|---|
| **Contraseñas con hash** | Solo se almacena el hash de la contraseña, nunca el texto original. |
| **Política de contraseñas** | Mínimo 8 caracteres, con letras y números. |
| **Bloqueo por intentos fallidos** | Tras 5 intentos fallidos consecutivos, el usuario se bloquea 10 minutos. |
| **Mensaje de error genérico** | No revela si el usuario existe o si falló la contraseña. |
| **Control de acceso por roles** | Las rutas de administración exigen rol de administrador. |
| **Protección CSRF** | Todos los formularios que modifican datos incluyen un token de verificación. |
| **Consultas parametrizadas** | Previenen la inyección SQL. |
| **Escape automático de plantillas** | Jinja2 escapa el contenido y mitiga el XSS. |
| **Sesiones seguras** | Cookie `HttpOnly` y `SameSite=Lax`, expiración a las 2 horas y sesión nueva al iniciar sesión. |
| **Cabeceras HTTP** | `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy` y HSTS en producción. |
| **Subida segura de archivos** | Lista de extensiones permitidas, verificación del contenido real (firma del archivo), límite de tamaño y cantidad, nombre aleatorio en disco y descarga solo con sesión iniciada. |
| **Archivos fuera de `static/`** | Las evidencias no son públicas; solo se sirven a usuarios autenticados. |
| **Validación de entradas** | Longitud y formato de los datos, con listas permitidas para prioridad, estado y rol. |
| **Auditoría** | Registro de eventos de autenticación, tickets, adjuntos, usuarios y accesos denegados. |
| **Secretos fuera del repositorio** | La clave de sesión, la base de datos y las evidencias están en `.gitignore`. |

### Eventos que se registran

| Evento | Se genera cuando |
|---|---|
| `LOGIN_OK` / `LOGOUT` | Un usuario inicia o cierra sesión |
| `LOGIN_FALLIDO` | Credenciales incorrectas |
| `LOGIN_BLOQUEADO` | Se supera el límite de intentos |
| `ACCESO_DENEGADO` | Un técnico intenta entrar a una sección de administrador |
| `CSRF_RECHAZADO` | Un formulario llega sin token válido |
| `SETUP_RECHAZADO` | Código de instalación incorrecto al crear el primer administrador |
| `TICKET_CREADO` / `TICKET_EDITADO` / `TICKET_TOMADO` / `TICKET_RESUELTO` / `TICKET_ELIMINADO` | Cambios en los tickets |
| `ADJUNTO_SUBIDO` / `ADJUNTO_ELIMINADO` / `ADJUNTO_RECHAZADO` | Gestión de evidencias |
| `USUARIO_CREADO` / `USUARIO_ELIMINADO` | Administración de usuarios |

---

## Limitaciones conocidas

- Pensado para **aprendizaje y demostración**: en local usa el servidor integrado de Flask con `debug=True`.
- El bloqueo por intentos se aplica por nombre de usuario, no por dirección IP.
- No incluye autenticación de dos factores ni recuperación de contraseña.
- El SLA se calcula desde la fecha de creación del ticket, sin horario laboral ni feriados.
- La base de datos SQLite y las evidencias se guardan en el disco del servidor; para uso real conviene una base de datos gestionada y copias de seguridad.

## Mejoras futuras

- [ ] Cambio de contraseña por parte del usuario
- [ ] Exportación de reportes a Excel y PDF
- [ ] Comentarios e historial por ticket
- [ ] Autenticación de dos factores (2FA)
- [ ] Detección de IPs con múltiples intentos fallidos

---

## Autor

**Valerio Ayarza**
Estudiante de Ingeniería y Ciberseguridad · Universidad del Istmo (Panamá)

GitHub: [valerio507](https://github.com/valerio507)
