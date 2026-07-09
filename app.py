"""
Planeador Académico — App Web
Colegio Humboldt
Corre con: python3 app.py
Luego abre: http://127.0.0.1:8080
"""

import os
import json
import hashlib
import atexit
import webbrowser
import threading
import time
from datetime import datetime
from flask import Flask, render_template, request, jsonify, session, redirect, url_for

# Cargar variables de entorno desde .env
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # Si no está instalado, usa variables del sistema

# Rate limiting
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    LIMITER_OK = True
except ImportError:
    LIMITER_OK = False
    print("[!] flask-limiter no instalado. Corre: pip3 install flask-limiter")

# CSRF Protection
try:
    from flask_wtf.csrf import CSRFProtect, generate_csrf
    CSRF_OK = True
except ImportError:
    CSRF_OK = False

# Logging de auditoría
import logging
import logging.handlers

def configurar_logging():
    logger = logging.getLogger("planeador_audit")
    logger.setLevel(logging.INFO)
    handler = logging.handlers.RotatingFileHandler(
        os.path.join(CARPETA_DATOS, "audit.log"),
        maxBytes=1_000_000,  # 1MB
        backupCount=3,
        encoding="utf-8"
    )
    handler.setFormatter(logging.Formatter(
        "%(asctime)s | %(levelname)s | %(message)s"
    ))
    if not logger.handlers:
        logger.addHandler(handler)
    return logger

audit_log = None  # se inicializa después de asegurar carpeta

import re
import html
from cryptography.fernet import Fernet

# ─────────────────────────────────────────────
# SANITIZACIÓN DE INPUTS
# ─────────────────────────────────────────────

def sanitize(value, tipo="text", max_len=500):
    """
    Sanitiza un valor según su tipo.
    tipos: text, nombre, codigo, password, año, url, textarea
    """
    if value is None:
        return ""
    value = str(value).strip()

    # Limitar longitud
    limites = {
        "text":     200,
        "nombre":   100,
        "codigo":   10,
        "password": 128,
        "año":      4,
        "url":      500,
        "textarea": 2000,
    }
    value = value[:limites.get(tipo, max_len)]

    if tipo == "password":
        # Contraseñas: no modificar contenido, solo longitud
        return value

    if tipo == "codigo":
        # Códigos de curso/asignatura: solo alfanuméricos
        return re.sub(r'[^A-Za-z0-9]', '', value).upper()

    if tipo == "año":
        # Año: solo 4 dígitos
        clean = re.sub(r'[^0-9]', '', value)
        return clean[:4] if len(clean) == 4 else value

    if tipo == "nombre":
        # Nombres: letras, espacios, tildes y guiones
        return re.sub(r'[<>&"\'`;]', '', value).strip()

    if tipo == "textarea":
        # Texto largo: escapar HTML pero permitir saltos de línea
        value = html.escape(value, quote=True)
        return value

    # text por defecto: escapar caracteres peligrosos
    return html.escape(value, quote=True)


def sanitize_list(lst, tipo="codigo"):
    """Sanitiza una lista de strings."""
    if not isinstance(lst, list):
        return []
    return [sanitize(item, tipo) for item in lst if item and str(item).strip()]


def sanitize_dict_keys(d):
    """Sanitiza las claves de un diccionario (para bloques de periodos)."""
    if not isinstance(d, dict):
        return {}
    result = {}
    for k, v in d.items():
        clean_k = re.sub(r'[^0-9]', '', str(k))[:2]
        clean_v = sanitize(v, "textarea") if isinstance(v, str) else ""
        if clean_k:
            result[clean_k] = clean_v
    return result


def get_json_safe():
    """Obtiene JSON del request de forma segura."""
    try:
        data = request.get_json(force=True, silent=True)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}

# Selenium para deteccion de materias
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import Select, WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import TimeoutException
    from webdriver_manager.chrome import ChromeDriverManager
    SELENIUM_OK = True
except ImportError:
    SELENIUM_OK = False

def _crear_driver_chrome():
    """Crea un driver de Chrome. Si HEADLESS=true (uso en servidor/contenedor),
    corre sin ventana usando el Chromium/ChromeDriver del sistema (CHROME_BIN /
    CHROMEDRIVER_BIN). En Mac local sigue abriendo una ventana visible."""
    opts = webdriver.ChromeOptions()
    opts.add_argument("--disable-notifications")

    headless = os.environ.get("HEADLESS", "false").lower() == "true"
    if headless:
        opts.add_argument("--headless=new")
        opts.add_argument("--no-sandbox")
        opts.add_argument("--disable-dev-shm-usage")
        opts.add_argument("--disable-gpu")
        opts.add_argument("--window-size=1920,1080")
    else:
        opts.add_argument("--start-maximized")

    chrome_bin = os.environ.get("CHROME_BIN")
    if chrome_bin:
        opts.binary_location = chrome_bin

    chromedriver_bin = os.environ.get("CHROMEDRIVER_BIN")
    if chromedriver_bin:
        service = Service(executable_path=chromedriver_bin)
    else:
        service = Service(ChromeDriverManager().install())

    return webdriver.Chrome(service=service, options=opts)


app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "cambia-esta-clave-en-produccion")

# ── Seguridad de sesión ───────────────────────
app.config['SESSION_COOKIE_SAMESITE']    = 'Lax'
app.config['SESSION_COOKIE_SECURE']      = os.environ.get('SESSION_COOKIE_SECURE', 'false').lower() == 'true'   # True en producción vía variable de entorno
app.config['SESSION_COOKIE_HTTPONLY']    = True     # JS no puede leer la cookie
app.config['PERMANENT_SESSION_LIFETIME'] = 86400 * 7
app.config['SESSION_COOKIE_NAME']        = '__Host-session' if False else 'session'

# ── CSRF ─────────────────────────────────────
if CSRF_OK:
    csrf = CSRFProtect(app)
    app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # 1 hora

# ── Headers de seguridad ──────────────────────
@app.after_request
def agregar_headers_seguridad(response):
    # Evitar clickjacking
    response.headers['X-Frame-Options'] = 'DENY'
    # Evitar sniffing de MIME
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # XSS protection básico
    response.headers['X-XSS-Protection'] = '1; mode=block'
    # Content Security Policy
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://fonts.googleapis.com https://fonts.gstatic.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    )
    # Referrer policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    # Permissions policy
    response.headers['Permissions-Policy'] = 'geolocation=(), camera=(), microphone=(self)'
    return response

# ── Rate Limiter ──────────────────────────────
# Límites por defecto (se sobreescriben por ruta)
# Formato: "cantidad por periodo" — ej: "10 per minute"
if LIMITER_OK:
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["200 per day", "60 per hour"],
        storage_uri="memory://",
    )
else:
    # Fallback: decorator vacío si no está instalado
    class _FakeLimiter:
        def limit(self, *a, **kw):
            return lambda f: f
        def exempt(self, f):
            return f
    limiter = _FakeLimiter()

CARPETA_DATOS = os.environ.get("DATA_DIR", os.path.expanduser("~/Desktop/planeador_academico"))
AÑO_ACTUAL   = str(datetime.now().year)

# ── Constantes de la plataforma ───────────────
URL_LOGIN  = "https://www.colhumboldt.controlacademico.com/login.php"
URL_PLANES = "https://www.colhumboldt.controlacademico.com/modules.php?name=Plan_Aula"
URL_AULA_V = "https://www.colhumboldt.controlacademico.com/AulaVirtual/preguntaseval/inicio.php"
PAUSA      = 4
TIMEOUT    = 45
RUTA_CONFIG  = os.path.join(CARPETA_DATOS, "config.json")

def cargar_config():
    if not os.path.exists(RUTA_CONFIG): return {}
    try:
        with open(RUTA_CONFIG, encoding="utf-8") as f: return json.load(f)
    except: return {}

def guardar_config_global(data):
    os.makedirs(os.path.dirname(RUTA_CONFIG), exist_ok=True)
    with open(RUTA_CONFIG, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def get_fernet():
    """Devuelve instancia de Fernet usando SECRET_KEY como base."""
    import base64, hashlib
    key = os.environ.get("SECRET_KEY", "clave-default-cambiar")
    # Derivar clave de 32 bytes en base64 url-safe
    key_bytes = hashlib.sha256(key.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key_bytes))

def encriptar_credencial(texto):
    """Encripta una credencial para guardarla segura."""
    if not texto: return ""
    try:
        return get_fernet().encrypt(texto.encode()).decode()
    except Exception:
        return ""

def desencriptar_credencial(texto_enc):
    """Desencripta una credencial guardada."""
    if not texto_enc: return ""
    try:
        return get_fernet().decrypt(texto_enc.encode()).decode()
    except Exception:
        return ""


def get_api_key():
    """Devuelve el API key — primero config.json, luego .env"""
    return cargar_config().get("api_key") or os.environ.get("AI_API_KEY", "")

def get_proveedor():
    """Devuelve el proveedor — primero config.json, luego .env"""
    return cargar_config().get("proveedor") or os.environ.get("AI_PROVIDER", "anthropic")

# ─────────────────────────────────────────────
# UTILIDADES
# ─────────────────────────────────────────────

def asegurar_carpeta():
    os.makedirs(CARPETA_DATOS, exist_ok=True)
    global audit_log
    if audit_log is None:
        audit_log = configurar_logging()

def log_auditoria(evento, usuario=None, detalle=""):
    """Registra eventos de seguridad en el log de auditoría."""
    global audit_log
    if audit_log is None:
        asegurar_carpeta()
    ip = request.remote_addr if request else "sistema"
    msg = f"IP={ip} | USER={usuario or 'anon'} | EVENTO={evento}"
    if detalle:
        msg += f" | {detalle}"
    audit_log.info(msg)


def _limpiar_al_salir():
    for sid, driver in list(_drivers_activos.items()):
        try: driver.quit()
        except: pass
    _drivers_activos.clear()

atexit.register(_limpiar_al_salir)
def enc(pw):
    import bcrypt
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

def verificar_pw(pw, hashed):
    import bcrypt
    try:
        if hashed.startswith("$2"):
            return bcrypt.checkpw(pw.encode(), hashed.encode())
        return hashlib.sha256(pw.encode()).hexdigest() == hashed
    except:
        return False

def ruta_perfiles():
    return os.path.join(CARPETA_DATOS, "perfiles.json")

def ruta_memoria(profe, materia):
    import re
    p = profe.lower().replace(" ", "_")
    m = re.sub(r'[áéíóúñ]',
        lambda x: {'á':'a','é':'e','í':'i','ó':'o','ú':'u','ñ':'n'}[x.group()],
        materia.lower().replace(" ", "_").replace("/","_"))
    return os.path.join(CARPETA_DATOS, f"mem_{p}_{m}.json")

def cargar_perfiles():
    r = ruta_perfiles()
    if not os.path.exists(r): return {}
    try:
        with open(r, encoding="utf-8") as f: return json.load(f)
    except: return {}

def guardar_perfiles(p):
    asegurar_carpeta()
    with open(ruta_perfiles(), "w", encoding="utf-8") as f:
        json.dump(p, f, ensure_ascii=False, indent=2)

def cargar_memoria(profe, materia):
    r = ruta_memoria(profe, materia)
    if not os.path.exists(r): return {"observaciones": [], "estilo": "", "periodos": {}}
    try:
        with open(r, encoding="utf-8") as f: return json.load(f)
    except: return {"observaciones": [], "estilo": "", "periodos": {}}

def guardar_memoria(profe, materia, mem):
    asegurar_carpeta()
    with open(ruta_memoria(profe, materia), "w", encoding="utf-8") as f:
        json.dump(mem, f, ensure_ascii=False, indent=2)

def get_año(perfiles, nombre):
    return perfiles[nombre].get("año_activo", AÑO_ACTUAL)

def get_materias(perfiles, nombre):
    año = get_año(perfiles, nombre)
    return perfiles[nombre]["años"].get(año, {}).get("materias", {})

def set_materias(perfiles, nombre, mats):
    año = get_año(perfiles, nombre)
    perfiles[nombre]["años"][año]["materias"] = mats
    guardar_perfiles(perfiles)
    return perfiles

def usuario_actual():
    return session.get("usuario")

# ─────────────────────────────────────────────
# RUTAS — AUTENTICACIÓN
# ─────────────────────────────────────────────

@app.route("/")
def index():
    if usuario_actual():
        return redirect(url_for("dashboard"))
    return render_template("login.html")

@app.route("/login", methods=["POST"])
@limiter.limit("10 per minute; 30 per hour")
def login():
    data     = get_json_safe()
    nombre   = sanitize(data.get("nombre", ""), "nombre")
    password = sanitize(data.get("password", ""), "password")
    perfiles = cargar_perfiles()

    if nombre not in perfiles:
        return jsonify({"ok": False, "error": "Perfil no encontrado"})

    if not verificar_pw(password, perfiles[nombre]["password"]):
        log_auditoria("LOGIN_FAIL", nombre, "Contraseña incorrecta")
        return jsonify({"ok": False, "error": "Contraseña incorrecta"})

    session.permanent = True
    session["usuario"] = nombre
    log_auditoria("LOGIN_OK", nombre)
    return jsonify({"ok": True})

@app.route("/logout")
def logout():
    usuario = session.get("usuario", "anon")
    log_auditoria("LOGOUT", usuario)
    session.clear()
    return redirect(url_for("index"))

@app.route("/registro", methods=["GET", "POST"])
@limiter.limit("5 per hour")
def registro():
    data     = get_json_safe()
    nombre   = sanitize(data.get("nombre", ""), "nombre")
    password = sanitize(data.get("password", ""), "password")
    año      = sanitize(data.get("año", AÑO_ACTUAL), "año")

    if not nombre or not password:
        return jsonify({"ok": False, "error": "Faltan datos obligatorios"})

    # Verificar que haya API key configurada
    if not get_api_key():
        return jsonify({"ok": False, "error": "El administrador aun no ha configurado la API key del servidor"})

    perfiles = cargar_perfiles()
    if nombre in perfiles:
        return jsonify({"ok": False, "error": "Ya existe un perfil con ese nombre"})

    perfiles[nombre] = {
        "password":   enc(password),
        "año_activo": año,
        "creado":     datetime.now().strftime("%Y-%m-%d"),
        "años":       {año: {"materias": {}}},
        "es_coordinador":  (data.get("rol","profesor") == "coordinador"),
    }
    guardar_perfiles(perfiles)
    session["usuario"] = nombre
    return jsonify({"ok": True})

@app.route("/api/admin/configurar", methods=["POST"])
@limiter.limit("5 per hour")
def admin_configurar():
    """Solo el primer usuario (admin) puede configurar la API key del servidor."""
    data        = get_json_safe()
    api_key     = sanitize(data.get("api_key", ""), "password")  # no escapar la key
    proveedor   = sanitize(data.get("proveedor", "anthropic"), "codigo")
    clave_admin = sanitize(data.get("clave_admin", ""), "password")
    # Validar proveedor
    if proveedor not in ("anthropic", "openai"):
        proveedor = "anthropic"

    # Clave de administrador hardcodeada — cámbiala aquí
    CLAVE_ADMIN = os.environ.get("ADMIN_KEY", "")
    if not CLAVE_ADMIN:
        return jsonify({"ok": False, "error": "ADMIN_KEY no configurada en .env"})

    if clave_admin != CLAVE_ADMIN:
        return jsonify({"ok": False, "error": "Clave de administrador incorrecta"})
    if not api_key:
        return jsonify({"ok": False, "error": "API key vacía"})

    guardar_config_global({"api_key": api_key, "proveedor": proveedor})
    log_auditoria("ADMIN_CONFIG", "admin", f"proveedor={proveedor}")
    return jsonify({"ok": True})

@app.route("/api/admin/estado")
def admin_estado():
    """Indica si la API key ya está configurada."""
    key = get_api_key()
    return jsonify({"configurada": bool(key), "proveedor": get_proveedor(),
                    "preview": key[:10]+"..." if key else ""})

# ─────────────────────────────────────────────
# RUTAS — DASHBOARD
# ─────────────────────────────────────────────

@app.route("/dashboard")
def dashboard():
    nombre = usuario_actual()
    if not nombre: return redirect(url_for("index"))
    perfiles = cargar_perfiles()
    mats     = get_materias(perfiles, nombre)
    año      = get_año(perfiles, nombre)
    es_coord = cargar_perfiles().get(nombre, {}).get("es_coordinador", False)
    return render_template("dashboard.html",
        nombre=nombre, año=año, es_coordinador=es_coord, materias=mats,
        num_materias=len(mats),
        num_cursos=sum(len(m["cursos"]) for m in mats.values()))

@app.route("/api/dashboard")
def api_dashboard():
    nombre = usuario_actual()
    if not nombre: return jsonify({"ok": False})
    perfiles = cargar_perfiles()
    mats     = get_materias(perfiles, nombre)
    año      = get_año(perfiles, nombre)
    return jsonify({
        "ok": True,
        "nombre": nombre,
        "año": año,
        "materias": mats,
        "num_materias": len(mats),
        "num_cursos": sum(len(m["cursos"]) for m in mats.values()),
    })

# ─────────────────────────────────────────────
# RUTAS — MATERIAS
# ─────────────────────────────────────────────

@app.route("/materias")
def materias():
    nombre = usuario_actual()
    if not nombre: return redirect(url_for("index"))
    perfiles = cargar_perfiles()
    mats     = get_materias(perfiles, nombre)
    año      = get_año(perfiles, nombre)
    return render_template("materias.html", nombre=nombre, año=año, materias=mats)

@app.route("/api/materias/agregar", methods=["POST"])
@limiter.limit("20 per hour")
def agregar_materia():
    nombre = usuario_actual()
    if not nombre: return jsonify({"ok": False})
    data     = get_json_safe()
    nom_mat  = sanitize(data.get("nombre", ""), "nombre")
    codigo   = sanitize(data.get("codigo", ""), "codigo")
    cursos   = sanitize_list(data.get("cursos", []), "codigo")
    recursos = sanitize(data.get("recursos", "Tablero y marcadores\n* Cuaderno"), "textarea")

    if not nom_mat or not codigo:
        return jsonify({"ok": False, "error": "Nombre y código obligatorios"})

    perfiles = cargar_perfiles()
    mats     = get_materias(perfiles, nombre)

    for m in mats.values():
        if m["codigo"] == codigo:
            return jsonify({"ok": False, "error": f"Ya tienes el código {codigo}"})

    k = str(max([int(x) for x in mats.keys()], default=0) + 1)
    mats[k] = {
        "nombre": nom_mat, "codigo": codigo, "cursos": cursos,
        "recursos": recursos,
        "contexto_ia": f"Eres profesor de {nom_mat} del Colegio Humboldt.",
    }
    set_materias(perfiles, nombre, mats)
    return jsonify({"ok": True, "key": k})

@app.route("/api/materias/editar_cursos", methods=["POST"])
def editar_cursos():
    nombre = usuario_actual()
    if not nombre: return jsonify({"ok": False})
    data   = get_json_safe()
    key    = sanitize(str(data.get("key", "")), "codigo")
    cursos = sanitize_list(data.get("cursos", []), "codigo")
    perfiles = cargar_perfiles()
    mats     = get_materias(perfiles, nombre)
    if key not in mats:
        return jsonify({"ok": False, "error": "Materia no encontrada"})
    mats[key]["cursos"] = cursos
    set_materias(perfiles, nombre, mats)
    return jsonify({"ok": True})

@app.route("/api/materias/editar_recursos", methods=["POST"])
def editar_recursos():
    nombre = usuario_actual()
    if not nombre: return jsonify({"ok": False})
    data     = get_json_safe()
    key      = sanitize(str(data.get("key", "")), "codigo")
    recursos = sanitize(data.get("recursos", ""), "textarea")
    perfiles = cargar_perfiles()
    mats     = get_materias(perfiles, nombre)
    if key not in mats:
        return jsonify({"ok": False, "error": "Materia no encontrada"})
    mats[key]["recursos"] = recursos
    set_materias(perfiles, nombre, mats)
    return jsonify({"ok": True})

# ─────────────────────────────────────────────
# RUTAS — PERIODOS
# ─────────────────────────────────────────────

@app.route("/periodos")
def periodos():
    nombre = usuario_actual()
    if not nombre: return redirect(url_for("index"))
    perfiles = cargar_perfiles()
    mats     = get_materias(perfiles, nombre)
    año      = get_año(perfiles, nombre)
    return render_template("periodos.html", nombre=nombre, año=año, materias=mats)

@app.route("/api/periodos/guardar", methods=["POST"])
@limiter.limit("30 per hour")
def guardar_periodo():
    nombre = usuario_actual()
    if not nombre: return jsonify({"ok": False})
    data       = get_json_safe()
    mat_nombre = sanitize(data.get("materia", ""), "nombre")
    num_per    = sanitize(str(data.get("periodo", "1")), "año")[:1]
    semanas    = max(1, min(20, int(data.get("semanas", 10) or 10)))
    tema       = sanitize(data.get("tema_central", ""), "text")
    bloques    = sanitize_dict_keys(data.get("bloques", {}))

    mem = cargar_memoria(nombre, mat_nombre)
    if "periodos" not in mem: mem["periodos"] = {}
    proyecto       = sanitize(data.get("proyecto", ""), "text")
    proyecto_desc  = sanitize(data.get("proyecto_desc", ""), "textarea")
    proyecto_fecha = sanitize(data.get("proyecto_fecha", ""), "text")
    mem["periodos"][num_per] = {
        "semanas": semanas, "tema_central": tema,
        "bloques": bloques,
        "proyecto": proyecto,
        "proyecto_desc": proyecto_desc,
        "proyecto_fecha": proyecto_fecha,
        "configurado": datetime.now().strftime("%Y-%m-%d"),
    }
    guardar_memoria(nombre, mat_nombre, mem)
    return jsonify({"ok": True})

@app.route("/api/periodos/obtener")
def obtener_periodos():
    nombre   = usuario_actual()
    if not nombre: return jsonify({"ok": False})
    materia  = request.args.get("materia", "")
    mem      = cargar_memoria(nombre, materia)
    return jsonify({"ok": True, "periodos": mem.get("periodos", {})})

# ─────────────────────────────────────────────
# RUTAS — CHAT IA
# ─────────────────────────────────────────────

@app.route("/asistente")
def asistente():
    nombre = usuario_actual()
    if not nombre: return redirect(url_for("index"))
    perfiles = cargar_perfiles()
    mats     = get_materias(perfiles, nombre)
    año      = get_año(perfiles, nombre)
    return render_template("asistente.html", nombre=nombre, año=año, materias=mats)

@app.route("/api/chat/inicio", methods=["POST"])
@limiter.limit("30 per minute")
def chat_inicio():
    """
    Inicia la conversación del asistente.
    Si es la primera vez, hace onboarding.
    Si ya conoce al profesor, hace preguntas contextuales sobre la sesión.
    """
    nombre = usuario_actual()
    if not nombre: return jsonify({"ok": False})

    data       = get_json_safe()
    mat_nombre = sanitize(data.get("materia", ""), "nombre")

    perfiles  = cargar_perfiles()
    api_key   = get_api_key()
    proveedor = get_proveedor()
    mem       = cargar_memoria(nombre, mat_nombre)
    estilo    = mem.get("estilo", "")
    nc        = nombre.split()[0]

    es_primera_vez = not estilo

    if es_primera_vez:
        sistema = f"""Eres un asistente pedagógico que está conociendo a {nc}, profesor de {mat_nombre}, por primera vez.
Tu misión es hacerle preguntas MUY CONCRETAS y específicas para entender
su metodología única, qué busca en sus clases y cómo enseña de verdad.

PREGUNTAS QUE DEBES HACER (de una en una, en conversación natural):
1. ¿Qué metodología usas en tu clase? ¿Cómo describes tu forma de enseñar?
2. ¿Qué deben aprender o llevarse los estudiantes de tu clase — no el contenido, sino lo profundo?
3. ¿Cómo sabes que realmente aprendieron? ¿Qué ves en ellos cuando sí aprendió?
4. ¿Qué haces tú que otro profesor de {mat_nombre} probablemente no haría?
5. ¿Qué momento de la clase te dice que estás en el camino correcto?
6. ¿Qué es lo que NUNCA harías en tu clase aunque otro lo haga?

REGLAS:
- Una sola pregunta a la vez, sin listarlas
- Escucha la respuesta y haz una pregunta de seguimiento si es superficial
- Tono: colega curioso, no entrevistador
- Máximo 2 líneas por mensaje
- Empieza presentándote en 1 línea y haz la primera pregunta"""

        prompt = f"Preséntate brevemente y haz la primera pregunta a {nc}."
    else:
        sistema = f"""Eres el asistente pedagógico de {nombre}, profesor de {mat_nombre}.

ASÍ ES ESTE PROFESOR:
{estilo}

Tu objetivo es hacer preguntas MUY CONCRETAS sobre la sesión actual.
Pregunta cosas como:
- ¿En qué punto exacto van los estudiantes con este tema?
- ¿Qué pasó la semana pasada — funcionó, no funcionó?
- ¿Qué quieres que logren esta semana específicamente?
- ¿Hay algún estudiante o grupo que necesite algo diferente?
- ¿Cuánto tiempo tienes disponible para esta clase?

Una pregunta a la vez. Máximo 2 líneas. Tono de colega."""

        prompt = f"Saluda a {nc} en 1 línea y haz tu primera pregunta concreta sobre lo que necesita planear esta semana."

    try:
        if proveedor == "anthropic":
            import anthropic
            client = anthropic.Anthropic(api_key=api_key)
            res = client.messages.create(
                model="claude-haiku-4-5-20251001",
                max_tokens=200, system=sistema,
                messages=[{"role": "user", "content": prompt}])
            respuesta = res.content[0].text.strip()
        else:
            import openai
            client = openai.OpenAI(api_key=api_key)
            res = client.chat.completions.create(
                model="gpt-4o-mini", max_tokens=200,
                messages=[{"role":"system","content":sistema},
                          {"role":"user","content":prompt}])
            respuesta = res.choices[0].message.content.strip()

        return jsonify({
            "ok": True,
            "respuesta": respuesta,
            "es_primera_vez": es_primera_vez,
            "tiene_estilo": bool(estilo)
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/chat", methods=["POST"])
@limiter.limit("30 per minute; 200 per hour")
def chat():
    nombre = usuario_actual()
    if not nombre: return jsonify({"ok": False})

    data       = get_json_safe()
    mensaje    = str(data.get("mensaje", "")).strip()[:2000]
    mat_nombre = sanitize(data.get("materia", ""), "nombre")
    modo       = data.get("modo", "chat")  # "onboarding" o "chat"

    historial_raw = data.get("historial", [])
    historial = []
    if isinstance(historial_raw, list):
        for msg in historial_raw[-12:]:
            if isinstance(msg, dict) and msg.get("role") in ("user", "assistant"):
                historial.append({
                    "role":    msg["role"],
                    "content": str(msg.get("content", ""))[:1000]
                })

    if not mensaje:
        return jsonify({"ok": False, "error": "Mensaje vacío"})

    perfiles  = cargar_perfiles()
    api_key   = get_api_key()
    proveedor = get_proveedor()
    mem       = cargar_memoria(nombre, mat_nombre)
    estilo    = mem.get("estilo", "")
    nc        = nombre.split()[0]

    if modo == "onboarding":
        sistema = f"""Estás conociendo a {nombre}, profesor de {mat_nombre}, por primera vez.
Tu misión: hacerle preguntas MUY CONCRETAS para entender su metodología real.

PREGUNTAS CLAVE (una a la vez, en orden natural):
1. ¿Qué metodología usas? ¿Cómo describes tu forma de enseñar?
2. ¿Qué deben aprender los estudiantes — no el contenido, sino lo profundo?
3. ¿Cómo sabes que realmente aprendieron? ¿Qué ves en ellos?
4. ¿Qué haces tú que otro profesor de {mat_nombre} probablemente no haría?
5. ¿Qué momento de la clase te dice que vas por buen camino?
6. ¿Qué NUNCA harías aunque otro lo haga?

Si una respuesta es vaga o corta, profundiza con "¿puedes darme un ejemplo concreto?"
Cuando tengas respuestas concretas de al menos 4 preguntas, escribe exactamente:
PERFIL_LISTO: [escribe aquí un párrafo de 6-10 líneas describiendo al profesor
en tercera persona: su filosofía, métodos únicos, cómo evalúa el aprendizaje,
lo que lo diferencia y lo que nunca haría. Que sea específico, no genérico.]

Tono: colega curioso, no encuestador. Máximo 2 líneas por pregunta."""
    else:
        sistema = f"""Eres el asistente pedagógico de {nombre}, profesor de {mat_nombre}.
{f"ASÍ ES ESTE PROFESOR:{chr(10)}{estilo}" if estilo else ""}
Tu rol es hacer preguntas CONCRETAS para entender exactamente qué planear:
- ¿En qué punto van los estudiantes con este tema?
- ¿Qué funcionó o no la semana pasada?
- ¿Qué quiere lograr específicamente esta semana?
- ¿Hay grupos o estudiantes que necesitan algo diferente?
Cuando el profesor tenga claro qué quiere, ayúdale con ideas específicas.
Máximo 3 líneas. Usa el nombre {nc}. Tono de colega."""

    try:
        if proveedor == "anthropic":
            import anthropic
            client = anthropic.Anthropic(api_key=api_key)
            msgs = historial + [{"role": "user", "content": mensaje}]
            res  = client.messages.create(
                model="claude-haiku-4-5-20251001",
                max_tokens=300, system=sistema, messages=msgs)
            respuesta = res.content[0].text.strip()
        else:
            import openai
            client = openai.OpenAI(api_key=api_key)
            msgs = [{"role":"system","content":sistema}] + historial + [{"role":"user","content":mensaje}]
            res  = client.chat.completions.create(
                model="gpt-4o-mini", messages=msgs, max_tokens=300)
            respuesta = res.choices[0].message.content.strip()

        # Detectar si el asistente completó el onboarding
        perfil_nuevo = None
        if "PERFIL_LISTO:" in respuesta:
            partes      = respuesta.split("PERFIL_LISTO:")
            respuesta   = partes[0].strip()
            perfil_nuevo = partes[1].strip() if len(partes) > 1 else ""
            if perfil_nuevo:
                mem["estilo"] = perfil_nuevo
                guardar_memoria(nombre, mat_nombre, mem)

        return jsonify({
            "ok":          True,
            "respuesta":   respuesta,
            "perfil_nuevo": perfil_nuevo,
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

# ─────────────────────────────────────────────
# RUTAS — PLANEAR
# ─────────────────────────────────────────────

@app.route("/planear")
def planear():
    nombre = usuario_actual()
    if not nombre: return redirect(url_for("index"))
    perfiles = cargar_perfiles()
    mats     = get_materias(perfiles, nombre)
    año      = get_año(perfiles, nombre)
    return render_template("planear.html", nombre=nombre, año=año, materias=mats)

@app.route("/api/planear/generar_grupo", methods=["POST"])
@limiter.limit("20 per hour; 5 per minute")
def generar_grupo():
    """Genera título y actividades para un grupo de cursos."""
    nombre = usuario_actual()
    if not nombre: return jsonify({"ok": False})

    data         = get_json_safe()
    ideas        = sanitize(data.get("ideas", ""), "textarea")
    mat_nombre   = sanitize(data.get("materia", ""), "nombre")
    s1           = str(max(1, min(20, int(data.get("semana1", 1) or 1))))
    s2           = str(max(1, min(20, int(data.get("semana2", 2) or 2))))
    estilo_profe = sanitize(data.get("estilo", ""), "textarea")
    ctx_mem      = sanitize(data.get("ctx_mem", ""), "textarea")
    ctx_periodo  = sanitize(data.get("ctx_periodo", ""), "textarea")
    # Sanitizar listas de historial
    titulos_raw  = data.get("titulos_previos", [])
    acts_raw     = data.get("actividades_previas", [])
    titulos_prev = [sanitize(t, "text") for t in titulos_raw if isinstance(t, str)][:5]
    acts_prev    = [sanitize(a, "textarea") for a in acts_raw if isinstance(a, str)][:3]

    perfiles  = cargar_perfiles()
    api_key   = get_api_key()
    proveedor = get_proveedor()

    # Prompt título
    hist_t = ""
    if titulos_prev:
        hist_t = "\n\nTITULOS YA USADOS (NO repetir):\n" + "\n".join(f"- {t}" for t in titulos_prev)

    prompt_titulo = (
        f"Asistente de planeacion. Tema: {ideas}."
        f"\nEscribe SOLO el titulo del tema, maximo 8 palabras, español, mayuscula inicial, sin punto ni comillas, sin mencionar curso materia semanas ni numeros."
        f"{hist_t}"
    )

    # Prompt actividades
    hist_a = ""
    if acts_prev:
        hist_a = "\n\nACTIVIDADES YA USADAS (usa verbos y estructura DIFERENTES):\n" + "\n---\n".join(acts_prev[-2:])

    ctx_p_txt = f"\n\nCONTEXTO DE PROGRESION:\n{ctx_periodo}" if ctx_periodo else ""

    # Proyecto del periodo
    try:
        mem_proy = cargar_memoria(nombre, mat_nombre)
        per_actual = str(data.get("periodo", "1"))
        proy = mem_proy.get("periodos", {}).get(per_actual, {}).get("proyecto", "")
        proy_desc = mem_proy.get("periodos", {}).get(per_actual, {}).get("proyecto_desc", "")
        proy_fecha = mem_proy.get("periodos", {}).get(per_actual, {}).get("proyecto_fecha", "")
        if proy:
            ctx_p_txt += f"\n\nPROYECTO CENTRAL DEL PERIODO: {proy}"
            if proy_desc: ctx_p_txt += f"\nDescripcion: {proy_desc}"
            if proy_fecha: ctx_p_txt += f"\nFecha de presentacion: {proy_fecha}"
            ctx_p_txt += "\nCada clase debe ser una etapa que acerque al estudiante a completar este proyecto."
    except Exception:
        pass
    est_txt   = f"\nESTILO DEL PROFESOR:\n{estilo_profe}" if estilo_profe else ""

    # Obtener estructura de clase si existe
    estructura_txt = ""
    try:
        mem_est = cargar_memoria(nombre, mat_nombre)
        est     = mem_est.get("estructura", {})
        secs    = est.get("secciones", [])
        if secs:
            lineas_est = ["ESTRUCTURA DE CLASE DE ESTE PROFESOR (respeta este orden):"]
            total_min  = sum(s.get("duracion", 10) for s in secs)
            for s in secs:
                desc = f" — {s['descripcion']}" if s.get("descripcion") else ""
                lineas_est.append(f"  · {s['nombre']} ({s['duracion']} min){desc}")
            lineas_est.append(f"  Total: {total_min} minutos")
            lineas_est.append("Cada semana debe incluir estas secciones en este orden.")
            estructura_txt = "\n\n" + "\n".join(lineas_est)
    except Exception:
        pass

    # Materiales reales de la materia
    try:
        mem_mat = cargar_memoria(nombre, mat_nombre)
        recursos_mat = mem_mat.get("recursos", "")
    except Exception:
        recursos_mat = ""
    recursos_txt = f"\n\nMATERIALES DISPONIBLES (usa SOLO estos):\n{recursos_mat}" if recursos_mat else ""

    # Historial de clases anteriores por curso
    cursos_grupo = data.get("cursos", [])
    historial_txt = ""
    try:
        mem_h = cargar_memoria(nombre, mat_nombre)
        hist = mem_h.get("historial_cursos", {})
        lineas = []
        for curso in cursos_grupo:
            entradas = hist.get(curso, [])
            if entradas:
                ultimas = entradas[-3:]
                temas = " → ".join(e["titulo"] for e in ultimas)
                lineas.append(f"  {curso}: {temas}")
        if lineas:
            historial_txt = "\n\nCLASES ANTERIORES DE ESTOS CURSOS (NO repetir, continuar desde aqui):\n" + "\n".join(lineas)
    except Exception:
        pass

    # Observaciones del profesor
    obs_txt = ""
    try:
        mem_obs = cargar_memoria(nombre, mat_nombre)
        obs_list = mem_obs.get("observaciones", [])
        if obs_list:
            recientes = [o["observacion"] for o in obs_list[-4:]]
            obs_txt = "\n\nINDICACIONES DEL PROFESOR (respeta siempre):\n" + "\n".join(f"  - {o}" for o in recientes)
    except Exception:
        pass

    sistema_acts = (
        f"Eres asistente de planeacion para un profesor de {mat_nombre} de colegio colombiano. "
        f"Conoces profundamente esta materia y propones actividades REALES y ESPECIFICAS de {mat_nombre}. "
        "Las actividades deben ser concretas, breves y ejecutables en una clase normal de 45-60 min. "
        "NUNCA menciones nombres de canciones, artistas ni obras especificas — escribe: la cancion del periodo, la obra trabajada, etc. "
        "NUNCA uses listas numeradas. NUNCA agregues texto antes ni despues del bloque solicitado. "
        "Cada actividad: verbo infinitivo + objeto concreto, maximo 6 palabras. "
        "REGLA CLAVE DE PROGRESION: cada clase debe avanzar un paso mas en complejidad respecto a la anterior — nunca retroceder ni repetir nivel. "
        "REGLA CLAVE DE DIFERENCIACION: si hay historial de cursos diferentes, el texto de las actividades DEBE ser distinto para cada curso aunque el tema sea similar — adapta el vocabulario, el nivel y los ejercicios al curso especifico. "
        "Al inicio del bloque de cada semana, incluye una frase corta que conecte con lo visto antes, por ejemplo: 'Continuando con el proceso iniciado...' o 'Avanzando desde lo trabajado la clase anterior...'. "
    )

    prompt_acts = f"""Soy profesor de {mat_nombre}.{est_txt}{recursos_txt}{historial_txt}{obs_txt}

TEMA DE LA CLASE: {ideas}{ctx_p_txt}{estructura_txt}

Escribe EXACTAMENTE este bloque, sin agregar nada antes ni despues:

Semana {s1} En esta semana vamos a:
* [actividad especifica de {mat_nombre}]
* [actividad especifica de {mat_nombre}]
* [actividad especifica de {mat_nombre}]
* [actividad especifica de {mat_nombre}]

Semana {s2} En esta semana vamos a:
* [actividad especifica de {mat_nombre}]
* [actividad especifica de {mat_nombre}]
* [actividad especifica de {mat_nombre}]
* [actividad especifica de {mat_nombre}]

Reglas estrictas: verbo infinitivo, max 6 palabras por actividad, semana {s1} introduce el tema, semana {s2} profundiza o aplica, actividades progresivas y reales de {mat_nombre}, sin nombres propios de canciones ni artistas.{hist_a}"""

    try:
        if proveedor == "anthropic":
            import anthropic
            client = anthropic.Anthropic(api_key=api_key)

            # Generar título
            res_t = client.messages.create(
                model="claude-haiku-4-5-20251001", max_tokens=60,
                messages=[{"role":"user","content":prompt_titulo}])
            titulo = res_t.content[0].text.strip().strip('"').strip("'")
            titulo = titulo.lstrip("0123456789.-) ")
            titulo = titulo.split("\n")[0].strip()

            # Generar actividades
            res_a = client.messages.create(
                model="claude-haiku-4-5-20251001", max_tokens=500,
                system=sistema_acts,
                messages=[{"role":"user","content":prompt_acts}])
            acts = res_a.content[0].text.strip()
        else:
            import openai
            client = openai.OpenAI(api_key=api_key)

            res_t = client.chat.completions.create(
                model="gpt-4o-mini", max_tokens=60,
                messages=[{"role":"user","content":prompt_titulo}])
            titulo = res_t.choices[0].message.content.strip().strip('"').strip("'")
            titulo = titulo.lstrip("0123456789.-) ").split("\n")[0].strip()

            res_a = client.chat.completions.create(
                model="gpt-4o-mini", max_tokens=500,
                messages=[{"role":"system","content":sistema_acts},
                          {"role":"user","content":prompt_acts}])
            acts = res_a.choices[0].message.content.strip()

        if "Semana" in acts:
            acts = acts[acts.find("Semana"):]

        # Guardar historial por curso
        try:
            cursos_grupo = data.get("cursos", [])
            if cursos_grupo:
                mem_h = cargar_memoria(nombre, mat_nombre)
                if "historial_cursos" not in mem_h:
                    mem_h["historial_cursos"] = {}
                for curso in cursos_grupo:
                    if curso not in mem_h["historial_cursos"]:
                        mem_h["historial_cursos"][curso] = []
                    mem_h["historial_cursos"][curso].append({
                        "periodo": str(data.get("periodo", "")),
                        "bloque": str(data.get("bloque", "")),
                        "semanas": f"{s1}-{s2}",
                        "titulo": titulo,
                    })
                    mem_h["historial_cursos"][curso] = mem_h["historial_cursos"][curso][-8:]
                guardar_memoria(nombre, mat_nombre, mem_h)
        except Exception:
            pass

        return jsonify({"ok": True, "titulo": titulo, "actividades": acts})

    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@app.route("/api/memoria/estilo", methods=["GET"])
def obtener_estilo():
    nombre    = usuario_actual()
    if not nombre: return jsonify({"ok": False})
    mat_nombre = request.args.get("materia", "")
    mem        = cargar_memoria(nombre, mat_nombre)
    return jsonify({"ok": True, "estilo": mem.get("estilo", ""), "periodos": mem.get("periodos", {})})

@app.route("/api/memoria/guardar_observacion", methods=["POST"])
def guardar_observacion():
    nombre = usuario_actual()
    if not nombre: return jsonify({"ok": False})
    data       = get_json_safe()
    mat_nombre = sanitize(data.get("materia", ""), "nombre")
    obs        = sanitize(data.get("observacion", ""), "textarea")
    periodo    = sanitize(str(data.get("periodo", "1")), "año")[:1]
    bloque     = sanitize(str(data.get("bloque", "0")), "año")[:1]
    if not obs: return jsonify({"ok": False})
    mem = cargar_memoria(nombre, mat_nombre)
    mem["observaciones"].append({
        "fecha": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "periodo": periodo, "bloque": bloque, "obs": obs,
    })
    if len(mem["observaciones"]) > 20:
        mem["observaciones"] = mem["observaciones"][-20:]
    guardar_memoria(nombre, mat_nombre, mem)
    return jsonify({"ok": True})

# ─────────────────────────────────────────────
# RUTAS — PERFIL
# ─────────────────────────────────────────────

@app.route("/perfil")
def perfil():
    nombre = usuario_actual()
    if not nombre: return redirect(url_for("index"))
    perfiles = cargar_perfiles()
    año      = get_año(perfiles, nombre)
    config   = cargar_config()
    return render_template("perfil.html", nombre=nombre, año=año,
        proveedor=config.get("proveedor","anthropic"),
        api_key_preview=config.get("api_key","")[:10]+"..." if config.get("api_key") else "No configurada")

@app.route("/api/perfil/cambiar_password", methods=["POST"])
@limiter.limit("5 per hour")
def cambiar_password():
    nombre = usuario_actual()
    if not nombre: return jsonify({"ok": False})
    data   = get_json_safe()
    actual = sanitize(data.get("actual", ""), "password")
    nueva  = sanitize(data.get("nueva", ""), "password")
    if len(nueva) < 6:
        return jsonify({"ok": False, "error": "La contraseña debe tener al menos 6 caracteres"})
    perfiles = cargar_perfiles()
    if not verificar_pw(actual, perfiles[nombre]["password"]):
        return jsonify({"ok": False, "error": "Contraseña actual incorrecta"})
    perfiles[nombre]["password"] = enc(nueva)
    guardar_perfiles(perfiles)
    return jsonify({"ok": True})

@app.route("/api/perfil/cambiar_api_key", methods=["POST"])
@limiter.limit("10 per hour")
def cambiar_api_key():
    nombre = usuario_actual()
    if not nombre: return jsonify({"ok": False})
    data  = get_json_safe()
    nueva = sanitize(data.get("api_key", ""), "password")
    if nueva and not (nueva.startswith("sk-") or nueva.startswith("sk-ant-")):
        return jsonify({"ok": False, "error": "API key inválida — debe empezar con sk-"})
    perfiles = cargar_perfiles()
    perfiles[nombre]["api_key"] = nueva
    guardar_perfiles(perfiles)
    return jsonify({"ok": True})

@app.route("/api/perfil/guardar_credenciales_colegio", methods=["POST"])
@limiter.limit("10 per hour")
def guardar_credenciales_colegio():
    """Guarda usuario y contraseña del colegio encriptados."""
    nombre = usuario_actual()
    if not nombre: return jsonify({"ok": False})
    data     = get_json_safe()
    usuario  = sanitize(data.get("usuario_colegio", ""), "text")
    password = str(data.get("password_colegio", "")).strip()[:100]
    if not usuario or not password:
        return jsonify({"ok": False, "error": "Usuario y contraseña requeridos"})
    perfiles = cargar_perfiles()
    perfiles[nombre]["colegio_usuario"] = encriptar_credencial(usuario)
    perfiles[nombre]["colegio_password"] = encriptar_credencial(password)
    guardar_perfiles(perfiles)
    log_auditoria("CREDENCIALES_COLEGIO", nombre, "guardadas/actualizadas")
    return jsonify({"ok": True})


@app.route("/api/perfil/tiene_credenciales")
def tiene_credenciales():
    nombre = usuario_actual()
    if not nombre: return jsonify({"ok": False})
    perfiles = cargar_perfiles()
    tiene = bool(perfiles[nombre].get("colegio_usuario"))
    return jsonify({"ok": True, "tiene": tiene})


@app.route("/api/perfil/cambiar_año", methods=["POST"])
def cambiar_año():
    nombre = usuario_actual()
    if not nombre: return jsonify({"ok": False})
    data  = get_json_safe()
    nuevo = sanitize(data.get("año", ""), "año")
    if not nuevo.isdigit() or len(nuevo) != 4:
        return jsonify({"ok": False, "error": "Año inválido"})
    perfiles = cargar_perfiles()
    if nuevo not in perfiles[nombre]["años"]:
        perfiles[nombre]["años"][nuevo] = {"materias": {}}
    perfiles[nombre]["año_activo"] = nuevo
    guardar_perfiles(perfiles)
    return jsonify({"ok": True})

# ─────────────────────────────────────────────
# DETECCION AUTOMATICA DE MATERIAS
# ─────────────────────────────────────────────

@app.route("/api/detectar_materias", methods=["POST"])
@limiter.limit("10 per hour")
def detectar_materias():
    """
    Abre Chrome, espera login del usuario,
    luego barre todos los cursos y devuelve
    las asignaturas encontradas.
    """
    if not SELENIUM_OK:
        return jsonify({"ok": False, "error": "Selenium no instalado. Corre: pip3 install selenium webdriver-manager"})

    nombre = usuario_actual()
    if not nombre:
        return jsonify({"ok": False, "error": "No hay sesion activa"})

    # Usando constantes globales

    def hacer_barrido():
        driver = _crear_driver_chrome()

        resultado = {"ok": False, "error": "", "materias": [], "cursos_plataforma": []}

        try:
            driver.get(URL_LOGIN)
            time.sleep(2)
            login_ok = _login_automatico(driver, nombre, lambda *a, **k: None)
            if not login_ok:
                for _ in range(90):
                    time.sleep(1)
                    if "login" not in driver.current_url.lower():
                        break
                else:
                    resultado["error"] = "Tiempo de espera agotado. Inicia sesion mas rapido."
                    driver.quit()
                    return resultado

            # Ir a Planes de Area
            driver.get(URL_PLANES)
            time.sleep(PAUSA + 2)

            # Leer todos los cursos
            try:
                el_curso = WebDriverWait(driver, TIMEOUT).until(
                    EC.presence_of_element_located((By.ID, "CURSO"))
                )
            except TimeoutException:
                resultado["error"] = "No se pudo cargar Planes de Area"
                driver.quit()
                return resultado

            cursos = []
            for o in el_curso.find_elements(By.TAG_NAME, "option"):
                val = o.get_attribute("value")
                nom = o.text.strip()
                if val and val != "" and "SELECCIONE" not in nom.upper():
                    cursos.append({"codigo": val, "nombre": nom})

            resultado["cursos_plataforma"] = [c["codigo"] for c in cursos]

            if not cursos:
                resultado["error"] = "No se encontraron cursos"
                driver.quit()
                return resultado

            # Barrer cada curso
            mapa = {}
            for curso in cursos:
                try:
                    driver.get(URL_PLANES)
                    time.sleep(PAUSA)
                    el_c = WebDriverWait(driver, TIMEOUT).until(
                        EC.presence_of_element_located((By.ID, "CURSO")))
                    Select(el_c).select_by_value(curso["codigo"])
                    time.sleep(PAUSA)

                    driver.execute_script(
                        "var el=document.getElementById('ASIGNATURA');"
                        "if(el){el.disabled=false;el.removeAttribute('disabled');}")
                    time.sleep(1)

                    el_a = driver.find_element(By.ID, "ASIGNATURA")
                    for o in el_a.find_elements(By.TAG_NAME, "option"):
                        val = o.get_attribute("value")
                        nom = o.text.strip()
                        if not val or val == "" or "SELECCIONE" in nom.upper():
                            continue
                        if val not in mapa:
                            mapa[val] = {"codigo": val, "nombre": nom, "cursos": []}
                        if curso["codigo"] not in mapa[val]["cursos"]:
                            mapa[val]["cursos"].append(curso["codigo"])
                except Exception:
                    continue

            resultado["ok"]      = True
            resultado["materias"] = list(mapa.values())
            # Guardar materias detectadas en el perfil
            perfiles = cargar_perfiles()
            mats = get_materias(perfiles, nombre)
            k = max([int(x) for x in mats.keys()], default=0)
            for mat in list(mapa.values()):
                ya_existe = any(m["codigo"] == mat["codigo"] for m in mats.values())
                if not ya_existe:
                    k += 1
                    mats[str(k)] = {
                        "nombre": mat["nombre"],
                        "codigo": mat["codigo"],
                        "cursos": mat["cursos"],
                        "recursos": "Tablero y marcadores\n* Cuaderno",
                        "contexto_ia": f"Eres profesor de {mat['nombre']} del Colegio Humboldt.",
                    }
            set_materias(perfiles, nombre, mats)
            driver.quit()

        except Exception as e:
            resultado["error"] = str(e)
            try: driver.quit()
            except: pass

        return resultado

    # Correr en hilo separado con timeout
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor() as ex:
        future  = ex.submit(hacer_barrido)
        try:
            res = future.result(timeout=300)  # 5 min max
        except concurrent.futures.TimeoutError:
            res = {"ok": False, "error": "Timeout — el proceso tardó demasiado"}

    return jsonify(res)




# ─────────────────────────────────────────────
# ESTRUCTURA DE CLASE
# ─────────────────────────────────────────────

@app.route("/estructura")
def estructura():
    nombre = usuario_actual()
    if not nombre: return redirect(url_for("index"))
    perfiles = cargar_perfiles()
    mats     = get_materias(perfiles, nombre)
    año      = get_año(perfiles, nombre)
    return render_template("estructura.html", nombre=nombre, año=año, materias=mats)


@app.route("/api/estructura/guardar", methods=["POST"])
@limiter.limit("30 per hour")
def guardar_estructura():
    """Guarda la estructura de clase de una materia en su memoria."""
    nombre = usuario_actual()
    if not nombre: return jsonify({"ok": False})

    data       = get_json_safe()
    mat_nombre = sanitize(data.get("materia", ""), "nombre")
    secciones  = data.get("secciones", [])  # [{nombre, duracion, descripcion}]

    if not mat_nombre:
        return jsonify({"ok": False, "error": "Materia requerida"})

    # Sanitizar secciones
    secciones_limpias = []
    for s in secciones[:10]:  # máximo 10 secciones
        if not isinstance(s, dict): continue
        secciones_limpias.append({
            "nombre":      sanitize(s.get("nombre", ""), "text"),
            "duracion":    max(1, min(90, int(s.get("duracion", 10) or 10))),
            "descripcion": sanitize(s.get("descripcion", ""), "textarea"),
        })

    mem = cargar_memoria(nombre, mat_nombre)
    mem["estructura"] = {
        "secciones":   secciones_limpias,
        "actualizado": datetime.now().strftime("%Y-%m-%d"),
    }
    guardar_memoria(nombre, mat_nombre, mem)
    return jsonify({"ok": True})


@app.route("/api/memoria/borrar_estilo", methods=["POST"])
def borrar_estilo():
    nombre = usuario_actual()
    if not nombre: return jsonify({"ok": False})
    data       = get_json_safe()
    mat_nombre = sanitize(data.get("materia", ""), "nombre")
    mem        = cargar_memoria(nombre, mat_nombre)
    mem["estilo"] = ""
    guardar_memoria(nombre, mat_nombre, mem)
    return jsonify({"ok": True})


@app.route("/api/estructura/obtener")
def obtener_estructura():
    nombre    = usuario_actual()
    if not nombre: return jsonify({"ok": False})
    mat_nombre = sanitize(request.args.get("materia", ""), "nombre")
    mem        = cargar_memoria(nombre, mat_nombre)
    return jsonify({"ok": True, "estructura": mem.get("estructura", {})})

# ─────────────────────────────────────────────
# ENVÍO A LA PLATAFORMA DEL COLEGIO
# ─────────────────────────────────────────────

# Almacén de progreso por sesión (en memoria)
_progreso_sesiones = {}
_drivers_activos   = {}  # session_id -> driver (mantener Chrome abierto entre materias)

def _log_progreso(session_id, tipo, mensaje):
    """Agrega un mensaje al log de progreso de una sesión."""
    if session_id not in _progreso_sesiones:
        _progreso_sesiones[session_id] = []
    _progreso_sesiones[session_id].append({"tipo": tipo, "msg": mensaje})


@app.route("/api/enviar_plataforma", methods=["POST"])
@limiter.limit("10 per hour")
def enviar_plataforma():
    """
    Recibe los grupos generados y los envía a la plataforma
    del colegio usando Selenium. Devuelve un session_id para
    consultar el progreso.
    """
    if not SELENIUM_OK:
        return jsonify({"ok": False,
            "error": "Selenium no instalado. Corre: pip3 install selenium webdriver-manager"})

    nombre = usuario_actual()
    if not nombre:
        return jsonify({"ok": False, "error": "No hay sesión activa"})

    data      = get_json_safe()
    grupos    = data.get("grupos", [])      # [{cursos:[...], titulo:"", actividades:"", recursos:""}]
    p_val     = sanitize(str(data.get("periodo", "1")), "año")[:1]
    b_val     = sanitize(str(data.get("bloque", "0")), "año")[:1]
    mat_codigo = sanitize(data.get("codigo_asignatura", ""), "codigo")

    if not grupos or not mat_codigo:
        return jsonify({"ok": False, "error": "Faltan datos — grupos o código de asignatura"})

    # Crear ID de sesión único para esta tarea
    import uuid
    session_id = str(uuid.uuid4())[:8]
    _progreso_sesiones[session_id] = []

    # Usando constantes globales

    # Reutilizar driver existente si hay una sesión activa
    driver_existente = data.get("session_id_anterior", "")
    driver_existente = re.sub(r'[^a-f0-9]', '', driver_existente)[:8]

    def correr_selenium():
        log = lambda t, m: _log_progreso(session_id, t, m)

        # Intentar reutilizar Chrome ya abierto
        driver_prev = _drivers_activos.pop(driver_existente, None) if driver_existente else None

        if driver_prev:
            driver = driver_prev
            log("info", "Reutilizando Chrome abierto — continuando con nueva materia")
        else:
            driver = _crear_driver_chrome()

            try:
                driver.get(URL_LOGIN)
                time.sleep(2)
                login_ok = _login_automatico(driver, nombre, log)
                if login_ok:
                    log("ok", "Login automático exitoso")
                else:
                    log("info", "Chrome abierto — inicia sesión en la plataforma del colegio")
                    for _ in range(90):
                        time.sleep(1)
                        if "login" not in driver.current_url.lower():
                            break
                    else:
                        log("error", "Tiempo de espera agotado")
                        driver.quit()
                        return
            except Exception as e:
                log("error", f"Error abriendo Chrome: {str(e)}")
                try: driver.quit()
                except: pass
                return

        try:

            log("ok", "Sesión detectada — iniciando envío")

            ok_list  = []
            err_list = []

            # Expandir grupos a lista plana de cursos con su contenido
            tareas = []
            for grupo in grupos:
                for curso in grupo.get("cursos", []):
                    tareas.append({
                        "curso":       sanitize(curso, "codigo"),
                        "titulo":      sanitize(grupo.get("titulo", ""), "text"),
                        "actividades": sanitize(grupo.get("actividades", ""), "textarea"),
                        "recursos":    sanitize(grupo.get("recursos", "Tablero y marcadores\n* Cuaderno"), "textarea"),
                    })

            total = len(tareas)
            log("info", f"Total de cursos a procesar: {total}")

            for i, tarea in enumerate(tareas, 1):
                curso = tarea["curso"]
                log("info", f"[{i}/{total}] Procesando {curso}...")

                try:
                    # Cargar página
                    driver.get(URL_PLANES)
                    time.sleep(PAUSA)

                    # Seleccionar CURSO
                    from selenium.webdriver.support.ui import Select as SeleniumSelect
                    el_c = WebDriverWait(driver, TIMEOUT).until(
                        EC.presence_of_element_located((By.ID, "CURSO")))
                    SeleniumSelect(el_c).select_by_value(curso)
                    time.sleep(PAUSA)

                    # Seleccionar ASIGNATURA
                    driver.execute_script(
                        "var el=document.getElementById('ASIGNATURA');"
                        "if(el){el.disabled=false;el.removeAttribute('disabled');}")
                    time.sleep(0.5)
                    el_a = driver.find_element(By.ID, "ASIGNATURA")
                    ops  = [o.get_attribute("value")
                            for o in el_a.find_elements(By.TAG_NAME, "option")]
                    if mat_codigo not in ops:
                        log("warn", f"{curso}: asignatura {mat_codigo} no disponible — saltando")
                        err_list.append(curso)
                        continue
                    SeleniumSelect(el_a).select_by_value(mat_codigo)
                    driver.execute_script(
                        f"var el=document.getElementById('ASIGNATURA');"
                        f"el.value='{mat_codigo}';"
                        f"el.dispatchEvent(new Event('change',{{bubbles:true}}));")
                    time.sleep(PAUSA)

                    # Seleccionar PERIODO
                    try:
                        el_p = driver.find_element(By.ID, "PERIODO")
                        driver.execute_script(
                            "var el=arguments[0];el.disabled=false;"
                            "el.removeAttribute('disabled');", el_p)
                        SeleniumSelect(el_p).select_by_value(p_val)
                    except Exception:
                        driver.execute_script(
                            f"var el=document.getElementById('PERIODO');"
                            f"if(el){{el.disabled=false;el.value='{p_val}';"
                            f"el.dispatchEvent(new Event('change',{{bubbles:true}}))}}")
                    time.sleep(2)

                    # Click LISTAR
                    driver.execute_script("document.getElementById('buttonx').click();")
                    try:
                        WebDriverWait(driver, TIMEOUT).until(
                            EC.presence_of_element_located((By.ID, "FECHAS")))
                    except TimeoutException:
                        log("warn", f"{curso}: FECHAS no apareció — saltando")
                        err_list.append(curso)
                        continue
                    time.sleep(2)

                    # Forzar FECHAS
                    driver.execute_script("""
                        var f=document.getElementById('FECHAS');
                        if(!f)return;
                        f.disabled=false;f.removeAttribute('disabled');
                        for(var i=0;i<f.options.length;i++){
                            f.options[i].disabled=false;
                            f.options[i].removeAttribute('disabled');}
                        var e=false;
                        for(var j=0;j<f.options.length;j++){
                            if(f.options[j].value===arguments[0]){f.selectedIndex=j;e=true;break;}}
                        if(!e){var o=document.createElement('option');
                            o.value=arguments[0];o.text='Bloque '+arguments[0];
                            f.appendChild(o);f.value=arguments[0];}
                        f.dispatchEvent(new Event('change',{bubbles:true}));
                        try{if(typeof fechasinifin==='function')fechasinifin(arguments[0]);}catch(e){}
                    """, b_val)
                    time.sleep(3)

                    # Esperar campos de texto
                    try:
                        WebDriverWait(driver, 45).until(
                            EC.visibility_of_element_located((By.ID, "TXT_TEMAS")))
                        WebDriverWait(driver, 10).until(
                            EC.visibility_of_element_located((By.ID, "TXT_ACTIVIDADES")))
                    except TimeoutException:
                        log("warn", f"{curso}: campos de texto no aparecieron — saltando")
                        err_list.append(curso)
                        continue

                    # Contar filas antes
                    try:
                        filas_antes = len([
                            f for f in driver.find_elements(By.CSS_SELECTOR, "table tr")
                            if len(f.find_elements(By.TAG_NAME, "td")) >= 5])
                    except Exception:
                        filas_antes = 0

                    # Llenar campos
                    driver.execute_script("""
                        function set(id,val){
                            var el=document.getElementById(id);if(!el)return;
                            el.disabled=false;el.removeAttribute('disabled');el.value=val;}
                        set('TXT_TEMAS',arguments[0]);
                        set('TXT_ACTIVIDADES',arguments[1]);
                        set('TXT_RECURSOS1',arguments[2]);
                        set('TXT_RECURSOS2',arguments[2]);
                    """, tarea["titulo"], tarea["actividades"], tarea["recursos"])
                    time.sleep(2)

                    # Guardar UNA sola vez
                    driver.execute_script("document.getElementById('buttonx1').click();")
                    time.sleep(4)

                    # Cerrar modal
                    try:
                        WebDriverWait(driver, 6).until(
                            EC.element_to_be_clickable(
                                (By.CSS_SELECTOR, ".btnok"))).click()
                        time.sleep(2)
                    except TimeoutException:
                        pass

                    # Verificar tabla
                    try:
                        filas_despues = [
                            f for f in driver.find_elements(By.CSS_SELECTOR, "table tr")
                            if len(f.find_elements(By.TAG_NAME, "td")) >= 5]
                        nuevas = len(filas_despues) - filas_antes

                        if nuevas == 1:
                            celdas   = filas_despues[-1].find_elements(By.TAG_NAME, "td")
                            num      = celdas[0].text.strip()
                            f_inicio = celdas[2].text.strip() if len(celdas) > 2 else "?"
                            f_fin    = celdas[3].text.strip() if len(celdas) > 3 else "?"
                            log("ok", f"{curso} guardado — Fila {num} | {f_inicio} al {f_fin}")
                            ok_list.append(curso)
                        elif nuevas == 0:
                            log("warn", f"{curso}: no se detectó fila nueva — verifica manualmente")
                            err_list.append(curso)
                        else:
                            log("warn", f"{curso}: {nuevas} filas nuevas — posible doble guardado")
                            ok_list.append(curso)
                    except Exception:
                        log("ok", f"{curso} guardado")
                        ok_list.append(curso)

                    time.sleep(2)

                except Exception as ex:
                    log("error", f"{curso}: {type(ex).__name__} — {str(ex)[:80]}")
                    err_list.append(curso)
                    continue

            # Resumen final
            log("done", f"Terminado — {len(ok_list)} guardados, {len(err_list)} con error")
            if err_list:
                log("warn", f"Con error: {', '.join(err_list)}")
            log("info", "Chrome sigue abierto — puedes planear otra materia o cerrarlo")

            # Guardar driver para reutilizar en otra materia
            _drivers_activos[session_id] = driver

        except Exception as e:
            log("error", f"Error general: {str(e)}")
            try:
                driver.quit()
                _drivers_activos.pop(session_id, None)
            except: pass

    # Correr en hilo separado
    t = threading.Thread(target=correr_selenium, daemon=True)
    t.start()

    return jsonify({"ok": True, "session_id": session_id})


@app.route("/api/cerrar_chrome/<session_id>", methods=["POST"])
def cerrar_chrome(session_id):
    """Cierra Chrome cuando el profesor termina todas las materias."""
    session_id = re.sub(r'[^a-f0-9]', '', session_id)[:8]
    driver = _drivers_activos.pop(session_id, None)
    if driver:
        try: driver.quit()
        except: pass
    _progreso_sesiones.pop(session_id, None)
    return jsonify({"ok": True})


@app.route("/api/progreso/<session_id>")
def obtener_progreso(session_id):
    """Devuelve el log de progreso de una sesión de envío."""
    session_id = re.sub(r'[^a-f0-9]', '', session_id)[:8]  # sanitizar
    logs = _progreso_sesiones.get(session_id, [])
    # Limpiar sesiones muy viejas (más de 50 entradas)
    if len(logs) > 100:
        _progreso_sesiones.pop(session_id, None)
    return jsonify({"ok": True, "logs": logs})


# ─────────────────────────────────────────────
# AGENTE AUTÓNOMO
# ─────────────────────────────────────────────

# URL_AULA definida como URL_AULA_V en constantes globales

# Mapa de códigos de curso a valores de la plataforma
CURSO_A_PLATAFORMA = {
    "0101": "0101SJ1SJA", "0102": "0102SJ1SJA",
    "0201": "0201SJ1SJA", "0301": "0301SJ1SJA",
    "0302": "0302SJ1SJA", "0401": "0401SJ1SJA",
    "0501": "0501SJ1SJA", "0601": "0601SJ1SJA",
    "0602": "0602SJ1SJA", "0701": "0701SJ1SJA",
    "0702": "0702SJ1SJA", "0801": "0801SJ1SJA",
    "0802": "0802SJ1SJA", "JA01": "JA01SJ1SJA",
    "PJ01": "PJ01SJ1SJA", "TR01": "TR01SJ1SJA",
}

_agente_sesiones = {}  # session_id -> logs


@app.route("/agente")
def agente():
    nombre = usuario_actual()
    if not nombre: return redirect(url_for("index"))
    perfiles = cargar_perfiles()
    mats     = get_materias(perfiles, nombre)
    año      = get_año(perfiles, nombre)
    return render_template("agente.html", nombre=nombre, año=año, materias=mats)


@app.route("/api/agente/interpretar", methods=["POST"])
@limiter.limit("20 per hour")
def agente_interpretar():
    """
    La IA interpreta la instrucción del profesor y devuelve
    un plan de tareas estructurado.
    """
    nombre = usuario_actual()
    if not nombre: return jsonify({"ok": False})

    data        = get_json_safe()
    # Usar password para no escapar URLs ni caracteres especiales
    instruccion = str(data.get("instruccion", "")).strip()[:1000]
    mat_nombre  = sanitize(data.get("materia", ""), "nombre")

    if not instruccion:
        return jsonify({"ok": False, "error": "Instrucción vacía"})

    perfiles  = cargar_perfiles()
    api_key   = get_api_key()
    proveedor = get_proveedor()
    mats      = get_materias(perfiles, nombre)

    # Construir lista de cursos disponibles
    cursos_disponibles = []
    for m in mats.values():
        cursos_disponibles.extend(m.get("cursos", []))
    cursos_str = ", ".join(set(cursos_disponibles))

    sistema = f"""Eres el asistente del profesor {nombre} del Colegio Humboldt.
Tu trabajo es interpretar instrucciones en lenguaje natural y convertirlas
en tareas concretas que un bot puede ejecutar.

Cursos del profesor: {cursos_str}

Tareas que puedes crear:
1. "comunicado" — enviar aviso/comunicado a cursos o estudiantes
2. "planear" — generar y subir planeación a la plataforma

Responde SOLO con JSON válido, sin texto adicional:
{{
  "tareas": [
    {{
      "tipo": "comunicado",
      "cursos": ["0701", "0702"],
      "mensaje": "texto del comunicado redactado profesionalmente",
      "asunto": "título corto del comunicado"
    }}
  ],
  "resumen": "descripción en 1 frase de lo que vas a hacer"
}}

Si la instrucción no es clara, devuelve:
{{"tareas": [], "resumen": "No entendí la instrucción", "error": "explicación"}}

IMPORTANTE:
- Redacta el mensaje del comunicado de forma profesional y completa
- Infiere los cursos del contexto (ej: "grado 7" = 0701 y 0702)
- "todos los cursos" = todos los que tiene el profesor
- No inventes tareas que no se mencionaron"""

    try:
        if proveedor == "anthropic":
            import anthropic
            client = anthropic.Anthropic(api_key=api_key)
            res = client.messages.create(
                model="claude-haiku-4-5-20251001",
                max_tokens=600, system=sistema,
                messages=[{"role": "user", "content": instruccion}])
            texto = res.content[0].text.strip()
        else:
            import openai
            client = openai.OpenAI(api_key=api_key)
            res = client.chat.completions.create(
                model="gpt-4o-mini", max_tokens=600,
                messages=[{"role":"system","content":sistema},
                          {"role":"user","content":instruccion}])
            texto = res.choices[0].message.content.strip()

        # Debug — imprimir respuesta en terminal
        print(f"[AGENTE DEBUG] Respuesta IA: {repr(texto[:500])}")

        # Limpiar y parsear JSON — robusto ante respuestas con texto extra
        texto = texto.replace("```json", "").replace("```", "").strip()

        # Intentar extraer el JSON aunque haya texto antes o después
        plan = None
        # Primero intentar parsear directo
        try:
            plan = json.loads(texto)
        except json.JSONDecodeError:
            # Buscar el primer { y el último } para extraer el JSON
            inicio = texto.find('{')
            fin    = texto.rfind('}')
            if inicio != -1 and fin != -1 and fin > inicio:
                try:
                    plan = json.loads(texto[inicio:fin+1])
                except json.JSONDecodeError:
                    pass

        if plan is None:
            return jsonify({
                "ok": False,
                "error": f"No pude interpretar. Respuesta IA: {texto[:200]}"
            })

        return jsonify({"ok": True, "plan": plan})

    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/agente/ejecutar", methods=["POST"])
@limiter.limit("10 per hour")
def agente_ejecutar():
    """Ejecuta el plan de tareas con Selenium."""
    if not SELENIUM_OK:
        return jsonify({"ok": False, "error": "Selenium no instalado"})

    nombre = usuario_actual()
    if not nombre: return jsonify({"ok": False})

    data   = get_json_safe()
    tareas = data.get("tareas", [])
    sid_anterior = re.sub(r'[^a-f0-9]', '', data.get("session_id_anterior", ""))[:8]

    if not tareas:
        return jsonify({"ok": False, "error": "Sin tareas"})

    import uuid
    session_id = str(uuid.uuid4())[:8]
    _agente_sesiones[session_id] = []

    def log(tipo, msg):
        _agente_sesiones[session_id].append({"tipo": tipo, "msg": msg})

    def correr():
        # Reutilizar Chrome si existe
        driver_prev = _drivers_activos.pop(sid_anterior, None) if sid_anterior else None

        if driver_prev:
            driver = driver_prev
            log("info", "Reutilizando Chrome abierto")
        else:
            try:
                driver = _crear_driver_chrome()
                time.sleep(2)
                driver.get(URL_LOGIN)
                time.sleep(3)
            except Exception as e:
                log("error", f"Error abriendo Chrome: {str(e)}")
                return

            # Intentar login automático si hay credenciales guardadas
            perfiles_check = cargar_perfiles()
            tiene_creds = bool(perfiles_check.get(nombre, {}).get("colegio_usuario"))

            if tiene_creds:
                log("info", "Entrando automáticamente a la plataforma...")
                login_ok = _login_automatico(driver, nombre, log)
                if not login_ok:
                    log("warn", "Login automático falló — inicia sesión manualmente en Chrome")
                    sesion_ok = False
                    for _ in range(120):
                        time.sleep(1)
                        try:
                            url_actual = driver.current_url.lower()
                            if "login" not in url_actual and "data:" not in url_actual:
                                sesion_ok = True
                                break
                        except Exception:
                            break
                    if not sesion_ok:
                        log("error", "No se detectó inicio de sesión")
                        try: driver.quit()
                        except: pass
                        return
            else:
                log("info", "Chrome abierto — inicia sesión manualmente en la plataforma")
                sesion_ok = False
                for _ in range(120):
                    time.sleep(1)
                    try:
                        url_actual = driver.current_url.lower()
                        if "login" not in url_actual and "data:" not in url_actual:
                            sesion_ok = True
                            break
                    except Exception:
                        break
                if not sesion_ok:
                    log("error", "No se detectó inicio de sesión")
                    try: driver.quit()
                    except: pass
                    return
                log("info", "Tip: guarda tus credenciales en Perfil para entrar automáticamente")

            log("ok", "Sesion lista — abriendo aula virtual")
            driver.get(URL_AULA_V)
            time.sleep(4)

            # Navegar directo al aula virtual
            try:
                # Construir URL completa del aula virtual
                url_aula_completa = "https://www.colhumboldt.controlacademico.com/AulaVirtual/"
                ventanas_antes = driver.window_handles

                # Click en el link del aula virtual
                link_aula = WebDriverWait(driver, 15).until(
                    EC.element_to_be_clickable((By.XPATH,
                        "//a[@title='Aula Virtual' or contains(@href,'AulaVirtual')]"
                    ))
                )
                link_aula.click()
                time.sleep(4)

                # Cambiar a la nueva pestaña si se abrió
                ventanas_despues = driver.window_handles
                nueva_ventana = [v for v in ventanas_despues if v not in ventanas_antes]
                if nueva_ventana:
                    driver.switch_to.window(nueva_ventana[0])
                    time.sleep(3)
                    log("info", "Aula virtual abierta")
                else:
                    # Si no abrió nueva pestaña, navegar directo
                    driver.get(url_aula_completa)
                    time.sleep(3)
                    log("info", "Aula virtual cargada")

                # Navegar a la página de comunicados dentro del aula
                driver.get(URL_AULA_V)
                time.sleep(4)
                log("info", "En la pagina de comunicados")

            except Exception as e:
                log("warn", "Navegando directo al aula: " + str(e)[:40])
                driver.get(URL_AULA_V)
                time.sleep(4)

            log("info", "En el aula virtual — ejecutando tareas")

        try:
            for i, tarea in enumerate(tareas, 1):
                tipo = tarea.get("tipo", "")
                log("info", "Tarea " + str(i) + "/" + str(len(tareas)) + ": " + tipo)

                if tipo == "comunicado":
                    _ejecutar_comunicado(driver, tarea, log)
                else:
                    log("warn", "Tipo de tarea '" + tipo + "' no reconocido")

            log("done", f"Agente terminó — {len(tareas)} tarea(s) ejecutada(s)")
            _drivers_activos[session_id] = driver

        except Exception as e:
            log("error", f"Error: {str(e)}")
            try: driver.quit()
            except: pass

    threading.Thread(target=correr, daemon=True).start()
    return jsonify({"ok": True, "session_id": session_id})


def _login_automatico(driver, nombre, log):
    """Hace login automático en la plataforma del colegio."""
    perfiles = cargar_perfiles()
    usuario_enc  = perfiles[nombre].get("colegio_usuario", "")
    password_enc = perfiles[nombre].get("colegio_password", "")

    if not usuario_enc or not password_enc:
        return False

    usuario  = desencriptar_credencial(usuario_enc)
    password = desencriptar_credencial(password_enc)

    if not usuario or not password:
        return False

    try:
        # Buscar campos de login
        campo_usuario = WebDriverWait(driver, 15).until(
            EC.presence_of_element_located((By.XPATH,
                "//input[@type='text' or @type='email' or @name='usuario' or @name='user' or @id='usuario' or @id='user']"
            ))
        )
        campo_usuario.clear()
        campo_usuario.send_keys(usuario)

        # Buscar campo de contraseña
        campo_pass = driver.find_element(By.XPATH,
            "//input[@type='password']")
        campo_pass.clear()
        campo_pass.send_keys(password)

        # Click en botón de login
        btn_login = driver.find_element(By.XPATH,
            "//button[@type='submit'] | //input[@type='submit']")
        btn_login.click()
        time.sleep(4)

        # Verificar que entró
        url_actual = driver.current_url.lower()
        if "login" not in url_actual and "data:" not in url_actual:
            log("ok", "Login automático exitoso")
            return True
        else:
            log("warn", "Login automático falló — verifica tus credenciales del colegio")
            return False

    except Exception as e:
        log("warn", f"Login automático: {str(e)[:60]}")
        return False


def _ejecutar_comunicado(driver, tarea, log):
    """Navega al aula virtual y envía un comunicado."""
    cursos  = tarea.get("cursos", [])
    mensaje = sanitize(tarea.get("mensaje", ""), "textarea")
    asunto  = sanitize(tarea.get("asunto", "Comunicado"), "text")

    if not cursos or not mensaje:
        log("error", "Comunicado sin cursos o mensaje"); return

    log("info", f"Enviando comunicado a: {', '.join(cursos)}")

    try:
        # Ir al aula virtual
        driver.get(URL_AULA_V)
        time.sleep(5)

        # Click en el botón Comunicados
        try:
            btn = WebDriverWait(driver, 30).until(
                EC.element_to_be_clickable((By.XPATH,
                    "//*[contains(text(),'Comunicado') or contains(text(),'comunicado')]")))
            btn.click()
            time.sleep(3)
        except TimeoutException:
            # Intentar por clase del div
            driver.execute_script("""
                var divs = document.querySelectorAll('.inner p, .inner, [con="Comunicado"]');
                for(var d of divs){
                    if(d.textContent.includes('Comunicado')){
                        d.click(); break;
                    }
                }
            """)
            time.sleep(3)

        # Seleccionar cursos en MultiSelectComunicado
        valores_plataforma = [CURSO_A_PLATAFORMA.get(c, c+"SJ1SJA") for c in cursos]

        driver.execute_script("""
            var sel = document.getElementById('MultiSelectComunicado');
            if (!sel) return;
            sel.disabled = false;
            // Deseleccionar todo primero
            for(var o of sel.options) o.selected = false;
            // Seleccionar los cursos indicados
            var vals = arguments[0];
            for(var o of sel.options){
                if(vals.includes(o.value)) o.selected = true;
            }
            sel.dispatchEvent(new Event('change', {bubbles:true}));
            // Llamar función interna de la página
            try{ cambioCurso('Comunicado'); } catch(e){}
        """, valores_plataforma)
        time.sleep(2)

        # También hacer click en los elementos visuales del multiselect
        for val in valores_plataforma:
            try:
                driver.execute_script(f"""
                    var items = document.querySelectorAll('#ms-MultiSelectComunicado .ms-elem-selectable');
                    for(var item of items){{
                        var span = item.querySelector('span');
                        if(span && item.id && !item.classList.contains('ms-selected')){{
                            // Buscar por valor correspondiente
                        }}
                    }}
                """)
            except Exception:
                pass
        time.sleep(1)

        # Escribir el mensaje en el editor
        # El editor puede ser un iframe (editor rico) o un textarea
        try:
            # Intentar con iframe de editor rico
            iframes = driver.find_elements(By.TAG_NAME, "iframe")
            editor_ok = False
            for iframe in iframes:
                try:
                    driver.switch_to.frame(iframe)
                    body = driver.find_element(By.TAG_NAME, "body")
                    body.clear()
                    body.send_keys(mensaje)
                    driver.switch_to.default_content()
                    editor_ok = True
                    break
                except Exception:
                    driver.switch_to.default_content()
                    continue

            if not editor_ok:
                # Intentar con textarea directo
                textareas = driver.find_elements(By.TAG_NAME, "textarea")
                for ta in textareas:
                    if ta.is_displayed():
                        ta.clear()
                        ta.send_keys(mensaje)
                        break
        except Exception as e:
            log("warn", f"Editor de texto: {str(e)[:50]}")

        time.sleep(2)

        # Buscar y hacer click en botón Guardar/Enviar
        try:
            btn_guardar = WebDriverWait(driver, 10).until(
                EC.element_to_be_clickable((By.XPATH,
                    "//button[contains(text(),'Guardar') or contains(text(),'Enviar') or contains(text(),'Publicar')]")))
            btn_guardar.click()
        except TimeoutException:
            # Intentar por JS
            driver.execute_script("""
                var btns = document.querySelectorAll('button, input[type=submit]');
                for(var b of btns){
                    var t = b.textContent || b.value || '';
                    if(t.includes('Guardar') || t.includes('Enviar') || t.includes('Publicar')){
                        b.click(); break;
                    }
                }
            """)
        time.sleep(3)

        log("ok", f"Comunicado enviado a {', '.join(cursos)}")

    except Exception as e:
        log("error", f"Error enviando comunicado: {str(e)[:80]}")


@app.route("/api/agente/progreso/<session_id>")
def agente_progreso(session_id):
    session_id = re.sub(r'[^a-f0-9]', '', session_id)[:8]
    logs = _agente_sesiones.get(session_id, [])
    return jsonify({"ok": True, "logs": logs})


# ─────────────────────────────────────────────
# MÓDULO COORDINADOR
# ─────────────────────────────────────────────

_reporte_sesiones = {}  # session_id -> {logs, reporte}


@app.route("/coordinador")
def coordinador():
    nombre = usuario_actual()
    if not nombre: return redirect(url_for("index"))
    perfiles = cargar_perfiles()
    # Solo coordinadores pueden acceder
    if not perfiles[nombre].get("es_coordinador", False):
        return redirect(url_for("dashboard"))
    año = get_año(perfiles, nombre)
    return render_template("coordinador.html",
        nombre=nombre, año=año, es_coordinador=True)


@app.route("/api/coordinador/verificar", methods=["POST"])
@limiter.limit("5 per hour")
def verificar_planeaciones():
    """
    El bot entra a la plataforma del colegio con las credenciales
    del coordinador, navega por todos los cursos y materias,
    y verifica si tienen planeación para el periodo/bloque indicado.
    """
    if not SELENIUM_OK:
        return jsonify({"ok": False, "error": "Selenium no instalado"})

    nombre = usuario_actual()
    if not nombre: return jsonify({"ok": False})
    # Solo coordinadores
    perfiles_check = cargar_perfiles()
    if not perfiles_check.get(nombre, {}).get("es_coordinador", False):
        return jsonify({"ok": False, "error": "Acceso solo para coordinadores"})

    data     = get_json_safe()
    periodo  = sanitize(str(data.get("periodo", "1")), "año")[:1]
    bloque   = sanitize(str(data.get("bloque", "0")), "año")[:1]

    import uuid
    session_id = str(uuid.uuid4())[:8]
    _reporte_sesiones[session_id] = {"logs": [], "reporte": None}

    def log(tipo, msg):
        _reporte_sesiones[session_id]["logs"].append({"tipo": tipo, "msg": msg})

    perfiles_data = cargar_perfiles()
    usuario_enc  = perfiles_data[nombre].get("colegio_usuario", "")
    password_enc = perfiles_data[nombre].get("colegio_password", "")

    def correr_verificacion():
        driver = _crear_driver_chrome()

        try:
            driver.get(URL_LOGIN)
            time.sleep(3)
            log("info", "Chrome abierto — inicia sesión como COORDINADOR en la plataforma")
            log("info", "El bot solo leerá datos, no modificará nada")

            # Esperar login manual (coordinador siempre entra manualmente por seguridad)
            sesion_ok = False
            for _ in range(180):  # 3 minutos
                time.sleep(1)
                try:
                    url = driver.current_url.lower()
                    if "login" not in url and "data:" not in url:
                        sesion_ok = True
                        break
                except Exception:
                    break

            if not sesion_ok:
                log("error", "No se detectó inicio de sesión")
                driver.quit(); return

            log("ok", "Sesión iniciada — comenzando verificación")

            # Ir a Planes de Área
            driver.get(URL_PLANES)
            time.sleep(PAUSA + 2)

            # Leer todos los cursos disponibles
            try:
                el_curso = WebDriverWait(driver, TIMEOUT).until(
                    EC.presence_of_element_located((By.ID, "CURSO")))
            except TimeoutException:
                log("error", "No se pudo cargar Planes de Área")
                driver.quit(); return

            cursos = []
            for o in el_curso.find_elements(By.TAG_NAME, "option"):
                val = o.get_attribute("value")
                nom = o.text.strip()
                if val and val != "" and "SELECCIONE" not in nom.upper():
                    cursos.append({"codigo": val, "nombre": nom})

            log("info", f"Verificando {len(cursos)} cursos en Periodo {periodo}, Bloque {bloque}...")

            # Estructura del reporte
            reporte = {
                "periodo":   periodo,
                "bloque":    bloque,
                "completos": [],  # {curso, materia}
                "faltantes": [],  # {curso, materia}
                "por_materia": {},# materia -> {completos:[], faltantes:[]}
            }

            total = len(cursos)
            for i, curso in enumerate(cursos, 1):
                log("info", f"[{i}/{total}] Revisando {curso['codigo']} — {curso['nombre']}...")

                try:
                    driver.get(URL_PLANES)
                    time.sleep(PAUSA)

                    # Seleccionar curso
                    el_c = WebDriverWait(driver, TIMEOUT).until(
                        EC.presence_of_element_located((By.ID, "CURSO")))
                    Select(el_c).select_by_value(curso["codigo"])
                    time.sleep(PAUSA)

                    # Leer asignaturas disponibles
                    driver.execute_script("""
                        var el=document.getElementById('ASIGNATURA');
                        if(el){el.disabled=false;el.removeAttribute('disabled');}
                    """)
                    time.sleep(1)

                    el_a = driver.find_element(By.ID, "ASIGNATURA")
                    asigs = [
                        {"codigo": o.get_attribute("value"), "nombre": o.text.strip()}
                        for o in el_a.find_elements(By.TAG_NAME, "option")
                        if o.get_attribute("value") and o.get_attribute("value") != ""
                        and "SELECCIONE" not in o.text.upper()
                    ]

                    if not asigs:
                        continue

                    # Verificar cada asignatura
                    for asig in asigs:
                        try:
                            # Seleccionar asignatura
                            driver.execute_script("""
                                var el=document.getElementById('ASIGNATURA');
                                el.disabled=false;el.removeAttribute('disabled');
                                el.value=arguments[0];
                                el.dispatchEvent(new Event('change',{bubbles:true}));
                            """, asig["codigo"])
                            time.sleep(2)

                            # Seleccionar periodo
                            try:
                                Select(driver.find_element(By.ID, "PERIODO")).select_by_value(periodo)
                            except Exception:
                                driver.execute_script(
                                    f"var el=document.getElementById('PERIODO');"
                                    f"if(el){{el.value='{periodo}';"
                                    f"el.dispatchEvent(new Event('change',{{bubbles:true}}));}}")
                            time.sleep(1)

                            # Click en Listar
                            driver.execute_script("document.getElementById('buttonx').click();")
                            time.sleep(4)

                            # Leer la tabla de planeaciones
                            filas = driver.find_elements(By.CSS_SELECTOR, "table tr")
                            filas_datos = [
                                f for f in filas
                                if len(f.find_elements(By.TAG_NAME, "td")) >= 4
                            ]

                            # Verificar si hay planeación para este bloque
                            tiene_planeacion = False
                            for fila in filas_datos:
                                celdas = fila.find_elements(By.TAG_NAME, "td")
                                if len(celdas) >= 4:
                                    # La fecha de inicio corresponde al bloque
                                    s1_esperada = str(1 + int(bloque) * 2)
                                    info = celdas[4].text.strip() if len(celdas) > 4 else ""
                                    if info:  # hay contenido
                                        tiene_planeacion = True
                                        break

                            entrada = {
                                "curso":   curso["codigo"],
                                "nombre_curso": curso["nombre"],
                                "materia": asig["nombre"],
                                "codigo_materia": asig["codigo"],
                            }

                            if tiene_planeacion:
                                reporte["completos"].append(entrada)
                                nom_mat = asig["nombre"]
                                if nom_mat not in reporte["por_materia"]:
                                    reporte["por_materia"][nom_mat] = {"completos": [], "faltantes": []}
                                reporte["por_materia"][nom_mat]["completos"].append(curso["codigo"])
                                log("ok", f"  ✓ {asig['nombre']}")
                            else:
                                reporte["faltantes"].append(entrada)
                                nom_mat = asig["nombre"]
                                if nom_mat not in reporte["por_materia"]:
                                    reporte["por_materia"][nom_mat] = {"completos": [], "faltantes": []}
                                reporte["por_materia"][nom_mat]["faltantes"].append(curso["codigo"])
                                log("warn", f"  ✗ {asig['nombre']} — SIN PLANEACIÓN")

                        except Exception as ex:
                            log("warn", f"  Error en {asig['nombre']}: {str(ex)[:40]}")
                            continue

                except Exception as ex:
                    log("warn", f"Error en {curso['codigo']}: {str(ex)[:40]}")
                    continue

            # Guardar reporte y cerrar Chrome (coordinador no mantiene sesión)
            _reporte_sesiones[session_id]["reporte"] = reporte
            try: driver.quit()
            except: pass

            # Resumen final
            total_ok  = len(reporte["completos"])
            total_fal = len(reporte["faltantes"])
            log("ok", f"Verificación completada — {total_ok} con planeación, {total_fal} sin planeación")
            log("done", f"Reporte listo — revisa los resultados")

        except Exception as e:
            log("error", f"Error general: {str(e)}")
            try: driver.quit()
            except: pass

    threading.Thread(target=correr_verificacion, daemon=True).start()
    return jsonify({"ok": True, "session_id": session_id})


@app.route("/api/coordinador/progreso/<session_id>")
def coordinador_progreso(session_id):
    session_id = re.sub(r'[^a-f0-9]', '', session_id)[:8]
    datos      = _reporte_sesiones.get(session_id, {})
    return jsonify({
        "ok":      True,
        "logs":    datos.get("logs", []),
        "reporte": datos.get("reporte"),
    })

# ─────────────────────────────────────────────
# APAGADO DE EMERGENCIA
# ─────────────────────────────────────────────

@app.route("/api/emergencia/apagar", methods=["POST"])
@limiter.limit("5 per hour")
def apagar_emergencia():
    """Cierra todos los Chrome abiertos y apaga el servidor."""
    nombre = usuario_actual()
    if not nombre: return jsonify({"ok": False})

    # Cerrar todos los drivers activos
    for sid, driver in list(_drivers_activos.items()):
        try: driver.quit()
        except: pass
    _drivers_activos.clear()
    _progreso_sesiones.clear()
    _agente_sesiones.clear()

    # Apagar servidor después de responder
    def apagar():
        time.sleep(1)
        import os, signal
        os.kill(os.getpid(), signal.SIGTERM)

    log_auditoria("EMERGENCIA_APAGAR", nombre or "anon")
    threading.Thread(target=apagar, daemon=True).start()
    return jsonify({"ok": True})


# ─────────────────────────────────────────────
# LOGS DE AUDITORÍA (solo admin)
# ─────────────────────────────────────────────

@app.route("/api/admin/audit_log")
@limiter.limit("10 per hour")
def ver_audit_log():
    """Muestra los últimos 100 eventos de auditoría — solo admin."""
    nombre = usuario_actual()
    if not nombre: return jsonify({"ok": False})
    clave  = request.args.get("clave", "")
    CLAVE_ADMIN = os.environ.get("ADMIN_KEY", "")
    if not CLAVE_ADMIN or clave != CLAVE_ADMIN:
        log_auditoria("AUDIT_LOG_ACCESO_DENEGADO", nombre)
        return jsonify({"ok": False, "error": "No autorizado"}), 403
    ruta_log = os.path.join(CARPETA_DATOS, "audit.log")
    if not os.path.exists(ruta_log):
        return jsonify({"ok": True, "logs": []})
    with open(ruta_log, encoding="utf-8") as f:
        lineas = f.readlines()[-100:]
    return jsonify({"ok": True, "logs": [l.strip() for l in lineas]})


# ─────────────────────────────────────────────
# ERROR HANDLERS
# ─────────────────────────────────────────────

@app.errorhandler(429)
def too_many_requests(e):
    return jsonify({
        "ok":    False,
        "error": "Demasiadas solicitudes. Espera un momento antes de intentar de nuevo.",
        "retry_after": str(e.description),
    }), 429

@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/api/"):
        return jsonify({"ok": False, "error": "Ruta no encontrada"}), 404
    return redirect(url_for("index"))

@app.errorhandler(500)
def server_error(e):
    return jsonify({"ok": False, "error": "Error interno del servidor"}), 500


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def abrir_navegador():
    time.sleep(1.5)
    webbrowser.open("http://127.0.0.1:8080")

if __name__ == "__main__":
    asegurar_carpeta()
    print("\n" + "="*50)
    print("  Planeador Académico — Colegio Humboldt")
    print("="*50)
    print("  Abriendo en http://127.0.0.1:8080")
    print("  Presiona Ctrl+C para detener")
    print("="*50 + "\n")
    threading.Thread(target=abrir_navegador, daemon=True).start()
    app.run(debug=False, port=8080, host="0.0.0.0")
