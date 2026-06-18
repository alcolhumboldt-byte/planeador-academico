#!/usr/bin/env python3
"""
Script de configuración inicial del Planeador Académico
Corre este script UNA VEZ antes de iniciar la app por primera vez.
"""

import os
import secrets
import shutil

print("\n" + "="*50)
print("  Planeador Académico — Configuración inicial")
print("="*50)

# Verificar que .env no existe ya
if os.path.exists(".env"):
    sobreescribir = input("\n  Ya existe un .env. ¿Sobreescribir? (s/N): ").strip().lower()
    if sobreescribir != "s":
        print("  Cancelado.")
        exit()

# Generar secret key aleatoria
secret_key = secrets.token_hex(32)
print(f"\n  [✓] Clave secreta generada automáticamente")

# Pedir admin key
print("\n  Esta clave la usarás para configurar la API key desde el navegador.")
admin_key = input("  Crea tu clave de administrador: ").strip()
if not admin_key:
    admin_key = secrets.token_hex(16)
    print(f"  [✓] Clave generada: {admin_key}  ← GUÁRDALA")

# Pedir API key (opcional)
print("\n  API key de Anthropic (sk-ant-...) o presiona ENTER para configurarla después:")
api_key = input("  API key: ").strip()

proveedor = "anthropic"
if api_key and api_key.startswith("sk-") and not api_key.startswith("sk-ant-"):
    proveedor = "openai"

# Escribir .env
env_content = f"""# Planeador Académico — Configuración
# NO subir este archivo a GitHub

SECRET_KEY={secret_key}
ADMIN_KEY={admin_key}
AI_API_KEY={api_key}
AI_PROVIDER={proveedor}
"""

with open(".env", "w") as f:
    f.write(env_content)

print("\n" + "="*50)
print("  [✓] Archivo .env creado correctamente")
if api_key:
    print("  [✓] API key configurada")
else:
    print("  [!] API key pendiente — configúrala desde el navegador")
print("\n  Ahora corre: python3 app.py")
print("="*50 + "\n")

# Verificar dependencias
print("  Verificando dependencias...")
try:
    import flask
    print("  [✓] flask")
except ImportError:
    print("  [✗] flask — instala con: pip3 install flask")

try:
    import dotenv
    print("  [✓] python-dotenv")
except ImportError:
    print("  [✗] python-dotenv — instala con: pip3 install python-dotenv")

try:
    import anthropic
    print("  [✓] anthropic")
except ImportError:
    print("  [!] anthropic no instalado — pip3 install anthropic")

try:
    import openai
    print("  [✓] openai")
except ImportError:
    print("  [!] openai no instalado (opcional) — pip3 install openai")

try:
    from selenium import webdriver
    print("  [✓] selenium")
except ImportError:
    print("  [!] selenium no instalado — pip3 install selenium webdriver-manager")

print()
