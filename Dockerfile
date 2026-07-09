# Dockerfile — Planeador Académico (Colegio Humboldt)
# Base: Python 3.14 slim (Debian trixie)
FROM python:3.14-slim

# --- Dependencias de sistema para Selenium + Chromium headless ---
RUN apt-get update && apt-get install -y --no-install-recommends \
    chromium \
    chromium-driver \
    fonts-liberation \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Chromium y su driver quedan en estas rutas al instalar por apt en Debian.
# app.py los lee vía _crear_driver_chrome() y corre headless cuando HEADLESS=true.
ENV CHROME_BIN=/usr/bin/chromium
ENV CHROMEDRIVER_BIN=/usr/bin/chromedriver
ENV HEADLESS=true

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Carpeta de datos persistentes (perfiles.json, config.json, audit.log, mem_*.json)
# Se monta como volumen en docker-compose.yml / en Coolify (Storages)
ENV DATA_DIR=/data
RUN mkdir -p /data

EXPOSE 8080

# workers=1 es intencional: el estado en memoria del backend
# (_progreso_sesiones, _drivers_activos, _agente_sesiones, _reporte_sesiones)
# vive dentro de un solo proceso. Con más de 1 worker, cada uno tendría su
# propia copia y el polling de progreso (SSE) se rompería.
# --threads permite atender varias peticiones/usuarios en paralelo dentro
# de ese único proceso.
CMD ["gunicorn", "--workers", "1", "--threads", "8", "--timeout", "180", \
     "--bind", "0.0.0.0:8080", "app:app"]
