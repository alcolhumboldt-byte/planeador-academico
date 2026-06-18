#!/bin/bash
APP_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$APP_DIR"

if ! command -v python3 &>/dev/null; then
    osascript -e 'display alert "Python no instalado" message "Descarga Python desde python.org e instálalo." as critical'
    open "https://www.python.org/downloads/"
    exit 1
fi

osascript -e 'display notification "Preparando el Planeador..." with title "Planeador Académico"'
pip3 install flask anthropic flask-limiter python-dotenv selenium webdriver-manager --quiet 2>/dev/null

(sleep 2 && open "http://127.0.0.1:8080") &
python3 app.py
