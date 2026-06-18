# Planeador Académico — Instrucciones

## Requisitos
- Python 3.8 o superior
- pip3

## Instalación (solo una vez)

```bash
pip3 install flask anthropic openai
```

## Correr la app

```bash
python3 app.py
```

Se abre automáticamente en http://localhost:5000

## Estructura de archivos

```
planeador_app/
├── app.py              ← servidor principal
├── static/
│   └── css/app.css     ← estilos
└── templates/
    ├── base.html
    ├── layout.html
    ├── login.html
    ├── dashboard.html
    ├── asistente.html
    ├── planear.html
    ├── periodos.html
    ├── materias.html
    └── perfil.html
```

## Datos guardados

Todos los datos se guardan en:
~/Desktop/planeador_academico/

- perfiles.json          ← perfiles y materias
- mem_nombre_materia.json ← memoria e historial por materia
