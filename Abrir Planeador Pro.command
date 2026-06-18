#!/bin/bash
cd "$(dirname "$0")"
/Library/Frameworks/Python.framework/Versions/3.14/bin/python3 app.py &
sleep 3
open http://127.0.0.1:8080
wait
