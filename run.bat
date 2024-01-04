@echo off
setlocal

set "APP=%~1"
set "PORT=%~2"

set "FLASK_APP=%APP%/__init__.py"
set "FLASK_RUN_PORT=%PORT%"

flask run

endlocal