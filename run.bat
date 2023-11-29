@echo off
setlocal

set "APP=%~1"
set "PORT=%~2"

set "FLASK_APP=%APP%/__init__.py"
set "FLASK_ENV=development"
set "FLASK_DEBUG=1"
set "FLASK_RUN_PORT=%PORT%"

flask run

endlocal