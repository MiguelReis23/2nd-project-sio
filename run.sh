#!/bin/bash

APP="$1"
PORT="$2"

export FLASK_APP=$APP/__init__.py
export FLASK_ENV=development
export FLASK_DEBUG=1
export FLASK_RUN_PORT=$PORT
flask run