from datetime import timedelta
from flask import Flask, render_template, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os

db = SQLAlchemy()
mail= Mail()
limiter = Limiter(key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])

def create_app():

    app = Flask(__name__, template_folder='templates', static_folder='static', static_url_path='/static')
    app.config['SECRET_KEY'] = os.urandom(24)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.sqlite'
    app.config['SESSION_TYPE'] = 'filesystem' 
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['SESSION_COOKIE_NAME'] = '_Host-detimerch_session'
    app.config['SESSION_COOKIE_PATH'] = '/'
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)
    app.config['X-POWERED-BY'] = 'Detimerch'
    app.config['X-CONTENT-TYPE-OPTIONS'] = 'nosniff'
    app.config['X-FRAME-OPTIONS'] = 'SAMEORIGIN'
    app.config['Referrer-Policy'] = 'no-referrer'
    app.config['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    app.config['Pragma'] = 'no-cache'


    app.config['MAIL_SERVER']='smtp.gmail.com'
    app.config['MAIL_PORT'] = 465
    app.config['MAIL_USERNAME'] = 'detimerch@gmail.com'
    app.config['MAIL_PASSWORD'] = 'algl kwdy cnjf lssf'
    app.config['MAIL_USE_TLS'] = False
    app.config['MAIL_USE_SSL'] = True
    app.config['MAIL_DEFAULT_SENDER'] = 'detimerch@gmail.com'
    limiter.init_app(app)

    db.init_app(app)
    mail.init_app(app)

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    from .models import User
    with app.app_context():
        db.create_all()
    
    
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    @app.errorhandler(404)
    def page_not_found(e):
        print(e)
        return render_template('404.html')

    
    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)

    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    from .database import database as database_blueprint
    app.register_blueprint(database_blueprint)

    from .profile import prof as profile_blueprint
    app.register_blueprint(profile_blueprint)

    from.cart import crt as cart_blueprint
    app.register_blueprint(cart_blueprint)

    from .favorites import fvt as favorites_blueprint
    app.register_blueprint(favorites_blueprint)

    from .search import src as search_blueprint
    app.register_blueprint(search_blueprint)

    # Apply rate limiting to all blueprints
    
    limiter.limit("500 per day")(cart_blueprint)
    limiter.limit("50 per day")(auth_blueprint)

    return app

