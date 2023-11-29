from flask import Flask, render_template, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager


db = SQLAlchemy()

def create_app():

    app = Flask(__name__, template_folder='templates', static_folder='static', static_url_path='/static')
    app.config['SECRET_KEY'] = 'zzz'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'


    db.init_app(app)

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

    return app

