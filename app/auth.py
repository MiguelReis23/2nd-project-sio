import time
from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required, current_user
from .models import User
from app import db
from werkzeug.security import generate_password_hash

auth  = Blueprint('auth', __name__)


@auth.route('/login')
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    else:
        return render_template('login.html')
    
@auth.route('/login', methods=['POST'])
def login_post():
    username = request.form.get('username')
    password = request.form.get('password')
    
    result = db.session.execute(
        "SELECT * FROM user WHERE username = '" + username + "' AND password = '" + password + "';").fetchall()
    
    user = User.query.filter_by(username=username).first()

    if not user:
        flash('User does not exist.', 'error')
        return redirect(url_for('auth.login'))

    if not result:
        flash('Wrong password.')
        return redirect(url_for('auth.login'))
    
    login_user(user)
    return redirect(url_for('main.index'))

@auth.route('/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route('/register')
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    else:
        return render_template('register.html')
    
@auth.route('/register', methods=['POST'])
def register_post():
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')
    
    user = User.query.filter_by(username=username).first()
    
    if user:
        flash('Username already exists.')
        return redirect(url_for('auth.register'))
    
    if password:
        if password == confirm_password:
            new_user = User(username=username, email=email, password=password)
        else:
            flash('Passwords do not match.')
            return redirect(url_for('auth.register'))
    


    db.session.add(new_user)
    db.session.commit()
    
    return redirect(url_for('auth.login'))
    