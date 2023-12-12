from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required, current_user
from app_org.models import User
from app_org import db
import time
from werkzeug.security import generate_password_hash, check_password_hash

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
    
    user = User.query.filter_by(username=username).first()

    if not user:
        flash('Please check your login details and try again.')
        return redirect(url_for('auth.login'))

    if user.failed_login_attempts >= 5:
        flash('Your account is blocked, try angain later!', 'error')
        user.reset_failed_login_attempts()
        db.session.commit()
        return redirect(url_for('auth.login'))

    if not check_password_hash(user.password, password):
        flash('Please check your login details and try again.')
        user.increment_failed_login_attempts()
        db.session.commit()
        return redirect(url_for('auth.login'))
    
    user.reset_failed_login_attempts()
    db.session.commit()
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
            new_user = User(username=username, email=email, password=generate_password_hash(password, method='sha256'))
        else:
            flash('Passwords do not match.')
            return redirect(url_for('auth.register'))
    


    db.session.add(new_user)
    db.session.commit()
    
    return redirect(url_for('auth.login'))