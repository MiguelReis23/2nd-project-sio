from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required, current_user
from flask import redirect, url_for
from .models import User
from . import db
from werkzeug.security import generate_password_hash, check_password_hash
import re
from .models import User

auth = Blueprint('auth', __name__)

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
    else:
        # if user.failed_login_attempts >= 2:
        #     flash('Your account is blocked, try angain later!', 'error')
            
        #     user.reset_failed_login_attempts()
        #     db.session.commit()
        #     return redirect(url_for('auth.login'))
        
        if not check_password_hash(user.password, password):
            flash(f'Failed login attempt for username: {username}')
            flash('Please check your login details and try again.')
            user.increment_failed_login_attempts()
            db.session.commit()
            return redirect(url_for('auth.login'))

    user.reset_failed_login_attempts()
    db.session.commit()
    login_user(user, remember=True)
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
    uppercase_regex = re.compile(r'[A-Z]')
    lowercase_regex = re.compile(r'[a-z]')
    digit_regex = re.compile(r'[0-9]')
    special_regex = re.compile(r'[!@#$%^&*()_+{}|:"<>?]')
    pass_regex = uppercase_regex.search(password) and lowercase_regex.search(password) and digit_regex.search(password) and special_regex.search(password)
    common_passwords = open('PASSWORDS.txt', 'r')

    if user:
        flash('Username already exists.')
        return redirect(url_for('auth.register'))
    
    if password != confirm_password:      
        flash('Passwords do not match.')
        return redirect(url_for('auth.register'))
    
    if password == confirm_password:

        for line in common_passwords:
            common = []
            if password == line.strip():
                common.append(password)
                flash('Invalid password. Password cannot be a common password.')
                return redirect(url_for('auth.register'))
        
        if len(password) < 12:
            flash('Password must have at least 12 characters.')
            return redirect(url_for('auth.register'))
        elif len(password) <= 128:
            if pass_regex:
                if re.search(r"[^\u0000-\u00ff]", password):
                    
                    return redirect(url_for('auth.register'))
                if re.search(r"\s", password):

                    return redirect(url_for('auth.register'))
                new_user = User(username=username, email=email, password=generate_password_hash(password, method='sha256'))
                flash('Account created successfully!')
                db.session.add(new_user)
                db.session.commit()
                return redirect(url_for('auth.login'))
            else:
                flash('Invalid password. Password must contain at least one lowercase letter, one uppercase letter, one digit, one special character, no Emojis and no Spaces.')
                return redirect(url_for('auth.register'))
    
    
    return redirect(url_for('auth.login'))