import time
from flask import Blueprint, render_template, redirect, url_for, request, flash, session
from flask_login import login_user, logout_user, login_required, current_user
from flask import redirect, url_for
from app_sec.models import User
from app_sec import db
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
# import pyotp
import os
# import qrcode
from flask import Flask,abort


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
        
        if check_password_hash(user.password, password):
            if user.failed_login_attempts >= 2:
                if user.last_login_attempt and user.last_login_attempt > datetime.now():
                    flash(f'Please wait until {user.last_login_attempt.strftime("%H:%M:%S")} before trying again.')
                    return redirect(url_for('auth.login'))
                elif user.last_login_attempt and user.last_login_attempt <= datetime.now():
                    flash('Your account is now unlocked.')
                    user.reset_failed_login_attempts()
                    db.session.commit()
                    time.sleep(0.1)
            else:
                user.reset_failed_login_attempts()
                user.last_login_attempt = datetime.now()
                db.session.commit()
                login_user(user, remember=True)
                return redirect(url_for('main.index'))
            
        elif not check_password_hash(user.password, password):
            flash('Please check your login details and try again.')
            user.increment_failed_login_attempts()
            if user.failed_login_attempts >= 2:
                user.last_login_attempt = datetime.now() + timedelta(seconds=30)
                flash(f'Please wait until {user.last_login_attempt.strftime("%H:%M:%S")} before trying again.')
                
            db.session.commit()
            return redirect(url_for('auth.login'))
        
    user.reset_failed_login_attempts()
    user.last_login_attempt = datetime.now()
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
    common_passwords = open('PASSWORDS.txt', 'r', encoding='utf-8')

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
        elif len(password) > 128:
            
            flash('Password must have at most 128 characters.')
            return redirect(url_for('auth.register'))
        else:
            flash('Account successfuly created.')
            new_user = User(username=username, email=email, password=generate_password_hash(password, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            # key = pyotp.random_base32()
            # uri = pyotp.totp.TOTP(key).provisioning_uri(name = username, issuer_name="Deti_Merch")
            # filename=qrcode.make(uri).save('static/assets/qr_code.png')
            return render_template('2FA.html')
        