import time
from flask import Blueprint, render_template, redirect, url_for, request, flash, session
from flask_login import login_user, logout_user, login_required, current_user
from flask import redirect, url_for, Flask
from app_sec.models import User
from app_sec import db, mail
from flask_mail import Message
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import pyotp
import os
import qrcode
import hashlib
import requests
from base64 import urlsafe_b64encode, urlsafe_b64decode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet

from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired

auth = Blueprint('auth', __name__)

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    twofa_code = StringField('2facode', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField('Register')

@auth.route('/login')
def login():
    form = LoginForm()
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    else:
        return render_template('login.html', form=form)
    
@auth.route('/login', methods=['POST'])
def login_post():
    username = request.form.get('username')
    password = request.form.get('password')
    user = User.query.filter_by(username=username).first()
    twofa_code = request.form.get('twofa_code')
    encrypted_key = user.key
    if not user:
        flash('Please check your login details and try again.')
        return redirect(url_for('auth.login'))
    else:
        if check_password_hash(user.password, password):
            decrypted_key = decrypt_key(encrypted_key, username, password)
            totp = pyotp.TOTP(decrypted_key)
            if totp.verify(twofa_code):
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
            else:
                flash('Please check your login details and try again.')
                user.increment_failed_login_attempts()
                if user.failed_login_attempts >= 2:
                    user.last_login_attempt = datetime.now() + timedelta(seconds=30)
                    flash(f'Please wait until {user.last_login_attempt.strftime("%H:%M:%S")} before trying again.')
                db.session.commit()
                return redirect(url_for('auth.login'))
                
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
    reg = RegisterForm()
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    else:
        return render_template('register.html', reg=reg)
    
@auth.route('/register', methods=['POST'])
def register_post():
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')
    user = User.query.filter_by(username=username).first()
    user_email = User.query.filter_by(email=email).first()
    common_passwords = open('PASSWORDS.txt', 'r', encoding='utf-8')
  	
    password_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = password_hash[:5], password_hash[5:]

    api_url = f'https://api.pwnedpasswords.com/range/{prefix}'

    response = requests.get(api_url)    # Check if the HIBP API request was successful

    if response.status_code == 200:
        hashes = (line.split(':') for line in response.text.splitlines())
        found_hashes = {h[0]: h[1] for h in hashes}
        if suffix in found_hashes:
            flash('Password has been found in data breaches. Please choose a different password.')
            return redirect(url_for('auth.register'))

    if user:
        flash('Username already exists.')
        return redirect(url_for('auth.register'))
    
    if user_email:
        flash('Email address already exists.')
        return redirect(url_for('auth.register'))
    
    if password != confirm_password:      
        flash('Passwords do not match.')
        return redirect(url_for('auth.register'))
    
    if password == confirm_password:

        for line in common_passwords:
            common = []
            if password == line.strip():
                common.append(password)
                flash('Password has been found in data breaches. Please choose a different password.')
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
            key= pyotp.random_base32()
            totp= pyotp.TOTP(key).provisioning_uri(username, issuer_name="Detimerch")
            encrypted_key=encrypt_key(key, username, password)
            print(password)
            new_user.key=encrypted_key
            dir_path = os.path.dirname(os.path.abspath(__file__))
            qrcode.make(totp).save(os.path.join(dir_path, "static/assets/QR.png"))
            db.session.commit()
            msg = Message("Account created")
            msg.recipients= [email]
            msg.body = """Dear {username},
            We are pleased to inform you that your account has been created successfully in Deti@merch.

            If you did not create an account in Deti@merch, please ignore this email.

            Thank you for using Deti@merch. We hope you enjoy your experience with us.

            Best regards,
            Deti@Merch Security Team
            """.format(username=username)

            mail.send(msg)


            return render_template('QRcode.html', key=key)



def encrypt_key(key, username, password):
    kdf= PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=username.encode(),
        iterations=100000,
        backend=default_backend()
    )
    derived_key= urlsafe_b64encode(kdf.derive(password.encode()))
    f= Fernet(derived_key)
    encrypted_key= f.encrypt(key.encode())
    return encrypted_key


def decrypt_key(key, username, password):
    kdf= PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=username.encode(),
        iterations=100000,
        backend=default_backend()
    )
    derived_key= urlsafe_b64encode(kdf.derive(password.encode()))
    f= Fernet(derived_key)
    decrypted_key= f.decrypt(key).decode()
    return decrypted_key