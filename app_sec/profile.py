import re
from flask import Blueprint, render_template, redirect, url_for, request, flash, Flask, session
from flask_login import login_required, current_user    
from app_sec.models import User
from app_sec import db, mail
from flask_mail import Message
import os
from werkzeug.security import generate_password_hash, check_password_hash
import hashlib
import requests
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired

prof = Blueprint('profile', __name__)



class ProfileForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    first_name = StringField('First name')
    last_name = StringField('Last name')
    phone_number = StringField('Phone number')
    address = StringField('Address')
    old_password = PasswordField('Old password', validators=[DataRequired()])
    new_password = PasswordField('New password')
    confirm_password = PasswordField('Confirm new password')
    username = StringField('Username')
    submit = SubmitField('Save changes')

@prof.route('/profile')
@login_required
def profile():
    user = User.query.filter_by(id=current_user.id).first()	
    return render_template('profile.html', user=user)

@prof.route('/edit_profile/')
@login_required
def edit_page():
    profile_form = ProfileForm()
    user = User.query.filter_by(id=current_user.id).first()
    return render_template('edit_profile.html', user=user, profile=profile_form)


@prof.route('/edit_profile', methods=['POST'])
@login_required
def edit_profile():
    email = request.form.get('email')
    first_name = request.form.get('first_name')
    last_name = request.form.get('last_name')
    phone_number = request.form.get('phone_number')
    address = request.form.get('address')  
    user = User.query.filter_by(id=current_user.id).first()
    current_email = user.email
    old_password = request.form.get('old_password')
    new_password = request.form.get('new_password')
    confirm_new_password = request.form.get('confirm_new_password')

    
    common_passwords = open('PASSWORDS.txt', 'r', encoding='utf-8')
    password_hash = hashlib.sha1(new_password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = password_hash[:5], password_hash[5:]

    api_url = f'https://api.pwnedpasswords.com/range/{prefix}'

    response = requests.get(api_url)    # Check if the HIBP API request was successful

    if response.status_code == 200:
        hashes = (line.split(':') for line in response.text.splitlines())
        found_hashes = {h[0]: h[1] for h in hashes}
        if suffix in found_hashes:
            flash('Password has been found in data breaches. Please choose a different password.')
            return redirect(url_for('profile.edit'))


    if old_password:
        if not check_password_hash(user.password, old_password):
            flash('Please check your password and try again.')
            return redirect(url_for('profile.edit_profile'))
        
        # if new password and confirm new password are empty
        elif not new_password and not confirm_new_password:
            if email:
                user.email = email
            if first_name:
                user.first_name = first_name
            if last_name:
                user.last_name = last_name
            if phone_number:
                user.phone_number = phone_number
            if address:
                user.address = address

            flash('Profile updated successfully!')

            msg = Message("Profile updated")
            msg.recipients= [current_email]
            msg.body = """Dear {username},

            We hope this message finds you well. We wanted to inform you that your profile on Deti@Merch has been successfully updated. Your information is now current, ensuring a seamless and personalized experience on our site.

            If you did not make these changes or have any concerns about your account security, please reach out to us at "detimerch@gmail.com". We take the security of your account seriously and will investigate any unauthorized changes promptly.

            Thank you for choosing Deti@Merch. We appreciate your trust in us, and we're committed to providing you with the best shopping experience.

            Best regards,
            Deti@Merch Security Team
            """.format(username=user.username)

            mail.send(msg)
            db.session.commit()
            return redirect(url_for('profile.profile'))
        
        if new_password != confirm_new_password:      
            flash('Passwords do not match.')
            return redirect(url_for('profile.edit_profile'))
        
        elif new_password == old_password:
            flash('Password cannot be the same as the old one.')
            return redirect(url_for('profile.edit_profile'))
        
        elif new_password == confirm_new_password:

            for line in common_passwords:
                common = []
                if user.password == line.strip():
                    common.append(user.password)
                    flash('Invalid password. Password cannot be a common password.')
                    return redirect(url_for('profile.edit_profile'))

            if len(user.password) < 12:
                flash('Password must have at least 12 characters.')
                return redirect(url_for('profile.edit_profile'))
            elif len(user.password) > 128:
                flash('Password must have less than 128 characters.')
                return redirect(url_for('profile.edit_profile'))
            else:
                    
                if email:
                    user.email = email
                if first_name:
                    user.first_name = first_name
                if last_name:
                    user.last_name = last_name
                if phone_number:
                    user.phone_number = phone_number
                if address:
                    user.address = address

                flash('Password changed successfully!')
                user.password = generate_password_hash(new_password, method='sha256')

                msg = Message("Password updated")
                msg.recipients= [current_email]
                msg.body = """Dear {username},

                We hope this message finds you well. We wanted to inform you that your password on Deti@Merch has been successfully updated. Your information is now current, ensuring a seamless and personalized experience on our site.

                If you did not make these changes or have any concerns about your account security, please reach out to us at "detimerch@gmail.com". We take the security of your account seriously and will investigate any unauthorized changes promptly.

                Thank you for choosing Deti@Merch. We appreciate your trust in us, and we're committed to providing you with the best shopping experience.

                Best regards,
                Deti@Merch Security Team
                """.format(username=user.username)

                mail.send(msg)
                db.session.commit()     
                return redirect(url_for('profile.profile'))
    
    return redirect(url_for('profile.profile'))

@prof.route('/delete_profile',methods=['POST'])
@login_required
def delete_profile():
    user = User.query.filter_by(id=current_user.id).first()
    old_password = request.form.get('old_password')

    if old_password:
        if not check_password_hash(user.password, old_password):
            flash('Please check your password and try again.')
            return redirect(url_for('profile.edit_profile'))
        
        elif check_password_hash(user.password, old_password):
            db.session.delete(user)
            db.session.commit()
    else:
        flash('Please check your password and try again.')
        return redirect(url_for('profile.edit_profile'))    
        
    flash('Account deleted successfully!')
    return redirect(url_for('auth.login'))
        
