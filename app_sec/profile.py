import re
from flask import Blueprint, render_template, redirect, url_for, request, flash, Flask, session
from flask_login import login_required, current_user    
from app_sec.models import User
from app_sec import db, mail
from flask_mail import Message
import os
from werkzeug.security import generate_password_hash, check_password_hash

prof = Blueprint('profile', __name__)

@prof.route('/profile')
@login_required
def profile():
    user = User.query.filter_by(id=current_user.id).first()	
    return render_template('profile.html', user=user)

@prof.route('/edit_profile/')
@login_required
def edit_page():
    user = User.query.filter_by(id=current_user.id).first()
    return render_template('edit_profile.html', user=user)


@prof.route('/edit_profile', methods=['POST'])
@login_required
def edit_profile():
    email = request.form.get('email')
    first_name = request.form.get('first_name')
    last_name = request.form.get('last_name')
    phone_number = request.form.get('phone_number')
    address = request.form.get('address')
    
    # image = request.files.get('image')

    # if image and not image.filename.endswith('.png') and not image.filename.endswith('.jpeg'):
    #     print('Please upload a .png or .jpeg image.')
    #     return redirect(url_for('profile.edit_profile', id=current_user.id))
 
    #password = request.form.get('password')


  
    user = User.query.filter_by(id=current_user.id).first()
    current_email = user.email
    old_password = request.form.get('old_password')
    new_password = request.form.get('new_password')
    confirm_new_password = request.form.get('confirm_new_password')
    
    common_passwords = open('PASSWORDS.txt', 'r', encoding='utf-8')

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
            print(current_email)

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
                db.session.commit()     
                return redirect(url_for('profile.edit_profile'))

    
        # if image:
        #     user.image = image.filename
        #     image.save(os.path.join("app/static/pictures",image.filename))
    
    
    return redirect(url_for('profile.profile'))