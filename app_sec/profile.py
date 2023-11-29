from flask import Blueprint, render_template, redirect, url_for, request, flash, Flask
from flask_login import login_required, current_user    
from app_sec.models import User
from app_sec import db
import os
from werkzeug.security import generate_password_hash

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
    print("BBBBB")
    # image = request.files.get('image')

    # if image and not image.filename.endswith('.png') and not image.filename.endswith('.jpeg'):
    #     print('Please upload a .png or .jpeg image.')
    #     return redirect(url_for('profile.edit_profile', id=current_user.id))
 
    #password = request.form.get('password')
    user = User.query.filter_by(id=current_user.id).first()
    new_password = request.form.get('new_password')
    confirm_new_password = request.form.get('confirm_new_password')
    print("AAAAA")
    
    if new_password == confirm_new_password:
        user.password = generate_password_hash(new_password, method='sha256')
    else:
        print('Passwords do not match.')
        return render_template('profile.edit_profile', user=user)
    
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
        # if image:
        #     user.image = image.filename
        #     image.save(os.path.join("app/static/pictures",image.filename))
    
    
    db.session.commit()

    print("------------------")
    print('User profile updated.')
    print("------------------")

    return redirect(url_for('profile.profile'))