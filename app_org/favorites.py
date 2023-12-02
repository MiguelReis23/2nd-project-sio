from flask import Blueprint, render_template, redirect, url_for, request, flash, Flask
from flask_login import login_required, current_user    
from app_org.models import User, Wishlist, Product
from app_org import db
import os

fvt= Blueprint('favorites', __name__)

@fvt.route('/favorites', methods=['GET'])
@login_required
def favorite():
    user=User.query.filter_by(id=current_user.id).first()
    wishlist = Wishlist.query.filter_by(user_id=current_user.id).all()
    product_details = [ Product.query.filter_by(id=wishlist_item.product_id).first() for wishlist_item in wishlist ]

    print("---------")
    print(product_details)
    print("---------")
    return render_template('favorites.html', user=user, product_details=product_details)


@fvt.route('/favorites/add/<int:product_id>', methods=['POST'])
@login_required
def add_to_favorites(product_id):
    product=Product.query.get(product_id)
    if product:
        wishlist_item = Wishlist.query.filter_by(user_id=current_user.id, product_id=product_id).first()
        if wishlist_item:
            flash("Item already in favorites")
        else:
            wishlist_item = Wishlist(user_id=current_user.id, product_id=product_id)
            db.session.add(wishlist_item)
            flash("item added to favorites")
        db.session.commit()
        print("---------")
        
        print("---------")

    return redirect(url_for('main.index'))


@fvt.route('/favorites/remove/<int:product_id>', methods=['POST'])
@login_required
def remove_from_favorites(product_id):
    product=Product.query.get(product_id)
    if product:
        wishlist_item = Wishlist.query.filter_by(user_id=current_user.id, product_id=product_id).first()
        if wishlist_item:
            db.session.delete(wishlist_item)
        db.session.commit()
        print("---------")
        print("---------")

    return redirect(url_for('favorites.favorite'))


