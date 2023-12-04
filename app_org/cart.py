from flask import Blueprint, render_template, redirect, url_for, request, flash, Flask
from flask_login import login_required, current_user    
from app_org.models import User
from app_org.models import Product
from app_org.models import Cart


from app_org import db
import os


crt= Blueprint('cart', __name__)

@crt.route('/cart', methods=['GET'])
@login_required
def cart():
    user=User.query.get(current_user.id)
    cart = Cart.query.filter_by(user_id=current_user.id).all()
    product_details = [ Product.query.filter_by(id=cart_item.product_id).first() for cart_item in cart ]
    CartItem = [(Product.query.get(cart_item.product_id), cart_item.quantity) for cart_item in cart]
    total=sum([product.price*quantity for product,quantity in CartItem])
    print("--------AA")
    print(CartItem)
    print("---------AAAA")
    for product in product_details:
        print(product.image)
    return render_template('cart.html', user=user, CartItem=CartItem,total=total)


@crt.route('/cart/add/<int:product_id>', methods=['POST'])
@login_required
def add_to_cart(product_id):
    product=Product.query.get(product_id)
    if product:
        cart_item = Cart.query.filter_by(user_id=current_user.id, product_id=product_id).first()
        if cart_item:
            flash("Item quantity in cart increased")
            cart_item.quantity += 1
        else:
            cart_item = Cart(user_id=current_user.id, product_id=product_id)
            db.session.add(cart_item)
            print("---------")
            flash("item added to cart")
            print("---------")
        db.session.commit()
        
    return redirect(url_for('main.index'))


@crt.route('/cart/remove/<int:product_id>', methods=['POST'])
@login_required
def remove_from_cart(product_id):
    product=Product.query.get(product_id)
    if product:
        cart_item = Cart.query.filter_by(user_id=current_user.id, product_id=product_id).first()
        if cart_item:
            db.session.delete(cart_item)
        db.session.commit()
        print("---------")
        flash("item removed from cart")
        print("---------")

    return redirect(url_for('cart.cart'))

@crt.route('/cart/update/<int:product_id>', methods=['POST'])
@login_required
def update_cart(product_id):
    product=Product.query.get(product_id)
    if product:
        cart_item = Cart.query.filter_by(user_id=current_user.id, product_id=product_id).first()
        if cart_item:
            cart_item.quantity = int(request.form.get('quantity'))
        if cart_item.quantity == 0:
            cart_item.quantity = 1
        if cart_item.quantity < 0:
            cart_item.quantity = 1
        flash("item quantity updated")
        db.session.commit()
    
    print("---------")
    print(cart_item.quantity)
    print("---------")

    return redirect(url_for('cart.cart'))


@crt.route('/cart/checkout', methods=['POST'])
@login_required
def checkout():
    user=User.query.get(current_user.id)
    cart = Cart.query.filter_by(user_id=current_user.id).all()
    CartItem = [(Product.query.get(cart_item.product_id), cart_item.quantity) for cart_item in cart]
    total=sum([product.price*quantity for product,quantity in CartItem])
    return render_template('checkout.html', user=user,total=total)


@crt.route('/cart/checkout/confirm', methods=['POST'])
@login_required
def confirm_checkout():
    db.session.query(Cart).filter(Cart.user_id == current_user.id).delete()
    db.session.commit()
    flash("Order confirmed")
    return redirect(url_for('main.index'))



