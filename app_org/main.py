from flask import Blueprint, render_template
from flask_login import login_user, logout_user, login_required, current_user
from app_org.models import User, Product
from app_org import db
from flask import request, redirect, url_for
main = Blueprint('main', __name__)


@main.route('/', methods=['GET'])
@login_required
def index():
    user=User.query.filter_by(id=current_user.id).first()
    products = Product.query.all()
    return render_template('index.html',user=user, products=products)


@main.route('/' , methods=['POST'])
@login_required
def index_post():
    products = Product.query.all()
    return render_template('index.html', products=products)


@main.route('/product/<int:product_id>', methods=['GET'])
@login_required
def product(product_id):
    product = Product.query.filter_by(id=product_id).first()
    if not product:
        return render_template('404.html')
    return render_template('product.html', product=product)


@main.route('/addproduct', methods=['GET'])
@login_required
def add_product():
    user=User.query.filter_by(id=current_user.id).first()
    if user.isAdmin == False:
        return redirect(url_for('main.index'))
    else:
        return render_template('addproduct.html')

@main.route('/addproduct', methods=['POST'])
@login_required
def add_product_post():
    name = request.form.get('name')
    price = request.form.get('price')
    description = request.form.get('description')
    image = request.files.get('image')
    if image and not image.filename.endswith('.png') and not image.filename.endswith('.jpeg'):
        print('Please upload a .png or .jpeg image.')
        return redirect(url_for('main.add_product'))
    product = Product(name=name, price=price, description=description, image=image.filename)
    db.session.add(product)
    db.session.commit()
    return redirect(url_for('main.index'))