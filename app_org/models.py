from flask_login import UserMixin
from app_org import db

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    first_name = db.Column(db.String(100), default= "")
    last_name = db.Column(db.String(100))
    isAdmin = db.Column(db.Boolean, default=False)
    phone_number = db.Column(db.String(20))
    image = db.Column(db.String(20), nullable=False, default='default.png')
    address = db.Column(db.String(100))
    failed_login_attempts = db.Column(db.Integer, default=0)
    
    def increment_failed_login_attempts(self):
        self.failed_login_attempts += 1

    def reset_failed_login_attempts(self):
        self.failed_login_attempts = 0

    def default_username(self):
        self.first_name = self.username
        

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description= db.Column(db.String(1000))
    price = db.Column(db.Float, nullable=False)
    image = db.Column(db.String(20), nullable=False, default='default_image.png')
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    category= db.relationship('Category', backref=db.backref('products', lazy=True))
    has_stock = db.Column(db.Boolean, default=True)

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)

class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
    quantity = db.Column(db.Integer, nullable=False, default=1)

class Wishlist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
