from datetime import datetime
from flask_login import UserMixin
from app_sec import db
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    isAdmin = db.Column(db.Boolean, default=False)
    phone_number = db.Column(db.String(20))
    image = db.Column(db.String(20), nullable=False, default='default.png')
    address = db.Column(db.String(100))
    failed_login_attempts = db.Column(db.Integer, default=0)
    last_login_attempt = db.Column(db.DateTime, default= datetime.now())
    key = db.Column(db.String(32), nullable=False)

    
    def increment_failed_login_attempts(self):
        self.failed_login_attempts += 1
        self.last_login_attempt = datetime.now()

    def reset_failed_login_attempts(self):
        self.failed_login_attempts = 0    
           

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description= db.Column(db.String(1000))
    price = db.Column(db.Float, nullable=False)
    image = db.Column(db.String(20), nullable=False, default='favicon.png')
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


class AddToWishlistForm(FlaskForm):
    submit = SubmitField('Add to wishlist')

class RemoveFromWishlistForm(FlaskForm):
    submit = SubmitField('Remove from wishlist')

class AddToCartForm(FlaskForm):
    submit = SubmitField('Add to cart')

class RemoveFromCartForm(FlaskForm):
    submit = SubmitField('Remove from cart')

class UpdateCartForm(FlaskForm):
    submit = SubmitField('Update cart')

class CheckoutForm(FlaskForm):
    submit = SubmitField('Checkout')

class CheckoutConfirmForm(FlaskForm):
    submit = SubmitField('Confirm checkout')

class AddProductForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    price = StringField('Price', validators=[DataRequired()])
    description = StringField('Description')
    image = StringField('Image')
    category = StringField('Category', validators=[DataRequired()])
    submit = SubmitField('Add product')


