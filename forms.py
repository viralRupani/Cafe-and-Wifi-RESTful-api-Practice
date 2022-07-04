from flask_wtf import FlaskForm
from wtforms import StringField, BooleanField, SubmitField, EmailField, PasswordField
from wtforms.validators import DataRequired


class AddCafe(FlaskForm):
    name = StringField('name', validators=[DataRequired()])
    map_url = StringField('map_url', validators=[DataRequired()])
    img_url = StringField('img_url', validators=[DataRequired()])
    location = StringField('location', validators=[DataRequired()])
    seats = StringField('seats', validators=[DataRequired()])
    has_toilet = BooleanField('has_toilet')
    has_wifi = BooleanField('has_wifi')
    has_sockets = BooleanField('has_sockets')
    can_take_calls = BooleanField('can_take_calls')
    coffee_price = StringField('coffee_price')
    submit = SubmitField('Submit')


class Register(FlaskForm):
    email = EmailField('email', validators=[DataRequired()])
    password = PasswordField('password', validators=[DataRequired()])
    # re_password = PasswordField('re_password', validators=[DataRequired()])
    register = SubmitField('register')


class Login(FlaskForm):
    email = EmailField('email', validators=[DataRequired()])
    password = PasswordField('password', validators=[DataRequired()])
    login = SubmitField('login')
