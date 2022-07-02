from flask import Flask, jsonify, render_template, redirect, url_for, request, abort, flash
from flask_sqlalchemy import SQLAlchemy
from forms import AddCafe, Register, Login
from flask_login import login_user, UserMixin, LoginManager, current_user, logout_user
from flask_bootstrap import Bootstrap
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////professional/Cafe and Wifi/cafes.db'
app.config['SECRET_KEY'] = 'lksdfunliesu'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
bootstrap = Bootstrap(app)
login_manager = LoginManager(app)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(30), nullable=False)
    password = db.Column(db.String(12), nullable=False)


class Cafe(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), unique=True, nullable=False)
    map_url = db.Column(db.String(500), nullable=False)
    img_url = db.Column(db.String(500), nullable=False)
    location = db.Column(db.String(250), nullable=False)
    seats = db.Column(db.String(250), nullable=False)
    has_toilet = db.Column(db.Boolean, nullable=False)
    has_wifi = db.Column(db.Boolean, nullable=False)
    has_sockets = db.Column(db.Boolean, nullable=False)
    can_take_calls = db.Column(db.Boolean, nullable=False)
    coffee_price = db.Column(db.String(250), nullable=True)

    def to_dict(self):
        return {column.name: getattr(self, column.name) for column in self.__table__.columns}


# db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(id=user_id).first()


def authenticated_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function


@app.route('/login', methods=['GET', 'POST'])
def login():
    login_form = Login()
    user = User.query.filter_by(email=login_form.email.data).first()
    if user:
        if check_password_hash(pwhash=user.password, password=login_form.password.data):
            login_user(user)
            return redirect(url_for('show_all_cafes'))
        else:
            flash('Please Check your Email/Password')
    else:
        flash('User does not exist')
    return render_template('login.html', form=login_form)


@app.route('/register', methods=["GET", "POST"])
def register():
    register_form = Register()
    if register_form.validate_on_submit():
        user = User.query.filter_by(email=register_form.email.data).first()
        if not user:
            if register_form.password.data == register_form.re_password.data:
                new_user = User(
                    email=register_form.email.data,
                    password=generate_password_hash(password=register_form.password.data, method="pbkdf2:sha256",
                                                    salt_length=8)
                )
                db.session.add(new_user)
                db.session.commit()
                return redirect(url_for('login'))
            else:
                flash('password does not match')
        else:
            flash('User Already Exist.')
    return render_template('register.html', form=register_form)


@app.route('/logout_user')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/')
def home():
    return 'Welcome to Cafe and Wifi' \
           '<br/>' \
           '<a href="/show_all_cafes">Start Here</a>'


@app.route('/show_all_cafes')
def show_all_cafes():
    cafes = db.session.query(Cafe).all()
    return render_template('index.html', cafes=cafes)


@app.route("/search", methods=["GET"])
def search_cafe():
    query_name = request.args.get("n").title()
    cafe = db.session.query(Cafe).filter_by(name=query_name).first()
    if cafe:
        return render_template('search_cafe.html', cafe=cafe)
    else:
        return "<h2><center>Really Sorry... We don't have that Cafe info</center></h2>", 404


@app.route('/add-cafe', methods=["GET", "POST"])
@authenticated_only
def add_cafe():
    form = AddCafe()
    if form.validate_on_submit():
        new_cafe = Cafe(
            name=form.name.data,
            map_url=form.map_url.data,
            img_url=form.img_url.data,
            location=form.location.data,
            has_sockets=form.has_sockets.data,
            has_toilet=form.has_toilet.data,
            has_wifi=form.has_wifi.data,
            can_take_calls=form.can_take_calls.data,
            seats=form.seats.data,
            coffee_price=form.coffee_price.data
        )
        db.session.add(new_cafe)
        db.session.commit()
        return '<center><h1>Success</h1></center>'
    return render_template('add_cafe.html', form=form)


@app.route('/update-cafe/<int:cafe_id>', methods=['PATCH', 'GET'])
def update_cafe(cafe_id):
    # form = AddCafe()
    coffee_price = request.args.get('p')
    cafe = db.session.query(Cafe).filter_by(id=cafe_id).first()
    if cafe:
        cafe.coffee_price = coffee_price
        db.session.commit()
        return 'Success', 200
    return 'Cafe Not available'


@app.route('/delete/<int:cafe_id>')
def delete_cafe(cafe_id):
    if request.args.get('api_key') == "secret_api_key":
        cafe = db.session.query(Cafe).filter_by(id=cafe_id).first()
        if cafe:
            db.session.delete(cafe)
            db.session.commit()
            return "<center><h3>Cafe has been deleted</h3></center>"
        else:
            return "<center><h3></h3>Cafe Not available</center>"
    else:
        return "<center><h3>You are not authorized to delete Cafe</h3></center>"


if __name__ == '__main__':
    app.run(debug=True)
