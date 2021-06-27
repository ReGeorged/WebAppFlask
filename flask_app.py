from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from cloudipsp import Api, Checkout
app=Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///shop.db'
app.config['SQLALCHEMY_BINDS'] = { 'users' : 'sqlite:///users.db'}
app.config['SQLALCHEMY_TRACK_MODIFICATION']=False
app.config['SECRET_KEY']='123'


db=SQLAlchemy(app)
bcrypt=Bcrypt(app)

login_manager=LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'





#DB-Table-Record
#Table
#id title price isActive
#1 Some 100 True
#2 Some2 200 False
#3 Some3 40 True
class Item(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    title=db.Column(db.String(100), nullable=False)
    price=db.Column(db.Integer, nullable=False)
    isActive=db.Column(db.Boolean, default=True)
    #text=db.Column(db.text, nullable=False)
    def __repr__(self):
        return self.title

class User (db.Model, UserMixin):
    __bind_key__="users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)

    password = db.Column(db.String(80), nullable=False)
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
#rac me aman mawama ;d

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Register")
    def validate_username(self, username):
        existing_user_name = User.query.filter_by(
            username=username.data).first()
        if existing_user_name:
            raise ValidationError(
                "This username already exists"
            )

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Log In")



@app.route('/')
def index():
    items=Item.query.order_by(Item.price).all()
    return render_template('index.html', data=items)
@app.route('/about')
def about():
    return render_template('about.html')
@app.route('/buy/<int:id>')
def item_buy(id):
    item=Item.query.get(id)
    api=Api(merchant_id=1396424,
            secret_key='test')
    checkout=Checkout(api=api)
    data={
        "currency":"USD",
        "amount": str(item.price)+"00"
    }
    url=checkout.url(data).get('checkout_url')
    return redirect(url)
@app.route('/create', methods=['POST','GET'])
def create():
    if request.method == "POST":
        title = request.form['title']
        price = request.form['price']
        item=Item(title=title, price=price)
        try:
            db.session.add(item)
            db.session.commit()
            return redirect('/')
        except:
            return "შეცდომა მოხდა"
    else:
        return render_template('create.html')
@app.route('/register', methods=['GET', "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return  redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route ('/dashboard', methods = ['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')



@app.route('/login', methods=['GET', "POST"])
def login():

    form = LoginForm()
    if form.validate_on_submit():
        user= User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))

    return  render_template('login.html', form = form)

@app.route('/logout', methods=['POST', 'GET'])
@login_required
def logout ():
    logout_user()
    return redirect(url_for('login'))


if __name__=="__main__":
   app.run(debug=True)
