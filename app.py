from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask import Flask, render_template, redirect, url_for, request, flash
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms.validators import DataRequired, Length
from wtforms import StringField, SubmitField, validators
from flask_sqlalchemy import SQLAlchemy
from cryptography.fernet import Fernet
from flask_wtf import FlaskForm
from datetime import datetime
import webbrowser
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'fallback_key')
app.config['SQLALCHEMY_DATABASE_URI'] = (
    'mssql+pyodbc://SVR-CMP-01/22MayC294?driver=ODBC+Driver+17+for+SQL+Server&Trusted_Connection=yes'
)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_PROTECTION'] = 'strong'

ENCRYPTION_KEY = Fernet.generate_key()
cipher = Fernet(ENCRYPTION_KEY)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    name = db.Column(db.String(50), nullable=False, server_default='')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class DiaryEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('diary_entries', lazy=True))

class PaymentInfo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    card_number = db.Column(db.String(16), nullable=False)
    expiration_date = db.Column(db.String(5), nullable=False)
    cvv = db.Column(db.String(3), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('payment_info', lazy=True))

class Subscription(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    is_subscribed = db.Column(db.Boolean, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('subscription', lazy=True))

    def __init__(self, is_subscribed, user):
        self.is_subscribed = is_subscribed
        self.user = user

class PaymentForm(FlaskForm):
    card_number = StringField('Card Number', validators=[DataRequired(), Length(min=16, max=16)])
    expiration_date = StringField('Expiration Date (MM/YY)', validators=[DataRequired(), Length(min=5, max=5), validators.Regexp(r'\d{2}/\d{2}', message='Must be in MM/YY format')])
    cvv = StringField('CVV', validators=[DataRequired(), Length(min=3, max=3)])
    submit = SubmitField('Subscribe')

def process_payment(card_number, expiration_date, cvv):
    return True

def encrypt_card_info(card_number, expiration_date, cvv):
    data = f"{card_number}::{expiration_date}::{cvv}"
    encrypted_data = cipher.encrypt(data.encode())
    return encrypted_data

def decrypt_card_info(encrypted_data):
    decrypted_data = cipher.decrypt(encrypted_data).decode()
    card_number, expiration_date, cvv = decrypted_data.split("::")
    return card_number, expiration_date, cvv

@app.route('/subscription', methods=['GET', 'POST'])
@login_required
def subscription():
    form = PaymentForm()

    if form.validate_on_submit():
        payment_successful = process_payment(form.card_number.data, form.expiration_date.data, form.cvv.data)

        if payment_successful:
            payment_info = PaymentInfo(
                card_number=form.card_number.data,
                expiration_date=form.expiration_date.data,
                cvv=form.cvv.data,
                user=current_user
            )
            db.session.add(payment_info)

            current_user.subscription.is_subscribed = True

            subscription = Subscription(is_subscribed=True, user=current_user)
            db.session.add(subscription)

            db.session.commit()

            flash('Subscription successful!', 'success')
            return redirect(url_for('homepage'))
        else:
            flash('Payment failed. Please check your payment information and try again.', 'danger')

    return render_template('subscriptions.html', form=form)

@app.route('/diary', methods=['GET', 'POST'])
@login_required
def diary():
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')

        new_entry = DiaryEntry(title=title, content=content, user=current_user, date=datetime.utcnow())
        db.session.add(new_entry)
        db.session.commit()
        flash('Diary entry added successfully.', 'success')
        
    diary_entries = DiaryEntry.query.filter_by(user=current_user).all()

    return render_template('diary.html', diary_entries=diary_entries, username=current_user.username)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        name = request.form['name']

        if User.query.filter_by(username=username).first():
            flash('Email is already in use; choose a different one.', 'danger')
        else:
            new_user = User(username=username, name=name)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully; you can now log in.', 'success')
            return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('homepage'))
        else:
            flash('Invalid email or password; please try again.', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/homepage')
@login_required
def homepage():
    return render_template('homepage.html', username=current_user.username)

@app.route('/navbar')
@login_required
def navbar():
    return render_template('navbar.html')

def open_browser():
    webbrowser.open_new_tab('http://127.0.0.1:5000/signup')

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    open_browser()
    app.run(debug=True, use_reloader=False)
