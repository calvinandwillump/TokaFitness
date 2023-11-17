from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
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

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    name = db.Column(db.String(50), nullable=False, server_default='')

class DiaryEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('diary_entries', lazy=True))

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
            flash('Email is already in use choose a different one.', 'danger')
        else:
            new_user = User(username=username, password=password, name=name)
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully you can now log in.', 'success')
            return redirect(url_for('login'))
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and user.password == password:
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('homepage'))
        else:
            flash('Invalid email or password please try again.', 'danger')

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
def navbar():
    return render_template('navbar.html')

def open_browser():
    webbrowser.open_new_tab('http://127.0.0.1:5000/signup')

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    open_browser()
    app.run(debug=True, use_reloader=False)
