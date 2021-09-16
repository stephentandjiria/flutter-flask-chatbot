import werkzeug
from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

import os

import time

app = Flask(__name__)

# Offline Mode
app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Online Mode (Postgre)
# app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
# app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Login preparation
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- End of Login preparation ---

##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    username = db.Column(db.String(1000))

#Line below only required once, when creating DB.
db.create_all()

@app.route('/')
def home():
    logged_in = current_user.is_authenticated
    print(logged_in)
    return jsonify({
        'logged_in': logged_in,
    })

@app.route('/bot', methods=['POST'])
def response():
    query = dict(request.form)['query']
    result = query + ' ' + time.ctime()
    return jsonify({'response' : result})

@app.route('/register', methods=["POST"])
def register():
    email = request.form.get('email')
    password = request.form.get('password')

    # check if user exists in database
    user = User.query.filter_by(email=email).first()

    if user != None:
        print("user exists, logging in")
        login_user(user)
        return jsonify({
            'message': 'User exists, logging in',
            'username': user.username,
        })
    else:
        hash_and_salted_password = generate_password_hash(
            password,
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            email=email,
            username=request.form.get('username'),
            password=hash_and_salted_password,
        )

        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)
        return jsonify({
            'message': 'Register completed',
            'username': new_user.username,
        })

@app.route('/login', methods=["POST"])
def login():
    email = request.form.get('email')
    password = request.form.get('password')

    # check if user exists in database
    user = User.query.filter_by(email=email).first()

    if user == None:
        return jsonify({
            'message': 'Wrong email',
            'username': 'No user',
        })
    else:
        # check if inserted password, if hashed, matches database's password (previously hashed in registration)
        if check_password_hash(user.password, password):
            login_user(user)
            return jsonify({
                'message': 'Login successful',
                'username': user.username,
            })
        else:
            return jsonify({
                'message': 'Wrong password',
                'username': 'No user',
            })

@app.route('/get_user', methods=["GET"])
def get_user():
    logged_in = current_user.is_authenticated
    print(logged_in)
    if logged_in:
        username = current_user.username
        return jsonify({
            'logged_in': logged_in,
            'username': username,
        })
    else:
        return jsonify({
            'logged_in': logged_in,
            'username': '<user not logged-in>',
        })

@app.route('/logout')
def logout():
    logout_user()
    return jsonify({
        'message': 'Logout successful',
        'username': 'No user',
    })

@app.route('/secrets')
@login_required
def secrets():
    return jsonify({
        'message': f'{current_user.username} is seeing this.',
        'username': current_user.username,
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0',)