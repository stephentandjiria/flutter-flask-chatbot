from flask import Flask, jsonify, request
import time
from flask_wtf.csrf import CSRFProtect

import werkzeug
from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

import os

app = Flask(__name__)

# app.config['SECRET_KEY'] = '9A1945'
app.config['SECRET_KEY'] = os.getenv("9A1945")
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
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
    name = db.Column(db.String(1000))

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
        # print("user exists, logging in")
        login_user(user)
        return jsonify({
            'message': 'User exists, logging in',
            'user': user,
        })
    else:
        hash_and_salted_password = generate_password_hash(
            password,
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            email=email,
            name=request.form.get('name'),
            password=hash_and_salted_password,
        )

        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)
        return jsonify({
            'message': 'Register completed',
            'user': new_user,
        })

@app.route('/login', methods=["POST"])
def login():
    email = request.form.get('email')
    password = request.form.get('password')

    # check if user exists in database
    user = User.query.filter_by(email=email).first()

    if user == None:
        return jsonify({
            'message': 'Wrong username',
            'user': 'No user',
        })
    else:
        # check if inserted password, if hashed, matches database's password (previously hashed in registration)
        if check_password_hash(user.password, password):
            login_user(user)
            return jsonify({
                'message': 'Login successful',
                'user': user,
            })
        else:
            return jsonify({
                'message': 'Wrong password',
                'user': 'No user',
            })

@app.route('/logout')
def logout():
    logout_user()
    return jsonify({
        'message': 'Logout successful',
        'user': 'No user',
    })

@app.route('/secrets')
@login_required
def secrets():
    return jsonify({
        'message': f'{current_user.name} is seeing this.',
        'user': current_user.name,
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0',)