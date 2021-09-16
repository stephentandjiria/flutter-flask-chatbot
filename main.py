import werkzeug
from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy

from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

import os

import time
from datetime import datetime
from datetime import timedelta
from datetime import timezone

app = Flask(__name__)

# ====== FLASK_JWT SETUP 1 ======

app.config["JWT_SECRET_KEY"] = "asdf1234" # TODO: set in Heroku
# ACCESS_EXPIRES = timedelta(hours=1)
# app.config["JWT_ACCESS_TOKEN_EXPIRES"] = ACCESS_EXPIRES # TODO : uncomment if token has expiry time
jwt = JWTManager(app)

# ====== DATABASE SETUP ======

# Offline Mode
# app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Online Mode (Postgre)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app) # TODO : only for first time database creation

##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    username = db.Column(db.String(1000))

# for Logout : This could be expanded to fit the needs of your application. For example,
# it could track who revoked a JWT, when a token expires, notes for why a
# JWT was revoked, an endpoint to un-revoked a JWT, etc.
class TokenBlocklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False)

#Line below only required once, when creating DB.
# db.create_all()

# ====== FLASK_JWT SETUP 2 ======

# for Logout : Callback function to check if a JWT exists in the database blocklist
@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    token = db.session.query(TokenBlocklist.id).filter_by(jti=jti).scalar()
    return token is not None

# ====== API ROUTES ======

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
        print("Email is already taken")
        return jsonify({
            'msg': 'Email is already taken',
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

        access_token = create_access_token(identity=new_user.username)
        return jsonify({
            'msg': 'Register completed',
            'access_token': access_token,
        })

@app.route('/login', methods=["POST"])
def login():
    email = request.form.get('email')
    password = request.form.get('password')

    # check if user exists in database
    user = User.query.filter_by(email=email).first()

    if user == None:
        return jsonify({
            'msg': 'Wrong email',
        })
    else:
        # check if inserted password, if hashed, matches database's password (previously hashed in registration)
        if check_password_hash(user.password, password):
            access_token = create_access_token(identity=user.username)
            return jsonify({
                'msg': 'Login successful',
                'access_token': access_token,
            })
        else:
            return jsonify({
                'msg': 'Wrong password',
            })

# Protect a route with jwt_required, which will kick out requests
# without a valid JWT present.
@app.route("/get_user", methods=["GET"])
@jwt_required()
def get_user():
    # Access the identity of the current user with get_jwt_identity
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

# TODO : Token refresh API route https://flask-jwt-extended.readthedocs.io/en/stable/refreshing_tokens/#explicit-refreshing-with-refresh-tokens

# Endpoint for revoking the current users access token. Saved the unique
# identifier (jti) for the JWT into our database.
@app.route("/logout", methods=["DELETE"])
@jwt_required()
def modify_token():
    jti = get_jwt()["jti"]
    now = datetime.now(timezone.utc)
    db.session.add(TokenBlocklist(jti=jti, created_at=now))
    db.session.commit()
    return jsonify(msg="JWT revoked")

# A blocklisted access token will not be able to access this any more
# TODO : Any protected API route
@app.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    return jsonify(msg="hello world")

if __name__ == '__main__':
    app.run(host='0.0.0.0',)