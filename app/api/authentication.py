from flask import g, jsonify, request
from flask_httpauth import HTTPBasicAuth
from app.models.User import User, AnonymousUser
from . import api
from .errors import unauthorized, forbidden
from .. import db

auth = HTTPBasicAuth()

@api.route('/register', methods=['POST'])
def create_user():
    request_data = request.get_json()
    print(request_data)
    user = User(email=request_data['email'],
                    username=request_data['username'],
                    password=request_data['password'])
    db.session.add(user)
    db.session.commit()
    token = user.generate_confirmation_token()
    return jsonify({'token': g.current_user.generate_auth_token(
        expiration=3600), 'expiration': 3600})

@auth.verify_password
def verify_password(email_or_token, password):
    if email_or_token == '':
        g.current_user = AnonymousUser()
        return True
    if password == '':
        g.current_user = User.verify_auth_token(email_or_token)
        g.token_used = True
        return g.current_user is not None
    user = User.query.filter_by(email=email_or_token).first()
    if not user:
        return False
    g.current_user = user
    g.token_used = False
    return user.verify_password(password)

@auth.error_handler
def auth_error():
    return unauthorized('Invalid credentials')

@api.before_request
@auth.login_required
def before_request():
    if not g.current_user.is_anonymous and \
            not g.current_user.confirmed:
        return forbidden('Unconfirmed account')

@api.route('/token')
def get_token():
    if g.current_user.is_anonymous or g.token_used:
        return unauthorized('Invalid credentials')
    return jsonify({'token': g.current_user.generate_auth_token(
        expiration=3600), 'expiration': 3600})
