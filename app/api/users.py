import re
from flask import Blueprint, make_response, jsonify, request
from flask_jwt_extended import jwt_required, create_access_token, get_jwt_identity
from werkzeug.exceptions import abort
from ..models import Users
from config import Config

users_bp = Blueprint('users', __name__)

error_pwd_validation_msg = 'Password must contain 6-20 characters, including Upper/Lowercase, special characters, and numbers.'

# Fetches user profile details based on the username
@users_bp.route(Config.USER_PROFILE, methods=['GET'])
@jwt_required()
def user_profile(username):
    if get_jwt_identity() == username:
        user = Users.objects.get(username=username)
        return make_response(jsonify({
            'name': user.name,
            'email': user.email,
            'dob': user.dob
        }), 200)
    abort(401)

# User can update their user profile
@users_bp.route(Config.UPDATE_PROFILE, methods=['PUT'])
@jwt_required()
def update_profile(username):
    if get_jwt_identity() == username:
        user = Users.objects(username=username).first()
        if 'name' in request.json:
            user.update(name=request.json['name'])
        if 'email' in request.json:
            user.update(email=request.json['email'])  # Corrected field
        if 'dob' in request.json:
            user.update(dob=request.json['dob'])
        return make_response(jsonify({'success': 'User profile updated successfully'}), 200)
    abort(401)

# User can change their password
@users_bp.route(Config.CHANGE_PASSWORD, methods=['PUT'])
@jwt_required()
def change_password(username):
    if get_jwt_identity() == username:
        user = Users.objects(username=username).first()
        old_password = request.json.get('old_password')
        new_password = request.json.get('new_password')

        if not old_password or not new_password:
            return make_response(jsonify({'error': 'Missing Fields'}), 400)

        if old_password == user.password:
            if not password_validation(new_password):
                return make_response(jsonify({'password_validation': error_pwd_validation_msg}), 400)
            user.update(password=new_password)
            return make_response(jsonify({'success': 'Password changed successfully'}), 200)
        return make_response(jsonify({'error': "Old password doesn't match"}), 401)
    abort(401)

# User can delete their account
@users_bp.route(Config.DELETE_ACCOUNT, methods=['DELETE'])
@jwt_required()
def delete_account(username):
    if get_jwt_identity() == username:
        user = Users.objects(username=username).first()
        if not user:
            abort(404)
        user.delete()
        return make_response(jsonify({"success": 'Account deleted successfully'}), 200)
    abort(401)

# User authentication
@users_bp.route(Config.SIGN_IN, methods=['POST'])
def sign_in():
    try:
        username = request.json['username']
        password = request.json['password']
        user = Users.objects.get(username=username, password=password)
        access_token = create_access_token(identity=username)
        return make_response(jsonify({
            'access_token': access_token,
            'name': user.name,
            'email': user.email,
            'dob': user.dob
        }), 200)
    except Users.DoesNotExist:
        return make_response(jsonify({'error': 'Incorrect Username or Password'}), 401)

# Create new account
@users_bp.route(Config.SIGN_UP, methods=['POST'])
def sign_up():
    try:
        username = request.json['username']
        if Users.objects(username=username).first():
            return make_response(jsonify({'error': f'Username {username} already exists'}), 400)

        email = request.json['email']
        if not email_validation(email):
            return make_response(jsonify({'error': f'{email} is not a valid email address'}), 400)

        password = request.json['password']
        if not password_validation(password):
            return make_response(jsonify({'error': error_pwd_validation_msg}), 400)

        user = Users(
            username=username,
            password=password,
            name=request.json['name'],
            email=email,
            dob=request.json['dob']
        )
        user.save()
        return make_response(jsonify({'success': 'User created successfully'}), 201)
    except KeyError:
        abort(400)

# Error handlers
@users_bp.errorhandler(400)
def invalid_request(error):
    return make_response(jsonify({'error': f'Invalid Request: {str(error)}'}), 400)

@users_bp.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Sorry, user not found'}), 404)

@users_bp.errorhandler(401)
def unauthorized(error):
    return make_response(jsonify({'error': 'Unauthorized access'}), 401)

# Utility methods
def password_validation(password):
    pwd_regex = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{6,20}$"
    return re.match(pwd_regex, password)

def email_validation(email):
    email_regex = r'^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
    return re.match(email_regex, email)
