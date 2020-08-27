from functools import wraps
from flask import request, redirect, url_for, current_app
import jwt

def jwt_protected(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        authHeader = request.headers['Authorization']
        if (authHeader is not None) or (authHeader.startswith('JWT')):
            current_app.config['JWT_KEY'] = current_app.config['JWT_PUBLIC_KEY']
            decoded = jwt.decode(authHeader.split('JWT ')[1], current_app.config['JWT_KEY'], algorithms=current_app.config['SUPPORTED_ALGORITHMS'])

            return f(*args, **kwargs)
        else:
            return '400'
        return f(*args, **kwargs)
    return decorated_function
