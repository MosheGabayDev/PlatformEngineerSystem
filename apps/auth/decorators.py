from functools import wraps
from flask import jsonify
from flask_login import current_user

def require_permission(resource, action):
    """
    Decorator to check if user has required permission
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return jsonify({'error': 'Authentication required'}), 401
                
            if not current_user.has_permission(resource, action):
                return jsonify({'error': 'Permission denied'}), 403
                
            return f(*args, **kwargs)
        return decorated_function
    return decorator 