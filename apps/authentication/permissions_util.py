import json
from flask_login import current_user
from functools import wraps
from flask import abort

def require_permission(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user or not hasattr(current_user, 'is_authenticated') or not current_user.is_authenticated:
                abort(403)
            try:
                user_perms = json.loads(current_user.permissions) if current_user.permissions else []
            except Exception:
                user_perms = []
            user_perms = [str(p).strip().lower() for p in user_perms]
            if 'admin' in user_perms or permission.lower() in user_perms:
                return f(*args, **kwargs)
            abort(403)
        return decorated_function
    return decorator 