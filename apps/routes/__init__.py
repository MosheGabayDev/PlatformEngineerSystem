from flask import Blueprint

blueprint = Blueprint('main', __name__)

from . import views

def init_app(app):
    from .main import bp as main_bp
    from .auth import bp as auth_bp
    from .admin import bp as admin_bp
    from .tasks import bp as tasks_bp
    from .task_chains import bp as task_chains_bp
    from .monitoring import bp as monitoring_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(admin_bp, url_prefix='/admin')
    app.register_blueprint(tasks_bp, url_prefix='/tasks')
    app.register_blueprint(task_chains_bp)
    app.register_blueprint(monitoring_bp, url_prefix='/monitoring') 