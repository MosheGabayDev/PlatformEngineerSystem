# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

import os
from flask import Flask, request, redirect, url_for
from flask_login import LoginManager, current_user
from flask_sqlalchemy import SQLAlchemy
from importlib import import_module
from flasgger import Swagger
from apps.scheduler import start_scheduler
from apps.scheduler_ui import scheduled_tasks_bp
from apps.db import db
from apps.authentication.models import Users

login_manager = LoginManager()

@login_manager.unauthorized_handler
def unauthorized_handler():
    from flask import render_template
    return render_template('home/page-403.html'), 403

@login_manager.user_loader
def user_loader(id):
    return Users.query.filter_by(id=id).first()

@login_manager.request_loader
def request_loader(request):
    username = request.form.get('username')
    user = Users.query.filter_by(username=username).first()
    return user if user else None

def register_extensions(app):
    db.init_app(app)
    login_manager.init_app(app)

def register_blueprints(app):
    for module_name in ('authentication', 'home', 'dyn_dt', 'charts'):
        module = import_module('apps.{}.routes'.format(module_name))
        app.register_blueprint(module.blueprint)

from apps.authentication.oauth import github_blueprint, google_blueprint

def create_app(config):

    # Contextual
    static_prefix = '/static'
    templates_dir = os.path.dirname(config.BASE_DIR)

    TEMPLATES_FOLDER = os.path.join(templates_dir,'templates')
    STATIC_FOLDER = os.path.join(templates_dir,'static')

    print(' > TEMPLATES_FOLDER: ' + TEMPLATES_FOLDER)
    print(' > STATIC_FOLDER:    ' + STATIC_FOLDER)

    app = Flask(__name__, static_url_path=static_prefix, template_folder=TEMPLATES_FOLDER, static_folder=STATIC_FOLDER)

    app.config.from_object(config)
    register_extensions(app)
    register_blueprints(app)
    app.register_blueprint(github_blueprint, url_prefix="/login")    
    app.register_blueprint(google_blueprint, url_prefix="/login")    
    # Import and register the API blueprint here to avoid circular import
    from apps.api import api_bp
    app.register_blueprint(api_bp)
    app.register_blueprint(scheduled_tasks_bp)
    Swagger(app)
    # start_scheduler(app)

    @app.before_request
    def require_login():
        endpoint = request.endpoint or ""
        if (
            endpoint is None
            or endpoint.startswith("static")
            or "login" in endpoint
            or "register" in endpoint
            or endpoint == "favicon"
        ):
            return
        if not current_user.is_authenticated:
            return redirect(url_for('authentication_blueprint.login'))

    return app
