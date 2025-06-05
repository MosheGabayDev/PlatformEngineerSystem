# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

import os
from flask import Flask, request, redirect, url_for, render_template
from flask_login import LoginManager, current_user
from flask_sqlalchemy import SQLAlchemy
from importlib import import_module
from flasgger import Swagger
from apps.scheduler import start_scheduler
from apps.scheduler_ui import scheduled_tasks_bp
from apps.db import db
from apps.authentication.models import Users
import logging
from logging.handlers import RotatingFileHandler
from logging import basicConfig, DEBUG, getLogger, StreamHandler
from os import path
from apps.server_profiles.routes import server_profiles
import datetime as dt
import json
from flask_migrate import Migrate
from apps.tasks import tasks_bp, tasks_ui_bp
from apps.extensions import migrate
from apps.routes import blueprint

login_manager = LoginManager()
migrate = Migrate()

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
    migrate.init_app(app, db)

def register_blueprints(app):
    print("Registering blueprints...")
    
    # Import and register the API blueprints
    from apps.api import api_bp, client_api
    print("Registering api_bp and client_api blueprints")
    app.register_blueprint(api_bp)
    app.register_blueprint(client_api)
    print("API blueprints registered successfully")
    
    # Import and register other blueprints
    for module_name in ('authentication', 'home', 'dyn_dt', 'charts'):
        try:
            print(f"Trying to import {module_name} blueprint")
            module = import_module(f'apps.{module_name}.routes')
            if hasattr(module, 'blueprint'):
                print(f"Registering {module_name} blueprint")
                app.register_blueprint(module.blueprint)
                print(f"{module_name} blueprint registered successfully")
        except ImportError as e:
            print(f"Could not import {module_name}: {e}")
            continue
        except Exception as e:
            print(f"Error registering {module_name} blueprint: {e}")
            continue
    
    print("Finished registering blueprints")
    
    # Import and register the routes blueprint
    app.register_blueprint(blueprint)
    print("Routes blueprint registered successfully")

def configure_database(app):
    with app.app_context():
        try:
            db.create_all()
            print("Database tables created successfully")
        except Exception as e:
            print('> Error: DBMS Exception: ' + str(e))

    @app.teardown_request
    def shutdown_session(exception=None):
        db.session.remove()

def create_app(config_object=None):
    app = Flask(__name__)
    
    if config_object:
        app.config.from_object(config_object)
    
    # Initialize logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger('werkzeug')
    logger.setLevel(logging.INFO)
    
    @app.before_request
    def log_request_info():
        app.logger.info('Request URL: %s', request.url)
        app.logger.info('Request Method: %s', request.method)
        app.logger.info('Request Headers: %s', dict(request.headers))
    
    register_extensions(app)
    register_blueprints(app)
    configure_database(app)
    app.register_blueprint(scheduled_tasks_bp)
    app.register_blueprint(server_profiles)
    app.register_blueprint(tasks_bp, url_prefix='/api')
    app.register_blueprint(tasks_ui_bp)
    Swagger(app)
    # start_scheduler(app)

    # --- LOGGING CONFIGURATION ---
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../logs')
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    log_file = os.path.join(log_dir, 'app.log')
    file_handler = RotatingFileHandler(log_file, maxBytes=5*1024*1024, backupCount=5, encoding='utf-8')
    file_handler.setLevel(logging.INFO)
    formatter = logging.Formatter('[%(asctime)s] %(levelname)s in %(module)s: %(message)s')
    file_handler.setFormatter(formatter)
    if not app.logger.handlers:
        app.logger.addHandler(file_handler)
    else:
        # Avoid duplicate handlers
        for h in app.logger.handlers:
            if isinstance(h, RotatingFileHandler) and h.baseFilename == log_file:
                break
        else:
            app.logger.addHandler(file_handler)
    # --- END LOGGING CONFIGURATION ---

    @app.before_request
    def require_login():
        # Skip authentication for client API endpoints
        if request.path.startswith('/api/client/'):
            return None
            
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

    # Template filter להמרת זמן מ-UTC לזמן מקומי
    @app.template_filter('to_local_time')
    def to_local_time(utc_dt, format_str='%d/%m/%Y %H:%M'):
        """Convert UTC datetime to local time and format it"""
        if not utc_dt:
            return 'Never'
        
        # If the datetime is naive (no timezone info), assume it's UTC
        if utc_dt.tzinfo is None:
            utc_dt = utc_dt.replace(tzinfo=dt.timezone.utc)
        
        # Convert to local time
        local_dt = utc_dt.astimezone()
        
        return local_dt.strftime(format_str)

    @app.template_filter('from_json')
    def from_json(value):
        try:
            return json.loads(value)
        except:
            return []

    # Register error handlers
    @app.errorhandler(404)
    def not_found_error(error):
        return render_template('404.html'), 404

    @app.errorhandler(500)
    def internal_error(error):
        return render_template('500.html'), 500

    return app
