# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from flask import Blueprint
from .routes import register_routes

blueprint = Blueprint(
    'authentication_blueprint',
    __name__,
    url_prefix=''
)

def init_app(app):
    register_routes(app)
