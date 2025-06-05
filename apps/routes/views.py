from flask import render_template
from . import blueprint

@blueprint.route('/')
def index():
    return render_template('index.html')

@blueprint.route('/dashboard')
def dashboard():
    return render_template('dashboard.html') 