from flask import Blueprint, render_template
from apps.db import db
from apps.models import ScheduledTask

scheduled_tasks_bp = Blueprint('scheduled_tasks', __name__, url_prefix='/scheduled_tasks')

@scheduled_tasks_bp.route('/')
def index():
    tasks = ScheduledTask.query.order_by(ScheduledTask.id).all()
    return render_template('scheduled_tasks/index.html', tasks=tasks) 