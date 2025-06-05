from flask import Blueprint

scheduled_tasks_bp = Blueprint('scheduled_tasks', __name__)

@scheduled_tasks_bp.route('/scheduled-tasks')
def index():
    return 'Scheduled Tasks' 