from flask import Blueprint, request, jsonify, render_template
from apps.extensions import db
from apps.models.tasks import Task, TaskType, TaskStatus, ScheduledTask
from apps.models.alerts import Alert, AlertType, AlertSeverity
from apps.tasks.task_manager import TaskManager
from apps.tasks.monitoring import TaskMonitor
from apps.tasks.scheduler import add_scheduled_task, remove_scheduled_task
from flask_login import login_required, current_user
from apps.tasks import tasks_bp, tasks_ui_bp
from datetime import datetime
from apps.tasks.chain_manager import ChainManager
from apps.auth.decorators import require_permission

@tasks_bp.route('/tasks', methods=['POST'])
@login_required
@require_permission('task', 'create')
def create_task():
    """
    Create a new task
    """
    data = request.json
    
    # Validate required fields
    if not all(k in data for k in ['name', 'type', 'parameters']):
        return jsonify({'error': 'Missing required fields'}), 400
        
    try:
        # Create task
        task = Task(
            name=data['name'],
            type=TaskType(data['type']),
            parameters=data['parameters'],
            created_by=current_user.id
        )
        
        db.session.add(task)
        db.session.commit()
        
        # Execute task
        TaskManager.execute_task(task)
        db.session.commit()
        
        return jsonify(task.to_dict()), 201
        
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@tasks_bp.route('/tasks/batch', methods=['POST'])
@login_required
@require_permission('task', 'create')
def create_tasks_batch():
    """
    Create and execute multiple tasks in parallel
    """
    data = request.json
    
    if not isinstance(data, list):
        return jsonify({'error': 'Expected array of tasks'}), 400
        
    tasks = []
    for task_data in data:
        if not all(k in task_data for k in ['name', 'type', 'parameters']):
            return jsonify({'error': f'Missing required fields in task: {task_data}'}), 400
            
        task = Task(
            name=task_data['name'],
            type=TaskType(task_data['type']),
            parameters=task_data['parameters'],
            created_by=current_user.id
        )
        tasks.append(task)
        
    try:
        # Add all tasks
        for task in tasks:
            db.session.add(task)
        db.session.commit()
        
        # Execute tasks in parallel
        results = TaskManager.execute_tasks_parallel(tasks)
        
        return jsonify(results), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@tasks_bp.route('/tasks/<int:task_id>', methods=['GET'])
@login_required
@require_permission('task', 'read')
def get_task(task_id):
    """
    Get task details
    """
    task = Task.query.get_or_404(task_id)
    return jsonify(task.to_dict())

@tasks_bp.route('/tasks', methods=['GET'])
@login_required
@require_permission('task', 'read')
def list_tasks():
    """
    List all tasks
    """
    tasks = Task.query.all()
    return jsonify([task.to_dict() for task in tasks])

@tasks_bp.route('/tasks/<int:task_id>', methods=['DELETE'])
@login_required
@require_permission('task', 'delete')
def delete_task(task_id):
    """
    Delete a task
    """
    task = Task.query.get_or_404(task_id)
    
    try:
        db.session.delete(task)
        db.session.commit()
        return '', 204
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@tasks_bp.route('/tasks/stats', methods=['GET'])
@login_required
@require_permission('task', 'read')
def get_task_stats():
    """
    Get task statistics
    """
    return jsonify(TaskMonitor.get_task_stats())

@tasks_bp.route('/tasks/history', methods=['GET'])
@login_required
@require_permission('task', 'read')
def get_tasks_history():
    """
    Get task history for the last N days
    """
    days = request.args.get('days', default=7, type=int)
    return jsonify(TaskMonitor.get_task_history(days))

@tasks_bp.route('/tasks/celery/stats', methods=['GET'])
@login_required
@require_permission('task', 'read')
def get_celery_stats():
    """
    Get Celery worker statistics
    """
    return jsonify(TaskMonitor.get_celery_stats())

@tasks_ui_bp.route('/tasks/dashboard', methods=['GET'])
@login_required
def dashboard():
    return render_template('tasks/dashboard.html')

# Scheduled Tasks API
@tasks_bp.route('/scheduled-tasks', methods=['POST'])
@login_required
def create_scheduled_task():
    """
    Create a new scheduled task
    """
    data = request.json
    
    # Validate required fields
    if not all(k in data for k in ['name', 'task_type', 'parameters', 'schedule']):
        return jsonify({'error': 'Missing required fields'}), 400
        
    try:
        # Create scheduled task
        scheduled_task = ScheduledTask(
            name=data['name'],
            task_type=data['task_type'],
            parameters=data['parameters'],
            schedule=data['schedule'],
            is_active=data.get('is_active', True),
            created_by=current_user.id
        )
        
        db.session.add(scheduled_task)
        db.session.commit()
        
        # Add to scheduler if active
        if scheduled_task.is_active:
            add_scheduled_task(scheduled_task)
        
        return jsonify(scheduled_task.to_dict()), 201
        
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@tasks_bp.route('/scheduled-tasks/<int:task_id>', methods=['GET'])
@login_required
def get_scheduled_task(task_id):
    """
    Get scheduled task details
    """
    task = ScheduledTask.query.get_or_404(task_id)
    return jsonify(task.to_dict())

@tasks_bp.route('/scheduled-tasks', methods=['GET'])
@login_required
def list_scheduled_tasks():
    """
    List all scheduled tasks
    """
    tasks = ScheduledTask.query.all()
    return jsonify([task.to_dict() for task in tasks])

@tasks_bp.route('/scheduled-tasks/<int:task_id>', methods=['PUT'])
@login_required
def update_scheduled_task(task_id):
    """
    Update a scheduled task
    """
    task = ScheduledTask.query.get_or_404(task_id)
    data = request.json
    
    try:
        # Update fields
        if 'name' in data:
            task.name = data['name']
        if 'task_type' in data:
            task.task_type = data['task_type']
        if 'parameters' in data:
            task.parameters = data['parameters']
        if 'schedule' in data:
            task.schedule = data['schedule']
        if 'is_active' in data:
            task.is_active = data['is_active']
            
        db.session.commit()
        
        # Update scheduler
        if task.is_active:
            add_scheduled_task(task)
        else:
            remove_scheduled_task(task.id)
        
        return jsonify(task.to_dict())
        
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@tasks_bp.route('/scheduled-tasks/<int:task_id>', methods=['DELETE'])
@login_required
def delete_scheduled_task(task_id):
    """
    Delete a scheduled task
    """
    task = ScheduledTask.query.get_or_404(task_id)
    
    try:
        # Remove from scheduler
        remove_scheduled_task(task.id)
        
        # Delete from database
        db.session.delete(task)
        db.session.commit()
        
        return '', 204
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@tasks_ui_bp.route('/scheduled-tasks')
@login_required
def scheduled_tasks():
    """
    Scheduled tasks management UI
    """
    return render_template('tasks/scheduled_tasks.html')

# Alerts API
@tasks_bp.route('/alerts', methods=['GET'])
@login_required
def list_alerts():
    """
    List all alerts
    """
    alerts = Alert.query.order_by(Alert.created_at.desc()).all()
    return jsonify([alert.to_dict() for alert in alerts])

@tasks_bp.route('/alerts/active', methods=['GET'])
@login_required
def list_active_alerts():
    """
    List all active (unresolved) alerts
    """
    alerts = TaskMonitor.get_active_alerts()
    return jsonify([alert.to_dict() for alert in alerts])

@tasks_bp.route('/alerts/<int:alert_id>', methods=['GET'])
@login_required
def get_alert(alert_id):
    """
    Get alert details
    """
    alert = Alert.query.get_or_404(alert_id)
    return jsonify(alert.to_dict())

@tasks_bp.route('/alerts/<int:alert_id>/resolve', methods=['POST'])
@login_required
def resolve_alert(alert_id):
    """
    Resolve an alert
    """
    alert = Alert.query.get_or_404(alert_id)
    
    try:
        alert.is_resolved = True
        alert.resolved_at = datetime.utcnow()
        alert.resolved_by = current_user.id
        
        db.session.commit()
        return jsonify(alert.to_dict())
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@tasks_bp.route('/alerts/stats', methods=['GET'])
@login_required
def get_alert_stats():
    """
    Get alert statistics
    """
    return jsonify(TaskMonitor.get_alert_stats())

@tasks_bp.route('/alerts/check', methods=['POST'])
@login_required
def check_alerts():
    """
    Manually trigger alert check
    """
    TaskMonitor.check_task_health()
    return jsonify({'message': 'Alert check completed'})

@tasks_ui_bp.route('/alerts')
@login_required
def alerts():
    """
    Alerts management UI
    """
    return render_template('tasks/alerts.html')

# Task Chain API
@tasks_bp.route('/task-chains', methods=['POST'])
@login_required
def create_task_chain():
    """
    Create a new task chain
    """
    data = request.json
    
    # Validate required fields
    if not all(k in data for k in ['name', 'tasks']):
        return jsonify({'error': 'Missing required fields'}), 400
        
    try:
        chain = ChainManager.create_chain(
            name=data['name'],
            description=data.get('description'),
            tasks=data['tasks'],
            created_by=current_user.id
        )
        
        return jsonify(chain.to_dict()), 201
        
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@tasks_bp.route('/task-chains/<int:chain_id>', methods=['GET'])
@login_required
def get_task_chain(chain_id):
    """
    Get task chain details
    """
    chain = TaskChain.query.get_or_404(chain_id)
    return jsonify(chain.to_dict())

@tasks_bp.route('/task-chains', methods=['GET'])
@login_required
def list_task_chains():
    """
    List all task chains
    """
    chains = TaskChain.query.all()
    return jsonify([chain.to_dict() for chain in chains])

@tasks_bp.route('/task-chains/<int:chain_id>', methods=['PUT'])
@login_required
def update_task_chain(chain_id):
    """
    Update a task chain
    """
    chain = TaskChain.query.get_or_404(chain_id)
    data = request.json
    
    try:
        if 'name' in data:
            chain.name = data['name']
        if 'description' in data:
            chain.description = data['description']
        if 'is_active' in data:
            chain.is_active = data['is_active']
            
        db.session.commit()
        return jsonify(chain.to_dict())
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@tasks_bp.route('/task-chains/<int:chain_id>', methods=['DELETE'])
@login_required
def delete_task_chain(chain_id):
    """
    Delete a task chain
    """
    chain = TaskChain.query.get_or_404(chain_id)
    
    try:
        db.session.delete(chain)
        db.session.commit()
        return '', 204
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@tasks_bp.route('/task-chains/<int:chain_id>/execute', methods=['POST'])
@login_required
def execute_task_chain(chain_id):
    """
    Execute a task chain
    """
    try:
        task = ChainManager.execute_chain(chain_id)
        return jsonify(task.to_dict())
        
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@tasks_ui_bp.route('/task-chains')
@login_required
def task_chains():
    """
    Task chains management UI
    """
    return render_template('tasks/task_chains.html')

@tasks_bp.route('/tasks/<int:task_id>/cancel', methods=['POST'])
@login_required
def cancel_task(task_id):
    """
    Cancel a running task
    """
    task = Task.query.get_or_404(task_id)
    
    if task.status != TaskStatus.RUNNING:
        return jsonify({'error': 'Task is not running'}), 400
        
    try:
        TaskManager.cancel_task(task)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@tasks_bp.route('/tasks/<int:task_id>/history', methods=['GET'])
@login_required
def get_task_execution_history(task_id):
    """
    Get task execution history
    """
    task = Task.query.get_or_404(task_id)
    history = TaskHistory.query.filter_by(task_id=task_id).order_by(TaskHistory.created_at.desc()).all()
    
    return jsonify([{
        'timestamp': h.created_at.isoformat() if h.created_at else None,
        'status': h.status,
        'details': h.output
    } for h in history]) 