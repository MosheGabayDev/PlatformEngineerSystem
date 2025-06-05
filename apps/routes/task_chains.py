from flask import Blueprint, jsonify, request
from apps.extensions import db
from apps.models.task_chain import TaskChain, TaskChainTask, TaskChainExecution
from apps.models.task import Task
from apps.tasks.chain_tasks import execute_task_chain
from datetime import datetime
from sqlalchemy import func

bp = Blueprint('task_chains', __name__)

@bp.route('/task-chains/data')
def get_chains():
    """Get paginated task chains data for DataTables"""
    draw = request.args.get('draw', type=int)
    start = request.args.get('start', type=int)
    length = request.args.get('length', type=int)
    search = request.args.get('search[value]', '')

    query = TaskChain.query

    if search:
        query = query.filter(TaskChain.name.ilike(f'%{search}%'))

    total = query.count()
    
    chains = query.order_by(TaskChain.name).offset(start).limit(length).all()
    
    data = []
    for chain in chains:
        data.append({
            'id': chain.id,
            'name': chain.name,
            'tasks': ', '.join([task.name for task in chain.tasks]),
            'schedule': chain.schedule,
            'status': chain.status,
            'last_run': chain.last_run.strftime('%Y-%m-%d %H:%M:%S') if chain.last_run else '-',
            'next_run': chain.next_run.strftime('%Y-%m-%d %H:%M:%S') if chain.next_run else '-'
        })

    return jsonify({
        'draw': draw,
        'recordsTotal': total,
        'recordsFiltered': total,
        'data': data
    })

@bp.route('/task-chains/metrics')
def get_metrics():
    """Get task chains metrics"""
    total_chains = TaskChain.query.count()
    active_chains = TaskChain.query.filter_by(status='active').count()
    pending_chains = TaskChain.query.filter_by(status='pending').count()
    failed_chains = TaskChain.query.filter_by(status='failed').count()

    return jsonify({
        'total_chains': total_chains,
        'active_chains': active_chains,
        'pending_chains': pending_chains,
        'failed_chains': failed_chains
    })

@bp.route('/task-chains/add', methods=['POST'])
def add_chain():
    """Add a new task chain"""
    data = request.get_json()

    chain = TaskChain(
        name=data['name'],
        description=data.get('description'),
        schedule=data['schedule'],
        schedule_options=data.get('schedule_options', {}),
        timeout=data.get('timeout', 3600),
        max_retries=data.get('retries', 3)
    )

    # Add tasks in order
    for i, task_id in enumerate(data['tasks']):
        task = Task.query.get(task_id)
        if task:
            chain.tasks.append(task)
            chain_task = TaskChainTask(
                chain=chain,
                task=task,
                order=i
            )
            db.session.add(chain_task)

    db.session.add(chain)
    db.session.commit()

    return jsonify({'message': 'Task chain added successfully'})

@bp.route('/task-chains/<int:chain_id>')
def get_chain(chain_id):
    """Get task chain details"""
    chain = TaskChain.query.get_or_404(chain_id)
    
    # Get recent executions
    recent_executions = chain.executions.order_by(TaskChainExecution.start_time.desc()).limit(10).all()
    executions_data = []
    for exec in recent_executions:
        executions_data.append({
            'id': exec.id,
            'start_time': exec.start_time.strftime('%Y-%m-%d %H:%M:%S'),
            'end_time': exec.end_time.strftime('%Y-%m-%d %H:%M:%S') if exec.end_time else None,
            'duration': exec.duration,
            'status': exec.status
        })

    return jsonify({
        'name': chain.name,
        'description': chain.description,
        'schedule': chain.schedule,
        'status': chain.status,
        'last_run': chain.last_run.strftime('%Y-%m-%d %H:%M:%S') if chain.last_run else '-',
        'next_run': chain.next_run.strftime('%Y-%m-%d %H:%M:%S') if chain.next_run else '-',
        'timeout': chain.timeout,
        'retries': chain.max_retries,
        'recent_executions': executions_data
    })

@bp.route('/task-chains/<int:chain_id>/run', methods=['POST'])
def run_chain(chain_id):
    """Run a task chain"""
    chain = TaskChain.query.get_or_404(chain_id)
    
    # Create new execution
    execution = TaskChainExecution(chain=chain)
    db.session.add(execution)
    db.session.commit()

    # Start chain execution using Celery
    execute_task_chain.delay(chain_id)

    return jsonify({'message': 'Task chain started successfully'})

@bp.route('/task-chains/<int:chain_id>/delete', methods=['POST'])
def delete_chain(chain_id):
    """Delete a task chain"""
    chain = TaskChain.query.get_or_404(chain_id)
    db.session.delete(chain)
    db.session.commit()

    return jsonify({'message': 'Task chain deleted successfully'}) 