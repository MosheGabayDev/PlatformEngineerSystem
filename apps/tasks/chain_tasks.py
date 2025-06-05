from celery import shared_task
from apps.extensions import db, celery
from apps.models.task_chain import TaskChain, TaskChainExecution, TaskChainTask
from apps.models.task import Task
from datetime import datetime, timedelta
import time
import logging

logger = logging.getLogger(__name__)

@shared_task
def execute_task_chain(chain_id):
    """Execute a task chain"""
    chain = TaskChain.query.get(chain_id)
    if not chain:
        logger.error(f"Task chain {chain_id} not found")
        return

    execution = TaskChainExecution(
        chain=chain,
        status='running',
        start_time=datetime.utcnow()
    )
    db.session.add(execution)
    db.session.commit()

    try:
        # Get ordered tasks
        chain_tasks = TaskChainTask.query.filter_by(chain_id=chain_id).order_by(TaskChainTask.order).all()
        
        for chain_task in chain_tasks:
            task = Task.query.get(chain_task.task_id)
            if not task:
                logger.error(f"Task {chain_task.task_id} not found in chain {chain_id}")
                continue

            # Execute task
            task_result = execute_task.delay(task.id)
            task_result.get(timeout=chain.timeout)  # Wait for task completion

        # Update execution status
        execution.status = 'success'
        execution.end_time = datetime.utcnow()
        execution.duration = int((execution.end_time - execution.start_time).total_seconds())

        # Update chain status
        chain.last_run = execution.end_time
        chain.status = 'active'
        chain.next_run = calculate_next_run(chain)

    except Exception as e:
        logger.error(f"Error executing task chain {chain_id}: {str(e)}")
        execution.status = 'failed'
        execution.end_time = datetime.utcnow()
        execution.duration = int((execution.end_time - execution.start_time).total_seconds())
        execution.error_message = str(e)
        
        # Update chain status
        chain.status = 'failed'
        chain.last_run = execution.end_time

    finally:
        db.session.commit()

@shared_task
def execute_task(task_id):
    """Execute a single task"""
    task = Task.query.get(task_id)
    if not task:
        logger.error(f"Task {task_id} not found")
        return

    try:
        # Execute task logic here
        # This is a placeholder - implement actual task execution
        time.sleep(1)  # Simulate task execution
        return True
    except Exception as e:
        logger.error(f"Error executing task {task_id}: {str(e)}")
        raise

def calculate_next_run(chain):
    """Calculate next run time based on schedule"""
    if chain.schedule == 'manual':
        return None
    
    now = datetime.utcnow()
    
    if chain.schedule == 'interval':
        interval = chain.schedule_options.get('interval', 3600)  # Default 1 hour
        return now + timedelta(seconds=interval)
    
    elif chain.schedule == 'cron':
        # Implement cron schedule calculation
        # This is a placeholder - implement actual cron calculation
        return now + timedelta(hours=1)
    
    return None

@celery.on_after_configure.connect
def setup_periodic_tasks(sender, **kwargs):
    """Setup periodic tasks for task chains"""
    # Add periodic task to check and run scheduled chains
    sender.add_periodic_task(
        60.0,  # Run every minute
        check_scheduled_chains.s(),
        name='check-scheduled-chains'
    )

@shared_task
def check_scheduled_chains():
    """Check and run scheduled task chains"""
    now = datetime.utcnow()
    
    # Find chains that need to run
    chains = TaskChain.query.filter(
        TaskChain.status == 'active',
        TaskChain.next_run <= now
    ).all()
    
    for chain in chains:
        execute_task_chain.delay(chain.id) 