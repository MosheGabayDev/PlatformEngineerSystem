from celery.schedules import crontab
from apps.tasks.celery_app import celery_app
from apps.extensions import db
from apps.models.tasks import ScheduledTask, Task, TaskType
from datetime import datetime
import json

def init_scheduler():
    """
    Initialize the scheduler with all active scheduled tasks
    """
    # Clear existing schedules
    celery_app.conf.beat_schedule = {}
    
    # Get all active scheduled tasks
    scheduled_tasks = ScheduledTask.query.filter_by(is_active=True).all()
    
    for scheduled_task in scheduled_tasks:
        add_scheduled_task(scheduled_task)

def add_scheduled_task(scheduled_task):
    """
    Add a new scheduled task to Celery Beat
    """
    # Parse cron expression
    cron_parts = scheduled_task.schedule.split()
    if len(cron_parts) != 5:
        raise ValueError("Invalid cron expression")
    
    minute, hour, day_of_month, month, day_of_week = cron_parts
    
    # Create Celery Beat schedule
    schedule = crontab(
        minute=minute,
        hour=hour,
        day_of_month=day_of_month,
        month_of_year=month,
        day_of_week=day_of_week
    )
    
    # Add to Celery Beat schedule
    celery_app.conf.beat_schedule[f'scheduled_task_{scheduled_task.id}'] = {
        'task': 'apps.tasks.scheduler.run_scheduled_task',
        'schedule': schedule,
        'args': (scheduled_task.id,)
    }

def remove_scheduled_task(scheduled_task_id):
    """
    Remove a scheduled task from Celery Beat
    """
    schedule_key = f'scheduled_task_{scheduled_task_id}'
    if schedule_key in celery_app.conf.beat_schedule:
        del celery_app.conf.beat_schedule[schedule_key]

@celery_app.task
def run_scheduled_task(scheduled_task_id):
    """
    Execute a scheduled task
    """
    scheduled_task = ScheduledTask.query.get(scheduled_task_id)
    if not scheduled_task or not scheduled_task.is_active:
        return
    
    try:
        # Create and execute task
        task = Task(
            name=scheduled_task.name,
            type=TaskType(scheduled_task.task_type),
            parameters=scheduled_task.parameters,
            created_by=scheduled_task.created_by
        )
        
        db.session.add(task)
        db.session.commit()
        
        # Update scheduled task
        scheduled_task.last_run = datetime.utcnow()
        db.session.commit()
        
        # Execute task
        from apps.tasks.task_manager import TaskManager
        TaskManager.execute_task(task)
        
    except Exception as e:
        print(f"Error executing scheduled task {scheduled_task_id}: {str(e)}")
        scheduled_task.last_run = datetime.utcnow()
        db.session.commit() 