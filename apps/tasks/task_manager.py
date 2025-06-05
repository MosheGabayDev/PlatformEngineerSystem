from typing import Dict, Any, List
from apps.extensions import db
from apps.models.tasks import Task, TaskType, TaskStatus
from apps.tasks.executors.agent_executor import AgentExecutor
from apps.tasks.executors.ssh_executor import SSHExecutor
from apps.tasks.executors.cloud_executor import CloudExecutor
from apps.tasks.celery_app import celery_app
from celery.result import AsyncResult
from apps.utils.logger import task_logger, system_logger

class TaskManager:
    @staticmethod
    def get_executor(task: Task):
        """
        Get the appropriate executor for the task type
        """
        if task.type == TaskType.AGENT:
            return AgentExecutor(task)
        elif task.type == TaskType.SSH:
            return SSHExecutor(task)
        elif task.type == TaskType.CLOUD:
            return CloudExecutor(task)
        else:
            raise ValueError(f"Unsupported task type: {task.type}")
            
    @staticmethod
    def execute_task(task: Task) -> Dict[str, Any]:
        """
        Execute a task using the appropriate executor
        """
        try:
            # Log task start
            task_logger.log_task_event(
                task.id,
                'task_started',
                {'task_type': task.type.value, 'parameters': task.parameters}
            )
            
            # Update task status and add history entry
            task.status = TaskStatus.RUNNING
            task.add_history_entry(TaskStatus.RUNNING.value, "Task started")
            db.session.commit()

            # Get executor and execute
            executor = TaskManager.get_executor(task)
            result = executor.execute()

            # Update task with result
            task.status = TaskStatus.COMPLETED
            task.result = result
            task.add_history_entry(TaskStatus.COMPLETED.value, "Task completed successfully")
            db.session.commit()
            
            # Log task completion
            task_logger.log_task_event(
                task.id,
                'task_completed',
                {'result': result}
            )

            return result
        except Exception as e:
            # Log error
            task_logger.log_error(
                task.id,
                e,
                {'task_type': task.type.value, 'parameters': task.parameters}
            )
            
            # Update task with error
            task.status = TaskStatus.FAILED
            task.error = str(e)
            task.add_history_entry(TaskStatus.FAILED.value, f"Task failed: {str(e)}")
            db.session.commit()
            raise
            
    @staticmethod
    def execute_tasks_parallel(tasks: List[Task]) -> List[Dict[str, Any]]:
        """
        Execute multiple tasks in parallel
        """
        results = []
        for task in tasks:
            # Log task creation
            task_logger.log_task_event(
                task.id,
                'task_created',
                {'task_type': task.type.value, 'parameters': task.parameters}
            )
            
            # Create Celery task
            celery_task = execute_task_async.delay(task.id)
            results.append({
                'task_id': task.id,
                'celery_task_id': celery_task.id
            })
        return results

    @staticmethod
    def cancel_task(task: Task) -> bool:
        """
        Cancel a running task
        """
        if task.status != TaskStatus.RUNNING:
            raise ValueError("Task is not running")

        try:
            # Log cancellation attempt
            task_logger.log_task_event(
                task.id,
                'task_cancellation_started',
                {'task_type': task.type.value}
            )
            
            # Get the Celery task ID from the task's result
            if task.result and isinstance(task.result, dict) and 'celery_task_id' in task.result:
                celery_task_id = task.result['celery_task_id']
                celery_task = AsyncResult(celery_task_id, app=celery_app)
                celery_task.revoke(terminate=True)

            # Update task status
            task.status = TaskStatus.CANCELLED
            task.add_history_entry(TaskStatus.CANCELLED.value, "Task cancelled by user")
            db.session.commit()
            
            # Log successful cancellation
            task_logger.log_task_event(
                task.id,
                'task_cancelled',
                {'task_type': task.type.value}
            )
            
            return True
        except Exception as e:
            # Log cancellation error
            task_logger.log_error(
                task.id,
                e,
                {'task_type': task.type.value, 'error_type': 'cancellation_error'}
            )
            
            task.error = f"Error cancelling task: {str(e)}"
            task.add_history_entry(TaskStatus.FAILED.value, f"Error cancelling task: {str(e)}")
            db.session.commit()
            return False

@celery_app.task
def execute_task_async(task_id: int) -> Dict[str, Any]:
    """
    Celery task for executing a task asynchronously
    """
    # Lazy import to avoid circular import
    from apps import create_app
    from apps.models import Task, db
    from flask import current_app
    app = create_app()
    with app.app_context():
        task = Task.query.get(task_id)
        if not task:
            raise ValueError(f"Task {task_id} not found")
        result = TaskManager.execute_task(task)
        db.session.commit()
        return result 