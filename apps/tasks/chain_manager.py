from typing import List, Dict, Any
from apps.models.tasks import Task, TaskChain, TaskChainTask, TaskStatus
from apps.extensions import db
from apps.tasks.task_manager import TaskManager
import json
from datetime import datetime, timedelta

class ChainManager:
    @staticmethod
    def create_chain(name: str, description: str, tasks: List[Dict[str, Any]], created_by: int) -> TaskChain:
        """
        Create a new task chain
        """
        chain = TaskChain(
            name=name,
            description=description,
            created_by=created_by
        )
        
        try:
            db.session.add(chain)
            db.session.flush()  # Get chain ID
            
            # Add tasks to chain
            for i, task_data in enumerate(tasks):
                chain_task = TaskChainTask(
                    chain_id=chain.id,
                    task_id=task_data['task_id'],
                    order=i + 1,
                    condition=task_data.get('condition'),
                    timeout_seconds=task_data.get('timeout_seconds'),
                    retry_count=task_data.get('retry_count', 0),
                    retry_delay_seconds=task_data.get('retry_delay_seconds', 60)
                )
                db.session.add(chain_task)
            
            db.session.commit()
            return chain
            
        except Exception as e:
            db.session.rollback()
            raise e
    
    @staticmethod
    def execute_chain(chain_id: int) -> Task:
        """
        Execute a task chain
        """
        chain = TaskChain.query.get_or_404(chain_id)
        if not chain.is_active:
            raise ValueError("Task chain is not active")
        
        # Get first task in chain
        first_task = chain.tasks[0].task if chain.tasks else None
        if not first_task:
            raise ValueError("Task chain is empty")
        
        # Execute first task
        return TaskManager.execute_task(first_task)
    
    @staticmethod
    def check_chain_conditions(task: Task) -> bool:
        """
        Check if conditions are met for next task in chain
        """
        if not task.chain_task_id:
            return True
            
        chain_task = TaskChainTask.query.get(task.chain_task_id)
        if not chain_task or not chain_task.condition:
            return True
            
        try:
            condition = json.loads(chain_task.condition)
            result = task.result or {}
            
            # Check each condition
            for key, value in condition.items():
                if key not in result or result[key] != value:
                    return False
                    
            return True
            
        except Exception:
            return False
    
    @staticmethod
    def handle_task_completion(task: Task):
        """
        Handle task completion and trigger next task if conditions are met
        """
        if not task.chain_id:
            return
            
        if task.status != TaskStatus.COMPLETED:
            return
            
        if not ChainManager.check_chain_conditions(task):
            return
            
        # Get next task in chain
        chain_task = TaskChainTask.query.get(task.chain_task_id)
        if not chain_task:
            return
            
        next_chain_task = TaskChainTask.query.filter(
            TaskChainTask.chain_id == task.chain_id,
            TaskChainTask.order > chain_task.order
        ).order_by(TaskChainTask.order).first()
        
        if next_chain_task:
            # Create and execute next task
            next_task = Task(
                name=next_chain_task.task.name,
                type=next_chain_task.task.type,
                parameters=next_chain_task.task.parameters,
                chain_id=task.chain_id,
                chain_task_id=next_chain_task.id,
                created_by=task.created_by
            )
            
            db.session.add(next_task)
            db.session.commit()
            
            TaskManager.execute_task(next_task)
    
    @staticmethod
    def retry_failed_task(task: Task):
        """
        Retry a failed task in chain
        """
        if not task.chain_task_id:
            return
            
        chain_task = TaskChainTask.query.get(task.chain_task_id)
        if not chain_task or chain_task.retry_count <= 0:
            return
            
        # Create new task instance
        new_task = Task(
            name=task.name,
            type=task.type,
            parameters=task.parameters,
            chain_id=task.chain_id,
            chain_task_id=task.chain_task_id,
            created_by=task.created_by
        )
        
        db.session.add(new_task)
        db.session.commit()
        
        # Schedule task execution after delay
        TaskManager.execute_task(new_task, delay_seconds=chain_task.retry_delay_seconds) 