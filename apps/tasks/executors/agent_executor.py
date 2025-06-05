import subprocess
import json
from typing import Dict, Any
from apps.models.tasks import Task, TaskStatus

class AgentExecutor:
    def __init__(self, task: Task):
        self.task = task
        
    def execute(self) -> Dict[str, Any]:
        """
        Execute a task on a local agent
        """
        try:
            # Update task status to running
            self.task.status = TaskStatus.RUNNING
            
            # Get command from parameters
            command = self.task.parameters.get('command')
            if not command:
                raise ValueError("No command specified in task parameters")
                
            # Execute command
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = process.communicate()
            
            # Update task with results
            if process.returncode == 0:
                self.task.status = TaskStatus.COMPLETED
                self.task.result = {
                    'stdout': stdout,
                    'stderr': stderr,
                    'return_code': process.returncode
                }
            else:
                self.task.status = TaskStatus.FAILED
                self.task.error = stderr
                self.task.result = {
                    'stdout': stdout,
                    'stderr': stderr,
                    'return_code': process.returncode
                }
                
            return self.task.result
            
        except Exception as e:
            self.task.status = TaskStatus.FAILED
            self.task.error = str(e)
            raise 