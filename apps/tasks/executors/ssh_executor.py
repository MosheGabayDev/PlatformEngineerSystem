import paramiko
from typing import Dict, Any
from apps.models.tasks import Task, TaskStatus

class SSHExecutor:
    def __init__(self, task: Task):
        self.task = task
        
    def execute(self) -> Dict[str, Any]:
        """
        Execute a task via SSH
        """
        try:
            # Update task status to running
            self.task.status = TaskStatus.RUNNING
            
            # Get SSH parameters
            hostname = self.task.parameters.get('hostname')
            username = self.task.parameters.get('username')
            password = self.task.parameters.get('password')
            key_filename = self.task.parameters.get('key_filename')
            command = self.task.parameters.get('command')
            
            if not all([hostname, command]):
                raise ValueError("Missing required SSH parameters")
                
            # Create SSH client
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connect to server
            connect_kwargs = {
                'hostname': hostname,
                'username': username
            }
            
            if password:
                connect_kwargs['password'] = password
            if key_filename:
                connect_kwargs['key_filename'] = key_filename
                
            client.connect(**connect_kwargs)
            
            # Execute command
            stdin, stdout, stderr = client.exec_command(command)
            
            # Get results
            stdout_str = stdout.read().decode()
            stderr_str = stderr.read().decode()
            exit_status = stdout.channel.recv_exit_status()
            
            # Close connection
            client.close()
            
            # Update task with results
            if exit_status == 0:
                self.task.status = TaskStatus.COMPLETED
                self.task.result = {
                    'stdout': stdout_str,
                    'stderr': stderr_str,
                    'exit_status': exit_status
                }
            else:
                self.task.status = TaskStatus.FAILED
                self.task.error = stderr_str
                self.task.result = {
                    'stdout': stdout_str,
                    'stderr': stderr_str,
                    'exit_status': exit_status
                }
                
            return self.task.result
            
        except Exception as e:
            self.task.status = TaskStatus.FAILED
            self.task.error = str(e)
            raise 