import boto3
from typing import Dict, Any
from apps.models.tasks import Task, TaskStatus

class CloudExecutor:
    def __init__(self, task: Task):
        self.task = task
        
    def execute(self) -> Dict[str, Any]:
        """
        Execute a task on cloud provider (AWS)
        """
        try:
            # Update task status to running
            self.task.status = TaskStatus.RUNNING
            
            # Get cloud parameters
            action = self.task.parameters.get('action')
            instance_id = self.task.parameters.get('instance_id')
            region = self.task.parameters.get('region', 'us-east-1')
            
            if not all([action, instance_id]):
                raise ValueError("Missing required cloud parameters")
                
            # Create EC2 client
            session = boto3.Session(region_name=region)
            ec2 = session.client('ec2')
            
            # Execute action
            if action == 'start':
                response = ec2.start_instances(InstanceIds=[instance_id])
            elif action == 'stop':
                response = ec2.stop_instances(InstanceIds=[instance_id])
            elif action == 'reboot':
                response = ec2.reboot_instances(InstanceIds=[instance_id])
            elif action == 'terminate':
                response = ec2.terminate_instances(InstanceIds=[instance_id])
            else:
                raise ValueError(f"Unsupported action: {action}")
                
            # Update task with results
            self.task.status = TaskStatus.COMPLETED
            self.task.result = {
                'action': action,
                'instance_id': instance_id,
                'response': response
            }
            
            return self.task.result
            
        except Exception as e:
            self.task.status = TaskStatus.FAILED
            self.task.error = str(e)
            raise 