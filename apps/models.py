# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from email.policy import default
from apps.db import db
from sqlalchemy.exc import SQLAlchemyError
from apps.exceptions.exception import InvalidUsage
import datetime as dt
from sqlalchemy.orm import relationship
from enum import Enum
import uuid
from sqlalchemy.dialects.postgresql import UUID

class Product(db.Model):

    __tablename__ = 'products'

    id            = db.Column(db.Integer, primary_key=True)
    name          = db.Column(db.String(128), nullable=False)
    info          = db.Column(db.Text, nullable=True)
    price         = db.Column(db.Integer, nullable=False)
    
    def __init__(self, **kwargs):
        super(Product, self).__init__(**kwargs)

    def __repr__(self):
        return f"{self.name} / ${self.price}"

    @classmethod
    def find_by_id(cls, _id: int) -> "Product":
        return cls.query.filter_by(id=_id).first() 

    @classmethod
    def get_list(cls):
        return cls.query.all()

    def save(self) -> None:
        try:
            db.session.add(self)
            db.session.commit()
        except SQLAlchemyError as e:
            db.session.rollback()
            db.session.close()
            error = str(e.__dict__['orig'])
            raise InvalidUsage(error, 422)

    def delete(self) -> None:
        try:
            db.session.delete(self)
            db.session.commit()
        except SQLAlchemyError as e:
            db.session.rollback()
            db.session.close()
            error = str(e.__dict__['orig'])
            raise InvalidUsage(error, 422)
        return

class AWS_SERVERS(db.Model):
    __tablename__ = 'aws_servers'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    ip_address = db.Column(db.String(15), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='Active')
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow)
    
    # AWS specific fields
    instance_id = db.Column(db.String(50), unique=True, nullable=True)
    instance_type = db.Column(db.String(50), nullable=True)
    availability_zone = db.Column(db.String(50), nullable=True)
    state = db.Column(db.String(20), nullable=True)
    launch_time = db.Column(db.DateTime, nullable=True)
    
    def __init__(self, **kwargs):
        super(AWS_SERVERS, self).__init__(**kwargs)

    def __repr__(self):
        return f"{self.name} ({self.ip_address})"

    @classmethod
    def find_by_id(cls, _id: int) -> "AWS_SERVERS":
        return cls.query.filter_by(id=_id).first()
    
    @classmethod
    def find_by_instance_id(cls, instance_id: str) -> "AWS_SERVERS":
        return cls.query.filter_by(instance_id=instance_id).first()

    @classmethod
    def get_list(cls):
        return cls.query.all()

    def save(self) -> None:
        try:
            db.session.add(self)
            db.session.commit()
        except SQLAlchemyError as e:
            db.session.rollback()
            db.session.close()
            error = str(e.__dict__['orig'])
            raise InvalidUsage(error, 422)

    def delete(self) -> None:
        try:
            db.session.delete(self)
            db.session.commit()
        except SQLAlchemyError as e:
            db.session.rollback()
            db.session.close()
            error = str(e.__dict__['orig'])
            raise InvalidUsage(error, 422)

    @classmethod
    def sync_from_aws(cls):
        """Sync servers from AWS EC2"""
        try:
            import boto3
            from flask import current_app

            # Only use profile in non-PROD environments
            session_params = {
                'region_name': current_app.config['AWS_REGION']
            }
            
            if current_app.config['DEBUG']:  # Non-PROD environment
                session_params['profile_name'] = 'pango-nonprod'

            session = boto3.Session(**session_params)
            ec2 = session.client('ec2')
            instances = ec2.describe_instances()
            
            for reservation in instances['Reservations']:
                for instance in reservation['Instances']:
                    # Skip terminated instances
                    if instance['State']['Name'] == 'terminated':
                        continue
                        
                    # Check if instance already exists in DB
                    existing_server = cls.find_by_instance_id(instance['InstanceId'])
                    
                    # Get the Name tag if it exists
                    name = instance['InstanceId']
                    for tag in instance.get('Tags', []):
                        if tag['Key'] == 'Name':
                            name = tag['Value']
                            break
                    
                    # Get IP address (private if no public)
                    ip_address = instance.get('PublicIpAddress', instance.get('PrivateIpAddress', '0.0.0.0'))
                    
                    if existing_server:
                        # Update existing server
                        existing_server.name = name
                        existing_server.ip_address = ip_address
                        existing_server.instance_type = instance['InstanceType']
                        existing_server.availability_zone = instance['Placement']['AvailabilityZone']
                        existing_server.state = instance['State']['Name']
                        existing_server.launch_time = instance['LaunchTime']
                        existing_server.save()
                    else:
                        # Create new server
                        new_server = cls(
                            name=name,
                            ip_address=ip_address,
                            instance_id=instance['InstanceId'],
                            instance_type=instance['InstanceType'],
                            availability_zone=instance['Placement']['AvailabilityZone'],
                            state=instance['State']['Name'],
                            launch_time=instance['LaunchTime'],
                            status='Active'
                        )
                        new_server.save()
                        
            return True
        except Exception as e:
            print(f"Error syncing from AWS: {str(e)}")
            return False

class Server(db.Model):
    __tablename__ = 'servers'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()), unique=True, nullable=False)
    name = db.Column(db.String(128), nullable=False)
    last_seen = db.Column(db.DateTime, nullable=True)
    local_ip = db.Column(db.String(45), nullable=True)
    public_ip = db.Column(db.String(45), nullable=True)
    dns_servers = db.Column(db.Text, nullable=True)  # Comma-separated list or JSON
    dhcp_server = db.Column(db.String(128), nullable=True)
    disk_size_gb = db.Column(db.Float, nullable=True)
    disk_free_gb = db.Column(db.Float, nullable=True)
    cpu_type = db.Column(db.String(128), nullable=True)
    ram_gb = db.Column(db.Float, nullable=True)
    internet_access = db.Column(db.Boolean, nullable=True)
    listening_ports = db.Column(db.Text, nullable=True)  # Comma-separated list or JSON
    last_login_time = db.Column(db.DateTime, nullable=True)
    last_login_user = db.Column(db.String(128), nullable=True)
    running_services = db.Column(db.Text, nullable=True)  # Comma-separated list or JSON
    update_interval_seconds = db.Column(db.Integer, nullable=False, default=300)  # Default: 5 minutes
    client_poll_interval_seconds = db.Column(db.Integer, nullable=False, default=20)
    is_approved = db.Column(db.Boolean, nullable=False, default=False)
    token = db.Column(db.String(128), nullable=True)  # Client token for authentication
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow)

    def __repr__(self):
        return f"<Server {self.name} ({self.id})>"

class Command(db.Model):
    __tablename__ = 'commands'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()), unique=True, nullable=False)
    name = db.Column(db.String(128), nullable=False)
    description = db.Column(db.Text, nullable=True)
    os_type = db.Column(db.String(32), nullable=False)  # e.g., 'Windows', 'Linux'
    os_version = db.Column(db.String(64), nullable=True)
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    timeout_seconds = db.Column(db.Integer, nullable=True)
    reason = db.Column(db.Text, nullable=True)
    updated_at = db.Column(db.DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow)
    updated_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    update_reason = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return f"<Command {self.name} ({self.id})>"

class Task(db.Model):
    __tablename__ = 'tasks'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()), unique=True, nullable=False)
    name = db.Column(db.String(128), nullable=False)
    reason = db.Column(db.Text, nullable=True)
    tasks_json = db.Column(db.Text, nullable=True)  # Additional JSON configuration for the task
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow)
    updated_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    # Relationship to TaskCommand
    commands = relationship('TaskCommand', back_populates='task', cascade='all, delete-orphan', order_by='TaskCommand.order')

    def __repr__(self):
        return f"<Task {self.name} ({self.id})>"

class TaskCommand(db.Model):
    __tablename__ = 'task_commands'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()), unique=True, nullable=False)
    task_id = db.Column(db.String(36), db.ForeignKey('tasks.id'), nullable=False)
    command_id = db.Column(db.String(36), db.ForeignKey('commands.id'), nullable=False)
    order = db.Column(db.Integer, nullable=False)
    expected_output = db.Column(db.Text, nullable=True)  # Regex or string
    run_as_admin = db.Column(db.Boolean, default=True)
    run_in_sandbox = db.Column(db.Boolean, default=False)
    max_output_lines = db.Column(db.Integer, default=100)

    # Relationships
    task = relationship('Task', back_populates='commands')
    command = relationship('Command')

    def __repr__(self):
        return f"<TaskCommand Task:{self.task_id} Command:{self.command_id} Order:{self.order}>"

class CommandHistory(db.Model):
    __tablename__ = 'command_history'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()), unique=True, nullable=False)
    server_id = db.Column(db.String(36), db.ForeignKey('servers.id'), nullable=False)
    server_name = db.Column(db.String(128), nullable=True)
    command_id = db.Column(db.String(36), db.ForeignKey('commands.id'), nullable=True)
    command_name = db.Column(db.String(128), nullable=True)
    task_id = db.Column(db.String(36), db.ForeignKey('tasks.id'), nullable=True)  # If run as part of a task
    task_command_id = db.Column(db.String(36), db.ForeignKey('task_commands.id'), nullable=True)
    scheduled_time = db.Column(db.DateTime, nullable=True)
    executed_time = db.Column(db.DateTime, nullable=True)
    duration_seconds = db.Column(db.Float, nullable=True)
    output = db.Column(db.Text, nullable=True)
    run_type = db.Column(db.String(32), nullable=False)  # 'online_cli' or 'task'
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    reason = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow)

    def __repr__(self):
        return f"<CommandHistory Command:{self.command_id} Server:{self.server_id} Time:{self.executed_time}>"

class TaskHistory(db.Model):
    __tablename__ = 'task_history'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()), unique=True, nullable=False)
    task_id = db.Column(db.String(36), db.ForeignKey('tasks.id'), nullable=False)
    server_id = db.Column(db.String(36), db.ForeignKey('servers.id'), nullable=False)
    server_name = db.Column(db.String(128), nullable=True)
    started_at = db.Column(db.DateTime, nullable=True)
    finished_at = db.Column(db.DateTime, nullable=True)
    duration_seconds = db.Column(db.Float, nullable=True)
    output = db.Column(db.Text, nullable=True)  # Summary or aggregated output
    status = db.Column(db.String(32), nullable=True)  # e.g., 'success', 'failed', 'partial'
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    reason = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow)

    def __repr__(self):
        return f"<TaskHistory Task:{self.task_id} Server:{self.server_id} Started:{self.started_at}>"

class ClientConfig(db.Model):
    __tablename__ = 'client_configs'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()), unique=True, nullable=False)
    server_id = db.Column(db.String(36), db.ForeignKey('servers.id'), nullable=False, unique=True)
    update_interval_seconds = db.Column(db.Integer, nullable=False, default=300)  # Default: 5 minutes
    client_poll_interval_seconds = db.Column(db.Integer, nullable=False, default=20)
    max_output_lines = db.Column(db.Integer, default=100)
    run_as_admin_default = db.Column(db.Boolean, default=True)
    run_in_sandbox_default = db.Column(db.Boolean, default=False)
    config_json = db.Column(db.Text, nullable=True)  # Additional JSON config if needed
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow)

    def __repr__(self):
        return f"<ClientConfig Server:{self.server_id}>"

class ApiToken(db.Model):
    __tablename__ = 'api_tokens'

    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(64), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    permissions = db.Column(db.Text, nullable=True)  # JSON or comma-separated list
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=dt.datetime.now(dt.timezone.utc))
    expires_at = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f"<ApiToken {self.token} User:{self.user_id}>"

class AuditLog(db.Model):
    __tablename__ = 'audit_log'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    username = db.Column(db.String(64), nullable=True)
    api_token_id = db.Column(db.Integer, db.ForeignKey('api_tokens.id'), nullable=True)
    action_type = db.Column(db.String(64), nullable=False)
    action_details = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow, index=True)

class ScheduledTask(db.Model):
    __tablename__ = 'scheduled_tasks'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False, unique=True)
    description = db.Column(db.Text, nullable=True)
    job_id = db.Column(db.String(128), nullable=False, unique=True)
    cron = db.Column(db.String(64), nullable=False, default='0 3 * * *')
    is_enabled = db.Column(db.Boolean, default=True)
    last_run = db.Column(db.DateTime, nullable=True)
    next_run = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow)
