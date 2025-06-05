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
from apps.authentication.models import Users
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
import json

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

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
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
    public_key = db.Column(db.Text, nullable=True)  # Client's public key for request signing
    private_key = db.Column(db.Text, nullable=True)  # Server's private key for signing responses
    encryption_key = db.Column(db.Text, nullable=True)  # Key for encrypting the private key
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow)

    # Add relationships with cascade delete
    client_config = relationship('ClientConfig', backref='server', uselist=False, cascade='all, delete-orphan')
    command_histories = relationship('CommandHistory', cascade='all, delete-orphan')
    task_histories = relationship('TaskHistory', cascade='all, delete-orphan')

    def __repr__(self):
        return f"<Server {self.name} ({self.id})>"

class Command(db.Model):
    __tablename__ = 'commands'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(128), nullable=False)
    description = db.Column(db.Text, nullable=True)
    os_type = db.Column(db.String(32), nullable=False)  # e.g., 'Windows', 'Linux'
    os_version = db.Column(db.String(64), nullable=True)
    command_text = db.Column(db.Text, nullable=False)  # הפקודה בפועל
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    timeout_seconds = db.Column(db.Integer, nullable=True)
    reason = db.Column(db.Text, nullable=True)
    updated_at = db.Column(db.DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow)
    updated_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    update_reason = db.Column(db.Text, nullable=True)

    # Relationships
    histories = relationship('CommandHistory', back_populates='command')

    def __repr__(self):
        return f"<Command {self.name} ({self.id})>"

class TaskType(Enum):
    AGENT = "agent"
    SSH = "ssh"
    CLOUD = "cloud"

class TaskStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class Task(db.Model):
    __tablename__ = 'tasks'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    type = db.Column(db.Enum(TaskType), nullable=False)
    parameters = db.Column(db.JSON, nullable=False, default=dict)
    status = db.Column(db.Enum(TaskStatus), nullable=False, default=TaskStatus.PENDING)
    result = db.Column(db.JSON, nullable=True)
    error = db.Column(db.Text, nullable=True)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow)
    
    # Chain-related fields
    chain_id = db.Column(db.Integer, db.ForeignKey('task_chains.id'), nullable=True)
    chain_task_id = db.Column(db.Integer, db.ForeignKey('task_chain_tasks.id'), nullable=True)
    next_task_id = db.Column(db.Integer, db.ForeignKey('tasks.id'), nullable=True)
    
    # Relationships
    chain = db.relationship('TaskChain', foreign_keys=[chain_id], backref='chain_tasks')
    chain_task = db.relationship('TaskChainTask', foreign_keys=[chain_task_id], backref='tasks')
    next_task = db.relationship('Task', foreign_keys=[next_task_id], remote_side=[id], backref='previous_tasks')
    creator = db.relationship('Users', backref='created_tasks')
    commands = db.relationship('TaskCommand', back_populates='task', cascade='all, delete-orphan')
    history = db.relationship('TaskHistory', backref='task', cascade='all, delete-orphan')

    def __repr__(self):
        return f"<Task {self.name} ({self.id})>"

    def to_dict(self):
        result = {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'type': self.type.value,
            'status': self.status.value,
            'parameters': self.parameters,
            'result': self.result,
            'error': self.error,
            'created_by': self.created_by,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'chain_id': self.chain_id,
            'chain_task_id': self.chain_task_id,
            'next_task_id': self.next_task_id
        }
        return result

    def add_history_entry(self, status, output=None):
        """
        Add a history entry for this task
        """
        history = TaskHistory(
            task_id=self.id,
            status=status,
            output=output,
            created_by=self.created_by
        )
        db.session.add(history)
        db.session.commit()
        return history

class TaskCommand(db.Model):
    __tablename__ = 'task_commands'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    task_id = db.Column(db.Integer, db.ForeignKey('tasks.id'), nullable=False)
    command_id = db.Column(db.Integer, db.ForeignKey('commands.id'), nullable=False)
    order = db.Column(db.Integer, nullable=False)
    output_regex = db.Column(db.Text, nullable=True)  # REGEX pattern to validate command output
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

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    server_id = db.Column(db.Integer, db.ForeignKey('servers.id'), nullable=False)
    server_name = db.Column(db.String(128), nullable=True)
    command_id = db.Column(db.Integer, db.ForeignKey('commands.id'), nullable=True)
    command_name = db.Column(db.String(128), nullable=True)
    task_id = db.Column(db.Integer, db.ForeignKey('tasks.id'), nullable=True)  # If run as part of a task
    task_command_id = db.Column(db.Integer, db.ForeignKey('task_commands.id'), nullable=True)
    scheduled_time = db.Column(db.DateTime, nullable=True)
    executed_time = db.Column(db.DateTime, nullable=True)
    duration_seconds = db.Column(db.Float, nullable=True)
    output = db.Column(db.Text, nullable=True)
    output_regex = db.Column(db.Text, nullable=True)  # REGEX pattern to validate command output
    run_type = db.Column(db.String(32), nullable=False)  # 'online_cli' or 'task'
    run_status = db.Column(db.String(32), nullable=False, default='pending')  # 'pending', 'executing', 'success', 'failed'
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    reason = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow)

    # Relationships
    server = relationship('Server', backref='command_history')
    command = relationship('Command', back_populates='histories')
    task = relationship('Task', backref='command_history')
    task_command = relationship('TaskCommand', backref='command_history')

    def __repr__(self):
        return f"<CommandHistory Command:{self.command_id} Server:{self.server_id} Time:{self.executed_time}>"

class TaskHistory(db.Model):
    __tablename__ = 'task_history'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    task_id = db.Column(db.Integer, db.ForeignKey('tasks.id'), nullable=False)
    server_id = db.Column(db.Integer, db.ForeignKey('servers.id'), nullable=False)
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

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    server_id = db.Column(db.Integer, db.ForeignKey('servers.id'), nullable=False, unique=True)
    update_interval_seconds = db.Column(db.Integer, nullable=False, default=300)  # Default: 5 minutes
    client_poll_interval_seconds = db.Column(db.Integer, nullable=False, default=20)
    max_output_lines = db.Column(db.Integer, default=100)
    run_as_admin_default = db.Column(db.Boolean, default=True)
    run_in_sandbox_default = db.Column(db.Boolean, default=False)
    config_json = db.Column(db.Text, nullable=True)  # Additional JSON config if needed
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow)
    temporary_short_interval = db.Column(db.Boolean, default=False)  # Flag for temporary short interval
    temporary_interval_end_time = db.Column(db.DateTime, nullable=True)  # When the temporary interval should end

    def __repr__(self):
        return f"<ClientConfig Server:{self.server_id}>"

class ApiToken(db.Model):
    __tablename__ = 'api_tokens'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
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
    name = db.Column(db.String(100), nullable=False)
    task_type = db.Column(db.String(20), nullable=False, default='agent')
    parameters = db.Column(db.JSON, nullable=False, default=dict)
    schedule = db.Column(db.String(100), nullable=False, default='0 0 * * *')
    is_active = db.Column(db.Boolean, default=True)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow)
    
    # Relationships
    creator = db.relationship('Users', backref='scheduled_tasks')

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'task_type': self.task_type,
            'parameters': self.parameters,
            'schedule': self.schedule,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'created_by': self.created_by
        }

class AgentUpdateStatus(db.Model):
    __tablename__ = 'agent_update_status'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    server_id = db.Column(db.Integer, db.ForeignKey('servers.id'), nullable=False)
    version = db.Column(db.String(32), nullable=False)
    status = db.Column(db.String(32), nullable=False)  # success, failed
    timestamp = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow)

    # Relationships
    server = relationship('Server', backref='update_statuses')

    def __repr__(self):
        return f"<AgentUpdateStatus Server:{self.server_id} Version:{self.version} Status:{self.status}>"

class Agent(db.Model):
    __tablename__ = 'agents'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    hostname = db.Column(db.String(128), nullable=False)
    os = db.Column(db.String(64), nullable=False)
    os_version = db.Column(db.String(128), nullable=True)
    current_version = db.Column(db.String(32), nullable=True)
    desired_version = db.Column(db.String(32), nullable=True)
    status = db.Column(db.String(32), nullable=True)  # online, offline, updating, error
    last_seen = db.Column(db.DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow)
    registered_at = db.Column(db.DateTime, default=dt.datetime.utcnow)

    def __repr__(self):
        return f"<Agent {self.hostname} ({self.os})>"

class AlertType(Enum):
    TASK_FAILED = "task_failed"
    TASK_TIMEOUT = "task_timeout"
    TASK_STUCK = "task_stuck"
    SCHEDULED_TASK_MISSED = "scheduled_task_missed"
    SYSTEM_ERROR = "system_error"

class AlertSeverity(Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

class Alert(db.Model):
    __tablename__ = 'alerts'
    
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.Enum(AlertType), nullable=False)
    severity = db.Column(db.Enum(AlertSeverity), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    task_id = db.Column(db.Integer, db.ForeignKey('tasks.id'), nullable=True)
    scheduled_task_id = db.Column(db.Integer, db.ForeignKey('scheduled_tasks.id'), nullable=True)
    is_resolved = db.Column(db.Boolean, default=False)
    resolved_at = db.Column(db.DateTime, nullable=True)
    resolved_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow)
    
    # Relationships
    task = relationship('Task', backref='alerts')
    scheduled_task = relationship('ScheduledTask', backref='alerts')
    resolver = relationship('Users', foreign_keys=[resolved_by])
    
    def to_dict(self):
        return {
            'id': self.id,
            'type': self.type.value,
            'severity': self.severity.value,
            'title': self.title,
            'message': self.message,
            'task_id': self.task_id,
            'scheduled_task_id': self.scheduled_task_id,
            'is_resolved': self.is_resolved,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'resolved_by': self.resolved_by,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }

class TaskChain(db.Model):
    __tablename__ = 'task_chains'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow)
    
    # Relationships
    tasks = db.relationship('TaskChainTask', backref='chain', lazy=True)
    creator = db.relationship('Users', backref='created_chains')

class TaskChainTask(db.Model):
    __tablename__ = 'task_chain_tasks'
    
    id = db.Column(db.Integer, primary_key=True)
    chain_id = db.Column(db.Integer, db.ForeignKey('task_chains.id'), nullable=False)
    task_id = db.Column(db.Integer, db.ForeignKey('tasks.id'), nullable=False)
    order = db.Column(db.Integer, nullable=False)
    condition = db.Column(db.String(500), nullable=True)  # Python expression to evaluate
    timeout_seconds = db.Column(db.Integer, default=3600)
    retry_delay_seconds = db.Column(db.Integer, default=300)
    max_retries = db.Column(db.Integer, default=3)
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow)
    
    # Relationships
    task = db.relationship('Task', foreign_keys=[task_id], backref='chain_tasks')

class Role(db.Model):
    __tablename__ = 'roles'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow)
    
    # Relationships
    permissions = db.relationship('Permission', secondary='role_permissions', backref='roles')
    users = db.relationship('User', secondary='user_roles', backref='roles')
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'permissions': [p.to_dict() for p in self.permissions],
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class Permission(db.Model):
    __tablename__ = 'permissions'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200))
    resource = db.Column(db.String(50), nullable=False)  # e.g., 'task', 'alert', 'user'
    action = db.Column(db.String(50), nullable=False)    # e.g., 'create', 'read', 'update', 'delete'
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'resource': self.resource,
            'action': self.action,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

# Association tables for many-to-many relationships
role_permissions = db.Table('role_permissions',
    db.Column('role_id', db.Integer, db.ForeignKey('roles.id'), primary_key=True),
    db.Column('permission_id', db.Integer, db.ForeignKey('permissions.id'), primary_key=True)
)

user_roles = db.Table('user_roles',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('roles.id'), primary_key=True)
)

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    def has_permission(self, resource, action):
        """
        Check if user has specific permission
        """
        for role in self.roles:
            for permission in role.permissions:
                if permission.resource == resource and permission.action == action:
                    return True
        return False
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'is_active': self.is_active,
            'roles': [role.to_dict() for role in self.roles],
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None
        }
