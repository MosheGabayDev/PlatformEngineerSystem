from flask import Blueprint, request, jsonify, abort
from apps import db
from apps.models import Server, ClientConfig, Command, Task, TaskCommand, CommandHistory, TaskHistory, ApiToken, ScheduledTask
from apps.authentication.models import Users
import uuid
import datetime as dt
import json
from functools import wraps
from apps.utils import log_action

api_bp = Blueprint('api', __name__, url_prefix='/api')

def require_api_token(required_permissions=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            auth_header = request.headers.get('Authorization', '')
            if not auth_header.startswith('Bearer '):
                abort(401, description='Missing or invalid Authorization header')
            token_value = auth_header.split(' ', 1)[1]
            token = ApiToken.query.filter_by(token=token_value, is_active=True).first()
            if not token:
                abort(401, description='Invalid or inactive API token')
            if token.expires_at and token.expires_at < dt.datetime.now(dt.timezone.utc):
                abort(401, description='API token expired')
            # Check permissions if required
            if required_permissions:
                perms_token = json.loads(token.permissions) if token.permissions else []
                user = Users.query.get(token.user_id)
                perms_user = json.loads(user.permissions) if user and user.permissions else []
                # Both token and user must have all required permissions
                if not all(p in perms_token for p in required_permissions) or not all(p in perms_user for p in required_permissions):
                    abort(403, description='Insufficient token or user permissions')
            request.api_token = token
            # Log the API action
            log_action(
                user=None,
                action_type=f"API {request.method} {request.path}",
                details=f"Endpoint: {request.endpoint}, Args: {dict(request.args)}, JSON: {request.get_json(silent=True)}",
                api_token_id=token.id
            )
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Server registration endpoint (client registration)
@api_bp.route('/servers/register', methods=['POST'])
def register_server():
    """
    Register a new server (called by the client on first run).
    ---
    tags:
      - Servers
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - name
          properties:
            name:
              type: string
            local_ip:
              type: string
            public_ip:
              type: string
            dns_servers:
              type: string
            dhcp_server:
              type: string
            disk_size_gb:
              type: number
            disk_free_gb:
              type: number
            cpu_type:
              type: string
            ram_gb:
              type: number
            internet_access:
              type: boolean
            listening_ports:
              type: string
            last_login_time:
              type: string
            last_login_user:
              type: string
            running_services:
              type: string
    responses:
      201:
        description: Server registered
        schema:
          type: object
          properties:
            server_id:
              type: string
            token:
              type: string
    """
    data = request.get_json()
    if not data or 'name' not in data:
        return jsonify({'error': 'Missing required fields'}), 400

    # Generate server UUID and token
    server_id = uuid.uuid4()
    token = uuid.uuid4().hex

    server = Server(
        id=server_id,
        name=data['name'],
        local_ip=data.get('local_ip'),
        public_ip=data.get('public_ip'),
        dns_servers=data.get('dns_servers'),
        dhcp_server=data.get('dhcp_server'),
        disk_size_gb=data.get('disk_size_gb'),
        disk_free_gb=data.get('disk_free_gb'),
        cpu_type=data.get('cpu_type'),
        ram_gb=data.get('ram_gb'),
        internet_access=data.get('internet_access'),
        listening_ports=data.get('listening_ports'),
        last_login_time=data.get('last_login_time'),
        last_login_user=data.get('last_login_user'),
        running_services=data.get('running_services'),
        token=token,
        is_approved=False,
        last_seen=dt.datetime.now(dt.timezone.utc),
    )
    db.session.add(server)
    db.session.commit()

    # Create default client config
    client_config = ClientConfig(
        server_id=server_id
    )
    db.session.add(client_config)
    db.session.commit()

    return jsonify({'server_id': str(server_id), 'token': token}), 201

# Get all servers
@api_bp.route('/servers', methods=['GET'])
@require_api_token(['servers:read'])
def get_servers():
    """
    Get all servers.
    ---
    tags:
      - Servers
    responses:
      200:
        description: List of servers
    """
    servers = Server.query.all()
    return jsonify([
        {
            'id': str(s.id),
            'name': s.name,
            'last_seen': s.last_seen.isoformat() if s.last_seen else None,
            'local_ip': s.local_ip,
            'public_ip': s.public_ip,
            'is_approved': s.is_approved,
            'created_at': s.created_at.isoformat() if s.created_at else None,
        } for s in servers
    ])

# Get a single server by ID
@api_bp.route('/servers/<uuid:server_id>', methods=['GET'])
@require_api_token(['servers:read'])
def get_server(server_id):
    """
    Get a server by ID.
    ---
    tags:
      - Servers
    parameters:
      - in: path
        name: server_id
        required: true
        type: string
    responses:
      200:
        description: Server details
      404:
        description: Server not found
    """
    server = Server.query.get(server_id)
    if not server:
        return jsonify({'error': 'Server not found'}), 404
    return jsonify({
        'id': str(server.id),
        'name': server.name,
        'last_seen': server.last_seen.isoformat() if server.last_seen else None,
        'local_ip': server.local_ip,
        'public_ip': server.public_ip,
        'dns_servers': server.dns_servers,
        'dhcp_server': server.dhcp_server,
        'disk_size_gb': server.disk_size_gb,
        'disk_free_gb': server.disk_free_gb,
        'cpu_type': server.cpu_type,
        'ram_gb': server.ram_gb,
        'internet_access': server.internet_access,
        'listening_ports': server.listening_ports,
        'last_login_time': server.last_login_time.isoformat() if server.last_login_time else None,
        'last_login_user': server.last_login_user,
        'running_services': server.running_services,
        'is_approved': server.is_approved,
        'created_at': server.created_at.isoformat() if server.created_at else None,
        'updated_at': server.updated_at.isoformat() if server.updated_at else None,
    })

# Update server details (heartbeat/update)
@api_bp.route('/servers/<uuid:server_id>', methods=['PUT'])
@require_api_token(['servers:write'])
def update_server(server_id):
    """
    Update server details (heartbeat/update).
    ---
    tags:
      - Servers
    parameters:
      - in: path
        name: server_id
        required: true
        type: string
      - in: body
        name: body
        required: true
        schema:
          type: object
    responses:
      200:
        description: Server updated
      404:
        description: Server not found
    """
    server = Server.query.get(server_id)
    if not server:
        return jsonify({'error': 'Server not found'}), 404
    data = request.get_json()
    for field in [
        'local_ip', 'public_ip', 'dns_servers', 'dhcp_server', 'disk_size_gb', 'disk_free_gb',
        'cpu_type', 'ram_gb', 'internet_access', 'listening_ports', 'last_login_time',
        'last_login_user', 'running_services', 'update_interval_seconds', 'client_poll_interval_seconds']:
        if field in data:
            setattr(server, field, data[field])
    server.last_seen = dt.datetime.now(dt.timezone.utc)
    db.session.commit()
    return jsonify({'message': 'Server updated'})

# Approve a server
@api_bp.route('/servers/<uuid:server_id>/approve', methods=['POST'])
@require_api_token(['servers:write'])
def approve_server(server_id):
    """
    Approve a server.
    ---
    tags:
      - Servers
    parameters:
      - in: path
        name: server_id
        required: true
        type: string
    responses:
      200:
        description: Server approved
      404:
        description: Server not found
    """
    server = Server.query.get(server_id)
    if not server:
        return jsonify({'error': 'Server not found'}), 404
    server.is_approved = True
    db.session.commit()
    return jsonify({'message': 'Server approved'})

# Delete a server
@api_bp.route('/servers/<uuid:server_id>', methods=['DELETE'])
@require_api_token(['servers:write'])
def delete_server(server_id):
    """
    Delete a server.
    ---
    tags:
      - Servers
    parameters:
      - in: path
        name: server_id
        required: true
        type: string
    responses:
      200:
        description: Server deleted
      404:
        description: Server not found
    """
    server = Server.query.get(server_id)
    if not server:
        return jsonify({'error': 'Server not found'}), 404
    db.session.delete(server)
    db.session.commit()
    return jsonify({'message': 'Server deleted'})

# Get all commands
@api_bp.route('/commands', methods=['GET'])
@require_api_token(['commands:read'])
def get_commands():
    """
    Get all commands.
    ---
    tags:
      - Commands
    responses:
      200:
        description: List of commands
    """
    commands = Command.query.all()
    return jsonify([
        {
            'id': str(c.id),
            'name': c.name,
            'description': c.description,
            'os_type': c.os_type,
            'os_version': c.os_version,
            'created_at': c.created_at.isoformat() if c.created_at else None,
            'created_by': c.created_by,
            'timeout_seconds': c.timeout_seconds,
            'reason': c.reason,
            'updated_at': c.updated_at.isoformat() if c.updated_at else None,
            'updated_by': c.updated_by,
            'update_reason': c.update_reason,
        } for c in commands
    ])

# Get a single command by ID
@api_bp.route('/commands/<uuid:command_id>', methods=['GET'])
@require_api_token(['commands:read'])
def get_command(command_id):
    """
    Get a command by ID.
    ---
    tags:
      - Commands
    parameters:
      - in: path
        name: command_id
        required: true
        type: string
    responses:
      200:
        description: Command details
      404:
        description: Command not found
    """
    command = Command.query.get(command_id)
    if not command:
        return jsonify({'error': 'Command not found'}), 404
    return jsonify({
        'id': str(command.id),
        'name': command.name,
        'description': command.description,
        'os_type': command.os_type,
        'os_version': command.os_version,
        'created_at': command.created_at.isoformat() if command.created_at else None,
        'created_by': command.created_by,
        'timeout_seconds': command.timeout_seconds,
        'reason': command.reason,
        'updated_at': command.updated_at.isoformat() if command.updated_at else None,
        'updated_by': command.updated_by,
        'update_reason': command.update_reason,
    })

# Create a new command
@api_bp.route('/commands', methods=['POST'])
@require_api_token(['commands:write'])
def create_command():
    """
    Create a new command.
    ---
    tags:
      - Commands
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
    responses:
      201:
        description: Command created
    """
    data = request.get_json()
    required_fields = ['name', 'os_type', 'created_by']
    if not data or not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400
    command = Command(
        id=uuid.uuid4(),
        name=data['name'],
        description=data.get('description'),
        os_type=data['os_type'],
        os_version=data.get('os_version'),
        created_by=data['created_by'],
        timeout_seconds=data.get('timeout_seconds'),
        reason=data.get('reason'),
    )
    db.session.add(command)
    db.session.commit()
    return jsonify({'id': str(command.id)}), 201

# Update an existing command
@api_bp.route('/commands/<uuid:command_id>', methods=['PUT'])
@require_api_token(['commands:write'])
def update_command(command_id):
    """
    Update an existing command.
    ---
    tags:
      - Commands
    parameters:
      - in: path
        name: command_id
        required: true
        type: string
      - in: body
        name: body
        required: true
        schema:
          type: object
    responses:
      200:
        description: Command updated
      404:
        description: Command not found
    """
    command = Command.query.get(command_id)
    if not command:
        return jsonify({'error': 'Command not found'}), 404
    data = request.get_json()
    for field in ['name', 'description', 'os_type', 'os_version', 'timeout_seconds', 'reason', 'updated_by', 'update_reason']:
        if field in data:
            setattr(command, field, data[field])
    db.session.commit()
    return jsonify({'message': 'Command updated'})

# Delete a command
@api_bp.route('/commands/<uuid:command_id>', methods=['DELETE'])
@require_api_token(['commands:write'])
def delete_command(command_id):
    """
    Delete a command.
    ---
    tags:
      - Commands
    parameters:
      - in: path
        name: command_id
        required: true
        type: string
    responses:
      200:
        description: Command deleted
      404:
        description: Command not found
    """
    command = Command.query.get(command_id)
    if not command:
        return jsonify({'error': 'Command not found'}), 404
    db.session.delete(command)
    db.session.commit()
    return jsonify({'message': 'Command deleted'})

# Get all tasks
@api_bp.route('/tasks', methods=['GET'])
@require_api_token(['tasks:read'])
def get_tasks():
    """
    Get all tasks.
    ---
    tags:
      - Tasks
    responses:
      200:
        description: List of tasks
    """
    tasks = Task.query.all()
    return jsonify([
        {
            'id': str(t.id),
            'name': t.name,
            'reason': t.reason,
            'tasks_json': t.tasks_json,
            'created_by': t.created_by,
            'created_at': t.created_at.isoformat() if t.created_at else None,
            'updated_at': t.updated_at.isoformat() if t.updated_at else None,
            'updated_by': t.updated_by,
        } for t in tasks
    ])

# Get a single task by ID
@api_bp.route('/tasks/<uuid:task_id>', methods=['GET'])
@require_api_token(['tasks:read'])
def get_task(task_id):
    """
    Get a task by ID.
    ---
    tags:
      - Tasks
    parameters:
      - in: path
        name: task_id
        required: true
        type: string
    responses:
      200:
        description: Task details
      404:
        description: Task not found
    """
    task = Task.query.get(task_id)
    if not task:
        return jsonify({'error': 'Task not found'}), 404
    return jsonify({
        'id': str(task.id),
        'name': task.name,
        'reason': task.reason,
        'tasks_json': task.tasks_json,
        'created_by': task.created_by,
        'created_at': task.created_at.isoformat() if task.created_at else None,
        'updated_at': task.updated_at.isoformat() if task.updated_at else None,
        'updated_by': task.updated_by,
    })

# Create a new task
@api_bp.route('/tasks', methods=['POST'])
@require_api_token(['tasks:write'])
def create_task():
    """
    Create a new task.
    ---
    tags:
      - Tasks
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
    responses:
      201:
        description: Task created
    """
    data = request.get_json()
    required_fields = ['name', 'created_by']
    if not data or not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400
    task = Task(
        id=uuid.uuid4(),
        name=data['name'],
        reason=data.get('reason'),
        tasks_json=data.get('tasks_json'),
        created_by=data['created_by'],
    )
    db.session.add(task)
    db.session.commit()
    return jsonify({'id': str(task.id)}), 201

# Update an existing task
@api_bp.route('/tasks/<uuid:task_id>', methods=['PUT'])
@require_api_token(['tasks:write'])
def update_task(task_id):
    """
    Update an existing task.
    ---
    tags:
      - Tasks
    parameters:
      - in: path
        name: task_id
        required: true
        type: string
      - in: body
        name: body
        required: true
        schema:
          type: object
    responses:
      200:
        description: Task updated
      404:
        description: Task not found
    """
    task = Task.query.get(task_id)
    if not task:
        return jsonify({'error': 'Task not found'}), 404
    data = request.get_json()
    for field in ['name', 'reason', 'tasks_json', 'updated_by']:
        if field in data:
            setattr(task, field, data[field])
    db.session.commit()
    return jsonify({'message': 'Task updated'})

# Delete a task
@api_bp.route('/tasks/<uuid:task_id>', methods=['DELETE'])
@require_api_token(['tasks:write'])
def delete_task(task_id):
    """
    Delete a task.
    ---
    tags:
      - Tasks
    parameters:
      - in: path
        name: task_id
        required: true
        type: string
    responses:
      200:
        description: Task deleted
      404:
        description: Task not found
    """
    task = Task.query.get(task_id)
    if not task:
        return jsonify({'error': 'Task not found'}), 404
    db.session.delete(task)
    db.session.commit()
    return jsonify({'message': 'Task deleted'})

# Get all TaskCommands for a specific task
@api_bp.route('/tasks/<string:task_id>/commands', methods=['GET'])
@require_api_token(['tasks:read'])
def get_task_commands(task_id):
    """
    Get all TaskCommands for a specific task.
    ---
    tags:
      - TaskCommands
    parameters:
      - in: path
        name: task_id
        required: true
        type: string
    responses:
      200:
        description: List of TaskCommands
    """
    task_commands = TaskCommand.query.filter_by(task_id=task_id).order_by(TaskCommand.order).all()
    return jsonify([
        {
            'id': str(tc.id),
            'task_id': str(tc.task_id),
            'command_id': str(tc.command_id),
            'order': tc.order,
            'expected_output': tc.expected_output,
            'run_as_admin': tc.run_as_admin,
            'run_in_sandbox': tc.run_in_sandbox,
            'max_output_lines': tc.max_output_lines,
        } for tc in task_commands
    ])

# Add a TaskCommand to a task
@api_bp.route('/tasks/<string:task_id>/commands', methods=['POST'])
@require_api_token(['tasks:write'])
def add_task_command(task_id):
    """
    Add a TaskCommand to a task.
    ---
    tags:
      - TaskCommands
    parameters:
      - in: path
        name: task_id
        required: true
        type: string
      - in: body
        name: body
        required: true
        schema:
          type: object
    responses:
      201:
        description: TaskCommand created
    """
    data = request.get_json()
    required_fields = ['command_id', 'order']
    if not data or not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400
    task_command = TaskCommand(
        id=uuid.uuid4(),
        task_id=task_id,
        command_id=data['command_id'],
        order=data['order'],
        expected_output=data.get('expected_output'),
        run_as_admin=data.get('run_as_admin', True),
        run_in_sandbox=data.get('run_in_sandbox', False),
        max_output_lines=data.get('max_output_lines', 100),
    )
    db.session.add(task_command)
    db.session.commit()
    return jsonify({'id': str(task_command.id)}), 201

# Update a TaskCommand
@api_bp.route('/task_commands/<string:task_command_id>', methods=['PUT'])
@require_api_token(['tasks:write'])
def update_task_command(task_command_id):
    """
    Update a TaskCommand.
    ---
    tags:
      - TaskCommands
    parameters:
      - in: path
        name: task_command_id
        required: true
        type: string
      - in: body
        name: body
        required: true
        schema:
          type: object
    responses:
      200:
        description: TaskCommand updated
      404:
        description: TaskCommand not found
    """
    task_command = TaskCommand.query.get(task_command_id)
    if not task_command:
        return jsonify({'error': 'TaskCommand not found'}), 404
    data = request.get_json()
    for field in ['order', 'expected_output', 'run_as_admin', 'run_in_sandbox', 'max_output_lines']:
        if field in data:
            setattr(task_command, field, data[field])
    db.session.commit()
    return jsonify({'message': 'TaskCommand updated'})

# Delete a TaskCommand
@api_bp.route('/task_commands/<string:task_command_id>', methods=['DELETE'])
@require_api_token(['tasks:write'])
def delete_task_command(task_command_id):
    """
    Delete a TaskCommand.
    ---
    tags:
      - TaskCommands
    parameters:
      - in: path
        name: task_command_id
        required: true
        type: string
    responses:
      200:
        description: TaskCommand deleted
      404:
        description: TaskCommand not found
    """
    task_command = TaskCommand.query.get(task_command_id)
    if not task_command:
        return jsonify({'error': 'TaskCommand not found'}), 404
    db.session.delete(task_command)
    db.session.commit()
    return jsonify({'message': 'TaskCommand deleted'})

# CommandHistory endpoints
@api_bp.route('/command_history', methods=['GET'])
@require_api_token(['history:read'])
def get_command_history():
    """
    Get all command history records.
    ---
    tags:
      - CommandHistory
    responses:
      200:
        description: List of command history records
    """
    history = CommandHistory.query.order_by(CommandHistory.executed_time.desc()).all()
    return jsonify([
        {
            'id': str(h.id),
            'server_id': str(h.server_id),
            'server_name': h.server_name,
            'command_id': str(h.command_id),
            'command_name': h.command_name,
            'task_id': str(h.task_id) if h.task_id else None,
            'task_command_id': str(h.task_command_id) if h.task_command_id else None,
            'scheduled_time': h.scheduled_time.isoformat() if h.scheduled_time else None,
            'executed_time': h.executed_time.isoformat() if h.executed_time else None,
            'duration_seconds': h.duration_seconds,
            'output': h.output,
            'run_type': h.run_type,
            'created_by': h.created_by,
            'reason': h.reason,
            'created_at': h.created_at.isoformat() if h.created_at else None,
        } for h in history
    ])

@api_bp.route('/servers/<string:server_id>/command_history', methods=['GET'])
@require_api_token(['history:read'])
def get_server_command_history(server_id):
    """
    Get command history for a specific server.
    ---
    tags:
      - CommandHistory
    parameters:
      - in: path
        name: server_id
        required: true
        type: string
    responses:
      200:
        description: List of command history records for the server
    """
    history = CommandHistory.query.filter_by(server_id=server_id).order_by(CommandHistory.executed_time.desc()).all()
    return jsonify([
        {
            'id': str(h.id),
            'server_id': str(h.server_id),
            'server_name': h.server_name,
            'command_id': str(h.command_id),
            'command_name': h.command_name,
            'task_id': str(h.task_id) if h.task_id else None,
            'task_command_id': str(h.task_command_id) if h.task_command_id else None,
            'scheduled_time': h.scheduled_time.isoformat() if h.scheduled_time else None,
            'executed_time': h.executed_time.isoformat() if h.executed_time else None,
            'duration_seconds': h.duration_seconds,
            'output': h.output,
            'run_type': h.run_type,
            'created_by': h.created_by,
            'reason': h.reason,
            'created_at': h.created_at.isoformat() if h.created_at else None,
        } for h in history
    ])

@api_bp.route('/commands/<string:command_id>/history', methods=['GET'])
@require_api_token(['history:read'])
def get_command_history_by_command(command_id):
    """
    Get command history for a specific command.
    ---
    tags:
      - CommandHistory
    parameters:
      - in: path
        name: command_id
        required: true
        type: string
    responses:
      200:
        description: List of command history records for the command
    """
    history = CommandHistory.query.filter_by(command_id=command_id).order_by(CommandHistory.executed_time.desc()).all()
    return jsonify([
        {
            'id': str(h.id),
            'server_id': str(h.server_id),
            'server_name': h.server_name,
            'command_id': str(h.command_id),
            'command_name': h.command_name,
            'task_id': str(h.task_id) if h.task_id else None,
            'task_command_id': str(h.task_command_id) if h.task_command_id else None,
            'scheduled_time': h.scheduled_time.isoformat() if h.scheduled_time else None,
            'executed_time': h.executed_time.isoformat() if h.executed_time else None,
            'duration_seconds': h.duration_seconds,
            'output': h.output,
            'run_type': h.run_type,
            'created_by': h.created_by,
            'reason': h.reason,
            'created_at': h.created_at.isoformat() if h.created_at else None,
        } for h in history
    ])

@api_bp.route('/command_history', methods=['POST'])
@require_api_token(['history:write'])
def add_command_history():
    """
    Add a command history record.
    ---
    tags:
      - CommandHistory
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
    responses:
      201:
        description: Command history record created
    """
    data = request.get_json()
    required_fields = ['server_id', 'command_id', 'run_type']
    if not data or not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400
    history = CommandHistory(
        id=uuid.uuid4(),
        server_id=data['server_id'],
        server_name=data.get('server_name'),
        command_id=data['command_id'],
        command_name=data.get('command_name'),
        task_id=data.get('task_id'),
        task_command_id=data.get('task_command_id'),
        scheduled_time=data.get('scheduled_time'),
        executed_time=data.get('executed_time'),
        duration_seconds=data.get('duration_seconds'),
        output=data.get('output'),
        run_type=data['run_type'],
        created_by=data.get('created_by'),
        reason=data.get('reason'),
    )
    db.session.add(history)
    db.session.commit()
    return jsonify({'id': str(history.id)}), 201

# TaskHistory endpoints
@api_bp.route('/task_history', methods=['GET'])
@require_api_token(['history:read'])
def get_task_history():
    """
    Get all task history records.
    ---
    tags:
      - TaskHistory
    responses:
      200:
        description: List of task history records
    """
    history = TaskHistory.query.order_by(TaskHistory.started_at.desc()).all()
    return jsonify([
        {
            'id': str(h.id),
            'task_id': str(h.task_id),
            'server_id': str(h.server_id),
            'server_name': h.server_name,
            'started_at': h.started_at.isoformat() if h.started_at else None,
            'finished_at': h.finished_at.isoformat() if h.finished_at else None,
            'duration_seconds': h.duration_seconds,
            'output': h.output,
            'status': h.status,
            'created_by': h.created_by,
            'reason': h.reason,
            'created_at': h.created_at.isoformat() if h.created_at else None,
        } for h in history
    ])

@api_bp.route('/servers/<string:server_id>/task_history', methods=['GET'])
@require_api_token(['history:read'])
def get_server_task_history(server_id):
    """
    Get task history for a specific server.
    ---
    tags:
      - TaskHistory
    parameters:
      - in: path
        name: server_id
        required: true
        type: string
    responses:
      200:
        description: List of task history records for the server
    """
    history = TaskHistory.query.filter_by(server_id=server_id).order_by(TaskHistory.started_at.desc()).all()
    return jsonify([
        {
            'id': str(h.id),
            'task_id': str(h.task_id),
            'server_id': str(h.server_id),
            'server_name': h.server_name,
            'started_at': h.started_at.isoformat() if h.started_at else None,
            'finished_at': h.finished_at.isoformat() if h.finished_at else None,
            'duration_seconds': h.duration_seconds,
            'output': h.output,
            'status': h.status,
            'created_by': h.created_by,
            'reason': h.reason,
            'created_at': h.created_at.isoformat() if h.created_at else None,
        } for h in history
    ])

@api_bp.route('/tasks/<string:task_id>/history', methods=['GET'])
@require_api_token(['history:read'])
def get_task_history_by_task(task_id):
    """
    Get task history for a specific task.
    ---
    tags:
      - TaskHistory
    parameters:
      - in: path
        name: task_id
        required: true
        type: string
    responses:
      200:
        description: List of task history records for the task
    """
    history = TaskHistory.query.filter_by(task_id=task_id).order_by(TaskHistory.started_at.desc()).all()
    return jsonify([
        {
            'id': str(h.id),
            'task_id': str(h.task_id),
            'server_id': str(h.server_id),
            'server_name': h.server_name,
            'started_at': h.started_at.isoformat() if h.started_at else None,
            'finished_at': h.finished_at.isoformat() if h.finished_at else None,
            'duration_seconds': h.duration_seconds,
            'output': h.output,
            'status': h.status,
            'created_by': h.created_by,
            'reason': h.reason,
            'created_at': h.created_at.isoformat() if h.created_at else None,
        } for h in history
    ])

@api_bp.route('/task_history', methods=['POST'])
@require_api_token(['history:write'])
def add_task_history():
    """
    Add a task history record.
    ---
    tags:
      - TaskHistory
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
    responses:
      201:
        description: Task history record created
    """
    data = request.get_json()
    required_fields = ['task_id', 'server_id']
    if not data or not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400
    history = TaskHistory(
        id=uuid.uuid4(),
        task_id=data['task_id'],
        server_id=data['server_id'],
        server_name=data.get('server_name'),
        started_at=data.get('started_at'),
        finished_at=data.get('finished_at'),
        duration_seconds=data.get('duration_seconds'),
        output=data.get('output'),
        status=data.get('status'),
        created_by=data.get('created_by'),
        reason=data.get('reason'),
    )
    db.session.add(history)
    db.session.commit()
    return jsonify({'id': str(history.id)}), 201

# Get client config for a specific server
@api_bp.route('/servers/<string:server_id>/client_config', methods=['GET'])
@require_api_token(['servers:read'])
def get_client_config(server_id):
    """
    Get client config for a specific server.
    ---
    tags:
      - ClientConfig
    parameters:
      - in: path
        name: server_id
        required: true
        type: string
    responses:
      200:
        description: Client config details
      404:
        description: ClientConfig not found
    """
    config = ClientConfig.query.filter_by(server_id=server_id).first()
    if not config:
        return jsonify({'error': 'ClientConfig not found'}), 404
    return jsonify({
        'id': str(config.id),
        'server_id': str(config.server_id),
        'update_interval_seconds': config.update_interval_seconds,
        'client_poll_interval_seconds': config.client_poll_interval_seconds,
        'max_output_lines': config.max_output_lines,
        'run_as_admin_default': config.run_as_admin_default,
        'run_in_sandbox_default': config.run_in_sandbox_default,
        'config_json': config.config_json,
        'created_at': config.created_at.isoformat() if config.created_at else None,
        'updated_at': config.updated_at.isoformat() if config.updated_at else None,
    })

# Update client config for a specific server
@api_bp.route('/servers/<string:server_id>/client_config', methods=['PUT'])
@require_api_token(['servers:write'])
def update_client_config(server_id):
    """
    Update client config for a specific server.
    ---
    tags:
      - ClientConfig
    parameters:
      - in: path
        name: server_id
        required: true
        type: string
      - in: body
        name: body
        required: true
        schema:
          type: object
    responses:
      200:
        description: ClientConfig updated
      404:
        description: ClientConfig not found
    """
    config = ClientConfig.query.filter_by(server_id=server_id).first()
    if not config:
        return jsonify({'error': 'ClientConfig not found'}), 404
    data = request.get_json()
    for field in [
        'update_interval_seconds', 'client_poll_interval_seconds', 'max_output_lines',
        'run_as_admin_default', 'run_in_sandbox_default', 'config_json']:
        if field in data:
            setattr(config, field, data[field])
    db.session.commit()
    return jsonify({'message': 'ClientConfig updated'})

# User management endpoints
@api_bp.route('/users', methods=['GET'])
@require_api_token(['users:read'])
def get_users():
    """
    Get all users.
    ---
    tags:
      - Users
    responses:
      200:
        description: List of users
    """
    users = Users.query.all()
    return jsonify([
        {
            'id': u.id,
            'username': u.username,
            'email': u.email,
            'bio': u.bio,
        } for u in users
    ])

@api_bp.route('/users/<int:user_id>', methods=['GET'])
@require_api_token(['users:read'])
def get_user(user_id):
    """
    Get a user by ID.
    ---
    tags:
      - Users
    parameters:
      - in: path
        name: user_id
        required: true
        type: integer
    responses:
      200:
        description: User details
      404:
        description: User not found
    """
    user = Users.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return jsonify({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'bio': user.bio,
    })

@api_bp.route('/users', methods=['POST'])
@require_api_token(['users:write'])
def create_user():
    """
    Create a new user.
    ---
    tags:
      - Users
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
    responses:
      201:
        description: User created
    """
    data = request.get_json()
    required_fields = ['username', 'email', 'password']
    if not data or not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400
    if Users.query.filter_by(username=data['username']).first() or Users.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Username or email already exists'}), 400
    user = Users(
        username=data['username'],
        email=data['email'],
        password=data['password'],
        bio=data.get('bio'),
    )
    user.save()
    return jsonify({'id': user.id}), 201

@api_bp.route('/users/<int:user_id>', methods=['PUT'])
@require_api_token(['users:write'])
def update_user(user_id):
    """
    Update a user.
    ---
    tags:
      - Users
    parameters:
      - in: path
        name: user_id
        required: true
        type: integer
      - in: body
        name: body
        required: true
        schema:
          type: object
    responses:
      200:
        description: User updated
      404:
        description: User not found
    """
    user = Users.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    data = request.get_json()
    for field in ['username', 'email', 'bio', 'password']:
        if field in data:
            setattr(user, field, data[field])
    user.save()
    return jsonify({'message': 'User updated'})

@api_bp.route('/users/<int:user_id>', methods=['DELETE'])
@require_api_token(['users:write'])
def delete_user(user_id):
    """
    Delete a user.
    ---
    tags:
      - Users
    parameters:
      - in: path
        name: user_id
        required: true
        type: integer
    responses:
      200:
        description: User deleted
      404:
        description: User not found
    """
    user = Users.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    user.delete_from_db()
    return jsonify({'message': 'User deleted'})

# Submit a CLI command to a server (from UI/user)
@api_bp.route('/servers/<uuid:server_id>/run_command', methods=['POST'])
@require_api_token(['cli:write'])
def run_cli_command(server_id):
    """
    Submit a CLI command to a server (from UI/user).
    ---
    tags:
      - CLI
    parameters:
      - in: path
        name: server_id
        required: true
        type: string
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - command_text
            - created_by
          properties:
            command_text:
              type: string
            created_by:
              type: integer
            reason:
              type: string
    responses:
      201:
        description: Command submitted
        schema:
          type: object
          properties:
            command_history_id:
              type: string
    """
    data = request.get_json()
    required_fields = ['command_text', 'created_by']
    if not data or not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400
    # Create a CommandHistory record with status 'pending' and run_type 'online_cli'
    history = CommandHistory(
        id=uuid.uuid4(),
        server_id=server_id,
        command_id=None,
        command_name=data['command_text'],
        run_type='online_cli',
        created_by=data['created_by'],
        reason=data.get('reason'),
        created_at=dt.datetime.now(dt.timezone.utc),
        # status: pending (not a column, but can be inferred by output=None and executed_time=None)
    )
    db.session.add(history)
    db.session.commit()
    return jsonify({'command_history_id': str(history.id)}), 201

# Agent fetches pending CLI commands to run
@api_bp.route('/servers/<string:server_id>/pending_commands', methods=['GET'])
@require_api_token(['cli:read'])
def get_pending_cli_commands(server_id):
    """
    Get pending CLI commands for a server (for agent polling).
    ---
    tags:
      - CLI
    parameters:
      - in: path
        name: server_id
        required: true
        type: string
    responses:
      200:
        description: List of pending CLI commands
    """
    # Pending = run_type online_cli, output is None, executed_time is None
    pending = CommandHistory.query.filter_by(server_id=server_id, run_type='online_cli', output=None, executed_time=None).all()
    return jsonify([
        {
            'id': str(cmd.id),
            'command_name': cmd.command_name,
            'created_by': cmd.created_by,
            'reason': cmd.reason,
            'created_at': cmd.created_at.isoformat() if cmd.created_at else None,
        } for cmd in pending
    ])

# Agent submits result for a CLI command
@api_bp.route('/command_history/<string:command_history_id>/result', methods=['POST'])
@require_api_token(['cli:write'])
def submit_cli_command_result(command_history_id):
    """
    Submit result for a CLI command (from agent).
    ---
    tags:
      - CLI
    parameters:
      - in: path
        name: command_history_id
        required: true
        type: string
      - in: body
        name: body
        required: true
        schema:
          type: object
    responses:
      200:
        description: Result submitted
      404:
        description: CommandHistory not found
    """
    history = CommandHistory.query.get(command_history_id)
    if not history:
        return jsonify({'error': 'CommandHistory not found'}), 404
    data = request.get_json()
    # Required: output, executed_time, duration_seconds
    for field in ['output', 'executed_time', 'duration_seconds']:
        if field not in data:
            return jsonify({'error': f'Missing required field: {field}'}), 400
    history.output = data['output']
    history.executed_time = data['executed_time']
    history.duration_seconds = data['duration_seconds']
    db.session.commit()
    return jsonify({'message': 'Result submitted'})

# Admin-only endpoint to create API tokens
@api_bp.route('/api_tokens', methods=['POST'])
@require_api_token(['admin'])
def create_api_token():
    """
    Create a new API token (admin only).
    ---
    tags:
      - ApiToken
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - user_id
            - permissions
          properties:
            user_id:
              type: integer
            permissions:
              type: array
              items:
                type: string
              example: ["admin", "servers:read", "commands:write"]
            expires_at:
              type: string
              example: "2024-12-31T23:59:59Z"
    responses:
      201:
        description: API token created
        schema:
          type: object
          properties:
            token:
              type: string
    """
    data = request.get_json()
    user_id = data.get('user_id')
    permissions = data.get('permissions')
    expires_at = data.get('expires_at')
    if not user_id or not permissions:
        return {'error': 'user_id and permissions are required'}, 400
    token_value = uuid.uuid4().hex
    token = ApiToken(
        token=token_value,
        user_id=user_id,
        permissions=json.dumps(permissions),
        expires_at=dt.datetime.fromisoformat(expires_at) if expires_at else None
    )
    db.session.add(token)
    db.session.commit()
    return {'token': token_value}, 201 