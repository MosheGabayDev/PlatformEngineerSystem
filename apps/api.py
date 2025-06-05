from flask import Blueprint, request, jsonify, abort, send_file, g, current_app, Response
from apps import db
from apps.models.infrastructure import Server, ClientConfig, Command, CommandHistory
from apps.models.tasks import Task, TaskCommand, TaskHistory, ScheduledTask
from apps.models.authentication import ApiToken
from apps.models.agents import AgentUpdateStatus, Agent
from apps.authentication.models import Users
import uuid
import datetime as dt
import json
from functools import wraps
from apps.utils import log_action
from datetime import datetime
import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.fernet import Fernet
import secrets
import logging
from logging.handlers import RotatingFileHandler
import base64
import traceback

def verify_signature(public_key_pem, data, signature):
    """Verify the signature of the data using the public key"""
    try:
        print("=== Starting signature verification ===")
        print(f"Data to verify: {data}")
        print(f"Signature: {signature[:20]}...")  # Log only first 20 chars for security
        
        # Load the public key
        print("Loading public key")
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode(),
        )
        print("Public key loaded successfully")
        
        # Convert data to string if it's a dict
        if isinstance(data, dict):
            print("Converting data dict to string")
            data = json.dumps(data)
            print(f"Converted data: {data}")
        
        # Verify the signature
        print("Verifying signature")
        try:
            public_key.verify(
                base64.b64decode(signature),
                data.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("Signature verification successful")
            return True
        except Exception as e:
            print(f"Signature verification failed: {str(e)}")
            return False
    except Exception as e:
        print(f"Error in signature verification: {str(e)}")
        print(f"Error type: {type(e).__name__}")
        print(f"Error details: {e.__dict__ if hasattr(e, '__dict__') else 'No additional details'}")
        return False

def sign_response(data):
    """Sign the response data using the server's private key"""
    try:
        print("=== Starting response signing ===")
        print(f"Data to sign: {data}")
        
        # Load private key
        try:
            server = g.server
            print(f"Server private key: {server.private_key[:50]}...")  # Log first 50 chars
            
            # First decrypt the private key using the encryption key
            try:
                print("Decrypting private key using encryption key")
                f = Fernet(server.encryption_key.encode())
                decrypted_private_key = f.decrypt(server.private_key.encode())
                print("Successfully decrypted private key")
            except Exception as e:
                print(f"Failed to decrypt private key: {str(e)}")
                return None
            
            # Now load the decrypted private key
            try:
                private_key = serialization.load_pem_private_key(
                    decrypted_private_key,
                    password=None
                )
                print("Private key loaded successfully")
            except Exception as e:
                print(f"Failed to load private key: {str(e)}")
                return None
        except Exception as e:
            print(f"Failed to load private key: {str(e)}")
            print(f"Error type: {type(e).__name__}")
            print(f"Error details: {e.__dict__ if hasattr(e, '__dict__') else 'No additional details'}")
            return None
            
        # Convert data to string if it's a dict
        if isinstance(data, dict):
            print("Converting data dict to string")
            data_str = json.dumps(data)
        else:
            data_str = str(data)
            
        # Sign the data
        try:
            print("Signing data")
            signature = private_key.sign(
                data_str.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            # Convert to base64
            signature_b64 = base64.b64encode(signature).decode()
            print(f"Generated signature: {signature_b64[:20]}...")  # Log only first 20 chars
            return signature_b64
        except Exception as e:
            print(f"Failed to sign data: {str(e)}")
            return None
            
    except Exception as e:
        print(f"Error in response signing: {str(e)}")
        print(f"Error type: {type(e).__name__}")
        print(f"Error details: {e.__dict__ if hasattr(e, '__dict__') else 'No additional details'}")
        return None

def client_token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        print("=== Starting client authentication ===")
        auth_header = request.headers.get('Authorization', '')
        print(f"Auth header: {auth_header}")
        
        if not auth_header.startswith('Bearer '):
            print("Invalid Authorization header format")
            return {'error': 'Missing or invalid Authorization header'}, 401
            
        token_value = auth_header.split(' ', 1)[1]
        print(f"Token value: {token_value}")
        
        server = Server.query.filter_by(token=token_value).first()
        if not server:
            print("No server found with this token")
            return {'error': 'Invalid client token'}, 401
            
        print(f"Found server: ID={server.id}, Name={server.name}")
        
        # Verify that server has valid keys
        if not server.private_key or not server.encryption_key:
            print("Server is missing required keys")
            return {'error': 'Server is missing required keys'}, 401
            
        # Try to decrypt the private key to verify it's valid
        try:
            print("Verifying private key")
            fernet = Fernet(server.encryption_key.encode())
            decrypted_private_key = fernet.decrypt(server.private_key.encode())
            # Try to load the key to verify it's valid PEM
            private_key = serialization.load_pem_private_key(
                decrypted_private_key,
                password=None
            )
            print("Private key verified successfully")
        except Exception as e:
            print(f"Failed to verify private key: {str(e)}")
            return {'error': 'Invalid private key'}, 401
        
        # Update last_seen timestamp whenever client contacts the system
        server.last_seen = dt.datetime.now(dt.timezone.utc)
        db.session.commit()
        print(f"Updated last_seen timestamp for server {server.id}")
        
        g.server = server
        print("=== Client authentication completed successfully ===")
        
        # Call the original function
        try:
            response = f(*args, **kwargs)
        except Exception as e:
            print(f"Error in wrapped function: {str(e)}")
            return {'error': f'Error in wrapped function: {str(e)}'}, 500
        
        # Sign the response if it's a JSON response
        print("=== Starting response signing check ===")
        print(f"Response type: {type(response)}")
        print(f"Response content: {response}")
        
        if isinstance(response, tuple) and len(response) == 2 and isinstance(response[0], dict):
            print("=== Starting response signing process ===")
            data, status_code = response
            print(f"Response status code: {status_code}")
            print(f"Response data: {data}")
            
            if status_code == 200:  # Only sign successful responses
                print("Response is successful (200), proceeding with signing")
                try:
                    # Get server's private key from database
                    private_key = server.private_key
                    print(f"Server private key: {private_key[:50]}...")  # Log first 50 chars
                    
                    # First decrypt the private key using the encryption key
                    try:
                        print("Decrypting private key using encryption key")
                        fernet = Fernet(server.encryption_key.encode())
                        decrypted_private_key = fernet.decrypt(server.private_key.encode())
                        print("Successfully decrypted private key")
                    except Exception as e:
                        print(f"Failed to decrypt private key: {str(e)}")
                        return {'error': f'Failed to decrypt private key: {str(e)}'}, 500
                    
                    # Now load the decrypted private key
                    try:
                        private_key = serialization.load_pem_private_key(
                            decrypted_private_key,
                            password=None
                        )
                        print("Private key loaded successfully")
                    except Exception as e:
                        print(f"Failed to load private key: {str(e)}")
                        return {'error': f'Failed to load private key: {str(e)}'}, 500
                    
                    # Convert data to string if it's a dict
                    if isinstance(data, dict):
                        print("Converting data dict to string")
                        data_str = json.dumps(data, sort_keys=True)  # Sort keys for consistent ordering
                    else:
                        data_str = str(data)
                        
                    print(f"Data to sign: {data_str}")
                        
                    # Sign the data
                    print("Signing data")
                    signature = private_key.sign(
                        data_str.encode(),
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                    # Convert to base64
                    signature_b64 = base64.b64encode(signature).decode()
                    print(f"Generated signature: {signature_b64[:20]}...")  # Log only first 20 chars
                    
                    # Convert to Response object if it's not already
                    if not isinstance(response, Response):
                        print(f"Converting response from type {type(response)} to Response object")
                        print(f"Original response: {response}")
                        response = jsonify(data), status_code
                        print(f"Converted response: {response}")
                    # Add signature to headers
                    response[0].headers['X-Signature'] = signature_b64
                    print("Added signature to response headers")
                    print("=== Response signing completed successfully ===")
                except Exception as e:
                    print(f"Failed to sign response: {str(e)}")
                    print(f"Error type: {type(e).__name__}")
                    print(f"Error details: {e.__dict__ if hasattr(e, '__dict__') else 'No additional details'}")
                    return {'error': f'Failed to sign response: {str(e)}'}, 500
            else:
                print(f"Response status code {status_code} - skipping signature")
        else:
            print("Response is not a JSON tuple - skipping signature")
            print(f"Response is tuple: {isinstance(response, tuple)}")
            print(f"Response length: {len(response) if isinstance(response, tuple) else 'N/A'}")
            print(f"First element is dict: {isinstance(response[0], dict) if isinstance(response, tuple) and len(response) > 0 else 'N/A'}")
        
        return response
    return decorated_function

# Initialize blueprints
print("API module loaded, blueprints ready for registration")

# Create blueprints
api_bp = Blueprint('api_bp', __name__, url_prefix='/api')
client_api = Blueprint('client_api', __name__, url_prefix='/api/client')

# In-memory stores for demo (replace with DB in production)
CLIENTS = {}
COMMANDS = {}
LATEST_VERSION = '0.1.0'

CLIENT_VERSIONS_DIR = os.path.join(os.path.dirname(__file__), '../static/client_versions')

def require_api_token(required_permissions=None):
    def decorator(f):
        print("=== Starting API token authentication ===")
        @wraps(f)
        def decorated_function(*args, **kwargs):
            print("Checking API token authentication")
            auth_header = request.headers.get('Authorization', '')
            print(f"Auth header: {auth_header}")
            
            if not auth_header.startswith('Bearer '):
                print("Invalid Authorization header format")
                abort(401, description='Missing or invalid Authorization header')
                
            token_value = auth_header.split(' ', 1)[1]
            print(f"Token value: {token_value[:8]}...")  # Log only first 8 chars for security
            
            token = ApiToken.query.filter_by(token=token_value, is_active=True).first()
            if not token:
                print("No active token found")
                abort(401, description='Invalid or inactive API token')
                
            if token.expires_at and token.expires_at < dt.datetime.now(dt.timezone.utc):
                print(f"Token expired at {token.expires_at}")
                abort(401, description='API token expired')
                
            # Check permissions if required
            if required_permissions:
                print(f"Checking required permissions: {required_permissions}")
                perms_token = json.loads(token.permissions) if token.permissions else []
                user = Users.query.get(token.user_id)
                perms_user = json.loads(user.permissions) if user and user.permissions else []
                
                print(f"Token permissions: {perms_token}")
                print(f"User permissions: {perms_user}")
                
                # Both token and user must have all required permissions
                if not all(p in perms_token for p in required_permissions) or not all(p in perms_user for p in required_permissions):
                    print("Insufficient permissions")
                    abort(403, description='Insufficient token or user permissions')
                    
            request.api_token = token
            print("=== API token authentication successful ===")
            
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

# Public routes for initial client registration
@client_api.route('/register', methods=['POST'])
def register_client():
    """
    Register a new client.
    ---
    tags:
      - Clients
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - name
            - local_ip
            - public_ip
            - cpu_type
            - internet_access
          properties:
            name:
              type: string
            local_ip:
              type: string
            public_ip:
              type: string
            cpu_type:
              type: string
            internet_access:
              type: boolean
    responses:
      201:
        description: Client registered
        schema:
          type: object
          properties:
            server_id:
              type: integer
            token:
              type: string
            public_key:
              type: string
    """
    try:
        print("=== Starting client registration process ===")
        data = request.get_json()
        print(f"Received registration data: {data}")
        
        required_fields = ['name', 'local_ip', 'public_ip', 'cpu_type', 'internet_access']
        print(f"Checking required fields: {required_fields}")
        
        # Check required fields
        for field in required_fields:
            if field not in data:
                print(f"Missing required field: {field}")
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        print("All required fields are present")
        
        # Check if server already exists by both name and IP
        print(f"Checking for existing server with name: {data['name']}, local_ip: {data['local_ip']}, public_ip: {data['public_ip']}")
        existing_server = Server.query.filter(
            Server.name == data['name'],
            (Server.local_ip == data['local_ip']) | (Server.public_ip == data['public_ip'])
        ).first()
        
        if existing_server:
            print(f"Found existing server with ID: {existing_server.id}")
            # Generate new token and keys for existing server
            token = secrets.token_hex(16)
            print("Generated new token")
            private_key, public_key, encryption_key = generate_key_pair()
            print("Generated new key pair")
            
            # Update existing server
            print("Updating existing server")
            existing_server.token = token
            existing_server.public_key = public_key
            existing_server.private_key = private_key.decode() if isinstance(private_key, bytes) else private_key
            existing_server.encryption_key = encryption_key.decode() if isinstance(encryption_key, bytes) else encryption_key
            existing_server.last_seen = dt.datetime.now(dt.timezone.utc)
            
            db.session.commit()
            print("Successfully updated existing server")
            
            return jsonify({
                'server_id': existing_server.id,
                'token': token,
                'public_key': public_key
            }), 200
        
        print("No existing server found, creating new server")
        # Generate token for new server
        token = secrets.token_hex(16)
        print("Generated new token")
        
        # Generate RSA key pair
        private_key, public_key, encryption_key = generate_key_pair()
        print("Generated new key pair")
        
        # Create server record
        print("Creating new server record")
        server = Server(
            name=data['name'],
            local_ip=data['local_ip'],
            public_ip=data['public_ip'],
            cpu_type=data['cpu_type'],
            internet_access=data['internet_access'],
            token=token,
            public_key=public_key,
            private_key=private_key.decode() if isinstance(private_key, bytes) else private_key,
            encryption_key=encryption_key.decode() if isinstance(encryption_key, bytes) else encryption_key,
            is_approved=False,
            last_seen=dt.datetime.now(dt.timezone.utc)
        )
        
        print("Adding server to database")
        db.session.add(server)
        db.session.commit()
        print(f"Successfully created new server with ID: {server.id}")
        
        # Create default client configuration
        print("Creating default client configuration")
        config = ClientConfig(
            server_id=server.id,
            update_interval_seconds=30,
            client_poll_interval_seconds=20,
            max_output_lines=100,
            run_as_admin_default=True,
            run_in_sandbox_default=False,
            config_json=json.dumps({})  # Initialize with empty JSON object
        )
        db.session.add(config)
        db.session.commit()
        print("Successfully created client configuration")
        
        print("=== Client registration completed successfully ===")
        return jsonify({
            'server_id': server.id,
            'token': token,
            'public_key': public_key
        }), 201
        
    except Exception as e:
        print(f"=== Error in client registration ===")
        print(f"Error type: {type(e).__name__}")
        print(f"Error message: {str(e)}")
        print(f"Error details: {e.__dict__ if hasattr(e, '__dict__') else 'No additional details'}")
        db.session.rollback()
        return jsonify({'error': 'Internal server error', 'details': str(e)}), 500

# Get all servers
@api_bp.route('/servers', methods=['GET'])
@require_api_token(['servers:read'])
def get_servers():
    print("get_servers")
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
@api_bp.route('/servers/<int:server_id>', methods=['GET'])
@require_api_token(['servers:read'])
def get_server(server_id):  
    print("get_server")
    """
    Get a server by ID.
    ---
    tags:
      - Servers
    parameters:
      - in: path
        name: server_id
        required: true
        type: integer
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
        'id': server.id,
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
@api_bp.route('/servers/<int:server_id>', methods=['PUT'])
@require_api_token(['servers:write'])
def update_server(server_id):
    print("update_server")
    """
    Update server details (heartbeat/update).
    ---
    tags:
      - Servers
    parameters:
      - in: path
        name: server_id
        required: true
        type: integer
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
@api_bp.route('/servers/<int:server_id>/approve', methods=['POST'])
@require_api_token(['servers:write'])
def approve_server(server_id):
    print("approve_server")
    """
    Approve a server.
    ---
    tags:
      - Servers
    parameters:
      - in: path
        name: server_id
        required: true
        type: integer
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
@api_bp.route('/servers/<int:server_id>', methods=['DELETE'])
@require_api_token(['servers:write'])
def delete_server(server_id): 
    print("delete_server")
    """
    Delete a server.
    ---
    tags:
      - Servers
    parameters:
      - in: path
        name: server_id
        required: true
        type: integer
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
    print("get_commands")
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
    print("get_command")
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
    print("create_command")
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
    return jsonify({'id': command.id}), 201

# Update an existing command
@api_bp.route('/commands/<uuid:command_id>', methods=['PUT'])
@require_api_token(['commands:write'])
def update_command(command_id):
    print("update_command")
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
    print("delete_command")
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
    print("get_tasks")
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
    print("get_task")
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
    print("create_task")
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
        name=data['name'],
        reason=data.get('reason'),
        tasks_json=data.get('tasks_json'),
        created_by=data['created_by'],
    )
    db.session.add(task)
    db.session.commit()
    return jsonify({'id': task.id}), 201

# Update an existing task
@api_bp.route('/tasks/<uuid:task_id>', methods=['PUT'])
@require_api_token(['tasks:write'])
def update_task(task_id):
    print("update_task")
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
    print("delete_task")
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
    print("get_task_commands")
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
    print("add_task_command")
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
    return jsonify({'id': task_command.id}), 201

# Update a TaskCommand
@api_bp.route('/task_commands/<string:task_command_id>', methods=['PUT'])
@require_api_token(['tasks:write'])
def update_task_command(task_command_id): 
    print("update_task_command")
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
    print("delete_task_command")
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
    print("get_command_history")
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
    print("get_server_command_history")
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
    print("get_command_history_by_command")
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
    print("add_command_history")
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
    return jsonify({'id': history.id}), 201

# TaskHistory endpoints
@api_bp.route('/task_history', methods=['GET'])
@require_api_token(['history:read'])
def get_task_history():
    print("get_task_history")
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
    print("get_server_task_history")
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
    print("get_task_history_by_task")
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
    print("add_task_history")
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
    print("get_client_config")
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
    print("=== Starting client config update ===")
    print(f"Server ID: {server_id}")
    print(f"Request data: {request.get_json()}")
    
    config = ClientConfig.query.filter_by(server_id=server_id).first()
    if not config:
        print(f"No config found for server {server_id}")
        return jsonify({'error': 'ClientConfig not found'}), 404
        
    data = request.get_json()
    print(f"Updating config with data: {data}")
    
    for field in [
        'update_interval_seconds', 'client_poll_interval_seconds', 'max_output_lines',
        'run_as_admin_default', 'run_in_sandbox_default', 'config_json',
        'temporary_short_interval', 'temporary_interval_end_time']:
        if field in data:
            print(f"Setting {field} to {data[field]}")
            setattr(config, field, data[field])
            
    try:
        db.session.commit()
        print("Config updated successfully")
        return jsonify({'message': 'ClientConfig updated'})
    except Exception as e:
        print(f"Error updating config: {str(e)}")
        db.session.rollback()
        return jsonify({'error': f'Failed to update config: {str(e)}'}), 500

# User management endpoints
@api_bp.route('/users', methods=['GET'])
@require_api_token(['users:read'])
def get_users():
    print("get_users")
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
    print("get_user")
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
    print("create_user")
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
    print("update_user")
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
    print("delete_user")
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
@api_bp.route('/servers/<int:server_id>/run_command', methods=['POST'])
@require_api_token(['cli:write'])
def run_cli_command(server_id):
    print("run_cli_command")
    """
    Submit a CLI command to a server (from UI/user).
    ---
    tags:
      - CLI
    parameters:
      - in: path
        name: server_id
        required: true
        type: integer
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
              type: integer
    """
    data = request.get_json()
    required_fields = ['command_text', 'created_by']
    if not data or not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400
    # Create a CommandHistory record with run_type 'online_cli'
    history = CommandHistory(
        server_id=server_id,
        command_id=None,
        command_name=data['command_text'],
        run_type='online_cli',
        created_by=data['created_by'],
        reason=data.get('reason'),
        created_at=dt.datetime.now(dt.timezone.utc)
    )
    db.session.add(history)
    db.session.commit()
    return jsonify({'command_history_id': history.id}), 201

# Agent fetches pending CLI commands to run
@api_bp.route('/servers/<string:server_id>/pending_commands', methods=['GET'])
@require_api_token(['cli:read'])
def get_pending_cli_commands(server_id):
    print("get_pending_cli_commands")
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

# Add the original command history result endpoint
@client_api.route('/command_history/<string:command_history_id>/result', methods=['POST'])
@client_token_required
def submit_command_result(command_history_id):
    print("submit_command_result")
    """
    Submit result for a command (from agent).
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
    try:
        history = CommandHistory.query.get(command_history_id)
        if not history:
            return {'error': 'CommandHistory not found'}, 404
            
        # Verify the command belongs to the authenticated server
        server = g.server
        if history.server_id != server.id:
            return {'error': 'Command history does not belong to this server'}, 403
            
        data = request.get_json()
        # Required: output, executed_time, duration_seconds
        for field in ['output', 'executed_time', 'duration_seconds']:
            if field not in data:
                return {'error': f'Missing required field: {field}'}, 400
                
        history.output = data['output']
        
        # Handle executed_time - it could be a string or already a datetime
        executed_time = data['executed_time']
        if isinstance(executed_time, str):
            try:
                history.executed_time = dt.datetime.strptime(executed_time, '%Y-%m-%d %H:%M:%S')
            except ValueError:
                return {'error': 'Invalid executed_time format. Expected format: YYYY-MM-DD HH:MM:SS'}, 400
        else:
            history.executed_time = executed_time
            
        history.duration_seconds = data['duration_seconds']
        
        # Update run_status based on command execution
        # If there's an error in the output, mark as failed
        if data['output'] and ('error' in data['output'].lower() or 'failed' in data['output'].lower()):
            history.run_status = 'failed'
        else:
            history.run_status = 'success'
            
        try:
            db.session.commit()
            return {'message': 'Result submitted'}, 200
        except Exception as e:
            db.session.rollback()
            print(f"Database error while updating command history: {str(e)}")
            print(f"Error type: {type(e)}")
            print(f"Error details: {traceback.format_exc()}")
            return {'error': f'Database error while updating command history: {str(e)}'}, 500
            
    except Exception as e:
        print(f"Error in submit_command_result: {str(e)}")
        print(f"Error type: {type(e)}")
        print(f"Error details: {traceback.format_exc()}")
        return {'error': f'Internal server error: {str(e)}'}, 500

# Admin-only endpoint to create API tokens
@api_bp.route('/api_tokens', methods=['POST'])
@require_api_token(['admin'])
def create_api_token():
    print("create_api_token")
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

# Add logging to client_api
@client_api.before_request
def log_client_api_request():
    print(f"Client API request: {request.method} {request.path}")
    print(f"Headers: {dict(request.headers)}")
    print(f"URL: {request.url}")
    print(f"Endpoint: {request.endpoint}")
    print(f"View args: {request.view_args}")
    print(f"Query string: {request.query_string}")
    print(f"Form data: {request.form}")
    print(f"JSON data: {request.get_json(silent=True)}")
    return None

# Register blueprint in main app
def init_app(app):
    # Disable CSRF for client API endpoints
    app.config['WTF_CSRF_CHECK_DEFAULT'] = False
    
    @app.before_request
    def before_request():
        if request.path.startswith('/api/client/'):
            return  # Skip Flask-Login for client API endpoints

# Export blueprints
__all__ = ['api_bp', 'client_api']

@client_api.route('/approval_status/<int:client_id>', methods=['GET'])
@client_token_required
def check_server_approval(client_id):
    """
    Check if a server is approved.
    ---
    tags:
      - Servers
    parameters:
      - in: path
        name: client_id
        required: true
        type: integer
      - in: header
        name: Authorization
        required: true
        type: string
        description: Bearer token
    responses:
      200:
        description: Server approval status
      401:
        description: Unauthorized
      403:
        description: Forbidden
      404:
        description: Server not found
    """
    print(f"Checking approval status for client {client_id}")
    server = g.server  # Get the server from the decorator
    
    # Verify that the requested client_id matches the authenticated server
    if server.id != client_id:
        print(f"Token belongs to server {server.id} but requested approval status for server {client_id}")
        return {'error': 'Invalid server ID'}, 403
    
    print(f"Server {server.id} is {'approved' if server.is_approved else 'not approved'}")
    return {
        'is_approved': server.is_approved,
        'server_id': server.id,
        'name': server.name
    }, 200

def generate_encryption_key():
    """Generate a key for encrypting the private key"""
    key = Fernet.generate_key()
    return key

def generate_key_pair():
    """Generate RSA key pair"""
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Get public key
    public_key = private_key.public_key()
    
    # Save private key encrypted
    encryption_key = generate_encryption_key()
    f = Fernet(encryption_key)
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Encrypt the private key with the encryption key
    encrypted_private_key = f.encrypt(private_pem)
    
    # Save public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return encrypted_private_key, public_pem.decode(), encryption_key

@client_api.route('/latest-version', methods=['GET'])
@client_token_required
def get_latest_version():
    """
    Get the latest client version.
    ---
    tags:
      - Version
    responses:
      200:
        description: Latest version information
    """
    return jsonify({'version': LATEST_VERSION})

@client_api.route('/download/<version>', methods=['GET'])
@client_token_required
def download_client_version(version):
    """
    Download a specific client version.
    ---
    tags:
      - Version
    parameters:
      - in: path
        name: version
        required: true
        type: string
    responses:
      200:
        description: Client version file
      404:
        description: Version not found
    """
    version_file = os.path.join(CLIENT_VERSIONS_DIR, f'client_{version}.py')
    if not os.path.exists(version_file):
        return jsonify({'error': 'Version not found'}), 404
    return send_file(version_file)

@client_api.route('/update-status', methods=['POST'])
@client_token_required
def update_client_status():
    """
    Report client update status.
    ---
    tags:
      - Version
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - version
            - status
          properties:
            version:
              type: string
            status:
              type: string
    responses:
      200:
        description: Status updated
    """
    data = request.get_json()
    if not data or 'version' not in data or 'status' not in data:
        return jsonify({'error': 'Missing required fields'}), 400
        
    server = g.server
    status = AgentUpdateStatus(
        server_id=server.id,
        version=data['version'],
        status=data['status'],
        timestamp=dt.datetime.now(dt.timezone.utc)
    )
    db.session.add(status)
    db.session.commit()
    return jsonify({'message': 'Status updated'})

# --- SERVER LOGGING CONFIGURATION ---
log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../logs')
if not os.path.exists(log_dir):
    os.makedirs(log_dir)
log_file = os.path.join(log_dir, 'server.log')
file_handler = RotatingFileHandler(log_file, maxBytes=2*1024*1024, backupCount=5, encoding='utf-8')
file_handler.setLevel(logging.INFO)
formatter = logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s')
file_handler.setFormatter(formatter)
logger = logging.getLogger('server')
logger.setLevel(logging.INFO)
if not logger.handlers:
    logger.addHandler(file_handler)

# Client commands endpoint
@client_api.route('/commands/<int:client_id>', methods=['GET', 'POST'])
@client_token_required
def get_client_commands(client_id):
    """
    Get pending commands for a client.
    ---
    tags:
      - Commands
    parameters:
      - in: path
        name: client_id
        required: true
        type: integer
      - in: body
        name: body
        schema:
          type: object
          properties:
            last_seen:
              type: string
              format: date-time
    responses:
      200:
        description: List of pending commands
    """
    print(f"=== Getting commands for client {client_id} ===")
    server = g.server
    print(f"Authenticated server: ID={server.id}, Name={server.name}")
    
    if server.id != client_id:
        print(f"Client ID mismatch: requested {client_id}, authenticated {server.id}")
        return jsonify({'error': 'Invalid client ID'}), 403
        
    # Get client config
    try:
        client_config = ClientConfig.query.filter_by(server_id=client_id).first()
        interval = client_config.client_poll_interval_seconds if client_config else 20
        print(f"Client poll interval: {interval} seconds")
    except Exception as e:
        print(f"Error getting client config: {str(e)}")
        interval = 20
    
    # Update last_seen timestamp from POST request
    if request.method == 'POST':
        data = request.get_json()
        if data and 'last_seen' in data:
            try:
                last_seen = dt.datetime.strptime(data['last_seen'], '%Y-%m-%d %H:%M:%S')
                server.last_seen = last_seen
                db.session.commit()
                print(f"Updated last_seen timestamp to {last_seen}")
            except Exception as e:
                print(f"Failed to update last_seen timestamp: {str(e)}")
    
    # Get pending commands for this client from command_history
    try:
        now = dt.datetime.now(dt.timezone.utc)
        print(f"Getting pending commands as of {now}")
        
        pending_history = CommandHistory.query.filter(
            CommandHistory.server_id == client_id,
            CommandHistory.executed_time.is_(None),
            db.or_(
                CommandHistory.scheduled_time.is_(None),
                CommandHistory.scheduled_time <= now
            )
        ).all()
        
        print(f"Found {len(pending_history)} pending commands")
        for cmd in pending_history:
            print(f"Command: ID={cmd.id}, Name={cmd.command_name}")
        
        return {
            'commands': [{
                'id': str(hist.command_id) if hist.command_id else None,
                'command': hist.command.command_text if hist.command else hist.command_name,
                'as_admin': True,  # Default to running as admin for now
                'history_id': str(hist.id)  # Include history ID for updating status
            } for hist in pending_history],
            'interval': interval
        }, 200
    except Exception as e:
        print(f"Error getting pending commands: {str(e)}")
        return {'error': 'Internal server error', 'details': str(e)}, 500 

@api_bp.route('/command_history/<int:history_id>/result', methods=['POST'])
@require_api_token(['history:write'])
def command_history_result(history_id):
    """Submit command execution result and validate output"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
            
        # Get the command history entry
        history = CommandHistory.query.get_or_404(history_id)
        
        # Get the task command if this is part of a task
        task_command = None
        if history.task_command_id:
            task_command = TaskCommand.query.get(history.task_command_id)
        
        # Check output against regex if this is part of a task
        output = data.get('output', '')
        run_status = 'success'
        
        if task_command and task_command.output_regex:
            import re
            try:
                pattern = re.compile(task_command.output_regex)
                if not pattern.search(output):
                    run_status = 'failed'
                    log_error(f"Command output did not match regex pattern: {task_command.output_regex}")
            except Exception as e:
                log_error(f"Error checking output regex: {str(e)}")
                run_status = 'failed'
        
        # Update the history entry
        history.output = output
        history.error = data.get('error', '')
        history.executed_time = dt.datetime.strptime(data.get('executed_time'), '%Y-%m-%d %H:%M:%S')
        history.duration_seconds = data.get('duration_seconds', 0)
        history.run_status = run_status
        
        db.session.commit()
        
        # If this is part of a task, check if we need to continue with the next command
        if history.task_id and run_status == 'success':
            # Get the next command in the task
            next_command = TaskCommand.query.filter(
                TaskCommand.task_id == history.task_id,
                TaskCommand.order > task_command.order
            ).order_by(TaskCommand.order).first()
            
            if next_command:
                # Create history entry for next command
                next_history = CommandHistory(
                    server_id=history.server_id,
                    server_name=history.server_name,
                    command_id=next_command.command_id,
                    command_name=next_command.command.name,
                    task_id=history.task_id,
                    task_command_id=next_command.id,
                    run_type='task',
                    run_status='pending',
                    created_by=history.created_by
                )
                db.session.add(next_history)
                db.session.commit()
        
        return jsonify({'message': 'Result submitted successfully'})
        
    except Exception as e:
        db.session.rollback()
        log_error(f"Error processing command result: {str(e)}")
        return jsonify({'error': str(e)}), 500