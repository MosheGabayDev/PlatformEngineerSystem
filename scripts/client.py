import os
import sys
import time
import json
import requests
import platform
import subprocess
import traceback
import logging
import base64
from logging.handlers import RotatingFileHandler
import socket
from cryptography.hazmat.primitives import serialization, padding, hashes
from cryptography.hazmat.primitives.asymmetric import padding

CONFIG_FILE = os.path.join(os.path.dirname(__file__), 'client_config.json')

API_BASE = 'http://localhost:5000/api/client'  # Base API endpoint for client operations

DEFAULT_CONFIG = {
    'api_token': None,
    'interval': 30,
    'client_id': None,
    'last_version': '0.1.0',
    'debug': True
}

def load_config():
    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'w') as f:
            json.dump(DEFAULT_CONFIG, f, indent=2)
        return DEFAULT_CONFIG.copy()
    with open(CONFIG_FILE, 'r') as f:
        cfg = json.load(f)
        updated = False
        for k, v in DEFAULT_CONFIG.items():
            if k not in cfg:
                cfg[k] = v
                updated = True
        if updated:
            with open(CONFIG_FILE, 'w') as f2:
                json.dump(cfg, f2, indent=2)
        return cfg

def save_config(cfg):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(cfg, f, indent=2)

# --- LOGGING CONFIGURATION ---
cfg_for_log = load_config()
debug_mode = cfg_for_log.get('debug', False)
log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../logs')
if not os.path.exists(log_dir):
    os.makedirs(log_dir)
log_file = os.path.join(log_dir, 'client.log')
file_handler = RotatingFileHandler(log_file, maxBytes=2*1024*1024, backupCount=5, encoding='utf-8')
file_handler.setLevel(logging.DEBUG if debug_mode else logging.INFO)
formatter = logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s')
file_handler.setFormatter(formatter)
logger = logging.getLogger('client')
logger.setLevel(logging.DEBUG if debug_mode else logging.INFO)
if not logger.handlers:
    logger.addHandler(file_handler)

# Debug log file for debug-only messages (no sensitive info)
debug_log_file = os.path.join(os.path.dirname(__file__), 'client_debug.log')
debug_file_handler = RotatingFileHandler(debug_log_file, maxBytes=1*1024*1024, backupCount=2, encoding='utf-8')
debug_file_handler.setLevel(logging.DEBUG)
debug_formatter = logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s')
debug_file_handler.setFormatter(debug_formatter)
debug_logger = logging.getLogger('client_debug')
debug_logger.setLevel(logging.DEBUG)
if not debug_logger.handlers:
    debug_logger.addHandler(debug_file_handler)

# Utility print/log wrappers
def log_info(msg):
    print(msg)
    logger.info(msg)

def log_error(msg):
    print(msg, file=sys.stderr)
    logger.error(msg)

def log_debug(msg):
    # Only log if debug mode is enabled, and filter sensitive info
    if debug_mode:
        # Filter out sensitive info
        sensitive_keywords = ['key', 'token', 'private', 'secret', 'password']
        lower_msg = msg.lower()
        if not any(word in lower_msg for word in sensitive_keywords):
            print('[DEBUG]', msg)
            debug_logger.debug(msg)
        else:
            filtered_msg = '[Filtered sensitive debug message]'
            debug_logger.debug(filtered_msg)

def get_ip_addresses():
    # Get local IP
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = '127.0.0.1'
    finally:
        s.close()
    
    # Get public IP
    try:
        response = requests.get('https://api.ipify.org')
        public_ip = response.text
    except:
        public_ip = None
    
    return local_ip, public_ip

def get_system_info():
    """Gather system information for registration"""
    try:
        # Get IP addresses
        local_ip, public_ip = get_ip_addresses()
        
        # Get CPU info
        cpu_type = platform.processor()
        
        # Get hostname
        hostname = platform.node()
        
        # Check internet access
        internet_access = bool(public_ip)
        
        return {
            'hostname': hostname,
            'local_ip': local_ip,
            'public_ip': public_ip,
            'cpu_type': cpu_type,
            'internet_access': internet_access
        }
    except Exception as e:
        print(f"Error getting system info: {str(e)}")
        return {
            'hostname': 'unknown',
            'local_ip': 'unknown',
            'public_ip': 'unknown',
            'cpu_type': 'unknown',
            'internet_access': False
        }

def verify_server_response(response_data, signature):
    """Verify the server's response signature"""
    try:
        log_info("Verifying server response signature")
        
        # Load server's public key
        try:
            with open('server_public_key.pem', 'r') as f:
                public_key_pem = f.read()
            log_debug("Loaded server's public key")
        except Exception as e:
            log_error(f"Failed to load server's public key: {str(e)}")
            return False
            
        # Load the public key
        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode()
            )
            log_debug("Public key loaded successfully")
        except Exception as e:
            log_error(f"Failed to load public key: {str(e)}")
            return False
            
        # Convert data to string if it's a dict
        if isinstance(response_data, dict):
            log_debug("Converting response data dict to string")
            data_str = json.dumps(response_data, sort_keys=True)  # Sort keys for consistent ordering
        else:
            data_str = str(response_data)
            
        log_debug(f"Data to verify: {data_str}")
        log_debug(f"Signature to verify: {signature}")
            
        # Verify the signature
        try:
            log_debug("Verifying signature")
            public_key.verify(
                base64.b64decode(signature),
                data_str.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            log_debug("Signature verification successful")
            return True
        except Exception as e:
            log_error(f"Signature verification failed: {str(e)}")
            log_debug(f"Error type: {type(e).__name__}")
            log_debug(f"Error details: {e.__dict__ if hasattr(e, '__dict__') else 'No additional details'}")
            return False
            
    except Exception as e:
        log_error(f"Error in response verification: {str(e)}")
        log_debug(f"Exception details: {traceback.format_exc()}")
        return False

def make_api_request(method, endpoint, data=None, cfg=None):
    """Make an API request"""
    if not cfg or not cfg.get('api_token'):
        log_error("No API token available")
        return None
        
    headers = {
        'Authorization': f'Bearer {cfg["api_token"]}',
        'Content-Type': 'application/json'
    }
    
    try:
        url = f"{API_BASE}/{endpoint}"
        log_debug(f"Making {method} request to {url}")
        log_debug(f"Headers: {headers}")
        log_debug(f"Data: {data}")
        
        if method == 'GET':
            response = requests.get(url, headers=headers)
        elif method == 'POST':
            response = requests.post(url, headers=headers, json=data)
        else:
            log_error(f"Unsupported method: {method}")
            return None
            
        log_debug(f"Response status code: {response.status_code}")
        log_debug(f"Response headers: {dict(response.headers)}")
        
        # Verify server's signature if present
        if response.status_code == 200:
            signature = response.headers.get('X-Signature')
            if signature:
                log_info("Verifying server's response signature")
                if not verify_server_response(response.json(), signature):
                    log_error("Server response signature verification failed")
                    return None
                log_info("Server response signature verified successfully")
        
        log_debug(f"Response text: {response.text}")
        return response
    except Exception as e:
        log_error(f"Error making API request: {str(e)}")
        return None

def register_client():
    """Register the client with the server and get authentication token"""
    try:
        log_info("Starting client registration")
        
        # Get system information
        system_info = get_system_info()
        log_debug(f"System info: {system_info}")
        
        # Prepare registration data
        registration_data = {
            'name': system_info['hostname'],
            'local_ip': system_info['local_ip'],
            'public_ip': system_info['public_ip'],
            'cpu_type': system_info['cpu_type'],
            'internet_access': system_info['internet_access']
        }
        log_info(f"Sending registration request with data: {registration_data}")
        
        # Send registration request
        try:
            url = f"{API_BASE}/register"
            log_debug(f"Making POST request to {url}")
            log_debug(f"Data: {registration_data}")
            
            response = requests.post(url, json=registration_data)
            log_info(f"Registration response status: {response.status_code}")
            
            if response.status_code in [200, 201]:
                try:
                    data = response.json()
                    log_info(f"Registration successful. Server ID: {data.get('server_id')}")
                    log_debug(f"Registration response JSON: {json.dumps(data, indent=2)}")
                except Exception as e:
                    log_error(f"Failed to parse registration response as JSON: {str(e)}")
                    return False
                
                # Save server ID and token to config
                config = load_config()
                config['client_id'] = data.get('server_id')
                config['api_token'] = data.get('token')
                
                # Save server's public key
                try:
                    public_key = data.get('public_key')
                    if not public_key:
                        log_error("No public key received from server")
                        return False
                        
                    # Save to both config file and PEM file
                    config['server_public_key'] = public_key
                    with open('server_public_key.pem', 'w') as f:
                        f.write(public_key)
                    log_info("Saved server's public key to both config and PEM file")
                except Exception as e:
                    log_error(f"Failed to save server's public key: {str(e)}")
                    return False
                
                try:
                    save_config(config)
                    log_info("Saved client configuration to client_config.json")
                    log_debug(f"Saved config: {json.dumps(config, indent=2)}")
                except Exception as e:
                    log_error(f"Failed to save client configuration: {str(e)}")
                    return False
                return True
            else:
                log_error(f"Registration failed: {response.text}")
                return False
                
        except Exception as e:
            log_error(f"Error making registration request: {str(e)}")
            return False
            
    except Exception as e:
        log_error(f"Error during registration: {str(e)}")
        log_debug(traceback.format_exc())
        return False

def authenticate_request():
    """Add authentication token to request headers"""
    try:
        log_info("Getting authentication token")
        with open('token.txt', 'r') as f:
            token = f.read().strip()
        log_debug(f"Token: {token[:10]}...")  # Log only first 10 chars for security
        return {'Authorization': f'Bearer {token}'}
    except Exception as e:
        log_error(f"Failed to get authentication token: {str(e)}")
        return None

def get_commands():
    """Get pending commands from server"""
    try:
        log_info("Getting pending commands")
        headers = authenticate_request()
        if not headers:
            log_error("No authentication token found")
            return None
            
        log_debug(f"Making request to {API_BASE}/commands")
        log_debug(f"Headers: {headers}")
        
        response = requests.get(
            f'{API_BASE}/commands',
            headers=headers
        )
        
        log_info(f"Response status code: {response.status_code}")
        log_debug(f"Response headers: {dict(response.headers)}")
        
        if response.status_code == 200:
            try:
                data = response.json()
                log_info(f"Received {len(data.get('commands', []))} commands")
                log_debug(f"Response data: {json.dumps(data, indent=2)}")
                return data
            except Exception as e:
                log_error(f"Failed to parse response as JSON: {str(e)}")
                log_debug(f"Raw response: {response.text}")
                return None
        else:
            log_error(f"Failed to get commands: {response.text}")
            return None
            
    except Exception as e:
        log_error(f"Error getting commands: {str(e)}")
        log_debug(f"Exception details: {traceback.format_exc()}")
        return None

def fetch_commands(cfg):
    """Fetch pending commands from server"""
    if not cfg.get('api_token'):
        log_error('No API token available. Please register first.')
        return []
    
    try:
        log_info(f"Fetching commands from {API_BASE}/commands/{cfg['client_id']}")
        
        data = {
            'last_seen': time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())
        }
        log_debug(f"Request data: {data}")
        
        response = make_api_request('POST', f'commands/{cfg["client_id"]}', data=data, cfg=cfg)
        if not response:
            log_error("Failed to make API request")
            return []
            
        log_info(f"Response status code: {response.status_code}")
        log_debug(f"Response headers: {dict(response.headers)}")
        
        try:
            response_data = response.json()
            log_debug(f"Response data: {json.dumps(response_data, indent=2)}")
        except:
            log_debug(f"Raw response text: {response.text}")
        
        if response.status_code == 200:
            result = response.json()
            if 'interval' in result and isinstance(result['interval'], int):
                cfg['interval'] = result['interval']
                save_config(cfg)
                log_info(f"Updated poll interval to {result['interval']} seconds")
            commands = result.get('commands', [])
            log_info(f"Received {len(commands)} commands")
            return commands
        elif response.status_code == 401:
            log_error('Authentication failed. Please re-register the client.')
            cfg['api_token'] = None
            cfg['client_id'] = None
            save_config(cfg)
            return []
        else:
            log_error('Failed to fetch commands: ' + response.text)
    except Exception as e:
        log_error('Error fetching commands: ' + str(e))
        log_debug(f"Exception details: {traceback.format_exc()}")
    return []

def check_for_update(cfg):
    """Check for available updates and handle the update process"""
    try:
        log_info("Checking for updates...")
        headers = {'Authorization': f'Bearer {cfg["api_token"]}'}
        
        resp = requests.get(f'{API_BASE}/latest-version', headers=headers)
        if resp.status_code == 200:
            latest = resp.json().get('version', cfg['last_version'])
            log_info(f"Current version: {cfg['last_version']}, Latest version: {latest}")
            
            if latest != cfg['last_version']:
                log_info(f'Update available: {latest}')
                update_file = download_update(cfg, latest)
                if update_file:
                    perform_update(cfg, update_file, latest)
            else:
                log_info("Client is up to date")
        else:
            log_error(f'Failed to check for update: {resp.text}')
    except Exception as e:
        log_error(f'Error checking for update: {str(e)}')
        log_debug(f"Exception details: {traceback.format_exc()}")

def download_update(cfg, new_version):
    """Download the update file and verify its integrity"""
    try:
        log_info(f"Downloading update version {new_version}")
        headers = {'Authorization': f'Bearer {cfg["api_token"]}'}
        
        url = f'{API_BASE}/download/{new_version}'
        resp = requests.get(url, stream=True, headers=headers)
        
        if resp.status_code == 200:
            update_file = os.path.join(os.path.dirname(__file__), f'client_update_{new_version}.py')
            
            # Get file size from headers
            total_size = int(resp.headers.get('content-length', 0))
            block_size = 8192
            downloaded = 0
            
            with open(update_file, 'wb') as f:
                for chunk in resp.iter_content(chunk_size=block_size):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        # Log progress every 10%
                        if total_size > 0:
                            progress = (downloaded / total_size) * 100
                            if int(progress) % 10 == 0:
                                log_info(f"Download progress: {int(progress)}%")
            
            log_info(f'Downloaded update to {update_file}')
            
            # Verify file integrity if checksum is provided
            if 'X-Checksum' in resp.headers:
                expected_checksum = resp.headers['X-Checksum']
                actual_checksum = calculate_file_checksum(update_file)
                if actual_checksum != expected_checksum:
                    log_error("File integrity check failed")
                    os.remove(update_file)
                    return None
                log_info("File integrity check passed")
            
            return update_file
        else:
            log_error(f'Failed to download update: {resp.text}')
            return None
    except Exception as e:
        log_error(f'Error downloading update: {str(e)}')
        log_debug(f"Exception details: {traceback.format_exc()}")
        return None

def calculate_file_checksum(file_path):
    """Calculate SHA-256 checksum of a file"""
    import hashlib
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def perform_update(cfg, update_file, new_version):
    """Perform the update with rollback capability"""
    update_log = []
    update_log.append(f"Starting update process to version {new_version}")
    
    try:
        # Create backup
        backup_file = os.path.join(os.path.dirname(__file__), 'client_backup.py')
        current_file = os.path.abspath(__file__)
        
        update_log.append("Creating backup of current version")
        os.rename(current_file, backup_file)
        
        # Apply update
        update_log.append("Applying update")
        os.rename(update_file, current_file)
        
        # Verify the new file
        update_log.append("Verifying new installation")
        if not verify_new_installation(current_file):
            raise Exception("New installation verification failed")
        
        update_log.append("Update applied successfully")
        
        # Report success to server
        report_update_status(cfg, new_version, 'success', update_log)
        
        # Restart service
        update_log.append("Restarting service")
        if platform.system() == 'Windows':
            os.system('sc stop PlatformAgent && sc start PlatformAgent')
        else:
            os.system('systemctl restart platform-agent')
        
        update_log.append("Service restarted successfully")
        sys.exit(0)
        
    except Exception as e:
        error_msg = f"Update failed: {str(e)}"
        update_log.append(error_msg)
        log_error(error_msg)
        
        # Rollback
        update_log.append("Initiating rollback")
        try:
            if os.path.exists(backup_file):
                os.rename(backup_file, os.path.abspath(__file__))
                update_log.append("Rollback completed successfully")
            else:
                update_log.append("Backup file not found, rollback failed")
        except Exception as rollback_error:
            update_log.append(f"Rollback failed: {str(rollback_error)}")
        
        # Report failure to server
        report_update_status(cfg, new_version, 'failed', update_log)
        
        # Restart service after rollback
        try:
            if platform.system() == 'Windows':
                os.system('sc stop PlatformAgent && sc start PlatformAgent')
            else:
                os.system('systemctl restart platform-agent')
            update_log.append("Service restarted after rollback")
        except Exception as restart_error:
            update_log.append(f"Failed to restart service after rollback: {str(restart_error)}")

def verify_new_installation(file_path):
    """Verify that the new installation is valid"""
    try:
        # Try to import the new file
        with open(file_path, 'r') as f:
            content = f.read()
            compile(content, file_path, 'exec')
        return True
    except Exception as e:
        log_error(f"New installation verification failed: {str(e)}")
        return False

def report_update_status(cfg, version, status, update_log=None):
    """Report update status to server with detailed logs"""
    if not cfg.get('api_token'):
        log_error('No API token available. Please register first.')
        return
        
    data = {
        'version': version,
        'status': status,
        'timestamp': time.time(),
        'update_log': update_log if update_log else []
    }
    
    headers = {'Authorization': f'Bearer {cfg["api_token"]}'}
    
    try:
        log_info(f"Reporting update status: {status}")
        resp = requests.post(f'{API_BASE}/update-status', headers=headers, json=data)
        if resp.status_code == 200:
            log_info("Update status reported successfully")
        else:
            log_error(f"Failed to report update status: {resp.text}")
    except Exception as e:
        log_error(f'Error reporting update status: {str(e)}')
        log_debug(f"Exception details: {traceback.format_exc()}")

def check_approval_status(cfg):
    """Check if this server is approved in the servers table"""
    if not cfg.get('api_token') or not cfg.get('client_id'):
        log_error("Missing API token or client ID. Cannot check approval status.")
        return False
    
    response = make_api_request('GET', f'approval_status/{cfg["client_id"]}', cfg=cfg)
    if not response:
        return False
        
    if response.status_code == 200:
        try:
            result = response.json()
            is_approved = result.get('is_approved', False)
            if isinstance(is_approved, int):
                is_approved = bool(is_approved)
            if not is_approved:
                log_info('Server is waiting for admin approval in the servers table')
            else:
                log_info('Server is approved and ready to process commands')
            return is_approved
        except json.JSONDecodeError as e:
            log_error(f'Failed to parse server response as JSON: {response.text}')
            return False
    elif response.status_code == 401:
        log_error('Authentication failed. Please re-register the client.')
        cfg['api_token'] = None
        cfg['client_id'] = None
        save_config(cfg)
        return False
    else:
        log_error('Failed to check approval status: ' + response.text)
        return False

def run_command(command, as_admin=False):
    """Execute a command and return its output"""
    try:
        log_info(f"Running command: {command}")
        start_time = time.time()
        
        # Create process with appropriate privileges
        if as_admin and platform.system() == 'Windows':
            # On Windows, use PowerShell to execute as admin
            ps_command = f'powershell -Command "$output = & {{ cmd /c {command} 2>&1 }}; $output; $LASTEXITCODE"'
            process = subprocess.Popen(
                ps_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True
            )
            stdout, stderr = process.communicate()
            output = stdout.decode('utf-8', errors='replace')
            error = stderr.decode('utf-8', errors='replace')
            
            # Split output to get exit code (last line)
            output_lines = output.strip().split('\n')
            if output_lines:
                try:
                    exit_code = int(output_lines[-1])
                    output = '\n'.join(output_lines[:-1])  # Remove exit code from output
                except ValueError:
                    exit_code = process.returncode
            else:
                exit_code = process.returncode
        else:
            # Normal execution
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True
            )
            stdout, stderr = process.communicate()
            output = stdout.decode('utf-8', errors='replace')
            error = stderr.decode('utf-8', errors='replace')
            exit_code = process.returncode
            
        duration = time.time() - start_time
        
        # Log results
        if output:
            log_info(f"Command output: {output}")
        if error:
            log_error(f"Command error: {error}")
            
        return {
            'output': output,
            'error': error,
            'duration': duration,
            'exit_code': exit_code
        }
        
    except Exception as e:
        error_msg = f"Error executing command: {str(e)}"
        log_error(error_msg)
        log_debug(f"Exception details: {traceback.format_exc()}")
        return {
            'output': '',
            'error': error_msg,
            'duration': 0,
            'exit_code': -1
        }

def check_output_regex(output, regex_pattern):
    """Check if command output matches the regex pattern"""
    try:
        if not regex_pattern:
            return True  # If no regex pattern is provided, consider it a match
            
        import re
        pattern = re.compile(regex_pattern)
        return bool(pattern.search(output))
    except Exception as e:
        log_error(f"Error checking output regex: {str(e)}")
        return False

def send_command_result(cfg, command_id, history_id, result):
    """Send command execution result to server"""
    if not cfg.get('api_token'):
        log_error('No API token available. Please register first.')
        return False
        
    try:
        log_info(f"Sending result for command {command_id}")
        
        # Format the executed time in the correct format
        executed_time = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())
        
        # Get the command history entry to check regex pattern
        response = make_api_request('GET', f'command_history/{history_id}', cfg=cfg)
        if not response or response.status_code != 200:
            log_error(f"Failed to get command history entry {history_id}")
            return False
            
        history_data = response.json()
        regex_pattern = history_data.get('output_regex')
        
        # Check if output matches regex pattern
        output_matches = check_output_regex(result.get('output', ''), regex_pattern)
        
        data = {
            'output': result.get('output', ''),
            'error': result.get('error', ''),
            'executed_time': executed_time,
            'duration_seconds': result.get('duration', 0),
            'run_status': 'success' if output_matches else 'failed'
        }
        
        log_debug(f"Sending result data: {data}")
        
        # Use the correct API endpoint
        response = make_api_request('POST', f'command_history/{history_id}/result', data=data, cfg=cfg)
        if not response:
            log_error(f"Failed to send result for command {command_id}")
            return False
            
        if response.status_code == 200:
            log_info(f"Result for command {command_id} sent successfully")
            return True
        else:
            log_error(f"Failed to send result for command {command_id}: {response.text}")
            return False
            
    except Exception as e:
        log_error(f"Error sending command result: {str(e)}")
        log_debug(f"Exception details: {traceback.format_exc()}")
        return False

def main():
    cfg = load_config()
    while True:
        if not cfg.get('client_id') or not cfg.get('api_token'):
            register_client()
            cfg = load_config()
            if not cfg.get('client_id') or not cfg.get('api_token'):
                log_error('Registration failed. Retrying in 30 seconds...')
                time.sleep(30)
                continue
        
        # Check if server is approved
        if not check_approval_status(cfg):
            log_info('Waiting for admin approval... Will check again in 60 seconds')
            time.sleep(60)
            continue
        
        log_info('Fetching commands...')
        commands = fetch_commands(cfg)
        if commands is None:  # Authentication failed
            continue
            
        log_info('Commands: ' + str(commands))
        check_for_update(cfg)
        for cmd in commands:
            command_id = cmd.get('id')
            command_text = cmd.get('command')
            history_id = cmd.get('history_id')  # Get history_id from command
            as_admin = cmd.get('as_admin', False)
            log_info('Running command: ' + command_text + ' (admin=' + str(as_admin) + ')')
            result = run_command(command_text, as_admin=as_admin)
            log_info('Result: ' + str(result))
            send_command_result(cfg, command_id, history_id, result)
        time.sleep(cfg.get('interval', 30))

if __name__ == '__main__':
    main() 