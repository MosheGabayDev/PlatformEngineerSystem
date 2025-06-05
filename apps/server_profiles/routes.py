from flask import Blueprint, render_template, request, jsonify
from datetime import datetime, timedelta
from flask_login import login_required, current_user
from apps import db
from sqlalchemy import text
from apps.authentication.permissions_util import require_permission
import requests
from flask import current_app

server_profiles = Blueprint('server_profiles', __name__)

@server_profiles.route('/server-profiles')
@login_required
def server_list():
    """Display list of servers with clients installed"""
    servers = db.session.execute(text("""
          SELECT s.*,
                (SELECT COUNT(*)
                  FROM command_history ch
                  WHERE ch.server_id = s.id
                  AND ch.executed_time >= DATE_SUB(NOW(), INTERVAL 60 DAY)) AS command_count,
                CASE
                    WHEN DATE_ADD(s.last_seen, INTERVAL 3 HOUR) >= DATE_SUB(NOW(), INTERVAL 5 MINUTE) THEN 1
                    ELSE 0
                END AS is_active
          FROM servers s
          WHERE s.token IS NOT NULL
          ORDER BY s.name
    """)).fetchall()
    
    return render_template('server_profiles/list.html', servers=servers)

@server_profiles.route('/server-profiles/<int:server_id>')
@login_required
def server_profile(server_id):
    """Display detailed server profile and command history"""
    # Get server details with client config
    server = db.session.execute(text("""
        SELECT s.*,
               CASE WHEN DATE_ADD(s.last_seen, INTERVAL 3 HOUR) >= DATE_SUB(NOW(), INTERVAL 5 MINUTE) THEN 1 ELSE 0 END as is_active,
               cc.client_poll_interval_seconds,
               cc.update_interval_seconds,
               cc.run_as_admin_default,
               cc.run_in_sandbox_default,
               cc.max_output_lines
        FROM servers s 
        LEFT JOIN client_configs cc ON cc.server_id = s.id
        WHERE s.id = :server_id
    """), {'server_id': server_id}).fetchone()
    
    if not server:
        return render_template('home/page-404.html'), 404
    
    # Get command history for last 60 days
    command_history = db.session.execute(text("""
        SELECT ch.*,
               COALESCE(ch.command_name, c.name) as display_command_name
        FROM command_history ch
        LEFT JOIN commands c ON c.id = ch.command_id
        WHERE ch.server_id = :server_id
        AND ch.executed_time >= DATE_SUB(NOW(), INTERVAL 60 DAY)
        ORDER BY ch.executed_time DESC
    """), {
        'server_id': server_id
    }).fetchall()
    
    return render_template('server_profile.html',
                         server=server,
                         command_history=command_history)

@server_profiles.route('/server-profiles/<int:server_id>/run_cli_command_ui', methods=['POST'])
@login_required
@require_permission('admin')
def run_cli_command_ui(server_id):
    # Check if user has an active API token
    if not current_user.api_token or not current_user.api_token.is_active:
        return jsonify({'error': 'No active API token found. Please create an API token first.'}), 403

    data = request.get_json()
    command_text = data.get('command_text')
    run_as_admin = data.get('run_as_admin', False)
    reason = data.get('reason', 'Manual CLI execution')

    if not command_text:
        return jsonify({'error': 'No command provided'}), 400

    # Use the user's API token
    api_token = current_user.api_token.token
    headers = {'Authorization': f'Bearer {api_token}'}
    
    payload = {
        'command_text': command_text,
        'created_by': current_user.id,
        'reason': reason,
        'run_as_admin': run_as_admin
    }

    api_url = f"http://localhost:5000/api/servers/{server_id}/run_command"
    try:
        resp = requests.post(api_url, headers=headers, json=payload)
        if resp.status_code == 401:
            return jsonify({'error': 'Unauthorized - Please check your API token'}), 401
        elif resp.status_code == 403:
            return jsonify({'error': 'Forbidden - You do not have permission to execute commands'}), 403
        elif resp.status_code == 404:
            return jsonify({'error': 'Server not found'}), 404
        return jsonify(resp.json()), resp.status_code
    except requests.exceptions.RequestException as e:
        return jsonify({'error': f'Failed to communicate with server: {str(e)}'}), 500
    except Exception as e:
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500 