from flask import Blueprint, render_template, request, redirect, url_for, flash, abort
from apps.authentication.models import Users
from apps import db
from flask_login import current_user
from functools import wraps
import json
from apps.authentication.routes_permissions import ALL_PERMISSIONS as all_permissions
from apps.authentication.util import hash_pass
from apps.utils import log_action
from datetime import datetime, timedelta
from apps.models.audit import AuditLog
from apps.models.agents import AgentUpdateStatus, Agent
from apps.models.authentication import ApiToken
from apps.authentication.permissions_util import require_permission
from sqlalchemy.orm import joinedload
import uuid

users_bp = Blueprint('users', __name__, url_prefix='/users')

@users_bp.route('/', methods=['GET'])
def users_index():
    q = request.args.get('q', '').strip()
    if q:
        users = Users.query.filter(
            (Users.username.ilike(f'%{q}%')) | (Users.email.ilike(f'%{q}%'))
        ).all()
    else:
        users = Users.query.all()
    for user in users:
        user.is_active = getattr(user, 'is_active', True)
    perms = json.loads(current_user.permissions) if getattr(current_user, 'permissions', None) else []
    is_admin = 'admin' in [str(p).strip().lower() for p in perms]
    agent_update_statuses = []
    if is_admin:
        agent_update_statuses = AgentUpdateStatus.query.order_by(AgentUpdateStatus.created_at.desc()).limit(50).all()
    return render_template('users/index.html', users=users, all_permissions=all_permissions, is_admin=is_admin, agent_update_statuses=agent_update_statuses)

@users_bp.route('/add', methods=['POST'])
@require_permission('users:add')
def add_user():
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    permissions = request.form.getlist('permissions')
    bio = request.form.get('bio', '')
    # print("PERMISSIONS:", permissions)
    if Users.query.filter((Users.username==username)|(Users.email==email)).first():
        flash('Username or email already exists', 'danger')
        return redirect(url_for('users.users_index'))
    user = Users(username=username, email=email, password=password, permissions=json.dumps(permissions), bio=bio)
    db.session.add(user)
    db.session.commit()
    log_action(current_user, 'add_user', f'Added user {username}')
    flash('User added!', 'success')
    return redirect(url_for('users.users_index'))

@users_bp.route('/edit/<int:user_id>', methods=['POST'])
@require_permission('users:edit')
def edit_user(user_id):
    user = Users.query.get_or_404(user_id)
    old_data = {
        'username': user.username,
        'email': user.email,
        'bio': user.bio,
        'oauth_github': user.oauth_github,
        'oauth_google': user.oauth_google,
        'permissions': user.permissions,
        'is_active': getattr(user, 'is_active', True)
    }
    old_username = user.username
    user.username = request.form['username']
    user.email = request.form['email']
    user.bio = request.form.get('bio', user.bio)
    # OAuth fields are not editable via form, so we keep them as is
    password = request.form.get('password', '').strip()
    # Only admin can change password and permissions
    try:
        user_perms = json.loads(current_user.permissions) if current_user.permissions else []
    except Exception:
        user_perms = []
    user_perms = [str(p).strip().lower() for p in user_perms]
    if password and 'admin' in user_perms:
        user.password = hash_pass(password)
    elif password:
        flash('Only admin can change passwords.', 'danger')
    if 'admin' in user_perms:
        permissions = request.form.getlist('permissions')
        user.permissions = json.dumps(permissions)
    db.session.commit()
    # Log what changed
    new_data = {
        'username': user.username,
        'email': user.email,
        'bio': user.bio,
        'oauth_github': user.oauth_github,
        'oauth_google': user.oauth_google,
        'permissions': user.permissions,
        'is_active': getattr(user, 'is_active', True)
    }
    changes = []
    for k in new_data:
        if old_data[k] != new_data[k]:
            changes.append(f"{k}: '{old_data[k]}' → '{new_data[k]}'")
    change_str = ", ".join(changes) if changes else "No changes"
    log_action(
        current_user,
        'edit_user',
        f"Edited user id={user.id}, username={old_username} by {current_user.username}. Changes: {change_str}"
    )
    flash('User updated!', 'success')
    return redirect(url_for('users.users_index'))

@users_bp.route('/delete/<int:user_id>', methods=['POST'])
@require_permission('users:delete')
def delete_user(user_id):
    user = Users.query.get_or_404(user_id)
    log_action(current_user, 'delete_user', f'Deleted user {user.username}')
    db.session.delete(user)
    db.session.commit()
    flash('User deleted!', 'success')
    return redirect(url_for('users.users_index'))

@users_bp.route('/freeze/<int:user_id>')
@require_permission('users:freeze')
def freeze_user(user_id):
    user = Users.query.get_or_404(user_id)
    user.is_active = False
    db.session.commit()
    log_action(current_user, 'freeze_user', f'Froze user {user.username}')
    flash('User frozen!', 'warning')
    return redirect(url_for('users.users_index'))

@users_bp.route('/unfreeze/<int:user_id>')
@require_permission('users:freeze')
def unfreeze_user(user_id):
    user = Users.query.get_or_404(user_id)
    user.is_active = True
    db.session.commit()
    log_action(current_user, 'unfreeze_user', f'Unfroze user {user.username}')
    flash('User unfrozen!', 'success')
    return redirect(url_for('users.users_index'))

@users_bp.route('/profile')
@require_permission('users:read')
def profile():
    user = Users.query.get(current_user.id)
    user.permissions_list = json.loads(user.permissions) if user.permissions else []
    cutoff = datetime.utcnow() - timedelta(days=30)
    history = AuditLog.query.filter_by(user_id=user.id).filter(AuditLog.created_at >= cutoff).order_by(AuditLog.created_at.desc()).all()
    return render_template('users/profile.html', user=user, history=history)

@users_bp.route('/agents', methods=['GET'])
@require_permission('admin')
def agents_version_management():
    status_filter = request.args.get('status', '').strip()
    os_filter = request.args.get('os', '').strip()
    q = request.args.get('q', '').strip()
    agents_query = Agent.query
    if status_filter:
        agents_query = agents_query.filter(Agent.status == status_filter)
    if os_filter:
        agents_query = agents_query.filter(Agent.os == os_filter)
    if q:
        agents_query = agents_query.filter((Agent.hostname.ilike(f'%{q}%')) | (Agent.client_id.ilike(f'%{q}%')))
    agents = agents_query.order_by(Agent.registered_at.desc()).all()
    # Get latest update status for each agent
    agent_status_map = {}
    for agent in agents:
        status = AgentUpdateStatus.query.filter_by(client_id=agent.client_id).order_by(AgentUpdateStatus.created_at.desc()).first()
        agent_status_map[agent.client_id] = status
    # For filter dropdowns
    all_statuses = [s[0] for s in Agent.__table__.columns['status'].type.enums] if hasattr(Agent.__table__.columns['status'].type, 'enums') else ['online','offline','updating','error','']
    all_oses = sorted(set(a.os for a in Agent.query.all()))
    return render_template('users/agents.html', agents=agents, agent_status_map=agent_status_map, all_statuses=all_statuses, all_oses=all_oses, status_filter=status_filter, os_filter=os_filter, q=q)

@users_bp.route('/agents/<client_id>/set_version', methods=['POST'])
@require_permission('admin')
def set_agent_version(client_id):
    agent = Agent.query.filter_by(client_id=client_id).first_or_404()
    desired_version = request.form.get('desired_version', '').strip()
    agent.desired_version = desired_version
    db.session.commit()
    flash(f'Desired version for agent {agent.hostname} set to {desired_version}', 'success')
    return redirect(url_for('users.agents_version_management'))

@users_bp.route('/agents/set_all_versions', methods=['POST'])
@require_permission('admin')
def set_all_agents_version():
    desired_version = request.form.get('desired_version', '').strip()
    Agent.query.update({Agent.desired_version: desired_version})
    db.session.commit()
    flash(f'Desired version for all agents set to {desired_version}', 'success')
    return redirect(url_for('users.agents_version_management'))

@users_bp.route('/agents/<client_id>/history', methods=['GET'])
@require_permission('admin')
def agent_update_history(client_id):
    agent = Agent.query.filter_by(client_id=client_id).first_or_404()
    history = AgentUpdateStatus.query.filter_by(client_id=client_id).order_by(AgentUpdateStatus.created_at.desc()).all()
    return render_template('users/agent_history.html', agent=agent, history=history)

@users_bp.route('/api_token', methods=['POST'])
@require_permission('admin')
def create_api_token():
    """Create a new API token for the current user"""
    # Check if user already has an active token
    if current_user.api_token and current_user.api_token.is_active:
        flash('You already have an active API token', 'warning')
        return redirect(url_for('users.users_index'))

    # Create new token
    token_value = uuid.uuid4().hex
    token = ApiToken(
        name=f"Token for {current_user.username}",
        token=token_value,
        user_id=current_user.id,
        permissions=current_user.permissions,
        expires_at=datetime.now() + timedelta(days=30)  # Token expires in 30 days
    )
    db.session.add(token)
    db.session.commit()

    flash('API token created successfully', 'success')
    return redirect(url_for('users.users_index')) 