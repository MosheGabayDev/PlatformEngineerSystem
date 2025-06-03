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
from apps.models import AuditLog
from apps.authentication.permissions_util import require_permission

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
    return render_template('users/index.html', users=users, all_permissions=all_permissions, is_admin=is_admin)

@users_bp.route('/add', methods=['POST'])
@require_permission('users:add')
def add_user():
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    permissions = request.form.getlist('permissions')
    # print("PERMISSIONS:", permissions)
    if Users.query.filter((Users.username==username)|(Users.email==email)).first():
        flash('Username or email already exists', 'danger')
        return redirect(url_for('users.users_index'))
    user = Users(username=username, email=email, password=password, permissions=json.dumps(permissions))
    db.session.add(user)
    db.session.commit()
    log_action(current_user, 'add_user', f'Added user {username}')
    flash('User added!', 'success')
    return redirect(url_for('users.users_index'))

@users_bp.route('/edit/<int:user_id>', methods=['POST'])
@require_permission('users:edit')
def edit_user(user_id):
    user = Users.query.get_or_404(user_id)
    old_username = user.username
    user.username = request.form['username']
    user.email = request.form['email']
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
    log_action(current_user, 'edit_user', f'Edited user {old_username}')
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