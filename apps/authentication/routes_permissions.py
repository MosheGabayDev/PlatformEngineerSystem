from flask import Blueprint, render_template, request, redirect, url_for, flash
from apps.authentication.models import Users
from apps import db
import json

permissions_bp = Blueprint('permissions', __name__, url_prefix='/permissions')

# List of all possible permissions
ALL_PERMISSIONS = [
    'servers:read', 'servers:write',
    'commands:read', 'commands:write',
    'tasks:read', 'tasks:write',
    'cli:read', 'cli:write',
    'users:read', 'users:write',
    'users:add', 'users:edit', 'users:delete', 'users:freeze',
    'history:read', 'history:write',
    'admin'
]

@permissions_bp.route('/', methods=['GET'])
def permissions_index():
    users = Users.query.all()
    for user in users:
        # print(user.permissions)
        user.permissions_list = json.loads(user.permissions) if user.permissions else []
    return render_template('permissions/index.html', users=users, all_permissions=ALL_PERMISSIONS)

@permissions_bp.route('/edit/<int:user_id>', methods=['GET', 'POST'])
def edit_permissions(user_id):
    user = Users.query.get_or_404(user_id)
    if request.method == 'POST':
        selected = request.form.getlist('permissions')
        user.permissions = json.dumps(selected)
        db.session.commit()
        flash('Permissions updated!', 'success')
        return redirect(url_for('permissions.permissions_index'))
    user_permissions = json.loads(user.permissions) if user.permissions else []
    return render_template('permissions/edit.html', user=user, all_permissions=ALL_PERMISSIONS, user_permissions=user_permissions) 