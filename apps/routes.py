from flask import Blueprint, request, flash, redirect, url_for, render_template, json
from flask_login import login_required, current_user
from apps.db import db
from apps.models.tasks import Task, TaskCommand
from apps.models.infrastructure import Command
import traceback

blueprint = Blueprint('routes', __name__)

@blueprint.route('/tasks/create', methods=['GET', 'POST'])
@login_required
def create_task():
    """Create a new task"""
    print("\n=== Starting task creation/update process ===")
    print(f"User authenticated: {current_user.is_authenticated}")
    print(f"User ID: {current_user.id}")
    print(f"Request method: {request.method}")
    
    if request.method == 'POST':
        try:
            print("\n=== Processing POST request ===")
            data = request.form
            print("Received form data:", dict(data))
            
            # Get command IDs and regex patterns
            command_ids = request.form.getlist('command_ids[]')
            regex_patterns = request.form.getlist('regex_patterns[]')
            print(f"Command IDs: {command_ids}")
            print(f"Regex patterns: {regex_patterns}")
            
            # Create commands data array
            commands_data = []
            for i, (cmd_id, regex) in enumerate(zip(command_ids, regex_patterns)):
                if cmd_id:  # Only add if command is selected
                    cmd_data = {
                        'command_id': cmd_id,
                        'output_regex': regex,
                        'order': i
                    }
                    commands_data.append(cmd_data)
                    print(f"Added command data: {cmd_data}")
            
            print(f"Total commands to process: {len(commands_data)}")
            
            # Validation: must have at least one command
            if not commands_data:
                print("Validation failed: No commands provided")
                flash('You must add at least one command to the task.', 'error')
                return redirect(request.url)
            
            # Check if we're editing an existing task
            task_id = data.get('task_id')
            if task_id:
                print(f"Editing existing task ID: {task_id}")
                task = Task.query.get_or_404(task_id)
                print(f"Found existing task: {task.name}")
                print(f"Task created by: {task.created_by}")
                print(f"Current user: {current_user.id}")
                
                # Verify user has permission to edit
                if task.created_by != current_user.id and not current_user.has_permission('tasks:write'):
                    print("Permission denied: User is not the task creator and doesn't have tasks:write permission")
                    flash('You do not have permission to edit this task.', 'error')
                    return redirect(url_for('table_blueprint.model_dt', aPath='tasks'))
                
                task.name = data.get('name')
                task.reason = data.get('reason')
                task.updated_by = current_user.id
                task.tasks_json = json.dumps(commands_data)
                print(f"Updated task details: name={task.name}, reason={task.reason}")
                # Remove existing commands
                TaskCommand.query.filter_by(task_id=task.id).delete()
                print("Removed existing commands")
            else:
                print("Creating new task")
                # Create new task
                task = Task(
                    name=data.get('name'),
                    reason=data.get('reason'),
                    created_by=current_user.id,
                    tasks_json=json.dumps(commands_data)
                )
                db.session.add(task)
                print(f"Added new task: name={task.name}, reason={task.reason}")
            
            db.session.flush()  # Get task ID
            print(f"Task ID: {task.id}")
            
            # Add commands to task with order
            for cmd_data in commands_data:
                task_command = TaskCommand(
                    task_id=task.id,
                    command_id=cmd_data['command_id'],
                    output_regex=cmd_data['output_regex'],
                    order=cmd_data['order']
                )
                db.session.add(task_command)
                print(f"Added task command: {cmd_data}")
            
            print("Committing changes to database...")
            db.session.commit()
            print("Successfully committed changes")
            
            flash('Task {} successfully!'.format('updated' if task_id else 'created'), 'success')
            print("=== Task process completed successfully ===\n")
            return redirect(url_for('table_blueprint.model_dt', aPath='tasks'))
            
        except Exception as e:
            print("\n=== Error occurred during task process ===")
            print(f"Error type: {type(e).__name__}")
            print(f"Error message: {str(e)}")
            print("Error details:", traceback.format_exc())
            db.session.rollback()
            print("Rolled back database changes")
            flash(f'Error {"updating" if data.get("task_id") else "creating"} task: {str(e)}', 'error')
            print("=== Error handling completed ===\n")
            return redirect(url_for('routes.create_task'))
    
    # GET request - show form
    print("\n=== Loading task form ===")
    task_id = request.args.get('task_id')
    task = None
    if task_id:
        print(f"Loading existing task ID: {task_id}")
        task = Task.query.get_or_404(task_id)
        print(f"Found task: {task.name}")
        print(f"Task created by: {task.created_by}")
        print(f"Current user: {current_user.id}")
        
        # Verify user has permission to edit
        if task.created_by != current_user.id and not current_user.has_permission('tasks:write'):
            print("Permission denied: User is not the task creator and doesn't have tasks:write permission")
            flash('You do not have permission to edit this task.', 'error')
            return redirect(url_for('table_blueprint.model_dt', aPath='tasks'))
            
        # Ensure commands are ordered correctly
        task.commands.sort(key=lambda x: x.order)
        print(f"Loaded task: {task.name} with {len(task.commands)} commands")
    
    commands = Command.query.all()
    print(f"Loaded {len(commands)} available commands")
    print("=== Form loading completed ===\n")
    return render_template('tasks/create.html', commands=commands, task=task) 