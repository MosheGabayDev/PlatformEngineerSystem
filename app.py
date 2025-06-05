from flask import request, jsonify
from flask_login import login_required, current_user
from datetime import datetime
from app import db
from app.models import CommandHistory

@app.route('/api/command_history/<int:history_id>/result', methods=['POST'])
@login_required
def command_history_result(history_id):
    """Submit command execution result"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
            
        # Get the command history entry
        history = CommandHistory.query.get_or_404(history_id)
        
        # Verify the command belongs to this server
        if history.server_id != current_user.id:
            return jsonify({'error': 'Unauthorized'}), 403
            
        # Update the history entry
        history.output = data.get('output', '')
        history.error = data.get('error', '')
        history.executed_time = datetime.strptime(data.get('executed_time'), '%Y-%m-%d %H:%M:%S')
        history.duration_seconds = data.get('duration_seconds', 0)
        history.status = 'completed'
        
        db.session.commit()
        
        return jsonify({'message': 'Result submitted successfully'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500 