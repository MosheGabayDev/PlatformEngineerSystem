from flask import request, jsonify
from datetime import datetime
import traceback

@app.route('/api/commands', methods=['GET'])
def get_client_commands():
    try:
        # Get client ID from request headers
        client_id = request.headers.get('X-Client-ID')
        if not client_id:
            app.logger.error("No client ID provided in request headers")
            return jsonify({'error': 'Client ID is required'}), 400

        app.logger.info(f"Fetching commands for client ID: {client_id}")
        
        # Get current time
        current_time = datetime.utcnow()
        app.logger.info(f"Current time: {current_time}")

        # Query commands for this client
        commands = CommandHistory.query.filter(
            CommandHistory.server_id == client_id,
            CommandHistory.scheduled_time <= current_time,
            CommandHistory.run_status == 'pending'
        ).all()
        
        app.logger.info(f"Found {len(commands)} pending commands for client {client_id}")
        
        # Log details of each command found
        for cmd in commands:
            app.logger.info(f"Command details - ID: {cmd.id}, Type: {cmd.command_type}, "
                          f"Scheduled: {cmd.scheduled_time}, Status: {cmd.run_status}")

        # Convert commands to JSON
        commands_json = []
        for cmd in commands:
            command_data = {
                'id': cmd.id,
                'command_type': cmd.command_type,
                'command_data': cmd.command_data,
                'scheduled_time': cmd.scheduled_time.isoformat() if cmd.scheduled_time else None,
                'run_status': cmd.run_status
            }
            commands_json.append(command_data)
            app.logger.info(f"Added command to response - ID: {cmd.id}")

        app.logger.info(f"Returning {len(commands_json)} commands to client {client_id}")
        return jsonify(commands_json)

    except Exception as e:
        app.logger.error(f"Error in get_client_commands: {str(e)}")
        app.logger.error(f"Error type: {type(e)}")
        app.logger.error(f"Error details: {traceback.format_exc()}")
        return jsonify({'error': str(e)}), 500 