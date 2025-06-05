from apps import create_app, db
from apps.config import config_dict
from apps.models.infrastructure import CommandHistory
import datetime as dt

app = create_app(config_dict['Debug'])

with app.app_context():
    # Create a new command history record
    history = CommandHistory(
        server_id=8,  # Replace with your server ID
        command_name="dir",  # Simple command for testing
        run_type='online_cli',  # Using online_cli for immediate execution
        run_status='pending',  # Set initial status to pending
        created_by=1,
        reason="Testing immediate command execution",
        created_at=dt.datetime.now(dt.timezone.utc)
        # No command_id needed for online_cli commands
        # No scheduled_time - will execute immediately
    )
    db.session.add(history)
    db.session.commit()
    print(f"Created command history record with ID: {history.id}")

        # command_id=1,  # Replace with your command ID
        # command_name="Test Command",
        # scheduled_time=dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5),  # Schedule for 5 minutes from now
        # run_type='task',
        # reason="Testing scheduled command execution",