from apps.extensions import db
import datetime as dt

class ClientConfig(db.Model):
    __tablename__ = 'client_configs'

    id = db.Column(db.Integer, primary_key=True)
    server_id = db.Column(db.Integer, db.ForeignKey('servers.id'), nullable=False, unique=True)
    update_interval_seconds = db.Column(db.Integer, nullable=False, default=300)  # Default: 5 minutes
    client_poll_interval_seconds = db.Column(db.Integer, nullable=False, default=20)
    max_output_lines = db.Column(db.Integer, default=100)
    run_as_admin_default = db.Column(db.Boolean, default=True)
    run_in_sandbox_default = db.Column(db.Boolean, default=False)
    config_json = db.Column(db.Text, nullable=True)  # Additional JSON config if needed
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow)
    temporary_short_interval = db.Column(db.Boolean, default=False)  # Flag for temporary short interval
    temporary_interval_end_time = db.Column(db.DateTime, nullable=True)  # When the temporary interval should end

    def __repr__(self):
        return f'<ClientConfig Server:{self.server_id}>' 