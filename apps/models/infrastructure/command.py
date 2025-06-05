from apps.extensions import db
import datetime as dt

class Command(db.Model):
    __tablename__ = 'commands'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    command_text = db.Column(db.Text, nullable=False)
    timeout_seconds = db.Column(db.Integer, default=300)  # Default: 5 minutes
    run_as_admin = db.Column(db.Boolean, default=False)
    run_in_sandbox = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow)

    def __repr__(self):
        return f'<Command {self.name}>' 