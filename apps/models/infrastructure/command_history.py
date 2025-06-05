from apps.extensions import db
import datetime as dt

class CommandHistory(db.Model):
    __tablename__ = 'command_histories'

    id = db.Column(db.Integer, primary_key=True)
    command_id = db.Column(db.Integer, db.ForeignKey('commands.id'), nullable=False)
    server_id = db.Column(db.Integer, db.ForeignKey('servers.id'), nullable=False)
    status = db.Column(db.String(20), nullable=False)
    output = db.Column(db.Text)
    error = db.Column(db.Text)
    exit_code = db.Column(db.Integer)
    started_at = db.Column(db.DateTime, default=dt.datetime.utcnow)
    finished_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow)

    def __repr__(self):
        return f'<CommandHistory Command:{self.command_id} Server:{self.server_id}>' 