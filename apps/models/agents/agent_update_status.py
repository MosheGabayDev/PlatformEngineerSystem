from apps.extensions import db
import datetime as dt

class AgentUpdateStatus(db.Model):
    __tablename__ = 'agent_update_statuses'

    id = db.Column(db.Integer, primary_key=True)
    server_id = db.Column(db.Integer, db.ForeignKey('servers.id'), nullable=False)
    current_version = db.Column(db.String(50))
    target_version = db.Column(db.String(50))
    status = db.Column(db.String(20), nullable=False)
    error = db.Column(db.Text)
    started_at = db.Column(db.DateTime, default=dt.datetime.utcnow)
    finished_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow)

    def __repr__(self):
        return f'<AgentUpdateStatus Server:{self.server_id}>' 