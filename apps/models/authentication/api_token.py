from apps.extensions import db
import datetime as dt

class ApiToken(db.Model):
    __tablename__ = 'api_tokens'

    id = db.Column(db.Integer, primary_key=True)
    server_id = db.Column(db.Integer, db.ForeignKey('servers.id'), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    token = db.Column(db.String(100), nullable=False, unique=True)
    name = db.Column(db.String(100))
    expires_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

    def __repr__(self):
        if self.server_id:
            return f'<ApiToken Server:{self.server_id}>'
        return f'<ApiToken User:{self.user_id}>' 