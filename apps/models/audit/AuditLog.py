from apps.extensions import db

class AuditLog(db.Model):
    __tablename__ = 'AuditLog'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return f'<AuditLog {self.name}>' 