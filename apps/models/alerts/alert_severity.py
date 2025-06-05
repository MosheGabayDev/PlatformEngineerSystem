from apps.extensions import db

class AlertSeverity(db.Model):
    __tablename__ = 'alert_severities'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)

    def __repr__(self):
        return f'<AlertSeverity {self.name}>' 