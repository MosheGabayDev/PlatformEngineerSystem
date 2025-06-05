from apps.extensions import db

class AlertType(db.Model):
    __tablename__ = 'alert_types'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)

    def __repr__(self):
        return f'<AlertType {self.name}>' 