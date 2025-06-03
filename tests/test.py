from apps import create_app
from apps.db import db
app = create_app()
with app.app_context():
    db.create_all()