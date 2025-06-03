#!/usr/bin/env python3
import os
import sys
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from apps import create_app, db
from apps.utils import cleanup_audit_log
from apps.config import Config

if __name__ == '__main__':
    app = create_app(Config)
    with app.app_context():
        print(f"[{datetime.now().isoformat()}] Cleaning up AuditLog entries older than 90 days...")
        cleanup_audit_log()
        print("Done.") 