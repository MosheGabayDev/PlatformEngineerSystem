import os
import sys
from pathlib import Path

# Add the project root directory to Python path
project_root = str(Path(__file__).parent.parent)
sys.path.append(project_root)

from apps.tasks.celery_app import celery_app

if __name__ == '__main__':
    celery_app.worker_main(['worker', '--loglevel=info']) 