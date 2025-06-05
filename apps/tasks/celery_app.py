from celery import Celery
import os

def make_celery():
    celery = Celery(
        'tasks',
        broker=os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0'),
        backend=os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0')
    )
    celery.conf.update(
        task_serializer='json',
        result_serializer='json',
        accept_content=['json'],
        timezone='UTC',
        enable_utc=True,
        task_track_started=True,
        task_time_limit=30*60,
        task_soft_time_limit=25*60,
        worker_prefetch_multiplier=1,
        worker_max_tasks_per_child=1000,
        worker_concurrency=4,
    )
    return celery

celery_app = make_celery() 