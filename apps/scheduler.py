from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apps.utils import cleanup_audit_log
from datetime import datetime

def run_cleanup_audit_log():
    print(f"[{datetime.now().isoformat()}] Running scheduled cleanup_audit_log()")
    cleanup_audit_log()

def start_scheduler(app):
    from apps.db import db
    from apps.models import ScheduledTask
    scheduler = BackgroundScheduler()
    def job_wrapper(func):
        def wrapped():
            with app.app_context():
                func()
        return wrapped
    # Always ensure the cleanup job exists in the DB
    with app.app_context():
        cleanup_task = ScheduledTask.query.filter_by(job_id='cleanup_audit_log').first()
        if not cleanup_task:
            cleanup_task = ScheduledTask(
                name='Audit Log Cleanup',
                description='ניקוי לוג היסטוריה ישן (90 יום ומעלה)',
                job_id='cleanup_audit_log',
                cron='0 3 * * *',
                is_enabled=True
            )
            db.session.add(cleanup_task)
            db.session.commit()
        # Load all enabled scheduled tasks
        for task in ScheduledTask.query.filter_by(is_enabled=True).all():
            if task.job_id == 'cleanup_audit_log':
                trigger = CronTrigger.from_crontab(task.cron)
                scheduler.add_job(job_wrapper(run_cleanup_audit_log), trigger, id=task.job_id, replace_existing=True)
    scheduler.start()
    print("Scheduler started (all enabled jobs from DB)")
    return scheduler 