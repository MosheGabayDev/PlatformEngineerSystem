from typing import Dict, Any, List
from datetime import datetime, timedelta
from apps.extensions import db
from apps.models.tasks import Task, TaskStatus, ScheduledTask
from apps.models.alerts import Alert, AlertType, AlertSeverity
from celery.app.control import Control
from apps.tasks.celery_app import celery_app
import json

class TaskMonitor:
    @staticmethod
    def get_task_stats() -> Dict[str, Any]:
        """
        Get overall task statistics
        """
        total_tasks = Task.query.count()
        completed_tasks = Task.query.filter_by(status=TaskStatus.COMPLETED).count()
        failed_tasks = Task.query.filter_by(status=TaskStatus.FAILED).count()
        running_tasks = Task.query.filter_by(status=TaskStatus.RUNNING).count()
        pending_tasks = Task.query.filter_by(status=TaskStatus.PENDING).count()
        cancelled_tasks = Task.query.filter_by(status=TaskStatus.CANCELLED).count()
        
        # Calculate success rate
        success_rate = (completed_tasks / total_tasks * 100) if total_tasks > 0 else 0
        
        # Get recent tasks with more details
        recent_tasks = Task.query.order_by(Task.created_at.desc()).limit(10).all()
        
        # Get task history for the last 24 hours
        last_24h = datetime.utcnow() - timedelta(hours=24)
        tasks_24h = Task.query.filter(Task.created_at >= last_24h).all()
        
        # Calculate hourly statistics
        hourly_stats = {}
        for hour in range(24):
            hour_start = last_24h + timedelta(hours=hour)
            hour_end = hour_start + timedelta(hours=1)
            hour_tasks = [t for t in tasks_24h if hour_start <= t.created_at < hour_end]
            
            hourly_stats[hour] = {
                'total': len(hour_tasks),
                'completed': len([t for t in hour_tasks if t.status == TaskStatus.COMPLETED]),
                'failed': len([t for t in hour_tasks if t.status == TaskStatus.FAILED]),
                'running': len([t for t in hour_tasks if t.status == TaskStatus.RUNNING]),
                'cancelled': len([t for t in hour_tasks if t.status == TaskStatus.CANCELLED])
            }
        
        return {
            'total_tasks': total_tasks,
            'completed_tasks': completed_tasks,
            'failed_tasks': failed_tasks,
            'running_tasks': running_tasks,
            'pending_tasks': pending_tasks,
            'cancelled_tasks': cancelled_tasks,
            'success_rate': round(success_rate, 2),
            'recent_tasks': [task.to_dict() for task in recent_tasks],
            'hourly_stats': hourly_stats
        }
        
    @staticmethod
    def get_task_history(days: int = 7) -> Dict[str, Any]:
        """
        Get task history for the last N days
        """
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        tasks = Task.query.filter(
            Task.created_at >= start_date,
            Task.created_at <= end_date
        ).all()
        
        # Group tasks by date
        history = {}
        for task in tasks:
            date = task.created_at.date().isoformat()
            if date not in history:
                history[date] = {
                    'total': 0,
                    'completed': 0,
                    'failed': 0,
                    'running': 0,
                    'cancelled': 0,
                    'success_rate': 0
                }
            
            history[date]['total'] += 1
            if task.status == TaskStatus.COMPLETED:
                history[date]['completed'] += 1
            elif task.status == TaskStatus.FAILED:
                history[date]['failed'] += 1
            elif task.status == TaskStatus.RUNNING:
                history[date]['running'] += 1
            elif task.status == TaskStatus.CANCELLED:
                history[date]['cancelled'] += 1
            
            # Calculate success rate for the day
            if history[date]['total'] > 0:
                history[date]['success_rate'] = round(
                    (history[date]['completed'] / history[date]['total']) * 100, 2
                )
        
        return history
        
    @staticmethod
    def get_celery_stats() -> Dict[str, Any]:
        """
        Get Celery worker statistics
        """
        control = Control(celery_app)
        
        return {
            'active': control.inspect().active() or {},
            'reserved': control.inspect().reserved() or {},
            'registered': control.inspect().registered() or {},
            'stats': control.inspect().stats() or {}
        }
    
    @staticmethod
    def check_task_health():
        """
        Check task health and create alerts if needed
        """
        # Check for stuck tasks (running for too long)
        stuck_threshold = datetime.utcnow() - timedelta(hours=1)
        stuck_tasks = Task.query.filter(
            Task.status == TaskStatus.RUNNING,
            Task.updated_at < stuck_threshold
        ).all()
        
        for task in stuck_tasks:
            TaskMonitor.create_alert(
                AlertType.TASK_STUCK,
                AlertSeverity.WARNING,
                f"Task {task.name} is stuck",
                f"Task {task.name} (ID: {task.id}) has been running for more than 1 hour",
                task_id=task.id
            )
        
        # Check for failed tasks
        failed_tasks = Task.query.filter(
            Task.status == TaskStatus.FAILED,
            Task.updated_at >= datetime.utcnow() - timedelta(hours=1)
        ).all()
        
        for task in failed_tasks:
            TaskMonitor.create_alert(
                AlertType.TASK_FAILED,
                AlertSeverity.ERROR,
                f"Task {task.name} failed",
                f"Task {task.name} (ID: {task.id}) failed with error: {task.error}",
                task_id=task.id
            )
        
        # Check for missed scheduled tasks
        missed_threshold = datetime.utcnow() - timedelta(minutes=5)
        missed_tasks = ScheduledTask.query.filter(
            ScheduledTask.is_active == True,
            ScheduledTask.next_run < missed_threshold
        ).all()
        
        for task in missed_tasks:
            TaskMonitor.create_alert(
                AlertType.SCHEDULED_TASK_MISSED,
                AlertSeverity.WARNING,
                f"Scheduled task {task.name} was missed",
                f"Scheduled task {task.name} (ID: {task.id}) was supposed to run at {task.next_run}",
                scheduled_task_id=task.id
            )
    
    @staticmethod
    def create_alert(type, severity, title, message, task_id=None, scheduled_task_id=None):
        """
        Create a new alert
        """
        alert = Alert(
            type=type,
            severity=severity,
            title=title,
            message=message,
            task_id=task_id,
            scheduled_task_id=scheduled_task_id
        )
        
        try:
            db.session.add(alert)
            db.session.commit()
            
            # TODO: Send notification (email, Slack, etc.)
            
            return alert
        except Exception as e:
            db.session.rollback()
            print(f"Error creating alert: {str(e)}")
            return None
    
    @staticmethod
    def get_active_alerts():
        """
        Get all active (unresolved) alerts
        """
        return Alert.query.filter_by(is_resolved=False).order_by(Alert.created_at.desc()).all()
    
    @staticmethod
    def get_alert_stats():
        """
        Get alert statistics
        """
        total_alerts = Alert.query.count()
        active_alerts = Alert.query.filter_by(is_resolved=False).count()
        
        severity_counts = {
            severity.value: Alert.query.filter_by(severity=severity, is_resolved=False).count()
            for severity in AlertSeverity
        }
        
        type_counts = {
            type.value: Alert.query.filter_by(type=type, is_resolved=False).count()
            for type in AlertType
        }
        
        return {
            'total_alerts': total_alerts,
            'active_alerts': active_alerts,
            'severity_counts': severity_counts,
            'type_counts': type_counts
        } 