from datetime import datetime, timedelta

def log_action(user=None, action_type=None, details=None, api_token_id=None):
    from apps import db
    from apps.models.audit import AuditLog
    log = AuditLog(
        user_id=user.id if user else None,
        username=user.username if user else None,
        api_token_id=api_token_id,
        action_type=action_type,
        action_details=details,
    )
    db.session.add(log)
    db.session.commit()

def cleanup_audit_log():
    from apps import db
    from apps.models.audit import AuditLog
    cutoff = datetime.utcnow() - timedelta(days=90)
    AuditLog.query.filter(AuditLog.created_at < cutoff).delete()
    db.session.commit() 