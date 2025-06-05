import logging
import os
from datetime import datetime
from logging.handlers import RotatingFileHandler
import json

class TaskLogger:
    def __init__(self, name, log_dir='logs'):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)
        
        # Create logs directory if it doesn't exist
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
            
        # File handler for all logs
        all_log_file = os.path.join(log_dir, 'all.log')
        all_handler = RotatingFileHandler(
            all_log_file,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        all_handler.setLevel(logging.INFO)
        
        # File handler for error logs
        error_log_file = os.path.join(log_dir, 'error.log')
        error_handler = RotatingFileHandler(
            error_log_file,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        error_handler.setLevel(logging.ERROR)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # Create formatters and add them to the handlers
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        all_handler.setFormatter(formatter)
        error_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        # Add the handlers to the logger
        self.logger.addHandler(all_handler)
        self.logger.addHandler(error_handler)
        self.logger.addHandler(console_handler)
        
    def log_task_event(self, task_id, event_type, details=None):
        """
        Log a task-related event
        """
        log_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'task_id': task_id,
            'event_type': event_type,
            'details': details
        }
        self.logger.info(json.dumps(log_data))
        
    def log_error(self, task_id, error, details=None):
        """
        Log a task-related error
        """
        log_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'task_id': task_id,
            'error': str(error),
            'details': details
        }
        self.logger.error(json.dumps(log_data))
        
    def log_system_event(self, event_type, details=None):
        """
        Log a system-level event
        """
        log_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': event_type,
            'details': details
        }
        self.logger.info(json.dumps(log_data))
        
    def log_security_event(self, event_type, user_id=None, details=None):
        """
        Log a security-related event
        """
        log_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': event_type,
            'user_id': user_id,
            'details': details
        }
        self.logger.warning(json.dumps(log_data))

# Create logger instances
task_logger = logging.getLogger('task')
system_logger = logging.getLogger('system')
security_logger = TaskLogger('security') 