import os
import yaml
from typing import Dict, Any
from pathlib import Path

class Config:
    def __init__(self, config_dir: str = 'config'):
        self.config_dir = config_dir
        self.config_data: Dict[str, Any] = {}
        self.load_config()
        
    def load_config(self):
        """
        Load all configuration files from the config directory
        """
        config_path = Path(self.config_dir)
        if not config_path.exists():
            os.makedirs(config_path)
            
        # Load default config
        default_config = {
            'app': {
                'name': 'Task Management System',
                'debug': False,
                'secret_key': os.urandom(24).hex()
            },
            'database': {
                'url': 'sqlite:///app.db'
            },
            'celery': {
                'broker_url': 'redis://localhost:6379/0',
                'result_backend': 'redis://localhost:6379/0'
            },
            'logging': {
                'level': 'INFO',
                'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                'directory': 'logs'
            },
            'security': {
                'session_timeout': 3600,  # 1 hour
                'max_login_attempts': 5,
                'password_min_length': 8
            },
            'tasks': {
                'max_retries': 3,
                'retry_delay': 300,  # 5 minutes
                'timeout': 3600  # 1 hour
            }
        }
        
        # Load environment-specific config
        env = os.getenv('FLASK_ENV', 'development')
        env_config_file = config_path / f'{env}.yml'
        
        if env_config_file.exists():
            with open(env_config_file) as f:
                env_config = yaml.safe_load(f)
                self._merge_config(default_config, env_config)
        
        # Load local config if exists
        local_config_file = config_path / 'local.yml'
        if local_config_file.exists():
            with open(local_config_file) as f:
                local_config = yaml.safe_load(f)
                self._merge_config(default_config, local_config)
                
        self.config_data = default_config
        
    def _merge_config(self, base: Dict[str, Any], override: Dict[str, Any]):
        """
        Recursively merge two configuration dictionaries
        """
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_config(base[key], value)
            else:
                base[key] = value
                
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value
        """
        keys = key.split('.')
        value = self.config_data
        
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default
                
            if value is None:
                return default
                
        return value
        
    def set(self, key: str, value: Any):
        """
        Set a configuration value
        """
        keys = key.split('.')
        config = self.config_data
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
            
        config[keys[-1]] = value
        
    def save(self, env: str = None):
        """
        Save configuration to a file
        """
        if env is None:
            env = os.getenv('FLASK_ENV', 'development')
            
        config_file = Path(self.config_dir) / f'{env}.yml'
        
        with open(config_file, 'w') as f:
            yaml.dump(self.config_data, f, default_flow_style=False)
            
    def reload(self):
        """
        Reload configuration from files
        """
        self.load_config()

# Create global config instance
config = Config() 