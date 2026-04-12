import logging
import json
import os
from logging.handlers import RotatingFileHandler

LOG_FILE = os.path.join(os.environ['PROGRAMDATA'], 'PersistenceMonitor', 'persistence.log')

class StructuredLogger:
    def __init__(self, max_bytes=10*1024*1024, backup_count=10):
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        self.logger = logging.getLogger('PersistenceMonitor')
        self.logger.setLevel(logging.INFO)
        handler = RotatingFileHandler(LOG_FILE, maxBytes=max_bytes, backupCount=backup_count)
        formatter = logging.Formatter('%(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def _log(self, level, msg_dict):
        msg_dict['timestamp'] = self._iso_timestamp()
        self.logger.log(level, json.dumps(msg_dict))

    def _iso_timestamp(self):
        from datetime import datetime
        return datetime.utcnow().isoformat()

    def info(self, **kwargs):
        self._log(logging.INFO, kwargs)

    def warning(self, **kwargs):
        self._log(logging.WARNING, kwargs)

    def error(self, **kwargs):
        self._log(logging.ERROR, kwargs)