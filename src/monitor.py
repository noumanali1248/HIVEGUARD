import json
import os
import sys
from .registry_watcher import RegistryWatcher
from .file_watcher import FileWatcher
from .baseline_db import BaselineDB
from .analyser import SuspicionAnalyser
from .logger import StructuredLogger
from .alert import AlertDispatcher

class PersistenceMonitor:
    def __init__(self, config_path):
        with open(config_path, 'r') as f:
            self.config = json.load(f)
        self.db = BaselineDB()
        self.logger = StructuredLogger(
            max_bytes=self.config.get('log_rotation_mb', 10)*1024*1024,
            backup_count=self.config.get('log_backup_count', 10)
        )
        self.analyser = SuspicionAnalyser(self.config)
        self.alert = AlertDispatcher(self.config)
        self.registry_watcher = RegistryWatcher(
            self.config['monitored_registry_keys'],
            self.db, self.analyser, self.logger, self.alert,
            interval=self.config.get('monitoring_interval_seconds', 5)
        )
        self.file_watcher = FileWatcher(
            self.config['startup_folders'],
            self.db, self.analyser, self.logger, self.alert
        )

    def start(self):
        self.logger.info(event="monitor_starting")
        self.registry_watcher.start()
        self.file_watcher.start()
        # Keep alive
        try:
            while True:
                import time
                time.sleep(60)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        self.logger.info(event="monitor_stopping")
        self.registry_watcher.stop()
        self.file_watcher.stop()
        self.db.close()