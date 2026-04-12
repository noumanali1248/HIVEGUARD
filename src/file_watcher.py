import os
import time
import hashlib
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from .baseline_db import BaselineDB
from .analyser import SuspicionAnalyser
from .logger import StructuredLogger
from .alert import AlertDispatcher

class StartupFolderHandler(FileSystemEventHandler):
    def __init__(self, folder_path, db, analyser, logger, alert):
        self.folder_path = folder_path
        self.db = db
        self.analyser = analyser
        self.logger = logger
        self.alert = alert

    def on_created(self, event):
        if not event.is_directory:
            self._handle_file(event.src_path, 'new')

    def on_deleted(self, event):
        if not event.is_directory:
            self._handle_deletion(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._handle_file(event.src_path, 'modified')

    def _handle_file(self, file_path, change_type):
        file_name = os.path.basename(file_path)
        try:
            file_hash = self._hash_file(file_path)
            file_size = os.path.getsize(file_path)
            last_mod = time.ctime(os.path.getmtime(file_path))
            stored_hash = self.db.get_file_hash(self.folder_path, file_name)

            if change_type == 'new' and stored_hash is None:
                suspicion = self.analyser.calculate_suspicion(self.folder_path, file_name, file_path)
                self._log_and_alert(change_type, file_name, file_path, suspicion, None, file_hash)
                self.db.set_file_baseline(self.folder_path, file_name, file_hash, file_size, last_mod)
            elif change_type == 'modified' and stored_hash != file_hash:
                suspicion = self.analyser.calculate_suspicion(self.folder_path, file_name, file_path)
                self._log_and_alert(change_type, file_name, file_path, suspicion, stored_hash, file_hash)
                self.db.set_file_baseline(self.folder_path, file_name, file_hash, file_size, last_mod)
        except Exception as e:
            self.logger.error(event="file_watch_error", file=file_path, error=str(e))

    def _handle_deletion(self, file_path):
        file_name = os.path.basename(file_path)
        self.db.delete_file_baseline(self.folder_path, file_name)
        self.logger.info(event="file_deleted", folder=self.folder_path, file=file_name)
        self.alert.send(f"File deleted from startup folder: {file_path}", 'WARNING')

    def _hash_file(self, path):
        sha256 = hashlib.sha256()
        with open(path, 'rb') as f:
            for block in iter(lambda: f.read(65536), b''):
                sha256.update(block)
        return sha256.hexdigest()

    def _log_and_alert(self, change_type, file_name, file_path, suspicion, old_hash, new_hash):
        self.db.log_change(change_type, self.folder_path, file_name, old_hash, new_hash, suspicion, file_path)
        log_msg = {
            'event': 'startup_file_change',
            'type': change_type,
            'folder': self.folder_path,
            'file': file_name,
            'path': file_path,
            'suspicion_score': suspicion
        }
        if suspicion >= self.analyser.config.get('scoring', {}).get('critical_threshold', 80):
            self.logger.error(**log_msg)
            self.alert.send(f"CRITICAL: New/modified file in startup folder: {file_path}", 'ERROR')
        elif suspicion >= self.analyser.config.get('scoring', {}).get('warning_threshold', 50):
            self.logger.warning(**log_msg)
            self.alert.send(f"WARNING: New/modified file in startup folder: {file_path}", 'WARNING')
        else:
            self.logger.info(**log_msg)

class FileWatcher:
    def __init__(self, folders, db, analyser, logger, alert):
        self.folders = [os.path.expandvars(f) for f in folders]
        self.db = db
        self.analyser = analyser
        self.logger = logger
        self.alert = alert
        self.observer = None

    def start(self):
        self._enumerate_existing_files()
        self.observer = Observer()
        for folder in self.folders:
            if os.path.exists(folder):
                handler = StartupFolderHandler(folder, self.db, self.analyser, self.logger, self.alert)
                self.observer.schedule(handler, folder, recursive=False)
        self.observer.start()

    def _enumerate_existing_files(self):
        for folder in self.folders:
            if not os.path.exists(folder):
                continue
            for filename in os.listdir(folder):
                file_path = os.path.join(folder, filename)
                if os.path.isfile(file_path):
                    try:
                        file_hash = self._hash_file(file_path)
                        file_size = os.path.getsize(file_path)
                        last_mod = time.ctime(os.path.getmtime(file_path))
                        self.db.set_file_baseline(folder, filename, file_hash, file_size, last_mod)
                    except Exception as e:
                        self.logger.error(event="baseline_file_enum_error", folder=folder, file=filename, error=str(e))

    def _hash_file(self, path):
        sha256 = hashlib.sha256()
        with open(path, 'rb') as f:
            for block in iter(lambda: f.read(65536), b''):
                sha256.update(block)
        return sha256.hexdigest()

    def stop(self):
        if self.observer:
            self.observer.stop()
            self.observer.join()