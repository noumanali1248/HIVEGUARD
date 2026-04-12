import sqlite3
import json
import hashlib
import os
from datetime import datetime

DB_PATH = os.path.join(os.environ['PROGRAMDATA'], 'PersistenceMonitor', 'baseline.db')

class BaselineDB:
    def __init__(self):
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        self.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        self._init_tables()

    def _init_tables(self):
        cursor = self.conn.cursor()
        # Registry baseline
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS registry_baseline (
                key_path TEXT,
                value_name TEXT,
                value_hash TEXT,
                first_seen TEXT,
                last_seen TEXT,
                is_allowlisted INTEGER DEFAULT 0,
                PRIMARY KEY (key_path, value_name)
            )
        ''')
        # File baseline (startup folders)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS file_baseline (
                folder_path TEXT,
                file_name TEXT,
                file_hash TEXT,
                file_size INTEGER,
                last_modified TEXT,
                PRIMARY KEY (folder_path, file_name)
            )
        ''')
        # Change log (structured)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS change_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                change_type TEXT,
                location TEXT,
                value_name TEXT,
                old_hash TEXT,
                new_hash TEXT,
                suspicious_score INTEGER,
                details TEXT
            )
        ''')
        self.conn.commit()

    @staticmethod
    def _hash_data(data):
        return hashlib.sha256(data.encode('utf-8', errors='ignore')).hexdigest()

    # Registry methods
    def get_registry_value_hash(self, key_path, value_name):
        cursor = self.conn.cursor()
        cursor.execute('SELECT value_hash FROM registry_baseline WHERE key_path=? AND value_name=?', (key_path, value_name))
        row = cursor.fetchone()
        return row[0] if row else None

    def set_registry_baseline(self, key_path, value_name, value_data):
        value_hash = self._hash_data(str(value_data))
        now = datetime.utcnow().isoformat()
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO registry_baseline (key_path, value_name, value_hash, first_seen, last_seen)
            VALUES (?, ?, ?, COALESCE((SELECT first_seen FROM registry_baseline WHERE key_path=? AND value_name=?), ?), ?)
        ''', (key_path, value_name, value_hash, key_path, value_name, now, now))
        self.conn.commit()
        return value_hash

    def delete_registry_baseline(self, key_path, value_name):
        cursor = self.conn.cursor()
        cursor.execute('DELETE FROM registry_baseline WHERE key_path=? AND value_name=?', (key_path, value_name))
        self.conn.commit()

    # File methods (similar)
    def get_file_hash(self, folder_path, file_name):
        cursor = self.conn.cursor()
        cursor.execute('SELECT file_hash FROM file_baseline WHERE folder_path=? AND file_name=?', (folder_path, file_name))
        row = cursor.fetchone()
        return row[0] if row else None

    def set_file_baseline(self, folder_path, file_name, file_hash, file_size, last_modified):
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO file_baseline (folder_path, file_name, file_hash, file_size, last_modified)
            VALUES (?, ?, ?, ?, ?)
        ''', (folder_path, file_name, file_hash, file_size, last_modified))
        self.conn.commit()

    def delete_file_baseline(self, folder_path, file_name):
        cursor = self.conn.cursor()
        cursor.execute('DELETE FROM file_baseline WHERE folder_path=? AND file_name=?', (folder_path, file_name))
        self.conn.commit()

    def log_change(self, change_type, location, value_name, old_hash, new_hash, suspicious_score, details):
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO change_log (timestamp, change_type, location, value_name, old_hash, new_hash, suspicious_score, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (datetime.utcnow().isoformat(), change_type, location, value_name, old_hash, new_hash, suspicious_score, details))
        self.conn.commit()

    def close(self):
        self.conn.close()