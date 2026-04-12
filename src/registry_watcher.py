import win32api
import win32con
import win32event
import threading
import time
from .baseline_db import BaselineDB
from .analyser import SuspicionAnalyser
from .logger import StructuredLogger
from .alert import AlertDispatcher

class RegistryWatcher:
    def __init__(self, monitored_keys, db, analyser, logger, alert, interval=5):
        self.monitored_keys = monitored_keys  # list of (hive, subkey)
        self.db = db
        self.analyser = analyser
        self.logger = logger
        self.alert = alert
        self.interval = interval
        self.running = True
        self._hive_map = {
            'HKEY_CURRENT_USER': win32con.HKEY_CURRENT_USER,
            'HKEY_LOCAL_MACHINE': win32con.HKEY_LOCAL_MACHINE,
            'HKEY_USERS': win32con.HKEY_USERS
        }

    def start(self):
        # Initial baseline enumeration
        self._enumerate_all()
        # Start a background thread that uses RegNotifyChangeKeyValue
        threading.Thread(target=self._monitor_loop, daemon=True).start()

    def _enumerate_all(self):
        for hive_str, subkey in self.monitored_keys:
            hive = self._hive_map.get(hive_str)
            if not hive:
                continue
            try:
                key = win32api.RegOpenKeyEx(hive, subkey, 0, win32con.KEY_READ)
                idx = 0
                while True:
                    try:
                        value_name, value_data, _ = win32api.RegEnumValue(key, idx)
                        value_str = str(value_data)
                        current_hash = self.db._hash_data(value_str)
                        stored_hash = self.db.get_registry_value_hash(f"{hive_str}\\{subkey}", value_name)
                        if stored_hash is None:
                            # New entry detected during baseline? Should not happen on first run.
                            self._handle_change('new', f"{hive_str}\\{subkey}", value_name, None, value_str)
                        elif stored_hash != current_hash:
                            self._handle_change('modified', f"{hive_str}\\{subkey}", value_name, stored_hash, value_str)
                        idx += 1
                    except OSError:
                        break
                win32api.RegCloseKey(key)
            except Exception as e:
                self.logger.error(event="enum_registry_failed", key=subkey, error=str(e))

    def _monitor_loop(self):
        # For each root key, create an event and wait
        while self.running:
            for hive_str, subkey in self.monitored_keys:
                hive = self._hive_map.get(hive_str)
                if not hive:
                    continue
                try:
                    key = win32api.RegOpenKeyEx(hive, subkey, 0, win32con.KEY_NOTIFY)
                    event = win32event.CreateEvent(None, 0, 0, None)
                    win32api.RegNotifyChangeKeyValue(key, True, win32con.REG_NOTIFY_CHANGE_LAST_SET | win32con.REG_NOTIFY_CHANGE_NAME, event, True)
                    # Wait for notification or interval
                    win32event.WaitForSingleObject(event, self.interval * 1000)
                    # Change occurred, re-enumerate this key
                    self._enumerate_single_key(hive_str, subkey)
                    win32api.RegCloseKey(key)
                except Exception as e:
                    self.logger.error(event="registry_watch_failed", key=subkey, error=str(e))
            time.sleep(1)

    def _enumerate_single_key(self, hive_str, subkey):
        hive = self._hive_map.get(hive_str)
        if not hive:
            return
        try:
            key = win32api.RegOpenKeyEx(hive, subkey, 0, win32con.KEY_READ)
            current_values = {}
            idx = 0
            while True:
                try:
                    value_name, value_data, _ = win32api.RegEnumValue(key, idx)
                    current_values[value_name] = str(value_data)
                    idx += 1
                except OSError:
                    break
            win32api.RegCloseKey(key)

            # Compare with baseline
            for value_name, value_str in current_values.items():
                current_hash = self.db._hash_data(value_str)
                stored_hash = self.db.get_registry_value_hash(f"{hive_str}\\{subkey}", value_name)
                if stored_hash is None:
                    self._handle_change('new', f"{hive_str}\\{subkey}", value_name, None, value_str)
                elif stored_hash != current_hash:
                    self._handle_change('modified', f"{hive_str}\\{subkey}", value_name, stored_hash, value_str)

            # Detect deletions
            # This requires storing all known keys for this subkey; simplified: we can query all from DB
            # For brevity, we assume deletions are caught on next full scan; but you can implement a full diff.
        except Exception as e:
            self.logger.error(event="enum_single_failed", key=subkey, error=str(e))

    def _handle_change(self, change_type, key_path, value_name, old_hash, new_value):
        suspicion = self.analyser.calculate_suspicion(key_path, value_name, new_value)
        self.db.log_change(change_type, key_path, value_name, old_hash, self.db._hash_data(new_value), suspicion, new_value)
        # Update baseline
        if change_type in ('new', 'modified'):
            self.db.set_registry_baseline(key_path, value_name, new_value)
        elif change_type == 'deleted':
            self.db.delete_registry_baseline(key_path, value_name)

        # Log structured message
        log_msg = {
            'event': 'registry_change',
            'type': change_type,
            'key': key_path,
            'value_name': value_name,
            'new_value': new_value,
            'suspicion_score': suspicion
        }
        if suspicion >= self.analyser.config.get('scoring', {}).get('critical_threshold', 80):
            self.logger.error(**log_msg)
            self.alert.send(f"CRITICAL: {key_path}\\{value_name} = {new_value} (score {suspicion})", 'ERROR')
        elif suspicion >= self.analyser.config.get('scoring', {}).get('warning_threshold', 50):
            self.logger.warning(**log_msg)
            self.alert.send(f"WARNING: {key_path}\\{value_name} = {new_value} (score {suspicion})", 'WARNING')
        else:
            self.logger.info(**log_msg)

    def stop(self):
        self.running = False