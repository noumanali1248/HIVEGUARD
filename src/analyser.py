import os
import re

class SuspicionAnalyser:
    def __init__(self, config):
        self.config = config
        self.allowlist_values = set(config.get('allowlist', {}).get('values', []))
        self.allowlist_paths = tuple(config.get('allowlist', {}).get('paths', []))

    def is_allowlisted(self, value):
        if value in self.allowlist_values:
            return True
        if any(value.lower().startswith(p.lower()) for p in self.allowlist_paths):
            return True
        return False

    def calculate_suspicion(self, key_path, value_name, new_value):
        """
        Returns score 0-100 based on multiple rules derived from MITRE T1547 and real-world threats.
        """
        if self.is_allowlisted(new_value):
            return 0

        score = 0
        value_lower = new_value.lower()
        key_lower = key_path.lower()

        # Rule 1: Executable in user-writable locations (T1547.001)
        if '.exe' in value_lower and any(p in value_lower for p in ['appdata', 'temp', 'public']):
            score += 30

        # Rule 2: Rundll32 loading a DLL (T1218.010)
        if 'rundll32.exe' in value_lower and '.dll' in value_lower:
            score += 40

        # Rule 3: Critical system keys (BootExecute, Winlogon)
        if key_lower.endswith('bootexecute') or 'winlogon' in key_lower:
            score += 80

        # Rule 4: Image File Execution Options debugger (T1547.009)
        if 'image file execution options' in key_lower and value_name.lower() == 'debugger':
            score += 90

        # Rule 5: Suspicious keywords in name/value
        suspicious_keywords = ['update', 'security', 'svchost', 'msupdate', 'java', 'adobe']
        for kw in suspicious_keywords:
            if kw in value_lower or kw in value_name.lower():
                score += 10
                break

        # Rule 6: PowerShell or script execution
        if any(ext in value_lower for ext in ['.ps1', '.vbs', '.js', '.bat', '.cmd']):
            score += 25

        # Rule 7: Registry RunOnce / RunServices keys (often abused)
        if any(x in key_lower for x in ['runonce', 'runservices']):
            score += 15

        return min(score, 100)