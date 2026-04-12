import smtplib
import socket
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import win32evtlog

class AlertDispatcher:
    def __init__(self, config):
        self.config = config
        self.eventlog_enabled = config.get('alerting', {}).get('eventlog', True)
        self.email_cfg = config.get('alerting', {}).get('email', {})
        self.syslog_cfg = config.get('alerting', {}).get('syslog', {})

    def send(self, message, severity='WARNING'):
        if self.eventlog_enabled:
            self._write_eventlog(message, severity)
        if self.email_cfg.get('enabled'):
            self._send_email(message, severity)
        if self.syslog_cfg.get('enabled'):
            self._send_syslog(message, severity)

    def _write_eventlog(self, message, severity):
        try:
            app_name = 'PersistenceMonitor'
            event_type = {
                'INFO': win32evtlog.EVENTLOG_INFORMATION_TYPE,
                'WARNING': win32evtlog.EVENTLOG_WARNING_TYPE,
                'ERROR': win32evtlog.EVENTLOG_ERROR_TYPE
            }.get(severity, win32evtlog.EVENTLOG_WARNING_TYPE)
            win32evtlog.ReportEvent(
                win32evtlog.RegisterEventSource(None, app_name),
                event_type,
                0,  # category
                1000,  # event ID
                None,  # sid
                [message],
                None
            )
        except Exception as e:
            logging.error(f"Failed to write event log: {e}")

    def _send_email(self, message, severity):
        cfg = self.email_cfg
        if not cfg.get('smtp_server'):
            return
        try:
            msg = MIMEMultipart()
            msg['From'] = cfg.get('username', 'persistence@monitor')
            msg['To'] = ', '.join(cfg.get('recipients', []))
            msg['Subject'] = f"[{severity}] Persistence Monitor Alert"
            body = f"Time: {self._timestamp()}\nSeverity: {severity}\nDetails:\n{message}"
            msg.attach(MIMEText(body, 'plain'))
            server = smtplib.SMTP(cfg['smtp_server'], cfg.get('port', 25))
            if cfg.get('use_tls'):
                server.starttls()
            if cfg.get('username'):
                server.login(cfg['username'], cfg.get('password', ''))
            server.send_message(msg)
            server.quit()
        except Exception as e:
            logging.error(f"Email alert failed: {e}")

    def _send_syslog(self, message, severity):
        # Simplified; use a real syslog library in production
        pass

    def _timestamp(self):
        from datetime import datetime
        return datetime.utcnow().isoformat()