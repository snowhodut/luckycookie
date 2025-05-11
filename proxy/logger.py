# 7.1
import json
import threading
from datetime import datetime

# 로그 레벨 상수
LOG_LEVEL_INFO = 0
LOG_LEVEL_WARNING = 1
LOG_LEVEL_ERROR = 2

# 위반 정보 클래스
class Violation:
    def __init__(self, rule_id, rule_name, field, content, severity):
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.field = field
        self.content = content
        self.severity = severity

    def to_dict(self):
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "field": self.field,
            "content": self.content,
            "severity": self.severity
        }
    
 # 로그 항목 클래스
class LogEntry:
    def __init__(self, level, client_ip, method, url, user_agent, blocked, violations, elapsed_time_ms):
        self.timestamp = datetime.utcnow().isoformat()
        self.level = level
        self.client_ip = client_ip
        self.method = method
        self.url = url
        self.user_agent = user_agent
        self.blocked = blocked
        self.violations = violations
        self.elapsed_time_ms = elapsed_time_ms

    def to_dict(self):
        return {
            "timestamp": self.timestamp,
            "level": self.level,
            "client_ip": self.client_ip,
            "method": self.method,
            "url": self.url,
            "user_agent": self.user_agent,
            "blocked": self.blocked,
            "violations": [v.to_dict() for v in self.violations] if self.violations else [],
            "elapsed_time_ms": self.elapsed_time_ms
        }

# 로거 클래스
class Logger:
    def __init__(self, filename, json_format=True):
        self.filename = filename
        self.json_format = json_format
        self.lock = threading.Lock()

    def log_request(self, entry: LogEntry):
        with self.lock:
            with open(self.filename, 'a', encoding='utf-8') as f:
                if self.json_format:
                    json.dump(entry.to_dict(), f, ensure_ascii=False)
                    f.write('\n')
                else:
                    level_map = {LOG_LEVEL_INFO: "INFO", LOG_LEVEL_WARNING: "WARNING", LOG_LEVEL_ERROR: "ERROR"}
                    status_str = "차단" if entry.blocked else "허용"

                    log_line = f"[{entry.timestamp}] {level_map.get(entry.level)} - {entry.method} {entry.url} {status_str} - {entry.client_ip} - {entry.elapsed_time_ms}ms\n"
                    f.write(log_line)

                    for v in entry.violations:
                        violation_line = f"  - 규칙 위반: [{v.rule_id}] {v.rule_name} (심각도: {v.severity}) - {v.field}에서 '{v.content}' 발견\n"
                        f.write(violation_line)

    def close(self):
        # 파일 핸들을 매번 열고 닫기 때문에 특별히 close는 필요 없음
        pass   