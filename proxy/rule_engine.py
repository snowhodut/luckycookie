# 5, 6
import re
import json
import threading
import time
import logging

# 규칙 유형 정의 (enum처럼 사용)
SQL_INJECTION = 0
XSS_ATTACK = 1
PATH_TRAVERSAL = 2
COMMAND_INJECTION = 3
FILE_INCLUSION = 4

type_map = {
    "sql_injection": SQL_INJECTION,
    "xss_attack": XSS_ATTACK,
    "path_traversal": PATH_TRAVERSAL,
    "command_injection": COMMAND_INJECTION,
    "file_inclusion": FILE_INCLUSION
}

# 규칙 클래스
class Rule:
    def __init__(self, rule_id, name, description, rule_type, pattern, severity):
        self.id = rule_id
        self.name = name
        self.description = description
        self.type = rule_type
        self.pattern = pattern
        self.severity = severity

# 규칙 엔진 클래스
class RuleEngine:
    def __init__(self):
        self.rules = []
        self.lock = threading.Lock()

    def add_default_rules(self):
        self.rules.append(Rule(
            rule_id=1001,
            name="SQL Injection Detection",
            description="SQL 명령어를 포함한 요청을 감지합니다",
            rule_type=SQL_INJECTION,
            pattern=re.compile(r'(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|OR|AND)\s+'),
            severity=3
        ))

        self.rules.append(Rule(
            rule_id=2001,
            name="XSS Attack Detection",
            description="자바스크립트 코드를 포함한 요청을 감지합니다",
            rule_type=XSS_ATTACK,
            pattern=re.compile(r'(?i)(<script|onerror|onload|alert\()'),
            severity=3
        ))

    def load_rules_from_file(self, filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
            rules = data.get("rules", [])
            for rule in rules:
                rule_id = rule.get("id")
                name = rule.get("name")
                description = rule.get("description")
                rule_type_str = rule.get("type", "").lower()
                pattern_str = rule.get("pattern")
                severity = rule.get("severity", 1)

                if not all([rule_id, name, pattern_str]):
                    continue  # 필수 필드 없으면 skip

                compiled_pattern = re.compile(pattern_str)

                rule_obj = Rule(
                    rule_id=rule_id,
                    name=name,
                    description=description,
                    rule_type=type_map.get(rule_type_str, -1),
                    pattern=compiled_pattern,
                    severity=severity
                )

                self.rules.append(rule_obj)


    def check_request(self, request_obj):
        """
        들어온 요청(request_obj)을 검사해서
        위반된 규칙이 있으면 (True, [위반 목록]) 반환
        아니면 (False, []) 반환
        """
        query = request_obj.query_string.decode()
        body = request_obj.get_data(as_text=True)
        combined = f"{query} {body}".upper()

        violations = []

        for rule in self.rules:
            if rule.pattern.search(combined):
                violations.append({
                    "rule": rule,
                    "field": "query/body",
                    "content": combined,
                })

        return (len(violations) > 0), violations
    
    def start_periodic_reload(self, filename, interval_seconds):
        def reload_loop():
            while True:
                time.sleep(interval_seconds)
                logging.info("🔄 규칙 파일 리로드 시도 중...")

                try:
                    temp_engine = RuleEngine()
                    temp_engine.load_rules_from_file(filename)
                except Exception as e:
                    logging.warning("⚠️ 규칙 파일 리로드 실패: %s", e)
                    continue

                with self.lock:
                    self.rules = temp_engine.rules
                logging.info("✅ 규칙 파일 리로드 성공: %d개 규칙 로드됨", len(self.rules))

        thread = threading.Thread(target=reload_loop, daemon=True)
        thread.start()