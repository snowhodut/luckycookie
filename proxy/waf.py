# 7.2

import time
import logging
from flask import request, g
from datetime import datetime

from logger import Logger, LogEntry, Violation, LOG_LEVEL_INFO, LOG_LEVEL_WARNING
from rule_engine import RuleEngine

# ——— 룰 엔진과 로거 초기화 ———
rule_engine = RuleEngine()
try:
    rule_engine.load_rules_from_file('rules.json')
except Exception as e:
    logging.warning(f"⚠️ 규칙 파일 로드 실패: {e} - 기본 규칙을 사용합니다")
    rule_engine.add_default_rules()

logger = Logger('waf.log', console_logging=True)
# 5분마다 규칙 자동 리로드
rule_engine.start_periodic_reload('rules.json', 300)

def waf_before_request():
    # 요청 시작 시간 저장
    g.start_time = time.time()

    # WAF 검사
    blocked, violations = rule_engine.check_request(request)

    # 경과 시간(ms)
    elapsed_ms = int((time.time() - g.start_time) * 1000)

    # Violation 객체 리스트
    log_violations = [
        Violation(
            rule_id=v['rule'].id,
            rule_name=v['rule'].name,
            field=v['field'],
            content=v['content'],
            severity=v['rule'].severity
        )
        for v in violations
    ]

    # 로그 엔트리 생성
    entry = LogEntry(
        timestamp=datetime.utcnow(),
        level=LOG_LEVEL_WARNING if blocked else LOG_LEVEL_INFO,
        client_ip=request.headers.get('X-Forwarded-For', request.remote_addr),
        method=request.method,
        url=request.url,
        user_agent=request.user_agent.string,
        blocked=blocked,
        violations=log_violations,
        elapsed_time_ms=elapsed_ms
    )

    # 로그 기록
    try:
        logger.log_request(entry)
    except Exception as e:
        logging.error(f"로깅 오류: {e}")

    # 차단된 요청 처리
    if blocked:
        for v in log_violations:
            logging.warning(f"⚠️ 규칙 위반 감지: [{v.rule_id}] {v.rule_name} - {v.field}에서 '{v.content}' 발견")
        return "보안 정책에 의해 차단된 요청입니다.", 403
