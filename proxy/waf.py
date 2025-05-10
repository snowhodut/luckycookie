# 7.2

import time
import logging
from flask import request, g
from datetime import datetime, timezone

from logger import Logger, LogEntry, Violation, LOG_LEVEL_INFO, LOG_LEVEL_WARNING
from rule_engine import RuleEngine

# WAF 미들웨어 초기화
rule_engine = RuleEngine()
logger = Logger('waf.log', console_logging=True)

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
        timestamp=datetime.now(timezone.utc),
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
