# 7.2

import time
from flask import Flask, request, Response
from rule_engine import RuleEngine
from logger import Logger
from proxy import forward_request

app = Flask(__name__)

# 규칙 엔진 생성
rule_engine = RuleEngine()
try:
    rule_engine.load_rules_from_file("rules.json")
except Exception as e:
    print(f"규칙 파일 로드 실패: {e} - 기본 규칙을 사용합니다")
    rule_engine.add_default_rules()

# 로깅 시스템 생성
logger = Logger("waf.log", to_console=True)

# 규칙 주기적 리로드
rule_engine.start_periodic_reload("rules.json", interval_seconds=300)

@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
def waf_handler(path):
    start_time = time.time()

    # 요청 검사
    blocked, violations = rule_engine.check_request(request)

    # 클라이언트 IP 추출
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)

    # 로그용 위반 정보 변환
    log_violations = []
    for v in violations:
        log_violations.append({
            "rule_id": v["rule"].id,
            "rule_name": v["rule"].name,
            "field": v["field"],
            "content": v["content"],
            "severity": v["rule"].severity
        })

    log_level = "INFO"
    if blocked:
        log_level = "WARNING"

    # 로그 엔트리 작성
    log_entry = {
        "timestamp": time.time(),
        "level": log_level,
        "client_ip": client_ip,
        "method": request.method,
        "url": request.url,
        "user_agent": request.headers.get("User-Agent", ""),
        "blocked": blocked,
        "violations": log_violations,
        "elapsed_time_ms": int((time.time() - start_time) * 1000)
    }

    try:
        logger.log_request(log_entry)
    except Exception as e:
        print(f"로깅 오류: {e}")

    if blocked:
        for v in violations:
            print(f"규칙 위반 감지: [{v['rule'].id}] {v['rule'].name} - {v['field']}에서 '{v['content']}' 발견")
        return Response("보안 정책에 의해 차단된 요청입니다.", status=403)

    # 정상 요청은 프록시 전달
    print(f"정상 요청 통과: {request.method} {request.path}")
    return forward_request(path, request)

if __name__ == "__main__":
    print("WAF 프록시 서버가 포트 3000에서 시작됩니다...")
    app.run(host="0.0.0.0", port=3000)

