from flask import Flask, request, Response
import requests
import threading
import time
import json
import logging

# ——— RuleEngine 클래스 ———
class RuleEngine:
    def __init__(self):
        self.rules = []

    def load_rules_from_file(self, path):
        with open(path, 'r', encoding='utf-8') as f:
            self.rules = json.load(f)

    def add_default_rules(self):
        # 기본 룰 추가
        pass

    def check_request(self, req):
        # Go의 CheckRequest와 동일하게 동작해야 함
        blocked = False
        violations = []
        # for each rule in self.rules:
        #     if 위반 발생:
        #         blocked = True or False
        #         violations.append({...})
        return blocked, violations

    def start_periodic_reload(self, path, interval_seconds):
        def _reload_loop():
            while True:
                try:
                    self.load_rules_from_file(path)
                except Exception as e:
                    logging.warning(f"⚠️ 규칙 파일 재로드 실패: {e}")
                time.sleep(interval_seconds)
        t = threading.Thread(target=_reload_loop, daemon=True)
        t.start()

# ——— Logger 클래스 ———
class Logger:
    def __init__(self, filename, console_logging=True):
        self.logger = logging.getLogger('waf')
        self.logger.setLevel(logging.INFO)
        fmt = logging.Formatter(
            '%(asctime)s %(levelname)s %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        fh = logging.FileHandler(filename, encoding='utf-8')
        fh.setFormatter(fmt)
        self.logger.addHandler(fh)
        if console_logging:
            ch = logging.StreamHandler()
            ch.setFormatter(fmt)
            self.logger.addHandler(ch)

    def log_request(self, entry):
        # entry: dict 형태로 Go의 LogEntry와 동일한 키를 가짐
        level = entry.get('Level', logging.INFO)
        self.logger.log(level, json.dumps(entry, ensure_ascii=False))

    def close(self):
        handlers = self.logger.handlers[:]
        for h in handlers:
            h.close()
            self.logger.removeHandler(h)

# ——— Flask 앱 설정 ———
app = Flask(__name__)

# Go 코드에서 main() 부분
# 대상 서버
TARGET_URL = 'http://localhost:8080'

# 인스턴스 생성 및 초기화
rule_engine = RuleEngine()
try:
    rule_engine.load_rules_from_file('rules.json')
except Exception as e:
    logging.warning(f"⚠️ 규칙 파일 로드 실패: {e} - 기본 규칙 사용")
    rule_engine.add_default_rules()

logger = Logger('waf.log', console_logging=True)

# 규칙 주기적 리로드 (5분마다)
rule_engine.start_periodic_reload('rules.json', 5 * 60)

# ——— WAF 미들웨어 ———
@app.before_request
def waf_before_request():
    start_time = time.time()

    blocked, violations = rule_engine.check_request(request)

    # 로그 항목 구성
    log_entry = {
        'Timestamp': time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime()),
        'Level': logging.WARNING if blocked else logging.INFO,
        'ClientIP': request.headers.get('X-Forwarded-For', request.remote_addr),
        'Method': request.method,
        'URL': request.url,
        'UserAgent': request.user_agent.string,
        'Blocked': blocked,
        'Violations': [
            {
                'RuleID': v['rule']['id'],
                'RuleName': v['rule']['name'],
                'Field': v['field'],
                'Content': v['content'],
                'Severity': v['rule']['severity'],
            } for v in violations
        ],
        'ElapsedTime': int((time.time() - start_time) * 1000),
    }

    # 로그 기록
    try:
        logger.log_request(log_entry)
    except Exception as e:
        logging.error(f"로깅 오류: {e}")

    if blocked:
        # 콘솔에 위반 사항 출력
        for v in violations:
            logging.warning(
                f"⚠️ 규칙 위반 감지: [{v['rule']['id']}] "
                f"{v['rule']['name']} - {v['field']}에서 '{v['content']}' 발견"
            )
        return "보안 정책에 의해 차단된 요청입니다.", 403

# ——— 리버스 프록시 엔드포인트 ———
@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
def proxy(path):
    # 원본 서버로 요청 전달
    resp = requests.request(
        method=request.method,
        url=f"{TARGET_URL}/{path}",
        headers={key: value for key, value in request.headers if key != 'Host'},
        data=request.get_data(),
        cookies=request.cookies,
        allow_redirects=False,
        stream=True
    )
    # 응답 헤더 필터링
    excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
    headers = [
        (name, value) for name, value in resp.raw.headers.items()
        if name.lower() not in excluded_headers
    ]
    return Response(resp.content, resp.status_code, headers)

# ——— 앱 실행 ———
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000)