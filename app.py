import logging
import re
from flask import Flask, request, Response
import requests
from proxy.proxy import reverse_proxy
from proxy.rule_engine import RuleEngine
# from proxy.logger import Logger

logging.basicConfig(level=logging.INFO)

app = Flask(__name__)
rule_engine = RuleEngine()

try:
    rule_engine.load_rules_from_file("rules.json")
    logging.info("✅ 규칙 파일 로드 성공")
except Exception as e:
    logging.warning("⚠️ 규칙 파일 로드 실패: %s - 기본 규칙 사용", e)
    rule_engine.add_default_rules()

# 자동 리로드 시작
rule_engine.start_periodic_reload("rules.json", interval_seconds=5 * 60)

# WAF 핸들러 등록
reverse_proxy(app, rule_engine)

if __name__ == "__main__":
    app.logger.info("🛡️ WAF 프록시 서버가 포트 3000에서 시작됩니다...")
    app.run(host="0.0.0.0", port=3000)