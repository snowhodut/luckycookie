# 4
import logging
from flask import request, Response
import requests
from proxy.rule_engine import RuleEngine

TARGET_URL = "http://localhost:8080"

def reverse_proxy(app, rule_engine):
    @app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
    @app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
    def proxy(path):
        # 요청 검사
        blocked, violations = rule_engine.check_request(request)

        if blocked:
            for v in violations:
                logging.warning("⚠️ 규칙 위반 감지: [%d] %s - %s에서 '%s' 발견",
                                v["rule"].id,
                                v["rule"].name,
                                v["field"],
                                v["content"])
            return Response("보안 정책에 의해 차단된 요청입니다.", status=403)

        # 정상 요청은 프록시로 전달
        logging.info("✅ 정상 요청 통과: %s %s", request.method, request.path)

        url = f"{TARGET_URL}/{path}"
        resp = requests.request(
            method=request.method,
            url=url,
            headers={key: value for key, value in request.headers if key.lower() != 'host'},
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            params=request.args,
            timeout=3
        )

        response = Response(resp.content, resp.status_code)
        for key, value in resp.headers.items():
            if key.lower() != 'content-encoding':
                response.headers[key] = value
        return response
