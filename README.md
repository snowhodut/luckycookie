# :cookie: Lucky Cookie: AI-Based Web Application Firewall (WAF)

XSS, SQL Injection 등 일반적인 웹 공격을 실시간으로 탐지하고 차단하는 머신러닝 기반 WAF 프로토타입입니다.

## Features

- 머신러닝 모델을 활용한 악성 웹 요청 탐지
- 지원 공격 유형: XSS, SQL Injection
- ML 알고리즘 비교: Random Forest, LightGBM, DistilBERT
- Flask 미들웨어 기반 실시간 필터링
- DVWA(Damn Vulnerable Web App) 환경에서 테스트 진행

## Tech Stack

- 백엔드: Flask
- 테스트 대상: DVWA
- ML 프레임워크: PyTorch
- 사용 모델: Random Forest, LightGBM, DistilBERT

## Goals

- 웹 트래픽을 분석하고 필터링할 수 있는 지능형 WAF 구현
- 실제 공격 패턴을 기반으로 ML 모델 성능 비교
- 보안 분야에서의 AI 활용 경험 확장
