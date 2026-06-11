# Architecture

LogShield는 SOC 환경의 로그 분석 흐름을 모의 구현한 미니 SIEM 플랫폼입니다.

## Pipeline

```text
Log Upload
    ↓
Parser
    ↓
Normalizer
    ↓
Detection Engine
    ↓
MITRE ATT&CK Mapping
    ↓
Risk Scoring
    ↓
Dashboard
    ↓
Incident Report
```

## Modules

| Module | Description |
|---|---|
| parser | 원본 로그에서 필드 추출 |
| normalizer | 서로 다른 로그를 공통 이벤트 스키마로 변환 |
| detection_engine | 규칙 기반 보안 이벤트 탐지 |
| mitre_mapper | 탐지 결과를 MITRE ATT&CK와 매핑 |
| risk_score | 위험도 점수 및 등급 산정 |
| dashboard | Streamlit 기반 시각화 |
| report_generator | 사고 리포트 생성 |
