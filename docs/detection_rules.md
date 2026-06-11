# Detection Rules

## LS-SSH-001: SSH Brute Force

- Source: SSH Auth Log
- Logic: 동일 IP에서 Failed password 이벤트가 기준 이상 발생
- MITRE ATT&CK: T1110 Brute Force
- Recommendation: IP 차단, MFA 적용, SSH 접근 제한

## LS-HTTP-001: Suspicious High Request Volume

- Source: Apache Access Log
- Logic: 동일 IP의 요청 횟수가 기준 이상 발생
- MITRE ATT&CK: T1498 Network Denial of Service
- Recommendation: 요청 패턴 확인 및 Rate Limit 적용

## LS-HTTP-002: HTTP Error Spike

- Source: Apache Access Log
- Logic: 4xx/5xx 오류가 동일 IP에서 반복 발생
- MITRE ATT&CK: T1595 Active Scanning
- Recommendation: URL 스캔 여부 확인

## LS-HTTP-003: Admin Path Scanning

- Source: Apache Access Log
- Logic: 관리자/백업/설정 파일 경로 접근 시도 다수 발생
- MITRE ATT&CK: T1595 Active Scanning
- Recommendation: WAF 룰 및 접근 제어 점검
