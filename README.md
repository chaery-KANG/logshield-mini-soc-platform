# LogShield Mini SOC Platform

보안관제(SOC) 환경을 모의 구현한 팀프로젝트형 Mini SIEM 로그 분석 플랫폼입니다.

Apache Access Log와 SSH Auth Log를 업로드하면 로그를 파싱하고, 공통 스키마로 정규화한 뒤, 규칙 기반 탐지 엔진을 통해 보안 이벤트를 식별합니다. 탐지 결과는 MITRE ATT&CK 프레임워크와 매핑되며, 위험도 점수와 Incident Report로 정리됩니다.

## Features

- Apache Access Log 분석
- SSH Auth Log 분석
- 로그 정규화
- 규칙 기반 탐지 엔진
- SSH Brute Force 탐지
- Admin Path Scanning 탐지
- HTTP Error Spike 탐지
- MITRE ATT&CK 매핑
- 위험도 점수화
- Streamlit 대시보드
- CSV Export
- Markdown Incident Report 생성

## Tech Stack

- Python
- Streamlit
- Pandas
- Regex
- Rule-based Detection
- MITRE ATT&CK Mapping

## Architecture

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

## Project Structure

```text
logshield-mini-soc-platform
├─ app.py
├─ core
│  ├─ parser.py
│  ├─ normalizer.py
│  ├─ detection_engine.py
│  ├─ mitre_mapper.py
│  └─ risk_score.py
├─ dashboard
│  └─ charts.py
├─ reports
│  └─ report_generator.py
├─ rules
│  └─ detection_rules.yaml
├─ sample_logs
│  ├─ apache_sample.log
│  └─ ssh_sample.log
├─ docs
│  ├─ architecture.md
│  ├─ detection_rules.md
│  └─ team_roles.md
├─ requirements.txt
└─ README.md
```

## How to Run

### 1. 가상환경 생성

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### 2. 라이브러리 설치

```powershell
pip install -r requirements.txt
```

### 3. 실행

```powershell
streamlit run app.py
```

## Sample Logs

`sample_logs` 폴더에 테스트용 로그가 포함되어 있습니다.

- `apache_sample.log`
- `ssh_sample.log`

앱 실행 후 로그 유형을 선택하고 샘플 로그를 업로드하면 탐지 결과를 확인할 수 있습니다.

## Detection Rules

| Rule ID | Attack Type | Source | MITRE ATT&CK |
|---|---|---|---|
| LS-SSH-001 | SSH Brute Force | SSH | T1110 |
| LS-HTTP-001 | Suspicious High Request Volume | Apache | T1498 |
| LS-HTTP-002 | HTTP Error Spike | Apache | T1595 |
| LS-HTTP-003 | Admin Path Scanning | Apache | T1595 |

## Team Role Simulation

| Role | Responsibility |
|---|---|
| Log Parser Engineer | Apache/SSH 로그 파싱 및 정규화 |
| Detection Engineer | Brute Force, Admin Scan, Error Spike 탐지 룰 설계 |
| SOC Analyst | MITRE ATT&CK 매핑, 위험도 분석, 대응 가이드 작성 |
| Dashboard Developer | Streamlit 기반 대시보드 구현 |
| Report Engineer | Incident Report 및 CSV Export 구현 |

## Portfolio Description

LogShield Mini SOC Platform은 실제 보안관제센터의 로그 분석 흐름을 모의 구현한 프로젝트입니다. 로그 파싱, 정규화, 탐지 룰 엔진, MITRE ATT&CK 매핑, 위험도 산정, 리포트 생성을 모듈화하여 SIEM의 기본 구조를 설계했습니다.

## GitHub Commit Example

```powershell
git init
git add .
git commit -m "feat: initialize LogShield mini SOC platform"
git branch -M main
git remote add origin https://github.com/chaery-KANG/logshield-mini-soc-platform.git
git push -u origin main
```

## Future Improvements

- Windows Event Log 지원
- GeoIP 기반 국가 분석
- Discord Webhook 알림
- Sigma Rule 연동
- MITRE ATT&CK Matrix 시각화
- 장기 로그 저장 및 검색 기능
