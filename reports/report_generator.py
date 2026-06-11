from datetime import datetime
import pandas as pd


def generate_markdown_report(events: pd.DataFrame, detections: pd.DataFrame, source_type: str) -> str:
    lines = [
        "# LogShield Incident Report",
        "",
        f"- Generated At: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"- Source Type: {source_type}",
        f"- Total Events: {len(events)}",
        f"- Unique Source IPs: {events['src_ip'].nunique() if not events.empty else 0}",
        f"- Detection Count: {len(detections)}",
        "",
        "## Executive Summary",
        "",
    ]

    if detections.empty:
        lines.append("탐지된 보안 이벤트가 없습니다.")
    else:
        high = detections[detections["severity"].isin(["HIGH", "CRITICAL"])]
        lines.append(f"총 {len(detections)}건의 보안 이벤트가 탐지되었으며, 이 중 HIGH 이상 이벤트는 {len(high)}건입니다.")

    lines.extend(["", "## Detection Details", ""])

    if not detections.empty:
        for _, row in detections.iterrows():
            lines.extend([
                f"### {row['attack_type']}",
                "",
                f"- Rule ID: {row['rule_id']}",
                f"- Source IP: {row['src_ip']}",
                f"- Severity: {row['severity']}",
                f"- Risk Score: {row['risk_score']}",
                f"- MITRE ATT&CK: {row['mitre_technique_id']} / {row['mitre_technique_name']} / {row['mitre_tactic']}",
                f"- Evidence: {row['evidence']}",
                f"- Recommendation: {row['recommendation']}",
                "",
            ])

    lines.extend([
        "## Analyst Notes",
        "",
        "- 본 프로젝트는 SOC 로그 분석 흐름을 모의 구현한 미니 SIEM 플랫폼입니다.",
        "- 실제 운영 환경에서는 로그 수집기, 장기 저장소, 위협 인텔리전스, 자산 정보와 연계해야 합니다.",
    ])

    return "\n".join(lines)
