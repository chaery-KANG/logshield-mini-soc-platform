import pandas as pd


ADMIN_PATH_KEYWORDS = [
    "/admin", "/wp-admin", "/login", "/phpmyadmin", "/server-status",
    "/config", "/.env", "/backup", "/shell"
]


def run_detection(
    events: pd.DataFrame,
    source_type: str,
    request_threshold: int = 10,
    error_threshold: int = 5,
    brute_threshold: int = 5,
) -> pd.DataFrame:
    if events.empty:
        return pd.DataFrame()

    detections = []

    if source_type == "apache":
        detections.extend(_detect_suspicious_ip(events, request_threshold))
        detections.extend(_detect_error_spike(events, error_threshold))
        detections.extend(_detect_admin_scan(events))

    if source_type == "ssh":
        detections.extend(_detect_ssh_bruteforce(events, brute_threshold))

    return pd.DataFrame(detections)


def _detect_suspicious_ip(events: pd.DataFrame, threshold: int):
    rows = []
    grouped = events.groupby("src_ip").size().reset_index(name="count")
    for _, row in grouped[grouped["count"] >= threshold].iterrows():
        rows.append({
            "rule_id": "LS-HTTP-001",
            "attack_type": "Suspicious High Request Volume",
            "src_ip": row["src_ip"],
            "evidence": f"{row['count']} requests observed",
            "event_count": int(row["count"]),
            "recommendation": "요청량이 많은 IP를 확인하고 필요 시 차단 정책을 검토하세요.",
        })
    return rows


def _detect_error_spike(events: pd.DataFrame, threshold: int):
    rows = []
    http_events = events[events["status"] != ""].copy()
    http_events["status"] = http_events["status"].astype(int)
    errors = http_events[http_events["status"] >= 400]

    grouped = errors.groupby("src_ip").size().reset_index(name="count")
    for _, row in grouped[grouped["count"] >= threshold].iterrows():
        rows.append({
            "rule_id": "LS-HTTP-002",
            "attack_type": "HTTP Error Spike",
            "src_ip": row["src_ip"],
            "evidence": f"{row['count']} HTTP 4xx/5xx errors observed",
            "event_count": int(row["count"]),
            "recommendation": "404/401/403 반복 요청은 스캐닝 가능성이 있으므로 접근 URL과 User-Agent를 확인하세요.",
        })
    return rows


def _detect_admin_scan(events: pd.DataFrame):
    rows = []
    http_events = events[events["url"] != ""].copy()

    for src_ip, group in http_events.groupby("src_ip"):
        matched_urls = sorted({
            url for url in group["url"].astype(str)
            if any(keyword in url.lower() for keyword in ADMIN_PATH_KEYWORDS)
        })

        if len(matched_urls) >= 3:
            rows.append({
                "rule_id": "LS-HTTP-003",
                "attack_type": "Admin Path Scanning",
                "src_ip": src_ip,
                "evidence": ", ".join(matched_urls[:10]),
                "event_count": len(matched_urls),
                "recommendation": "관리자 경로 스캔이 의심됩니다. WAF 룰과 접근 제어 정책을 점검하세요.",
            })
    return rows


def _detect_ssh_bruteforce(events: pd.DataFrame, threshold: int):
    rows = []
    failed = events[events["event_name"] == "Failed password"]

    grouped = (
        failed.groupby("src_ip")
        .agg(
            count=("event_name", "count"),
            target_users=("username", lambda x: ", ".join(sorted(set(x))))
        )
        .reset_index()
    )

    for _, row in grouped[grouped["count"] >= threshold].iterrows():
        rows.append({
            "rule_id": "LS-SSH-001",
            "attack_type": "SSH Brute Force",
            "src_ip": row["src_ip"],
            "evidence": f"{row['count']} failed logins / users: {row['target_users']}",
            "event_count": int(row["count"]),
            "recommendation": "IP 차단, 계정 잠금 정책, MFA 적용, SSH 포트 접근 제한을 검토하세요.",
        })
    return rows
