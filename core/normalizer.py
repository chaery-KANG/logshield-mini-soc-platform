import pandas as pd


def normalize_events(df: pd.DataFrame, source_type: str) -> pd.DataFrame:
    """
    서로 다른 로그 형식을 SOC 분석용 공통 스키마로 정규화합니다.
    """
    if df.empty:
        return df

    if source_type == "apache":
        normalized = pd.DataFrame({
            "timestamp": df["timestamp"],
            "source_type": "apache",
            "src_ip": df["src_ip"],
            "event_name": df["method"] + " " + df["url"],
            "username": "",
            "url": df["url"],
            "status": df["status"],
            "raw_log": df["raw_log"],
        })
    elif source_type == "ssh":
        normalized = pd.DataFrame({
            "timestamp": df["timestamp"],
            "source_type": "ssh",
            "src_ip": df["src_ip"],
            "event_name": df["event_name"],
            "username": df["username"],
            "url": "",
            "status": "",
            "raw_log": df["raw_log"],
        })
    else:
        normalized = df.copy()

    return normalized
