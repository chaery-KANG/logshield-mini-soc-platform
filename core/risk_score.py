import pandas as pd


BASE_SCORE = {
    "SSH Brute Force": 70,
    "Admin Path Scanning": 65,
    "HTTP Error Spike": 50,
    "Suspicious High Request Volume": 40,
}


def apply_risk_score(detections: pd.DataFrame) -> pd.DataFrame:
    if detections.empty:
        return detections

    detections = detections.copy()
    scores = []

    for _, row in detections.iterrows():
        base = BASE_SCORE.get(row["attack_type"], 30)
        count_bonus = min(int(row.get("event_count", 0)) * 2, 25)
        score = min(base + count_bonus, 100)
        scores.append(score)

    detections["risk_score"] = scores
    detections["severity"] = detections["risk_score"].apply(_to_severity)
    return detections.sort_values("risk_score", ascending=False)


def _to_severity(score: int) -> str:
    if score >= 85:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"
