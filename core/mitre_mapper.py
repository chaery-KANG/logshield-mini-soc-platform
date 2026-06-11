import pandas as pd


MITRE_MAP = {
    "SSH Brute Force": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
    },
    "Admin Path Scanning": {
        "technique_id": "T1595",
        "technique_name": "Active Scanning",
        "tactic": "Reconnaissance",
    },
    "HTTP Error Spike": {
        "technique_id": "T1595",
        "technique_name": "Active Scanning",
        "tactic": "Reconnaissance",
    },
    "Suspicious High Request Volume": {
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "tactic": "Impact",
    },
}


def apply_mitre_mapping(detections: pd.DataFrame) -> pd.DataFrame:
    if detections.empty:
        return detections

    detections = detections.copy()

    detections["mitre_technique_id"] = detections["attack_type"].map(
        lambda x: MITRE_MAP.get(x, {}).get("technique_id", "N/A")
    )
    detections["mitre_technique_name"] = detections["attack_type"].map(
        lambda x: MITRE_MAP.get(x, {}).get("technique_name", "N/A")
    )
    detections["mitre_tactic"] = detections["attack_type"].map(
        lambda x: MITRE_MAP.get(x, {}).get("tactic", "N/A")
    )

    return detections
