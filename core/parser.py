import re
from typing import List
import pandas as pd


APACHE_PATTERN = re.compile(
    r'(?P<src_ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<url>\S+) (?P<protocol>[^"]+)" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
)

SSH_FAILED_PATTERN = re.compile(
    r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*sshd.*Failed password for (invalid user )?(?P<username>\S+) from (?P<src_ip>\S+)'
)

SSH_ACCEPTED_PATTERN = re.compile(
    r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*sshd.*Accepted password for (?P<username>\S+) from (?P<src_ip>\S+)'
)


def parse_apache_log(raw_text: str) -> pd.DataFrame:
    rows: List[dict] = []

    for line in raw_text.splitlines():
        match = APACHE_PATTERN.search(line)
        if match:
            row = match.groupdict()
            row["raw_log"] = line
            rows.append(row)

    df = pd.DataFrame(rows)
    if not df.empty:
        df["status"] = df["status"].astype(int)
    return df


def parse_ssh_log(raw_text: str) -> pd.DataFrame:
    rows: List[dict] = []

    for line in raw_text.splitlines():
        failed = SSH_FAILED_PATTERN.search(line)
        accepted = SSH_ACCEPTED_PATTERN.search(line)

        if failed:
            row = failed.groupdict()
            row["event_name"] = "Failed password"
            row["raw_log"] = line
            rows.append(row)
        elif accepted:
            row = accepted.groupdict()
            row["event_name"] = "Accepted password"
            row["raw_log"] = line
            rows.append(row)

    return pd.DataFrame(rows)
