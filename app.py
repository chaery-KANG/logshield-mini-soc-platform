import pandas as pd
import streamlit as st

from core.parser import parse_apache_log, parse_ssh_log
from core.normalizer import normalize_events
from core.detection_engine import run_detection
from core.mitre_mapper import apply_mitre_mapping
from core.risk_score import apply_risk_score
from dashboard.charts import render_summary_metrics, render_charts
from reports.report_generator import generate_markdown_report


st.set_page_config(
    page_title="LogShield Mini SOC Platform",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ LogShield Mini SOC Platform")
st.caption("팀프로젝트형 Mini SIEM / SOC 로그 분석 플랫폼")

with st.sidebar:
    st.header("Log Source")
    log_type = st.selectbox("로그 유형", ["Apache Access Log", "SSH Auth Log"])
    st.markdown("---")
    st.header("Detection Threshold")
    request_threshold = st.slider("Suspicious IP 요청 횟수 기준", 5, 50, 10)
    error_threshold = st.slider("Error Spike 기준", 3, 30, 5)
    brute_threshold = st.slider("SSH Brute Force 기준", 3, 30, 5)

uploaded_file = st.file_uploader("로그 파일 업로드", type=["log", "txt"])

if uploaded_file:
    raw_text = uploaded_file.read().decode("utf-8", errors="ignore")

    if log_type == "Apache Access Log":
        parsed_df = parse_apache_log(raw_text)
        source_type = "apache"
    else:
        parsed_df = parse_ssh_log(raw_text)
        source_type = "ssh"

    st.subheader("1. Parsed Logs")
    st.dataframe(parsed_df, use_container_width=True)

    if parsed_df.empty:
        st.warning("파싱된 로그가 없습니다. 로그 형식을 확인해주세요.")
        st.stop()

    normalized_df = normalize_events(parsed_df, source_type)

    st.subheader("2. Normalized Events")
    st.dataframe(normalized_df, use_container_width=True)

    detections = run_detection(
        normalized_df,
        source_type=source_type,
        request_threshold=request_threshold,
        error_threshold=error_threshold,
        brute_threshold=brute_threshold,
    )

    detections = apply_mitre_mapping(detections)
    detections = apply_risk_score(detections)

    st.subheader("3. Detection Results")

    if detections.empty:
        st.success("탐지된 보안 이벤트가 없습니다.")
    else:
        render_summary_metrics(normalized_df, detections)
        st.dataframe(detections, use_container_width=True)
        render_charts(normalized_df, detections)

        csv_data = detections.to_csv(index=False).encode("utf-8-sig")
        st.download_button(
            "Detection CSV 다운로드",
            data=csv_data,
            file_name="logshield_detections.csv",
            mime="text/csv",
        )

    st.subheader("4. Incident Report")
    report = generate_markdown_report(normalized_df, detections, source_type)
    st.text_area("Markdown Report", report, height=320)
    st.download_button(
        "Incident Report 다운로드",
        data=report,
        file_name="incident_report.md",
        mime="text/markdown",
    )

else:
    st.info("샘플 로그는 sample_logs 폴더에 있습니다. 로그 유형을 선택한 뒤 파일을 업로드하세요.")
    st.markdown("""
### Supported Logs

- Apache Access Log
- SSH Auth Log

### Pipeline

`Log Upload → Parsing → Normalization → Detection Engine → MITRE ATT&CK Mapping → Risk Scoring → Dashboard → Incident Report`
""")
