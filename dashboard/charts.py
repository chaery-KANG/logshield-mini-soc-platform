import streamlit as st
import pandas as pd


def render_summary_metrics(events: pd.DataFrame, detections: pd.DataFrame):
    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Total Events", len(events))
    col2.metric("Unique IPs", events["src_ip"].nunique())
    col3.metric("Detections", len(detections))

    if not detections.empty:
        critical_high = detections[detections["severity"].isin(["CRITICAL", "HIGH"])]
        col4.metric("High Risk Events", len(critical_high))
    else:
        col4.metric("High Risk Events", 0)


def render_charts(events: pd.DataFrame, detections: pd.DataFrame):
    st.markdown("### Dashboard")

    if not detections.empty:
        col1, col2 = st.columns(2)

        with col1:
            st.markdown("#### Severity Distribution")
            st.bar_chart(detections["severity"].value_counts())

        with col2:
            st.markdown("#### Attack Type Distribution")
            st.bar_chart(detections["attack_type"].value_counts())

    st.markdown("#### Top Source IPs")
    st.bar_chart(events["src_ip"].value_counts().head(10))
