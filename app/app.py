"""Main entry point for the Live Monitor App."""

import streamlit as st

st.set_page_config(
    page_title="Live Monitor App",
    page_icon=":material/shield:",
    layout="wide",
    initial_sidebar_state="expanded",
)

pg = st.navigation([
    st.Page("pages/live_monitor.py", title="Live Monitor", icon=":material/radar:"),
])

pg.run()
