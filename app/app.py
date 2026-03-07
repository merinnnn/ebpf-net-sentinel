from __future__ import annotations

import streamlit as st

from utils.styles import inject_css


st.set_page_config(page_title="NetSentinel", layout="wide")
inject_css()
st.switch_page("pages/dashboard.py")
