import streamlit as st
from main import app  # Import your compiled workflow

def run_alert_through_pipeline(alert_text: str):
    """Run alert through the pipeline and return final report."""
    try:
        final_output = app.invoke({"initial_alert": alert_text})
        return final_output.get("final_analysis", "❌ No analysis produced.")
    except Exception as e:
        return f"Error running pipeline: {e}"

# --- Streamlit UI ---
st.set_page_config(page_title="SOC Triage Dashboard", page_icon="🛡️", layout="wide")

st.title("🛡️ SOC Alert Triage Dashboard")
st.markdown("Analyze security alerts with automated investigation and reporting.")

# Sidebar input
st.sidebar.header("⚡ Input Alert")
alert_text = st.sidebar.text_area(
    "Paste a security alert here:",
    height=150,
    value="""Impossible Travel Alert for user jdoe@example.com: 
    A session was initiated from IP 104.28.21.31 (New York, USA) at 15:30:10 EST, 
    followed by a successful login from IP 45.137.234.19 (Moscow, Russia) at 15:32:45 EST. 
    The two events are separated by a time difference of 2 minutes and 35 seconds, 
    making physical travel impossible."""
)

if st.sidebar.button("🚀 Run Analysis"):
    with st.spinner("Running SOC pipeline..."):
        report = run_alert_through_pipeline(alert_text)

    # Display the report
    st.success("✅ Analysis completed")
    st.markdown("## 📑 Final Security Report")
    st.write(report)
