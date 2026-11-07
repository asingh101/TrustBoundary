from datetime import datetime
import pandas as pd
import requests
import streamlit as st

st.set_page_config(
    page_title="AgentGuard Security Console",
    page_icon="🛡️",
    layout="wide",
)

# Custom High-End SOC Styling (No generic Streamlit widgets)
st.markdown(
    """
    <style>
    /* Global Light Theme */
    .stApp {
        background-color: #f1f5f9;
        color: #0f172a;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    }
    
    /* Hide default streamlit branding elements for clean presentation */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    
    /* Custom Sleek Metric Cards */
    .metric-container {
        background: linear-gradient(135deg, #ffffff 0%, #f8fafc 100%);
        border: 1px solid #cbd5e1;
        border-left: 4px solid #3b82f6;
        border-radius: 12px;
        padding: 20px;
        box-shadow: 0 1px 3px rgba(15, 23, 42, 0.08), 0 1px 2px rgba(15, 23, 42, 0.04);
        margin-bottom: 20px;
    }
    .metric-container.blocked {
        border-left-color: #ef4444;
    }
    .metric-container.allowed {
        border-left-color: #10b981;
    }
    .metric-label {
        font-size: 0.85rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: #64748b;
        font-weight: 600;
        margin-bottom: 8px;
    }
    .metric-value {
        font-size: 2rem;
        font-weight: 700;
        color: #0f172a;
        line-height: 1;
    }
    
    /* Status Banners */
    .status-running {
        background-color: rgba(16, 185, 129, 0.12);
        border: 1px solid rgba(16, 185, 129, 0.35);
        color: #047857;
        padding: 14px 20px;
        border-radius: 10px;
        font-weight: 600;
        display: flex;
        align-items: center;
        gap: 10px;
        margin-bottom: 24px;
    }
    .status-killed {
        background-color: rgba(239, 68, 68, 0.12);
        border: 1px solid rgba(239, 68, 68, 0.35);
        color: #b91c1c;
        padding: 14px 20px;
        border-radius: 10px;
        font-weight: 600;
        display: flex;
        align-items: center;
        gap: 10px;
        margin-bottom: 24px;
    }
    
    /* Custom Headers */
    h1, h2, h3 {
        color: #0f172a !important;
        font-weight: 700 !important;
    }
    .flash {
        position: fixed;
        inset: 0;
        pointer-events: none;
        z-index: 9999;
        box-shadow: inset 0 0 0 10px #ef4444;
        animation: flash 1s ease-out forwards;
    }
    @keyframes flash {
        from { opacity: 1; }
        to { opacity: 0; }
    }
    </style>
""",
    unsafe_allow_html=True,
)

# Read query params (?sid=...&token=...) with fallback
query_params = st.query_params
default_sid = query_params.get("sid", "")
default_token = query_params.get("token", "")

# Header Section
col_logo, col_title = st.columns([0.06, 0.94])
with col_logo:
  st.markdown("### 🛡️")
with col_title:
  st.markdown(
      "## AgentGuard Security Console"
  )
  st.markdown(
      "<span style='color: #64748b; font-size: 0.95rem;'>Enterprise-Grade"
      " Execution Guardrails & Real-Time Threat Mitigation for AI"
      " Agents</span>",
      unsafe_allow_html=True,
  )

st.markdown("<hr style='border: 1px solid #cbd5e1; margin: 20px 0;'>", unsafe_allow_html=True)

# Sidebar Controls
st.sidebar.markdown(
    "<h3 style='color: #0f172a; font-size: 1.1rem;'>⚙️ Session Controls</h3>",
    unsafe_allow_html=True,
)
session_id = st.sidebar.text_input(
    "Session ID", value=default_sid, placeholder="Paste Session ID..."
)
token = st.sidebar.text_input(
    "Session Token",
    value=default_token,
    type="password",
    placeholder="Paste Token...",
)

st.sidebar.markdown(
    "<hr style='border: 1px solid #cbd5e1; margin: 20px 0;'>",
    unsafe_allow_html=True,
)
st.sidebar.markdown(
    "<h3 style='color: #ef4444; font-size: 1.1rem;'>🚨 Emergency Override</h3>",
    unsafe_allow_html=True,
)

if st.sidebar.button(
    "TERMINATE AGENT", type="primary", use_container_width=True
):
  if not session_id or not token:
    st.sidebar.error("Please provide both Session ID and Token.")
  else:
    try:
      res = requests.post(
          "http://127.0.0.1:8000/kill",
          headers={"X-Session-Token": token},
          json={"session_id": session_id},
          timeout=5,
      )
      if res.status_code == 200 and res.json().get("terminated"):
        st.sidebar.success("⚡ AGENT TERMINATED SUCCESSFULLY")
      else:
        st.sidebar.warning(f"Failed: {res.json()}")
    except Exception as e:
      st.sidebar.error(f"Error connecting to backend: {e}")


# Auto-refresh fragment running every 1 second
@st.fragment(run_every=1)
def render_dashboard():
  is_terminated = False
  if session_id and token:
    try:
      status_res = requests.get(
          "http://127.0.0.1:8000/status",
          params={"session_id": session_id},
          headers={"X-Session-Token": token},
          timeout=3,
      )
      if status_res.status_code == 200:
        is_terminated = status_res.json().get("terminated", False)
    except Exception:
      pass

  # Top Banner Status Indicator
  if session_id and token:
    if is_terminated:
      st.markdown(
          """
                <div class="status-killed">
                    <span>🔴</span> STATUS: KILLED — Agent execution has been halted via emergency override.
                </div>
            """,
          unsafe_allow_html=True,
      )
    else:
      st.markdown(
          """
                <div class="status-running">
                    <span>🟢</span> STATUS: RUNNING — Real-time execution guardrails active and monitoring.
                </div>
            """,
          unsafe_allow_html=True,
      )
  else:
    st.info(
        "ℹ️ Enter your Session ID and Token in the sidebar to activate live"
        " monitoring."
    )

  if session_id and token:
    try:
      res = requests.get(
          "http://127.0.0.1:8000/logs",
          params={"session_id": session_id},
          headers={"X-Session-Token": token},
          timeout=5,
      )
      if res.status_code == 200:
        raw_logs = res.json().get("logs", [])
        if raw_logs:
          processed = []
          for l in raw_logs:
            ts_str = l.get("timestamp", "")
            try:
              dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
              time_formatted = dt.astimezone().strftime("%H:%M:%S")
            except Exception:
              time_formatted = "-"

            rule = l.get("rule")
            status = l.get("status")
            if status == "ALLOWED":
              reason = "—"
            else:
              log_reason = l.get("reason")
              if log_reason and log_reason != rule:
                reason = log_reason
              elif not rule or rule == "None":
                reason = "—"
              elif rule == "sensitive_file":
                reason = "Attempted access to sensitive environment file (.env)"
              elif rule == "rm_rf":
                reason = "Dangerous recursive deletion command blocked"
              else:
                reason = f"Triggered security rule: {rule}"

            processed.append({
                "Time": time_formatted,
                "Command": l.get("command"),
                "Status": status,
                "Reason": reason,
            })

          df = pd.DataFrame(processed[::-1])

          total = len(df)
          allowed = len(df[df["Status"] == "ALLOWED"])
          blocked = len(df[df["Status"].isin(["BLOCKED", "TERMINATED"])])

          if blocked > st.session_state.get("seen_blocked", 0):
            st.markdown('<div class="flash"></div>', unsafe_allow_html=True)
          st.session_state.seen_blocked = blocked

          # Custom HTML Metric Cards
          m1, m2, m3 = st.columns(3)
          with m1:
            st.markdown(
                f"""
                            <div class="metric-container">
                                <div class="metric-label">Total Intercepted</div>
                                <div class="metric-value">{total}</div>
                            </div>
                        """,
                unsafe_allow_html=True,
            )
          with m2:
            st.markdown(
                f"""
                            <div class="metric-container allowed">
                                <div class="metric-label">Allowed Commands</div>
                                <div class="metric-value">{allowed}</div>
                            </div>
                        """,
                unsafe_allow_html=True,
            )
          with m3:
            st.markdown(
                f"""
                            <div class="metric-container blocked">
                                <div class="metric-label">Blocked Threats</div>
                                <div class="metric-value">{blocked}</div>
                            </div>
                        """,
                unsafe_allow_html=True,
            )

          st.markdown(
              "<br>", unsafe_allow_html=True
          )  # Spacing before table

          def style_rows(row):
            if row["Status"] == "ALLOWED":
              return [
                  "background-color: rgba(16, 185, 129, 0.1); color:"
                  " #047857;"
              ] * len(row)
            else:
              return [
                  "background-color: rgba(239, 68, 68, 0.1); color:"
                  " #b91c1c;"
              ] * len(row)

          st.dataframe(
              df.style.apply(style_rows, axis=1), use_container_width=True
          )
        else:
          st.info("No commands intercepted for this session yet.")
      else:
        st.warning("Unauthorized access or invalid session credentials.")
    except Exception as e:
      st.error(f"Backend offline or unreachable: {e}")
  else:
    st.info("Enter Session ID & Token in the sidebar to view live logs.")


render_dashboard()
