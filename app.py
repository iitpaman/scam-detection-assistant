import re
import streamlit as st
from detector import analyze_message, get_matched_words
from link_checker import analyze_links

st.set_page_config(page_title="Scam Detection Assistant", page_icon="🛡️")

st.markdown("""
    <style>
    .stButton>button {
        border-radius: 8px;
        font-weight: 600;
        padding: 0.5rem 1.5rem;
    }
    [data-testid="stMetricValue"] {
        font-size: 1.8rem;
    }
    h1 {
        background: linear-gradient(90deg, #3B82F6, #06B6D4);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    </style>
""", unsafe_allow_html=True)

if "total_checked" not in st.session_state:
    st.session_state.total_checked = 0
    st.session_state.total_risky = 0

with st.sidebar:
    st.subheader("📊 Session Stats")
    st.metric("Messages Checked", st.session_state.total_checked)
    st.metric("Flagged as Risky", st.session_state.total_risky)

st.title("🛡️ Citizen Scam Detection & Reporting Assistant")
st.write(
    "Paste any suspicious SMS, WhatsApp, or email message below. "
    "This tool checks it for common scam patterns and helps you report it."
)

message = st.text_area("Paste the message here:", height=120)

def highlight_message(text, matched_words):
    highlighted = text
    for word in sorted(set(matched_words), key=len, reverse=True):
        pattern = re.compile(re.escape(word), re.IGNORECASE)
        highlighted = pattern.sub(f":red[**{word}**]", highlighted)
    return highlighted

if st.button("Analyze Message", type="primary"):
    if not message.strip():
        st.warning("Please paste a message first.")
    else:
        risk, flags, confidence = analyze_message(message)
        matched_words = get_matched_words(message)

        # ---------- NEW: Link Check ----------
        link_results, link_risk = analyze_links(message)

        # Agar link High Risk hai toh final result ek level upar
        if link_risk == "High Risk":
            if risk in ("Safe", "Likely Safe"):
                risk = "Suspicious"
            elif risk == "Suspicious":
                risk = "High Risk"
            flags = list(flags) + ["dangerous_link"]
        # -------------------------------------

        st.session_state.total_checked += 1
        if risk in ("High Risk", "Suspicious"):
            st.session_state.total_risky += 1

        if risk == "High Risk":
            st.error(f"⚠️ **{risk}**")
        elif risk == "Suspicious":
            st.warning(f"🟠 **{risk}**")
        else:
            st.success(f"✅ **{risk}**")

        st.metric("Scam Probability (ML model)", f"{confidence*100:.0f}%")
        st.progress(min(confidence, 1.0))

        if matched_words:
            st.subheader("Flagged text")
            st.markdown(highlight_message(message, matched_words))

        st.subheader("Why?")
        flag_labels = {
            "urgency": "Creates false urgency",
            "credential_request": "Asks for OTP/PIN/password/Aadhaar",
            "suspicious_link": "Contains a suspicious link/click instruction",
            "money_lure": "Promises money, prizes, or lottery winnings",
            "payment_pressure": "Pressures you to pay a fee immediately",
            "dangerous_link": "Contains a high-risk link (see Link Check below)",
        }
        if flags:
            for flag in flags:
                st.markdown(f"- {flag_labels.get(flag, flag)}")
        else:
            st.markdown("- No rule-based red flags detected")

        # ---------- NEW: Link Check section ----------
        st.subheader("🔗 Link Check")
        if not link_results:
            st.caption("No links found in this message.")
        else:
            for r in link_results:
                if r["risk"] == "High Risk":
                    st.error(f"🔴 **High Risk** — `{r['url']}`")
                elif r["risk"] == "Suspicious":
                    st.warning(f"🟠 **Suspicious** — `{r['url']}`")
                else:
                    st.success(f"🟢 **Looks safe** — `{r['url']}`")
                for reason in r["reasons"]:
                    st.markdown(f"- {reason}")
            st.caption("Note: Links are never opened — only their name and structure are checked.")
        # ---------------------------------------------

        if risk in ("High Risk", "Suspicious"):
            st.subheader("What should you do?")
            st.markdown(
                "- **Do not** click any links or share OTP/PIN/passwords\n"
                "- Verify directly with the bank/company using their official number\n"
                "- Report at [cybercrime.gov.in](https://cybercrime.gov.in) or call **1930**"
            )

st.caption("Built for Hack for Social Cause 2027 — Digital Safety & Cyber Fraud Awareness track.")