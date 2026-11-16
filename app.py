import streamlit as st
import re
import math
import secrets
import string
import hashlib
import pandas as pd

# Page Configuration
st.set_page_config(page_title="PassVault AI | Security Auditor", page_icon="🔐", layout="wide")

# Custom CSS for Clean UI
st.markdown("""
    <style>
    .main-header {
        background: linear-gradient(90deg, #0f172a, #1e293b);
        padding: 20px;
        border-radius: 12px;
        color: white;
        margin-bottom: 20px;
        border-left: 6px solid #38bdf8;
    }
    .metric-box {
        background-color: #1e293b;
        padding: 15px;
        border-radius: 8px;
        color: #f8fafc;
        text-align: center;
    }
    </style>
""", unsafe_allow_html=True)

# Sidebar - Student & University Details
with st.sidebar:
    st.markdown("### 🎓 Student Profile")
    st.info(
        "**Name:** Rahul Attri\n\n"
        "**Roll No:** 25801072\n\n"
        "**Course:** B.Tech CSE\n\n"
        "**University:** Sant Baba Bhag Singh University (SBBSU)"
    )
    st.markdown("---")
    st.markdown("### 🛠️ Tech Stack")
    st.write("- **Language:** Python 3.x")
    st.write("- **Framework:** Streamlit")
    st.write("- **Security:** `hashlib`, `secrets`")
    st.write("- **Analysis:** Regex & Entropy Math")

# Main Header
st.markdown("""
    <div class="main-header">
        <h2 style="margin:0;">🔐 PassVault AI: Cyber Security & Password Auditor</h2>
        <p style="margin:5px 0 0 0; opacity: 0.85;">
            AI-Heuristic Password Strength Analyzer, Cryptographic Generator & Hash Converter
        </p>
    </div>
""", unsafe_allow_html=True)

# Helper Function: Calculate Entropy & Strength
def analyze_password(password):
    if not password:
        return 0, "Empty", 0, []
    
    pool_size = 0
    feedback = []
    
    if re.search(r"[a-z]", password):
        pool_size += 26
    else:
        feedback.append("Add lowercase letters (a-z).")
        
    if re.search(r"[A-Z]", password):
        pool_size += 26
    else:
        feedback.append("Add uppercase letters (A-Z).")
        
    if re.search(r"\d", password):
        pool_size += 10
    else:
        feedback.append("Include numbers (0-9).")
        
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        pool_size += 32
    else:
        feedback.append("Add special symbols (!@#$%^&*).")

    if len(password) < 8:
        feedback.append("Increase password length to at least 12 characters.")

    # Common weak pattern check
    common_patterns = ["123", "password", "admin", "qwerty", "welcome", "rahul", "2026"]
    for pattern in common_patterns:
        if pattern in password.lower():
            feedback.append(f"⚠️ Warning: Contains predictable sequence '{pattern}'.")

    # Entropy calculation: E = L * log2(R)
    entropy = round(len(password) * math.log2(pool_size), 2) if pool_size > 0 else 0
    
    if entropy < 40:
        status = "Weak 🔴"
    elif entropy < 65:
        status = "Moderate 🟡"
    elif entropy < 85:
        status = "Strong 🟢"
    else:
        status = "Very Strong 🛡️"
        
    # Estimated brute-force crack time (assuming 10 billion guesses/sec)
    combinations = pool_size ** len(password) if pool_size > 0 else 0
    seconds_to_crack = combinations / 1e10
    
    return entropy, status, seconds_to_crack, feedback

def format_crack_time(seconds):
    if seconds < 1:
        return "Instantly (< 1 sec)"
    elif seconds < 60:
        return f"{int(seconds)} Seconds"
    elif seconds < 3600:
        return f"{int(seconds // 60)} Minutes"
    elif seconds < 86400:
        return f"{int(seconds // 3600)} Hours"
    elif seconds < 31536000:
        return f"{int(seconds // 86400)} Days"
    else:
        years = int(seconds // 31536000)
        return f"{years:,} Years" if years < 1e9 else "Centuries (Uncrackable)"

# Navigation Tabs
tab1, tab2, tab3 = st.tabs([
    "🔍 AI Password Auditor", 
    "⚡ Cryptographic Generator", 
    "🔒 SHA-256 Hash Lab"
])

# TAB 1: Password Auditor
with tab1:
    st.subheader("Evaluate Password Security & Brute-Force Resistance")
    user_pwd = st.text_input("Enter a password to test:", type="password", placeholder="Type a password here...")
    
    if user_pwd:
        entropy, status, crack_sec, suggestions = analyze_password(user_pwd)
        
        col1, col2, col3 = st.columns(3)
        col1.metric("Security Rating", status)
        col2.metric("Entropy Score (Bits)", f"{entropy} bits")
        col3.metric("Est. Crack Time (GPU Attack)", format_crack_time(crack_sec))
        
        st.progress(min(int(entropy), 100) / 100)
        
        if suggestions:
            st.warning("### 🛠️ AI Security Recommendations:")
            for item in suggestions:
                st.write(f"- {item}")
        else:
            st.success("✅ Excellent! This password passes all security and complexity checks.")

# TAB 2: Password Generator
with tab2:
    st.subheader("Generate Cryptographically Secure Passwords")
    col_a, col_b = st.columns(2)
    
    with col_a:
        pwd_length = st.slider("Select Password Length", min_value=8, max_value=32, value=16)
        use_upper = st.checkbox("Include Uppercase (A-Z)", value=True)
        use_Digits = st.checkbox("Include Numbers (0-9)", value=True)
        use_symbols = st.checkbox("Include Symbols (!@#$%)", value=True)
        
    with col_b:
        if st.button("🚀 Generate Secure Password", use_container_width=True):
            chars = string.ascii_lowercase
            if use_upper:
                chars += string.ascii_uppercase
            if use_Digits:
                chars += string.digits
            if use_symbols:
                chars += "!@#$%^&*()-_=+[]{}|;:,.<>?"
                
            generated_pwd = "".join(secrets.choice(chars) for _ in range(pwd_length))
            st.code(generated_pwd, language="text")
            st.success("Generated using Python's `secrets` module (CSPRNG standard).")

# TAB 3: Cryptographic Hash Lab
with tab3:
    st.subheader("One-Way Cryptographic Hashing (SHA-256 & MD5)")
    st.write("Convert plain text or passwords into irreversible cryptographic hashes used in database storage.")
    
    raw_text = st.text_input("Enter text to hash:", placeholder="e.g., Rahul_SBBSU_2026")
    if raw_text:
        sha256_hash = hashlib.sha256(raw_text.encode()).hexdigest()
        md5_hash = hashlib.md5(raw_text.encode()).hexdigest()
        
        st.write("**SHA-256 Hash (Recommended Industry Standard):**")
        st.code(sha256_hash)
        
        st.write("**MD5 Hash (Legacy Checksum):**")
        st.code(md5_hash)
