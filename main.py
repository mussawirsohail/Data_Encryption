import streamlit as st
import json
import os
from cryptography.fernet import Fernet

# Constants
DATA_FILE = "data.json"
SECRET_KEY = b'V3hKqcmQxv0NdyWQ71fAtD6dGkDgf_O9_WptOEBXt1g='  # Unique pre-generated Fernet key
fernet = Fernet(SECRET_KEY)

# Helper Functions
def load_data():
    if not os.path.exists(DATA_FILE):
        with open(DATA_FILE, "w") as f:
            json.dump({}, f)
    try:
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=2)

def validate_login(username, password):
    users = load_data()
    return username in users and users[username]["password"] == password

def register_user(username, password):
    users = load_data()
    if username in users:
        return False
    users[username] = {"password": password, "encrypted_data": []}
    save_data(users)
    return True

def store_encrypted_data(username, encrypted_message):
    users = load_data()
    users[username]["encrypted_data"].append(encrypted_message)
    save_data(users)

# Streamlit UI Configuration
st.set_page_config(page_title="Secure Data Vault", layout="centered")
st.title("🔒 Secure Data Vault")

# Session Management
if "is_logged_in" not in st.session_state:
    st.session_state.is_logged_in = False
    st.session_state.current_user = None

# Login / Signup Interface
if not st.session_state.is_logged_in:
    tabs = st.tabs(["🔑 Login", "📝 Signup"])

    with tabs[0]:
        st.subheader("Login to your Account")
        login_username = st.text_input("Username", key="login_username")
        login_password = st.text_input("Password", type="password", key="login_password")

        if st.button("Log In"):
            if validate_login(login_username, login_password):
                st.session_state.is_logged_in = True
                st.session_state.current_user = login_username
                st.session_state.is_logged_in = True
                st.session_state.current_user = login_username
            else:
                st.error("Invalid username or password.")

    with tabs[1]:
        st.subheader("Create a New Account")
        new_username = st.text_input("New Username", key="new_username")
        new_password = st.text_input("New Password", type="password", key="new_password")

        if st.button("Create Account"):
            if register_user(new_username, new_password):
                st.success("Account created successfully! Please log in.")
            else:
                st.warning("Username already exists.")

# Main App Interface (after Login)
else:
    st.subheader(f"Welcome, {st.session_state.current_user}!")
    app_menu = st.radio("Choose Action", ["🔐 Encrypt Data", "🔓 Decrypt Data", "📦 View Stored Data", "🚪 Log Out"])

    if app_menu == "🔐 Encrypt Data":
        text_input = st.text_area("Enter data to encrypt:")
        if st.button("Encrypt and Save"):
            if text_input:
                encrypted_message = fernet.encrypt(text_input.encode()).decode()
                st.success("Your encrypted data:")
                st.code(encrypted_message)
                store_encrypted_data(st.session_state.current_user, encrypted_message)
            else:
                st.warning("Please provide some text to encrypt.")

    elif app_menu == "🔓 Decrypt Data":
        encrypted_text = st.text_area("Paste encrypted message here:")
        if st.button("Decrypt"):
            if encrypted_text:
                try:
                    decrypted_message = fernet.decrypt(encrypted_text.encode()).decode()
                    st.success("Decrypted message:")
                    st.code(decrypted_message)
                except Exception:
                    st.error("Failed to decrypt. Invalid data or key.")
            else:
                st.warning("Please paste some encrypted text.")

    elif app_menu == "📦 View Stored Data":
        users_data = load_data()
        user_data = users_data.get(st.session_state.current_user, {}).get("encrypted_data", [])
        st.subheader("Your Encrypted Messages:")
        if user_data:
            for idx, msg in enumerate(user_data, 1):
                st.code(f"{idx}. {msg}")
        else:
            st.info("No encrypted messages found.")

    elif app_menu == "🚪 Log Out":
        st.session_state.is_logged_in = False
        st.session_state.current_user = None
        st.success("You have logged out successfully.")
