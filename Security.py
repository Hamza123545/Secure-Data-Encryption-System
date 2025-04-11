import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

# Initialize session state
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = {}
if 'lockout_time' not in st.session_state:
    st.session_state.lockout_time = {}
if 'current_user' not in st.session_state:
    st.session_state.current_user = None
if 'users' not in st.session_state:
    st.session_state.users = {"admin": hashlib.sha256("admin123".encode()).hexdigest()}  # Default admin

# File for persistent storage
DATA_FILE = "encrypted_data.json"

# Generate or load encryption key
if os.path.exists("key.key"):
    with open("key.key", "rb") as key_file:
        KEY = key_file.read()
else:
    KEY = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(KEY)
cipher = Fernet(KEY)

# Load or initialize data
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

# Save data to JSON
def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

# In-memory data storage (loaded from JSON)
stored_data = load_data()

# Function to hash passkey with PBKDF2
def hash_passkey(passkey, salt=b'salt_'):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(passkey.encode()))
    return key.decode()

# Function to encrypt data
def encrypt_data(text, passkey):
    return cipher.encrypt(text.encode()).decode()

# Function to decrypt data by passkey
def decrypt_data_by_passkey(passkey, username):
    hashed_passkey = hash_passkey(passkey)
    user_data = stored_data.get(username, {}).get("data", [])
    decrypted_results = []
    
    for data_entry in user_data:
        if data_entry["passkey"] == hashed_passkey:
            try:
                decrypted_text = cipher.decrypt(data_entry["encrypted_text"].encode()).decode()
                decrypted_results.append({
                    "encrypted_text": data_entry["encrypted_text"],
                    "decrypted_text": decrypted_text
                })
            except:
                continue  # Skip invalid entries
    
    if decrypted_results:
        st.session_state.failed_attempts[username] = 0
        return decrypted_results
    else:
        st.session_state.failed_attempts[username] = st.session_state.failed_attempts.get(username, 0) + 1
        return None

# Check lockout status
def is_locked_out(username):
    if username in st.session_state.lockout_time:
        if time.time() < st.session_state.lockout_time[username]:
            return True
        else:
            del st.session_state.lockout_time[username]
            st.session_state.failed_attempts[username] = 0
    return False

# Streamlit UI
st.title("🔒 Secure Data Encryption System")

# Authentication: Login or Register
if not st.session_state.current_user:
    auth_choice = st.sidebar.selectbox("Choose Action", ["Login", "Register"])
    
    if auth_choice == "Login":
        st.subheader("🔑 Login")
        username = st.text_input("Username", key="login_username")
        password = st.text_input("Password", type="password", key="login_password")
        
        if st.button("Login"):
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            if username in st.session_state.users and st.session_state.users[username] == hashed_password:
                st.session_state.current_user = username
                st.success("✅ Logged in successfully!")
                st.rerun()
            else:
                st.error("❌ Invalid credentials!")
    
    elif auth_choice == "Register":
        st.subheader("📝 Register")
        new_username = st.text_input("New Username", key="register_username")
        new_password = st.text_input("New Password", type="password", key="register_password")
        confirm_password = st.text_input("Confirm Password", type="password", key="register_confirm_password")
        
        if st.button("Register"):
            if new_username and new_password and confirm_password:
                if new_username in st.session_state.users:
                    st.error("⚠️ Username already exists!")
                elif new_password != confirm_password:
                    st.error("⚠️ Passwords do not match!")
                elif len(new_password) < 6:
                    st.error("⚠️ Password must be at least 6 characters long!")
                else:
                    st.session_state.users[new_username] = hashlib.sha256(new_password.encode()).hexdigest()
                    st.success(f"✅ User {new_username} registered successfully! Please login.")
                    st.rerun()
            else:
                st.error("⚠️ All fields are required!")
else:
    # Navigation
    menu = ["Home", "Store Data", "Retrieve Data", "Logout"]
    choice = st.sidebar.selectbox("Navigation", menu)

    if choice == "Home":
        st.subheader("🏠 Welcome to the Secure Data System")
        st.write(f"Logged in as: {st.session_state.current_user}")
        st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

    elif choice == "Store Data":
        st.subheader("📂 Store Data Securely")
        user_data = st.text_area("Enter Data:", key="store_data")
        passkey = st.text_input("Enter Passkey:", type="password", key="store_passkey")

        if st.button("Encrypt & Save"):
            if user_data and passkey:
                hashed_passkey = hash_passkey(passkey)
                encrypted_text = encrypt_data(user_data, passkey)
                
                # Initialize user data if not exists
                if st.session_state.current_user not in stored_data:
                    stored_data[st.session_state.current_user] = {"data": []}
                
                # Store data
                stored_data[st.session_state.current_user]["data"].append({
                    "encrypted_text": encrypted_text,
                    "passkey": hashed_passkey
                })
                
                save_data(stored_data)
                st.success("✅ Data stored securely!")
            else:
                st.error("⚠️ Both fields are required!")

    elif choice == "Retrieve Data":
        st.subheader("🔍 Retrieve Your Data")
        
        if is_locked_out(st.session_state.current_user):
            st.error("🔒 Account temporarily locked. Please try again later.")
        else:
            # Use a unique key for the passkey input to avoid pre-filling
            passkey = st.text_input("Enter Passkey:", type="password", key="retrieve_passkey", value="")
            attempts_left = 3 - st.session_state.failed_attempts.get(st.session_state.current_user, 0)

            st.write(f"Attempts remaining: {attempts_left}")

            if st.button("Decrypt"):
                if passkey:
                    decrypted_results = decrypt_data_by_passkey(passkey, st.session_state.current_user)

                    if decrypted_results:
                        st.success("✅ Decrypted Data:")
                        for result in decrypted_results:
                            st.write(f"- **Encrypted**: {result['encrypted_text']}")
                            st.write(f"  **Decrypted**: {result['decrypted_text']}")
                    else:
                        st.error(f"❌ Incorrect passkey! Attempts remaining: {attempts_left - 1}")

                        if st.session_state.failed_attempts.get(st.session_state.current_user, 0) >= 3:
                            st.session_state.lockout_time[st.session_state.current_user] = time.time() + 300  # 5-minute lockout
                            st.warning("🔒 Too many failed attempts! Account locked for 5 minutes.")
                            st.rerun()
                else:
                    st.error("⚠️ Passkey is required!")

    elif choice == "Logout":
        st.session_state.current_user = None
        st.success("✅ Logged out successfully!")
        st.rerun()

# Admin: Add new user (optional, kept for admin control)
if st.session_state.current_user == "admin":
    with st.expander("Admin: Add New User"):
        new_username = st.text_input("New Username (Admin)", key="admin_username")
        new_password = st.text_input("New Password (Admin)", type="password", key="admin_password")
        
        if st.button("Add User"):
            if new_username and new_password:
                if new_username in st.session_state.users:
                    st.error("⚠️ Username already exists!")
                else:
                    st.session_state.users[new_username] = hashlib.sha256(new_password.encode()).hexdigest()
                    st.success(f"✅ User {new_username} added!")
            else:
                st.error("⚠️ Both fields required!")