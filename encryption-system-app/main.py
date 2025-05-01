import streamlit as st
from cryptography.fernet import Fernet
import hashlib
import base64
import os

# Persistent key generation/loading
def load_or_generate_key():
    key_file = "secret.key"
    if os.path.exists(key_file):
        with open(key_file, "rb") as f:
            key = f.read()
    else:
        key = Fernet.generate_key()
        with open(key_file, "wb") as f:
            f.write(key)
    return key

# Initialize encryption
key = load_or_generate_key()
cipher_suite = Fernet(key)

# Initialize session state
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False

def hash_passkey(passkey):
    """Hash the passkey using SHA-256 with salt"""
    salt = "secure_salt_"  # Add your own salt in production
    return hashlib.sha256((salt + passkey).encode()).hexdigest()

def encrypt_data(data, passkey):
    """Encrypt data using Fernet symmetric encryption"""
    try:
        return cipher_suite.encrypt(data.encode()).decode()
    except Exception as e:
        st.error(f"Encryption failed: {str(e)}")
        return None

def decrypt_data(encrypted_data, passkey):
    """Decrypt data using Fernet symmetric encryption"""
    try:
        return cipher_suite.decrypt(encrypted_data.encode()).decode()
    except:
        st.error("Decryption failed - invalid token or corrupted data")
        return None

def store_data(data_id, data, passkey):
    """Store encrypted data in memory"""
    hashed_passkey = hash_passkey(passkey)
    encrypted_text = encrypt_data(data, passkey)
    if encrypted_text is not None:
        st.session_state.stored_data[data_id] = {
            "encrypted_text": encrypted_text,
            "passkey": hashed_passkey
        }
        st.success("Data stored securely!")

def retrieve_data(data_id, passkey):
    """Retrieve and decrypt data if passkey is correct"""
    if data_id not in st.session_state.stored_data:
        st.error("Data ID not found!")
        return None
    
    stored_entry = st.session_state.stored_data[data_id]
    hashed_passkey = hash_passkey(passkey)
    
    if stored_entry["passkey"] == hashed_passkey:
        st.session_state.failed_attempts = 0  # Reset failed attempts
        decrypted_data = decrypt_data(stored_entry["encrypted_text"], passkey)
        if decrypted_data is not None:
            return decrypted_data
    else:
        st.session_state.failed_attempts += 1
        remaining_attempts = max(0, 3 - st.session_state.failed_attempts)
        st.error(f"Incorrect passkey! Attempts remaining: {remaining_attempts}")
        if st.session_state.failed_attempts >= 3:
            st.session_state.authenticated = False
            st.experimental_rerun()
        return None

def login_page():
    """Display login page after too many failed attempts"""
    st.title("🔒 Reauthorization Required")
    st.warning("Too many failed attempts. Please authenticate to continue.")
    
    login_passkey = st.text_input("Enter your admin passkey:", type="password")
    if st.button("Authenticate"):
        # In a real system, use proper password hashing and storage
        if login_passkey == "admin123":  # Replace with secure auth in production
            st.session_state.authenticated = True
            st.session_state.failed_attempts = 0
            st.experimental_rerun()
        else:
            st.error("Incorrect authentication passkey")

def home_page():
    """Display the main application interface"""
    st.title("🔐 Secure Data Encryption System")
    
    option = st.radio("Choose an option:", 
                     ("Store New Data", "Retrieve Data", "View Data IDs"))
    
    if option == "Store New Data":
        st.subheader("Store New Encrypted Data")
        data_id = st.text_input("Enter a unique ID for your data:")
        data = st.text_area("Enter the data to encrypt:")
        passkey = st.text_input("Enter a passkey:", type="password")
        confirm_passkey = st.text_input("Confirm passkey:", type="password")
        
        if st.button("Store Data Securely"):
            if passkey != confirm_passkey:
                st.error("Passkeys do not match!")
            elif not data_id or not data or not passkey:
                st.error("All fields are required!")
            elif data_id in st.session_state.stored_data:
                st.error("This data ID already exists!")
            else:
                store_data(data_id, data, passkey)
    
    elif option == "Retrieve Data":
        st.subheader("Retrieve Your Encrypted Data")
        data_id = st.text_input("Enter your data ID:")
        passkey = st.text_input("Enter your passkey:", type="password")
        
        if st.button("Decrypt Data"):
            if not data_id or not passkey:
                st.error("Both fields are required!")
            else:
                decrypted_data = retrieve_data(data_id, passkey)
                if decrypted_data is not None:
                    st.success("Data decrypted successfully!")
                    st.text_area("Decrypted Data:", value=decrypted_data, height=200)
    
    elif option == "View Data IDs":
        st.subheader("Available Data IDs")
        if st.session_state.stored_data:
            st.write("The following data IDs are stored:")
            for data_id in st.session_state.stored_data.keys():
                st.write(f"- {data_id}")
        else:
            st.info("No data has been stored yet.")

# Main app logic
def main():
    if st.session_state.failed_attempts >= 3 and not st.session_state.authenticated:
        login_page()
    else:
        home_page()

if __name__ == "__main__":
    main()