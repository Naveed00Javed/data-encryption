import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Initialize storage
stored_data = {}
failed_attempts = {}
login_authenticated = True

# Generate a Fernet Key (this can be static for the session)
fernet_key = Fernet.generate_key()
fernet = Fernet(fernet_key)

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return fernet.encrypt(text.encode()).decode()

def decrypt_data(cipher_text):
    return fernet.decrypt(cipher_text.encode()).decode()

def reauthorization():
    global login_authenticated
    st.title("🔒 Reauthorization Required")
    password = st.text_input("Enter admin password to continue:", type="password")
    if st.button("Login"):
        if password == "admin123":  # Simple hardcoded admin password
            login_authenticated = True
            for user in failed_attempts:
                failed_attempts[user] = 0
            st.success("Reauthorization successful!")
        else:
            st.error("Wrong admin password!")

# Streamlit App
st.title("🛡️ Secure Data Encryption System")

if "page" not in st.session_state:
    st.session_state.page = "Home"

if not login_authenticated:
    reauthorization()
else:
    menu = st.sidebar.selectbox("Navigate", ["Home", "Insert Data", "Retrieve Data"])

    if menu == "Home":
        st.header("Welcome to the Secure Data Manager")
        st.write("Use the sidebar to navigate.")

    elif menu == "Insert Data":
        st.header("📥 Insert New Data")
        username = st.text_input("Username")
        text = st.text_area("Enter the data to encrypt")
        passkey = st.text_input("Create a passkey", type="password")

        if st.button("Encrypt & Store"):
            if username and text and passkey:
                encrypted_text = encrypt_data(text)
                hashed_passkey = hash_passkey(passkey)
                stored_data[username] = {"encrypted_text": encrypted_text, "passkey": hashed_passkey}
                failed_attempts[username] = 0
                st.success("Data encrypted and stored successfully!")
            else:
                st.error("All fields are required!")

    elif menu == "Retrieve Data":
        st.header("📤 Retrieve Your Data")
        username = st.text_input("Enter your username")
        passkey = st.text_input("Enter your passkey", type="password")

        if st.button("Decrypt"):
            if username in stored_data:
                hashed_passkey = hash_passkey(passkey)
                if hashed_passkey == stored_data[username]["passkey"]:
                    decrypted_text = decrypt_data(stored_data[username]["encrypted_text"])
                    st.success("Decryption Successful!")
                    st.text_area("Your Decrypted Data:", decrypted_text, height=150)
                    failed_attempts[username] = 0
                else:
                    failed_attempts[username] += 1
                    attempts_left = 3 - failed_attempts[username]
                    if attempts_left > 0:
                        st.error(f"Wrong passkey! Attempts left: {attempts_left}")
                    else:
                        login_authenticated = False
                        st.error("Too many failed attempts! Redirecting to login...")
            else:
                st.error("Username not found!")
