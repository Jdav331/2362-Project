from flask import Flask, request, jsonify, send_file
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import bcrypt
import ssl
import os

app = Flask(__name__)

# In-memory database for user data
users_db = {}

# Directory to save uploaded files
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Generate a key from a password
def generate_key(password: str, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Encrypt the file
def encrypt_file(file_path, password):
    salt = os.urandom(16)  # Generate random salt
    key = generate_key(password, salt)  # Derive key using password and salt
    iv = os.urandom(16)  # Generate random IV
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Read file data and encrypt
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Save encrypted file with salt and IV prepended
    encrypted_path = f"{file_path}.enc"
    with open(encrypted_path, 'wb') as f:
        f.write(salt + iv + ciphertext)

    return encrypted_path

# Decrypt the file
def decrypt_file(encrypted_path, password):
    with open(encrypted_path, 'rb') as f:
        file_data = f.read()

    # Extract salt, IV, and ciphertext
    salt = file_data[:16]
    iv = file_data[16:32]
    ciphertext = file_data[32:]

    # Derive key and decrypt
    key = generate_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Save decrypted file
    decrypted_path = encrypted_path.replace('.enc', '.decrypted')
    with open(decrypted_path, 'wb') as f:
        f.write(plaintext)

    return decrypted_path

# Hash password
def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt)

# Check hashed password
def check_password(hashed_password, user_password):
    return bcrypt.checkpw(user_password.encode('utf-8'), hashed_password)

# Register route
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data['username']
    password = data['password']

    if username in users_db:
        return jsonify({'message': 'User already exists'}), 400

    hashed_password = hash_password(password)
    users_db[username] = hashed_password
    return jsonify({'message': 'User registered successfully'}), 200

# Login route
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']

    if username not in users_db:
        return jsonify({'message': 'User not found'}), 404

    stored_password = users_db[username]
    if check_password(stored_password, password):
        return jsonify({'message': 'Login successful!'}), 200
    else:
        return jsonify({'message': 'Incorrect password'}), 401

# Upload route
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'message': 'No file part in the request'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'message': 'No selected file'}), 400

    file_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(file_path)

    # Encrypt the file
    password = "securepassword123"
    encrypted_path = encrypt_file(file_path, password)
    os.remove(file_path)

    return jsonify({'message': f'File {file.filename} encrypted and uploaded successfully'}), 200

# Download route
@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    encrypted_path = os.path.join(UPLOAD_FOLDER, f"{filename}.enc")
    if not os.path.exists(encrypted_path):
        return jsonify({'message': 'File not found'}), 404

    # Decrypt the file
    password = "securepassword123"
    decrypted_path = decrypt_file(encrypted_path, password)

    return send_file(decrypted_path, as_attachment=True)

if __name__ == '__main__':
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.load_cert_chain(certfile='cert.pem', keyfile='key.pem')
    app.run(host='0.0.0.0', port=5000, ssl_context=context)
