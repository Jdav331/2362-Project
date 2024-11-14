from flask import Flask, request, jsonify, send_file  # Import Flask functions for server, JSON, and file sending
import bcrypt  # Import bcrypt for password hashing
import ssl  # Import ssl for secure (TLS/SSL) connections
import os  # Import os for file and directory operations

app = Flask(__name__)  # Create a Flask application instance

# This will act as an in-memory database for user data (for demo purposes only)
users_db = {}

# Directory to save uploaded files
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)  # Create the 'uploads' folder if it doesn't exist


# Function to hash a password before storing it
def hash_password(password):
    salt = bcrypt.gensalt()  # Generate random data to make the hash stronger
    return bcrypt.hashpw(password.encode('utf-8'), salt)  # Hash the password and return it


# Function to check if a provided password matches a stored hashed password
def check_password(hashed_password, user_password):
    return bcrypt.checkpw(user_password.encode('utf-8'), hashed_password)  # Compare hashed and plain passwords


# Route for registering a new user
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()  # Get the JSON data from the request
    username = data['username']  # Extract the username
    password = data['password']  # Extract the password

    if username in users_db:  # Check if the user already exists
        return jsonify({'message': 'User already exists'}), 400  # Return error if user exists

    hashed_password = hash_password(password)  # Hash the password for secure storage
    users_db[username] = hashed_password  # Save the username and hashed password in our database
    return jsonify({'message': 'User registered successfully'}), 200  # Confirm registration success


# Route for user login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()  # Get the JSON data from the request
    username = data['username']  # Extract the username
    password = data['password']  # Extract the password

    if username not in users_db:  # Check if the user exists
        return jsonify({'message': 'User not found'}), 404  # Return error if user doesn't exist

    stored_password = users_db[username]  # Retrieve the stored hashed password

    if check_password(stored_password, password):  # Check if provided password matches stored hash
        return jsonify({'message': 'Login successful!'}), 200  # Confirm login success
    else:
        return jsonify({'message': 'Incorrect password'}), 401  # Return error if password is incorrect


# Route for file upload
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:  # Check if the file part is in the request
        return jsonify({'message': 'No file part in the request'}), 400
    file = request.files['file']  # Get the file from the request
    if file.filename == '':  # Check if a file was selected
        return jsonify({'message': 'No selected file'}), 400
    file_path = os.path.join(UPLOAD_FOLDER, file.filename)  # Define where to save the file
    file.save(file_path)  # Save the file to the specified path
    return jsonify({'message': f'File {file.filename} uploaded successfully'}), 200  # Confirm file upload success

# adding change to commit

# Route for file download
@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    file_path = os.path.join(UPLOAD_FOLDER, filename)  # Define the path to the file
    if not os.path.exists(file_path):  # Check if the file exists
        return jsonify({'message': 'File not found'}), 404  # Return error if file doesn't exist
    return send_file(file_path, as_attachment=True)  # Send the file as an attachment to download


if __name__ == '__main__':
    # Set up SSL/TLS encryption for secure communication
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)  # Specify TLS protocol for secure connection
    context.load_cert_chain(certfile='cert.pem', keyfile='key.pem')  # Load the SSL certificate and private key
    app.run(host='0.0.0.0', port=5000, ssl_context=context)  # Start the app on https://localhost:5000
