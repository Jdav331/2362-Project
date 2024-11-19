from flask import Flask, request, \
    jsonify  # Import Flask framework and libraries for handling HTTP requests and JSON responses.
import bcrypt  # Import bcrypt for hashing and verifying passwords.
import ssl  # Import ssl for setting up secure (SSL/TLS) communication.

app = Flask(__name__)  # Create a new Flask app instance.

# This will act as an in-memory database to store users for the sake of this simple demo.
users_db = {}

import logging  # Import Python's built-in logging library.

# Configure logging to log INFO level messages.
logging.basicConfig(level=logging.INFO)

# Log incoming requests for monitoring purposes.
@app.before_request
def log_request_info():
    logging.info(f"Request Headers: {request.headers}")  # Log the request headers.
    logging.info(f"Request Body: {request.get_data()}")  # Log the request body.



# Function to hash a password
def hash_password(password):
    salt = bcrypt.gensalt()  # Generate a salt (random data to strengthen the hash).
    return bcrypt.hashpw(password.encode('utf-8'),
                         salt)  # Hash the password using bcrypt and return the hashed password.


# Function to check if the provided password matches the stored hashed password.
def check_password(hashed_password, user_password):
    return bcrypt.checkpw(user_password.encode('utf-8'),
                          hashed_password)  # Use bcrypt to check if the password matches.


# Route for registering a new user.
@app.route('/register', methods=['POST'])  # Define a POST endpoint for user registration.
def register():
    data = request.get_json()  # Get the request data (JSON format) sent from the client.
    username = data['username']  # Extract the username from the data.
    password = data['password']  # Extract the password from the data.

    if username in users_db:  # Check if the username already exists in the database.
        return jsonify({'message': 'User already exists'}), 400  # If user exists, return an error message.

    hashed_password = hash_password(password)  # Hash the password before storing it.
    users_db[username] = hashed_password  # Store the hashed password in the database.
    return jsonify({'message': 'User registered successfully'}), 200  # Respond with a success message.


# Route for user login.
@app.route('/login', methods=['POST'])  # Define a POST endpoint for user login.
def login():
    data = request.get_json()  # Get the request data (JSON format).
    username = data['username']  # Extract the username.
    password = data['password']  # Extract the password.

    if username not in users_db:  # Check if the user exists in the database.
        return jsonify({'message': 'User not found'}), 404  # If user doesn't exist, return an error.

    stored_password = users_db[username]  # Retrieve the stored hashed password for the user.

    if check_password(stored_password, password):  # Check if the provided password matches the stored one.
        return jsonify({'message': 'Login successful!'}), 200  # If correct, return a success message.
    else:
        return jsonify({'message': 'Incorrect password'}), 401  # If incorrect, return an error message.


if __name__ == '__main__':
    # Set up SSL/TLS encryption using an SSL context.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)  # Use TLS protocol for encryption.
    context.load_cert_chain(certfile='cert.pem', keyfile='key.pem')  # Load your SSL certificate and private key.

    # Run the Flask app with SSL/TLS enabled. The app will listen on all IP addresses (0.0.0.0) on port 5000.
    app.run(host='0.0.0.0', port=5000, ssl_context=context)