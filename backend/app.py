from flask import Flask, request, jsonify, send_file
from flask_mysqldb import MySQL
from flask_cors import CORS
from flask_bcrypt import Bcrypt
import config
import os
from werkzeug.utils import secure_filename
from datetime import datetime
from Crypto.Cipher import AES
from pathlib import Path

app = Flask(__name__)
CORS(app)
bcrypt = Bcrypt(app)

# MySQL Config
app.config['MYSQL_HOST'] = config.MYSQL_HOST
app.config['MYSQL_USER'] = config.MYSQL_USER
app.config['MYSQL_PASSWORD'] = config.MYSQL_PASSWORD
app.config['MYSQL_DB'] = config.MYSQL_DB

mysql = MySQL(app)

# For Upload folder and AES Key
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

SECRET_KEY = b'your16byteaeskey'  # 16 bytes key for AES-128

def pad(data):
    while len(data) % 16 != 0:
        data += b' '
    return data

@app.route('/')
def home():
    return "✅ Time Lock Backend is running!"

# ✅ Register Endpoint
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data['username']
    email = data['email']
    password = data['password']

    if not username or not email or not password:
        return jsonify({'error': 'All fields are required'}), 400

    cursor = mysql.connection.cursor()
    # Check if user exists
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    existing_user = cursor.fetchone()
    if existing_user:
        return jsonify({'error': 'User already exists'}), 400

    hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
    cursor.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)", (username, email, hashed_pw))
    mysql.connection.commit()
    cursor.close()
    return jsonify({'message': 'User registered successfully!'}), 201

# ✅ Login Endpoint
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data['email']
    password = data['password']

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()
    cursor.close()

    if user and bcrypt.check_password_hash(user[3], password):
        return jsonify({'message': 'Login successful', 'user_id': user[0], 'username': user[1]}), 200
    else:
        return jsonify({'error': 'Invalid email or password'}), 401

# ✅ Upload Endpoint
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    user_id = request.form['user_id']
    unlock_time = request.form['unlock_time']  # Format: "2025-04-25 18:00:00"
    unlock_time_obj = datetime.strptime(unlock_time, '%Y-%m-%dT%H:%M')


    # Save original file name
    original_filename = secure_filename(file.filename)
    file_data = file.read()

    # Encrypt file
    cipher = AES.new(SECRET_KEY, AES.MODE_ECB)
    encrypted_data = cipher.encrypt(pad(file_data))

    encrypted_filename = f"enc_{int(datetime.now().timestamp())}_{original_filename}"
    encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)

    with open(encrypted_path, 'wb') as f:
        f.write(encrypted_data)

    # Save metadata to database
    cursor = mysql.connection.cursor()
    cursor.execute(""" 
        INSERT INTO files (user_id, original_filename, encrypted_filename, unlock_time)
        VALUES (%s, %s, %s, %s)
    """, (user_id, original_filename, encrypted_filename, unlock_time_obj))
    mysql.connection.commit()
    cursor.close()

    return jsonify({'message': 'File uploaded and encrypted successfully!'})

@app.route('/decrypt', methods=['POST'])
def decrypt_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    encrypted_filename = file.filename

    # Fetch original filename and unlock time
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT original_filename, unlock_time FROM files WHERE encrypted_filename = %s", (encrypted_filename,))
    result = cursor.fetchone()
    cursor.close()

    if not result:
        return jsonify({'error': 'Invalid encrypted file name'}), 404

    original_filename, unlock_time = result
    current_time = datetime.now()

    if current_time < unlock_time:
        return jsonify({'error': f'File is locked until {unlock_time}. Please try again later.'}), 403

    file_data = file.read()
    cipher = AES.new(SECRET_KEY, AES.MODE_ECB)
    decrypted_data = cipher.decrypt(file_data).rstrip(b' ')

    base_dir = Path(__file__).resolve().parent
    output_dir = base_dir / "decrypted_files"
    output_dir.mkdir(parents=True, exist_ok=True)

    output_path = output_dir / original_filename
    with open(output_path, "wb") as f:
        f.write(decrypted_data)

    from mimetypes import guess_type
    mime_type, _ = guess_type(str(output_path))

    return send_file(
        str(output_path),
        as_attachment=True,
        download_name=original_filename,
        mimetype=mime_type or 'application/octet-stream'
    )


if __name__ == '__main__':
    app.run(debug=True)