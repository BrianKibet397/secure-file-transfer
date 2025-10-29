from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_file
from flask_cors import CORS
import mysql.connector
from mysql.connector import Error
import bcrypt
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
import base64
import os
from datetime import datetime
from functools import wraps
import io

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-in-production'
CORS(app)

# Database Configuration
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': 'your_password',  # Change this
    'database': 'secure_file_transfer'
}

UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Database connection helper
def get_db_connection():
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        return conn
    except Error as e:
        print(f"Error connecting to MySQL: {e}")
        return None

# Initialize database
def init_db():
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        
        # Create users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(100) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                public_key TEXT NOT NULL,
                private_key TEXT NOT NULL,
                failed_attempts INT DEFAULT 0,
                locked_until DATETIME NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create files table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id INT AUTO_INCREMENT PRIMARY KEY,
                sender_id INT NOT NULL,
                receiver_id INT NOT NULL,
                filename VARCHAR(255) NOT NULL,
                encrypted_file LONGBLOB NOT NULL,
                encrypted_key TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                downloaded BOOLEAN DEFAULT FALSE,
                FOREIGN KEY (sender_id) REFERENCES users(id),
                FOREIGN KEY (receiver_id) REFERENCES users(id)
            )
        ''')
        
        # Create logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT,
                action VARCHAR(100) NOT NULL,
                details TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        
        conn.commit()
        cursor.close()
        conn.close()
        print("Database initialized successfully")

# Decorator for login required
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'success': False, 'message': 'Login required'}), 401
        return f(*args, **kwargs)
    return decorated_function

# Log action
def log_action(user_id, action, details=''):
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO logs (user_id, action, details) VALUES (%s, %s, %s)',
            (user_id, action, details)
        )
        conn.commit()
        cursor.close()
        conn.close()

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password required'})
    
    # Generate RSA key pair
    key = RSA.generate(2048)
    private_key = key.export_key().decode('utf-8')
    public_key = key.publickey().export_key().decode('utf-8')
    
    # Hash password
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO users (username, password_hash, public_key, private_key) VALUES (%s, %s, %s, %s)',
                (username, password_hash, public_key, private_key)
            )
            conn.commit()
            user_id = cursor.lastrowid
            log_action(user_id, 'REGISTER', f'User {username} registered')
            cursor.close()
            conn.close()
            return jsonify({'success': True, 'message': 'Registration successful'})
        except mysql.connector.IntegrityError:
            return jsonify({'success': False, 'message': 'Username already exists'})
        except Exception as e:
            return jsonify({'success': False, 'message': str(e)})
    
    return jsonify({'success': False, 'message': 'Database connection failed'})

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        user = cursor.fetchone()
        
        if user:
            # Check if account is locked
            if user['locked_until'] and datetime.now() < user['locked_until']:
                cursor.close()
                conn.close()
                return jsonify({'success': False, 'message': 'Account temporarily locked. Try again later.'})
            
            # Verify password
            if bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
                # Reset failed attempts
                cursor.execute('UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = %s', (user['id'],))
                conn.commit()
                
                session['user_id'] = user['id']
                session['username'] = user['username']
                
                log_action(user['id'], 'LOGIN', f'User {username} logged in')
                cursor.close()
                conn.close()
                return jsonify({'success': True, 'message': 'Login successful'})
            else:
                # Increment failed attempts
                failed_attempts = user['failed_attempts'] + 1
                if failed_attempts >= 3:
                    from datetime import timedelta
                    locked_until = datetime.now() + timedelta(minutes=15)
                    cursor.execute('UPDATE users SET failed_attempts = %s, locked_until = %s WHERE id = %s',
                                 (failed_attempts, locked_until, user['id']))
                    conn.commit()
                    log_action(user['id'], 'LOCKED', f'Account locked due to failed attempts')
                    cursor.close()
                    conn.close()
                    return jsonify({'success': False, 'message': 'Account locked for 15 minutes due to multiple failed attempts'})
                else:
                    cursor.execute('UPDATE users SET failed_attempts = %s WHERE id = %s', (failed_attempts, user['id']))
                    conn.commit()
                    cursor.close()
                    conn.close()
                    return jsonify({'success': False, 'message': f'Invalid credentials. {3 - failed_attempts} attempts remaining.'})
        
        cursor.close()
        conn.close()
        return jsonify({'success': False, 'message': 'Invalid credentials'})
    
    return jsonify({'success': False, 'message': 'Database connection failed'})

@app.route('/logout')
@login_required
def logout():
    user_id = session.get('user_id')
    username = session.get('username')
    log_action(user_id, 'LOGOUT', f'User {username} logged out')
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=session.get('username'))

@app.route('/get_users')
@login_required
def get_users():
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT id, username FROM users WHERE id != %s', (session['user_id'],))
        users = cursor.fetchall()
        cursor.close()
        conn.close()
        return jsonify({'success': True, 'users': users})
    return jsonify({'success': False, 'message': 'Database error'})

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file provided'})
    
    file = request.files['file']
    receiver_id = request.form.get('receiver_id')
    
    if not receiver_id:
        return jsonify({'success': False, 'message': 'No receiver specified'})
    
    # Read file content
    file_content = file.read()
    filename = file.filename
    
    # Get receiver's public key
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT public_key FROM users WHERE id = %s', (receiver_id,))
        receiver = cursor.fetchone()
        
        if not receiver:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'message': 'Receiver not found'})
        
        # Generate AES key
        aes_key = get_random_bytes(32)  # 256-bit key
        
        # Encrypt file with AES
        cipher_aes = AES.new(aes_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(file_content)
        
        # Combine nonce, tag, and ciphertext
        encrypted_file = cipher_aes.nonce + tag + ciphertext
        
        # Encrypt AES key with receiver's RSA public key
        rsa_key = RSA.import_key(receiver['public_key'])
        cipher_rsa = PKCS1_OAEP.new(rsa_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)
        encrypted_aes_key_b64 = base64.b64encode(encrypted_aes_key).decode('utf-8')
        
        # Store in database
        cursor.execute(
            'INSERT INTO files (sender_id, receiver_id, filename, encrypted_file, encrypted_key) VALUES (%s, %s, %s, %s, %s)',
            (session['user_id'], receiver_id, filename, encrypted_file, encrypted_aes_key_b64)
        )
        conn.commit()
        
        log_action(session['user_id'], 'UPLOAD', f'File {filename} uploaded to user {receiver_id}')
        
        cursor.close()
        conn.close()
        
        return jsonify({'success': True, 'message': 'File uploaded and encrypted successfully'})
    
    return jsonify({'success': False, 'message': 'Database error'})

@app.route('/get_files')
@login_required
def get_files():
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute('''
            SELECT f.id, f.filename, f.timestamp, f.downloaded, u.username as sender
            FROM files f
            JOIN users u ON f.sender_id = u.id
            WHERE f.receiver_id = %s
            ORDER BY f.timestamp DESC
        ''', (session['user_id'],))
        files = cursor.fetchall()
        cursor.close()
        conn.close()
        
        # Convert datetime to string
        for file in files:
            file['timestamp'] = file['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
        
        return jsonify({'success': True, 'files': files})
    
    return jsonify({'success': False, 'message': 'Database error'})

@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor(dictionary=True)
        
        # Get file and user's private key
        cursor.execute('''
            SELECT f.filename, f.encrypted_file, f.encrypted_key, u.private_key
            FROM files f
            JOIN users u ON u.id = %s
            WHERE f.id = %s AND f.receiver_id = %s
        ''', (session['user_id'], file_id, session['user_id']))
        
        result = cursor.fetchone()
        
        if not result:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'message': 'File not found or access denied'})
        
        try:
            # Decrypt AES key with user's RSA private key
            private_key = RSA.import_key(result['private_key'])
            cipher_rsa = PKCS1_OAEP.new(private_key)
            encrypted_aes_key = base64.b64decode(result['encrypted_key'])
            aes_key = cipher_rsa.decrypt(encrypted_aes_key)
            
            # Decrypt file with AES
            encrypted_file = result['encrypted_file']
            nonce = encrypted_file[:16]
            tag = encrypted_file[16:32]
            ciphertext = encrypted_file[32:]
            
            cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
            decrypted_file = cipher_aes.decrypt_and_verify(ciphertext, tag)
            
            # Mark as downloaded
            cursor.execute('UPDATE files SET downloaded = TRUE WHERE id = %s', (file_id,))
            conn.commit()
            
            log_action(session['user_id'], 'DOWNLOAD', f'File {result["filename"]} downloaded')
            
            cursor.close()
            conn.close()
            
            # Send file
            return send_file(
                io.BytesIO(decrypted_file),
                as_attachment=True,
                download_name=result['filename']
            )
            
        except Exception as e:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'message': f'Decryption failed: {str(e)}'})
    
    return jsonify({'success': False, 'message': 'Database error'})

@app.route('/get_logs')
@login_required
def get_logs():
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute('''
            SELECT action, details, timestamp
            FROM logs
            WHERE user_id = %s
            ORDER BY timestamp DESC
            LIMIT 50
        ''', (session['user_id'],))
        logs = cursor.fetchall()
        cursor.close()
        conn.close()
        
        for log in logs:
            log['timestamp'] = log['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
        
        return jsonify({'success': True, 'logs': logs})
    
    return jsonify({'success': False, 'message': 'Database error'})

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)