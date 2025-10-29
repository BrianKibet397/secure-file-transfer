from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_file
from flask_cors import CORS
from datetime import timedelta
import os
import io

# Import our custom modules
import database as db
import auth
import encryption
from config import get_config

# Get configuration based on environment
config = get_config()

app = Flask(__name__)
app.config.from_object(config)
CORS(app)

UPLOAD_FOLDER = app.config['UPLOAD_FOLDER']
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# ==================== Routes ====================

@app.route('/')
def index():
    """Home page - redirect to dashboard if logged in, otherwise login"""
    if auth.is_authenticated():
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

# ==================== Authentication Routes ====================

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if request.method == 'GET':
        # Already logged in? Redirect to dashboard
        if auth.is_authenticated():
            return redirect(url_for('dashboard'))
        return render_template('register.html')
    
    # POST request - process registration
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    success, message, user_id = auth.register_user(username, password)
    
    return jsonify({'success': success, 'message': message})

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if request.method == 'GET':
        # Already logged in? Redirect to dashboard
        if auth.is_authenticated():
            return redirect(url_for('dashboard'))
        return render_template('login.html')
    
    # POST request - process login
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    success, message, user = auth.login_user(username, password)
    
    if success:
        auth.create_session(user)
    
    return jsonify({'success': success, 'message': message})

@app.route('/logout')
@auth.login_required
def logout():
    """User logout"""
    user_id = auth.get_session_user_id()
    username = auth.get_session_username()
    
    if user_id and username:
        auth.logout_user(user_id, username)
    
    return redirect(url_for('login'))

# ==================== Dashboard Routes ====================

@app.route('/dashboard')
@auth.login_required
def dashboard():
    """Main dashboard"""
    username = auth.get_session_username()
    return render_template('dashboard.html', username=username)

# ==================== User Routes ====================

@app.route('/get_users')
@auth.login_required
def get_users():
    """Get list of all users except current user"""
    user_id = auth.get_session_user_id()
    
    if not user_id:
        return jsonify({'success': False, 'message': 'User session not found'}), 401
    
    users = db.get_all_users_except(user_id)
    
    # Format created_at if present
    for user in users:
        if 'created_at' in user and user['created_at']:
            user['created_at'] = user['created_at'].strftime('%Y-%m-%d')
    
    return jsonify({
        'success': True, 
        'users': users,
        'count': len(users)
    })

@app.route('/validate_username/<username>')
@auth.login_required
def validate_username(username):
    """Validate if username exists and is not current user"""
    current_user_id = auth.get_session_user_id()
    user = db.get_user_by_username(username)
    
    if not user:
        return jsonify({
            'success': False, 
            'message': 'User not found',
            'exists': False
        })
    
    if user['id'] == current_user_id:
        return jsonify({
            'success': False,
            'message': 'Cannot send file to yourself',
            'exists': True,
            'is_self': True
        })
    
    return jsonify({
        'success': True,
        'message': 'User found',
        'exists': True,
        'user': {
            'id': user['id'],
            'username': user['username']
        }
    })

# ==================== File Transfer Routes ====================

@app.route('/upload', methods=['POST'])
@auth.login_required
def upload_file():
    """Upload and encrypt file"""
    # Validate file upload
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file provided'})
    
    file = request.files['file']
    receiver_id = request.form.get('receiver_id')
    receiver_username = request.form.get('receiver_username')  # Optional: username instead of ID
    
    # Support both ID and username
    if not receiver_id and not receiver_username:
        return jsonify({'success': False, 'message': 'No receiver specified'})
    
    if not file.filename:
        return jsonify({'success': False, 'message': 'No file selected'})
    
    # Read file content
    try:
        file_content = file.read()
        filename = file.filename
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error reading file: {str(e)}'})
    
    # Get receiver - by ID or username
    receiver = None
    if receiver_id:
        receiver = db.get_user_by_id(receiver_id)
    elif receiver_username:
        receiver = db.get_user_by_username(receiver_username)
    
    if not receiver:
        return jsonify({'success': False, 'message': 'Receiver not found'})
    
    # Prevent sending to self
    sender_id = auth.get_session_user_id()
    if receiver['id'] == sender_id:
        return jsonify({'success': False, 'message': 'Cannot send file to yourself'})
    
    # Encrypt file
    encrypted_file, encrypted_aes_key = encryption.encrypt_file(
        file_content, 
        receiver['public_key']
    )
    
    if not encrypted_file or not encrypted_aes_key:
        return jsonify({'success': False, 'message': 'Encryption failed'})
    
    # Store in database
    file_id = db.create_file(sender_id, receiver['id'], filename, encrypted_file, encrypted_aes_key)
    
    if file_id:
        # Log the action
        db.create_log(
            sender_id, 
            'UPLOAD', 
            f'File "{filename}" uploaded to user {receiver["username"]} (ID: {receiver["id"]})'
        )
        return jsonify({
            'success': True, 
            'message': 'File uploaded and encrypted successfully',
            'recipient': receiver['username']
        })
    else:
        return jsonify({'success': False, 'message': 'Failed to store file'})

@app.route('/get_files')
@auth.login_required
def get_files():
    """Get list of files for current user"""
    user_id = auth.get_session_user_id()
    files = db.get_files_for_user(user_id)
    
    # Convert datetime to string
    for file in files:
        if file['timestamp']:
            file['timestamp'] = file['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
    
    return jsonify({'success': True, 'files': files})

@app.route('/download/<int:file_id>')
@auth.login_required
def download_file(file_id):
    """Download and decrypt file"""
    user_id = auth.get_session_user_id()
    
    # Get file data
    file_data = db.get_file_by_id(file_id, user_id)
    
    if not file_data:
        return jsonify({'success': False, 'message': 'File not found or access denied'}), 404
    
    # Decrypt file
    decrypted_content = encryption.decrypt_file(
        file_data['encrypted_file'],
        file_data['encrypted_key'],
        file_data['private_key']
    )
    
    if decrypted_content is None:
        return jsonify({'success': False, 'message': 'Decryption failed'}), 500
    
    # Mark as downloaded
    db.mark_file_downloaded(file_id)
    
    # Log the action
    db.create_log(user_id, 'DOWNLOAD', f'File {file_data["filename"]} downloaded')
    
    # Send file
    return send_file(
        io.BytesIO(decrypted_content),
        as_attachment=True,
        download_name=file_data['filename'],
        mimetype='application/octet-stream'
    )

# ==================== Logging Routes ====================

@app.route('/get_logs')
@auth.login_required
def get_logs():
    """Get activity logs for current user"""
    user_id = auth.get_session_user_id()
    logs = db.get_logs_for_user(user_id)
    
    # Convert datetime to string
    for log in logs:
        if log['timestamp']:
            log['timestamp'] = log['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
    
    return jsonify({'success': True, 'logs': logs})

# ==================== Error Handlers ====================

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    if request.path.startswith('/api/'):
        return jsonify({'success': False, 'message': 'Endpoint not found'}), 404
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    return jsonify({'success': False, 'message': 'Internal server error'}), 500

@app.errorhandler(413)
def request_entity_too_large(error):
    """Handle file too large errors"""
    return jsonify({'success': False, 'message': 'File too large. Maximum size is 50MB'}), 413

# ==================== Application Startup ====================

def initialize_app():
    """Initialize application"""
    print("\n" + "="*50)
    print("🔐 Secure File Transfer System")
    print("="*50)
    
    # Initialize database
    print("\n📊 Initializing database...")
    if db.init_database():
        print("✓ Database ready")
    else:
        print("✗ Database initialization failed")
        return False
    
    # Create uploads directory
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
        print(f"✓ Created uploads directory: {UPLOAD_FOLDER}")
    
    print("\n✓ Application initialized successfully")
    print("="*50 + "\n")
    return True

if __name__ == '__main__':
    if initialize_app():
        print("🚀 Starting Flask server...")
        print("📍 Access the application at: http://localhost:5000\n")
        app.run(debug=True, host='0.0.0.0', port=5000)
    else:
        print("❌ Failed to initialize application")
        exit(1)