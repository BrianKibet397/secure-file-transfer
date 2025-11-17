from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_file
from flask_cors import CORS
from datetime import timedelta
import os
import io

# Import our custom modules
import database as db
import auth
import encryption
import utils
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

# ==================== Friend Management Routes ====================

@app.route('/send_friend_request', methods=['POST'])
@auth.login_required
def send_friend_request():
    """Send a friend request"""
    data = request.json
    friend_username = data.get('username')
    
    if not friend_username:
        return jsonify({'success': False, 'message': 'Username required'})
    
    user_id = auth.get_session_user_id()
    request_id, message = db.send_friend_request(user_id, friend_username)
    
    if request_id:
        db.create_log(user_id, 'FRIEND_REQUEST_SENT', f'Friend request sent to {friend_username}')
        return jsonify({'success': True, 'message': message})
    else:
        return jsonify({'success': False, 'message': message})

@app.route('/get_friend_requests')
@auth.login_required
def get_friend_requests():
    """Get pending friend requests"""
    user_id = auth.get_session_user_id()
    requests = db.get_friend_requests(user_id)
    
    for req in requests:
        if req['created_at']:
            req['created_at'] = req['created_at'].strftime('%Y-%m-%d %H:%M:%S')
    
    return jsonify({'success': True, 'requests': requests})

@app.route('/respond_friend_request', methods=['POST'])
@auth.login_required
def respond_friend_request():
    """Accept or reject a friend request"""
    data = request.json
    friend_id = data.get('friend_id')
    accept = data.get('accept', True)
    
    if not friend_id:
        return jsonify({'success': False, 'message': 'Friend ID required'})
    
    user_id = auth.get_session_user_id()
    success = db.respond_to_friend_request(user_id, friend_id, accept)
    
    if success:
        action = 'FRIEND_REQUEST_ACCEPTED' if accept else 'FRIEND_REQUEST_REJECTED'
        db.create_log(user_id, action, f'Friend request {"accepted" if accept else "rejected"}')
        message = 'Friend request accepted!' if accept else 'Friend request rejected'
        return jsonify({'success': True, 'message': message})
    else:
        return jsonify({'success': False, 'message': 'Failed to process request'})

@app.route('/get_friends')
@auth.login_required
def get_friends():
    """Get list of friends"""
    user_id = auth.get_session_user_id()
    friends = db.get_friends(user_id)
    
    for friend in friends:
        if friend['created_at']:
            friend['created_at'] = friend['created_at'].strftime('%Y-%m-%d')
    
    return jsonify({'success': True, 'friends': friends, 'count': len(friends)})

@app.route('/remove_friend', methods=['POST'])
@auth.login_required
def remove_friend():
    """Remove a friend"""
    data = request.json
    friend_id = data.get('friend_id')
    
    if not friend_id:
        return jsonify({'success': False, 'message': 'Friend ID required'})
    
    user_id = auth.get_session_user_id()
    success = db.remove_friend(user_id, friend_id)
    
    if success:
        db.create_log(user_id, 'FRIEND_REMOVED', f'Friend removed: {friend_id}')
        return jsonify({'success': True, 'message': 'Friend removed'})
    else:
        return jsonify({'success': False, 'message': 'Failed to remove friend'})

# ==================== File Transfer Routes ====================

@app.route('/upload', methods=['POST'])
@auth.login_required
def upload_file():
    """Create a file transfer request (not immediate upload)"""
    # Validate file upload
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file provided'})
    
    file = request.files['file']
    receiver_id = request.form.get('receiver_id')
    receiver_username = request.form.get('receiver_username')
    request_message = request.form.get('message', '')
    
    # Support both ID and username
    if not receiver_id and not receiver_username:
        return jsonify({'success': False, 'message': 'No receiver specified'})
    
    if not file.filename:
        return jsonify({'success': False, 'message': 'No file selected'})
    
    # Get receiver
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
    
    # Check if users are friends
    if not db.are_friends(sender_id, receiver['id']):
        return jsonify({
            'success': False, 
            'message': f'You must be friends with {receiver["username"]} to send files. Send a friend request first!'
        })
    
    # Clean and sanitize filename
    import os
    from werkzeug.utils import secure_filename
    
    filename = secure_filename(file.filename)
    if not filename:
        filename = 'unnamed_file'
    
    # Get file info
    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0)
    
    # Create file request (not uploading yet)
    request_id = db.create_file_request(
        sender_id, 
        receiver['id'], 
        filename, 
        file_size,
        request_message
    )
    
    if request_id:
        # Read and encrypt file
        file_content = file.read()
        
        # Encrypt file
        encrypted_file, encrypted_aes_key = encryption.encrypt_file(
            file_content, 
            receiver['public_key']
        )
        
        if encrypted_file and encrypted_aes_key:
            # Store encrypted file in request
            db.store_encrypted_file_for_request(request_id, encrypted_file, encrypted_aes_key)
        
        db.create_log(
            sender_id, 
            'FILE_REQUEST_SENT', 
            f'File request "{filename}" sent to {receiver["username"]}'
        )
        
        return jsonify({
            'success': True, 
            'message': f'File request sent to {receiver["username"]}. Waiting for approval...',
            'request_id': request_id,
            'filename': filename
        })
    else:
        return jsonify({'success': False, 'message': 'Failed to create file request'})

@app.route('/get_file_requests')
@auth.login_required
def get_file_requests():
    """Get pending file requests"""
    user_id = auth.get_session_user_id()
    requests = db.get_pending_file_requests(user_id)
    
    for req in requests:
        if req['created_at']:
            req['created_at'] = req['created_at'].strftime('%Y-%m-%d %H:%M:%S')
        if req['file_size']:
            # Format file size
            size_mb = req['file_size'] / (1024 * 1024)
            size_kb = req['file_size'] / 1024
            req['file_size_formatted'] = f"{size_mb:.2f} MB" if size_mb > 1 else f"{size_kb:.2f} KB"
    
    return jsonify({'success': True, 'requests': requests})

@app.route('/respond_file_request', methods=['POST'])
@auth.login_required
def respond_file_request():
    """Accept or reject a file request"""
    data = request.json
    request_id = data.get('request_id')
    accept = data.get('accept', True)
    
    if not request_id:
        return jsonify({'success': False, 'message': 'Request ID required'})
    
    user_id = auth.get_session_user_id()
    success, request_data = db.respond_to_file_request(request_id, user_id, accept)
    
    if success:
        action = 'FILE_REQUEST_ACCEPTED' if accept else 'FILE_REQUEST_REJECTED'
        details = f'File request for "{request_data["filename"]}" {"accepted" if accept else "rejected"}'
        db.create_log(user_id, action, details)
        
        message = f'File request accepted! You can now download "{request_data["filename"]}"' if accept else 'File request rejected'
        return jsonify({'success': True, 'message': message})
    else:
        return jsonify({'success': False, 'message': 'Failed to process request'})

@app.route('/get_files')
@auth.login_required
def get_files():
    """Get list of accepted files ready for download"""
    user_id = auth.get_session_user_id()
    files = db.get_accepted_files(user_id)
    
    # Convert datetime to string
    for file in files:
        if file['created_at']:
            file['created_at'] = file['created_at'].strftime('%Y-%m-%d %H:%M:%S')
        if file['responded_at']:
            file['responded_at'] = file['responded_at'].strftime('%Y-%m-%d %H:%M:%S')
        if file['file_size']:
            size_mb = file['file_size'] / (1024 * 1024)
            size_kb = file['file_size'] / 1024
            file['file_size_formatted'] = f"{size_mb:.2f} MB" if size_mb > 1 else f"{size_kb:.2f} KB"
    
    return jsonify({'success': True, 'files': files})

@app.route('/download/<int:request_id>')
@auth.login_required
def download_file(request_id):
    """Download and decrypt an accepted file"""
    user_id = auth.get_session_user_id()
    
    # Get file data
    file_data = db.get_file_request_for_download(request_id, user_id)
    
    if not file_data:
        return jsonify({'success': False, 'message': 'File not found or not approved'}), 404
    
    if not file_data['encrypted_file']:
        return jsonify({'success': False, 'message': 'File data not available'}), 404
    
    # Decrypt file
    decrypted_content = encryption.decrypt_file(
        file_data['encrypted_file'],
        file_data['encrypted_key'],
        file_data['private_key']
    )
    
    if decrypted_content is None:
        return jsonify({'success': False, 'message': 'Decryption failed'}), 500
    
    # Log the action
    db.create_log(user_id, 'FILE_DOWNLOADED', f'File "{file_data["filename"]}" downloaded')
    
    # Clean filename - remove any trailing underscores or weird characters
    filename = file_data['filename'].strip()
    
    # Send file with proper headers
    return send_file(
        io.BytesIO(decrypted_content),
        as_attachment=True,
        download_name=filename,
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