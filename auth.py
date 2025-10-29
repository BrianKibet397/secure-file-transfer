import bcrypt
from Crypto.PublicKey import RSA
from datetime import datetime, timedelta
from functools import wraps
from flask import session, jsonify
import database as db

def generate_rsa_keys():
    """Generate RSA key pair"""
    key = RSA.generate(2048)
    private_key = key.export_key().decode('utf-8')
    public_key = key.publickey().export_key().decode('utf-8')
    return public_key, private_key

def hash_password(password):
    """Hash password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password, password_hash):
    """Verify password against hash"""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
    except Exception as e:
        print(f"Error verifying password: {e}")
        return False

def register_user(username, password):
    """
    Register a new user
    Returns: (success: bool, message: str, user_id: int or None)
    """
    # Validate input
    if not username or not password:
        return False, 'Username and password required', None
    
    if len(username) < 3:
        return False, 'Username must be at least 3 characters', None
    
    if len(password) < 6:
        return False, 'Password must be at least 6 characters', None
    
    # Generate RSA keys
    try:
        public_key, private_key = generate_rsa_keys()
    except Exception as e:
        return False, f'Error generating encryption keys: {str(e)}', None
    
    # Hash password
    password_hash = hash_password(password)
    
    # Create user in database
    user_id = db.create_user(username, password_hash, public_key, private_key)
    
    if user_id:
        # Log registration
        db.create_log(user_id, 'REGISTER', f'User {username} registered')
        return True, 'Registration successful', user_id
    else:
        return False, 'Username already exists', None

def login_user(username, password):
    """
    Login user
    Returns: (success: bool, message: str, user: dict or None)
    """
    if not username or not password:
        return False, 'Username and password required', None
    
    # Get user from database
    user = db.get_user_by_username(username)
    
    if not user:
        return False, 'Invalid credentials', None
    
    # Check if account is locked
    if user['locked_until'] and datetime.now() < user['locked_until']:
        time_left = (user['locked_until'] - datetime.now()).seconds // 60
        return False, f'Account locked. Try again in {time_left} minutes.', None
    
    # Verify password
    if verify_password(password, user['password_hash']):
        # Reset failed attempts
        db.reset_failed_attempts(user['id'])
        
        # Log successful login
        db.create_log(user['id'], 'LOGIN', f'User {username} logged in')
        
        return True, 'Login successful', user
    else:
        # Increment failed attempts
        failed_attempts = user['failed_attempts'] + 1
        
        if failed_attempts >= 3:
            # Lock account for 15 minutes
            locked_until = datetime.now() + timedelta(minutes=15)
            db.update_failed_attempts(user['id'], failed_attempts, locked_until)
            db.create_log(user['id'], 'ACCOUNT_LOCKED', f'Account locked due to {failed_attempts} failed login attempts')
            return False, 'Account locked for 15 minutes due to multiple failed attempts', None
        else:
            # Just increment failed attempts
            db.update_failed_attempts(user['id'], failed_attempts)
            attempts_left = 3 - failed_attempts
            return False, f'Invalid credentials. {attempts_left} attempts remaining.', None

def logout_user(user_id, username):
    """Logout user"""
    db.create_log(user_id, 'LOGOUT', f'User {username} logged out')
    session.clear()

def login_required(f):
    """Decorator to require login for routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'success': False, 'message': 'Login required'}), 401
        return f(*args, **kwargs)
    return decorated_function

def get_current_user():
    """Get current logged in user"""
    if 'user_id' in session:
        return db.get_user_by_id(session['user_id'])
    return None

def is_authenticated():
    """Check if user is authenticated"""
    return 'user_id' in session

def create_session(user):
    """Create user session"""
    session['user_id'] = user['id']
    session['username'] = user['username']
    session.permanent = True

def get_session_user_id():
    """Get user ID from session"""
    return session.get('user_id')

def get_session_username():
    """Get username from session"""
    return session.get('username')