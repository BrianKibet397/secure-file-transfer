import mysql.connector
from mysql.connector import Error, pooling
from datetime import datetime
from config import Config

# Database Configuration
DB_CONFIG = Config.get_db_config()

# Connection Pool for better performance
connection_pool = None

def init_connection_pool():
    """Initialize database connection pool"""
    global connection_pool
    try:
        connection_pool = pooling.MySQLConnectionPool(
            pool_name="file_transfer_pool",
            pool_size=5,
            **DB_CONFIG
        )
        print("✓ Database connection pool created successfully")
    except Error as e:
        print(f"✗ Error creating connection pool: {e}")
        raise

def get_db_connection():
    """Get a connection from the pool"""
    try:
        if connection_pool is None:
            init_connection_pool()
        return connection_pool.get_connection()
    except Error as e:
        print(f"Error getting connection from pool: {e}")
        return None

def init_database():
    """Initialize database tables"""
    conn = get_db_connection()
    if not conn:
        print("✗ Failed to connect to database")
        return False
    
    try:
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
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_username (username)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
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
                FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (receiver_id) REFERENCES users(id) ON DELETE CASCADE,
                INDEX idx_receiver (receiver_id),
                INDEX idx_sender (sender_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        ''')
        
        # Create logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT,
                action VARCHAR(100) NOT NULL,
                details TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
                INDEX idx_user_timestamp (user_id, timestamp),
                INDEX idx_action (action)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        ''')
        
        # Create friendships table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS friendships (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                friend_id INT NOT NULL,
                status ENUM('pending', 'accepted', 'rejected', 'blocked') DEFAULT 'pending',
                requested_by INT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (friend_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (requested_by) REFERENCES users(id) ON DELETE CASCADE,
                UNIQUE KEY unique_friendship (user_id, friend_id),
                INDEX idx_user_status (user_id, status),
                INDEX idx_friend_status (friend_id, status)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        ''')
        
        # Create file_requests table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS file_requests (
                id INT AUTO_INCREMENT PRIMARY KEY,
                sender_id INT NOT NULL,
                receiver_id INT NOT NULL,
                filename VARCHAR(255) NOT NULL,
                file_size BIGINT NOT NULL,
                status ENUM('pending', 'accepted', 'rejected') DEFAULT 'pending',
                encrypted_file LONGBLOB NULL,
                encrypted_key TEXT NULL,
                request_message TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                responded_at TIMESTAMP NULL,
                FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (receiver_id) REFERENCES users(id) ON DELETE CASCADE,
                INDEX idx_receiver_status (receiver_id, status),
                INDEX idx_sender (sender_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        ''')
        
        conn.commit()
        cursor.close()
        print("✓ Database tables initialized successfully")
        return True
        
    except Error as e:
        print(f"✗ Error initializing database: {e}")
        conn.rollback()
        return False
    finally:
        conn.close()

# User Operations
def create_user(username, password_hash, public_key, private_key):
    """Create a new user"""
    conn = get_db_connection()
    if not conn:
        return None
    
    try:
        cursor = conn.cursor()
        cursor.execute(
            '''INSERT INTO users (username, password_hash, public_key, private_key) 
               VALUES (%s, %s, %s, %s)''',
            (username, password_hash, public_key, private_key)
        )
        conn.commit()
        user_id = cursor.lastrowid
        cursor.close()
        return user_id
    except mysql.connector.IntegrityError:
        return None
    except Error as e:
        print(f"Error creating user: {e}")
        conn.rollback()
        return None
    finally:
        conn.close()

def get_user_by_username(username):
    """Get user by username"""
    conn = get_db_connection()
    if not conn:
        return None
    
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        user = cursor.fetchone()
        cursor.close()
        return user
    except Error as e:
        print(f"Error getting user: {e}")
        return None
    finally:
        conn.close()

def get_user_by_id(user_id):
    """Get user by ID"""
    conn = get_db_connection()
    if not conn:
        return None
    
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
        user = cursor.fetchone()
        cursor.close()
        return user
    except Error as e:
        print(f"Error getting user: {e}")
        return None
    finally:
        conn.close()

def get_all_users_except(user_id):
    """Get all users except the specified user"""
    conn = get_db_connection()
    if not conn:
        return []
    
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute('''
            SELECT id, username, created_at
            FROM users 
            WHERE id != %s 
            ORDER BY username ASC
        ''', (user_id,))
        users = cursor.fetchall()
        cursor.close()
        return users
    except Error as e:
        print(f"Error getting users: {e}")
        return []
    finally:
        conn.close()

def update_failed_attempts(user_id, attempts, locked_until=None):
    """Update failed login attempts"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        cursor.execute(
            'UPDATE users SET failed_attempts = %s, locked_until = %s WHERE id = %s',
            (attempts, locked_until, user_id)
        )
        conn.commit()
        cursor.close()
        return True
    except Error as e:
        print(f"Error updating failed attempts: {e}")
        conn.rollback()
        return False
    finally:
        conn.close()

def reset_failed_attempts(user_id):
    """Reset failed login attempts"""
    return update_failed_attempts(user_id, 0, None)

# File Operations
def create_file(sender_id, receiver_id, filename, encrypted_file, encrypted_key):
    """Store encrypted file"""
    conn = get_db_connection()
    if not conn:
        return None
    
    try:
        cursor = conn.cursor()
        cursor.execute(
            '''INSERT INTO files (sender_id, receiver_id, filename, encrypted_file, encrypted_key) 
               VALUES (%s, %s, %s, %s, %s)''',
            (sender_id, receiver_id, filename, encrypted_file, encrypted_key)
        )
        conn.commit()
        file_id = cursor.lastrowid
        cursor.close()
        return file_id
    except Error as e:
        print(f"Error creating file: {e}")
        conn.rollback()
        return None
    finally:
        conn.close()

def get_files_for_user(user_id):
    """Get all files for a user"""
    conn = get_db_connection()
    if not conn:
        return []
    
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute('''
            SELECT f.id, f.filename, f.timestamp, f.downloaded, u.username as sender
            FROM files f
            JOIN users u ON f.sender_id = u.id
            WHERE f.receiver_id = %s
            ORDER BY f.timestamp DESC
        ''', (user_id,))
        files = cursor.fetchall()
        cursor.close()
        return files
    except Error as e:
        print(f"Error getting files: {e}")
        return []
    finally:
        conn.close()

def get_file_by_id(file_id, user_id):
    """Get file by ID if user is the receiver"""
    conn = get_db_connection()
    if not conn:
        return None
    
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute('''
            SELECT f.filename, f.encrypted_file, f.encrypted_key, u.private_key
            FROM files f
            JOIN users u ON u.id = %s
            WHERE f.id = %s AND f.receiver_id = %s
        ''', (user_id, file_id, user_id))
        file = cursor.fetchone()
        cursor.close()
        return file
    except Error as e:
        print(f"Error getting file: {e}")
        return None
    finally:
        conn.close()

def mark_file_downloaded(file_id):
    """Mark file as downloaded"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        cursor.execute('UPDATE files SET downloaded = TRUE WHERE id = %s', (file_id,))
        conn.commit()
        cursor.close()
        return True
    except Error as e:
        print(f"Error marking file as downloaded: {e}")
        conn.rollback()
        return False
    finally:
        conn.close()

# Logging Operations
def create_log(user_id, action, details=''):
    """Create a log entry"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO logs (user_id, action, details) VALUES (%s, %s, %s)',
            (user_id, action, details)
        )
        conn.commit()
        cursor.close()
        return True
    except Error as e:
        print(f"Error creating log: {e}")
        conn.rollback()
        return False
    finally:
        conn.close()

def get_logs_for_user(user_id, limit=50):
    """Get logs for a user"""
    conn = get_db_connection()
    if not conn:
        return []
    
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute('''
            SELECT action, details, timestamp
            FROM logs
            WHERE user_id = %s
            ORDER BY timestamp DESC
            LIMIT %s
        ''', (user_id, limit))
        logs = cursor.fetchall()
        cursor.close()
        return logs
    except Error as e:
        print(f"Error getting logs: {e}")
        return []
    finally:
        conn.close()

# Friendship Operations
def send_friend_request(user_id, friend_username):
    """Send a friend request"""
    conn = get_db_connection()
    if not conn:
        return None, "Database connection failed"
    
    try:
        cursor = conn.cursor(dictionary=True)
        
        # Get friend user
        cursor.execute('SELECT id FROM users WHERE username = %s', (friend_username,))
        friend = cursor.fetchone()
        
        if not friend:
            return None, "User not found"
        
        friend_id = friend['id']
        
        if friend_id == user_id:
            return None, "Cannot send friend request to yourself"
        
        # Check if friendship already exists
        cursor.execute('''
            SELECT id, status FROM friendships 
            WHERE (user_id = %s AND friend_id = %s) 
               OR (user_id = %s AND friend_id = %s)
        ''', (user_id, friend_id, friend_id, user_id))
        
        existing = cursor.fetchone()
        
        if existing:
            if existing['status'] == 'accepted':
                return None, "Already friends"
            elif existing['status'] == 'pending':
                return None, "Friend request already pending"
            elif existing['status'] == 'blocked':
                return None, "Cannot send friend request"
        
        # Create friendship (bidirectional)
        cursor.execute('''
            INSERT INTO friendships (user_id, friend_id, status, requested_by)
            VALUES (%s, %s, 'pending', %s)
        ''', (user_id, friend_id, user_id))
        
        cursor.execute('''
            INSERT INTO friendships (user_id, friend_id, status, requested_by)
            VALUES (%s, %s, 'pending', %s)
        ''', (friend_id, user_id, user_id))
        
        conn.commit()
        request_id = cursor.lastrowid
        cursor.close()
        return request_id, "Friend request sent"
        
    except Error as e:
        print(f"Error sending friend request: {e}")
        conn.rollback()
        return None, str(e)
    finally:
        conn.close()

def get_friend_requests(user_id):
    """Get pending friend requests for a user"""
    conn = get_db_connection()
    if not conn:
        return []
    
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute('''
            SELECT f.id, u.username, u.id as user_id, f.created_at
            FROM friendships f
            JOIN users u ON f.friend_id = u.id
            WHERE f.user_id = %s 
              AND f.status = 'pending'
              AND f.requested_by != %s
            ORDER BY f.created_at DESC
        ''', (user_id, user_id))
        requests = cursor.fetchall()
        cursor.close()
        return requests
    except Error as e:
        print(f"Error getting friend requests: {e}")
        return []
    finally:
        conn.close()

def respond_to_friend_request(user_id, friend_id, accept=True):
    """Accept or reject a friend request"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        status = 'accepted' if accept else 'rejected'
        
        # Update both records
        cursor.execute('''
            UPDATE friendships 
            SET status = %s 
            WHERE (user_id = %s AND friend_id = %s)
               OR (user_id = %s AND friend_id = %s)
        ''', (status, user_id, friend_id, friend_id, user_id))
        
        conn.commit()
        cursor.close()
        return True
    except Error as e:
        print(f"Error responding to friend request: {e}")
        conn.rollback()
        return False
    finally:
        conn.close()

def get_friends(user_id):
    """Get all accepted friends for a user"""
    conn = get_db_connection()
    if not conn:
        return []
    
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute('''
            SELECT u.id, u.username, f.created_at
            FROM friendships f
            JOIN users u ON f.friend_id = u.id
            WHERE f.user_id = %s AND f.status = 'accepted'
            ORDER BY u.username ASC
        ''', (user_id,))
        friends = cursor.fetchall()
        cursor.close()
        return friends
    except Error as e:
        print(f"Error getting friends: {e}")
        return []
    finally:
        conn.close()

def are_friends(user_id, friend_id):
    """Check if two users are friends"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id FROM friendships 
            WHERE user_id = %s AND friend_id = %s AND status = 'accepted'
        ''', (user_id, friend_id))
        result = cursor.fetchone()
        cursor.close()
        return result is not None
    except Error as e:
        print(f"Error checking friendship: {e}")
        return False
    finally:
        conn.close()

def remove_friend(user_id, friend_id):
    """Remove a friend (delete friendship)"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        cursor.execute('''
            DELETE FROM friendships 
            WHERE (user_id = %s AND friend_id = %s)
               OR (user_id = %s AND friend_id = %s)
        ''', (user_id, friend_id, friend_id, user_id))
        conn.commit()
        cursor.close()
        return True
    except Error as e:
        print(f"Error removing friend: {e}")
        conn.rollback()
        return False
    finally:
        conn.close()

# File Request Operations
def create_file_request(sender_id, receiver_id, filename, file_size, message=''):
    """Create a file transfer request"""
    conn = get_db_connection()
    if not conn:
        return None
    
    try:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO file_requests 
            (sender_id, receiver_id, filename, file_size, request_message)
            VALUES (%s, %s, %s, %s, %s)
        ''', (sender_id, receiver_id, filename, file_size, message))
        conn.commit()
        request_id = cursor.lastrowid
        cursor.close()
        return request_id
    except Error as e:
        print(f"Error creating file request: {e}")
        conn.rollback()
        return None
    finally:
        conn.close()

def get_pending_file_requests(user_id):
    """Get pending file requests for a user"""
    conn = get_db_connection()
    if not conn:
        return []
    
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute('''
            SELECT fr.id, fr.filename, fr.file_size, fr.request_message, 
                   fr.created_at, u.username as sender
            FROM file_requests fr
            JOIN users u ON fr.sender_id = u.id
            WHERE fr.receiver_id = %s AND fr.status = 'pending'
            ORDER BY fr.created_at DESC
        ''', (user_id,))
        requests = cursor.fetchall()
        cursor.close()
        return requests
    except Error as e:
        print(f"Error getting file requests: {e}")
        return []
    finally:
        conn.close()

def respond_to_file_request(request_id, user_id, accept=True):
    """Accept or reject a file request"""
    conn = get_db_connection()
    if not conn:
        return False, None
    
    try:
        cursor = conn.cursor(dictionary=True)
        
        # Get request details
        cursor.execute('''
            SELECT * FROM file_requests 
            WHERE id = %s AND receiver_id = %s AND status = 'pending'
        ''', (request_id, user_id))
        
        request = cursor.fetchone()
        if not request:
            return False, "Request not found or already processed"
        
        status = 'accepted' if accept else 'rejected'
        
        cursor.execute('''
            UPDATE file_requests 
            SET status = %s, responded_at = NOW()
            WHERE id = %s
        ''', (status, request_id))
        
        conn.commit()
        cursor.close()
        return True, request
    except Error as e:
        print(f"Error responding to file request: {e}")
        conn.rollback()
        return False, str(e)
    finally:
        conn.close()

def store_encrypted_file_for_request(request_id, encrypted_file, encrypted_key):
    """Store encrypted file data for an accepted request"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE file_requests 
            SET encrypted_file = %s, encrypted_key = %s
            WHERE id = %s
        ''', (encrypted_file, encrypted_key, request_id))
        conn.commit()
        cursor.close()
        return True
    except Error as e:
        print(f"Error storing encrypted file: {e}")
        conn.rollback()
        return False
    finally:
        conn.close()

def get_accepted_files(user_id):
    """Get accepted files ready for download"""
    conn = get_db_connection()
    if not conn:
        return []
    
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute('''
            SELECT fr.id, fr.filename, fr.file_size, fr.created_at, 
                   fr.responded_at, u.username as sender,
                   (fr.encrypted_file IS NOT NULL) as ready_to_download
            FROM file_requests fr
            JOIN users u ON fr.sender_id = u.id
            WHERE fr.receiver_id = %s AND fr.status = 'accepted'
            ORDER BY fr.responded_at DESC
        ''', (user_id,))
        files = cursor.fetchall()
        cursor.close()
        return files
    except Error as e:
        print(f"Error getting accepted files: {e}")
        return []
    finally:
        conn.close()

def get_file_request_for_download(request_id, user_id):
    """Get file request data for download"""
    conn = get_db_connection()
    if not conn:
        return None
    
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute('''
            SELECT fr.filename, fr.encrypted_file, fr.encrypted_key, u.private_key
            FROM file_requests fr
            JOIN users u ON u.id = %s
            WHERE fr.id = %s AND fr.receiver_id = %s AND fr.status = 'accepted'
        ''', (user_id, request_id, user_id))
        file_data = cursor.fetchone()
        cursor.close()
        return file_data
    except Error as e:
        print(f"Error getting file for download: {e}")
        return None
    finally:
        conn.close()

# Initialize connection pool when module is imported
try:
    init_connection_pool()
except Exception as e:
    print(f"Warning: Could not initialize connection pool: {e}")