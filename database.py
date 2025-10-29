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
        cursor.execute(
            'SELECT id, username FROM users WHERE id != %s ORDER BY username',
            (user_id,)
        )
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

# Initialize connection pool when module is imported
try:
    init_connection_pool()
except Exception as e:
    print(f"Warning: Could not initialize connection pool: {e}")