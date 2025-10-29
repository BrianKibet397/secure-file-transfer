import os
from datetime import timedelta

class Config:
    """Base configuration"""
    
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-change-in-production'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1)
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50MB max file size
    
    DB_HOST = os.environ.get('DB_HOST', 'localhost')
    DB_USER = os.environ.get('DB_USER', 'root')
    DB_PASSWORD = os.environ.get('DB_PASSWORD', '41398374')
    DB_NAME = os.environ.get('DB_NAME', 'secure_file_transfer')
    DB_POOL_SIZE = int(os.environ.get('DB_POOL_SIZE', 5))
    
    UPLOAD_FOLDER = 'uploads'
    ALLOWED_EXTENSIONS = None
    
    MAX_LOGIN_ATTEMPTS = 3
    LOCKOUT_DURATION_MINUTES = 15
    PASSWORD_MIN_LENGTH = 6
    USERNAME_MIN_LENGTH = 3
    
    RSA_KEY_SIZE = 2048
    AES_KEY_SIZE = 32
    
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    @staticmethod
    def get_db_config():
        return {
            'host': Config.DB_HOST,
            'user': Config.DB_USER,
            'password': Config.DB_PASSWORD,
            'database': Config.DB_NAME,
            'autocommit': False
        }

class DevelopmentConfig(Config):
    DEBUG = True
    TESTING = False

class ProductionConfig(Config):
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True
    
    @staticmethod
    def validate():
        issues = []
        if Config.SECRET_KEY == 'your-secret-key-change-in-production':
            issues.append("SECRET_KEY must be changed for production")
        if Config.DB_PASSWORD == 'your_password':
            issues.append("DB_PASSWORD must be changed for production")
        if issues:
            print("\n⚠️  PRODUCTION CONFIGURATION ISSUES:")
            for issue in issues:
                print(f"   - {issue}")
            print()
            return False
        return True

class TestingConfig(Config):
    DEBUG = True
    TESTING = True
    DB_NAME = 'secure_file_transfer_test'

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}

def get_config(env=None):
    if env is None:
        env = os.environ.get('FLASK_ENV', 'development')
    return config.get(env, config['default'])
