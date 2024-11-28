import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    # Application Configuration
    SECRET_KEY = os.getenv('SECRET_KEY')
    
    # Database Configuration Defaulting to SQLITE
    DB_TYPE = os.getenv('APP_DATABASE_TYPE', 'SQLITE')
    SQLITE_PATH = os.getenv('SQLITE_PATH')
    
    # Google OAuth Credentials
    GOOGLE_CLIENT_ID = os.getenv('GOOGLE_OAUTH_CLIENT_ID')
    GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_OAUTH_CLIENT_SECRET')
    
    # SMTP Configuration
    MAIL_SERVER = os.getenv('SMTP_SERVER')
    MAIL_PORT = int(os.getenv('SMTP_PORT', 587))
    MAIL_USE_TLS = os.getenv('SMTP_USE_TLS', 'True').lower() == 'true'
    MAIL_USERNAME = os.getenv('SMTP_USERNAME')
    MAIL_PASSWORD = os.getenv('SMTP_PASSWORD')
    MAIL_DEFAULT_SENDER = os.getenv('SMTP_DEFAULT_SENDER')
    
    # Base URL
    HOST_URL = os.getenv('HOST_URL')
    