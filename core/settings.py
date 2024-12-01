import os
from dotenv import load_dotenv
from core.logger import app_logger  


if load_dotenv():
    app_logger.info(".env file loaded successfully")
else:
    app_logger.warning("Failed to load .env file or file not found")

class Config:
    try:
        # Application Configuration
        SECRET_KEY = os.getenv('APP_SECRET_KEY')
        if not SECRET_KEY:
            app_logger.error("SECRET_KEY is not set")
            raise ValueError("SECRET_KEY must be set in the environment variables")
        else:
            app_logger.info("SECRET_KEY is loaded successfully")

        # Database Configuration Defaulting to SQLITE
        DB_TYPE = os.getenv('APP_DATABASE_TYPE', 'sqlite')
        SQLITE_PATH = os.getenv('SQLITE_PATH', 'sqlite:///cryptogram.db')
        SQLALCHEMY_DATABASE_URI = SQLITE_PATH
        SQLALCHEMY_TRACK_MODIFICATIONS = False
        app_logger.info(f"Database configuration set: {SQLALCHEMY_DATABASE_URI}")

        # SMTP Configuration
        MAIL_SERVER = os.getenv('SMTP_SERVER')
        if not MAIL_SERVER:
            app_logger.error("SMTP_SERVER is not set")
        MAIL_PORT = int(os.getenv('SMTP_PORT', 587))
        MAIL_USE_TLS = os.getenv('SMTP_USE_TLS', 'True').lower() == 'true'
        MAIL_USERNAME = os.getenv('SMTP_USERNAME')
        MAIL_PASSWORD = os.getenv('SMTP_PASSWORD')
        MAIL_DEFAULT_SENDER = os.getenv('SMTP_DEFAULT_SENDER')

        if MAIL_USERNAME and MAIL_PASSWORD:
            app_logger.info("SMTP credentials loaded successfully")
        else:
            app_logger.warning("SMTP credentials are incomplete")

        # Base URL
        HOST_URL = os.getenv('HOST_URL')
        if not HOST_URL:
            app_logger.warning("HOST_URL is not set")
        else:
            app_logger.info(f"HOST_URL is set to {HOST_URL}")

    except Exception as e:
        app_logger.error(f"Error in configuration: {str(e)}")
        raise
