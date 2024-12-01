from gevent import monkey
monkey.patch_all()

from flask import Flask
from flask_socketio import SocketIO
from flask_bcrypt import Bcrypt
from flask_mail import Mail
from itsdangerous import URLSafeTimedSerializer
from core.models import db
from core.logger import app_logger

# Initialize extensions
socketio = SocketIO(async_mode='gevent', cors_allowed_origins="*")
mail = Mail()
bcrypt = Bcrypt()

def create_app(test_config=None):
    app = Flask(__name__)
    app_logger.info('Initializing application...')
    
    try:
        # Load config
        if test_config is None:
            from core.settings import Config
            app.config.from_object(Config)
            app_logger.info('Loaded configuration from settings.py')
        else:
            app.config.update(test_config)
            app_logger.info('Loaded test configuration')

        # Initialize extensions
        db.init_app(app)
        socketio.init_app(app)
        mail.init_app(app)
        bcrypt.init_app(app)
        app_logger.info('Initialized extensions')

        # Initialize database
        with app.app_context():
            db.create_all()
            app_logger.info('Database tables created')

        # Create serializer for email verification
        app.serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

        # Register blueprints
        from core.routes import router
        app.register_blueprint(router.bp)
        app_logger.info('Registered blueprints')

        # Register SocketIO events
        from core import events
        app_logger.info('Registered SocketIO events')

    except Exception as e:
        app_logger.error(f'Error during application initialization: {str(e)}')
        raise

    app_logger.info('Application initialization completed')
    return app

# Create the application instance
application = create_app()

if __name__ == '__main__':
    socketio.run(application, debug=True, host='0.0.0.0', port=7350)