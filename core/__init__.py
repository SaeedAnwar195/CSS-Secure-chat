from flask import Flask
from flask_socketio import SocketIO
from flask_bcrypt import Bcrypt
from flask_mail import Mail
from itsdangerous import URLSafeTimedSerializer
from core.settings import Config

socketio = SocketIO(async_mode='gevent', cors_allowed_origins="*")
bcrypt = Bcrypt()
mail = Mail()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Initialize extensions
    socketio.init_app(app)
    bcrypt.init_app(app)
    mail.init_app(app)

    # Initialize serializer for email verification
    app.serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

    # Initialize database
    from core.database import Database
    Database.init_db(app)

    return app