import random
from datetime import datetime
from flask import current_app
from flask_mail import Message

class EmailService:
    @staticmethod
    def generate_otp():
        return ''.join([str(random.randint(0, 9)) for _ in range(6)])

    @staticmethod
    def send_otp_email(user):
        otp = EmailService.generate_otp()
        user.otp = otp
        user.otp_timestamp = datetime.utcnow()

        msg = Message(
            'Your Cryptogram Verification Code',
            sender=current_app.config['MAIL_USERNAME'],
            recipients=[user.email]
        )
        msg.body = f"""
        Welcome to Cryptogram!
        Your verification code is: {otp}
        This code will expire in 10 minutes.
        """
        current_app.mail.send(msg)
        return otp


class ChatManager:
    _active_users = {}
    _session_map = {}
    _user_emails = {}

    @classmethod
    def add_user(cls, username, session_id, email):
        cls._active_users[username] = session_id
        cls._session_map[session_id] = username
        cls._user_emails[username] = email
        return cls.get_all_users()

    @classmethod
    def remove_user(cls, session_id):
        if session_id in cls._session_map:
            username = cls._session_map[session_id]
            del cls._active_users[username]
            del cls._session_map[session_id]
            del cls._user_emails[username]
            return username
        return None

    @classmethod
    def get_user_session(cls, username):
        return cls._active_users.get(username)

    @classmethod
    def get_all_users(cls):
        return cls._user_emails
