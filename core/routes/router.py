from flask import Blueprint, render_template, request, session, redirect, url_for, flash
from flask_bcrypt import check_password_hash
from core.models import db, User
from core.utilities.helpers import EmailService
import re
from core.logger import app_logger

bp = Blueprint('cryptogram', __name__, template_folder='templates')


@bp.route('/signup', methods=['GET', 'POST'])
def signup():
    app_logger.info("Accessed /signup route")
    if request.method == 'POST':
        app_logger.info("Processing signup POST request")
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        app_logger.debug(f"Signup form data: username={username}, email={email}")

        msg = None

        # Validate email format
        if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w{2,4}$', email):
            msg = 'Invalid email format.'
            app_logger.warning(f"Email validation failed: {email}")
            return render_template('register.html', msg=msg)

        # Validate password complexity
        if not re.match(r'^(?=.*[!@#$%^&*(),.?":{}|<>])[A-Za-z\d!@#$%^&*(),.?":{}|<>]{8,}$', password):
            msg = 'Password must be at least 8 characters long and contain at least one special character.'
            app_logger.warning(f"Password validation failed for user: {username}")
            return render_template('register.html', msg=msg)

        # Validate password match
        if password != confirm_password:
            msg = 'Passwords do not match.'
            app_logger.warning("Password mismatch during signup")
            return render_template('register.html', msg=msg)

        try:
            app_logger.info("Checking for existing user")
            existing_user = User.query.filter(
                (User.username == username) | (User.email == email)).first()

            if existing_user:
                msg = 'Username or Email already exists. Please choose different credentials.'
                app_logger.warning(f"Duplicate user detected: {username}, {email}")
            else:
                app_logger.info("Creating new user")
                new_user = User(username=username, email=email, password=password)
                db.session.add(new_user)
                db.session.commit()
                app_logger.info(f"User created successfully: {username}")

                EmailService.send_verification_email(email)
                app_logger.info(f"Verification email sent to: {email}")
                return redirect(url_for('auth.verify_notice'))

        except Exception as e:
            db.session.rollback()
            app_logger.error(f"Error during user registration: {str(e)}")
            msg = f"Registration failed: {str(e)}"

        if msg:
            app_logger.debug(f"Rendering registration template with message: {msg}")
            return render_template('register.html', msg=msg)

    app_logger.info("Rendering signup template")
    return render_template('register.html')


@bp.route('/', methods=['GET', 'POST'])
@bp.route('/login', methods=['GET', 'POST'])
def login():
    app_logger.info("Accessed /login route")
    msg = ''
    if request.method == 'POST':
        app_logger.info("Processing login POST request")
        username = request.form['username']
        password = request.form['password']
        app_logger.debug(f"Login form data: username={username}")

        try:
            app_logger.info("Querying user from database")
            user = User.query.filter_by(username=username).first()

            if user:
                app_logger.info(f"User found: {username}")
                if user.verify_password(password):
                    if user.email_verified:
                        app_logger.info(f"Login successful for user: {username}")
                        session['loggedin'] = True
                        session['username'] = user.username
                        session['email'] = user.email
                        return redirect(url_for('cryptogram.index'))
                    else:
                        msg = "Email Verification Failed"
                        app_logger.warning(f"Email not verified for user: {username}")
                else:
                    msg = "Incorrect Username or Password"
                    app_logger.warning(f"Password mismatch for user: {username}")
            else:
                msg = "Incorrect Username or Password"
                app_logger.warning(f"User not found: {username}")

        except Exception as ex:
            msg = f"Exception occurred: {ex}"
            app_logger.error(f"Error during login: {ex}")

    app_logger.info("Rendering login template")
    return render_template('login.html', msg=msg)
