from flask import Blueprint, render_template, request, session, redirect, url_for, flash
from flask_bcrypt import check_password_hash
from core.models import db, User
from core.utilities.helpers import EmailService
import re
from core.logger import app_logger
from datetime import datetime, timedelta

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
        app_logger.debug(
            f"Signup form data: username={username}, email={email}")

        msg = None

        # Validate email format
        if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w{2,4}$', email):
            msg = 'Invalid email format.'
            app_logger.warning(f"Email validation failed: {email}")
            return render_template('register.html', msg=msg)

        # Validate password complexity
        if not re.match(r'^(?=.*[!@#$%^&*(),.?":{}|<>])[A-Za-z\d!@#$%^&*(),.?":{}|<>]{8,}$', password):
            msg = 'Password must be at least 8 characters long and contain at least one special character.'
            app_logger.warning(
                f"Password validation failed for user: {username}")
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
                app_logger.warning(
                    f"Duplicate user detected: {username}, {email}")
            else:
                app_logger.info("Creating new user")
                new_user = User(username=username,
                                email=email, password=password)
                db.session.add(new_user)
                db.session.commit()
                app_logger.info(f"User created successfully: {username}")

                # Send OTP email
                EmailService.send_otp_email(new_user)
                db.session.commit()  # Save the OTP to database
                app_logger.info(f"OTP sent to: {email}")

                # Store email in session for verification
                session['verification_email'] = email

                return redirect(url_for('cryptogram.verify_otp'))

        except Exception as e:
            db.session.rollback()
            app_logger.error(f"Error during user registration: {str(e)}")
            msg = f"Registration failed: {str(e)}"

        if msg:
            app_logger.debug(
                f"Rendering registration template with message: {msg}")
            return render_template('register.html', msg=msg)

    app_logger.info("Rendering signup template")
    return render_template('register.html')


@bp.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    app_logger.info("Accessed /verify_otp route")
    if 'verification_email' not in session:
        app_logger.warning("No email in session for OTP verification")
        return redirect(url_for('cryptogram.signup'))

    if request.method == 'POST':
        app_logger.info("Processing OTP verification")
        entered_otp = request.form['otp']
        user = User.query.filter_by(
            email=session['verification_email']).first()

        if not user:
            app_logger.error("User not found for OTP verification")
            return redirect(url_for('cryptogram.signup'))

        if user.otp == entered_otp:
            # Check if OTP is not expired (10 minutes validity)
            if datetime.utcnow() - user.otp_timestamp < timedelta(minutes=10):
                user.email_verified = True
                user.otp = None  # Clear the OTP
                db.session.commit()
                app_logger.info(
                    f"OTP verified successfully for user: {user.username}")
                session.pop('verification_email', None)
                return redirect(url_for('cryptogram.login'))
            else:
                app_logger.warning("OTP expired")
                msg = "OTP has expired. Please request a new one."
        else:
            app_logger.warning("Invalid OTP entered")
            msg = "Invalid OTP. Please try again."

        return render_template('verify_otp.html', msg=msg)

    app_logger.info("Rendering OTP verification template")
    return render_template('verify_otp.html')


@bp.route('/', methods=['GET', 'POST'])
@bp.route('/login', methods=['GET', 'POST'])
def login():
    app_logger.info("Accessed /login route")
    msg = ''
    if request.method == 'POST':
        app_logger.info("Processing login POST request")
        email = request.form['email']
        password = request.form['password']
        app_logger.debug(f"Login form data: username={email}")

        try:
            app_logger.info("Querying user from database")
            user = User.query.filter_by(email=email).first()

            if user:
                app_logger.info(f"User found: {email}")
                if user.verify_password(password):
                    if user.email_verified:
                        app_logger.info(
                            f"Login successful for user: {email}")
                        session['loggedin'] = True
                        session['username'] = user.username
                        session['email'] = user.email
                        return redirect(url_for('cryptogram.verify'))
                    else:
                        msg = "Email Verification Failed"
                        app_logger.warning(
                            f"Email not verified for user: {email}")
                else:
                    msg = "Incorrect Username or Password"
                    app_logger.warning(
                        f"Password mismatch for user: {email}")
            else:
                msg = "Incorrect Username or Password"
                app_logger.warning(f"User not found: {email}")

        except Exception as ex:
            msg = f"Exception occurred: {ex}"
            app_logger.error(f"Error during login: {ex}")

    app_logger.info("Rendering login template")
    return render_template('login.html', msg=msg)
