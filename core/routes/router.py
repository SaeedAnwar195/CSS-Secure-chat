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
                        return redirect(url_for('cryptogram.index'))
                    else:
                        msg = "Email Verification Failed"
                        app_logger.warning(
                            f"Email not verified for user: {email}")
                else:
                    msg = "Incorrect Username or Password"
                    app_logger.warning(
                        f"Password mismatch for user: {email}")
            else:
                msg = "User not found"
                app_logger.warning(f"User not found: {email}")

        except Exception as ex:
            msg = f"Exception occurred: {ex}"
            app_logger.error(f"Error during login: {ex}")

    app_logger.info("Rendering login template")
    return render_template('login.html', msg=msg)


@bp.route('/index')
def index():
    if 'loggedin' not in session:
        return redirect(url_for('cryptogram.login'))

    userData = {
        'Username': session['username'],
        'Email': session['email']
    }
    return render_template('index.html', userData=userData)


@bp.route('/reset-password', methods=['GET', 'POST'])
def reset_password_request():
    app_logger.info("Accessed password reset request route")
    if request.method == 'POST':
        email = request.form['email']
        app_logger.info(
            f"Processing password reset request for email: {email}")

        try:
            user = User.query.filter_by(email=email).first()
            if user:
                otp = EmailService.send_reset_password_otp(user)
                user.reset_password_otp = otp
                user.reset_password_timestamp = datetime.utcnow()
                db.session.commit()

                session['reset_email'] = email
                app_logger.info(f"Reset password OTP sent to: {email}")
                return redirect(url_for('cryptogram.reset_password_verify'))
            else:
                app_logger.warning(
                    f"Reset password requested for non-existent email: {email}")
                msg = "If this email is registered, you will receive a reset code."
        except Exception as e:
            app_logger.error(f"Error in reset password request: {str(e)}")
            msg = "An error occurred. Please try again later."

        return render_template('reset_password_request.html', msg=msg)

    return render_template('reset_password_request.html')


@bp.route('/reset-password/verify', methods=['GET', 'POST'])
def reset_password_verify():
    app_logger.info("Accessed reset password verification route")
    if 'reset_email' not in session:
        app_logger.warning("No reset email in session")
        return redirect(url_for('cryptogram.reset_password_request'))

    if request.method == 'POST':
        app_logger.info("Processing reset password verification")
        otp = request.form['otp']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            app_logger.warning("Password mismatch in reset verification")
            return render_template('reset_password_verify.html', msg="Passwords do not match")

        try:
            user = User.query.filter_by(email=session['reset_email']).first()
            if not user:
                app_logger.error(
                    f"User not found for reset email: {session['reset_email']}")
                return redirect(url_for('cryptogram.reset_password_request'))

            if user.reset_password_otp != otp:
                app_logger.warning("Invalid OTP entered for password reset")
                return render_template('reset_password_verify.html', msg="Invalid verification code")

            if datetime.utcnow() - user.reset_password_timestamp > timedelta(minutes=10):
                app_logger.warning("Expired OTP used for password reset")
                return render_template('reset_password_verify.html', msg="Verification code has expired")

            user.set_password(password)
            user.reset_password_otp = None
            user.reset_password_timestamp = None
            db.session.commit()

            session.pop('reset_email', None)
            app_logger.info(
                f"Password reset successful for user: {user.username}")
            return redirect(url_for('cryptogram.login', msg="Password reset successful. Please login with your new password."))

        except Exception as e:
            app_logger.error(f"Error in reset password verification: {str(e)}")
            return render_template('reset_password_verify.html', msg="An error occurred. Please try again.")

    return render_template('reset_password_verify.html')


@bp.route('/logout')
def logout():
    """Handle user logout by clearing session data."""
    app_logger.info(
        f"Processing logout for user: {session.get('username', 'Unknown')}")

    try:
        # Clear all session data
        session.pop('loggedin', None)
        session.pop('username', None)
        session.pop('email', None)
        session.pop('profile', None)
        session.pop('google_oauth_state', None)

        app_logger.info("User successfully logged out")
        return redirect(url_for('cryptogram.login'))

    except Exception as e:
        app_logger.error(f"Error during logout: {str(e)}")
        return redirect(url_for('cryptogram.login'))


@bp.route('/compose_email', methods=['GET', 'POST'])
def compose_email():
    """Handle email composition and sending."""
    app_logger.info("Accessed email composition route")

    if 'loggedin' not in session:
        app_logger.warning("Unauthorized access attempt to compose email")
        return redirect(url_for('cryptogram.login'))

    if request.method == 'POST':
        try:
            recipient = request.form.get('recipient')
            subject = request.form.get('subject')
            body = request.form.get('body')

            app_logger.info(f"Composing email to: {recipient}")

            # Create mailto link for external email client
            mailto_link = f"mailto:{recipient}?subject={subject}&body={body}"
            return redirect(mailto_link)

        except Exception as e:
            app_logger.error(f"Error in email composition: {str(e)}")
            return redirect(url_for('cryptogram.index'))

    return redirect(url_for('cryptogram.index'))


@bp.route('/send_email', methods=['GET', 'POST'])
def send_email():
    """Handle sending emails through the application."""
    app_logger.info("Accessed send email route")

    if 'loggedin' not in session:
        app_logger.warning("Unauthorized access attempt to send email")
        return redirect(url_for('cryptogram.login'))

    if request.method == 'POST':
        try:
            email = request.form['email']
            subject = request.form['subject']
            body = request.form['body']

            app_logger.debug(f"Sending email to: {email}, Subject: {subject}")

            # Create and send email message
            msg = Message(
                subject,
                recipients=[email]
            )
            msg.body = body
            mail.send(msg)

            app_logger.info(f"Email sent successfully to: {email}")
            flash('Email sent successfully!', 'success')
            return redirect(url_for('cryptogram.send_email'))

        except Exception as e:
            app_logger.error(f"Error sending email: {str(e)}")
            flash('Failed to send email. Please try again.', 'error')

    return render_template('send_email.html')


@bp.errorhandler(404)
def not_found_error(error):
    """Handle 404 Not Found errors."""
    app_logger.warning(f"404 error: {request.url}")
    return render_template('errors/404.html'), 404


@bp.errorhandler(500)
def internal_error(error):
    """Handle 500 Internal Server Error."""
    app_logger.error(f"500 error: {str(error)}")
    db.session.rollback()
    return render_template('errors/500.html'), 500


@bp.route('/send-key-email', methods=['POST'])
def send_key_email():
    data = request.json
    try:
        response = EmailService.send_key_email(data['email'], data['key'] )
        return jsonify({'success': response})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
