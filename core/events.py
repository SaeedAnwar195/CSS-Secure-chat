from flask import request
from flask_socketio import emit
from core import socketio
from core.logger import app_logger

# Store active client connections
clients = {}
clients_sid = {}
all_clients = {}

@socketio.on('connect')
def handle_connect():
    """Handle new client connections."""
    app_logger.info("New client connected")

@socketio.on('user_join')
def handle_user_join(data):
    """
    Handle user joining the chat system.
    Stores user connection info and broadcasts updated user list.
    """
    try:
        app_logger.info(f"Processing user join: {data.get('recipient')}")
        app_logger.debug(f"Join data - Recipient Name: {data.get('recipient')}, Email: {data.get('email')}")

        recipient = data['recipient']
        
        # Store user connection information
        clients_sid[recipient] = request.sid
        clients[request.sid] = recipient
        all_clients[recipient] = data['email']

        app_logger.info(f"User {recipient} joined successfully")
        # Broadcast updated user list to all clients
        emit("allUsers", {"allClients": all_clients}, broadcast=True)
        
    except Exception as e:
        app_logger.error(f"Error in user join: {str(e)}")
        emit('error', {'message': 'An unexpected error occurred'})

@socketio.on('send_email_notification')
def handle_send_email_notification(data):
    """Handle email notification sending between users."""
    try:
        recipient = data['recipient_name']
        if recipient in clients_sid:
            recipient_sid = clients_sid[recipient]
            
            app_logger.debug(f"Sending email notification - Recipient: {recipient}, SID: {recipient_sid}")
            app_logger.debug(f"Sender: {clients[request.sid]}")
            
            emit('email_send_notify', {
                'notification': data['notification'],
                'sender': clients[request.sid]
            }, room=recipient_sid)
        else:
            app_logger.warning(f"Recipient not connected: {recipient}")
            
    except Exception as e:
        app_logger.error(f"Error sending email notification: {str(e)}")

@socketio.on('reply_email_notification')
def handle_reply_email_notification(data):
    """Handle email reply notifications between users."""
    try:
        recipient = data['recipient_name']
        if recipient in clients_sid:
            recipient_sid = clients_sid[recipient]
            
            app_logger.debug(f"Sending reply notification - Recipient: {recipient}, SID: {recipient_sid}")
            app_logger.debug(f"Sender: {clients[request.sid]}")
            
            emit('email_reply_notify', {
                'notification': data['notification'],
                'sender': clients[request.sid]
            }, room=recipient_sid)
        else:
            app_logger.warning(f"Recipient not connected: {recipient}")
            
    except Exception as e:
        app_logger.error(f"Error sending reply notification: {str(e)}")

@socketio.on('message')
def handle_message(data):
    """Handle chat message sending between users."""
    try:
        recipient = data['recipient_name']
        app_logger.debug(f"Processing message - Recipient: {recipient}")
        app_logger.debug(f"Message content: {data['message']}")

        if recipient in clients_sid:
            recipient_sid = clients_sid[recipient]
            app_logger.debug(f"Sending to client: {recipient_sid}")
            
            emit('message', {
                'message': data['message'],
                'sender': clients[request.sid]
            }, room=recipient_sid)
        else:
            app_logger.warning(f"Recipient not connected: {recipient}")
            
    except Exception as e:
        app_logger.error(f"Error handling message: {str(e)}")

@socketio.on('logout')
def handle_logout(data):
    """Handle user logout, cleanup connections and notify others."""
    try:
        app_logger.info(f"Processing logout: {data}")
        
        if request.sid in clients:
            user = clients[request.sid]
            app_logger.info(f"Logging out user: {user}")
            
            # Clean up user data
            del clients_sid[user]
            del all_clients[user]
            del clients[request.sid]

            # Notify other users
            emit("logoutUsers", {"logoutUser": user}, broadcast=True)
            emit('logout_redirect', room=request.sid)
            
            app_logger.info(f"User {user} logged out successfully")
        else:
            app_logger.warning(f"Session ID not found: {request.sid}")
            
    except Exception as e:
        app_logger.error(f"Error during logout: {str(e)}")
        emit('error', {'message': 'Logout failed'}, room=request.sid)

@socketio.on('typing')
def handle_typing(data):
    """Handle typing indicator notifications."""
    try:
        recipient = data['recipient']
        if recipient in clients_sid:
            recipient_sid = clients_sid[recipient]
            app_logger.debug(f"User typing: {clients[request.sid]}")
            
            emit('typing', {
                'sender': clients[request.sid]
            }, room=recipient_sid)
            
    except Exception as e:
        app_logger.error(f"Error handling typing indicator: {str(e)}")

@socketio.on('stop_typing')
def handle_stop_typing(data):
    """Handle stop typing notifications."""
    try:
        recipient = data['recipient']
        if recipient in clients_sid:
            recipient_sid = clients_sid[recipient]
            app_logger.debug(f"User stopped typing: {clients[request.sid]}")
            
            emit('stop_typing', {
                'sender': clients[request.sid]
            }, room=recipient_sid)
            
    except Exception as e:
        app_logger.error(f"Error handling stop typing: {str(e)}")

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection."""
    app_logger.info("Client disconnected")
    
    if request.sid in clients:
        user = clients[request.sid]
        app_logger.info(f"Cleaning up session for user: {user}")
        
        # Clean up user data
        if user in clients_sid:
            del clients_sid[user]
        if user in all_clients:
            del all_clients[user]
        del clients[request.sid]