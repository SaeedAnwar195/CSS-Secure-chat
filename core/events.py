from flask import request
from flask_socketio import emit
from core import socketio
from core.utilities.helpers import ChatManager

@socketio.on('connect')
def handle_connect():
    print('Client Connected')

@socketio.on('user_join')
def handle_user_join(data):
    try:
        print(f"Recipient Name-------> {data['recipient']}")
        print(f"Recipient Email-------> {data['email']}")

        recipient = data['recipient']
        active_users = ChatManager.add_user(recipient, request.sid, data['email'])
        emit("allUsers", {"allClients": active_users}, broadcast=True)
    
    except Exception as ex:
        print(f"An error occurred: {ex}")
        emit('error', {'message': 'An unexpected error occurred'})

@socketio.on('send_email_notification')
def handle_send_email_notification(data):
    try:
        recipient = data['recipient_name']
        recipient_sid = ChatManager.get_user_session(recipient)
        
        if recipient_sid:
            emit('email_send_notify', {
                'notification': data['notification'],
                'sender': ChatManager._session_map[request.sid]
            }, room=recipient_sid)
        else:
            print('Recipient not connected.')
    except Exception as ex:
        print(f"An error occurred: {ex}")

@socketio.on('reply_email_notification')
def handle_reply_email_notification(data):
    try:
        recipient = data['recipient_name']
        recipient_sid = ChatManager.get_user_session(recipient)
        
        if recipient_sid:
            emit('email_reply_notify', {
                'notification': data['notification'],
                'sender': ChatManager._session_map[request.sid]
            }, room=recipient_sid)
        else:
            print('Recipient not connected.')
    except Exception as ex:
        print(f"An error occurred: {ex}")

@socketio.on('message')
def handle_message(data):
    try:
        recipient = data['recipient_name']
        recipient_sid = ChatManager.get_user_session(recipient)
        
        if recipient_sid:
            emit('message', {
                'message': data['message'],
                'sender': ChatManager._session_map[request.sid]
            }, room=recipient_sid)
        else:
            print('Recipient not connected.')
    except Exception as ex:
        print(f"An error occurred: {ex}")

@socketio.on('logout')
def handle_logout(data):
    try:
        if request.sid in ChatManager._session_map:
            username = ChatManager.remove_user(request.sid)
            if username:
                emit("logoutUsers", {"logoutUser": username}, broadcast=True)
                emit('logout_redirect', room=request.sid)
        else:
            print(f"Session ID {request.sid} not found")
    except Exception as ex:
        print(f"An error occurred: {ex}")
        emit('error', {'message': 'Logout failed'}, room=request.sid)

@socketio.on('typing')
def handle_typing(data):
    try:
        recipient = data['recipient']
        recipient_sid = ChatManager.get_user_session(recipient)
        if recipient_sid:
            emit('typing', {
                'sender': ChatManager._session_map[request.sid]
            }, room=recipient_sid)
    except Exception as ex:
        print(f"An error occurred: {ex}")

@socketio.on('stop_typing')
def handle_stop_typing(data):
    try:
        recipient = data['recipient']
        recipient_sid = ChatManager.get_user_session(recipient)
        if recipient_sid:
            emit('stop_typing', {
                'sender': ChatManager._session_map[request.sid]
            }, room=recipient_sid)
    except Exception as ex:
        print(f"An error occurred: {ex}")