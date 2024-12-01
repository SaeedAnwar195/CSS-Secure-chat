from flask import Flask
from flask_socketio import SocketIO
from core import create_app
from core.events import socketio

from gevent import monkey
monkey.patch_all()

app = create_app()

if __name__ == '__main__':
    socketio.run(app, debug=True)