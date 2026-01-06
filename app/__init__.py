from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
import os

db = SQLAlchemy()
socketio = SocketIO()

def create_app():
    app = Flask(__name__)
    basedir = os.path.abspath(os.path.dirname(__file__))
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, '../project.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = 'security-secret-key'

    db.init_app(app)
    socketio.init_app(app, cors_allowed_origins="*")

    # 웹소켓 핸들러 등록
    from app.api.websocket import register_socketio_handlers, ScanProgressEmitter
    register_socketio_handlers(socketio, ScanProgressEmitter(socketio))

    from app.routes import bp
    app.register_blueprint(bp)

    with app.app_context():
        db.create_all()

    return app, socketio


