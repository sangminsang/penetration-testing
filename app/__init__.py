"""
Flask 애플리케이션 초기화 모듈

이 모듈은 Flask 앱을 생성하고 설정하는 역할을 합니다.
- 데이터베이스 연결 설정
- WebSocket (SocketIO) 설정
- 라우트 등록
"""

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
from flask_cors import CORS
import os
import sys
import io

# Windows 인코딩 문제 해결: UTF-8 강제 설정
os.environ['PYTHONIOENCODING'] = 'utf-8'
if sys.stdout.encoding != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
if sys.stderr.encoding != 'utf-8':
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# 데이터베이스 및 WebSocket 객체 생성
db = SQLAlchemy()
socketio = SocketIO()
cors = CORS()


def create_app():
    """
    Flask 애플리케이션 팩토리 함수
    
    Returns:
        app: Flask 애플리케이션 인스턴스
        socketio: SocketIO 인스턴스
    """
    # Flask 앱 생성
    app = Flask(__name__)
    
    # 기본 디렉토리 경로 설정
    basedir = os.path.abspath(os.path.dirname(__file__))
    
    # 설정 파일 로드
    from app.config import Config
    app.config.from_object(Config)
    
    # 데이터베이스 URI 설정 (SQLite 사용)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(
        basedir, '../data/project.db'
    )
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'security-secret-key-change-in-production')
    
    # 확장 초기화
    db.init_app(app)
    cors.init_app(app)
    
    # WebSocket 설정 (스캔 진행 상황 실시간 전송용)
    socketio.init_app(
        app,
        cors_allowed_origins="*",
        ping_timeout=600,      # 10분 타임아웃 (긴 스캔 작업 대응)
        ping_interval=25,      # 25초마다 ping 전송
        async_mode='eventlet'  # 비동기 모드
    )
    
    # WebSocket 핸들러 등록
    from app.api.websocket import register_socketio_handlers
    register_socketio_handlers(socketio)
    
    # 라우트 등록
    from app.routes import bp
    app.register_blueprint(bp)
    
    # API 라우트 등록
    from app.api.scan import api_bp
    app.register_blueprint(api_bp)
    
    # 데이터베이스 테이블 생성
    with app.app_context():
        db.create_all()
    
    return app, socketio

