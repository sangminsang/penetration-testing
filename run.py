"""
Flask 애플리케이션 실행 스크립트

이 스크립트는 Flask 애플리케이션을 시작합니다.
"""

import eventlet

# Eventlet monkey patch 적용 (비동기 처리)
eventlet.monkey_patch()

# Windows 인코딩 문제 해결
import sys
import io
import os

os.environ['PYTHONIOENCODING'] = 'utf-8'
if sys.stdout.encoding != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
if sys.stderr.encoding != 'utf-8':
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

from app import create_app, socketio

# Flask 앱 생성
app, _ = create_app()

if __name__ == "__main__":
    # Flask 애플리케이션 실행
    # - host: 모든 네트워크 인터페이스에서 접근 가능
    # - port: 5000 포트 사용
    # - debug: 개발 모드 (프로덕션에서는 False로 설정)
    socketio.run(
        app,
        host="0.0.0.0",
        port=5000,
        debug=True,
        use_reloader=False
    )

