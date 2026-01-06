import eventlet
eventlet.monkey_patch() # 이 코드가 맨 위에 와야 합니다!

from app import create_app, socketio

app, _ = create_app()

if __name__ == "__main__":
    # 포트 5000에서 실행
    socketio.run(app, host="0.0.0.0", port=5000, debug=True, use_reloader=False)
