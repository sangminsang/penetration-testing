#!/bin/bash
# ZAP 시작 스크립트
# ZAP를 백그라운드로 실행한 후 워커 스크립트를 실행합니다.

# ZAP 시작 (백그라운드)
/opt/zap/zap.sh -daemon -host 0.0.0.0 -port 8080 \
    -config api.addrs.addr.name=.* \
    -config api.addrs.addr.regex=true \
    -config api.key=12345 &

# ZAP가 시작될 때까지 대기
echo "ZAP 서버 시작 대기 중..."
sleep 10

# 워커 스크립트 실행 (unbuffered 모드로 출력 즉시 반영)
python -u /app/worker.py

