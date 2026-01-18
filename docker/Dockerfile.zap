# ZAP 스캐너 도커 이미지
# OWASP ZAP를 사용하여 웹 애플리케이션 보안 스캔을 수행합니다.
# 공식 ZAP 이미지를 베이스로 사용

FROM zaproxy/zap-stable:latest

# root 사용자로 전환 (권한 문제 해결)
USER root

# Python 설치 (ZAP 이미지에 Python이 없을 수 있음)
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Python 심볼릭 링크 생성 (이미 존재하면 무시)
RUN ln -sf /usr/bin/python3 /usr/bin/python || true

# 작업 디렉토리 설정
WORKDIR /app

# Python 의존성 설치 (externally-managed-environment 오류 해결)
COPY requirements.txt .
RUN pip install --no-cache-dir --break-system-packages -r requirements.txt

# 앱 디렉토리 복사 (워커 스크립트가 app 모듈을 import하기 위해 필요)
COPY app /app/app

# 워커 스크립트 복사
COPY docker/workers/zap_worker.py /app/worker.py

# ZAP 실행 스크립트 (백그라운드)
COPY docker/workers/start_zap.sh /app/start_zap.sh
RUN chmod +x /app/start_zap.sh

# PYTHONPATH 환경 변수 설정
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# 실행 명령 (ZAP 시작 후 워커 실행, unbuffered 모드)
CMD ["/app/start_zap.sh"]

