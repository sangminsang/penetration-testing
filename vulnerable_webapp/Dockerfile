FROM python:3.12-slim

WORKDIR /app

# 시스템 패키지 설치 (ping, nslookup 등 명령어 사용을 위해)
RUN apt-get update && apt-get install -y \
    iputils-ping \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Python 패키지 설치
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 애플리케이션 파일 복사
COPY . .

# 포트 노출
EXPOSE 5000

# 애플리케이션 실행
CMD ["python", "app.py"]

