# 1. 베이스 이미지 설정
FROM python:3.9-slim

# 2. 필수 시스템 도구 및 종속성 설치
RUN apt-get update && apt-get install -y \
    wget \
    git \
    unzip \
    curl \
    nmap \
    whatweb \
    && rm -rf /var/lib/apt/lists/*

# 3. Nuclei 설치 (-o 옵션 추가)
RUN wget https://github.com/projectdiscovery/nuclei/releases/download/v3.3.5/nuclei_3.3.5_linux_amd64.zip \
    && unzip -o nuclei_3.3.5_linux_amd64.zip \
    && mv nuclei /usr/local/bin/ \
    && rm nuclei_3.3.5_linux_amd64.zip

# 3-1. Nuclei 템플릿 다운로드 (스캔 결과 생성을 위해 필수)
RUN nuclei -update-templates

# 4. Katana 설치 (-o 옵션 추가)
RUN wget https://github.com/projectdiscovery/katana/releases/download/v1.1.0/katana_1.1.0_linux_amd64.zip \
    && unzip -o katana_1.1.0_linux_amd64.zip \
    && mv katana /usr/local/bin/ \
    && rm katana_1.1.0_linux_amd64.zip

# 5. 작업 디렉토리 설정 및 코드 복사
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# 6. 환경 변수 설정
ENV PYTHONPATH=/app

# 7. 실행 명령
CMD ["python", "worker_entry.py"]
