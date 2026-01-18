# 도커 이미지 빌드 가이드

## 빌드 방법

### 방법 1: 개별 빌드 (권장)

`new` 폴더에서 다음 명령어들을 실행하세요:

```bash
# Nmap 스캐너 이미지 빌드
docker build -f docker/Dockerfile.nmap -t security-scanner-nmap:latest .

# Nuclei 스캐너 이미지 빌드
docker build -f docker/Dockerfile.nuclei -t security-scanner-nuclei:latest .

# ZAP 스캐너 이미지 빌드
docker build -f docker/Dockerfile.zap -t security-scanner-zap:latest .

# 웹 애플리케이션 이미지 빌드 (docker-compose에서 자동 빌드되지만 수동으로도 가능)
docker build -f docker/Dockerfile.web -t security-scanner-web:latest .
```

### 방법 2: 한 번에 빌드 (스크립트)

Windows PowerShell:
```powershell
docker build -f docker/Dockerfile.nmap -t security-scanner-nmap:latest .
docker build -f docker/Dockerfile.nuclei -t security-scanner-nuclei:latest .
docker build -f docker/Dockerfile.zap -t security-scanner-zap:latest .
```

Linux/Mac:
```bash
docker build -f docker/Dockerfile.nmap -t security-scanner-nmap:latest . && \
docker build -f docker/Dockerfile.nuclei -t security-scanner-nuclei:latest . && \
docker build -f docker/Dockerfile.zap -t security-scanner-zap:latest .
```

## 빌드 확인

빌드가 완료되면 다음 명령어로 확인할 수 있습니다:

```bash
docker images | grep security-scanner
```

다음과 같은 이미지들이 보여야 합니다:
- `security-scanner-nmap:latest`
- `security-scanner-nuclei:latest`
- `security-scanner-zap:latest`
- `security-scanner-web:latest` (docker-compose up 후)

## 실행

이미지 빌드가 완료되면:

```bash
# docker-compose로 서비스 시작 (web, mongodb, redis, zap)
docker-compose up -d

# 또는 웹 앱만 로컬에서 실행
python run.py
```

## 주의사항

- 각 이미지는 약 500MB~1GB 정도의 크기를 가질 수 있습니다.
- Nuclei와 Katana는 GitHub에서 다운로드하므로 인터넷 연결이 필요합니다.
- 빌드 시간은 네트워크 속도에 따라 5~15분 정도 소요될 수 있습니다.

