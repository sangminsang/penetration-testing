# 설치 및 실행 가이드

## 사전 요구사항

1. **Python 3.9 이상**
2. **Docker & Docker Compose**
3. **MongoDB** (NVD 데이터베이스용, 선택적)
4. **Ollama** (Llama AI 실행용)

## 설치 단계

### 1. 프로젝트 클론 및 이동

```bash
cd new
```

### 2. Python 의존성 설치

```bash
pip install -r requirements.txt
```

### 3. Ollama 설치 및 모델 다운로드

```bash
# Ollama 설치 (https://ollama.ai 참고)
# Windows: https://ollama.ai/download/windows

# 모델 다운로드 (예: llama3:8b)
ollama pull llama3:8b
```

### 4. MongoDB 설정 (선택적)

NVD 데이터베이스를 사용하려면 MongoDB가 필요합니다.

```bash
# MongoDB 설치 및 실행
# 또는 docker-compose.yml의 mongodb 서비스 사용
```

### 5. 도커 이미지 빌드

```bash
# Nmap 스캐너 이미지
docker build -f docker/Dockerfile.nmap -t security-scanner-nmap:latest .

# Nuclei 스캐너 이미지
docker build -f docker/Dockerfile.nuclei -t security-scanner-nuclei:latest .

# ZAP 스캐너 이미지
docker build -f docker/Dockerfile.zap -t security-scanner-zap:latest .

# 웹 애플리케이션 이미지
docker build -f docker/Dockerfile.web -t security-scanner-web:latest .
```

### 6. 환경 변수 설정 (선택적)

`.env` 파일 생성 (선택적):

```env
OLLAMA_BASE_URL=http://127.0.0.1:11434
OLLAMA_MODEL=llama3:8b
MONGO_HOST=127.0.0.1
MONGO_PORT=27017
ZAP_PROXY_HOST=127.0.0.1
ZAP_PROXY_PORT=8080
```

## 실행 방법

### 방법 1: 도커 컴포즈 사용 (권장)

```bash
# 모든 서비스 시작
docker-compose up -d

# 로그 확인
docker-compose logs -f

# 서비스 중지
docker-compose down
```

### 방법 2: 로컬에서 직접 실행

```bash
# 1. MongoDB, Redis, ZAP가 실행 중이어야 함
# 2. Flask 앱 실행
python run.py
```

웹 브라우저에서 `http://localhost:5000` 접속

## 사용 방법

1. **프로젝트 생성**
   - 웹 브라우저에서 프로젝트 목록 페이지 접속
   - "새 프로젝트 생성" 폼에 프로젝트 이름과 타겟 URL 입력
   - "프로젝트 생성" 버튼 클릭

2. **스캔 시작**
   - 프로젝트 목록에서 "대시보드" 버튼 클릭
   - "스캔 시작" 버튼 클릭
   - 스캔 진행 상황이 실시간으로 표시됨

3. **결과 확인**
   - 스캔 완료 후 대시보드에서 결과 확인
   - AI 분석 결과 및 최종 보고서 확인

## 문제 해결

### Ollama 연결 실패
- Ollama가 실행 중인지 확인: `ollama list`
- `OLLAMA_BASE_URL` 환경 변수 확인

### MongoDB 연결 실패
- MongoDB가 실행 중인지 확인
- `MONGO_HOST`, `MONGO_PORT` 환경 변수 확인
- NVD API를 사용하도록 설정 변경 가능

### 도커 컨테이너 실행 실패
- 도커 이미지가 빌드되었는지 확인: `docker images`
- 도커 네트워크 확인: `docker network ls`

### ZAP 연결 실패
- ZAP 컨테이너가 실행 중인지 확인
- `ZAP_PROXY_HOST`, `ZAP_PROXY_PORT` 환경 변수 확인

## 개발 모드

개발 중에는 다음과 같이 실행:

```bash
# 디버그 모드로 실행
export FLASK_ENV=development
python run.py
```

## 프로덕션 배포

프로덕션 환경에서는:

1. `SECRET_KEY` 환경 변수 설정
2. `debug=False`로 설정
3. HTTPS 사용
4. 실제 공격 실행 기능 비활성화

