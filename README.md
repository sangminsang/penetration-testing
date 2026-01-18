# 보안 진단 자동화 솔루션

## 프로젝트 개요
이 프로젝트는 타겟 URL에 대한 종합적인 보안 진단을 자동으로 수행하는 시스템입니다.

## 아키텍처

### 워크플로우
1. **사용자 입력**: 대시보드에서 타겟 URL 입력
2. **스캔 단계**: 3개의 도커 컨테이너에서 병렬 스캔 수행
   - Nmap: 네트워크 포트 및 서비스 탐지
   - Nuclei (Katana): 웹 취약점 탐지
   - ZAP: 웹 애플리케이션 보안 스캔
3. **데이터 처리**: 스캔 결과 통합, CPE 파싱, NVD DB 매핑
4. **AI 분석**: Llama AI를 통한 공격 시나리오 생성 및 실행
5. **보고서 생성**: 최종 진단 보고서 작성

### 폴더 구조
```
new/
├── app/                    # 메인 애플리케이션
│   ├── core/              # 핵심 비즈니스 로직
│   │   ├── scanners/      # 스캐너 모듈 (nmap, nuclei, zap)
│   │   ├── processors/    # 데이터 처리 모듈 (CPE 파싱, NVD 매핑)
│   │   ├── ai/           # AI 관련 모듈 (Llama 클라이언트, 공격 실행)
│   │   └── reporting/    # 보고서 생성 모듈
│   ├── api/              # API 엔드포인트
│   ├── static/           # 정적 파일 (CSS, JS)
│   └── templates/        # HTML 템플릿
├── docker/               # 도커 설정 파일
├── scan_results/         # 스캔 결과 저장 폴더
└── data/                # 데이터베이스 및 캐시
```

## 설치 및 실행

### 요구사항
- Docker & Docker Compose
- Python 3.9+
- MongoDB (NVD 데이터베이스용)
- Ollama (Llama AI 실행용)

### 실행 방법
```bash
# 1. 의존성 설치
pip install -r requirements.txt

# 2. 도커 컨테이너 빌드 및 실행
docker-compose up -d

# 3. Flask 애플리케이션 실행
python run.py
```

## 주요 기능
- 자동화된 보안 스캔 (Nmap, Nuclei, ZAP)
- CPE 기반 취약점 매핑
- AI 기반 공격 시나리오 생성
- 자동 공격 실행 및 검증
- 종합 보안 진단 보고서 생성

