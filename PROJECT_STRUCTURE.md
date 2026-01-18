# 프로젝트 구조 설명

## 전체 구조

```
new/
├── app/                          # 메인 애플리케이션
│   ├── __init__.py              # Flask 앱 초기화
│   ├── config.py                 # 설정 파일
│   ├── models.py                 # 데이터베이스 모델
│   ├── routes.py                 # 웹 라우트
│   ├── run.py                    # 실행 스크립트 (루트에 있음)
│   │
│   ├── api/                      # API 엔드포인트
│   │   ├── __init__.py
│   │   ├── scan.py               # 스캔 API
│   │   └── websocket.py           # WebSocket 핸들러
│   │
│   ├── core/                     # 핵심 비즈니스 로직
│   │   ├── scanners/             # 스캐너 모듈
│   │   │   ├── __init__.py
│   │   │   ├── nmap_scanner.py   # Nmap 스캐너
│   │   │   ├── nuclei_scanner.py # Nuclei 스캐너
│   │   │   ├── zap_scanner.py    # ZAP 스캐너
│   │   │   └── scan_orchestrator.py # 스캔 오케스트레이터
│   │   │
│   │   ├── processors/           # 데이터 처리 모듈
│   │   │   ├── __init__.py
│   │   │   ├── cpe_parser.py     # CPE 파서
│   │   │   ├── nvd_mapper.py     # NVD 매퍼
│   │   │   └── data_aggregator.py # 데이터 집계기
│   │   │
│   │   ├── ai/                   # AI 모듈
│   │   │   ├── __init__.py
│   │   │   ├── llama_client.py  # Llama 클라이언트
│   │   │   ├── scenario_generator.py # 공격 시나리오 생성기
│   │   │   └── attack_executor.py # 공격 실행기
│   │   │
│   │   └── reporting/            # 보고서 생성 모듈
│   │       ├── __init__.py
│   │       └── report_generator.py # 보고서 생성기
│   │
│   ├── static/                   # 정적 파일
│   │   └── css/
│   │       ├── style.css
│   │       └── dashboard.css
│   │
│   └── templates/                # HTML 템플릿
│       ├── base.html
│       ├── projects.html
│       └── dashboard.html
│
├── docker/                       # 도커 설정
│   ├── Dockerfile.nmap           # Nmap 도커 이미지
│   ├── Dockerfile.nuclei         # Nuclei 도커 이미지
│   ├── Dockerfile.zap             # ZAP 도커 이미지
│   ├── Dockerfile.web            # 웹 앱 도커 이미지
│   └── workers/                  # 도커 워커 스크립트
│       ├── nmap_worker.py
│       ├── nuclei_worker.py
│       ├── zap_worker.py
│       └── start_zap.sh
│
├── docker-compose.yml            # 도커 컴포즈 설정
├── requirements.txt              # Python 의존성
├── run.py                        # 실행 스크립트
├── README.md                     # 프로젝트 설명
└── PROJECT_STRUCTURE.md          # 이 파일
```

## 주요 모듈 설명

### 1. 스캐너 모듈 (`app/core/scanners/`)

- **nmap_scanner.py**: 네트워크 포트 및 서비스 탐지
- **nuclei_scanner.py**: Katana로 URL 수집, Nuclei로 취약점 탐지
- **zap_scanner.py**: OWASP ZAP를 사용한 웹 애플리케이션 보안 스캔
- **scan_orchestrator.py**: 3개의 스캐너를 도커 컨테이너에서 병렬 실행

### 2. 데이터 처리 모듈 (`app/core/processors/`)

- **cpe_parser.py**: 스캔 결과에서 CPE(Common Platform Enumeration) 추출
- **nvd_mapper.py**: CPE를 기반으로 NVD 데이터베이스에서 CVE 검색
- **data_aggregator.py**: 여러 스캔 결과를 통합하고 정제

### 3. AI 모듈 (`app/core/ai/`)

- **llama_client.py**: Ollama를 통해 Llama 모델과 통신
- **scenario_generator.py**: 스캔 결과를 기반으로 공격 시나리오 생성
- **attack_executor.py**: 생성된 공격 시나리오를 실제로 실행 (시뮬레이션)

### 4. 보고서 생성 모듈 (`app/core/reporting/`)

- **report_generator.py**: 모든 결과를 종합하여 최종 보안 진단 보고서 생성

## 워크플로우

1. **사용자 입력**: 대시보드에서 타겟 URL 입력
2. **스캔 실행**: 도커 컨테이너에서 Nmap, Nuclei, ZAP 병렬 실행
3. **결과 통합**: 스캔 결과를 파일로 저장하고 통합
4. **CPE 파싱**: 기술 스택 정보에서 CPE 추출
5. **NVD 매핑**: CPE를 기반으로 CVE 검색
6. **AI 분석**: Llama AI가 공격 시나리오 생성
7. **공격 실행**: 생성된 시나리오 실행 (선택적)
8. **보고서 생성**: 최종 보안 진단 보고서 작성

## 실행 방법

```bash
# 1. 의존성 설치
pip install -r requirements.txt

# 2. 도커 이미지 빌드
docker build -f docker/Dockerfile.nmap -t security-scanner-nmap:latest .
docker build -f docker/Dockerfile.nuclei -t security-scanner-nuclei:latest .
docker build -f docker/Dockerfile.zap -t security-scanner-zap:latest .
docker build -f docker/Dockerfile.web -t security-scanner-web:latest .

# 3. 도커 컴포즈 실행
docker-compose up -d

# 4. Flask 앱 실행
python run.py
```

## 주의사항

- 실제 공격 실행 기능은 시뮬레이션 모드로 구현되어 있습니다.
- 프로덕션 환경에서는 실제 공격 실행 기능을 비활성화하거나 제한해야 합니다.
- MongoDB와 Ollama가 실행 중이어야 합니다.

