# 프로젝트 구조 재구성 계획

## 새로운 폴더 구조

```
app/
├── core/                    # 핵심 기능 모듈
│   ├── __init__.py
│   ├── cve/                 # CVE 관련 모듈
│   │   ├── __init__.py
│   │   ├── database.py      # CVE 데이터베이스 관리 (신규)
│   │   ├── classifier.py    # CVE 분류 시스템 (신규)
│   │   └── matcher.py       # CVE 매칭 엔진 (nvd_client.py 기반)
│   ├── recon/               # 정보 수집 모듈
│   │   ├── __init__.py
│   │   ├── network.py       # 네트워크 정보 수집 (nmap_recon.py 기반)
│   │   ├── web.py           # 웹 정보 수집 (신규)
│   │   ├── osint.py         # OSINT 정보 수집 (신규)
│   │   └── supply_chain.py  # 공급망 정보 수집 (신규)
│   ├── scanner/             # 스캐너 모듈
│   │   ├── __init__.py
│   │   ├── mode_selector.py # 모드 선택 시스템 (신규)
│   │   └── scanner.py       # 통합 스캐너 (신규)
│   └── scenario/             # 공격 시나리오 생성
│       ├── __init__.py
│       ├── generator.py      # 시나리오 생성 (ai_client.py 기반)
│       └── reporter.py      # 보고서 생성 (loot_generator.py 기반)
├── api/                      # API 엔드포인트
│   ├── __init__.py
│   └── routes.py            # 기존 routes.py 이동
├── utils/                    # 유틸리티 모듈
│   ├── __init__.py
│   ├── exploit.py           # Exploit 정보 (searchsploit_client.py 기반)
│   ├── cpe.py               # CPE 변환 유틸리티 (신규)
│   └── version.py           # 버전 비교 유틸리티 (신규)
├── config.py                # 설정 파일 (기존 유지)
├── __init__.py              # Flask 앱 팩토리 (기존 유지)
└── static/                  # 정적 파일 (기존 유지)
    ├── css/
    └── js/
└── templates/               # 템플릿 (기존 유지)
```

## 파일 매핑

### 기존 파일 → 새 위치

1. **nmap_recon.py** → `core/recon/network.py`
2. **nvd_client.py** → `core/cve/matcher.py` (일부 기능)
3. **ai_client.py** → `core/scenario/generator.py`
4. **loot_generator.py** → `core/scenario/reporter.py`
5. **searchsploit_client.py** → `utils/exploit.py`
6. **routes.py** → `api/routes.py`
7. **config.py** → `config.py` (유지)
8. **cve_client.py, cve_bin_client.py** → 통합 검토 필요

## 구현 순서

1. 폴더 구조 생성
2. 기존 파일 이동 및 리팩토링
3. 새로운 모듈 생성 (database, classifier, mode_selector 등)
4. Import 경로 수정
5. 통합 테스트

