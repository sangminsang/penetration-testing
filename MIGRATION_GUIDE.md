# 프로젝트 구조 재구성 가이드

## 변경 사항

### 폴더 구조

기존의 평면적인 구조에서 모듈화된 구조로 변경되었습니다:

**기존:**
```
app/
├── nmap_recon.py
├── nvd_client.py
├── ai_client.py
├── loot_generator.py
├── searchsploit_client.py
├── routes.py
└── config.py
```

**새로운 구조:**
```
app/
├── core/                    # 핵심 기능 모듈
│   ├── cve/                 # CVE 관련
│   │   └── matcher.py       # CVE 매칭 (nvd_client.py 기반)
│   ├── recon/               # 정보 수집
│   │   └── network.py       # 네트워크 정보 (nmap_recon.py 기반)
│   ├── scanner/             # 스캐너 (향후 구현)
│   └── scenario/            # 공격 시나리오
│       ├── generator.py     # 시나리오 생성 (ai_client.py 기반)
│       └── reporter.py      # 보고서 생성 (loot_generator.py 기반)
├── api/                     # API 엔드포인트
│   └── routes.py            # 기존 routes.py 이동
├── utils/                   # 유틸리티
│   └── exploit.py           # Exploit 정보 (searchsploit_client.py 기반)
└── config.py                # 설정 (기존 유지)
```

## Import 경로 변경

### 기존 코드
```python
from .nmap_recon import run_recon
from .nvd_client import NvdClient
from .ai_client import build_prompt, call_ollama
from .loot_generator import enrich_loot
from .searchsploit_client import search_exploits_for_cves
```

### 새로운 코드
```python
from ..core.recon.network import run_recon
from ..core.cve.matcher import NvdClient
from ..core.scenario.generator import build_prompt, call_ollama
from ..core.scenario.reporter import enrich_loot
from ..utils.exploit import search_exploits_for_cves
```

## 기존 파일 처리

다음 파일들은 새 구조로 이동되었습니다:

1. ✅ `nmap_recon.py` → `core/recon/network.py`
2. ✅ `nvd_client.py` → `core/cve/matcher.py`
3. ✅ `ai_client.py` → `core/scenario/generator.py`
4. ✅ `loot_generator.py` → `core/scenario/reporter.py`
5. ✅ `searchsploit_client.py` → `utils/exploit.py`
6. ✅ `routes.py` → `api/routes.py`

## 향후 구현 예정

다음 모듈들은 기획서에 따라 향후 구현될 예정입니다:

### Phase 1: CVE 데이터베이스 및 분류
- `core/cve/database.py` - CVE 데이터베이스 관리
- `core/cve/classifier.py` - CVE 분류 시스템

### Phase 2: 정보 수집 확장
- `core/recon/web.py` - 웹 정보 수집
- `core/recon/osint.py` - OSINT 정보 수집
- `core/recon/supply_chain.py` - 공급망 정보 수집

### Phase 3: 모드별 스캐너
- `core/scanner/mode_selector.py` - 모드 선택 시스템
- `core/scanner/scanner.py` - 통합 스캐너

### Phase 4: 유틸리티
- `utils/cpe.py` - CPE 변환 유틸리티
- `utils/version.py` - 버전 비교 유틸리티

## 테스트 방법

1. 기존 기능이 정상 작동하는지 확인:
```bash
python run.py
```

2. API 엔드포인트 테스트:
```bash
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com"}'
```

## 주의사항

- 기존 파일들은 백업을 위해 유지하되, 새 구조의 파일을 사용합니다
- `app/__init__.py`의 import 경로가 업데이트되었습니다
- 모든 기능은 기존과 동일하게 작동해야 합니다

