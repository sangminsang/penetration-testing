# 중복 파일 분석 및 정리 제안

## 🔴 완전 중복 (삭제 가능)

### 1. `routes.py` (구버전)
- **상태**: `__init__.py`에서 사용하지 않음
- **대체**: `api/routes.py` (완전 개선 버전)
- **기능 차이**: 
  - 구버전: 동기식, 기본 기능만
  - 신버전: 비동기, 캐시 관리, 상세 스캔 (Network/Web/OS/DB/Cloud/Container)
- **권장**: ✅ **삭제 가능**

### 2. `nmap_recon.py` (구버전)
- **상태**: `routes.py`에서만 사용 (사용되지 않는 파일)
- **대체**: `core/recon/network.py` (NSE 스크립트, 상세 분석 포함)
- **권장**: ✅ **삭제 가능**

### 3. `ai_client.py` (구버전)
- **상태**: `routes.py`에서만 사용 (사용되지 않는 파일)
- **대체**: `core/scenario/generator.py` (동일 기능)
- **권장**: ✅ **삭제 가능**

### 4. `loot_generator.py` (구버전)
- **상태**: `routes.py`에서만 사용 (사용되지 않는 파일)
- **대체**: `core/scenario/reporter.py` (동일 기능)
- **권장**: ✅ **삭제 가능**

## 🟡 부분 중복 (검토 필요)

### 5. `nvd_client.py` (구버전)
- **상태**: 
  - `routes.py`에서 사용 (사용되지 않는 파일)
  - `main.py`에서 사용 (독립 실행용)
- **대체**: `core/cve/async_nvd_client.py` (비동기 버전)
- **권장**: 
  - `main.py`가 독립 실행용이면 `nvd_client.py` 유지
  - 또는 `main.py`를 `AsyncNvdClient`로 마이그레이션 후 삭제

## 📊 현재 사용 현황

```
__init__.py
  └─> api/routes.py (신버전) ✅ 사용 중
      ├─> core/recon/network.py
      ├─> core/recon/web.py
      ├─> core/recon/os.py
      ├─> core/recon/database.py
      ├─> core/recon/cloud.py
      ├─> core/recon/container.py
      ├─> core/scenario/generator.py
      ├─> core/scenario/reporter.py
      └─> core/cve/async_nvd_client.py

routes.py (구버전) ❌ 사용 안 함
  ├─> nmap_recon.py ❌
  ├─> nvd_client.py ⚠️ (main.py에서만 사용)
  ├─> ai_client.py ❌
  └─> loot_generator.py ❌

main.py (독립 실행용)
  └─> nvd_client.py ⚠️
```

## 🎯 정리 권장 사항

### 즉시 삭제 가능
1. ✅ `routes.py` - 완전히 사용되지 않음
2. ✅ `nmap_recon.py` - `core/recon/network.py`로 대체됨
3. ✅ `ai_client.py` - `core/scenario/generator.py`로 대체됨
4. ✅ `loot_generator.py` - `core/scenario/reporter.py`로 대체됨

### 검토 후 결정
5. ⚠️ `nvd_client.py` - `main.py`에서 사용 중
   - 옵션 A: `main.py`를 `AsyncNvdClient`로 마이그레이션 후 삭제
   - 옵션 B: `main.py`가 독립 실행용이면 유지

## 📝 정리 후 예상 구조

```
app/
├── __init__.py (api/routes.py 사용)
├── api/
│   └── routes.py (신버전) ✅
├── core/
│   ├── recon/ (network.py, web.py, os.py, ...)
│   ├── scenario/ (generator.py, reporter.py)
│   └── cve/ (async_nvd_client.py, matcher.py, ...)
├── main.py (독립 실행용, nvd_client.py 사용)
└── nvd_client.py (main.py 전용, 선택적 유지)
```

