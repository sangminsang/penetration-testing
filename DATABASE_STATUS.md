# 데이터베이스 연동 현황

## 현재 상황

### ❌ 로컬 데이터베이스 없음

**현재는 데이터베이스를 사용하지 않습니다!**

- ✅ **NVD API를 직접 호출**하는 방식으로 작동
- ❌ 로컬 CVE 데이터베이스 없음
- ❌ SQLite/PostgreSQL 데이터베이스 없음
- ❌ Redis 캐싱 없음

### 현재 작동 방식

```
스캔 요청
  ↓
app/core/cve/matcher.py의 NvdClient
  ↓
NVD API v2.0 직접 호출 (실시간)
  ↓
CVE 결과 반환
```

**장점:**
- 최신 CVE 데이터 즉시 반영
- 데이터베이스 관리 불필요
- 설정 간단

**단점:**
- API 호출 제한 (초당 5회)
- 네트워크 의존성
- 느린 응답 속도 (30만 CVE 검색 시)

## config.py의 CVE_SEARCH_BASE_URL

`app/config.py`에 다음 설정이 있습니다:

```python
CVE_SEARCH_BASE_URL = "https://localhost"
```

**하지만 현재는 사용되지 않습니다!**

- 이 설정은 cve-search API를 사용하려고 했던 흔적으로 보임
- 실제로는 `NvdClient`가 NVD API를 직접 호출
- cve-search는 Docker로 실행하는 로컬 CVE 검색 API

## 향후 계획 (PROJECT_PROPOSAL.md 참고)

### Phase 1: CVE 데이터베이스 구축 (3주)

**목표**: 로컬 CVE 데이터베이스 구축

**작업 내용**:
1. NVD API v2.0에서 전체 CVE 데이터 수집 (약 30만 개)
2. SQLite/PostgreSQL 데이터베이스에 저장
3. 카테고리별 분류 및 인덱싱
4. `app/core/cve/database.py` 모듈 구현

**예상 구조**:
```python
# app/core/cve/database.py (향후 구현)
class CVEDatabase:
    def __init__(self, db_path="cve.db"):
        # SQLite/PostgreSQL 연결
        
    def sync_from_nvd(self):
        # NVD API에서 전체 CVE 수집 및 저장
        
    def search_by_cpe(self, cpe_string):
        # 로컬 DB에서 CPE로 검색
        
    def search_by_keyword(self, keyword):
        # 로컬 DB에서 키워드로 검색
```

## 현재 실행 방법

### ✅ 별도 데이터베이스 설정 불필요!

**현재는 그냥 실행하면 됩니다:**

```bash
python run.py
```

**필요한 것:**
- ✅ Python 환경
- ✅ NVD API 키 (이미 `config.py`에 설정됨)
- ✅ 인터넷 연결 (NVD API 호출용)

**불필요한 것:**
- ❌ 데이터베이스 서버 설치
- ❌ 데이터베이스 초기화
- ❌ 데이터베이스 마이그레이션
- ❌ Docker (cve-search 등)

## 향후 데이터베이스 구축 시

### 옵션 1: SQLite (간단)

```bash
# 데이터베이스 초기화 (향후 구현)
python -m app.core.cve.database init

# NVD에서 데이터 동기화 (향후 구현)
python -m app.core.cve.database sync
```

### 옵션 2: PostgreSQL (확장성)

```python
# app/config.py에 추가 (향후)
DATABASE_URL = "postgresql://user:pass@localhost/cve_db"
```

### 옵션 3: cve-search API (Docker)

```bash
# cve-search Docker 실행 (선택사항)
docker run -d -p 5000:5000 cve-search/api-server

# config.py 수정
CVE_SEARCH_BASE_URL = "http://localhost:5000"
```

## 결론

### 현재 상태
- ✅ **데이터베이스 없이 작동**
- ✅ **NVD API 직접 호출**
- ✅ **별도 설정 불필요**

### 실행 방법
```bash
python run.py
```

**그냥 실행하면 됩니다!** 🚀

### 향후 계획
- Phase 1에서 로컬 CVE 데이터베이스 구축 예정
- 그때 `app/core/cve/database.py` 모듈 추가
- 데이터베이스 초기화 및 동기화 스크립트 제공

