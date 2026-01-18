# ZAP 취약점 유형 기반 CVE 매칭 제안

## 현재 상황 분석

### 1. Nuclei (15,581개 결과)
- **CVE:** 0개 ❌
- **심각도:** 모두 info
- **주요 탐지:** 토큰/키/비밀번호 노출, WAF 탐지
- **결론:** CVE가 없는 일반적인 정보 수집

### 2. ZAP (1,748개 알림)
- **CVE:** 0개 (기본) ❌
- **주요 탐지:**
  - **SQL Injection:** 3개 (High)
  - **XSS (DOM Based):** 278개 (High)
  - 보안 헤더 누락, CSP 미설정 등
- **결론:** 실제 취약점 발견했으나 CVE 매칭 안 됨

---

## 제안: ZAP 취약점 유형 → CVE 매칭

### 방법 1: 취약점 유형 → CWE → 관련 CVE 검색

#### 구현 방식
```python
# 1단계: ZAP 취약점 유형 → CWE 매핑 (이미 구현됨)
{
    "SQL Injection": "CWE-89",
    "Cross Site Scripting": "CWE-79",
    "Path Traversal": "CWE-22",
    ...
}

# 2단계: CWE → 관련 CVE 검색 (NVD API)
# 예: CWE-89 (SQL Injection)
GET https://services.nvd.nist.gov/rest/json/cves/2.0?cweId=CWE-89

# 3단계: 기술 스택 필터링
# Nmap에서 발견한 기술 스택과 매칭
# 예: Python 3.12.3 + CWE-89 → Python SQL Injection CVE만 필터링
```

#### 장점
- ✅ ZAP 취약점에 관련 CVE 추가 가능
- ✅ 실제 사용 중인 기술 스택과 연관

#### 단점
- ⚠️ CWE당 수천 개 CVE 반환 (너무 광범위)
- ⚠️ 실제 해당 시스템과 무관할 수 있음
- ⚠️ NVD API 호출 시간 증가

---

### 방법 2: 취약점 유형 + 기술 스택 → 정밀 CVE 검색

#### 구현 방식
```python
# 1단계: ZAP 취약점 + Nmap 기술 스택 조합
취약점: "SQL Injection" (CWE-89)
기술: "Python 3.12.3", "Flask"

# 2단계: NVD API 정밀 검색
# keywordSearch + cweId 조합
GET https://services.nvd.nist.gov/rest/json/cves/2.0?
    keywordSearch=Python+SQL
    &cweId=CWE-89
    &resultsPerPage=50

# 3단계: 버전 매칭
# CPE 정보로 버전 범위 확인
# 예: Python 3.12.3이 영향받는 버전인지 체크
```

#### 장점
- ✅ 더 정확한 CVE 매칭
- ✅ 기술 스택 기반 필터링으로 관련성 높음

#### 단점
- ⚠️ NVD API 호출 횟수 증가 (Rate Limit 주의)
- ⚠️ 구현 복잡도 증가

---

### 방법 3: 룰 기반 CVE 매핑 (간단한 방식)

#### 구현 방식
```python
# 미리 정의된 매핑 테이블
VULN_TYPE_TO_CVE_EXAMPLES = {
    "SQL Injection": [
        "CVE-2023-xxxxx",  # Django SQL Injection
        "CVE-2022-xxxxx",  # Flask-SQLAlchemy
    ],
    "Cross Site Scripting": [
        "CVE-2023-xxxxx",  # React XSS
        "CVE-2022-xxxxx",  # Vue.js XSS
    ],
}

# 기술 스택 매칭
if "Flask" in tech_stack and "SQL Injection" in vuln_type:
    return get_flask_sql_injection_cves()
```

#### 장점
- ✅ 빠른 구현
- ✅ API 호출 최소화

#### 단점
- ⚠️ 수동 관리 필요
- ⚠️ 최신 CVE 반영 어려움

---

## 권장 방안

### 단기 (즉시 구현 가능)
1. **CPE 기반 CVE 매칭 강화** (이미 56개 발견 ✅)
   - Nmap에서 발견한 서비스 버전 → CVE 검색
   - 이미 구현됨, 잘 작동 중

2. **CWE 메타데이터 활용** (이미 구현 ✅)
   - ZAP 취약점에 CWE 정보 추가
   - AI 분석 시 CWE 기반 설명 제공

### 중기 (추가 구현)
3. **하이브리드 방식**
   ```python
   if vuln.severity in ['high', 'critical']:  # High/Critical만
       if vuln.cwe and tech_stack:  # CWE + 기술 스택 있을 때만
           # NVD API 정밀 검색
           related_cves = search_nvd_by_cwe_and_tech(
               cwe=vuln.cwe,
               tech_stack=tech_stack,
               max_results=10  # 최대 10개로 제한
           )
   ```

### 장기 (선택적)
4. **ML 기반 CVE 추천**
   - 취약점 설명 + 기술 스택 → 벡터 임베딩
   - CVE 설명과 유사도 계산
   - 가장 관련성 높은 CVE 추천

---

## 구현 우선순위

### 즉시 적용 (Priority 1) ✅
- **현재 상태 유지**
- CPE 기반 CVE: 56개 (충분함)
- CWE 메타데이터: 잘 작동 중

### 선택적 구현 (Priority 2) ⚠️
- **High/Critical ZAP 취약점에만 CVE 매칭**
- 현재: SQL Injection 3개, XSS 278개
- 이 중 기술 스택과 관련된 CVE만 검색

### 고려 사항
1. **API Rate Limit**
   - NVD API: 50 requests/30s (API 키 있을 때)
   - ZAP 취약점마다 검색 시 제한 초과 가능

2. **정확도 vs 완성도**
   - 많은 CVE보다 **정확한 CVE**가 중요
   - 잘못된 CVE는 혼란만 가중

3. **사용자 기대치**
   - ZAP의 SQL Injection → SQL Injection 관련 CVE 기대
   - 하지만 해당 시스템과 무관할 수 있음

---

## 결론

### 현재 상황
- ✅ **CPE 기반 CVE 매칭:** 정상 작동 (56개)
- ✅ **CWE 메타데이터:** 정상 작동
- ⚠️ **ZAP/Nuclei CVE:** 0개 (정상, 원본 데이터에 없음)

### 권장 사항
1. **현재 상태 유지** - 이미 잘 작동 중
2. 필요 시 **High/Critical 취약점에만** 추가 CVE 매칭 구현
3. **정확도 우선** - 불필요한 CVE는 추가하지 않음

**최종 결론:** ZAP CVE 0건은 **정상**이며, 추가 구현은 **선택적**입니다.

