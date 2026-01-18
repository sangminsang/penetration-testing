# CWE 메타데이터 보강 옵션 분석

## 📋 현재 상황

### 현재 구현 상태
- ✅ `_enrich_cwe_metadata` 함수가 이미 존재
- ✅ `infrastructure_vulnerabilities`의 CWE도 추출하고 있음
- ⚠️ 하지만 메타데이터는 **플레이스홀더**만 저장됨
- ⚠️ 메타데이터 병합이 `vulnerabilities`에만 되어있고, `infrastructure_vulnerabilities`에는 병합 안 됨

### 현재 코드 위치
- `new/app/core/scanners/scan_orchestrator.py`의 `_enrich_cwe_metadata` 함수 (2522번째 줄)

---

## 🎯 CWE 메타데이터를 얻는 방법

### 방법 1: MITRE CWE 공식 데이터 다운로드 (권장) ⭐

#### 장점
- ✅ **무료**이고 공식 데이터
- ✅ **API 호출 제한 없음** (로컬 데이터 사용)
- ✅ **빠른 응답 속도** (네트워크 지연 없음)
- ✅ **오프라인 사용 가능**

#### 단점
- ⚠️ 주기적으로 데이터 업데이트 필요
- ⚠️ 초기 설정 필요 (데이터 다운로드 및 파싱)

#### 구현 방법

**1) MITRE CWE 데이터 다운로드**
```bash
# MITRE CWE 공식 사이트에서 XML/JSON 다운로드
# URL: https://cwe.mitre.org/data/downloads.html
# 또는 직접 다운로드:
wget https://cwe.mitre.org/data/xml/cwec_latest.xml.zip
```

**2) Python으로 파싱하여 JSON 변환**
```python
import xml.etree.ElementTree as ET
import json
from pathlib import Path

def parse_cwe_xml(xml_path: str) -> dict:
    """MITRE CWE XML을 파싱하여 JSON으로 변환"""
    tree = ET.parse(xml_path)
    root = tree.getroot()
    
    cwe_map = {}
    for weakness in root.findall('.//Weakness'):
        cwe_id = weakness.get('ID')
        name = weakness.find('Name')
        description = weakness.find('Description')
        
        if cwe_id and name is not None:
            cwe_map[f"CWE-{cwe_id}"] = {
                'cwe_id': f"CWE-{cwe_id}",
                'name': name.text if name is not None else '',
                'description': description.text if description is not None else '',
                'source': 'mitre_cwe'
            }
    
    return cwe_map

# 사용 예시
cwe_data = parse_cwe_xml('cwec_latest.xml')
with open('cwe_metadata.json', 'w', encoding='utf-8') as f:
    json.dump(cwe_data, f, ensure_ascii=False, indent=2)
```

**3) 백엔드에서 JSON 파일 로드**
```python
# scan_orchestrator.py에 추가
import json
from pathlib import Path

class ScanOrchestrator:
    def __init__(self):
        # CWE 메타데이터 로드
        self.cwe_metadata_cache = self._load_cwe_metadata()
    
    def _load_cwe_metadata(self) -> dict:
        """CWE 메타데이터 JSON 파일 로드"""
        cwe_file = Path(Config.CWE_METADATA_PATH)  # 예: 'data/cwe_metadata.json'
        if cwe_file.exists():
            try:
                with open(cwe_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"CWE 메타데이터 로드 실패: {e}")
        return {}
    
    def _enrich_cwe_metadata(self, aggregated_data):
        # ... 기존 코드 ...
        
        for cwe_id in sorted(all_cwe_ids):
            # 캐시에서 먼저 확인
            if cwe_id in self.cwe_metadata_cache:
                cwe_metadata_map[cwe_id] = self.cwe_metadata_cache[cwe_id]
                logger.debug(f"✅ CWE {cwe_id} 메타데이터 로드 (캐시)")
            else:
                # 캐시에 없으면 플레이스홀더 사용
                cwe_metadata_map[cwe_id] = {
                    'cwe_id': cwe_id,
                    'name': f"CWE-{cwe_id.replace('CWE-', '')}",
                    'description': 'CWE 메타데이터를 찾을 수 없습니다.',
                    'source': 'placeholder'
                }
```

---

### 방법 2: CWE-Search API 사용

#### 장점
- ✅ 실시간 최신 데이터
- ✅ 별도 데이터 관리 불필요

#### 단점
- ⚠️ API 호출 제한 가능성
- ⚠️ 네트워크 지연
- ⚠️ 외부 서비스 의존성

#### 구현 방법
```python
# CWE-Search API 엔드포인트 (예시)
# https://cwe-search.com/api/cwe/{cwe_id}

def fetch_cwe_from_search(cwe_id: str) -> dict:
    """CWE-Search API에서 CWE 메타데이터 가져오기"""
    try:
        cwe_number = cwe_id.replace('CWE-', '')
        url = f"https://cwe-search.com/api/cwe/{cwe_number}"
        
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return {
                'cwe_id': cwe_id,
                'name': data.get('name', ''),
                'description': data.get('description', ''),
                'source': 'cwe_search'
            }
    except Exception as e:
        logger.warning(f"CWE-Search API 호출 실패: {e}")
    return None
```

---

### 방법 3: 정적 JSON 파일 (CWE Top 25 등)

#### 장점
- ✅ **가장 간단함**
- ✅ **빠른 구현**
- ✅ **API 호출 불필요**

#### 단점
- ⚠️ 제한된 CWE만 포함 (Top 25 등)
- ⚠️ 전체 CWE 커버리지 낮음

#### 구현 방법
```python
# data/cwe_top25.json 파일 생성
{
  "CWE-79": {
    "cwe_id": "CWE-79",
    "name": "Cross-site Scripting (XSS)",
    "description": "웹 애플리케이션이 사용자 입력을 적절히 검증하지 않아 공격자가 스크립트를 삽입할 수 있는 취약점"
  },
  "CWE-89": {
    "cwe_id": "CWE-89",
    "name": "SQL Injection",
    "description": "SQL 쿼리에 사용자 입력이 직접 포함되어 공격자가 쿼리를 조작할 수 있는 취약점"
  },
  // ... CWE Top 25
}

# 백엔드에서 로드
def _load_cwe_top25(self) -> dict:
    """CWE Top 25 메타데이터 로드"""
    cwe_file = Path('data/cwe_top25.json')
    if cwe_file.exists():
        with open(cwe_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}
```

---

### 방법 4: 프론트엔드에서 필요할 때만 API 호출

#### 장점
- ✅ 백엔드 부하 감소
- ✅ 사용자가 실제로 보는 CWE만 조회

#### 단점
- ⚠️ 프론트엔드에서 CORS 문제 가능성
- ⚠️ 사용자 경험 저하 (로딩 시간)

#### 구현 방법
```javascript
// 프론트엔드에서 CWE 메타데이터 가져오기
async function fetchCweMetadata(cweId) {
    try {
        // MITRE CWE 공식 사이트에서 직접 가져오기 (CORS 문제 가능)
        // 또는 백엔드 프록시 API 사용
        const response = await fetch(`/api/cwe/${cweId}`);
        if (response.ok) {
            return await response.json();
        }
    } catch (error) {
        console.warn(`CWE ${cweId} 메타데이터 조회 실패:`, error);
    }
    return null;
}
```

---

## 🎯 권장 구현 방안

### 단계별 구현 (점진적 개선)

#### 1단계: 정적 JSON 파일 (즉시 구현 가능) ⭐
- CWE Top 25 또는 주요 CWE 50개를 JSON 파일로 저장
- 가장 자주 나타나는 CWE만 커버
- **구현 시간**: 1-2시간

#### 2단계: MITRE CWE 데이터 다운로드 (중기)
- MITRE 공식 XML/JSON 다운로드
- 주기적으로 업데이트 (월 1회)
- **구현 시간**: 반나절

#### 3단계: infrastructure_vulnerabilities에도 메타데이터 병합 (필수)
- 현재는 `vulnerabilities`에만 병합됨
- `infrastructure_vulnerabilities`에도 병합 필요
- **구현 시간**: 1시간

---

## 💡 실제 구현 예시 (1단계: 정적 JSON)

### 1. CWE Top 25 JSON 파일 생성

```json
// data/cwe_metadata.json
{
  "CWE-79": {
    "cwe_id": "CWE-79",
    "name": "Cross-site Scripting (XSS)",
    "description": "웹 애플리케이션이 사용자 입력을 적절히 검증하지 않아 공격자가 스크립트를 삽입할 수 있는 취약점입니다."
  },
  "CWE-89": {
    "cwe_id": "CWE-89",
    "name": "SQL Injection",
    "description": "SQL 쿼리에 사용자 입력이 직접 포함되어 공격자가 쿼리를 조작할 수 있는 취약점입니다."
  },
  "CWE-20": {
    "cwe_id": "CWE-20",
    "name": "Improper Input Validation",
    "description": "입력 데이터를 적절히 검증하지 않아 보안 문제가 발생할 수 있는 취약점입니다."
  }
  // ... CWE Top 25 또는 주요 CWE 50개
}
```

### 2. scan_orchestrator.py 수정

```python
class ScanOrchestrator:
    def __init__(self):
        # CWE 메타데이터 캐시 로드
        self.cwe_metadata_cache = self._load_cwe_metadata()
    
    def _load_cwe_metadata(self) -> dict:
        """CWE 메타데이터 JSON 파일 로드"""
        try:
            cwe_file = Path(Config.CWE_METADATA_PATH)  # 'data/cwe_metadata.json'
            if cwe_file.exists():
                with open(cwe_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    logger.info(f"✅ CWE 메타데이터 로드 완료: {len(data)}개")
                    return data
            else:
                logger.warning(f"⚠️ CWE 메타데이터 파일 없음: {cwe_file}")
        except Exception as e:
            logger.error(f"❌ CWE 메타데이터 로드 실패: {e}")
        return {}
    
    def _enrich_cwe_metadata(self, aggregated_data: Dict[str, Any]) -> Dict[str, Any]:
        # ... 기존 CWE 추출 로직 ...
        
        for cwe_id in sorted(all_cwe_ids):
            # 캐시에서 먼저 확인
            if cwe_id in self.cwe_metadata_cache:
                cwe_metadata_map[cwe_id] = self.cwe_metadata_cache[cwe_id]
                logger.debug(f"✅ CWE {cwe_id} 메타데이터 로드 (캐시)")
            else:
                # 캐시에 없으면 플레이스홀더
                cwe_metadata_map[cwe_id] = {
                    'cwe_id': cwe_id,
                    'name': f"CWE-{cwe_id.replace('CWE-', '')}",
                    'description': 'CWE 메타데이터를 찾을 수 없습니다.',
                    'source': 'placeholder'
                }
        
        # vulnerabilities에 메타데이터 병합 (기존 로직)
        # ... 기존 코드 ...
        
        # ⭐ infrastructure_vulnerabilities에도 메타데이터 병합 추가
        infra_enriched_count = 0
        for infra_vuln in infrastructure_vulnerabilities:
            nvd_data = infra_vuln.get('nvd_data', {})
            cwe = nvd_data.get('cwe', '')
            if cwe:
                cwe_str = str(cwe).strip()
                if cwe_str.startswith('CWE-'):
                    cwe_normalized = cwe_str.upper()
                elif cwe_str.startswith('CWE'):
                    cwe_normalized = f"CWE-{cwe_str[3:]}"
                elif cwe_str.isdigit():
                    cwe_normalized = f"CWE-{cwe_str}"
                else:
                    continue
                
                if cwe_normalized in cwe_metadata_map:
                    if 'nvd_data' not in infra_vuln:
                        infra_vuln['nvd_data'] = {}
                    infra_vuln['nvd_data']['cwe_metadata'] = cwe_metadata_map[cwe_normalized]
                    infra_enriched_count += 1
        
        logger.info(f"✅ {enriched_count}개 취약점 + {infra_enriched_count}개 인프라 취약점에 CWE 메타데이터 병합 완료")
        
        enriched_data['vulnerabilities'] = vulnerabilities
        enriched_data['infrastructure_vulnerabilities'] = infrastructure_vulnerabilities
        return enriched_data
```

### 3. Config에 경로 추가

```python
# app/config.py
class Config:
    # ... 기존 설정 ...
    CWE_METADATA_PATH = os.path.join(BASE_DIR, 'data', 'cwe_metadata.json')
```

---

## 📊 방법별 비교

| 방법 | 구현 난이도 | 비용 | 성능 | 커버리지 | 권장도 |
|------|------------|------|------|----------|--------|
| **정적 JSON (Top 25)** | ⭐ 쉬움 | 무료 | ⭐⭐⭐ 빠름 | ⭐⭐ 낮음 | ⭐⭐⭐ 즉시 구현 |
| **MITRE 데이터 다운로드** | ⭐⭐ 보통 | 무료 | ⭐⭐⭐ 빠름 | ⭐⭐⭐ 높음 | ⭐⭐⭐ 중기 구현 |
| **CWE-Search API** | ⭐⭐ 보통 | 무료 | ⭐⭐ 보통 | ⭐⭐⭐ 높음 | ⭐⭐ 선택적 |
| **프론트엔드 API 호출** | ⭐⭐⭐ 어려움 | 무료 | ⭐ 느림 | ⭐⭐⭐ 높음 | ⭐ 비권장 |

---

## 🎯 결론 및 권장 사항

### 즉시 구현 (1단계)
**정적 JSON 파일 방식**을 권장합니다:
- ✅ 가장 빠르게 구현 가능
- ✅ CWE Top 25만으로도 대부분의 경우 커버
- ✅ API 호출 불필요
- ✅ `infrastructure_vulnerabilities`에도 메타데이터 병합 추가

### 중기 개선 (2단계)
**MITRE CWE 공식 데이터 다운로드**:
- 월 1회 업데이트 스크립트 작성
- 전체 CWE 커버리지 확보

### 답변: MITRE API 직접 호출이 필요한가?
**❌ 아니요! 직접 호출할 필요 없습니다.**

1. **MITRE는 공식 REST API를 제공하지 않습니다**
   - XML/JSON 데이터 파일을 다운로드하는 방식

2. **권장 방법**:
   - MITRE 공식 사이트에서 XML/JSON 다운로드
   - 로컬에 저장하여 사용
   - 주기적으로 업데이트

3. **대안**:
   - CWE-Search 같은 서드파티 API 사용 가능
   - 하지만 로컬 데이터가 더 안정적

---

**작성일**: 2026-01-14  
**작성자**: AI Assistant  
**버전**: 1.0
