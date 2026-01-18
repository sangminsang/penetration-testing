# 개선 사항 테스트 가이드

> **작성일**: 2026-01-13  
> **목적**: 구현된 개선 사항을 실제 스캔으로 검증

---

## 📋 사전 준비

### 1. 프로젝트 재시작
```bash
cd C:\Users\Windows10\Desktop\allNEW\new

# Docker 컨테이너 재시작
docker-compose down
docker-compose up -d --build

# 로그 확인
docker logs security-scanner-web -f
```

### 2. 환경 확인
```bash
# Ollama 서버 확인
curl http://localhost:11434/api/version

# CVE-Search 서버 확인
curl http://localhost:5000/api/cve/CVE-2021-44228

# 포트 확인
netstat -ano | findstr :5000
netstat -ano | findstr :11434
```

---

## 🧪 테스트 시나리오

### 시나리오 1: 기본 스캔 (PoC 검증 활성화)

**목적**: PoC 검증 결과가 AI 보고서에 반영되는지 확인

**실행 명령**:
```bash
curl -X POST http://localhost:5000/api/scan/start \
  -H "Content-Type: application/json" \
  -d '{
    "project_id": 2,
    "target_url": "http://testphp.vulnweb.com",
    "enable_poc_verification": true
  }'
```

**예상 소요 시간**: ~25-30분

**확인 항목**:
1. **PoC 검증 로그**:
   ```bash
   docker logs security-scanner-web -f | grep "PoC 검증"
   ```
   - `[PoC 검증 X/Y] 🔄 검증 중`
   - `[PoC 검증 X/Y] ✅ 검증 성공`
   - `[PoC 검증] ✅ 검증 완료: 성공=X, 실패=Y`

2. **통합 리포트에 PoC 데이터 포함**:
   ```bash
   # 최신 스캔 결과 찾기
   cd new/scan_results/outputs
   ls -lt | head -3
   
   # 해당 디렉토리로 이동
   cd testphp_vulnweb_com_XXXXXXXXXX
   
   # PoC 데이터 확인 (Windows에서 jq 없으면 수동으로 파일 열기)
   cat final_integrated_report.json | jq '.vulnerabilities[] | select(.poc_code != null) | {name, poc_verified: (.poc_code != null), extracted_data: .execution_result.extracted_data}'
   ```

3. **AI 보고서 확인**:
   ```bash
   cat ai_report.md
   ```
   - ✅ 실제 PoC 코드 포함 (Python 코드)
   - ✅ 실제 실행 결과 포함 (`VULNERABILITY_FOUND:` 출력)
   - ✅ 탈취 데이터 표 형식으로 표시
   - ✅ `[서비스명]`, `[실제 URL]` 같은 플레이스홀더 없음

4. **공격 체인 확인**:
   - ✅ Phase 1-4로 구분됨
   - ✅ 각 Phase에 실제 취약점 나열
   - ✅ `connection` 필드에 이전 단계 연결 설명

5. **디버깅 파일 확인**:
   ```bash
   # 프롬프트 내용 확인
   cat debug_prompt.txt | head -100
   
   # 공격 시나리오 확인
   cat debug_ai_scenario.json
   ```

---

### 시나리오 2: PoC 검증 비활성화 비교

**목적**: PoC 검증이 없을 때와 차이 확인

**실행 명령**:
```bash
curl -X POST http://localhost:5000/api/scan/start \
  -H "Content-Type: application/json" \
  -d '{
    "project_id": 2,
    "target_url": "http://testphp.vulnweb.com",
    "enable_poc_verification": false
  }'
```

**예상 소요 시간**: ~20-25분 (PoC 검증 스킵)

**확인 항목**:
1. PoC 검증 로그 없음
2. `final_integrated_report.json`에 `poc_code` 필드 없음
3. AI 보고서에 템플릿 또는 일반적인 PoC 예시만 표시

**비교 결과**:
| 항목 | PoC 검증 ON | PoC 검증 OFF |
|------|-------------|--------------|
| 실제 PoC 코드 | ✅ | ❌ |
| 실행 결과 | ✅ | ❌ |
| 탈취 데이터 | ✅ | ❌ |
| 보고서 신뢰도 | 높음 | 낮음 |

---

### 시나리오 3: 다른 타겟 테스트

**목적**: 다양한 타겟에서 동작 확인

**추천 타겟**:
1. `http://testphp.vulnweb.com` (테스트 완료)
2. `http://demo.testfire.net` (Altoro Mutual 은행 데모)
3. `http://zero.webappsecurity.com` (Zero Bank)

**실행 명령**:
```bash
curl -X POST http://localhost:5000/api/scan/start \
  -H "Content-Type: application/json" \
  -d '{
    "project_id": 3,
    "target_url": "http://demo.testfire.net",
    "enable_poc_verification": true
  }'
```

---

## ✅ 검증 체크리스트

### Phase 1 검증
- [ ] **PoC 데이터 포함**: `final_integrated_report.json`에 `poc_code`, `execution_result`, `extracted_data` 포함
- [ ] **AI 보고서 반영**: `ai_report.md`에 실제 PoC 코드와 실행 결과 표시
- [ ] **탈취 데이터 시각화**: 표 형식으로 표시
- [ ] **플레이스홀더 제거**: `[...]` 형식 없음
- [ ] **공격 체인 생성**: Phase 1-4로 분류
- [ ] **Phase 연결**: `connection` 필드에 이전 단계 데이터 활용 명시

### Phase 2 검증
- [ ] **CVSS 상세**: `cvss_details` 필드에 한국어 설명 포함
- [ ] **AI 보고서**: CVSS 메트릭 상세 설명 (Attack Vector, Complexity 등)

### Phase 3 검증
- [ ] **타임스탬프**: 공격 실행 결과에 `timestamp` 포함
- [ ] **실행 시간**: `elapsed_seconds` 포함
- [ ] **상태 이모지**: `status` 필드에 ✅/❌ 표시

---

## 🐛 문제 해결

### 문제 1: PoC 검증이 실행되지 않음

**증상**:
```
[PoC 검증] ⏭️ PoC 검증 비활성화
```

**원인**: `enable_poc_verification: false` 또는 검증 대상 취약점 없음

**해결**:
1. 요청에 `enable_poc_verification: true` 포함 확인
2. ZAP 스캔 결과 확인 (Nuclei는 PoC 검증 제외)
3. ZAP High/Critical + Low/Medium Confidence 취약점 확인

---

### 문제 2: AI 보고서에 템플릿만 출력

**증상**:
```markdown
### [취약점 1: 구체적 이름]
```

**원인**: 프롬프트 데이터 부족 또는 AI 모델 문제

**해결**:
1. `debug_prompt.txt` 확인:
   ```bash
   cat debug_prompt.txt | grep "poc_verified"
   cat debug_prompt.txt | grep "extracted_data"
   ```
2. Ollama 모델 재시작:
   ```bash
   ollama stop llama3.1:8b
   ollama run llama3.1:8b
   ```
3. Temperature 설정 확인 (`ai_analyzer.py` line 366):
   ```python
   'temperature': 0.1  # 낮을수록 정확, 높을수록 창의적
   ```

---

### 문제 3: 공격 체인이 비어있음

**증상**:
```json
"공격 체인 (자동 생성)": []
```

**원인**: 취약점 분류 실패

**해결**:
1. 취약점 이름 확인:
   ```bash
   cat final_integrated_report.json | jq '.vulnerabilities[].name'
   ```
2. 키워드 추가 (`ai_analyzer.py` 헬퍼 메서드):
   ```python
   # _is_initial_access에 키워드 추가
   access_keywords = [..., 'your_keyword']
   ```

---

### 문제 4: CVSS 상세 정보 없음

**증상**:
```json
"cvss_details": null
```

**원인**: NVD 데이터 부족 또는 CVE ID 없음

**해결**:
1. CVE ID 확인:
   ```bash
   cat final_integrated_report.json | jq '.vulnerabilities[] | select(.cve != null and .cve != []) | {name, cve}'
   ```
2. CVE-Search 서버 확인:
   ```bash
   curl http://localhost:5000/api/cve/CVE-2021-44228
   ```
3. NVD 매핑 로그 확인:
   ```bash
   docker logs security-scanner-web | grep "CVE-SEARCH"
   ```

---

## 📊 테스트 결과 보고서 템플릿

```markdown
## 테스트 결과

**테스트 일시**: YYYY-MM-DD HH:MM:SS  
**타겟 URL**: http://testphp.vulnweb.com  
**PoC 검증**: ✅ 활성화

### Phase 1 검증 결과
- PoC 데이터 포함: ✅ / ❌
- AI 보고서 반영: ✅ / ❌
- 탈취 데이터 표시: ✅ / ❌
- 플레이스홀더 제거: ✅ / ❌
- 공격 체인 생성: ✅ / ❌

### Phase 2 검증 결과
- CVSS 상세 정보: ✅ / ❌
- AI 보고서 CVSS 설명: ✅ / ❌

### Phase 3 검증 결과
- 타임스탬프: ✅ / ❌
- 실행 시간: ✅ / ❌
- 상태 이모지: ✅ / ❌

### 발견된 문제
1. [문제 설명]
2. [문제 설명]

### 개선 효과 (주관적 평가)
- 보고서 신뢰도: X% → Y%
- 증거력: X% → Y%
- 현실성: X% → Y%

### 스크린샷
- [ai_report.md 일부 캡처]
- [final_integrated_report.json 일부 캡처]
```

---

## 📞 지원 요청

**테스트 중 문제 발생 시**:
1. 로그 수집:
   ```bash
   docker logs security-scanner-web > scan_logs.txt
   ```
2. 스캔 결과 압축:
   ```bash
   # Windows PowerShell
   Compress-Archive -Path new\scan_results\outputs\testphp_vulnweb_com_* -DestinationPath scan_results.zip
   ```
3. 문제 설명과 함께 전송

**문서 버전**: 1.0  
**최종 수정**: 2026-01-13

