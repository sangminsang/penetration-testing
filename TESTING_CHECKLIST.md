# 워크플로우 테스트 체크리스트

## 🎯 테스트 목표

수정된 `scenario_generator.py`를 포함한 전체 워크플로우가 정상적으로 동작하는지 검증합니다.

---

## ✅ 사전 준비 사항

### 1. Docker 컨테이너 상태 확인
```bash
# 모든 컨테이너가 실행 중인지 확인
docker ps

# 예상 컨테이너 목록:
# - security-scanner-web
# - security-scanner-zap
# - security-scanner-redis
# - security-scanner-mongodb
# - security-scanner-cve-db
# - security-scanner-cve-search
```

### 2. Ollama 서버 확인 (AI 보고서 생성용)
```bash
# Ollama 서버 연결 테스트
curl http://localhost:11434/api/tags

# llama3.1:8b 모델 확인
curl http://localhost:11434/api/show -d '{"name": "llama3.1:8b"}'
```

### 3. PoC 검증 설정 확인
`new/app/config.py` 파일에서:
```python
POC_VERIFICATION_ENABLED = os.environ.get('POC_VERIFICATION_ENABLED', 'true').lower() == 'true'
```

---

## 📋 테스트 시나리오

### 시나리오 1: 전체 워크플로우 테스트 (추천)

#### 1-1. 웹 대시보드에서 스캔 시작
1. 브라우저에서 `http://localhost:5000` 접속
2. 프로젝트 목록에서 기존 프로젝트 선택 또는 새 프로젝트 생성
3. "스캔 시작" 버튼 클릭
4. 실시간 로그 터미널에서 진행 상황 모니터링

#### 1-2. 로그 모니터링
```bash
# 웹 컨테이너 로그 실시간 확인
docker logs security-scanner-web -f
```

#### 1-3. 예상 로그 흐름
```
[ORCHESTRATOR DEBUG] 전체 스캔 시작: <target_url>
[RUN_DOCKER_SCANS DEBUG] Nmap 스캔 시작
[DOCKER DEBUG] ✅ 컨테이너 생성 성공!
[RUN_DOCKER_SCANS DEBUG] Nuclei 스캔 시작
[RUN_DOCKER_SCANS DEBUG] ZAP 스캔 시작
[PoC 검증] 🔄 25개 ZAP 취약점 PoC 검증 시작
[PoC 검증] ✅ 검증 완료: 성공=6, 실패=3, 수동검증필요=16
[CVE-SEARCH] ✅ 6개 고유 CVE 발견 완료
[CWE ENRICHMENT] ✅ 239개 취약점에 CWE 메타데이터 병합 완료

🆕 [공격 시나리오 생성 시작] ← 이 부분이 정상 실행되어야 함
🆕 [AI 보고서 생성 시작]
🆕 [전체 스캔 완료]
```

#### 1-4. 검증 포인트
- [ ] **오류 없이 스캔 완료**: `[ORCHESTRATOR DEBUG] ✅ 전체 스캔 완료` 로그 확인
- [ ] **공격 시나리오 생성 성공**: `SyntaxError` 없음
- [ ] **AI 보고서 생성 성공**: `ai_report.md` 파일 생성

---

### 시나리오 2: 스캔 결과 파일 확인

#### 2-1. 출력 디렉토리 확인
```bash
# 최신 스캔 결과 디렉토리 찾기
ls -lt new/scan_results/outputs/

# 예: new/scan_results/outputs/testphp_vulnweb_com_1768317708
```

#### 2-2. 필수 파일 존재 여부 확인
```bash
cd new/scan_results/outputs/<최신_디렉토리>

# 필수 파일 목록:
ls -lh
```

**예상 파일**:
- ✅ `nmap_*.json` - Nmap 스캔 결과
- ✅ `nuclei_*.json` - Nuclei 스캔 결과
- ✅ `zap_*.json` - ZAP 스캔 결과
- ✅ `final_integrated_report.json` - 통합 리포트
- ✅ `ai_report.md` - AI 보고서 (마크다운)

#### 2-3. 통합 리포트 검증
```bash
# final_integrated_report.json 파일 확인
cat final_integrated_report.json | python -m json.tool | head -50
```

**검증 항목**:
```json
{
  "metadata": {
    "target_url": "...",
    "generated_at": "..."
  },
  "vulnerabilities": [...],  // 취약점 목록
  "infrastructure": {...},   // 인프라 정보
  "selected_chains": [...],  // 🆕 공격 시나리오 (여기가 중요!)
  "summary": {...}
}
```

#### 2-4. AI 보고서 검증
```bash
# ai_report.md 파일 내용 확인
cat ai_report.md | head -100
```

**검증 항목**:
- ✅ `# 보안 분석 보고서` 헤더 존재
- ✅ `## 공격 체인 요약` 섹션 존재
- ✅ `## 발견된 취약점 분석` 섹션 존재
- ✅ `## 권장 조치사항` 섹션 존재

---

### 시나리오 3: 대시보드 UI 확인

#### 3-1. 프로젝트 대시보드 접속
1. 브라우저에서 `http://localhost:5000/dashboard/<project_id>` 접속
2. 스캔 이력 드롭다운에서 최신 스캔 결과 선택

#### 3-2. 탭별 확인
1. **취약점 목록 탭**:
   - [ ] 취약점 테이블 정상 표시
   - [ ] 이름/설명이 같은 컬럼에 표시 (수정된 UI)
   - [ ] 취약점 클릭 시 상세 모달 팝업
   - [ ] 모달의 배경색과 글자색이 대비되어 가독성 좋음 (수정된 UI)

2. **인프라 & 정찰 정보 탭**:
   - [ ] 인프라 서비스 카드 표시
   - [ ] 탐색된 엔드포인트 테이블 표시

3. **AI 정밀 리포트 탭**:
   - [ ] 🆕 AI 보고서 마크다운 렌더링 정상
   - [ ] 공격 체인 요약 섹션 존재
   - [ ] 취약점 분석 및 권장 조치사항 표시

4. **Raw Data 탭**:
   - [ ] JSON 데이터 통계 표시
   - [ ] 전체 JSON 데이터 표시

---

## 🔍 문제 발생 시 디버깅

### 1. `SyntaxError` 재발생 시
```bash
# scenario_generator.py 문법 재검증
cd new
python -m py_compile app/core/ai/scenario_generator.py

# 임포트 테스트
python -c "from app.core.ai.scenario_generator import ScenarioGenerator; print('OK')"
```

### 2. AI 보고서 생성 안 됨
```bash
# Ollama 서버 연결 확인
curl http://localhost:11434/api/tags

# Ollama 서버 재시작 (필요 시)
ollama serve
```

### 3. 공격 시나리오가 비어있음 (`selected_chains: []`)
- **원인**: AI가 JSON 형식을 올바르게 생성하지 못함
- **해결**: 로그에서 AI 응답 확인 후 `scenario_generator.py`의 `_parse_response()` 메서드 검토

### 4. PoC 검증이 실행되지 않음
```bash
# config.py 확인
grep POC_VERIFICATION_ENABLED new/app/config.py

# 환경 변수 설정 (필요 시)
export POC_VERIFICATION_ENABLED=true
```

---

## 📊 성공 기준

### 필수 조건 (Must Have)
- ✅ 모든 스캐너(Nmap, Nuclei, ZAP) 정상 실행
- ✅ `SyntaxError` 없이 전체 워크플로우 완료
- ✅ `final_integrated_report.json` 파일 생성
- ✅ `ai_report.md` 파일 생성
- ✅ 대시보드에서 스캔 결과 정상 표시

### 권장 조건 (Nice to Have)
- ✅ PoC 검증 6개 이상 성공
- ✅ `selected_chains`에 1개 이상의 공격 시나리오 포함
- ✅ AI 보고서에 공격 체인 요약 섹션 포함
- ✅ 대시보드 UI 가독성 향상 (이름/설명 레이아웃, 모달 색상)

---

## 🚀 빠른 테스트 명령

```bash
# 1. 작업 디렉토리 이동
cd C:\Users\Windows10\Desktop\allNEW\new

# 2. 문법 검증
python -m py_compile app/core/ai/scenario_generator.py
python -c "from app.core.ai.scenario_generator import ScenarioGenerator; print('✅ OK')"

# 3. Docker 컨테이너 로그 모니터링 (별도 터미널)
docker logs security-scanner-web -f

# 4. 웹 브라우저에서 스캔 시작
# http://localhost:5000 → 프로젝트 선택 → 스캔 시작

# 5. 결과 확인
# 대시보드에서 AI 정밀 리포트 탭 확인
```

---

## 📝 테스트 결과 기록

### 테스트 실행 정보
- **테스트 일시**: _____________
- **테스트 대상 URL**: _____________
- **Scan ID**: _____________

### 결과 체크리스트
- [ ] Nmap 스캔 성공
- [ ] Nuclei 스캔 성공
- [ ] ZAP 스캔 성공
- [ ] PoC 검증 실행
- [ ] CVE/CWE 조회 성공
- [ ] 공격 시나리오 생성 성공
- [ ] AI 보고서 생성 성공
- [ ] 대시보드 정상 표시

### 발견된 이슈
- 이슈 1: _____________
- 이슈 2: _____________

---

**작성일**: 2026-01-14  
**작성자**: AI Assistant  
**버전**: 1.0

