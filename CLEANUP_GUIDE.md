# 프로젝트 정리 가이드

## 📋 개요
개발 과정에서 생성된 불필요한 파일들을 정리하여 프로젝트 구조를 깔끔하게 유지합니다.

**작성일**: 2026-01-14

---

## 🗑️ 안전하게 삭제 가능한 파일 목록

### 1. 개발 과정 문서 (19개)

이미 작업이 완료되어 참고만 필요하거나, 프로젝트 구동에 불필요한 문서들입니다.

#### 대시보드 관련 분석/구현 문서 (7개)
```
✅ 삭제 가능:
- DASHBOARD_STRUCTURE.md                    # 초기 대시보드 구조 분석
- DASHBOARD_ISSUES_ANALYSIS.md              # 대시보드 문제점 분석
- DASHBOARD_ADDITIONAL_ISSUES.md            # 추가 문제점 분석
- DASHBOARD_IMPROVEMENTS_IMPLEMENTATION.md  # 개선 구현 문서
- FINAL_IMPLEMENTATION_VERIFICATION.md      # 최종 구현 검증
```

**보관 권장** (참고용):
```
⚠️ 보관 권장:
- CWE_METADATA_ENRICHMENT_OPTIONS.md        # CWE 메타데이터 옵션 (향후 참고)
- CWE_METADATA_IMPLEMENTATION.md            # CWE 구현 문서 (향후 참고)
```

**이유**: 
- 삭제 가능 파일: 이미 대시보드 구현 완료, 코드에 반영됨
- 보관 권장 파일: CWE 메타데이터 업데이트 시 참고 가능

#### 버그 수정 및 개선 문서 (6개)
```
✅ 삭제 가능:
- ATTACK_SCENARIO_PARSING_FIX.md            # 공격 시나리오 파싱 수정
- BUGFIX_SUMMARY.md                         # 버그 수정 요약
- WORKFLOW_FIX_SUMMARY.md                   # 워크플로우 수정 요약
- AI_REPORT_IMPROVEMENT_ANALYSIS.md         # AI 리포트 개선 분석
- DATA_FLOW_IMPROVEMENT.md                  # 데이터 흐름 개선
- IMPROVEMENT_PLAN.md                       # 개선 계획
```

**이유**: 이미 모든 버그와 개선사항이 코드에 반영됨

#### 요약 및 검증 문서 (3개)
```
✅ 삭제 가능:
- IMPLEMENTATION_SUMMARY.md                 # 구현 요약
- IMPROVEMENT_SUMMARY.md                    # 개선 요약
- FINAL_SUMMARY.md                          # 최종 요약
```

**이유**: 작업 완료 후 요약 문서, 참고용으로만 유지 필요

#### 워크플로우 검증 문서 (1개)
```
✅ 삭제 가능:
- WORKFLOW_VERIFICATION.md                  # 워크플로우 검증
```

**이유**: 워크플로우 정상 작동 확인 완료

#### 테스트 가이드 (2개)
```
⚠️ 보관 권장:
- TESTING_CHECKLIST.md                      # 테스트 체크리스트
- TESTING_GUIDE.md                          # 테스트 가이드
```

**이유**: 향후 테스트 시 참고 가능

---

### 2. 테스트/프리뷰 HTML 파일 (2개)

```
✅ 삭제 가능:
- dashboard_preview.html                    # 대시보드 프리뷰 (실제는 app/templates/dashboard.html)
- dashboard_test.html                       # 대시보드 테스트
```

**이유**: 
- 실제 대시보드는 `app/templates/dashboard.html`에 있음
- 테스트/개발용으로만 사용됨
- 프로젝트 구동에 불필요

---

### 3. 임시 Python 스크립트 (3개)

```
✅ 삭제 가능:
- complete_attack_and_update.py             # 공격 완료 및 업데이트 (일회성)
- generate_ai_report.py                     # AI 리포트 생성 (일회성)
- update_report_with_actual_attacks.py      # 리포트 업데이트 (일회성)
```

**이유**: 
- 일회성 테스트/업데이트 스크립트
- 기능이 `scan_orchestrator.py`에 통합됨
- 프로젝트 구동에 불필요

---

### 4. 백업 파일 (1개)

```
✅ 삭제 가능:
- Aegis_AI_Backup_260110.tar.gz             # 구 버전 백업 (1월 10일)
```

**이유**: 
- 이미 최신 코드가 프로젝트에 있음
- 150MB 이상의 용량 차지
- 필요시 Git 이력으로 복구 가능

---

### 5. 빈 폴더 (1개)

```
✅ 삭제 가능:
- scan_test/                                # 빈 테스트 폴더
```

**이유**: 내용이 없는 빈 폴더

---

## ✅ 보관 필수 파일 목록

### 1. 프로젝트 필수 문서 (4개)

```
🔒 삭제 불가:
- README.md                                 # 프로젝트 설명
- INSTALLATION.md                           # 설치 가이드
- BUILD_DOCKER.md                           # Docker 빌드 가이드
- PROJECT_STRUCTURE.md                      # 프로젝트 구조 (선택적)
```

**이유**: 프로젝트 이해 및 설치에 필수

---

### 2. 애플리케이션 코드 (모두 필수)

```
🔒 삭제 불가:
- app/                                      # 메인 애플리케이션
- docker/                                   # Docker 설정
- scripts/                                  # 유틸리티 스크립트
- data/                                     # 데이터 파일
- vulnerable_webapp/                        # 테스트용 취약한 웹앱
- run.py                                    # 메인 실행 파일
- requirements.txt                          # Python 패키지
- docker-compose.yml                        # Docker Compose 설정
```

---

### 3. 스캔 결과 (선택적)

```
⚠️ 선택적 삭제:
- scan_results/outputs/                     # 과거 스캔 결과 (11개 폴더, 188개 파일)
```

**권장사항**:
- 최근 1-2개 스캔 결과만 보관
- 나머지는 백업 후 삭제 (용량 확보)
- 또는 전체 보관 (테스트 데이터로 활용)

---

## 📊 삭제 가능한 파일 요약

### 안전하게 삭제 가능 (총 27개)

| 카테고리 | 개수 | 용량 예상 |
|---------|------|----------|
| 개발 과정 문서 (.md) | 13개 | ~500KB |
| 테스트/프리뷰 HTML | 2개 | ~100KB |
| 임시 Python 스크립트 | 3개 | ~50KB |
| 백업 파일 (.tar.gz) | 1개 | ~150MB |
| 빈 폴더 | 1개 | 0KB |
| **합계** | **20개** | **~150MB** |

### 선택적 삭제 가능

| 카테고리 | 개수 | 용량 예상 |
|---------|------|----------|
| 과거 스캔 결과 | 11개 폴더 | ~50MB |

### 보관 권장 (참고용)

| 카테고리 | 개수 | 용량 예상 |
|---------|------|----------|
| CWE 메타데이터 문서 | 2개 | ~50KB |
| 테스트 가이드 | 2개 | ~20KB |

---

## 🚀 삭제 명령어 (PowerShell)

### 1. 개발 과정 문서 삭제 (13개)

```powershell
cd "C:\Users\YONSAI\Desktop\SentinAI_Backup_20260114_1205\new"

# 대시보드 관련 (5개)
Remove-Item "DASHBOARD_STRUCTURE.md"
Remove-Item "DASHBOARD_ISSUES_ANALYSIS.md"
Remove-Item "DASHBOARD_ADDITIONAL_ISSUES.md"
Remove-Item "DASHBOARD_IMPROVEMENTS_IMPLEMENTATION.md"
Remove-Item "FINAL_IMPLEMENTATION_VERIFICATION.md"

# 버그 수정 및 개선 (6개)
Remove-Item "ATTACK_SCENARIO_PARSING_FIX.md"
Remove-Item "BUGFIX_SUMMARY.md"
Remove-Item "WORKFLOW_FIX_SUMMARY.md"
Remove-Item "AI_REPORT_IMPROVEMENT_ANALYSIS.md"
Remove-Item "DATA_FLOW_IMPROVEMENT.md"
Remove-Item "IMPROVEMENT_PLAN.md"

# 요약 (3개)
Remove-Item "IMPLEMENTATION_SUMMARY.md"
Remove-Item "IMPROVEMENT_SUMMARY.md"
Remove-Item "FINAL_SUMMARY.md"

# 워크플로우 검증 (1개)
Remove-Item "WORKFLOW_VERIFICATION.md"
```

### 2. 테스트/프리뷰 HTML 파일 삭제 (2개)

```powershell
Remove-Item "dashboard_preview.html"
Remove-Item "dashboard_test.html"
```

### 3. 임시 Python 스크립트 삭제 (3개)

```powershell
Remove-Item "complete_attack_and_update.py"
Remove-Item "generate_ai_report.py"
Remove-Item "update_report_with_actual_attacks.py"
```

### 4. 백업 파일 삭제 (1개)

```powershell
Remove-Item "Aegis_AI_Backup_260110.tar.gz"
```

### 5. 빈 폴더 삭제 (1개)

```powershell
Remove-Item "scan_test" -Recurse -Force
```

### 6. 한 번에 모두 삭제 (권장)

```powershell
cd "C:\Users\YONSAI\Desktop\SentinAI_Backup_20260114_1205\new"

# 개발 과정 문서 (13개)
Remove-Item "DASHBOARD_STRUCTURE.md" -ErrorAction SilentlyContinue
Remove-Item "DASHBOARD_ISSUES_ANALYSIS.md" -ErrorAction SilentlyContinue
Remove-Item "DASHBOARD_ADDITIONAL_ISSUES.md" -ErrorAction SilentlyContinue
Remove-Item "DASHBOARD_IMPROVEMENTS_IMPLEMENTATION.md" -ErrorAction SilentlyContinue
Remove-Item "FINAL_IMPLEMENTATION_VERIFICATION.md" -ErrorAction SilentlyContinue
Remove-Item "ATTACK_SCENARIO_PARSING_FIX.md" -ErrorAction SilentlyContinue
Remove-Item "BUGFIX_SUMMARY.md" -ErrorAction SilentlyContinue
Remove-Item "WORKFLOW_FIX_SUMMARY.md" -ErrorAction SilentlyContinue
Remove-Item "AI_REPORT_IMPROVEMENT_ANALYSIS.md" -ErrorAction SilentlyContinue
Remove-Item "DATA_FLOW_IMPROVEMENT.md" -ErrorAction SilentlyContinue
Remove-Item "IMPROVEMENT_PLAN.md" -ErrorAction SilentlyContinue
Remove-Item "IMPLEMENTATION_SUMMARY.md" -ErrorAction SilentlyContinue
Remove-Item "IMPROVEMENT_SUMMARY.md" -ErrorAction SilentlyContinue
Remove-Item "FINAL_SUMMARY.md" -ErrorAction SilentlyContinue
Remove-Item "WORKFLOW_VERIFICATION.md" -ErrorAction SilentlyContinue

# 테스트/프리뷰 HTML (2개)
Remove-Item "dashboard_preview.html" -ErrorAction SilentlyContinue
Remove-Item "dashboard_test.html" -ErrorAction SilentlyContinue

# 임시 Python 스크립트 (3개)
Remove-Item "complete_attack_and_update.py" -ErrorAction SilentlyContinue
Remove-Item "generate_ai_report.py" -ErrorAction SilentlyContinue
Remove-Item "update_report_with_actual_attacks.py" -ErrorAction SilentlyContinue

# 백업 파일 (1개)
Remove-Item "Aegis_AI_Backup_260110.tar.gz" -ErrorAction SilentlyContinue

# 빈 폴더 (1개)
Remove-Item "scan_test" -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "✅ 정리 완료! 20개 파일/폴더 삭제됨" -ForegroundColor Green
```

---

## 🔍 선택적 정리 (과거 스캔 결과)

### 과거 스캔 결과 정리 (용량 확보)

**현재 상태**:
- 폴더: 11개
- 파일: 188개 (JSON, TXT, MD 등)
- 예상 용량: ~50MB

**권장사항**:
1. **최근 2-3개 스캔 결과만 보관**
2. **나머지는 백업 후 삭제**

**삭제 명령어** (예시: 오래된 스캔 결과만 삭제):
```powershell
cd "C:\Users\YONSAI\Desktop\SentinAI_Backup_20260114_1205\new\scan_results\outputs"

# 특정 날짜 이전 결과 삭제 (예: 1월 11일 이전)
Get-ChildItem -Directory | 
    Where-Object { $_.Name -match "1768[0-2]" } | 
    Remove-Item -Recurse -Force

Write-Host "✅ 오래된 스캔 결과 삭제 완료" -ForegroundColor Green
```

**주의**: 스캔 결과는 테스트 데이터로 활용 가능하므로, 삭제 전 백업 권장

---

## 📋 정리 후 프로젝트 구조

```
new/
├── app/                              # 메인 애플리케이션 ✅
├── data/                             # 데이터 파일 ✅
├── docker/                           # Docker 설정 ✅
├── scripts/                          # 유틸리티 스크립트 ✅
├── scan_results/                     # 스캔 결과 (선택적 정리) ⚠️
├── vulnerable_webapp/                # 테스트용 웹앱 ✅
│
├── README.md                         # 프로젝트 설명 ✅
├── INSTALLATION.md                   # 설치 가이드 ✅
├── BUILD_DOCKER.md                   # Docker 빌드 ✅
├── PROJECT_STRUCTURE.md              # 프로젝트 구조 ✅
├── TESTING_CHECKLIST.md              # 테스트 체크리스트 ⚠️
├── TESTING_GUIDE.md                  # 테스트 가이드 ⚠️
├── CWE_METADATA_ENRICHMENT_OPTIONS.md # CWE 옵션 ⚠️
├── CWE_METADATA_IMPLEMENTATION.md    # CWE 구현 ⚠️
│
├── run.py                            # 메인 실행 파일 ✅
├── requirements.txt                  # Python 패키지 ✅
└── docker-compose.yml                # Docker Compose ✅
```

**범례**:
- ✅ 필수 파일 (삭제 불가)
- ⚠️ 선택적 보관 (참고용)
- ❌ 삭제된 파일 (20개)

---

## ⚠️ 주의사항

### 1. 백업 권장
삭제 전 중요한 문서는 백업 권장:
```powershell
# 문서 백업
cd "C:\Users\YONSAI\Desktop\SentinAI_Backup_20260114_1205"
New-Item -ItemType Directory -Path "docs_backup_20260114" -Force
Copy-Item "new\*.md" -Destination "docs_backup_20260114\" -ErrorAction SilentlyContinue
```

### 2. Git 이력
- Git을 사용 중이라면 삭제된 파일도 이력에서 복구 가능
- `git log -- <파일명>` 으로 이력 확인 가능

### 3. 단계적 삭제
- 한 번에 모두 삭제보다는 카테고리별로 단계적 삭제 권장
- 삭제 후 프로젝트 정상 작동 확인

---

## 📊 정리 효과

### 삭제 전
- 문서 파일: ~40개
- 프로젝트 크기: ~200MB+
- 구조: 복잡함 (개발 과정 파일 혼재)

### 삭제 후
- 문서 파일: ~10개 (필수 + 참고용)
- 프로젝트 크기: ~50MB (150MB 절약)
- 구조: 깔끔함 (필수 파일만 유지)

---

## 🎯 최종 권장사항

### 즉시 삭제 권장 (안전)
1. ✅ 개발 과정 문서 13개
2. ✅ 테스트/프리뷰 HTML 2개
3. ✅ 임시 Python 스크립트 3개
4. ✅ 백업 파일 1개
5. ✅ 빈 폴더 1개

**합계: 20개 파일/폴더 (~150MB)**

### 선택적 삭제
- ⚠️ 과거 스캔 결과 (테스트 데이터로 활용 가능)

### 보관 권장
- ⚠️ CWE 메타데이터 문서 2개 (향후 참고)
- ⚠️ 테스트 가이드 2개 (향후 참고)

---

**작성일**: 2026-01-14  
**작성자**: AI Assistant  
**버전**: 1.0
