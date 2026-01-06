# 대시보드 데이터 흐름 설명

## ✅ 개선 완료: 스캔 결과가 대시보드로 전송됨

### 데이터 흐름

```
┌─────────────────────────────────────────────────────────┐
│ 1. Docker 워커 실행                                      │
│    - collect_web_info() 실행                            │
│    - 결과를 JSON 파일로 저장 (scan_results/)            │
└─────────────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────────────┐
│ 2. 결과 파일 모니터링 (app/api/websocket.py)            │
│    - scan_results/ 폴더에서 결과 파일 감지              │
│    - 실시간으로 파일 읽기                                │
└─────────────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────────────┐
│ 3. 데이터 형식 변환                                      │
│    - webtechnologies → technology_detected 이벤트       │
│    - nuclei_vulns → CVE 형식으로 변환                    │
│    - 기술과 취약점 연결                                  │
└─────────────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────────────┐
│ 4. WebSocket으로 대시보드 전송                          │
│    - technology_detected 이벤트 emit                    │
│    - scan_completed 이벤트 emit                          │
└─────────────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────────────┐
│ 5. 대시보드 표시 (live_scan_v2.js)                      │
│    - 기술 스택 카드 렌더링                               │
│    - 취약점 차트 업데이트                                │
│    - 보안 점수 계산                                      │
└─────────────────────────────────────────────────────────┘
```

---

## 📊 데이터 형식 매핑

### collect_web_info() 반환값:
```python
{
    'webtechnologies': [
        {'name': 'Apache', 'version': '2.4.41', 'source': 'Nuclei'},
        {'name': 'PHP', 'version': '7.4.3', 'source': 'WhatWeb'}
    ],
    'nuclei_vulns': [
        {
            'name': 'Apache 2.4.41 Path Traversal',
            'severity': 'high',
            'url': 'http://target.com/admin',
            'template_id': 'CVE-2021-41773'
        }
    ],
    'zap_results': {
        'alerts': [...],
        'scanned_urls': 5
    },
    'verifications': [...]
}
```

### 대시보드가 기대하는 형식 (technology_detected 이벤트):
```javascript
{
    name: 'Apache',
    version: '2.4.41',
    source: 'Nuclei',
    cves: [
        {
            cve_id: 'CVE-2021-41773',
            severity: 'HIGH',
            description: 'Apache 2.4.41 Path Traversal',
            url: 'http://target.com/admin'
        }
    ]
}
```

### 변환 로직 (app/api/websocket.py):
- ✅ `webtechnologies` → `technology_detected` 이벤트로 변환
- ✅ `nuclei_vulns` → CVE 형식으로 변환하여 기술과 연결
- ✅ 기술별로 취약점 그룹화

---

## 🎯 대시보드에 표시되는 정보

### 1. 기술 스택 카드
- **출처**: `webtechnologies` (Nuclei + WhatWeb)
- **표시**: 기술 이름, 버전, 출처
- **이벤트**: `technology_detected`

### 2. 취약점 정보
- **출처**: `nuclei_vulns` → CVE 형식으로 변환
- **표시**: 기술 카드에 연결된 CVE 목록
- **차트**: 심각도별 분포, CVSS/EPSS 스캐터 플롯

### 3. 보안 점수
- **계산**: 취약점 심각도 기반
- **공식**: 100 - (CRITICAL×20 + HIGH×10 + MEDIUM×3 + LOW×1)

### 4. 공격 표면 맵
- **기술 노드**: 기술 스택
- **취약점 노드**: CVE
- **연결**: 기술과 취약점 간 관계

---

## ⚠️ 현재 제한사항

### ZAP 결과와 Verification 결과
- **현재**: 대시보드에 직접 표시되지 않음
- **이유**: 대시보드가 `technology_detected` 이벤트만 처리
- **향후 개선**: 별도 이벤트 추가 가능
  - `zap_alerts_detected` 이벤트
  - `verification_completed` 이벤트

### 데이터 저장
- **현재**: JSON 파일로만 저장
- **DB 저장**: `ScanResult` 모델에 저장하는 로직 추가 가능

---

## 🔄 실시간 업데이트

### 파일 모니터링 방식:
1. **폴링**: 2초마다 결과 파일 체크
2. **중복 방지**: `processed_files` 세트로 처리된 파일 추적
3. **완료 조건**: 80% 이상 파일 생성 시 완료로 간주

### 성능 고려사항:
- 최대 대기 시간: 10분
- 파일 읽기 오류 처리: 예외 발생 시 다음 파일로 진행
- 메모리: 처리된 파일 경로만 저장 (파일 내용은 읽고 버림)

---

## ✅ 확인 사항

### 스캔 결과가 대시보드에 표시되는지 확인:
1. ✅ `collect_web_info()`가 올바른 형식으로 데이터 반환
2. ✅ `run_integrated_scan()`이 결과 파일을 읽어서 WebSocket으로 전송
3. ✅ 대시보드가 `technology_detected` 이벤트를 받아서 표시
4. ✅ 기술 스택과 취약점이 올바르게 연결되어 표시

### 테스트 방법:
1. 스캔 시작
2. 브라우저 개발자 도구에서 WebSocket 이벤트 확인
3. `technology_detected` 이벤트가 수신되는지 확인
4. 대시보드에 기술 카드가 나타나는지 확인

---

## 🚀 향후 개선 가능 사항

1. **ZAP 결과 표시**: 별도 섹션에 ZAP 알림 표시
2. **Verification 결과 표시**: 검증 결과를 별도 카드로 표시
3. **실시간 스트리밍**: 파일 대신 WebSocket으로 직접 스트리밍
4. **DB 저장**: 결과를 데이터베이스에 저장하여 히스토리 관리

