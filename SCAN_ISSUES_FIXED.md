# 스캔 결과 비어있는 문제 해결

## 🔍 발견된 문제점

### 결과 파일 분석
```json
{
    "headers": {...},           // ✅ 정상 (nginx, PHP 정보)
    "webtechnologies": [],      // ❌ 비어있음
    "nuclei_vulns": [],        // ❌ 비어있음
    "zap_results": null,       // ❌ null
    "verifications": []        // ❌ 없음
}
```

### 문제 원인

1. **에러가 조용히 실패**
   - `except Exception as e: logger.warning(...)` - 에러만 로깅하고 계속 진행
   - 실제 원인을 알 수 없음

2. **도구 설치 확인 부족**
   - Katana/Nuclei/WhatWeb이 설치되어 있는지 확인 안 함
   - 도구가 없어도 에러 없이 진행

3. **디버깅 정보 부족**
   - 각 단계별 성공/실패 여부를 명확히 표시하지 않음
   - 결과 파일 크기나 내용 확인 안 함

4. **헤더 정보 미활용**
   - 헤더에 nginx, PHP 정보가 있는데 기술 스택에 추가 안 함

---

## ✅ 수정 사항

### 1. 헤더에서 기술 스택 추출 추가
```python
# Step 0에서 헤더 수집 시 기술 스택도 추출
- Server: nginx/1.19.0 → nginx 기술 스택 추가
- X-Powered-By: PHP/5.6.40 → PHP 기술 스택 추가
```

### 2. 에러 로깅 강화
```python
# 이전: logger.warning(...)
# 수정: logger.error(..., exc_info=True) + print(...)
- 상세한 에러 메시지 출력
- 스택 트레이스 포함
- 각 단계별 성공/실패 명확히 표시
```

### 3. 도구 설치 확인 강화
```python
# 이전: shutil.which()만 확인
# 수정: 설치 여부 확인 + 명확한 메시지
- 도구가 없으면 "건너뜀" 메시지 출력
- 실행 실패 시 에러 코드와 메시지 출력
```

### 4. 결과 파일 검증 추가
```python
# Nuclei 결과 파일 검증
- 파일 존재 확인
- 파일 크기 확인 (비어있는지 체크)
- JSON 파싱 에러 처리
```

### 5. Nmap 전체 스캔 추가
```python
# Step 6: Nmap 전체 스캔
- 네트워크 레벨 정보 수집
- 포트 및 서비스 탐지
- OS 핑거프린팅
- 비웹 서비스 발견
```

---

## 🔧 Dockerfile 개선

### 추가된 패키지
```dockerfile
RUN apt-get install -y \
    nmap \      # 네트워크 스캔
    whatweb \   # 기술 스택 탐지
    ...
```

---

## 📊 개선된 스캔 워크플로우

```
Step 0: 헤더 수집 + 기술 스택 추출 (nginx, PHP 등)
   ↓
Step 1: Katana 크롤링 (에러 로깅 강화)
   ↓
Step 2: Nuclei 스캔 (결과 파일 검증 추가)
   ↓
Step 3: WhatWeb 탐지 (에러 처리 개선)
   ↓
Step 4: ZAP Targeted Scan
   ↓
Step 5: VulnerabilityVerifier
   ↓
Step 6: Nmap 전체 스캔 ⭐ NEW
```

---

## 🎯 예상 개선 결과

### 이전:
```json
{
    "webtechnologies": [],  // 비어있음
    "nuclei_vulns": []     // 비어있음
}
```

### 개선 후:
```json
{
    "webtechnologies": [
        {"name": "nginx", "version": "1.19.0", "source": "HTTP-Header"},
        {"name": "PHP", "version": "5.6.40", "source": "HTTP-Header"},
        {"name": "Apache", "version": "2.4.41", "source": "Nmap"},
        ...
    ],
    "nuclei_vulns": [
        {"name": "SQL Injection", "severity": "high", "url": "..."},
        ...
    ],
    "nmap_results": [
        {"ip": "...", "ports": [...]},
        ...
    ]
}
```

---

## ⚠️ 주의사항

### Nmap 스캔 시간
- 전체 포트 스캔: 5-30분 소요
- Docker 워커에서 실행 시 타임아웃 고려 필요

### 권한 문제
- Nmap은 루트 권한이 필요한 기능이 있음 (OS 핑거프린팅 등)
- Docker 컨테이너에서 실행 시 권한 확인 필요

---

## 🚀 다음 단계

1. **Docker 이미지 재빌드**
   ```bash
   docker build -t my-scanner-image:latest .
   ```

2. **스캔 재실행**
   - 개선된 로깅으로 문제점 파악 가능
   - 헤더에서 최소한의 기술 스택 정보 확보

3. **결과 확인**
   - `webtechnologies`에 최소한 헤더 정보 포함
   - `nmap_results`에 네트워크 정보 포함

