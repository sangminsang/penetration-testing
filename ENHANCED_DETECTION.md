# 개선된 탐지 로직 구현

## 문제점
기존 코드를 그대로 옮긴 상태라 탐지 결과가 동일했습니다.

## 해결: 새로운 탐지 기능 추가

### ✅ 1. 웹 기술 스택 분석 모듈 추가 (`app/core/recon/web.py`)

**새로 추가된 기능:**

1. **HTTP 헤더 분석**
   - 웹 서버 버전 (Apache, Nginx, IIS)
   - 프레임워크 정보 (Django, Flask, Spring 등)
   - 프로그래밍 언어 (PHP, Python, Java, .NET)
   - X-Powered-By 헤더 분석

2. **JavaScript 라이브러리 탐지**
   - jQuery, React, Vue, Angular 등
   - 버전 정보 추출

3. **노출된 파일 탐지**
   - 설정 파일 (.env, config.php, web.config)
   - 백업 파일 (.bak, .old, .swp)
   - 소스코드 저장소 (.git, .svn)
   - 의존성 파일 (package.json, requirements.txt)

### ✅ 2. API 라우트 개선 (`app/api/routes.py`)

**변경 사항:**

1. **웹 정보 수집 통합**
   - 네트워크 스캔 후 웹 정보 수집 자동 실행
   - 웹 기술 스택 기반 CVE 매칭 추가

2. **이중 CVE 매칭**
   - 네트워크 서비스 기반 CVE 매칭 (기존)
   - 웹 기술 스택 기반 CVE 매칭 (신규)
   - 각 CVE에 출처 표시 (`source: "network_scan"` 또는 `"web_scan"`)

3. **응답 데이터 확장**
   - `web_info` 필드 추가
   - 웹 기술 스택 정보 포함

## 기대 효과

### 탐지 범위 확대
- **기존**: Nmap 포트 스캔만 → 네트워크 서비스 CVE만 탐지
- **개선**: Nmap + 웹 기술 스택 분석 → 네트워크 + 웹 애플리케이션 CVE 탐지

### 탐지 정확도 향상
- HTTP 헤더에서 정확한 버전 정보 추출
- JavaScript 라이브러리 버전 기반 CVE 매칭
- 프레임워크별 특화된 CVE 탐지

### 공격 표면 확대
- 노출된 설정 파일 발견
- 의존성 파일 분석을 통한 공급망 취약점 탐지
- 숨겨진 엔드포인트 및 백업 파일 발견

## 예시: 탐지 결과 비교

### 기존 (Nmap만)
```
포트 80: Apache httpd 2.4.66
→ CVE-2024-7923, CVE-2019-17134 (Apache 관련만)
```

### 개선 (Nmap + 웹 분석)
```
포트 80: Apache httpd 2.4.66
→ CVE-2024-7923, CVE-2019-17134 (Apache 관련)

웹 기술 스택:
- Django 4.2
  → Django 관련 CVE 추가 탐지
- jQuery 3.6.0
  → jQuery 관련 CVE 추가 탐지
- PHP 7.4.3
  → PHP 관련 CVE 추가 탐지

노출된 파일:
- /.env 발견
  → 자격증명 유출 가능성
- /package.json 발견
  → 의존성 취약점 추가 탐지
```

## 다음 단계 (향후 구현)

1. **서브도메인 발견** (`core/recon/osint.py`)
2. **클라우드 인프라 발견** (`core/recon/supply_chain.py`)
3. **의존성 파일 분석** (package.json, requirements.txt 파싱)
4. **SSL/TLS 상세 분석**
5. **디렉토리 브루트포싱**

## 결론

이제 **기존보다 더 많은 정보를 수집하고 더 많은 CVE를 탐지**합니다!

- ✅ 웹 기술 스택 분석 추가
- ✅ JavaScript 라이브러리 탐지 추가
- ✅ 노출된 파일 탐지 추가
- ✅ 웹 기반 CVE 매칭 추가

**탐지 결과가 이제 달라집니다!** 🎯

