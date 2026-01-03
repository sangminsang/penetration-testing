# 침투 테스트 자동화 플랫폼 기획서
## CVE 기반 취약점 탐지 및 공격 시나리오 생성 시스템

---

## 📋 프로젝트 개요

### 프로젝트명
**CVE-Driven Penetration Testing Automation Platform**

### 프로젝트 목적
NVD(National Vulnerability Database)의 전체 CVE 데이터를 활용하여, 타겟 서버의 취약점을 자동으로 탐지하고 공격 시나리오를 생성하는 플랫폼 구축

### 핵심 가치
- **정보 수집 자동화**: 타겟 URL 입력만으로 전체 취약점 정보 수집
- **CVE 기반 정확한 매칭**: 30만 개 이상의 CVE 데이터베이스 활용
- **공격 시나리오 제시**: 실제 공격은 하지 않고, 전문가가 수행할 수 있는 상세 가이드 제공
- **카테고리별 분류**: 웹, OS, 네트워크, 애플리케이션 등 현업 기준 분류

---

## 🎯 프로젝트 목표

### 1. CVE 데이터베이스 구축 및 분류
- **목표**: NVD에서 제공하는 전체 CVE 데이터 수집 및 카테고리별 분류
- **범위**: 
  - NVD API v2.0을 통한 전체 CVE 수집 (약 30만 개)
  - CVE 내용 분석을 통한 자동 분류
  - 카테고리: 웹, OS, 네트워크, 애플리케이션, 클라우드, 컨테이너 등

### 2. 타겟 서버 정보 수집 시스템
- **목표**: URL 입력 시 서버의 모든 정보를 수집하여 CVE 매칭 가능한 데이터 확보
- **핵심 원칙**: 실제 화이트해커가 수행하는 모든 정보 수집 기법을 자동화

#### 2.1 네트워크 레벨 정보 수집
- **포트 및 서비스 스캔**
  - 열린 포트 탐지
  - 서비스 식별 (HTTP, HTTPS, SSH, FTP, MySQL 등)
  - 서비스 버전 정보 (배너 그래빙)
  - 운영체제 정보 (OS 핑거프린팅)
  - 네트워크 토폴로지 매핑

#### 2.2 웹 애플리케이션 정보 수집
- **웹 기술 스택 분석**
  - 웹 서버 버전 (Apache, Nginx, IIS)
  - 프로그래밍 언어 및 버전 (PHP, Python, Java, Node.js)
  - 프레임워크 및 라이브러리 (Django, Flask, Spring, Express, WordPress 등)
  - HTTP 헤더 분석 (Server, X-Powered-By, X-AspNet-Version 등)
  - JavaScript 라이브러리 및 버전 (jQuery, React, Vue 등)
  - 쿠키 및 세션 관리 방식

- **웹 구조 탐색**
  - 디렉토리 및 파일 브루트포싱
  - 숨겨진 엔드포인트 발견
  - API 엔드포인트 발견 (REST, GraphQL)
  - 백업 파일 발견 (.bak, .old, .swp, .git)
  - 설정 파일 노출 (.env, config.php, web.config)
  - 소스코드 유출 (.git 디렉토리, .svn)

- **인증 및 보안 설정**
  - 인증 메커니즘 분석
  - WAF/CDN 탐지
  - SSL/TLS 설정 분석
  - CORS 정책 확인

#### 2.3 자산 경계 확장 (Asset Boundary Expansion)
- **서브도메인 발견**
  - DNS 레코드 조회 (A, AAAA, CNAME, MX, TXT, NS)
  - Certificate Transparency (CT) 로그 분석
  - 서브도메인 브루트포싱
  - 검색 엔진 기반 발견 (Google dorking)

- **IP 및 인프라 정보**
  - WHOIS 정보 수집
  - ASN (Autonomous System Number) 분석
  - Reverse DNS (PTR) 분석
  - 같은 ASN 내 다른 IP 범위 발견
  - 클라우드 인프라 식별 (AWS, GCP, Azure)

- **클라우드 자산 발견**
  - S3 버킷 발견 및 접근 가능 여부
  - Azure Blob Storage
  - Google Cloud Storage
  - 클라우드 Metadata API 노출

#### 2.4 공급망 정보 수집 (Supply Chain Intelligence)
- **의존성 및 라이브러리 정보**
  - 패키지 매니저 파일 분석 (package.json, requirements.txt, pom.xml, Gemfile)
  - 사용 중인 라이브러리 및 버전
  - 의존성 트리 분석
  - 알려진 취약한 의존성 탐지

- **소스코드 저장소 정보**
  - GitHub/GitLab/Bitbucket 저장소 발견
  - 공개 저장소에서 설정 파일, 자격증명 노출 확인
  - 커밋 히스토리 분석 (하드코딩된 자격증명)
  - 이슈 및 PR에서 정보 유출 확인

#### 2.5 OSINT (Open Source Intelligence)
**⚠️ 주의**: 자동화 가능한 OSINT만 수행 (수동 검색은 제외)

- **공개 정보 수집**
  - 도메인 등록 정보 (WHOIS)
  - DNS 레코드 정보
  - SSL 인증서 정보
  - 서브도메인 정보 (Certificate Transparency)

- **기술 스택 정보**
  - Stack Overflow, Reddit 등 기술 스택 정보
  - 개발자 포럼에서 인프라 정보
  - 공개 문서에서 기술 스택 힌트

- **이메일 및 계정 정보**
  - 이메일 주소 수집 (Hunter.io API 등)
  - 이메일 형식 패턴 분석
  - 이메일 기반 계정 발견

#### 2.6 인증 정보 수집
- **기본 자격증명 정보**
  - Default credentials 데이터베이스
  - 제품별 기본 계정 정보

- **설정 파일에서 자격증명**
  - .env 파일에서 데이터베이스 자격증명
  - config 파일에서 API 키
  - 백업 파일에서 하드코딩된 자격증명

#### 2.7 네트워크 서비스 상세 정보
- **각 서비스별 상세 탐지**
  - SSH: 키 교환 알고리즘, 지원 암호화 방식
  - FTP: 익명 접근 가능 여부, 지원 명령어
  - MySQL/PostgreSQL: 버전, 인증 방식
  - SMB: 버전, 공유 폴더, 익명 접근
  - SMTP: Open Relay 가능 여부, SPF/DKIM 설정

#### 2.8 수집 정보의 CVE 매칭 활용

**수집된 정보 → CVE 매칭 예시**:

```
1. 포트 80: Apache httpd 2.4.66
   → CVE 매칭: Apache httpd 관련 CVE

2. X-Powered-By: PHP/7.4.3
   → CVE 매칭: PHP 7.4.3 관련 CVE

3. package.json: express@4.17.1
   → CVE 매칭: Express.js 4.17.1 관련 CVE

4. .git 디렉토리 발견
   → CVE 매칭: Git 관련 CVE + 소스코드 유출 가능성

5. S3 버킷 Public 접근 가능
   → CVE 매칭: 클라우드 설정 오류 (CVE는 아니지만 취약점)

6. GitHub 저장소에서 .env 파일 노출
   → CVE 매칭: 자격증명 유출 (CVE는 아니지만 취약점)
```

**가치**: 
- 단순 포트 스캔만으로는 놓칠 수 있는 취약점 발견
- 공급망 취약점까지 포함한 전체 공격 표면 파악
- 실제 화이트해커가 수행하는 수준의 정보 수집

### 3. 모드별 선택 스캔 시스템
- **목표**: 사용자가 원하는 카테고리만 선택하여 효율적인 스캔 수행
- **지원 모드**:
  - **전체 모드 (All)**: 모든 카테고리 스캔
  - **웹 모드 (Web)**: 웹 관련 CVE만 탐지
  - **시스템 모드 (OS)**: OS 및 시스템 관련 CVE만 탐지
  - **네트워크 모드 (Network)**: 네트워크 서비스 관련 CVE만 탐지
  - **애플리케이션 모드 (Application)**: 애플리케이션 관련 CVE만 탐지
  - **데이터베이스 모드 (Database)**: 데이터베이스 관련 CVE만 탐지
  - **클라우드 모드 (Cloud)**: 클라우드 인프라 관련 CVE만 탐지
  - **컨테이너 모드 (Container)**: 컨테이너 관련 CVE만 탐지
  - **커스텀 모드 (Custom)**: 여러 카테고리 조합 선택

- **모드별 최적화**:
  - 각 모드에 맞는 정보 수집 전략 자동 선택
  - 불필요한 스캔 제외로 성능 향상
  - 모드별 특화된 보고서 생성

### 4. CVE 매칭 엔진
- **목표**: 수집된 정보와 CVE 데이터베이스를 정확히 매칭
- **기능**:
  - CPE 기반 정확한 매칭
  - 버전 범위 기반 필터링 (패치된 CVE 제외)
  - False Positive 자동 제거
  - **카테고리별 필터링**: 선택한 모드에 해당하는 CVE만 매칭

### 5. 공격 시나리오 생성
- **목표**: 발견된 취약점을 바탕으로 실제 공격 가능한 시나리오 생성
- **제약**: 실제 공격은 실행하지 않고, 전문가가 수동으로 수행할 수 있는 가이드만 제공

---

## 🏗️ 시스템 아키텍처

### 전체 시스템 구조

```
┌─────────────────────────────────────────────────────────────┐
│                    사용자 인터페이스 (Web Dashboard)          │
│                    - URL 입력                                │
│                    - 결과 시각화                              │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│              타겟 서버 정보 수집 모듈 (Recon Engine)          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │  Nmap    │  │  Banner  │  │   OS     │  │  Web     │   │
│  │  Scan    │  │ Grabbing │  │Fingerprint│ │  Stack   │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
│                                                             │
│  모드별 최적화된 정보 수집 전략 적용                        │
│  - 웹 모드: 웹 기술 스택, 디렉토리, API 엔드포인트 집중     │
│  - 시스템 모드: OS 핑거프린팅, 시스템 서비스 집중            │
│  - 네트워크 모드: 네트워크 서비스 상세 분석 집중             │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│              CVE 데이터베이스 및 분류 시스템                  │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  NVD API → CVE 수집 → 내용 분석 → 카테고리 분류      │   │
│  │                                                       │   │
│  │  카테고리:                                            │   │
│  │  - 웹 (Web)                                          │   │
│  │  - OS (Operating System)                             │   │
│  │  - 네트워크 (Network)                                │   │
│  │  - 애플리케이션 (Application)                        │   │
│  │  - 클라우드 (Cloud)                                  │   │
│  │  - 컨테이너 (Container)                             │   │
│  └──────────────────────────────────────────────────────┘   │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│              CVE 매칭 엔진 (Matching Engine)                 │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │  CPE     │  │ Version  │  │  False   │  │  Priority│   │
│  │ Matching │  │ Filtering│  │Positive  │  │ Ranking  │   │
│  │          │  │          │  │ Removal  │  │          │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│         공격 시나리오 생성 모듈 (Scenario Generator)           │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │  Attack  │  │  Exploit │  │   AI     │  │ Reporting│   │
│  │  Chain   │  │  Info    │  │ Scenario │  │          │   │
│  │  Design  │  │  Search  │  │ Generator│  │          │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
└─────────────────────────────────────────────────────────────┘
```

---

## 📊 CVE 분류 체계

### 분류 기준
CVE ID가 아닌 **CVE 내용(CWE, 설명, 영향 제품)**을 분석하여 현업 기준으로 분류

### 카테고리 정의 및 탐지 전략

각 카테고리는 **수집 정보 → CVE 매칭 → 탐지 검증**의 3단계 프로세스로 구성됩니다.

---

#### 1. 웹 (Web)
**기준**: 웹 애플리케이션, 웹 서버, 웹 프레임워크 관련 취약점

**포함 CVE 유형**:
- OWASP Top 10 관련 (SQL Injection, XSS, CSRF 등)
- 웹 서버 취약점 (Apache, Nginx, IIS)
- 웹 프레임워크 취약점 (Django, Flask, Spring, Express 등)
- API 취약점 (REST, GraphQL)
- **예시**: CVE-2021-41773 (Apache Path Traversal), CVE-2021-44228 (Log4j)

**필수 수집 정보**:
1. **웹 서버 정보**
   - 포트: 80/tcp, 443/tcp, 8080/tcp, 8443/tcp
   - 서버 버전: Apache, Nginx, IIS 버전
   - HTTP 헤더: Server, X-Powered-By, X-AspNet-Version
   - 수집 방법: 배너 그래빙, HTTP 헤더 분석

2. **웹 프레임워크 정보**
   - 프레임워크: Django, Flask, Spring, Express, Laravel 등
   - 버전: 정확한 버전 번호
   - 수집 방법: HTTP 헤더, 에러 페이지, JavaScript 소스코드 분석

3. **프로그래밍 언어 정보**
   - 언어: PHP, Python, Java, Node.js, .NET 등
   - 버전: PHP 7.4.3, Python 3.11.14 등
   - 수집 방법: X-Powered-By 헤더, 에러 메시지, 파일 확장자

4. **JavaScript 라이브러리 정보**
   - 라이브러리: jQuery, React, Vue, Angular 등
   - 버전: 정확한 버전 번호
   - 수집 방법: HTML 소스코드 분석, JavaScript 파일 분석

5. **의존성 정보 (공급망)**
   - package.json, requirements.txt, pom.xml, Gemfile 등
   - 라이브러리 및 버전 목록
   - 수집 방법: 파일 브루트포싱, GitHub 저장소 스캔

6. **웹 구조 정보**
   - 디렉토리 구조, API 엔드포인트
   - 설정 파일 노출 (.env, config.php)
   - 수집 방법: 디렉토리 브루트포싱, 파일 탐색

**CVE 매칭 전략**:
```python
# 웹 카테고리 CVE 매칭 예시
web_cve_matching = {
    "apache_httpd": {
        "cpe": "cpe:2.3:a:apache:http_server",
        "version_source": "배너 그래빙, HTTP Server 헤더",
        "cve_example": "CVE-2024-7923, CVE-2021-41773"
    },
    "express": {
        "cpe": "cpe:2.3:a:expressjs:express",
        "version_source": "package.json, npm 패키지 정보",
        "cve_example": "CVE-2023-43622"
    },
    "django": {
        "cpe": "cpe:2.3:a:djangoproject:django",
        "version_source": "requirements.txt, HTTP 응답",
        "cve_example": "Django 관련 CVE"
    }
}
```

**탐지 검증 방법**:
- 버전 기반 매칭: 수집된 버전이 CVE 영향 범위에 포함되는지 확인
- 설정 파일 분석: mod_proxy 활성화 여부 등 설정 기반 검증
- 능동적 테스트: Critical CVE의 경우 실제 패턴 테스트 (안전한 범위 내)

---

#### 2. OS (Operating System)
**기준**: 운영체제 커널, 시스템 라이브러리, 권한 상승 관련 취약점

**포함 CVE 유형**:
- Linux 커널 취약점
- Windows 시스템 취약점
- 권한 상승 취약점 (Privilege Escalation)
- 시스템 라이브러리 취약점
- **예시**: CVE-2021-4034 (Polkit Pkexec), CVE-2021-34527 (Windows Print Spooler)

**필수 수집 정보**:
1. **OS 정보**
   - OS 타입: Linux, Windows, macOS, Unix
   - OS 버전: Linux 3.2-4.9, Windows 10/11, macOS 버전
   - 커널 버전: Linux 커널 버전
   - 수집 방법: OS 핑거프린팅 (Nmap -O), TTL 값 분석, TCP 윈도우 크기

2. **시스템 서비스 정보**
   - SSH 버전: OpenSSH 버전
   - 시스템 라이브러리: glibc, libc 버전
   - 수집 방법: SSH 배너, 시스템 명령어 (권한 있을 시)

3. **시스템 구성 정보**
   - 사용자 계정 정보 (가능한 경우)
   - 파일 시스템 정보
   - 수집 방법: 시스템 접근 시 (권한 필요)

**CVE 매칭 전략**:
```python
# OS 카테고리 CVE 매칭 예시
os_cve_matching = {
    "linux_kernel": {
        "cpe": "cpe:2.3:o:linux:linux_kernel",
        "version_source": "OS 핑거프린팅, uname 명령어",
        "cve_example": "CVE-2021-4034, CVE-2021-27365"
    },
    "windows": {
        "cpe": "cpe:2.3:o:microsoft:windows",
        "version_source": "OS 핑거프린팅, SMB 버전",
        "cve_example": "CVE-2021-34527, CVE-2020-1472"
    },
    "openssh": {
        "cpe": "cpe:2.3:a:openssh:openssh",
        "version_source": "SSH 배너 그래빙",
        "cve_example": "SSH 관련 CVE"
    }
}
```

**탐지 검증 방법**:
- OS 버전 매칭: 핑거프린팅 결과와 CVE 영향 OS 버전 비교
- 서비스 버전 매칭: SSH 등 시스템 서비스 버전 기반 매칭
- 권한 상승 취약점: SUID/SGID 파일, 커널 버전 기반 검증

---

#### 3. 네트워크 (Network)
**기준**: 네트워크 프로토콜, 네트워크 서비스 관련 취약점

**포함 CVE 유형**:
- SSL/TLS 취약점
- SMB/Samba 취약점
- SSH 취약점
- FTP 취약점
- DNS 취약점
- VPN 취약점
- **예시**: CVE-2014-0160 (Heartbleed), CVE-2017-0144 (EternalBlue)

**필수 수집 정보**:
1. **SSL/TLS 정보**
   - SSL/TLS 버전: TLS 1.0, 1.1, 1.2, 1.3
   - 암호화 알고리즘: 지원하는 암호화 스위트
   - 인증서 정보: 발급자, 만료일, 키 길이
   - 수집 방법: testssl.sh, openssl s_client, SSL 스캔

2. **SMB/Samba 정보**
   - SMB 버전: SMBv1, SMBv2, SMBv3
   - Samba 버전: 정확한 버전 번호
   - 공유 폴더: 익명 접근 가능 여부
   - 수집 방법: Nmap SMB 스크립트, enum4linux

3. **SSH 정보**
   - SSH 버전: OpenSSH 버전
   - 키 교환 알고리즘: 지원하는 알고리즘
   - 암호화 알고리즘: 지원하는 암호화 방식
   - 수집 방법: SSH 배너 그래빙, SSH 핸드셰이크 분석

4. **FTP 정보**
   - FTP 서버 버전: ProFTPD, vsftpd, FileZilla 등
   - 익명 접근: 가능 여부
   - 수집 방법: FTP 배너 그래빙, FTP 명령어

5. **DNS 정보**
   - DNS 서버 버전: BIND 버전
   - DNS 설정: DNSSEC, DNS over HTTPS
   - 수집 방법: DNS 쿼리, dig 명령어

6. **VPN 정보**
   - VPN 타입: OpenVPN, IPSec, PPTP
   - VPN 버전: 정확한 버전
   - 수집 방법: 포트 스캔, VPN 프로토콜 분석

**CVE 매칭 전략**:
```python
# 네트워크 카테고리 CVE 매칭 예시
network_cve_matching = {
    "openssl": {
        "cpe": "cpe:2.3:a:openssl:openssl",
        "version_source": "SSL/TLS 핸드셰이크, 인증서 정보",
        "cve_example": "CVE-2014-0160 (Heartbleed), CVE-2014-0224"
    },
    "samba": {
        "cpe": "cpe:2.3:a:samba:samba",
        "version_source": "SMB 프로토콜 분석, SMB 버전",
        "cve_example": "CVE-2017-0144 (EternalBlue), CVE-2021-44142"
    },
    "openssh": {
        "cpe": "cpe:2.3:a:openssh:openssh",
        "version_source": "SSH 배너 그래빙",
        "cve_example": "SSH 관련 CVE"
    },
    "bind": {
        "cpe": "cpe:2.3:a:isc:bind",
        "version_source": "DNS 쿼리, dig 명령어",
        "cve_example": "BIND 관련 CVE"
    }
}
```

**탐지 검증 방법**:
- 프로토콜 버전 매칭: SSL/TLS 버전, SMB 버전 기반 매칭
- 암호화 알고리즘 분석: 약한 암호화 알고리즘 사용 여부
- 능동적 테스트: Heartbleed 등 실제 취약점 패턴 테스트

---

#### 4. 애플리케이션 (Application)
**기준**: 데스크톱 애플리케이션, 모바일 앱, 독립 실행형 소프트웨어

**포함 CVE 유형**:
- 브라우저 취약점 (Chrome, Firefox, Edge)
- 오피스 소프트웨어 취약점
- 미디어 플레이어 취약점
- 모바일 앱 취약점
- **예시**: CVE-2025-6558 (Chrome 제로데이)

**필수 수집 정보**:
1. **애플리케이션 프레임워크 정보**
   - 프레임워크: Express, Django, Flask, Spring Boot 등
   - 버전: 정확한 버전 번호
   - 수집 방법: package.json, requirements.txt, HTTP 헤더

2. **런타임 환경 정보**
   - Node.js 버전: JavaScript 런타임
   - Python 버전: Python 인터프리터
   - Java 버전: JVM 버전
   - 수집 방법: HTTP 헤더, 에러 메시지, 파일 확장자

3. **애플리케이션 서비스 정보**
   - 포트: 8000/tcp, 8080/tcp, 3000/tcp 등
   - 서비스 버전: Werkzeug, Gunicorn 등
   - 수집 방법: 배너 그래빙, HTTP 응답

**CVE 매칭 전략**:
```python
# 애플리케이션 카테고리 CVE 매칭 예시
application_cve_matching = {
    "express": {
        "cpe": "cpe:2.3:a:expressjs:express",
        "version_source": "package.json, npm 패키지",
        "cve_example": "CVE-2023-43622"
    },
    "werkzeug": {
        "cpe": "cpe:2.3:a:werkzeug:werkzeug",
        "version_source": "배너 그래빙, requirements.txt",
        "cve_example": "CVE-2024-49767"
    },
    "django": {
        "cpe": "cpe:2.3:a:djangoproject:django",
        "version_source": "requirements.txt, HTTP 응답",
        "cve_example": "Django 관련 CVE"
    }
}
```

**탐지 검증 방법**:
- 의존성 파일 분석: package.json 등에서 버전 확인
- 배너 그래빙: 서비스 버전 직접 확인
- 공급망 분석: 의존성 트리 전체 분석

---

#### 5. 데이터베이스 (Database)
**기준**: 데이터베이스 서버 및 관련 도구 취약점

**포함 CVE 유형**:
- MySQL 취약점
- PostgreSQL 취약점
- MongoDB 취약점
- Redis 취약점
- 데이터베이스 관리 도구 취약점
- **예시**: CVE-2024-49767 (pgAdmin)

**필수 수집 정보**:
1. **데이터베이스 서버 정보**
   - DB 타입: MySQL, PostgreSQL, MongoDB, Redis
   - DB 버전: 정확한 버전 번호
   - 포트: 3306/tcp (MySQL), 5432/tcp (PostgreSQL), 27017/tcp (MongoDB), 6379/tcp (Redis)
   - 수집 방법: 데이터베이스 핸드셰이크, 배너 그래빙, 에러 메시지

2. **데이터베이스 관리 도구 정보**
   - phpMyAdmin, pgAdmin, MongoDB Compass 등
   - 버전: 정확한 버전 번호
   - 수집 방법: 웹 인터페이스, HTTP 헤더

3. **인증 정보**
   - 인증 없음: 익명 접근 가능 여부
   - 기본 자격증명: Default credentials
   - 수집 방법: 연결 시도, 기본 계정 시도

**CVE 매칭 전략**:
```python
# 데이터베이스 카테고리 CVE 매칭 예시
database_cve_matching = {
    "mysql": {
        "cpe": "cpe:2.3:a:mysql:mysql",
        "version_source": "MySQL 핸드셰이크, 배너 그래빙",
        "cve_example": "MySQL 관련 CVE"
    },
    "postgresql": {
        "cpe": "cpe:2.3:a:postgresql:postgresql",
        "version_source": "PostgreSQL 프로토콜, SELECT version()",
        "cve_example": "PostgreSQL 관련 CVE"
    },
    "mongodb": {
        "cpe": "cpe:2.3:a:mongodb:mongodb",
        "version_source": "MongoDB 프로토콜, 배너",
        "cve_example": "MongoDB 관련 CVE"
    },
    "redis": {
        "cpe": "cpe:2.3:a:redis:redis",
        "version_source": "Redis 프로토콜, INFO 명령어",
        "cve_example": "Redis 관련 CVE"
    },
    "pgadmin": {
        "cpe": "cpe:2.3:a:pgadmin:pgadmin",
        "version_source": "웹 인터페이스, HTTP 헤더",
        "cve_example": "CVE-2024-49767"
    }
}
```

**탐지 검증 방법**:
- 데이터베이스 버전 매칭: 핸드셰이크 또는 쿼리로 버전 확인
- 인증 설정 확인: 인증 없음, 기본 자격증명 확인
- 관리 도구 버전: 웹 인터페이스에서 버전 확인

---

#### 6. 클라우드 (Cloud)
**기준**: 클라우드 인프라, 클라우드 서비스 관련 취약점

**포함 CVE 유형**:
- AWS 서비스 취약점
- Azure 서비스 취약점
- GCP 서비스 취약점
- 클라우드 관리 도구 취약점
- **예시**: 클라우드 IAM, S3 버킷 설정 오류 (CVE는 아니지만 취약점)

**필수 수집 정보**:
1. **클라우드 인프라 정보**
   - 클라우드 제공자: AWS, Azure, GCP
   - ASN 정보: 클라우드 ASN 번호
   - IP 범위: 클라우드 IP 범위
   - 수집 방법: WHOIS, ASN 조회, IP 범위 확인

2. **클라우드 자산 정보**
   - S3 버킷: 버킷 이름, Public 접근 가능 여부
   - Azure Blob Storage: 컨테이너, Public 접근
   - GCP Cloud Storage: 버킷, Public 접근
   - 수집 방법: 버킷 이름 브루트포싱, 접근 권한 확인

3. **클라우드 Metadata API**
   - AWS Metadata API: 169.254.169.254
   - Azure Metadata API: 169.254.169.254
   - GCP Metadata API: 169.254.169.254
   - 수집 방법: SSRF를 통한 접근, 직접 접근 시도

**CVE 매칭 전략**:
```python
# 클라우드 카테고리 CVE 매칭 예시
cloud_cve_matching = {
    "aws": {
        "cpe": "cpe:2.3:a:amazon:aws",
        "version_source": "ASN 정보, IP 범위, 서비스 응답",
        "cve_example": "AWS 서비스 관련 CVE"
    },
    "azure": {
        "cpe": "cpe:2.3:a:microsoft:azure",
        "version_source": "ASN 정보, IP 범위",
        "cve_example": "Azure 서비스 관련 CVE"
    },
    "gcp": {
        "cpe": "cpe:2.3:a:google:cloud",
        "version_source": "ASN 정보, IP 범위",
        "cve_example": "GCP 서비스 관련 CVE"
    }
}
```

**탐지 검증 방법**:
- 클라우드 인프라 식별: ASN, IP 범위로 클라우드 제공자 확인
- 자산 발견: 버킷 이름 브루트포싱, 접근 권한 확인
- 설정 오류: Public 접근 가능 여부, Metadata API 노출 확인

---

#### 7. 컨테이너 (Container)
**기준**: 컨테이너 런타임, 오케스트레이션 관련 취약점

**포함 CVE 유형**:
- Docker 취약점
- Kubernetes 취약점
- 컨테이너 이미지 취약점
- **예시**: CVE-2021-41091 (Docker), CVE-2020-8558 (Kubernetes)

**필수 수집 정보**:
1. **Docker 정보**
   - Docker API 노출: 포트 2375/tcp, 2376/tcp
   - Docker 버전: API 응답에서 버전 확인
   - 수집 방법: Docker API 쿼리, 포트 스캔

2. **Kubernetes 정보**
   - Kubernetes API 서버: 포트 6443/tcp
   - Kubernetes 버전: API 응답에서 버전 확인
   - 수집 방법: Kubernetes API 쿼리, 인증서 분석

3. **컨테이너 이미지 정보**
   - 이미지 이름 및 태그
   - 이미지 취약점: 이미지 스캔 도구 활용
   - 수집 방법: Docker API, 이미지 레지스트리

**CVE 매칭 전략**:
```python
# 컨테이너 카테고리 CVE 매칭 예시
container_cve_matching = {
    "docker": {
        "cpe": "cpe:2.3:a:docker:docker",
        "version_source": "Docker API 응답, docker version",
        "cve_example": "CVE-2021-41091"
    },
    "kubernetes": {
        "cpe": "cpe:2.3:a:kubernetes:kubernetes",
        "version_source": "Kubernetes API 응답, kubectl version",
        "cve_example": "CVE-2020-8558"
    }
}
```

**탐지 검증 방법**:
- 컨테이너 런타임 버전: API 응답에서 버전 확인
- API 노출 확인: Docker/Kubernetes API 접근 가능 여부
- 이미지 스캔: 컨테이너 이미지 내 취약점 스캔

---

#### 8. 기타 (Others)
**기준**: 위 카테고리에 속하지 않는 기타 취약점
- 하드웨어 취약점
- 펌웨어 취약점
- IoT 디바이스 취약점

**필수 수집 정보**:
- 하드웨어 정보: 제조사, 모델, 펌웨어 버전
- IoT 디바이스 정보: 디바이스 타입, 펌웨어 버전
- 수집 방법: 디바이스 응답, 펌웨어 분석

**CVE 매칭 전략**:
- 하드웨어/펌웨어 버전 기반 매칭
- IoT 디바이스 특화 스캔

### 분류 자동화 방법

#### 1단계: CVE 메타데이터 분석
```python
# CVE 분류 기준
classification_rules = {
    "web": {
        "keywords": ["http", "web", "server", "framework", "api", "sql injection", "xss"],
        "cwe": ["CWE-89", "CWE-79", "CWE-352", "CWE-434"],
        "products": ["apache", "nginx", "iis", "django", "flask", "spring"]
    },
    "os": {
        "keywords": ["kernel", "privilege", "escalation", "system", "root"],
        "cwe": ["CWE-269", "CWE-264", "CWE-284"],
        "products": ["linux", "windows", "unix", "macos"]
    },
    "network": {
        "keywords": ["ssl", "tls", "smb", "ssh", "ftp", "dns", "vpn"],
        "cwe": ["CWE-295", "CWE-326", "CWE-327"],
        "products": ["openssl", "openssh", "samba", "bind"]
    },
    # ... 기타 카테고리
}
```

#### 2단계: CWE 매핑
- CWE (Common Weakness Enumeration) 코드를 기반으로 카테고리 결정
- 예: CWE-89 (SQL Injection) → 웹 카테고리

#### 3단계: 제품명 매핑
- CPE (Common Platform Enumeration)의 제품 정보를 기반으로 카테고리 결정
- 예: `cpe:2.3:a:apache:http_server` → 웹 카테고리

#### 4단계: 설명 텍스트 분석
- CVE 설명에서 키워드 추출 및 카테고리 결정
- 자연어 처리 (NLP) 활용

---

## 🔍 탐지 프로세스

### 전체 워크플로우

```
1. 사용자 입력
   └─> URL: https://example.com

2. 타겟 서버 정보 수집
   ├─> 포트 스캔 (Nmap)
   ├─> 서비스 버전 탐지 (배너 그래빙)
   ├─> OS 핑거프린팅
   ├─> 웹 기술 스택 분석
   └─> 네트워크 정보 수집

3. 수집된 정보 정규화
   ├─> CPE 형식 변환
   ├─> 버전 정보 정규화
   └─> 서비스 정보 구조화

4. CVE 데이터베이스 조회
   ├─> CPE 기반 매칭
   ├─> 버전 범위 필터링
   └─> 카테고리별 필터링

5. 결과 통합 및 우선순위 정렬
   ├─> CVSS 점수 기반 정렬
   ├─> Exploit 존재 여부 확인
   └─> 카테고리별 그룹핑

6. 공격 시나리오 생성
   ├─> 공격 체인 설계
   ├─> 단계별 가이드 생성
   └─> 보고서 생성

7. 결과 시각화
   └─> 대시보드에 표시
```

### 상세 프로세스

#### Phase 1: 정보 수집 (Information Gathering)

**입력**: `https://example.com`

**수집 항목**:

1. **포트 및 서비스 스캔**
   ```
   포트: 80/tcp, 443/tcp, 22/tcp, 3306/tcp
   서비스: http, https, ssh, mysql
   ```

2. **서비스 버전 탐지**
   ```
   80/tcp: Apache httpd 2.4.66
   443/tcp: Apache httpd 2.4.66 (SSL)
   22/tcp: OpenSSH 7.4
   3306/tcp: MySQL 5.7.35
   ```

3. **OS 정보**
   ```
   OS: Linux 3.2 - 4.9
   ```

4. **웹 기술 스택**
   ```
   Server: Apache/2.4.66
   X-Powered-By: PHP/7.4.3
   Framework: WordPress 6.0
   ```

5. **CPE 변환**
   ```
   cpe:2.3:a:apache:http_server:2.4.66
   cpe:2.3:a:openssh:openssh:7.4
   cpe:2.3:a:mysql:mysql:5.7.35
   cpe:2.3:o:linux:linux_kernel:4.9
   ```

#### Phase 2: CVE 매칭 (CVE Matching)

**매칭 프로세스**:

1. **CPE 기반 검색**
   ```python
   for cpe in detected_cpes:
       cves = query_nvd_by_cpe(cpe)
       all_cves.extend(cves)
   ```

2. **버전 범위 필터링**
   ```python
   for cve in all_cves:
       if is_version_vulnerable(target_version, cve):
           vulnerable_cves.append(cve)
   ```

3. **카테고리별 분류**
   ```python
   categorized = {
       "web": [],
       "os": [],
       "network": [],
       "application": [],
       "database": [],
       "cloud": [],
       "container": []
   }
   
   for cve in vulnerable_cves:
       category = classify_cve(cve)
       categorized[category].append(cve)
   ```

**결과 예시**:
```json
{
  "web": [
    {
      "cve_id": "CVE-2024-7923",
      "cvss": 9.8,
      "severity": "Critical",
      "description": "Apache httpd authentication bypass",
      "product": "Apache httpd",
      "version": "2.4.66",
      "source": "포트 스캔 - 배너 그래빙"
    },
    {
      "cve_id": "CVE-2023-43622",
      "cvss": 7.5,
      "severity": "High",
      "description": "Express.js prototype pollution",
      "product": "Express.js",
      "version": "4.17.1",
      "source": "공급망 분석 - package.json"
    }
  ],
  "network": [
    {
      "cve_id": "CVE-2017-0144",
      "cvss": 8.1,
      "severity": "High",
      "description": "SMB Remote Code Execution",
      "product": "SMB",
      "version": "1.0",
      "source": "포트 스캔 - SMB 버전 탐지"
    }
  ],
  "application": [
    {
      "cve_id": "CVE-2024-49767",
      "cvss": 7.5,
      "severity": "High",
      "description": "Werkzeug resource exhaustion",
      "product": "Werkzeug",
      "version": "3.1.4",
      "source": "포트 스캔 - 배너 그래빙 (8000/tcp)"
    }
  ],
  "cloud": [
    {
      "issue_type": "Misconfiguration",
      "severity": "High",
      "description": "S3 버킷 Public 접근 가능",
      "bucket": "example-backup.s3.amazonaws.com",
      "source": "자산 경계 확장 - 클라우드 스캔"
    }
  ]
}
```

#### Phase 3: 공격 시나리오 생성

**시나리오 생성 프로세스**:

1. **공격 체인 설계**
   - Initial Access → Privilege Escalation → Data Exfiltration
   - 발견된 CVE를 단계별로 연결

2. **단계별 가이드 생성**
   - 각 CVE별 공격 명령어
   - 예상 결과 설명
   - 실패 시 대안 방법

3. **보고서 생성**
   - 취약점 상세 정보
   - 공격 경로 다이어그램
   - 대응 방안

---

## 🛠️ 기술 스택

### 백엔드
- **프레임워크**: Flask (Python)
- **데이터베이스**: 
  - SQLite/PostgreSQL (CVE 데이터베이스)
  - Redis (캐싱)
- **외부 API**:
  - NVD API v2.0 (CVE 데이터)
  - Searchsploit (Exploit 정보)

### 정보 수집 도구
- **Nmap**: 포트 스캔, 서비스 버전 탐지, OS 핑거프린팅
- **Python-nmap**: Nmap Python 래퍼
- **Requests**: HTTP 요청 및 배너 그래빙
- **Wappalyzer**: 웹 기술 스택 분석
- **subfinder/amass**: 서브도메인 발견
- **gobuster/dirsearch**: 디렉토리 브루트포싱
- **testssl.sh**: SSL/TLS 상세 분석
- **whois/dnsrecon**: DNS 및 WHOIS 정보 수집
- **s3scanner/cloud_enum**: 클라우드 인프라 발견
- **GitHub API**: 공개 저장소 스캔 (자동화 가능한 범위만)

### AI/LLM
- **Ollama**: 공격 시나리오 생성
- **모델**: Gemma3:4b 또는 유사 모델

### 프론트엔드
- **템플릿 엔진**: Jinja2
- **CSS 프레임워크**: Bootstrap 5
- **JavaScript**: Vanilla JS (시각화)

---

## 📈 구현 단계

### Phase 1: CVE 데이터베이스 구축 및 분류 시스템 (3주)

**목표**: NVD에서 전체 CVE 데이터 수집 및 카테고리별 분류 시스템 구축

**작업 내용**:

**1주차: CVE 데이터 수집**
1. NVD API v2.0 연동
2. 전체 CVE 데이터 수집 (약 30만 개)
3. CVE 메타데이터 저장 (CPE, CWE, CVSS, 설명 등)
4. 데이터베이스 스키마 설계

**2주차: CVE 분류 알고리즘 개발**
5. 카테고리별 분류 규칙 정의 (키워드, CWE, CPE 패턴)
6. CWE 기반 자동 분류 로직 개발
7. CPE 패턴 매칭 로직 개발
8. 설명 텍스트 분석 (NLP) 로직 개발
9. 다중 카테고리 처리 로직 개발

**3주차: 카테고리별 데이터베이스 구축**
10. 카테고리별 인덱스 생성
11. 카테고리별 CVE 통계 생성
12. 분류 정확도 검증 및 튜닝

**산출물**:
- CVE 데이터베이스 (SQLite/PostgreSQL)
- CVE 분류 시스템 (8개 카테고리)
- 카테고리별 인덱스 및 통계
- 분류 정확도 리포트

### Phase 2-1: 정보 수집 모듈 강화 (4주)

**목표**: 실제 화이트해커 수준의 포괄적인 정보 수집 모듈 구축

**작업 내용**:

**2주차: 기본 네트워크/웹 정보 수집**
1. Nmap 통합 강화 (서비스 버전 탐지, OS 핑거프린팅)
2. 배너 그래빙 모듈 개발 (HTTP, FTP, SSH, SMTP 등)
3. 웹 기술 스택 분석 모듈 개발 (Wappalyzer 연동)
4. 디렉토리/파일 브루트포싱 모듈 개발
5. CPE 변환 모듈 개발

**3주차: 자산 경계 확장**
6. 서브도메인 발견 모듈 (DNS, CT 로그, 브루트포싱)
7. WHOIS/ASN 분석 모듈
8. 클라우드 인프라 발견 모듈 (S3, Azure, GCP)
9. Reverse DNS 분석 모듈

**4주차: 공급망 및 고급 정보 수집**
10. 의존성 파일 분석 모듈 (package.json, requirements.txt 등)
11. GitHub/GitLab 저장소 스캔 모듈 (공개 저장소만)
12. 설정 파일 노출 탐지 모듈 (.env, config 파일)
13. SSL/TLS 상세 분석 모듈

**산출물**:
- 포괄적인 정보 수집 모듈
- CPE 변환 엔진
- 수집 데이터 구조화
- 공급망 정보 수집 시스템

### Phase 3: CVE 매칭 엔진 개발 (2주)

**목표**: 수집된 정보와 CVE를 정확히 매칭하는 엔진 구축

**작업 내용**:
1. CPE 기반 매칭 로직 개발
2. 버전 범위 필터링 로직 개발
3. False Positive 제거 로직 개발
4. 카테고리별 필터링 기능
5. 우선순위 정렬 알고리즘

**산출물**:
- CVE 매칭 엔진
- 필터링 시스템
- 우선순위 정렬 시스템

### Phase 4: 공격 시나리오 생성 (2주)

**목표**: 발견된 취약점을 바탕으로 공격 시나리오 생성

**작업 내용**:
1. 공격 체인 설계 로직 개발
2. LLM 프롬프트 최적화
3. 단계별 가이드 생성
4. 보고서 템플릿 개발

**산출물**:
- 공격 시나리오 생성 모듈
- 보고서 생성 시스템

### Phase 5: 대시보드 및 시각화 (1주)

**목표**: 사용자 친화적인 대시보드 구축

**작업 내용**:
1. 결과 시각화 (카테고리별 표시)
2. 공격 경로 다이어그램
3. 상호작용 기능 추가

**산출물**:
- 웹 대시보드
- 시각화 컴포넌트

---

## 🎯 기대 효과

### 정량적 효과

| 항목 | 현재 | 목표 | 개선율 |
|------|------|------|--------|
| CVE 커버리지 | 수동 검색 | 30만 개 전체 | **무한대** |
| 정보 수집 범위 | 포트/서비스만 | 포트/서비스/웹/공급망/자산경계 전체 | **500%** |
| 정보 수집 시간 | 수동 (시간 단위) | 자동 (분 단위) | **90% 감소** |
| CVE 매칭 정확도 | 60% | 95% | **58% 향상** |
| 공급망 취약점 발견 | 없음 | 의존성 기반 자동 탐지 | **신규** |
| False Positive | 높음 | 낮음 | **80% 감소** |
| 보고서 생성 시간 | 수동 (일 단위) | 자동 (분 단위) | **95% 감소** |

### 정성적 효과

1. **업무 효율성 향상**
   - 수동 작업 시간 대폭 감소
   - 일관된 보고서 품질

2. **정확도 향상**
   - CPE 기반 정확한 매칭
   - 버전 필터링으로 오탐 감소

3. **확장성**
   - 새로운 CVE 자동 반영
   - 카테고리별 확장 용이

4. **교육적 가치**
   - 초보자도 쉽게 이해할 수 있는 시나리오
   - 학습 자료로 활용 가능

---

## ⚠️ 제약사항 및 고려사항

### 기술적 제약사항

1. **NVD API Rate Limiting**
   - API 키 필요 (무료: 5 requests/30초)
   - 대량 데이터 수집 시 시간 소요
   - **해결책**: 캐싱, 배치 처리, 로컬 데이터베이스 구축

2. **정보 수집의 한계**
   - 방화벽으로 인한 포트 스캔 제한
   - WAF로 인한 정보 수집 차단
   - **해결책**: 우회 기법, 다양한 수집 방법 병행

3. **CVE 매칭 정확도**
   - 버전 정보 부정확 시 오매칭
   - CPE 매핑 오류 가능성
   - **해결책**: 다중 검증, False Positive 필터링

### 법적/윤리적 고려사항

1. **권한 있는 테스트만 수행**
   - 명시적 허가 없이 스캔 금지
   - 사용자 동의 필수

2. **데이터 보안**
   - 수집된 정보 암호화 저장
   - 개인정보 보호

3. **책임 면제**
   - 시스템은 정보 제공만 수행
   - 실제 공격은 사용자 책임

---

## 📝 결론

본 프로젝트는 **NVD의 전체 CVE 데이터를 활용한 자동화된 취약점 탐지 및 공격 시나리오 생성 플랫폼**입니다.

### 핵심 차별화 포인트

1. **CVE 내용 기반 분류**: CVE ID가 아닌 내용 분석으로 현업 기준 분류
2. **전체 CVE 커버리지**: 30만 개 이상의 CVE 데이터베이스 활용
3. **정확한 매칭**: CPE 기반 매칭 + 버전 필터링으로 오탐 최소화
4. **포괄적인 정보 수집**: 실제 화이트해커 수준의 정보 수집 (포트 스캔 + 웹 구조 + 공급망 + 자산 경계)
5. **공급망 취약점 탐지**: 의존성 파일 분석을 통한 라이브러리 취약점 자동 탐지
6. **자동화된 시나리오**: AI 기반 공격 시나리오 자동 생성

### 성공 기준

- ✅ 타겟 URL 입력만으로 전체 취약점 정보 수집
- ✅ 모드별 선택 스캔 기능 구현 (전체/웹/시스템/네트워크 등)
- ✅ 모드별 최적화된 정보 수집 및 CVE 매칭
- ✅ **카테고리별 탐지 파이프라인 구현** (정보 수집 → CVE 매칭 → 탐지 검증)
- ✅ **카테고리별 필수 정보 수집 전략 구현** (각 카테고리별 최적화된 수집)
- ✅ **카테고리별 CVE 매칭 전략 구현** (CPE 변환, 버전 매칭, 필터링)
- ✅ CVE 매칭 정확도 95% 이상
- ✅ 카테고리별 분류 정확도 90% 이상
- ✅ 공격 시나리오 생성 시간 5분 이내
- ✅ 모드별 스캔 시간 최적화 (전체 모드 대비 50% 이상 단축))

이 프로젝트를 통해 **전문가 수준의 침투 테스트를 자동화**하고, **보안 취약점을 사전에 발견**하여 보안을 강화할 수 있습니다.

