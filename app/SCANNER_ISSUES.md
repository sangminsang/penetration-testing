# 스캐너 모듈 문제점 및 개선 사항

## ✅ 최신 개선사항 (2025년 업데이트)

### 완료된 주요 개선사항

#### 1. 취약점 검증 정확도 개선 ✅
- **다단계 검증 체계**: Time-based SQLi 통계적 유의성 확인 (여러 샘플 측정)
- **컨텍스트 인식 탐지**: HTTP 상태 코드, 응답 시간, 콘텐츠 길이 변화 종합 분석
- **신뢰도 스코어링**: 각 탐지 결과에 0~100점 신뢰도 점수 부여

#### 2. 회피 기술 및 스텔스 모드 ✅
- **페이로드 인코딩 다양화**: URL, 이중 URL, Unicode, Base64, Hex, HTML Entity 인코딩
- **Rate Limiting 대응**: 랜덤 딜레이, User-Agent 로테이션
- **WAF Bypass**: ModSecurity, Cloudflare, AWS WAF, Imperva별 우회 페이로드

#### 3. 익스플로잇 체인 구축 ✅
- **Attack Path Analysis**: 정보 노출 → 권한 상승 → RCE 경로 자동 매핑
- **Post-Exploitation 시뮬레이션**: 권한 획득 후 추가 정찰 및 피벗팅 시나리오
- **CVSS 기반 우선순위**: CVSS 3.1 스코어로 정량화

#### 4. 최신 공격 벡터 ✅
- **SSTI**: Jinja2, Freemarker, Velocity, Smarty, Twig 템플릿 엔진 취약점
- **GraphQL**: Introspection, Batching Attack, Nested Query DoS
- **JWT**: 알고리즘 혼동, None 알고리즘, 약한 시크릿 키 브루트포스
- **Prototype Pollution**: Node.js 환경 대상 프로토타입 오염 공격
- **HTTP Request Smuggling**: CL.TE, TE.CL 요청 밀수 기법

#### 5. 인증 및 세션 관리 테스트 ✅
- **Broken Authentication**: 패스워드 정책, 세션 타임아웃, 다중 로그인 테스트
- **OAuth/OIDC**: 리다이렉션 조작, state 파라미터 검증, 토큰 탈취 시나리오
- **API 키 관리**: 하드코딩된 시크릿 탐지, 토큰 만료 검증

#### 6. 데이터베이스 공격 심화 ✅
- **NoSQL Injection**: MongoDB의 $where, $ne 연산자 인젝션
- **ORM Injection**: Sequelize, TypeORM, Hibernate 레벨 인젝션
- **Blind SQLi 자동화**: 바이너리 서치 기반 데이터 추출
- **Out-of-Band**: DNS Exfiltration, HTTP 콜백 기반 Blind SQLi

#### 7. 클라우드 네이티브 보안 ✅
- **IAM 권한 검증**: 과도한 권한 부여, AssumeRole 체인 분석
- **컨테이너 탈출**: Privileged 컨테이너, hostPath 마운트, Docker socket 노출
- **Serverless 취약점**: Lambda 인젝션, 이벤트 인젝션, 콜드 스타트 공격
- **SSRF to Metadata**: IMDSv1/v2 차이 활용, 토큰 탈취 시도

#### 8. 리포팅 및 재현성 ✅
- **PoC 자동 생성**: curl/Python 재현 스크립트 자동 생성
- **증거 수집**: HTTP 요청/응답 자동 캡처, 타임스탬프 기록
- **CVSS 계산**: 각 취약점의 CVSS 벡터 자동 계산
- **Executive Summary**: 경영진용 요약 리포트 자동 생성

#### 9. 성능 및 안정성 ✅
- **연결 풀링**: requests.Session 재사용으로 TCP 핸드셰이크 오버헤드 감소
- **타임아웃 계층화**: Connect timeout과 Read timeout 분리
- **에러 복구**: 네트워크 오류 시 자동 재시도 메커니즘
- **리소스 제한**: 메모리 사용량 모니터링, 동시 스레드 수 제한

#### 10. Compliance 및 표준 준수 ✅
- **OWASP Top 10 매핑**: 각 탐지 항목을 OWASP Top 10 카테고리로 분류
- **CWE/CVE 참조**: 발견된 취약점과 CWE ID 자동 매핑
- **PTES/OSSTMM 준수**: 정찰-스캔-익스플로잇-보고 단계 명확화

---

# 스캐너 모듈 문제점 및 개선 사항

## 현재 구현된 기능 상세

### 1. Network Scanner (network.py) - 현재 기능

#### 포트 스캔 및 서비스 식별
- ✅ **Nmap 포트 스캔**: 전체 포트 스캔 (`-p-` 옵션 지원)
- ✅ **서비스 버전 검색**: `-sV` 옵션으로 서비스 제품명 및 버전 추출
- ✅ **호스트 정보 수집**: 
  - IP 주소 (마스킹 옵션 지원)
  - 호스트명
  - 호스트 상태 (up/down)
  - OS 매칭 정보 (nmap osmatch 결과)
- ✅ **포트 상세 정보 수집**:
  - 포트 번호
  - 프로토콜 (tcp/udp)
  - 서비스명 (nmap이 식별한 서비스)
  - 제품명 (product)
  - 버전 (version)
  - 전체 버전 문자열 (product + version)

#### 프로토콜별 상세 분석
- ✅ **SSL/TLS 분석** (443, 8443 포트):
  - TLS 버전 확인
  - Cipher suite 정보
  - 인증서 정보 (subject, issuer, 만료일)
- ✅ **SSH 분석** (22 포트):
  - SSH 배너 그랩핑
  - SSH 버전 문자열 추출
- ⚠️ **SMB 분석** (445 포트):
  - 함수는 있지만 실제 구현 없음 (빈 껍데기)

#### 기타 기능
- ✅ **IP 마스킹**: 보안을 위한 IP 주소 마스킹 (마지막 옥텟을 x로 변경)
- ✅ **에러 처리**: 각 분석 함수에 try-except 처리

---

### 2. Web Scanner (web.py) - 현재 기능

#### HTTP 헤더 분석
- ✅ **웹 서버 식별**: `Server` 헤더에서 웹 서버 정보 추출
- ✅ **프레임워크 식별**: `X-Powered-By` 헤더에서 프레임워크 정보 추출
- ✅ **프로토콜 자동 시도**: HTTP와 HTTPS 모두 자동 시도
- ✅ **프로그래밍 언어 탐지**:
  - PHP 버전 추출 (X-Powered-By에서)
  - ASP.NET 버전 추출 (X-AspNet-Version 헤더)
- ✅ **Python 프레임워크 탐지**: 
  - Django 버전 추출 (응답 본문에서)
- ✅ **Node.js/Express 탐지**:
  - 헤더에서 Express 힌트 확인
  - 응답 본문에서 Node.js/Express 키워드 확인
  - Node.js 버전 추출 시도

#### JavaScript 라이브러리 탐지
- ✅ **jQuery**: 버전 추출
- ✅ **React**: 버전 추출
- ✅ **Vue**: 버전 추출
- ✅ **Angular**: 
  - `ng-version` 속성에서 버전 추출
  - 정규식으로 버전 추출
  - 버전 없이도 Angular 사용 감지
- ✅ **Node.js 힌트**: HTML에서 Node.js 버전 추출

#### 노출 파일 탐지
- ✅ **설정 파일**: `.env`, `.env.local`, `.env.production`, `config.php`, `web.config`, `application.properties`, `settings.py`, `config.json`
- ✅ **백업 파일**: `.git`, `.svn`, `.hg`, `backup.sql`, `dump.sql`
- ✅ **소스코드 파일**: `package.json`, `requirements.txt`, `pom.xml`, `Gemfile`, `composer.json`, `package-lock.json`
- ✅ **파일 크기 확인**: 발견된 파일의 크기 정보 수집

#### package.json 파싱
- ✅ **Node.js 버전**: `engines.node`에서 Node.js 버전 추출
- ✅ **의존성 분석**: 
  - Express 버전 추출
  - Angular 버전 추출 (@angular/core 또는 angular)
  - Sequelize, Mongoose, TypeORM 등 ORM 라이브러리 추출
- ✅ **의존성 소스 구분**: dependencies와 devDependencies 모두 확인

#### URL 처리
- ✅ **포트 번호 지원**: `172.17.0.1:3000` 형식 URL 자동 처리
- ✅ **프로토콜 자동 선택**: 포트가 있으면 http://, 없으면 https:// 사용

---

### 3. OS Scanner (os.py) - 현재 기능

#### OS 핑거프린팅
- ✅ **Nmap OS 매칭**: nmap의 osmatch 결과 활용
- ✅ **OS 정보 추출**:
  - OS 타입 (Linux, Windows 등)
  - OS 버전 (전체 이름)
  - OS 상세 정보 (모든 매칭 결과)
  - 정확도 (accuracy) 점수
- ✅ **최적 매칭 선택**: 정확도가 가장 높은 OS 정보 선택

#### 시스템 서비스 탐지
- ✅ **SSH 서비스 탐지**:
  - SSH/sshd 서비스 식별
  - OpenSSH 제품명 추출
  - SSH 버전 정보 추출
  - 포트 정보 포함
- ✅ **서비스 정보 종합**: 제품명과 버전을 결합한 전체 정보 생성

#### 기술 스택 변환
- ✅ **OS 기술 스택**: OS 정보를 기술 스택 형식으로 변환
- ✅ **시스템 서비스 기술 스택**: SSH 등 시스템 서비스를 기술 스택으로 변환
- ✅ **출처 정보**: 각 정보의 출처 표시 (OS Fingerprinting, Nmap Scan)

---

### 4. Database Scanner (database.py) - 현재 기능

#### 데이터베이스 프로토콜 분석
- ✅ **MySQL 분석** (3306 포트):
  - MySQL 핸드셰이크 패킷 수신
  - 핸드셰이크에서 버전 정보 추출 (정규식 사용)
- ✅ **PostgreSQL 분석** (5432 포트):
  - PostgreSQL 프로토콜 연결
  - 프로토콜 응답에서 버전 정보 추출
- ✅ **MongoDB 분석** (27017 포트):
  - MongoDB 프로토콜 연결
  - 프로토콜 응답에서 버전 정보 추출

#### Nmap 결과 활용
- ✅ **SQL Server**: 1433 포트에서 Nmap이 감지한 정보 활용
- ✅ **Redis**: 6379 포트에서 Nmap이 감지한 정보 활용
- ✅ **기타 DB**: Nmap에서 이미 식별된 제품명/버전 정보 활용

#### 기술 스택 변환
- ✅ **데이터베이스 기술 스택**: 발견된 DB를 기술 스택 형식으로 변환
- ✅ **포트 정보 포함**: 각 DB의 포트 번호 포함
- ✅ **DB 타입 정보**: mysql, postgresql, mongodb 등 타입 정보 포함

---

### 5. Cloud Scanner (cloud.py) - 현재 기능

#### 클라우드 스토리지 확인
- ✅ **AWS S3 버킷 확인**:
  - 버킷 존재 여부 확인
  - 공개 접근 가능 여부 확인 (200 vs 403 응답)
  - 여러 URL 패턴 시도 (s3.amazonaws.com, 버킷명.s3.amazonaws.com)
- ✅ **Azure Blob Storage 확인**:
  - Blob Storage 존재 여부 확인
  - 공개 접근 가능 여부 확인
  - 컨테이너 이름 지원
- ✅ **Google Cloud Storage 확인**:
  - GCS 버킷 존재 여부 확인
  - 공개 접근 가능 여부 확인

#### 버킷 이름 추측
- ✅ **도메인 기반 패턴 생성**:
  - 기본 도메인명
  - `-backup`, `-dev`, `-staging`, `-prod`, `-test`, `-assets`, `-static` 접미사 추가
- ✅ **패턴 테스트**: 생성된 패턴으로 버킷 존재 여부 확인 (최대 5개)

#### 기술 스택 변환
- ✅ **클라우드 기술 스택**: 발견된 클라우드 자산을 기술 스택으로 변환
- ✅ **공개 여부 정보**: 버킷의 공개/비공개 상태 포함

---

### 6. Container Scanner (container.py) - 현재 기능

#### Docker API 분석
- ✅ **Docker API 확인** (2375, 2376 포트):
  - Docker API 노출 여부 확인
  - `/version` 엔드포인트로 Docker 버전 추출
- ✅ **컨테이너 목록 조회**:
  - `/containers/json` 엔드포인트로 실행 중인 컨테이너 목록 조회
  - 컨테이너 정보 JSON 파싱

#### Kubernetes API 분석
- ✅ **Kubernetes API 확인** (6443, 8080 포트):
  - Kubernetes API 노출 여부 확인
  - `/version` 엔드포인트로 Kubernetes 버전 추출 (gitVersion)

#### 기술 스택 변환
- ✅ **컨테이너 기술 스택**: 발견된 컨테이너 정보를 기술 스택으로 변환
- ✅ **노출 여부 정보**: API가 노출되어 있는지 여부 포함
- ✅ **포트 정보**: 각 서비스의 포트 번호 포함

---

## 통합 및 데이터 흐름

### 스캔 프로세스 (api/routes.py)
1. **네트워크 스캔**: `run_recon()` - Nmap으로 기본 포트/서비스 스캔
2. **웹 정보 수집**: `collect_web_info()` - 웹 애플리케이션 기술 스택 분석
3. **OS 정보 수집**: `collect_os_info()` - OS 핑거프린팅 및 시스템 서비스
4. **네트워크 상세 정보**: `collect_network_info()` - SSL/TLS, SSH 상세 분석
5. **데이터베이스 정보**: `collect_database_info()` - DB 프로토콜 분석
6. **클라우드 정보**: `collect_cloud_info()` - 클라우드 스토리지 확인
7. **컨테이너 정보**: `collect_container_info()` - Docker/Kubernetes API 확인

### 카테고리별 분류
- ✅ **포트 기반 분류**: 
  - 웹 포트: 80, 443, 8080, 8443, 8000, 8888
  - DB 포트: 3306, 5432, 27017, 6379, 1433, 1521
- ✅ **서비스명 기반 분류**: 서비스명과 제품명으로 카테고리 자동 분류
- ✅ **기술 스택 통합**: 모든 수집된 정보를 `web_technologies`, `os_technologies` 등으로 통합

### CVE 매칭 연동
- ✅ **네트워크 서비스 기반**: 포트에서 발견된 제품/버전으로 CVE 검색
- ✅ **웹 기술 스택 기반**: 웹 스캔에서 발견된 기술로 CVE 검색
- ✅ **OS 기술 스택 기반**: OS 스캔에서 발견된 기술로 CVE 검색
- ✅ **데이터베이스 기반**: DB 스캔에서 발견된 DB로 CVE 검색
- ✅ **클라우드 기반**: 클라우드 스캔에서 발견된 기술로 CVE 검색
- ✅ **컨테이너 기반**: 컨테이너 스캔에서 발견된 기술로 CVE 검색

---

## 1. Network Scanner (network.py)

### 🔴 심각한 문제
- **OS 핑거프린팅 미활용**: `-O` 옵션이 없어 OS 정보를 제대로 못 가져옴
- **Nmap 스크립트 미사용**: `--script` 옵션으로 더 정확한 서비스 식별 가능한데 안 씀
- **SMB 분석 빈 껍데기**: 함수는 있지만 실제 구현 없음
- **FTP, Telnet, RDP 등 주요 프로토콜 분석 없음**

### ⚠️ 개선 필요
- **SSL/TLS 상세 분석 부족**: 취약한 cipher suite, 프로토콜 버전 체크 없음
- **SSH 키 교환 알고리즘 분석 없음**: 버전만 가져옴
- **포트 범위 제한**: SSL은 443, 8443만 체크 (다른 HTTPS 포트 무시)
- **타임아웃 처리**: 모든 함수에 5초 고정, 조정 불가

### ✅ 추가 필요 기능
- FTP 배너 그랩핑 및 익명 접근 테스트
- RDP 버전 및 취약점 확인
- SNMP 커뮤니티 스트링 브루트포싱
- DNS 정보 수집 (zone transfer 시도)
- NTP 정보 수집
- LDAP 정보 수집

---

## 2. Web Scanner (web.py)

### 🔴 심각한 문제
- **User-Agent 없음**: 차단될 가능성 높음
- **WAF 탐지 없음**: Cloudflare, AWS WAF 등 탐지 안 함
- **CMS 탐지 없음**: WordPress, Drupal, Joomla 등 탐지 안 함
- **디렉토리 브루트포싱 없음**: 일반적인 경로 탐색 안 함
- **API 엔드포인트 탐지 없음**: REST API, GraphQL 등 탐지 안 함

### ⚠️ 개선 필요
- **보안 헤더 분석 없음**: CSP, HSTS, X-Frame-Options 등 체크 안 함
- **HTTP 메서드 테스트 없음**: OPTIONS, PUT, DELETE 등 테스트 안 함
- **CORS 설정 확인 없음**: CORS misconfiguration 체크 안 함
- **robots.txt, sitemap.xml 분석 없음**
- **JavaScript 소스코드 분석 부족**: minified 코드 분석 안 함
- **서브도메인 발견 없음**: subdomain enumeration 안 함

### ✅ 추가 필요 기능
- **Wappalyzer 같은 기술 스택 탐지 라이브러리 활용**
- **웹 취약점 스캔**: SQL Injection, XSS 테스트 (기본)
- **파일 업로드 취약점 테스트**
- **인증 우회 테스트**: 기본 인증, JWT 등
- **세션 관리 취약점**: 쿠키 설정 분석
- **웹캐시 포이즈닝 테스트**

---

## 3. OS Scanner (os.py)

### 🔴 심각한 문제
- **OS 핑거프린팅 의존**: nmap -O 옵션이 없으면 작동 안 함 (현재 설정에 없음)
- **시스템 서비스 탐지 부족**: SSH만 체크, 다른 서비스 무시
- **커널 버전 정보 없음**: OS 버전만 있고 커널 버전 없음

### ⚠️ 개선 필요
- **시스템 아키텍처 정보 없음**: x86, ARM 등
- **패치 레벨 정보 없음**: 보안 업데이트 상태 확인 안 함
- **서비스 버전 정확도**: nmap 결과만 의존, 추가 검증 없음

### ✅ 추가 필요 기능
- **Nmap OS 스캔 옵션 추가**: `-O` 옵션으로 정확한 OS 탐지
- **시스템 서비스 확장**: FTP, Telnet, RDP 등
- **커널 버전 추출**: Linux 커널 버전 등
- **패키지 매니저 정보**: apt, yum 등으로 설치된 패키지 확인 (가능하면)

---

## 4. Database Scanner (database.py)

### 🔴 심각한 문제
- **인증 우회 테스트 없음**: 익명 접근, 약한 비밀번호 테스트 안 함
- **Redis, Elasticsearch 분석 없음**: 포트만 체크하고 실제 분석 안 함
- **SQL Server 분석 없음**: 1433 포트만 체크
- **데이터베이스 버전 추출 부정확**: 간단한 정규식만 사용

### ⚠️ 개선 필요
- **프로토콜 파싱 부족**: MySQL, PostgreSQL 프로토콜 제대로 파싱 안 함
- **에러 메시지 분석 없음**: SQL 에러로 버전 정보 추출 안 함
- **데이터베이스 설정 확인 없음**: 보안 설정 체크 안 함

### ✅ 추가 필요 기능
- **Redis 정보 수집**: INFO 명령어로 버전, 설정 확인
- **Elasticsearch 정보 수집**: 클러스터 정보, 버전 확인
- **MongoDB 상세 분석**: 인증 없이 접근 가능한지, 버전 확인
- **SQL Server 버전 확인**: TDS 프로토콜 파싱
- **데이터베이스 취약점 스캔**: 기본 설정 취약점 체크

---

## 5. Cloud Scanner (cloud.py)

### 🔴 심각한 문제
- **메타데이터 서비스 확인 없음**: AWS, Azure, GCP 메타데이터 엔드포인트 체크 안 함
- **버킷 이름 추측만 함**: 실제 발견 방법이 제한적
- **클라우드 서비스 식별 없음**: 어떤 클라우드인지 자동 탐지 안 함

### ⚠️ 개선 필요
- **S3 버킷 리스팅**: 버킷 정책, ACL 확인 안 함
- **클라우드 인스턴스 메타데이터**: IAM 역할, 인스턴스 정보 수집 안 함
- **클라우드 특화 취약점**: SSRF를 통한 메타데이터 접근 테스트 안 함

### ✅ 추가 필요 기능
- **AWS 메타데이터 서비스 확인**: 169.254.169.254 체크
- **Azure 메타데이터 확인**: 169.254.169.254 체크
- **GCP 메타데이터 확인**: 169.254.169.254 체크
- **버킷 정책 분석**: S3 버킷 정책, ACL 분석
- **클라우드 서비스 자동 탐지**: HTTP 헤더, DNS 레코드로 클라우드 식별

---

## 6. Container Scanner (container.py)

### 🔴 심각한 문제
- **Docker API 보안 체크 없음**: 인증 없이 접근 가능한지만 체크
- **컨테이너 이미지 분석 없음**: 실행 중인 컨테이너 이미지 정보 안 가져옴
- **Kubernetes 정보 수집 부족**: API 버전만 가져옴

### ⚠️ 개선 필요
- **Docker 소켓 확인 없음**: /var/run/docker.sock 마운트 확인 안 함
- **컨테이너 취약점 스캔 없음**: 실행 중인 컨테이너의 취약점 체크 안 함
- **Kubernetes RBAC 확인 없음**: 권한 설정 확인 안 함

### ✅ 추가 필요 기능
- **Docker API 상세 정보**: 컨테이너 목록, 이미지 목록, 네트워크 정보
- **컨테이너 이미지 분석**: 베이스 이미지, 설치된 패키지 확인
- **Kubernetes 리소스 수집**: Pod, Service, Deployment 정보
- **컨테이너 보안 설정 확인**: privileged 모드, capabilities 등

---

## 공통 문제점

### 🔴 모든 스캐너 공통
1. **에러 처리 부족**: try-except만 있고 구체적인 에러 로깅 없음
2. **타임아웃 설정 고정**: 모든 함수에 5초 고정, 조정 불가
3. **재시도 로직 없음**: 네트워크 오류 시 재시도 안 함
4. **Rate limiting 없음**: API 호출 제한 없어 차단될 수 있음
5. **프록시 지원 없음**: 프록시를 통한 스캔 불가
6. **멀티스레딩 없음**: 순차 실행이라 느림
7. **결과 캐싱 없음**: 같은 타겟 재스캔 시 중복 작업

### ⚠️ 개선 필요
- **설정 파일 분리**: 하드코딩된 값들을 config로 분리
- **로깅 시스템**: print 대신 proper logging
- **진행 상황 표시**: 스캔 진행률 표시
- **결과 검증**: 수집한 정보의 신뢰도 점수

---

## 우선순위별 개선 권장사항

### 🔥 최우선 (즉시 수정 필요)
1. **Web Scanner**: User-Agent 추가, WAF 탐지, CMS 탐지
2. **Network Scanner**: Nmap 스크립트 활용, OS 핑거프린팅 옵션 추가
3. **Database Scanner**: 인증 우회 테스트, Redis/Elasticsearch 분석

### ⚡ 높은 우선순위
4. **Web Scanner**: 디렉토리 브루트포싱, API 엔드포인트 탐지
5. **Network Scanner**: FTP, RDP, SNMP 분석
6. **Cloud Scanner**: 메타데이터 서비스 확인

### 📋 중간 우선순위
7. **Container Scanner**: Docker API 상세 분석
8. **OS Scanner**: 시스템 서비스 확장
9. **공통**: 멀티스레딩, 재시도 로직

### 💡 낮은 우선순위
10. **모든 스캐너**: 결과 캐싱, 프록시 지원

