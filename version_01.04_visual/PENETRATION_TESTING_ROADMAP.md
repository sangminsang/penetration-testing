# 침투 테스트 자동화 로드맵
## 현재 상태 분석 및 개선 방향

**⚠️ 중요**: 본 시스템은 **실제 공격을 실행하지 않습니다**. 정보를 수집하고 공격 시나리오만 제시하며, 실제 공격은 전문가가 수동으로 수행합니다.

---

## 📊 현재 구현된 기능

### ✅ Part A: 정보 수집 (Information Gathering)
- **Nmap 스캔**
  - 포트 스캔 (`-sV -Pn`)
  - 서비스/버전 감지
  - OS 핑거프린팅
  - IP 마스킹 (보안)

- **CVE 검색**
  - NVD API v2.0 연동
  - CPE 기반 정확한 매칭
  - 버전 필터링 (패치된 CVE 제외)
  - 하이브리드 검색 (CPE → 키워드 폴백)

- **Exploit 검색**
  - Searchsploit 연동
  - Exploit DB ID 매핑

### ✅ Part B: 공격 시나리오 제시 (Attack Scenario Generation)
- **공격 체인 설계**
  - Initial Access → Privilege Escalation → Data Exfiltration
  - LLM 기반 시나리오 생성
  - Loot/Proof 생성 (시뮬레이션)

---

## 📋 Part A: 정보 수집 (Information Gathering)

**목표**: 대상에 대한 모든 정보를 수집하여 공격 시나리오 생성에 필요한 데이터 확보

### 1. 자산 경계 확장 (Domain & Infrastructure Recon)

**목표**: 대상 URL 하나로부터 연결된 모든 서버와 숨겨진 인프라를 발견하여 공격 표면을 확대

#### 1.1 서브도메인 열거 (Subdomain Enumeration)
- [ ] **DNS 레코드 조회**
  - A, AAAA, CNAME, MX, TXT, NS 레코드
  - 도구: `dig`, `nslookup`, `dnsrecon`, `dnsenum`

- [ ] **Certificate Transparency (CT) 로그 분석**
  - `crt.sh` API 연동
  - Let's Encrypt 인증서 기반 서브도메인 발견
  - 도구: `ctfr`, `crt.sh` API 직접 호출

- [ ] **사전 기반 브루트포싱**
  - 도구: `gobuster`, `subbrute`, `dnsrecon`
  - 워드리스트: `SecLists/Discovery/DNS/`
  - 가치: dev-api.target.com, jenkins.target.com, staging.target.com 등 보안이 취약한 서브도메인 발견

- [ ] **검색 엔진 기반 발견**
  - Google dorking: `site:*.target.com`
  - Shodan: `hostname:target.com`
  - Censys: 서브도메인 검색

- [ ] **통합 도구**
  - `subfinder`: 여러 소스 통합
  - `amass`: 패시브 + 액티브 스캔
  - `sublist3r`: 멀티 소스 열거

#### 1.2 WAF/CDN 탐지 및 우회 전략
- [ ] **WAF 탐지**
  - 도구: `wafw00f`, `nmap http-waf-detect`
  - HTTP 응답 헤더 패턴 분석 (X-Powered-By, Server, etc.)
  - 응답 지연 시간 분석 (차단 시 지연 발생)
  - 가치: 자동화 코드가 차단당하지 않도록 우회 전략 수립, 공격 속도 조절

- [ ] **CDN 탐지**
  - Cloudflare, AWS CloudFront, Akamai 등 식별
  - 실제 IP 주소 발견 (Origin IP)
  - 도구: `cloudflare-origin-ip`, `sublist3r --bruteforce`
  - 가치: CDN 뒤에 숨겨진 실제 서버 발견

- [ ] **우회 기법 정보 수집**
  - User-Agent 로테이션 전략
  - IP 로테이션 (프록시 풀) 정보
  - Rate Limiting 우회 방법

#### 1.3 IP 및 ASN 정보 분석
- [ ] **WHOIS 조회**
  - 도메인 등록 정보
  - IP 주소 소유권 정보
  - 네임서버 정보
  - 이메일 주소 수집
  - 도구: `whois`, `whois` API

- [ ] **ASN (Autonomous System Number) 분석**
  - IP 주소의 ASN 조회
  - 같은 ASN 내 다른 IP 범위 발견
  - 도구: `whois`, `bgp.he.net`, `ipapi.co`
  - 가치: 클라우드 인프라(AWS/GCP/Azure) 식별, 같은 네트워크 내 다른 자산 발견

- [ ] **Reverse DNS (PTR) 분석**
  - IP → 도메인 역매핑
  - 숨겨진 호스트명 발견
  - 도구: `dig -x`, `nmap -R`
  - 가치: 직접 노출되지 않은 서버 발견

- [ ] **지리적 위치 정보**
  - IP 기반 위치 추정
  - 데이터센터 위치 확인
  - 도구: `maxmind GeoIP`, `ipapi.co`

#### 1.4 클라우드 인프라 식별
- [ ] **클라우드 제공자 식별**
  - AWS: IP 범위 확인, S3 버킷 발견
  - GCP: Google Cloud IP 범위
  - Azure: Microsoft Azure IP 범위
  - 도구: `cloud_enum`, `s3scanner`, `gcp-scanner`

- [ ] **클라우드 자산 발견**
  - S3 버킷 열람 가능 여부 (읽기 전용 확인)
  - Azure Blob Storage
  - Google Cloud Storage
  - 가치: Public 버킷에서 민감 정보 노출 가능성

---

### 2. 패시브 정보 수집 (OSINT)

#### 2.1 소셜 미디어/깃허브 정보 수집
- [ ] **GitHub dorking**
  - API 키, 비밀번호, 설정 파일 노출 검색
  - `.env` 파일, `config.json` 등
  - 도구: GitHub 검색 API, `gitrob`, `truffleHog`
  - 가치: 소스코드에서 하드코딩된 자격증명 발견

- [ ] **GitLab, Bitbucket 스캔**
  - Private 저장소 정보 유출 가능성
  - 도구: `gitrob`, `truffleHog`

- [ ] **기술 스택 정보**
  - Stack Overflow, Reddit 등 기술 스택 정보
  - 개발자 포럼에서 인프라 정보

#### 2.2 이메일 수집 및 검증
- [ ] **이메일 수집**
  - Hunter.io, EmailHippo API
  - 이메일 형식 패턴 분석
  - 가치: 소셜 엔지니어링 타겟, 계정 발견

- [ ] **이메일 기반 계정 발견**
  - 다양한 서비스에서 동일 이메일 사용 여부
  - 도구: `hunter.io`, `emailrep.io`

---

### 3. 액티브 정보 수집

#### 3.1 웹 기술 스택 분석
- [ ] **기술 스택 식별**
  - 도구: `Wappalyzer`, `BuiltWith` API
  - HTTP 헤더 분석 (Server, X-Powered-By, etc.)
  - 쿠키 분석 (세션 관리 방식)
  - JavaScript 파일 분석 (프레임워크, 라이브러리)
  - 가치: 알려진 취약점이 있는 프레임워크/라이브러리 식별

#### 3.2 디렉토리/파일 브루트포싱
- [ ] **디렉토리 발견**
  - 도구: `gobuster`, `dirb`, `dirsearch`, `ffuf`
  - 워드리스트: `SecLists`, `dirbuster`
  - 가치: 숨겨진 관리 페이지, API 엔드포인트 발견

- [ ] **백업 파일 발견**
  - `.bak`, `.old`, `.swp`, `.git` 등
  - 가치: 소스코드 유출, 설정 파일 노출

- [ ] **설정 파일 노출**
  - `.env`, `config.php`, `web.config` 등
  - 가치: 데이터베이스 자격증명, API 키 노출

#### 3.3 네트워크 분석
- [ ] **네트워크 토폴로지 매핑**
  - Traceroute (네트워크 경로)
  - 네트워크 세그먼트 분석
  - 방화벽 규칙 추론
  - 도구: `traceroute`, `mtr`

- [ ] **스니핑 및 패킷 분석** (옵션)
  - 도구: `tcpdump`, `Wireshark`
  - 네트워크 트래픽 분석 (평문 통신 감지)
  - 가치: 평문 통신으로 자격증명 노출 가능성

---

### 4. 취약점 스캔 (Vulnerability Scanning)

#### 4.1 웹 애플리케이션 취약점
- [ ] **OWASP Top 10 자동 스캔**
  - 도구: `OWASP ZAP`, `Nikto`, `Nuclei`
  - SQL Injection
  - XSS (Cross-Site Scripting)
  - CSRF (Cross-Site Request Forgery)
  - XXE (XML External Entity)
  - SSRF (Server-Side Request Forgery)
  - 파일 업로드 취약점
  - 인증/인가 우회
  - 가치: 실제 공격 가능한 취약점 발견

- [ ] **API 보안 테스트**
  - REST API 엔드포인트 발견
  - GraphQL 취약점
  - API 인증 우회 가능성
  - Rate Limiting 우회 가능성
  - 도구: `Postman`, `Insomnia`, `graphw00f`
  - 가치: API 기반 공격 경로 발견

- [ ] **웹 서버 취약점**
  - Apache/Nginx 설정 오류
  - 디렉토리 리스팅
  - HTTP 메서드 허용 (PUT, DELETE, etc.)
  - 도구: `nikto`, `nmap http-enum`

#### 4.2 네트워크 서비스 취약점
- [ ] **SSL/TLS 취약점**
  - 도구: `sslscan`, `testssl.sh`, `sslyze`
  - 약한 암호화 알고리즘
  - 만료된 인증서
  - Heartbleed, POODLE 등 알려진 취약점
  - 가치: 중간자 공격(MITM) 가능성

- [ ] **SMB/Samba 취약점**
  - 도구: `smbmap`, `enum4linux`, `smbclient`
  - 익명 접근 가능 여부
  - SMB 버전 확인
  - EternalBlue (MS17-010) 등 알려진 취약점
  - 가치: 네트워크 공유 접근, 권한 상승 가능성

- [ ] **SSH 취약점**
  - 약한 키 교환 알고리즘
  - 비밀번호 인증 허용 여부
  - 도구: `ssh-audit`
  - 가치: SSH 브루트포싱 가능성

- [ ] **FTP 취약점**
  - 익명 접근
  - 약한 인증
  - 도구: `nmap ftp-* scripts`
  - 가치: 파일 업로드/다운로드 가능성

- [ ] **데이터베이스 취약점**
  - MySQL/PostgreSQL 익명 접근
  - MongoDB 인증 없음
  - Redis 인증 없음
  - 도구: `nmap mysql-*`, `mongodb-unauth-checker`
  - 가치: 데이터베이스 직접 접근 가능성

- [ ] **메일 서버 취약점**
  - Open Relay
  - SPF/DKIM/DMARC 설정 오류
  - 도구: `nmap smtp-*`
  - 가치: 스팸 발송, 이메일 스푸핑 가능성

#### 4.3 클라우드/컨테이너 취약점
- [ ] **Docker 취약점**
  - Docker API 노출
  - 컨테이너 이미지 취약점 스캔
  - 도구: `trivy`, `clair`, `docker-bench-security`
  - 가치: 컨테이너 탈출 가능성

- [ ] **Kubernetes 취약점**
  - API 서버 노출
  - RBAC 설정 오류
  - 도구: `kubectl`, `kube-hunter`
  - 가치: 클러스터 접근 가능성

- [ ] **클라우드 설정 오류**
  - IAM 권한 과다 부여
  - Public 버킷/컨테이너
  - 도구: `prowler`, `scout-suite`, `cloudsplaining`
  - 가치: 클라우드 리소스 무단 접근 가능성

---

### 5. 취약점 정보 수집 (Exploit Intelligence)

**⚠️ 주의**: 실제 Exploit을 실행하지 않고, 정보만 수집합니다.

#### 5.1 Exploit 정보 수집
- [ ] **Exploit DB 검색**
  - Searchsploit 연동
  - CVE별 Exploit ID 매핑
  - 가치: 공격 시나리오에 실제 사용 가능한 Exploit 정보 제공

- [ ] **PoC 스크립트 정보 수집**
  - GitHub PoC 정보 수집 (실행하지 않음)
  - Exploit-DB 스크립트 정보
  - 가치: 공격 방법론 제시

- [ ] **Metasploit 모듈 정보**
  - 사용 가능한 모듈 목록
  - 모듈별 요구사항
  - 가치: 공격 시나리오에 Metasploit 사용 방법 제시

#### 5.2 자격증명 테스트 정보
- [ ] **기본 자격증명 정보 수집**
  - Default credentials DB
  - 도구: `default-http-login-hunter`
  - 가치: 시도할 기본 자격증명 목록 제시

- [ ] **브루트포싱 전략 수집**
  - 워드리스트 정보: `rockyou.txt`, 커스텀 리스트
  - 도구 정보: `hydra`, `medusa`, `patator`
  - 가치: 브루트포싱 시나리오 제시

- [ ] **세션 관리 분석**
  - 쿠키 분석 및 재사용 가능성
  - JWT 토큰 분석 및 조작 가능성
  - 가치: 인증 우회 시나리오 제시

---

## 📋 Part B: 공격 시나리오 제시 (Attack Scenario Generation)

**목표**: 수집된 정보를 바탕으로 실제 공격 가능한 시나리오를 생성하여 전문가가 수동으로 공격을 수행할 수 있도록 가이드 제공

**⚠️ 중요**: 아래 시나리오는 **제시만 하며 실제로 실행하지 않습니다**. 모든 공격은 전문가가 수동으로 수행합니다.

---

### 1. 공격 체인 설계 (Attack Chain Design)

#### 1.1 Initial Access (초기 진입) 시나리오
- [ ] **CVE 기반 RCE 시나리오**
  - 발견된 CVE와 Exploit 정보 결합
  - 단계별 공격 명령어 제시
  - 예상 결과 설명
  - 가치: 원격 코드 실행 경로 제시

- [ ] **웹 취약점 기반 진입 시나리오**
  - SQL Injection → Command Injection 체인
  - 파일 업로드 → Webshell 체인
  - SSRF → 내부 네트워크 접근 체인
  - 가치: 웹 애플리케이션을 통한 진입 경로 제시

- [ ] **인증 우회 시나리오**
  - 기본 자격증명 시도 목록
  - 세션 하이재킹 방법
  - JWT 토큰 조작 방법
  - 가치: 인증을 우회한 진입 경로 제시

#### 1.2 Privilege Escalation (권한 상승) 시나리오
- [ ] **Linux 권한 상승 시나리오**
  - SUID/SGID 바이너리 악용 방법
  - 커널 취약점 악용 방법
  - Cron 작업 취약점 악용 방법
  - 도구: `linpeas`, `linux-exploit-suggester` 사용 가이드
  - 가치: 일반 사용자 → root 권한 상승 경로 제시

- [ ] **Windows 권한 상승 시나리오**
  - UAC 우회 방법
  - 서비스 권한 오류 악용
  - 도구: `winpeas`, `windows-exploit-suggester` 사용 가이드
  - 가치: 일반 사용자 → Administrator 권한 상승 경로 제시

#### 1.3 Lateral Movement (측면 이동) 시나리오
- [ ] **네트워크 스캔 시나리오**
  - 내부 네트워크 호스트 발견 방법
  - 내부 서비스 스캔 방법
  - 가치: 한 호스트에서 다른 호스트로 이동 경로 제시

- [ ] **자격증명 재사용 시나리오**
  - Windows: `mimikatz`, `lsassy` 사용 방법
  - Linux: `/etc/shadow` 덤프 방법
  - 브라우저 비밀번호 추출 방법
  - 가치: 획득한 자격증명으로 다른 시스템 접근 경로 제시

- [ ] **Pass-the-Hash/Ticket 시나리오**
  - Kerberos 티켓 재사용 방법
  - NTLM 해시 재사용 방법
  - 가치: 인증 없이 다른 시스템 접근 경로 제시

#### 1.4 Data Exfiltration (데이터 탈취) 시나리오
- [ ] **민감 정보 수집 시나리오**
  - 환경 변수 (.env 파일) 수집 방법
  - 설정 파일 수집 방법
  - 로그 파일에서 자격증명 추출 방법
  - 데이터베이스 덤프 방법
  - 가치: 목표 데이터 수집 경로 제시

- [ ] **데이터 전송 시나리오**
  - DNS 터널링 방법
  - HTTP/HTTPS 터널링 방법
  - ICMP 터널링 방법
  - 가치: 수집한 데이터를 외부로 전송하는 경로 제시

---

### 2. 상세 공격 시나리오 생성

#### 2.1 단계별 공격 가이드
- [ ] **Step-by-Step 공격 명령어**
  - 각 단계별 실행할 명령어 제시
  - 예상 출력 및 결과 설명
  - 실패 시 대안 방법 제시
  - 가치: 전문가가 따라할 수 있는 상세 가이드

#### 2.2 공격 도구 사용 가이드
- [ ] **Metasploit 사용 시나리오**
  - 모듈 선택 가이드
  - Payload 생성 방법
  - 실행 순서
  - 가치: Metasploit을 활용한 공격 방법 제시

- [ ] **PoC 스크립트 실행 가이드**
  - GitHub PoC 다운로드 및 실행 방법
  - Exploit-DB 스크립트 실행 방법
  - 주의사항 및 안전 조치
  - 가치: 커스텀 Exploit 실행 방법 제시

- [ ] **웹 공격 도구 사용 가이드**
  - `sqlmap` 사용 시나리오
  - `burp suite` 사용 시나리오
  - 가치: 웹 취약점 악용 방법 제시

#### 2.3 우회 전략 제시
- [ ] **WAF 우회 시나리오**
  - 탐지된 WAF에 따른 우회 방법
  - 인코딩 기법
  - 요청 분할 기법
  - 가치: WAF를 우회한 공격 방법 제시

- [ ] **Rate Limiting 우회 시나리오**
  - 요청 간격 조절 방법
  - IP 로테이션 방법
  - 가치: Rate Limiting을 우회한 공격 방법 제시

---

### 3. 보고서 생성 (Reporting)

#### 3.1 상세 취약점 보고서
- [ ] **취약점 상세 정보**
  - CVSS 점수 및 벡터
  - 영향도 분석
  - 재현 단계 (Step-by-step)
  - PoC 코드/스크린샷 (시뮬레이션)
  - 가치: 개발팀이 취약점을 이해하고 패치할 수 있도록 상세 정보 제공

- [ ] **위험도 평가**
  - 비즈니스 영향도
  - 우선순위 정렬
  - 패치 권고사항
  - 가치: 우선순위에 따른 대응 계획 수립

#### 3.2 시각화
- [ ] **공격 경로 다이어그램**
  - 네트워크 토폴로지
  - 공격 체인 플로우차트
  - 도구: `D3.js`, `Cytoscape.js`
  - 가치: 공격 경로를 시각적으로 이해

- [ ] **타임라인**
  - 공격 단계별 시간 기록
  - 이벤트 로그
  - 가치: 공격 순서 및 시간대 파악

#### 3.3 대응 방안
- [ ] **패치 권고**
  - 업데이트 버전 정보
  - 임시 완화책 (Workaround)
  - 가치: 즉시 적용 가능한 보안 조치

- [ ] **방어 전략**
  - WAF 규칙 제안
  - 네트워크 세그먼테이션
  - 모니터링 권고
  - 가치: 장기적인 보안 강화 방안

---

## 🎯 우선순위별 구현 로드맵

### Phase 1: 정보 수집 강화 (High Priority)
1. **자산 경계 확장** (서브도메인 열거, ASN 분석)
2. **WAF/CDN 탐지** (wafw00f, 실제 IP 발견)
3. **웹 기술 스택 분석** (Wappalyzer 연동)
4. **디렉토리 브루트포싱** (gobuster/dirsearch)
5. **SSL/TLS 취약점 스캔** (testssl.sh)

**예상 효과**: 정보 수집 범위 500% 증가, 공격 표면 확대

### Phase 2: 웹 취약점 스캔 (High Priority)
1. **OWASP ZAP/Nikto 연동**
2. **Nuclei 템플릿 기반 스캔**
3. **API 엔드포인트 발견**
4. **취약점 정보 수집** (실제 공격은 하지 않음)

**예상 효과**: 웹 애플리케이션 취약점 발견률 500% 증가

### Phase 3: 네트워크 서비스 취약점 (Medium Priority)
1. **SSL/TLS 상세 분석**
2. **SMB/SSH/FTP 취약점 스캔**
3. **데이터베이스 인증 확인**
4. **기본 자격증명 정보 수집**

**예상 효과**: 네트워크 레벨 취약점 발견률 200% 증가

### Phase 4: 공격 시나리오 생성 강화 (Medium Priority)
1. **상세 공격 가이드 생성**
2. **도구 사용 시나리오 제시**
3. **우회 전략 시나리오 제시**
4. **시각화된 공격 경로 생성**

**예상 효과**: 공격 시나리오 완성도 400% 증가

### Phase 5: 고급 기능 (Low Priority)
1. **OSINT 자동화** (GitHub dorking, Shodan)
2. **클라우드 취약점 스캔**
3. **컨테이너 보안 스캔**
4. **측면 이동 시나리오 생성**

**예상 효과**: 전체적인 침투 테스트 완성도 향상

---

## 🔧 필요한 도구 통합

### 필수 도구 (Must Have) - 정보 수집
- `subfinder` / `amass` - 서브도메인 발견 (자산 경계 확장)
- `wafw00f` - WAF/CDN 탐지
- `gobuster` / `dirsearch` - 디렉토리 브루트포싱
- `nikto` - 웹 서버 취약점 스캔
- `nuclei` - 빠른 취약점 스캔
- `testssl.sh` - SSL/TLS 분석
- `Wappalyzer` - 기술 스택 분석
- `whois` / `dnsrecon` - IP/ASN/DNS 분석

### 권장 도구 (Should Have) - 정보 수집
- `crt.sh` API - Certificate Transparency 로그
- `cloud_enum` / `s3scanner` - 클라우드 인프라 발견
- `OWASP ZAP` - 웹 애플리케이션 스캔
- `enum4linux` - SMB 열거
- `sslscan` - SSL 분석
- `ffuf` - 웹 퍼저
- `dnsrecon` / `dnsenum` - DNS 상세 분석

### 정보 수집용 도구 (Exploit 정보만 수집, 실행 안 함)
- `searchsploit` - Exploit DB 검색
- `metasploit` - 모듈 정보 수집 (실행 안 함)
- `hydra` - 브루트포싱 전략 정보 (실행 안 함)

### 고급 도구 (Nice to Have)
- `Burp Suite` - 상세 웹 분석
- `shodan` API - 인터넷 스캔
- `trivy` - 컨테이너 취약점 스캔
- `prowler` - AWS 보안 스캔

---

## 📈 기대 효과

### 현재 vs 개선 후 비교

| 항목 | 현재 | 개선 후 | 증가율 |
|------|------|---------|--------|
| 정보 수집 범위 | 포트/서비스만 | 포트/서비스/웹/OSINT/자산경계 | **500%** |
| 자산 경계 확장 | 단일 URL만 | 서브도메인/클라우드/ASN 전체 | **1000%** |
| 취약점 발견 수 | CVE만 | CVE + 웹 + 네트워크 | **800%** |
| 공격 시나리오 완성도 | 기본 | 상세 + 시각화 + 단계별 가이드 | **400%** |
| 보고서 완성도 | 기본 | 상세 + 시각화 | **300%** |

### 비즈니스 가치
- **실제 공격 가능한 취약점만 보고** → 우선순위 명확화
- **자동화된 정보 수집** → 시간 절약 80%
- **상세한 공격 시나리오** → 전문가가 빠르게 공격 수행 가능
- **시각화된 공격 경로** → 경영진 이해도 향상

---

## 🚀 구현 전략

### 1. 모듈화 설계
- 각 도구를 독립적인 모듈로 구현
- 플러그인 방식으로 확장 가능
- 실패 시 다음 도구로 자동 폴백

### 2. 병렬 처리
- 여러 스캔을 동시에 실행
- 결과를 실시간으로 통합
- 진행 상황 시각화

### 3. 안전 모드 (정보 수집만)
- **실제 Exploit 실행 금지**
- 정보 수집 및 시나리오 제시만 수행
- 모든 공격은 전문가가 수동으로 수행

### 4. 결과 통합
- 모든 도구 결과를 통합 데이터베이스에 저장
- 중복 제거 및 우선순위 정렬
- AI 기반 위험도 평가 및 시나리오 생성

---

## 📝 결론

현재 프로젝트는 **기본적인 정찰과 CVE 매핑**만 구현되어 있습니다. 
실제 화이트해커/레드팀이 수행하는 **전체 침투 테스트 프로세스**를 지원하려면:

### Part A: 정보 수집 (자동화)
1. **자산 경계 확장** (서브도메인, ASN, 클라우드 인프라 발견)
2. **WAF/CDN 탐지 및 우회 전략** (실제 IP 발견, 차단 우회 방법)
3. **정찰 단계 강화** (OSINT, 디렉토리, 기술 스택)
4. **웹 취약점 스캔** (OWASP Top 10)
5. **네트워크 서비스 취약점** (SSL, SMB, SSH 등)
6. **취약점 정보 수집** (Exploit 정보, PoC 정보)

### Part B: 공격 시나리오 제시 (자동화)
1. **공격 체인 설계** (Initial Access → Privilege Escalation → Data Exfiltration)
2. **상세 공격 가이드 생성** (Step-by-step 명령어)
3. **도구 사용 시나리오 제시** (Metasploit, PoC 스크립트 등)
4. **우회 전략 제시** (WAF, Rate Limiting 등)
5. **상세 보고서** (시각화, 재현 단계, 대응 방안)

**핵심 원칙**: 
- ✅ **정보 수집은 자동화**: 모든 정보를 자동으로 수집
- ✅ **공격 시나리오는 제시만**: 실제 공격은 실행하지 않고 시나리오만 생성
- ✅ **실제 공격은 수동**: 모든 공격은 전문가가 수동으로 수행

이 모든 기능을 통합하면 **완전 자동화된 정보 수집 및 공격 시나리오 생성 플랫폼**이 됩니다.
