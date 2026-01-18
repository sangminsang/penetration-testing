# 🏦 VulnBank - 모의해킹 연습용 취약한 웹 애플리케이션

> ⚠️ **경고**: 이 애플리케이션은 **교육 목적으로만** 사용해야 합니다!
> 절대로 실제 서비스 환경에서 사용하지 마세요.

## 📋 개요

VulnBank는 모의해킹(펜테스트) 연습을 위해 의도적으로 취약점이 포함된 가상의 온라인 뱅킹 웹 애플리케이션입니다. OWASP Top 10을 포함한 다양한 웹 취약점을 학습하고 실습할 수 있습니다.

## 🔥 포함된 취약점 목록

### 1. SQL Injection
- **위치**: 로그인, 회원가입, 검색 기능
- **공격 예시**: `' OR '1'='1'--`
- **학습 포인트**: Parameterized Query 사용의 중요성

### 2. XSS (Cross-Site Scripting)
- **Reflected XSS**: 검색 페이지
- **Stored XSS**: 공지사항, 송금 메모
- **공격 예시**: `<script>alert('XSS')</script>`
- **학습 포인트**: 입출력 데이터 이스케이프 처리

### 3. CSRF (Cross-Site Request Forgery)
- **위치**: 송금, 비밀번호 변경
- **학습 포인트**: CSRF 토큰의 필요성

### 4. IDOR (Insecure Direct Object Reference)
- **위치**: 계좌 조회 (`/account/<user_id>`), 메시지 조회
- **공격 예시**: URL의 user_id 값 변경
- **학습 포인트**: 접근 권한 검사의 중요성

### 5. 파일 업로드 취약점
- **위치**: 프로필 사진 업로드
- **공격**: 악성 스크립트(웹쉘) 업로드
- **학습 포인트**: 파일 타입/내용 검증

### 6. 디렉토리 트래버설 (Path Traversal)
- **위치**: 파일 다운로드 기능
- **공격 예시**: `../../../etc/passwd`
- **학습 포인트**: 경로 검증 및 화이트리스트

### 7. 커맨드 인젝션
- **위치**: 서버 상태 확인, DNS 조회
- **공격 예시**: `localhost; cat /etc/passwd`
- **학습 포인트**: 사용자 입력을 시스템 명령에 사용 금지

### 8. 인증/세션 취약점
- **쿠키 기반 인증**: 관리자 페이지
- **예측 가능한 세션**: 약한 시크릿 키
- **학습 포인트**: 안전한 세션 관리

### 9. 정보 노출
- **위치**: 에러 메시지, HTML 주석, 콘솔 로그
- **노출 정보**: 스택 트레이스, DB 정보, 서버 버전
- **학습 포인트**: 에러 처리 및 디버그 모드

### 10. 약한 암호화
- **MD5 해시**: 비밀번호 저장
- **학습 포인트**: bcrypt, Argon2 사용

## 🚀 설치 및 실행

### 요구사항
- Python 3.8 이상
- pip

> 📖 **VMware에서 실행하려면**: [VMWARE_SETUP.md](VMWARE_SETUP.md) 문서를 참조하세요.

### 설치 방법

```bash
# 1. 프로젝트 폴더로 이동
cd vulnerable_webapp

# 2. 가상환경 생성 (선택사항)
python -m venv venv
source venv/bin/activate  # Linux/Mac
# 또는
venv\Scripts\activate  # Windows

# 3. 패키지 설치
pip install -r requirements.txt

# 4. 애플리케이션 실행
python app.py
```

### 접속
- URL: http://localhost:5000
- 또는 http://서버IP:5000

## 👤 테스트 계정

| 아이디 | 비밀번호 | 권한 | 잔액 |
|--------|----------|------|------|
| admin | admin123 | 관리자 | ₩999,999 |
| user1 | password1 | 일반 | ₩50,000 |
| user2 | password2 | 일반 | ₩30,000 |
| testuser | test1234 | 일반 | ₩15,000 |

## 🧪 취약점 테스트 가이드

### SQL Injection 테스트
1. 로그인 페이지로 이동
2. 아이디에 `' OR '1'='1'--` 입력
3. 비밀번호는 아무거나 입력
4. 로그인 성공 확인

### XSS 테스트
1. 검색 페이지로 이동
2. `<script>alert('XSS')</script>` 검색
3. 알림창 표시 확인

### IDOR 테스트
1. 로그인 후 대시보드로 이동
2. 계좌 조회 URL 확인 (`/account/2`)
3. URL의 숫자를 1로 변경 (`/account/1`)
4. 관리자 계좌 정보 노출 확인

### 관리자 페이지 접근 (쿠키 조작)
1. 브라우저 개발자 도구 열기 (F12)
2. Console에서 실행: `document.cookie = "user_role=admin"`
3. `/admin` 페이지 접속
4. 관리자 페이지 접근 성공 확인

### 커맨드 인젝션 테스트
1. 관리자 페이지 → 서버 상태 확인
2. 호스트 입력: `localhost; whoami`
3. 시스템 명령 실행 결과 확인

## 📁 프로젝트 구조

```
vulnerable_webapp/
├── app.py                 # 메인 Flask 애플리케이션
├── requirements.txt       # Python 패키지 목록
├── vulnbank.db           # SQLite 데이터베이스 (자동 생성)
├── README.md             # 이 파일
│
├── templates/            # HTML 템플릿
│   ├── base.html         # 기본 레이아웃
│   ├── index.html        # 메인 페이지
│   ├── login.html        # 로그인
│   ├── register.html     # 회원가입
│   ├── dashboard.html    # 대시보드
│   ├── transfer.html     # 송금
│   ├── profile.html      # 프로필
│   ├── account.html      # 계좌 조회
│   ├── search.html       # 검색
│   ├── notices.html      # 공지사항 목록
│   ├── notice.html       # 공지사항 상세
│   ├── write_notice.html # 공지사항 작성
│   ├── admin.html        # 관리자 페이지
│   ├── server_status.html# 서버 상태
│   ├── dns_lookup.html   # DNS 조회
│   ├── download.html     # 파일 다운로드
│   ├── change_password.html # 비밀번호 변경
│   ├── message.html      # 메시지 조회
│   └── error.html        # 에러 페이지
│
├── static/               # 정적 파일
│   ├── style.css         # CSS 스타일
│   └── script.js         # JavaScript
│
├── uploads/              # 업로드 파일 저장
│
└── documents/            # 다운로드용 문서
    ├── terms.txt
    ├── privacy.txt
    └── config.ini        # 민감 정보 포함 (취약점)
```

## 🛡️ 취약점 수정 가이드

각 취약점에 대한 수정 방법은 다음과 같습니다:

1. **SQL Injection**: Parameterized Query 또는 ORM 사용
2. **XSS**: Jinja2 자동 이스케이프 활성화, `| safe` 필터 제거
3. **CSRF**: Flask-WTF의 CSRF 토큰 사용
4. **IDOR**: 세션 기반 권한 검사 추가
5. **파일 업로드**: 화이트리스트 확장자, 파일 시그니처 검사
6. **디렉토리 트래버설**: 경로 정규화, 화이트리스트 검사
7. **커맨드 인젝션**: subprocess 모듈의 리스트 인자 사용
8. **세션 관리**: 강력한 시크릿 키, HttpOnly/Secure 쿠키
9. **정보 노출**: 디버그 모드 비활성화, 에러 핸들링
10. **암호화**: bcrypt 또는 Argon2 사용

## 📚 학습 자료

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackTheBox](https://www.hackthebox.com/)

## ⚠️ 법적 고지

이 애플리케이션은 **합법적인 보안 교육 및 연습 목적**으로만 사용해야 합니다.
허가 없이 다른 시스템에 이 기술을 적용하는 것은 **불법**입니다.

---

**Made for Educational Purposes Only** 🎓







