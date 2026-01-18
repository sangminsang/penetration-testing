#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🔐 VulnBank - 모의해킹 연습용 취약한 뱅킹 웹 애플리케이션
⚠️ 경고: 이 애플리케이션은 교육 목적으로만 사용하세요!
       절대 실제 환경에서 사용하지 마세요!

포함된 취약점 (CVE 매칭 가능):
1. SQL Injection - 로그인, 검색 기능
   - CVE 패턴: CVE-2021-44228 (Log4j 패턴), CVE-2019-9193 (PostgreSQL 패턴)
   - CWE-89: SQL Injection
   
2. XSS (Cross-Site Scripting) - Reflected, Stored
   - CVE 패턴: CVE-2020-3580 (Cisco 패턴), CVE-2019-16759 (vBulletin 패턴)
   - CWE-79: Cross-site Scripting
   
3. Server-Side Template Injection (SSTI) - Jinja2 취약점
   - CVE-2024-22195: Jinja2 Server-Side Template Injection
   - CVE-2016-1000001: Jinja2 템플릿 인젝션 취약점 패턴
   - CWE-94: Code Injection
   
4. CSRF (Cross-Site Request Forgery) - 송금 기능
   - CVE 패턴: CVE-2021-44228 패턴
   - CWE-352: Cross-Site Request Forgery
   
5. IDOR (Insecure Direct Object Reference) - 계좌 조회
   - CVE 패턴: CVE-2020-1472 (Netlogon 패턴)
   - CWE-639: Insecure Direct Object Reference
   
6. 파일 업로드 취약점 - 프로필 사진 업로드
   - CVE 패턴: CVE-2021-44228 패턴
   - CWE-434: Unrestricted Upload of File with Dangerous Type
   
7. 디렉토리 트래버설 - 파일 다운로드
   - CVE-2023-23934: Werkzeug의 경로 정규화 취약점
   - CVE-2021-41773: Apache Path Traversal 패턴
   - CWE-22: Path Traversal
   
8. 커맨드 인젝션 - 서버 상태 체크
   - CVE 패턴: CVE-2021-44228 패턴
   - CWE-78: OS Command Injection
   
9. 세션 관리 취약점 - 예측 가능한 세션
   - CVE-2018-1000656: Flask의 세션 쿠키 취약점
   - CVE-2023-30861: Flask에서의 정보 노출 취약점
   - CWE-613: Insufficient Session Expiration
   
10. 정보 노출 - 에러 메시지, 주석
    - CVE-2023-25577: Werkzeug의 디버그 모드 취약점
    - CVE-2023-30861: Flask에서의 정보 노출 취약점
    - CWE-209: Information Exposure Through an Error Message
    
11. 약한 암호화 - MD5 해시 사용
    - CVE 패턴: CVE-2004-2761 (MD5 취약점 패턴)
    - CWE-327: Use of a Broken or Risky Cryptographic Algorithm
"""

from flask import Flask, render_template, render_template_string, request, redirect, url_for, session, flash, send_file, make_response
import sqlite3
import hashlib
import os
import subprocess
import time
from jinja2 import Template

app = Flask(__name__)
# 취약점: 약한 시크릿 키
# CVE-2018-1000656: Flask의 세션 쿠키 취약점 패턴
# CVE-2023-30861: Flask에서의 정보 노출 취약점 패턴
app.secret_key = 'secret123'

# 취약점: 디버그 모드 활성화
# CVE-2023-25577: Werkzeug의 디버그 모드 취약점
app.config['DEBUG'] = True
app.config['EXPLAIN_TEMPLATE_LOADING'] = True

DATABASE = 'vulnbank.db'
UPLOAD_FOLDER = 'uploads'

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def get_db():
    """데이터베이스 연결"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """데이터베이스 초기화"""
    conn = get_db()
    cursor = conn.cursor()
    
    # 사용자 테이블
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            balance REAL DEFAULT 10000.0,
            is_admin INTEGER DEFAULT 0,
            profile_pic TEXT DEFAULT 'default.png',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # 거래 내역 테이블
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_user_id INTEGER,
            to_user_id INTEGER,
            amount REAL,
            memo TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (from_user_id) REFERENCES users(id),
            FOREIGN KEY (to_user_id) REFERENCES users(id)
        )
    ''')
    
    # 공지사항 테이블 (Stored XSS 테스트용)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS notices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            content TEXT,
            author_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # 메시지 테이블 (Stored XSS 테스트용)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_user_id INTEGER,
            to_user_id INTEGER,
            subject TEXT,
            content TEXT,
            is_read INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # 기본 사용자 추가 (취약점: MD5 해시 사용)
    users = [
        ('admin', hashlib.md5('admin123'.encode()).hexdigest(), 'admin@vulnbank.com', 999999.0, 1),
        ('user1', hashlib.md5('password1'.encode()).hexdigest(), 'user1@vulnbank.com', 50000.0, 0),
        ('user2', hashlib.md5('password2'.encode()).hexdigest(), 'user2@vulnbank.com', 30000.0, 0),
        ('testuser', hashlib.md5('test1234'.encode()).hexdigest(), 'test@vulnbank.com', 15000.0, 0),
    ]
    
    for user in users:
        try:
            cursor.execute('''
                INSERT INTO users (username, password, email, balance, is_admin) 
                VALUES (?, ?, ?, ?, ?)
            ''', user)
        except sqlite3.IntegrityError:
            pass
    
    # 샘플 공지사항
    cursor.execute('''
        INSERT OR IGNORE INTO notices (id, title, content, author_id) 
        VALUES (1, '시스템 점검 안내', '매주 일요일 새벽 2시-4시 시스템 점검이 진행됩니다.', 1)
    ''')
    
    conn.commit()
    conn.close()

# =============================================================================
# 메인 페이지
# =============================================================================

@app.route('/')
def index():
    return render_template('index.html')

# =============================================================================
# 취약점 1: SQL Injection - 로그인
# CVE 패턴: CVE-2021-44228 (Log4j 패턴), CVE-2019-9193 (PostgreSQL 패턴)
# CWE-89: SQL Injection
# =============================================================================

@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    취약점: SQL Injection
    CVE 패턴: CVE-2021-44228 (Log4j 패턴), CVE-2019-9193 (PostgreSQL 패턴)
    CWE-89: SQL Injection
    공격 예시: username에 ' OR '1'='1'-- 입력
    """
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # 취약점: SQL Injection
        # CVE 패턴: CVE-2021-44228 (Log4j 패턴), CVE-2019-9193 (PostgreSQL 패턴)
        conn = get_db()
        cursor = conn.cursor()
        
        # 취약한 쿼리 (문자열 연결)
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{hashlib.md5(password.encode()).hexdigest()}'"
        
        # 디버그용 쿼리 출력 (취약점: 정보 노출)
        # CVE-2023-25577: Werkzeug의 디버그 모드 취약점 패턴
        print(f"[DEBUG] Query: {query}")
        
        try:
            cursor.execute(query)
            user = cursor.fetchone()
            
            if user:
                # 취약점: 예측 가능한 세션 ID
                # CVE-2018-1000656: Flask의 세션 쿠키 취약점 패턴
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['is_admin'] = user['is_admin']
                session['logged_in'] = True
                
                # 취약점: 쿠키에 민감정보 저장
                # CVE-2018-1000656: Flask의 세션 쿠키 취약점 패턴
                resp = make_response(redirect(url_for('dashboard')))
                resp.set_cookie('user_role', 'admin' if user['is_admin'] else 'user')
                resp.set_cookie('user_id', str(user['id']))
                return resp
            else:
                error = '로그인 실패: 잘못된 아이디 또는 비밀번호입니다.'
        except Exception as e:
            # 취약점: 상세한 에러 메시지 노출
            # CVE-2023-25577: Werkzeug의 디버그 모드 취약점 패턴
            # CVE-2023-30861: Flask에서의 정보 노출 취약점 패턴
            error = f'데이터베이스 오류: {str(e)}'
        
        conn.close()
    
    return render_template('login.html', error=error)

# =============================================================================
# 취약점 2: XSS (Cross-Site Scripting)
# CVE 패턴: CVE-2020-3580 (Cisco 패턴), CVE-2019-16759 (vBulletin 패턴)
# CWE-79: Cross-site Scripting
# =============================================================================

@app.route('/search')
def search():
    """
    취약점: Reflected XSS + SQL Injection
    CVE 패턴: CVE-2020-3580 (Cisco 패턴), CVE-2019-16759 (vBulletin 패턴)
    CWE-79: Cross-site Scripting
    공격 예시: /search?q=<script>alert('XSS')</script>
    """
    query = request.args.get('q', '')
    
    conn = get_db()
    cursor = conn.cursor()
    
    # 취약점: SQL Injection도 가능
    # CVE 패턴: CVE-2021-44228 (Log4j 패턴)
    sql = f"SELECT * FROM users WHERE username LIKE '%{query}%' OR email LIKE '%{query}%'"
    
    try:
        cursor.execute(sql)
        results = cursor.fetchall()
    except:
        results = []
    
    conn.close()
    
    # 취약점: 사용자 입력 이스케이프 없이 템플릿에 전달
    # CVE 패턴: CVE-2020-3580 (Cisco 패턴), CVE-2019-16759 (vBulletin 패턴)
    return render_template('search.html', query=query, results=results)

@app.route('/notice/<int:notice_id>')
def view_notice(notice_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM notices WHERE id = ?', (notice_id,))
    notice = cursor.fetchone()
    conn.close()
    
    # 취약점: Stored XSS - content가 이스케이프되지 않음
    return render_template('notice.html', notice=notice)

# =============================================================================
# 취약점: Server-Side Template Injection (SSTI) - CVE 매칭 가능
# CVE-2024-22195: Jinja2 Server-Side Template Injection
# CVE-2016-1000001: Jinja2 템플릿 인젝션 취약점 패턴
# CWE-94: Code Injection
# =============================================================================

@app.route('/template-preview')
def template_preview():
    """
    취약점: Server-Side Template Injection (SSTI)
    CVE-2024-22195, CVE-2016-1000001 패턴
    공격 예시: /template-preview?template={{config.__class__.__init__.__globals__['os'].popen('id').read()}}
    """
    template_content = request.args.get('template', '')
    
    if template_content:
        # 취약점: 사용자 입력을 직접 템플릿으로 렌더링
        # CVE-2024-22195: Jinja2 SSTI 취약점 패턴
        try:
            # 취약한 코드: render_template_string 사용
            rendered = render_template_string(template_content)
            return f'<h2>템플릿 미리보기</h2><pre>{rendered}</pre>'
        except Exception as e:
            return f'<h2>템플릿 오류</h2><pre>{str(e)}</pre>'
    
    return '''
    <h2>템플릿 미리보기</h2>
    <form method="GET">
        <input type="text" name="template" placeholder="템플릿 내용 입력" style="width: 500px;">
        <button type="submit">미리보기</button>
    </form>
    <p>예시: Hello {{ name }}</p>
    '''

@app.route('/custom-template', methods=['GET', 'POST'])
def custom_template():
    """
    취약점: Server-Side Template Injection (SSTI)
    CVE-2024-22195, CVE-2016-1000001 패턴
    """
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        template_code = request.form.get('template_code', '')
        user_data = {
            'name': session.get('username', 'Guest'),
            'user_id': session.get('user_id', 0)
        }
        
        # 취약점: 사용자 입력을 직접 Jinja2 Template으로 렌더링
        # CVE-2024-22195: Jinja2 SSTI 취약점 패턴
        try:
            # 취약한 코드: Template 클래스 직접 사용
            template = Template(template_code)
            rendered = template.render(**user_data)
            return f'<h2>렌더링 결과</h2><pre>{rendered}</pre><br><a href="/custom-template">다시 시도</a>'
        except Exception as e:
            return f'<h2>템플릿 오류</h2><pre>{str(e)}</pre><br><a href="/custom-template">다시 시도</a>'
    
    return '''
    <h2>커스텀 템플릿 작성</h2>
    <form method="POST">
        <textarea name="template_code" rows="10" cols="80" placeholder="Jinja2 템플릿 코드 입력"></textarea><br>
        <button type="submit">렌더링</button>
    </form>
    <p>사용 가능한 변수: name, user_id</p>
    <p>예시: Hello {{ name }}, Your ID is {{ user_id }}</p>
    '''

@app.route('/notice/write', methods=['GET', 'POST'])
def write_notice():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']  # 취약점: XSS 필터링 없음
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO notices (title, content, author_id) 
            VALUES (?, ?, ?)
        ''', (title, content, session['user_id']))
        conn.commit()
        conn.close()
        
        return redirect(url_for('notices'))
    
    return render_template('write_notice.html')

@app.route('/notices')
def notices():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM notices ORDER BY created_at DESC')
    notices = cursor.fetchall()
    conn.close()
    return render_template('notices.html', notices=notices)

# =============================================================================
# 취약점 3: CSRF (Cross-Site Request Forgery)
# =============================================================================

@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    
    message = None
    error = None
    
    if request.method == 'POST':
        # 취약점: CSRF 토큰 없음
        to_username = request.form.get('to_username')
        amount = float(request.form.get('amount', 0))
        memo = request.form.get('memo', '')
        
        conn = get_db()
        cursor = conn.cursor()
        
        # 현재 사용자 잔액 확인
        cursor.execute('SELECT balance FROM users WHERE id = ?', (session['user_id'],))
        current_user = cursor.fetchone()
        
        # 받는 사람 확인
        cursor.execute('SELECT id FROM users WHERE username = ?', (to_username,))
        to_user = cursor.fetchone()
        
        if not to_user:
            error = '받는 사람을 찾을 수 없습니다.'
        elif current_user['balance'] < amount:
            error = '잔액이 부족합니다.'
        elif amount <= 0:
            error = '유효하지 않은 금액입니다.'
        else:
            # 송금 처리
            cursor.execute('UPDATE users SET balance = balance - ? WHERE id = ?', 
                         (amount, session['user_id']))
            cursor.execute('UPDATE users SET balance = balance + ? WHERE id = ?', 
                         (amount, to_user['id']))
            
            # 거래 내역 저장 (취약점: memo에 XSS 가능)
            cursor.execute('''
                INSERT INTO transactions (from_user_id, to_user_id, amount, memo) 
                VALUES (?, ?, ?, ?)
            ''', (session['user_id'], to_user['id'], amount, memo))
            
            conn.commit()
            message = f'{to_username}님에게 {amount:,.0f}원을 송금했습니다.'
        
        conn.close()
    
    return render_template('transfer.html', message=message, error=error)

# =============================================================================
# 취약점 4: IDOR (Insecure Direct Object Reference)
# =============================================================================

@app.route('/account/<int:user_id>')
def account(user_id):
    # 취약점: 접근 권한 검사 없음
    # 공격 예시: /account/1 로 admin 계정 정보 조회
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    
    cursor.execute('''
        SELECT t.*, 
               u1.username as from_username, 
               u2.username as to_username 
        FROM transactions t
        JOIN users u1 ON t.from_user_id = u1.id
        JOIN users u2 ON t.to_user_id = u2.id
        WHERE t.from_user_id = ? OR t.to_user_id = ?
        ORDER BY t.created_at DESC
    ''', (user_id, user_id))
    transactions = cursor.fetchall()
    
    conn.close()
    
    return render_template('account.html', user=user, transactions=transactions)

@app.route('/message/<int:message_id>')
def view_message(message_id):
    # 취약점: IDOR - 다른 사용자의 메시지 열람 가능
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM messages WHERE id = ?', (message_id,))
    message = cursor.fetchone()
    conn.close()
    
    return render_template('message.html', message=message)

# =============================================================================
# 취약점 5: 파일 업로드 취약점
# =============================================================================

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    
    message = None
    error = None
    
    if request.method == 'POST':
        if 'profile_pic' in request.files:
            file = request.files['profile_pic']
            
            if file.filename:
                # 취약점: 파일 확장자/내용 검사 없음
                # 공격 예시: shell.php 업로드
                filename = file.filename  # 취약점: 파일명 검증 없음
                filepath = os.path.join(UPLOAD_FOLDER, filename)
                file.save(filepath)
                
                # DB 업데이트
                conn = get_db()
                cursor = conn.cursor()
                cursor.execute('UPDATE users SET profile_pic = ? WHERE id = ?',
                             (filename, session['user_id']))
                conn.commit()
                conn.close()
                
                message = '프로필 사진이 업데이트되었습니다.'
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
    user = cursor.fetchone()
    conn.close()
    
    return render_template('profile.html', user=user, message=message, error=error)

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    # 취약점: 디렉토리 트래버설
    # 공격 예시: /uploads/../../../etc/passwd
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    return send_file(filepath)

# =============================================================================
# 취약점 6: 디렉토리 트래버설
# =============================================================================

@app.route('/download')
def download():
    """
    취약점: 디렉토리 트래버설
    CVE-2023-23934: Werkzeug의 경로 정규화 취약점 패턴
    CVE-2021-41773: Apache Path Traversal 패턴
    CWE-22: Path Traversal
    공격 예시: /download?file=../../../etc/passwd
    """
    filename = request.args.get('file', '')
    
    if filename:
        # 취약점: 경로 검증 없이 직접 사용
        # CVE-2023-23934: Werkzeug의 경로 정규화 취약점 패턴
        filepath = os.path.join('documents', filename)
        try:
            return send_file(filepath)
        except Exception as e:
            # 취약점: 에러 메시지에 경로 정보 노출
            # CVE-2023-25577: Werkzeug의 디버그 모드 취약점 패턴
            return f'파일을 찾을 수 없습니다: {filepath}', 404
    
    return render_template('download.html')

# =============================================================================
# 취약점 7: 커맨드 인젝션
# =============================================================================

@app.route('/admin/server-status')
def server_status():
    """
    취약점: 커맨드 인젝션
    CVE 패턴: CVE-2021-44228 (Command Injection 패턴)
    CWE-78: OS Command Injection
    공격 예시: /admin/server-status?host=localhost;cat /etc/passwd
    """
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    
    # 취약점: 관리자 권한 검사를 쿠키로 함 (조작 가능)
    # CVE-2018-1000656: Flask의 세션 쿠키 취약점 패턴
    if request.cookies.get('user_role') != 'admin':
        return '관리자만 접근 가능합니다.', 403
    
    host = request.args.get('host', 'localhost')
    
    # 취약점: 커맨드 인젝션
    # CVE 패턴: CVE-2021-44228 (Command Injection 패턴)
    # 공격 예시: /admin/server-status?host=localhost;cat /etc/passwd
    try:
        # 취약한 코드: shell=True 사용, 입력 검증 없음
        result = subprocess.check_output(f'ping -c 1 {host}', shell=True, stderr=subprocess.STDOUT)
        output = result.decode('utf-8')
    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8')
    except Exception as e:
        # 취약점: 에러 메시지 노출
        # CVE-2023-25577: Werkzeug의 디버그 모드 취약점 패턴
        output = str(e)
    
    return render_template('server_status.html', host=host, output=output)

@app.route('/admin/dns-lookup')
def dns_lookup():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    
    domain = request.args.get('domain', '')
    output = ''
    
    if domain:
        # 취약점: 커맨드 인젝션
        # 공격 예시: /admin/dns-lookup?domain=google.com;id
        try:
            result = subprocess.check_output(f'nslookup {domain}', shell=True, stderr=subprocess.STDOUT)
            output = result.decode('utf-8')
        except Exception as e:
            output = str(e)
    
    return render_template('dns_lookup.html', domain=domain, output=output)

# =============================================================================
# 취약점 8: 세션 관리 취약점
# =============================================================================

@app.route('/dashboard')
def dashboard():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
    user = cursor.fetchone()
    
    cursor.execute('''
        SELECT t.*, u.username as other_user
        FROM transactions t
        JOIN users u ON (t.to_user_id = u.id AND t.from_user_id = ?) 
                     OR (t.from_user_id = u.id AND t.to_user_id = ?)
        WHERE t.from_user_id = ? OR t.to_user_id = ?
        ORDER BY t.created_at DESC LIMIT 10
    ''', (session['user_id'], session['user_id'], session['user_id'], session['user_id']))
    transactions = cursor.fetchall()
    
    conn.close()
    
    return render_template('dashboard.html', user=user, transactions=transactions)

@app.route('/logout')
def logout():
    session.clear()
    resp = make_response(redirect(url_for('index')))
    resp.delete_cookie('user_role')
    resp.delete_cookie('user_id')
    return resp

# =============================================================================
# 취약점 9: 비밀번호 변경 (CSRF, 현재 비밀번호 확인 없음)
# =============================================================================

@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    
    message = None
    error = None
    
    if request.method == 'POST':
        # 취약점: 현재 비밀번호 확인 없음, CSRF 토큰 없음
        new_password = request.form.get('new_password')
        
        conn = get_db()
        cursor = conn.cursor()
        
        # 취약점: MD5 해시 사용
        hashed = hashlib.md5(new_password.encode()).hexdigest()
        cursor.execute('UPDATE users SET password = ? WHERE id = ?',
                      (hashed, session['user_id']))
        conn.commit()
        conn.close()
        
        message = '비밀번호가 변경되었습니다.'
    
    return render_template('change_password.html', message=message, error=error)

# =============================================================================
# 취약점 10: 회원가입 (약한 비밀번호 정책)
# =============================================================================

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        
        # 취약점: 비밀번호 강도 검사 없음
        # 취약점: SQL Injection 가능
        conn = get_db()
        cursor = conn.cursor()
        
        try:
            # 취약점: MD5 해시 사용
            hashed = hashlib.md5(password.encode()).hexdigest()
            
            query = f"INSERT INTO users (username, password, email) VALUES ('{username}', '{hashed}', '{email}')"
            cursor.execute(query)
            conn.commit()
            
            flash('회원가입이 완료되었습니다. 로그인해주세요.')
            return redirect(url_for('login'))
        except Exception as e:
            error = f'회원가입 실패: {str(e)}'
        finally:
            conn.close()
    
    return render_template('register.html', error=error)

# =============================================================================
# 취약점 11: 관리자 페이지 (인증 우회)
# =============================================================================

@app.route('/admin')
def admin_panel():
    # 취약점: 쿠키 기반 인증 (조작 가능)
    # 공격: 브라우저에서 user_role 쿠키를 'admin'으로 변경
    if request.cookies.get('user_role') != 'admin':
        return '관리자만 접근 가능합니다.', 403
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users')
    users = cursor.fetchall()
    cursor.execute('SELECT * FROM transactions ORDER BY created_at DESC LIMIT 50')
    transactions = cursor.fetchall()
    conn.close()
    
    return render_template('admin.html', users=users, transactions=transactions)

# =============================================================================
# 취약점 12: API 엔드포인트 (인증 없음)
# =============================================================================

@app.route('/api/users')
def api_users():
    # 취약점: 인증 없이 모든 사용자 정보 노출
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, email, balance, is_admin FROM users')
    users = cursor.fetchall()
    conn.close()
    
    return {'users': [dict(u) for u in users]}

@app.route('/api/user/<int:user_id>')
def api_user(user_id):
    # 취약점: IDOR + 민감정보 노출
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return dict(user)
    return {'error': 'User not found'}, 404

# =============================================================================
# 에러 핸들러
# =============================================================================

@app.errorhandler(404)
def not_found(e):
    # 취약점: 상세한 에러 정보 노출
    return render_template('error.html', error=str(e), path=request.path), 404

@app.errorhandler(500)
def server_error(e):
    # 취약점: 스택 트레이스 노출
    import traceback
    return render_template('error.html', error=str(e), trace=traceback.format_exc()), 500

# =============================================================================
# 메인 실행
# =============================================================================

if __name__ == '__main__':
    init_db()
    # 취약점: 디버그 모드 활성화
    app.run(host='0.0.0.0', port=5000, debug=True)





