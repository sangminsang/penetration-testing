#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🔐 VulnBank - 분산 환경용 웹 애플리케이션
MySQL/MariaDB를 사용하는 버전 (API/DB 서버: 172.16.10.20 연결)

이 버전은 Webserver(172.16.10.10)에 배포하고
DB는 API/DB 서버(172.16.10.20)에 분리 배포할 때 사용합니다.
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, make_response
import pymysql
import hashlib
import os
import subprocess
import time
from config import *

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def get_db():
    """MySQL 데이터베이스 연결"""
    conn = pymysql.connect(
        host=MYSQL_CONFIG['host'],
        port=MYSQL_CONFIG['port'],
        user=MYSQL_CONFIG['user'],
        password=MYSQL_CONFIG['password'],
        database=MYSQL_CONFIG['database'],
        charset=MYSQL_CONFIG['charset'],
        cursorclass=pymysql.cursors.DictCursor
    )
    return conn

def init_db():
    """데이터베이스 초기화 (MySQL)"""
    conn = get_db()
    cursor = conn.cursor()
    
    # 사용자 테이블
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(100) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            email VARCHAR(255),
            balance DECIMAL(15,2) DEFAULT 10000.0,
            is_admin TINYINT DEFAULT 0,
            profile_pic VARCHAR(255) DEFAULT 'default.png',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    ''')
    
    # 거래 내역 테이블
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS transactions (
            id INT AUTO_INCREMENT PRIMARY KEY,
            from_user_id INT,
            to_user_id INT,
            amount DECIMAL(15,2),
            memo TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (from_user_id) REFERENCES users(id),
            FOREIGN KEY (to_user_id) REFERENCES users(id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    ''')
    
    # 공지사항 테이블
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS notices (
            id INT AUTO_INCREMENT PRIMARY KEY,
            title VARCHAR(255),
            content TEXT,
            author_id INT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    ''')
    
    # 메시지 테이블
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INT AUTO_INCREMENT PRIMARY KEY,
            from_user_id INT,
            to_user_id INT,
            subject VARCHAR(255),
            content TEXT,
            is_read TINYINT DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    ''')
    
    # 기본 사용자 추가
    users = [
        ('admin', hashlib.md5('admin123'.encode()).hexdigest(), 'admin@vulnbank.com', 999999.0, 1),
        ('user1', hashlib.md5('password1'.encode()).hexdigest(), 'user1@vulnbank.com', 50000.0, 0),
        ('user2', hashlib.md5('password2'.encode()).hexdigest(), 'user2@vulnbank.com', 30000.0, 0),
        ('testuser', hashlib.md5('test1234'.encode()).hexdigest(), 'test@vulnbank.com', 15000.0, 0),
    ]
    
    for user in users:
        try:
            cursor.execute('''
                INSERT IGNORE INTO users (username, password, email, balance, is_admin) 
                VALUES (%s, %s, %s, %s, %s)
            ''', user)
        except:
            pass
    
    # 샘플 공지사항
    cursor.execute('''
        INSERT IGNORE INTO notices (id, title, content, author_id) 
        VALUES (1, '시스템 점검 안내', '매주 일요일 새벽 2시-4시 시스템 점검이 진행됩니다.', 1)
    ''')
    
    conn.commit()
    conn.close()
    print("[+] Database initialized successfully!")

# =============================================================================
# 메인 페이지
# =============================================================================

@app.route('/')
def index():
    return render_template('index.html')

# =============================================================================
# 취약점 1: SQL Injection - 로그인
# =============================================================================

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db()
        cursor = conn.cursor()
        
        # 취약점: SQL Injection (문자열 포맷팅)
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{hashlib.md5(password.encode()).hexdigest()}'"
        print(f"[DEBUG] Query: {query}")
        
        try:
            cursor.execute(query)
            user = cursor.fetchone()
            
            if user:
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['is_admin'] = user['is_admin']
                session['logged_in'] = True
                
                resp = make_response(redirect(url_for('dashboard')))
                resp.set_cookie('user_role', 'admin' if user['is_admin'] else 'user')
                resp.set_cookie('user_id', str(user['id']))
                conn.close()
                return resp
            else:
                error = '로그인 실패: 잘못된 아이디 또는 비밀번호입니다.'
        except Exception as e:
            error = f'데이터베이스 오류: {str(e)}'
        
        conn.close()
    
    return render_template('login.html', error=error)

# =============================================================================
# 취약점 2: XSS (Cross-Site Scripting)
# =============================================================================

@app.route('/search')
def search():
    query = request.args.get('q', '')
    
    conn = get_db()
    cursor = conn.cursor()
    
    # 취약점: SQL Injection
    sql = f"SELECT * FROM users WHERE username LIKE '%{query}%' OR email LIKE '%{query}%'"
    
    try:
        cursor.execute(sql)
        results = cursor.fetchall()
    except:
        results = []
    
    conn.close()
    return render_template('search.html', query=query, results=results)

@app.route('/notice/<int:notice_id>')
def view_notice(notice_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM notices WHERE id = %s', (notice_id,))
    notice = cursor.fetchone()
    conn.close()
    return render_template('notice.html', notice=notice)

@app.route('/notice/write', methods=['GET', 'POST'])
def write_notice():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO notices (title, content, author_id) 
            VALUES (%s, %s, %s)
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
        to_username = request.form.get('to_username')
        amount = float(request.form.get('amount', 0))
        memo = request.form.get('memo', '')
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('SELECT balance FROM users WHERE id = %s', (session['user_id'],))
        current_user = cursor.fetchone()
        
        cursor.execute('SELECT id FROM users WHERE username = %s', (to_username,))
        to_user = cursor.fetchone()
        
        if not to_user:
            error = '받는 사람을 찾을 수 없습니다.'
        elif current_user['balance'] < amount:
            error = '잔액이 부족합니다.'
        elif amount <= 0:
            error = '유효하지 않은 금액입니다.'
        else:
            cursor.execute('UPDATE users SET balance = balance - %s WHERE id = %s', 
                         (amount, session['user_id']))
            cursor.execute('UPDATE users SET balance = balance + %s WHERE id = %s', 
                         (amount, to_user['id']))
            
            cursor.execute('''
                INSERT INTO transactions (from_user_id, to_user_id, amount, memo) 
                VALUES (%s, %s, %s, %s)
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
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
    user = cursor.fetchone()
    
    cursor.execute('''
        SELECT t.*, 
               u1.username as from_username, 
               u2.username as to_username 
        FROM transactions t
        JOIN users u1 ON t.from_user_id = u1.id
        JOIN users u2 ON t.to_user_id = u2.id
        WHERE t.from_user_id = %s OR t.to_user_id = %s
        ORDER BY t.created_at DESC
    ''', (user_id, user_id))
    transactions = cursor.fetchall()
    
    conn.close()
    return render_template('account.html', user=user, transactions=transactions)

@app.route('/message/<int:message_id>')
def view_message(message_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM messages WHERE id = %s', (message_id,))
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
                filename = file.filename
                filepath = os.path.join(UPLOAD_FOLDER, filename)
                file.save(filepath)
                
                conn = get_db()
                cursor = conn.cursor()
                cursor.execute('UPDATE users SET profile_pic = %s WHERE id = %s',
                             (filename, session['user_id']))
                conn.commit()
                conn.close()
                
                message = '프로필 사진이 업데이트되었습니다.'
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = %s', (session['user_id'],))
    user = cursor.fetchone()
    conn.close()
    
    return render_template('profile.html', user=user, message=message, error=error)

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    return send_file(filepath)

# =============================================================================
# 취약점 6: 디렉토리 트래버설
# =============================================================================

@app.route('/download')
def download():
    filename = request.args.get('file', '')
    
    if filename:
        filepath = os.path.join('documents', filename)
        try:
            return send_file(filepath)
        except Exception as e:
            return f'파일을 찾을 수 없습니다: {filepath}', 404
    
    return render_template('download.html')

# =============================================================================
# 취약점 7: 커맨드 인젝션
# =============================================================================

@app.route('/admin/server-status')
def server_status():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    
    if request.cookies.get('user_role') != 'admin':
        return '관리자만 접근 가능합니다.', 403
    
    host = request.args.get('host', 'localhost')
    
    try:
        result = subprocess.check_output(f'ping -c 1 {host}', shell=True, stderr=subprocess.STDOUT)
        output = result.decode('utf-8')
    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8')
    except Exception as e:
        output = str(e)
    
    return render_template('server_status.html', host=host, output=output)

@app.route('/admin/dns-lookup')
def dns_lookup():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    
    domain = request.args.get('domain', '')
    output = ''
    
    if domain:
        try:
            result = subprocess.check_output(f'nslookup {domain}', shell=True, stderr=subprocess.STDOUT)
            output = result.decode('utf-8')
        except Exception as e:
            output = str(e)
    
    return render_template('dns_lookup.html', domain=domain, output=output)

# =============================================================================
# 대시보드 및 기타
# =============================================================================

@app.route('/dashboard')
def dashboard():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM users WHERE id = %s', (session['user_id'],))
    user = cursor.fetchone()
    
    cursor.execute('''
        SELECT t.*, u.username as other_user
        FROM transactions t
        JOIN users u ON (t.to_user_id = u.id AND t.from_user_id = %s) 
                     OR (t.from_user_id = u.id AND t.to_user_id = %s)
        WHERE t.from_user_id = %s OR t.to_user_id = %s
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

@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    
    message = None
    error = None
    
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        
        conn = get_db()
        cursor = conn.cursor()
        
        hashed = hashlib.md5(new_password.encode()).hexdigest()
        cursor.execute('UPDATE users SET password = %s WHERE id = %s',
                      (hashed, session['user_id']))
        conn.commit()
        conn.close()
        
        message = '비밀번호가 변경되었습니다.'
    
    return render_template('change_password.html', message=message, error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        
        conn = get_db()
        cursor = conn.cursor()
        
        try:
            hashed = hashlib.md5(password.encode()).hexdigest()
            
            # 취약점: SQL Injection
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

@app.route('/admin')
def admin_panel():
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

@app.route('/api/users')
def api_users():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, email, balance, is_admin FROM users')
    users = cursor.fetchall()
    conn.close()
    
    return {'users': users}

@app.route('/api/user/<int:user_id>')
def api_user(user_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return dict(user)
    return {'error': 'User not found'}, 404

@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', error=str(e), path=request.path), 404

@app.errorhandler(500)
def server_error(e):
    import traceback
    return render_template('error.html', error=str(e), trace=traceback.format_exc()), 500

if __name__ == '__main__':
    print_config()
    try:
        init_db()
    except Exception as e:
        print(f"[!] Database initialization failed: {e}")
        print("[*] Make sure the database server is running and accessible.")
    
    app.run(host=WEB_SERVER_HOST, port=WEB_SERVER_PORT, debug=DEBUG_MODE)










