# 🚀 VulnBank 배포 가이드

이 문서는 모의해킹 랩 네트워크 구조에 VulnBank를 배포하는 방법을 설명합니다.

---

## 📋 네트워크 구조

```
┌─────────────────────────────────────────────────────────────────┐
│                    WAN (192.168.111.0/24)                       │
│    Kali Linux: 192.168.111.10 (공격자)                          │
│    pfSense WAN: 192.168.111.20                                  │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                    ┌───────▼───────┐
                    │   pfSense     │
                    │   Firewall    │
                    └───────┬───────┘
                            │
        ┌───────────────────┼───────────────────┐
        ▼                   │                   ▼
┌───────────────────┐       │       ┌───────────────────┐
│ DMZ (172.16.10.0) │       │       │ LAN (10.0.0.0)    │
│                   │       │       │                   │
│ Webserver         │       │       │ FileServer        │
│ 172.16.10.10      │◄──────┼──────►│ 10.0.0.20         │
│ [VulnBank Web]    │       │       │                   │
│                   │       │       │ Windows10         │
│ API/DB Server     │       │       │ 10.0.0.100        │
│ 172.16.10.20      │       │       │                   │
│ [MySQL/MariaDB]   │       │       │                   │
└───────────────────┘       │       └───────────────────┘
```

---

## 🔧 배포 방식 선택

### 방식 1: 단일 서버 (Standalone) - 간단한 테스트용
- Webserver(172.16.10.10) 한 대에 웹앱 + SQLite DB 모두 설치

### 방식 2: 분산 서버 (Distributed) - 실제 환경과 유사
- Webserver(172.16.10.10): 웹 애플리케이션
- API/DB(172.16.10.20): MySQL/MariaDB 데이터베이스

---

## 📦 방식 1: 단일 서버 배포 (Standalone)

### Webserver (172.16.10.10)에서 실행

```bash
# 1. 파일 전송 (Kali에서 Webserver로)
# 방법 A: SCP 사용
scp -r vulnerable_webapp/ user@172.16.10.10:/home/user/

# 방법 B: Python HTTP 서버로 다운로드
# Kali에서:
cd vulnerable_webapp && python3 -m http.server 8888
# Webserver에서:
wget -r http://192.168.111.10:8888/

# 2. Webserver SSH 접속
ssh user@172.16.10.10

# 3. 필요한 패키지 설치
sudo apt update
sudo apt install -y python3 python3-pip python3-venv

# 4. 프로젝트 디렉토리로 이동
cd /home/user/vulnerable_webapp

# 5. 가상환경 생성 및 활성화
python3 -m venv venv
source venv/bin/activate

# 6. 패키지 설치
pip install flask

# 7. 애플리케이션 실행
python app.py
```

### 서비스로 등록 (자동 시작)

```bash
# systemd 서비스 파일 생성
sudo nano /etc/systemd/system/vulnbank.service
```

```ini
[Unit]
Description=VulnBank Web Application
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/home/user/vulnerable_webapp
Environment=PATH=/home/user/vulnerable_webapp/venv/bin
ExecStart=/home/user/vulnerable_webapp/venv/bin/python app.py
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
# 서비스 시작
sudo systemctl daemon-reload
sudo systemctl enable vulnbank
sudo systemctl start vulnbank

# 상태 확인
sudo systemctl status vulnbank
```

---

## 📦 방식 2: 분산 서버 배포 (Distributed)

### 1단계: API/DB 서버 설정 (172.16.10.20)

```bash
# SSH 접속
ssh user@172.16.10.20

# MariaDB 설치
sudo apt update
sudo apt install -y mariadb-server mariadb-client

# MariaDB 보안 설정
sudo mysql_secure_installation

# MariaDB 시작
sudo systemctl enable mariadb
sudo systemctl start mariadb

# 원격 접속 허용 설정
sudo nano /etc/mysql/mariadb.conf.d/50-server.cnf
```

`50-server.cnf` 수정:
```ini
# bind-address = 127.0.0.1  # 이 줄을 주석 처리
bind-address = 0.0.0.0      # 모든 IP에서 접속 허용 (취약점)
```

```bash
# MariaDB 재시작
sudo systemctl restart mariadb

# 데이터베이스 초기화
sudo mysql < db_server_setup.sql

# 또는 수동으로:
sudo mysql -u root -p
```

MySQL 콘솔에서:
```sql
-- 데이터베이스 생성
CREATE DATABASE vulnbank_db CHARACTER SET utf8mb4;

-- 사용자 생성 (원격 접속 허용 - 취약점)
CREATE USER 'vulnbank'@'%' IDENTIFIED BY 'Vuln@2024!';
GRANT ALL PRIVILEGES ON vulnbank_db.* TO 'vulnbank'@'%';
FLUSH PRIVILEGES;

-- 종료
EXIT;
```

```bash
# 방화벽에서 MySQL 포트 열기
sudo ufw allow 3306/tcp
```

### 2단계: Webserver 설정 (172.16.10.10)

```bash
# SSH 접속
ssh user@172.16.10.10

# 필요한 패키지 설치
sudo apt update
sudo apt install -y python3 python3-pip python3-venv

# 프로젝트 디렉토리로 이동
cd /home/user/vulnerable_webapp

# 가상환경 생성 및 활성화
python3 -m venv venv
source venv/bin/activate

# 패키지 설치 (MySQL 커넥터 포함)
pip install flask pymysql

# 환경 변수 설정
export DEPLOY_MODE=distributed
export DB_HOST=172.16.10.20
export DB_PORT=3306
export DB_USER=vulnbank
export DB_PASSWORD='Vuln@2024!'
export DB_NAME=vulnbank_db

# 분산 버전 실행
python app_distributed.py
```

### 환경 변수 파일 사용 (.env)

```bash
# .env 파일 생성
nano /home/user/vulnerable_webapp/.env
```

```bash
# VulnBank Environment Configuration
DEPLOY_MODE=distributed
WEB_HOST=0.0.0.0
WEB_PORT=5000
DEBUG=True

# Database Configuration (API/DB Server)
DB_HOST=172.16.10.20
DB_PORT=3306
DB_USER=vulnbank
DB_PASSWORD=Vuln@2024!
DB_NAME=vulnbank_db
```

```bash
# 환경 변수 로드 후 실행
export $(cat .env | xargs) && python app_distributed.py
```

---

## 🛡️ pfSense 방화벽 설정

### DMZ → LAN 접근 차단 (기본 보안)
1. pfSense 웹 인터페이스 접속 (https://192.168.111.20)
2. Firewall → Rules → OPT1 (DMZ)
3. 규칙 추가:
   - Action: Block
   - Source: DMZ net
   - Destination: LAN net

### WAN → DMZ 포트 포워딩
외부(Kali)에서 Webserver에 접근할 수 있도록 설정:

1. Firewall → NAT → Port Forward
2. 규칙 추가:
   - Interface: WAN
   - Protocol: TCP
   - Destination: WAN address
   - Destination Port: 80, 5000
   - Redirect Target IP: 172.16.10.10
   - Redirect Target Port: 5000

### DMZ 내부 통신 허용
Webserver(172.16.10.10) ↔ API/DB(172.16.10.20) 통신:

1. Firewall → Rules → OPT1 (DMZ)
2. 규칙 추가:
   - Action: Pass
   - Source: 172.16.10.10
   - Destination: 172.16.10.20
   - Port: 3306

---

## 🧪 배포 확인 테스트

### Kali Linux에서 테스트 (192.168.111.10)

```bash
# 1. 포트 스캔
nmap -sV 172.16.10.10

# 2. 웹 접속 테스트
curl http://172.16.10.10:5000

# 3. 브라우저에서 접속
firefox http://172.16.10.10:5000
```

### 연결 확인

```bash
# Webserver에서 DB 서버 연결 테스트
mysql -h 172.16.10.20 -u vulnbank -p vulnbank_db

# 또는 Python으로 테스트
python3 -c "
import pymysql
conn = pymysql.connect(host='172.16.10.20', user='vulnbank', password='Vuln@2024!', database='vulnbank_db')
print('Database connection successful!')
conn.close()
"
```

---

## 📂 파일 전송 방법

### 방법 1: SCP (SSH 기반)
```bash
# Kali → Webserver
scp -r vulnerable_webapp/ user@172.16.10.10:/home/user/
```

### 방법 2: SFTP
```bash
sftp user@172.16.10.10
put -r vulnerable_webapp/
```

### 방법 3: Python HTTP 서버
```bash
# Kali에서 (파일 제공)
cd /path/to/vulnerable_webapp
python3 -m http.server 8888

# Webserver에서 (파일 다운로드)
wget -r -np http://192.168.111.10:8888/
```

### 방법 4: Git (권장)
```bash
# Webserver에서
git clone https://github.com/your-repo/vulnerable_webapp.git
```

---

## 🔥 접속 URL 정리

| 서비스 | URL | 비고 |
|--------|-----|------|
| VulnBank 웹 | http://172.16.10.10:5000 | DMZ 내부 |
| VulnBank 웹 (외부) | http://192.168.111.20:5000 | pfSense NAT |
| MySQL 서버 | 172.16.10.20:3306 | API/DB 서버 |
| pfSense 관리 | https://192.168.111.20 | 방화벽 설정 |

---

## 📝 테스트 계정

| 아이디 | 비밀번호 | 권한 |
|--------|----------|------|
| admin | admin123 | 관리자 |
| user1 | password1 | 일반 |
| user2 | password2 | 일반 |
| testuser | test1234 | 일반 |

---

## 🚨 트러블슈팅

### DB 연결 실패
```bash
# MariaDB 상태 확인
sudo systemctl status mariadb

# 포트 열려있는지 확인
netstat -tlnp | grep 3306

# 방화벽 확인
sudo ufw status

# 원격 접속 테스트
mysql -h 172.16.10.20 -u vulnbank -p
```

### 웹 접속 실패
```bash
# Flask 실행 상태 확인
ps aux | grep python

# 포트 확인
netstat -tlnp | grep 5000

# 로그 확인
journalctl -u vulnbank -f
```

### pfSense NAT 문제
1. Firewall → NAT → Outbound에서 Hybrid 또는 Manual 모드 확인
2. Firewall → Rules에서 해당 규칙이 있는지 확인
3. Diagnostics → States에서 연결 상태 확인

---

**⚠️ 주의: 이 환경은 교육 목적으로만 사용하세요!**










