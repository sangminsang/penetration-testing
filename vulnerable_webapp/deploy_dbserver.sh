#!/bin/bash
# =============================================================================
# VulnBank Database Server 배포 스크립트
# API/DB Server (172.16.10.20)에서 실행
# =============================================================================

set -e

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   🗄️  VulnBank - Database Server 배포 스크립트               ║"
echo "║   대상 서버: 172.16.10.20                                    ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 변수 설정
DB_NAME="vulnbank_db"
DB_USER="vulnbank"
DB_PASS="Vuln@2024!"

echo -e "${YELLOW}[*] MariaDB 데이터베이스 서버를 설정합니다.${NC}"
echo ""

# 1. MariaDB 설치
echo -e "${GREEN}[1/5] MariaDB 설치 중...${NC}"
sudo apt update
sudo apt install -y mariadb-server mariadb-client

# 2. MariaDB 시작
echo -e "${GREEN}[2/5] MariaDB 서비스 시작 중...${NC}"
sudo systemctl enable mariadb
sudo systemctl start mariadb

# 3. 원격 접속 허용 설정
echo -e "${GREEN}[3/5] 원격 접속 설정 중...${NC}"

# bind-address 설정 변경
sudo sed -i 's/^bind-address\s*=.*/bind-address = 0.0.0.0/' /etc/mysql/mariadb.conf.d/50-server.cnf

# 설정이 없으면 추가
if ! grep -q "^bind-address" /etc/mysql/mariadb.conf.d/50-server.cnf; then
    echo "bind-address = 0.0.0.0" | sudo tee -a /etc/mysql/mariadb.conf.d/50-server.cnf
fi

# MariaDB 재시작
sudo systemctl restart mariadb

# 4. 데이터베이스 및 사용자 생성
echo -e "${GREEN}[4/5] 데이터베이스 설정 중...${NC}"

# SQL 명령 실행
sudo mysql << EOF
-- 데이터베이스 생성
CREATE DATABASE IF NOT EXISTS ${DB_NAME} 
CHARACTER SET utf8mb4 
COLLATE utf8mb4_unicode_ci;

-- 사용자 생성 (원격 접속 허용 - 취약점)
CREATE USER IF NOT EXISTS '${DB_USER}'@'%' IDENTIFIED BY '${DB_PASS}';
CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';

-- 권한 부여
GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'%';
GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'localhost';
FLUSH PRIVILEGES;

-- 데이터베이스 사용
USE ${DB_NAME};

-- 사용자 테이블
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    balance DECIMAL(15,2) DEFAULT 10000.0,
    is_admin TINYINT DEFAULT 0,
    profile_pic VARCHAR(255) DEFAULT 'default.png',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 거래 내역 테이블
CREATE TABLE IF NOT EXISTS transactions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    from_user_id INT,
    to_user_id INT,
    amount DECIMAL(15,2),
    memo TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (from_user_id) REFERENCES users(id),
    FOREIGN KEY (to_user_id) REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 공지사항 테이블
CREATE TABLE IF NOT EXISTS notices (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(255),
    content TEXT,
    author_id INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 메시지 테이블
CREATE TABLE IF NOT EXISTS messages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    from_user_id INT,
    to_user_id INT,
    subject VARCHAR(255),
    content TEXT,
    is_read TINYINT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 초기 사용자 데이터 (비밀번호는 MD5 해시)
INSERT IGNORE INTO users (username, password, email, balance, is_admin) VALUES
('admin', '0192023a7bbd73250516f069df18b500', 'admin@vulnbank.com', 999999.0, 1),
('user1', '7c6a180b36896a65c3f2e2bf07d5c917', 'user1@vulnbank.com', 50000.0, 0),
('user2', '6cb75f652a9b52798eb6cf2201057c73', 'user2@vulnbank.com', 30000.0, 0),
('testuser', '16d7a4fca7442dda3ad93c9a726597e4', 'test@vulnbank.com', 15000.0, 0);

-- 초기 공지사항
INSERT IGNORE INTO notices (id, title, content, author_id) VALUES
(1, '시스템 점검 안내', '매주 일요일 새벽 2시-4시 시스템 점검이 진행됩니다.', 1),
(2, '보안 업데이트 공지', '최신 보안 패치가 적용되었습니다.', 1);

-- 초기 거래 내역
INSERT IGNORE INTO transactions (from_user_id, to_user_id, amount, memo) VALUES
(1, 2, 5000, '용돈'),
(2, 3, 2000, '점심값');
EOF

# 5. 방화벽 설정
echo -e "${GREEN}[5/5] 방화벽 설정 중...${NC}"
sudo ufw allow 3306/tcp 2>/dev/null || true

echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo -e "${GREEN}✅ Database Server 배포 완료!${NC}"
echo ""
echo "  🗄️  데이터베이스: ${DB_NAME}"
echo "  👤 DB 사용자:    ${DB_USER}"
echo "  🔑 DB 비밀번호:  ${DB_PASS}"
echo "  🌐 접속 포트:    3306"
echo ""
echo "  📋 연결 테스트:"
echo "     mysql -h 172.16.10.20 -u ${DB_USER} -p${DB_PASS} ${DB_NAME}"
echo ""
echo "  👤 테스트 계정 (웹 로그인용):"
echo "     - admin / admin123"
echo "     - user1 / password1"
echo "     - testuser / test1234"
echo "═══════════════════════════════════════════════════════════════════"
echo ""

# 상태 확인
sudo systemctl status mariadb --no-pager

# 테이블 확인
echo ""
echo -e "${YELLOW}[*] 생성된 테이블 목록:${NC}"
sudo mysql -e "USE ${DB_NAME}; SHOW TABLES;"

echo ""
echo -e "${YELLOW}[*] 사용자 목록:${NC}"
sudo mysql -e "USE ${DB_NAME}; SELECT id, username, email, balance, is_admin FROM users;"










