-- =============================================================================
-- VulnBank Database Setup Script
-- API/DB Server (172.16.10.20)에서 실행
-- =============================================================================

-- 데이터베이스 생성
CREATE DATABASE IF NOT EXISTS vulnbank_db 
CHARACTER SET utf8mb4 
COLLATE utf8mb4_unicode_ci;

USE vulnbank_db;

-- 사용자 생성 및 권한 부여
-- 취약점: 원격 접속 허용 (%)
CREATE USER IF NOT EXISTS 'vulnbank'@'%' IDENTIFIED BY 'Vuln@2024!';
GRANT ALL PRIVILEGES ON vulnbank_db.* TO 'vulnbank'@'%';
FLUSH PRIVILEGES;

-- =============================================================================
-- 테이블 생성
-- =============================================================================

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

-- =============================================================================
-- 초기 데이터 삽입
-- =============================================================================

-- 기본 사용자 (비밀번호는 MD5 해시 - 취약점)
INSERT IGNORE INTO users (username, password, email, balance, is_admin) VALUES
('admin', '0192023a7bbd73250516f069df18b500', 'admin@vulnbank.com', 999999.0, 1),      -- admin123
('user1', '7c6a180b36896a65c3f2e2bf07d5c917', 'user1@vulnbank.com', 50000.0, 0),      -- password1
('user2', '6cb75f652a9b52798eb6cf2201057c73', 'user2@vulnbank.com', 30000.0, 0),      -- password2
('testuser', '16d7a4fca7442dda3ad93c9a726597e4', 'test@vulnbank.com', 15000.0, 0);   -- test1234

-- 샘플 공지사항
INSERT IGNORE INTO notices (id, title, content, author_id) VALUES
(1, '시스템 점검 안내', '매주 일요일 새벽 2시-4시 시스템 점검이 진행됩니다.', 1),
(2, '보안 업데이트 공지', '최신 보안 패치가 적용되었습니다. 안전한 서비스 이용을 위해 비밀번호를 변경해주세요.', 1);

-- 샘플 거래 내역
INSERT IGNORE INTO transactions (from_user_id, to_user_id, amount, memo) VALUES
(1, 2, 5000, '용돈'),
(2, 3, 2000, '점심값'),
(3, 1, 1000, '커피값');

-- =============================================================================
-- 취약점을 위한 추가 설정
-- =============================================================================

-- 취약점: 에러 메시지 상세 출력 허용
SET GLOBAL sql_mode = '';

-- 확인
SELECT 'VulnBank Database Setup Complete!' as status;
SELECT COUNT(*) as user_count FROM users;










