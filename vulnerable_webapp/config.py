#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VulnBank 설정 파일
네트워크 구조에 맞게 배포할 수 있도록 설정값을 관리합니다.

네트워크 구조:
- Webserver (172.16.10.10) : 웹 애플리케이션 서버
- API/DB (172.16.10.20)    : 데이터베이스 서버
- FileServer (10.0.0.20)   : 파일 서버 (LAN)
- Windows10 (10.0.0.100)   : 사용자 PC (LAN)
"""

import os

# =============================================================================
# 배포 모드 설정
# =============================================================================
# 'standalone' : 단일 서버에서 SQLite 사용 (테스트용)
# 'distributed': 분산 환경에서 MySQL/MariaDB 사용 (실제 랩 환경)
DEPLOY_MODE = os.environ.get('DEPLOY_MODE', 'standalone')

# =============================================================================
# 웹 서버 설정 (Webserver: 172.16.10.10)
# =============================================================================
WEB_SERVER_HOST = os.environ.get('WEB_HOST', '0.0.0.0')
WEB_SERVER_PORT = int(os.environ.get('WEB_PORT', 5000))
DEBUG_MODE = os.environ.get('DEBUG', 'True').lower() == 'true'

# Flask 시크릿 키 (취약점: 약한 키 - 교육 목적)
SECRET_KEY = os.environ.get('SECRET_KEY', 'secret123')

# =============================================================================
# 데이터베이스 설정
# =============================================================================

# SQLite 설정 (standalone 모드)
SQLITE_DATABASE = 'vulnbank.db'

# MySQL/MariaDB 설정 (distributed 모드 - API/DB: 172.16.10.20)
MYSQL_CONFIG = {
    'host': os.environ.get('DB_HOST', '172.16.10.20'),
    'port': int(os.environ.get('DB_PORT', 3306)),
    'user': os.environ.get('DB_USER', 'vulnbank'),
    'password': os.environ.get('DB_PASSWORD', 'Vuln@2024!'),
    'database': os.environ.get('DB_NAME', 'vulnbank_db'),
    'charset': 'utf8mb4'
}

# =============================================================================
# 파일 업로드 설정
# =============================================================================
UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', 'uploads')
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB

# 취약점: 모든 확장자 허용 (위험!)
ALLOWED_EXTENSIONS = None  # None = 모든 파일 허용

# =============================================================================
# 네트워크 구성 정보 (참조용)
# =============================================================================
NETWORK_CONFIG = {
    'wan': {
        'subnet': '192.168.111.0/24',
        'gateway': '192.168.111.1',
        'hosts': {
            'kali': '192.168.111.10',
            'pfsense_wan': '192.168.111.20'
        }
    },
    'dmz': {
        'subnet': '172.16.10.0/24',
        'gateway': '172.16.10.1',
        'hosts': {
            'webserver': '172.16.10.10',
            'apidb': '172.16.10.20'
        }
    },
    'lan': {
        'subnet': '10.0.0.0/24',
        'gateway': '10.0.0.1',
        'hosts': {
            'fileserver': '10.0.0.20',
            'windows10': '10.0.0.100'
        }
    }
}

# =============================================================================
# 로깅 설정
# =============================================================================
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'DEBUG')
LOG_FILE = os.environ.get('LOG_FILE', 'vulnbank.log')


def get_database_uri():
    """현재 모드에 따른 데이터베이스 URI 반환"""
    if DEPLOY_MODE == 'distributed':
        return f"mysql+pymysql://{MYSQL_CONFIG['user']}:{MYSQL_CONFIG['password']}@{MYSQL_CONFIG['host']}:{MYSQL_CONFIG['port']}/{MYSQL_CONFIG['database']}"
    else:
        return f"sqlite:///{SQLITE_DATABASE}"


def print_config():
    """현재 설정 출력"""
    print("=" * 60)
    print("VulnBank Configuration")
    print("=" * 60)
    print(f"Deploy Mode    : {DEPLOY_MODE}")
    print(f"Web Server     : {WEB_SERVER_HOST}:{WEB_SERVER_PORT}")
    print(f"Debug Mode     : {DEBUG_MODE}")
    if DEPLOY_MODE == 'distributed':
        print(f"Database Host  : {MYSQL_CONFIG['host']}:{MYSQL_CONFIG['port']}")
        print(f"Database Name  : {MYSQL_CONFIG['database']}")
    else:
        print(f"Database File  : {SQLITE_DATABASE}")
    print("=" * 60)


if __name__ == '__main__':
    print_config()










