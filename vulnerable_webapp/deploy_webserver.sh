#!/bin/bash
# =============================================================================
# VulnBank Webserver 배포 스크립트
# Webserver (172.16.10.10)에서 실행
# =============================================================================

set -e

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   🏦 VulnBank - Webserver 배포 스크립트                      ║"
echo "║   대상 서버: 172.16.10.10                                    ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 변수 설정
INSTALL_DIR="/opt/vulnbank"
SERVICE_NAME="vulnbank"
DEPLOY_MODE="${DEPLOY_MODE:-standalone}"

echo -e "${YELLOW}[*] 배포 모드: ${DEPLOY_MODE}${NC}"
echo ""

# 1. 필수 패키지 설치
echo -e "${GREEN}[1/6] 필수 패키지 설치 중...${NC}"
sudo apt update
sudo apt install -y python3 python3-pip python3-venv

# 2. 설치 디렉토리 생성
echo -e "${GREEN}[2/6] 설치 디렉토리 생성 중...${NC}"
sudo mkdir -p ${INSTALL_DIR}
sudo cp -r . ${INSTALL_DIR}/
sudo chown -R www-data:www-data ${INSTALL_DIR}

# 3. 가상환경 생성 및 패키지 설치
echo -e "${GREEN}[3/6] Python 가상환경 설정 중...${NC}"
cd ${INSTALL_DIR}
sudo -u www-data python3 -m venv venv
source venv/bin/activate

if [ "$DEPLOY_MODE" = "distributed" ]; then
    echo -e "${YELLOW}[*] 분산 모드 - PyMySQL 포함 설치${NC}"
    pip install flask pymysql
else
    echo -e "${YELLOW}[*] 단일 모드 - Flask만 설치${NC}"
    pip install flask
fi

# 4. 업로드/문서 디렉토리 생성
echo -e "${GREEN}[4/6] 디렉토리 생성 중...${NC}"
sudo -u www-data mkdir -p ${INSTALL_DIR}/uploads
sudo -u www-data mkdir -p ${INSTALL_DIR}/documents

# 5. 환경 변수 파일 생성
echo -e "${GREEN}[5/6] 환경 설정 파일 생성 중...${NC}"

if [ "$DEPLOY_MODE" = "distributed" ]; then
    cat > ${INSTALL_DIR}/.env << EOF
# VulnBank Environment Configuration (Distributed Mode)
DEPLOY_MODE=distributed
WEB_HOST=0.0.0.0
WEB_PORT=5000
DEBUG=True

# Database Configuration (API/DB Server: 172.16.10.20)
DB_HOST=${DB_HOST:-172.16.10.20}
DB_PORT=${DB_PORT:-3306}
DB_USER=${DB_USER:-vulnbank}
DB_PASSWORD=${DB_PASSWORD:-Vuln@2024!}
DB_NAME=${DB_NAME:-vulnbank_db}
EOF
else
    cat > ${INSTALL_DIR}/.env << EOF
# VulnBank Environment Configuration (Standalone Mode)
DEPLOY_MODE=standalone
WEB_HOST=0.0.0.0
WEB_PORT=5000
DEBUG=True
EOF
fi

# 6. systemd 서비스 등록
echo -e "${GREEN}[6/6] systemd 서비스 등록 중...${NC}"

if [ "$DEPLOY_MODE" = "distributed" ]; then
    APP_FILE="app_distributed.py"
else
    APP_FILE="app.py"
fi

sudo cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
[Unit]
Description=VulnBank Vulnerable Web Application
After=network.target

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=${INSTALL_DIR}
Environment="PATH=${INSTALL_DIR}/venv/bin"
EnvironmentFile=${INSTALL_DIR}/.env
ExecStart=${INSTALL_DIR}/venv/bin/python ${APP_FILE}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# 서비스 시작
sudo systemctl daemon-reload
sudo systemctl enable ${SERVICE_NAME}
sudo systemctl start ${SERVICE_NAME}

# 방화벽 설정
echo -e "${GREEN}[*] 방화벽 포트 개방 (5000/tcp)...${NC}"
sudo ufw allow 5000/tcp 2>/dev/null || true

echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo -e "${GREEN}✅ VulnBank 배포 완료!${NC}"
echo ""
echo "  📍 설치 경로: ${INSTALL_DIR}"
echo "  🌐 접속 URL:  http://172.16.10.10:5000"
echo "  📋 서비스:    systemctl status ${SERVICE_NAME}"
echo ""
echo "  👤 테스트 계정:"
echo "     - admin / admin123 (관리자)"
echo "     - user1 / password1 (일반)"
echo "     - testuser / test1234 (테스트)"
echo "═══════════════════════════════════════════════════════════════════"
echo ""

# 서비스 상태 확인
sudo systemctl status ${SERVICE_NAME} --no-pager










