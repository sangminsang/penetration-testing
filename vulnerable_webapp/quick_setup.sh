#!/bin/bash
# =============================================================================
# VulnBank 빠른 설치 스크립트
# 한 번의 명령으로 설치 완료!
# =============================================================================

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   🏦 VulnBank - 빠른 설치 스크립트                           ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# 현재 IP 확인
CURRENT_IP=$(hostname -I | awk '{print $1}')
echo "현재 서버 IP: ${CURRENT_IP}"
echo ""

# 서버 유형 선택
echo "이 서버의 역할을 선택하세요:"
echo ""
echo "  1) Webserver (172.16.10.10) - 웹 애플리케이션 서버"
echo "  2) DB Server (172.16.10.20) - 데이터베이스 서버"
echo "  3) All-in-One - 단일 서버에 모두 설치 (테스트용)"
echo ""
read -p "선택 [1-3]: " choice

case $choice in
    1)
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "Webserver 배포를 시작합니다..."
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        
        read -p "DB 서버 IP (기본: 172.16.10.20): " db_host
        DB_HOST=${db_host:-172.16.10.20}
        
        export DEPLOY_MODE=distributed
        export DB_HOST=${DB_HOST}
        
        chmod +x deploy_webserver.sh
        ./deploy_webserver.sh
        ;;
    2)
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "Database Server 배포를 시작합니다..."
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        
        chmod +x deploy_dbserver.sh
        ./deploy_dbserver.sh
        ;;
    3)
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "All-in-One 배포를 시작합니다 (Standalone 모드)..."
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        
        export DEPLOY_MODE=standalone
        
        chmod +x deploy_webserver.sh
        ./deploy_webserver.sh
        ;;
    *)
        echo "잘못된 선택입니다. 1, 2, 또는 3을 입력하세요."
        exit 1
        ;;
esac

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   ✅ 설치가 완료되었습니다!                                  ║"
echo "╚══════════════════════════════════════════════════════════════╝"










